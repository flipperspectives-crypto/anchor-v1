"""ANCHOR v1 — SCITT evidence mapping (Wave 4; RFC 9943 / RFC 9942).

Maps every ANCHOR governance event — policy decisions, multisig approvals,
capability minting, consumption, execution receipts, revocations — into
SCITT **Signed Statements** (COSE_Sign1, RFC 9943 §6), registered with a
**Transparency Service** that returns **Receipts** (RFC 9942), which the
client embeds into the statement's unprotected header to form a
**Transparent Statement** (RFC 9943 §7) verifiable fully offline.

Wire shapes follow the normative CDDL (RFC 9943 Figure 3):

* Statement protected header: ``{15: {1: iss, 2: sub}, 1: -8, 4: kid}``
  — CWT claims (RFC 9597) carrying the mandatory issuer and subject.
* Transparent statement: receipts ride in the unprotected header at
  label ``394`` as a list of byte strings, so a log can attach them
  after the fact without invalidating the issuer's signature.
* Receipt: a COSE_Sign1 with **detached payload**; protected header
  ``{15: {1: log_iss, 2: statement_hash}, 1: -8, 4: kid, 395: 1}``
  (``vds`` = 1 means RFC 9162 SHA-256, per the RFC 9942 registry), and
  the inclusion proof in the unprotected header at label ``396``.
  The receipt signs the Merkle root **derived** from the proof — the
  verifier recomputes it from the statement bytes and the audit path
  and never takes a root as input.

The Merkle tree is RFC 6962/9162 with domain separation
(``0x00`` leaves, ``0x01`` nodes) and the largest-power-of-two split.

The transparency service is an injectable interface
(:class:`TransparencyLog`); :class:`LocalTransparencyLog` is an in-memory
reference that keeps the whole flow hermetic in tests. A production
deployment would point ``register`` at a real SCITT service — the
statement and receipt bytes are wire-compatible either way.

This module has its own minimal COSE_Sign1 codec and does NOT reuse
``anchor_v1.cose``: that module deliberately hardens capability tokens
(exact ``{alg, kid}`` protected header, empty unprotected header) and
must not be loosened for SCITT's different header requirements.
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Callable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from anchor_v1.cbor import CBORError, cbor_dumps, cbor_loads
from anchor_v1.crypto import Ed25519Signer

__all__ = [
    # statement types (the SCITT "feed")
    "STATEMENT_DECISION",
    "STATEMENT_APPROVAL",
    "STATEMENT_MINT",
    "STATEMENT_CONSUME",
    "STATEMENT_EXECUTION",
    "STATEMENT_REVOCATION",
    "STATEMENT_FREEZE",
    "STATEMENT_POLICY_CHANGE",
    "STATEMENT_EPOCH",
    "KNOWN_STATEMENT_TYPES",
    # errors
    "SCITTError",
    # statements
    "issue_statement",
    "parse_statement",
    "add_receipt",
    "verify_transparent_statement",
    # transparency service
    "TransparencyLog",
    "LocalTransparencyLog",
    # evidence mapping
    "decision_statement",
    "approval_statement",
    "mint_statement",
    "consume_statement",
    "execution_statement",
    "revocation_statement",
    "freeze_statement",
    "policy_change_statement",
    "epoch_statement",
]

STATEMENT_DECISION = "anchor.v1/decision"
STATEMENT_APPROVAL = "anchor.v1/approval"
STATEMENT_MINT = "anchor.v1/mint"
STATEMENT_CONSUME = "anchor.v1/consume"
STATEMENT_EXECUTION = "anchor.v1/execution"
STATEMENT_REVOCATION = "anchor.v1/revocation"
STATEMENT_FREEZE = "anchor.v1/freeze"
STATEMENT_POLICY_CHANGE = "anchor.v1/policy_change"
STATEMENT_EPOCH = "anchor.v1/epoch"

KNOWN_STATEMENT_TYPES = frozenset(
    {
        STATEMENT_DECISION,
        STATEMENT_APPROVAL,
        STATEMENT_MINT,
        STATEMENT_CONSUME,
        STATEMENT_EXECUTION,
        STATEMENT_REVOCATION,
        STATEMENT_FREEZE,
        STATEMENT_POLICY_CHANGE,
        STATEMENT_EPOCH,
    }
)

# COSE / SCITT label registry.
_LABEL_ALG = 1
_LABEL_KID = 4
_LABEL_CWT_CLAIMS = 15
_LABEL_RECEIPTS = 394
_LABEL_VDS = 395
_LABEL_VDP = 396
_CWT_ISS = 1
_CWT_SUB = 2
_ALG_EDDSA = -8
_VDS_RFC9162_SHA256 = 1
_PROOF_TYPE_INCLUSION = -1


class SCITTError(ValueError):
    """Any SCITT structural, signature, or inclusion failure (fail closed)."""


# ---------------------------------------------------------------------------
# minimal COSE_Sign1 codec for SCITT (independent of anchor_v1.cose)
# ---------------------------------------------------------------------------


def _scitt_sign(
    *,
    payload: bytes | None,
    protected: dict,
    unprotected: dict,
    sign_fn: Callable[[bytes], bytes],
    detached_payload: bytes | None = None,
) -> bytes:
    """Build a COSE_Sign1. ``payload=None`` encodes a detached (nil) payload;
    ``detached_payload`` supplies the bytes covered by the signature in that
    case (e.g. the Merkle root a receipt attests to)."""
    if payload is not None and detached_payload is not None:
        raise SCITTError("payload and detached_payload are mutually exclusive")
    protected_bytes = cbor_dumps(protected)
    if detached_payload is not None:
        sig_payload = bytes(detached_payload)
    elif payload is not None:
        sig_payload = bytes(payload)
    else:
        sig_payload = b""
    sig_structure = cbor_dumps(
        ["Signature1", protected_bytes, b"", sig_payload]
    )
    signature = sign_fn(sig_structure)
    if not isinstance(signature, (bytes, bytearray)) or len(signature) != 64:
        raise SCITTError("sign_fn must return a 64-byte Ed25519 signature")
    return cbor_dumps(
        [protected_bytes, dict(unprotected), None if payload is None else bytes(payload), bytes(signature)]
    )


def _scitt_parse(message: bytes) -> tuple[dict, dict, bytes | None, bytes, bytes]:
    """Parse a COSE_Sign1 into (protected, unprotected, payload, signature,
    protected_bytes). Does NOT verify."""
    if not isinstance(message, (bytes, bytearray)):
        raise SCITTError("COSE message must be bytes")
    try:
        outer = cbor_loads(bytes(message))
    except CBORError as exc:
        raise SCITTError(f"malformed COSE_Sign1: {exc}") from exc
    if not isinstance(outer, list) or len(outer) != 4:
        raise SCITTError("COSE_Sign1 must be an array of 4 elements")
    protected_bytes, unprotected, payload, signature = outer
    if not isinstance(protected_bytes, bytes):
        raise SCITTError("body_protected must be a byte string")
    if not isinstance(unprotected, dict):
        raise SCITTError("unprotected header must be a map")
    if payload is not None and not isinstance(payload, bytes):
        raise SCITTError("payload must be a byte string or nil")
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise SCITTError("signature must be a 64-byte string")
    try:
        protected = cbor_loads(protected_bytes)
    except CBORError as exc:
        raise SCITTError(f"malformed protected header: {exc}") from exc
    if not isinstance(protected, dict):
        raise SCITTError("protected header must be a map")
    return protected, unprotected, payload, signature, protected_bytes


def _check_protected(protected: dict, *, what: str) -> tuple[bytes, str, str]:
    """Enforce the RFC 9943 protected-header shape. Returns (kid, iss, sub)."""
    if protected.get(_LABEL_ALG) != _ALG_EDDSA:
        raise SCITTError(f"{what}: protected alg must be EdDSA (-8)")
    kid = protected.get(_LABEL_KID)
    if not isinstance(kid, bytes) or not kid:
        raise SCITTError(f"{what}: protected kid must be a non-empty bstr")
    cwt = protected.get(_LABEL_CWT_CLAIMS)
    if not isinstance(cwt, dict):
        raise SCITTError(f"{what}: protected header must carry CWT claims (label 15)")
    iss = cwt.get(_CWT_ISS)
    sub = cwt.get(_CWT_SUB)
    if not isinstance(iss, str) or not iss:
        raise SCITTError(f"{what}: CWT iss claim must be a non-empty string")
    if not isinstance(sub, str) or not sub:
        raise SCITTError(f"{what}: CWT sub claim must be a non-empty string")
    return kid, iss, sub


def _scitt_verify(
    message: bytes,
    trusted_keys: Mapping[bytes, Ed25519PublicKey],
    *,
    detached_payload: bytes | None = None,
    what: str = "statement",
) -> tuple[dict, dict, bytes, str, str]:
    """Verify a COSE_Sign1. Returns (protected, unprotected, payload, iss, sub).

    With ``detached_payload`` set, the message must carry a nil payload and
    the signature is checked against the supplied bytes.
    """
    protected, unprotected, payload, signature, protected_bytes = _scitt_parse(message)
    kid, iss, sub = _check_protected(protected, what=what)
    if detached_payload is not None:
        if payload is not None:
            raise SCITTError(f"{what}: expected a detached (nil) payload")
        payload = bytes(detached_payload)
    elif payload is None:
        raise SCITTError(f"{what}: nil payload without detached content")
    key = trusted_keys.get(kid)
    if key is None:
        raise SCITTError(f"{what}: unknown kid {kid!r}")
    sig_structure = cbor_dumps(["Signature1", protected_bytes, b"", payload])
    try:
        key.verify(signature, sig_structure)
    except InvalidSignature as exc:
        raise SCITTError(f"{what}: signature verification failed") from exc
    return protected, unprotected, payload, iss, sub


# ---------------------------------------------------------------------------
# RFC 6962 / RFC 9162 Merkle tree (domain-separated)
# ---------------------------------------------------------------------------


def _leaf(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n: int) -> int:
    """Largest power of two strictly smaller than n (RFC 6962 §2.1)."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _mth(leaf_hashes: list[bytes]) -> bytes:
    if not leaf_hashes:
        raise SCITTError("cannot build a Merkle tree over zero leaves")
    if len(leaf_hashes) == 1:
        return leaf_hashes[0]
    k = _split(len(leaf_hashes))
    return _node(_mth(leaf_hashes[:k]), _mth(leaf_hashes[k:]))


def _audit_path(leaf_hashes: list[bytes], leaf_index: int) -> list[bytes]:
    """RFC 6962 audit path, ordered leaf -> root."""
    n = len(leaf_hashes)
    if not (0 <= leaf_index < n):
        raise SCITTError("leaf_index out of range")
    if n == 1:
        return []
    k = _split(n)
    if leaf_index < k:
        return _audit_path(leaf_hashes[:k], leaf_index) + [_mth(leaf_hashes[k:])]
    return [_mth(leaf_hashes[:k])] + _audit_path(leaf_hashes[k:], leaf_index - k)


def _root_from_proof(
    leaf_hash: bytes, leaf_index: int, proof: list[bytes], tree_size: int
) -> bytes:
    """Recompute the Merkle root from a leaf hash and an RFC 6962 audit path."""
    if tree_size <= 0:
        raise SCITTError("tree_size must be positive")
    if not (0 <= leaf_index < tree_size):
        raise SCITTError("leaf_index out of range for tree_size")
    if tree_size == 1:
        if proof:
            raise SCITTError("non-empty proof for a single-leaf tree")
        return leaf_hash
    k = _split(tree_size)
    if leaf_index < k:
        if not proof:
            raise SCITTError("audit path too short")
        *inner, right_root = proof
        left_root = _root_from_proof(leaf_hash, leaf_index, list(inner), k)
        return _node(left_root, right_root)
    else:
        if not proof:
            raise SCITTError("audit path too short")
        left_root, *inner = proof
        right_root = _root_from_proof(
            leaf_hash, leaf_index - k, list(inner), tree_size - k
        )
        return _node(left_root, right_root)


# ---------------------------------------------------------------------------
# signed statements
# ---------------------------------------------------------------------------


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def issue_statement(
    *,
    statement_type: str,
    subject: str,
    claims: Mapping[str, Any],
    issuer: Ed25519Signer,
    issued_at: str | None = None,
) -> bytes:
    """Create a SCITT Signed Statement (COSE_Sign1) about ``subject``.

    The protected header carries the mandatory CWT ``iss``/``sub`` claims
    (RFC 9943 §6). The payload is the attached CBOR map
    ``{statement_type, subject, issued_at, claims}``. Empty issuer key id,
    empty subject, or an unknown statement type raises — a statement that
    is not attributable or not typed is worse than no statement.
    """
    if not issuer.key_id:
        raise SCITTError("statement issuer key id must not be empty")
    if not isinstance(subject, str) or not subject:
        raise SCITTError("statement subject must be a non-empty string")
    if statement_type not in KNOWN_STATEMENT_TYPES:
        raise SCITTError(f"unknown statement type: {statement_type!r}")
    if not isinstance(claims, Mapping):
        raise SCITTError("statement claims must be a mapping")
    payload = cbor_dumps(
        {
            "statement_type": statement_type,
            "subject": subject,
            "issued_at": issued_at or _utcnow_iso(),
            "claims": dict(claims),
        }
    )
    protected = {
        _LABEL_CWT_CLAIMS: {_CWT_ISS: issuer.key_id, _CWT_SUB: subject},
        _LABEL_ALG: _ALG_EDDSA,
        _LABEL_KID: issuer.key_id.encode("utf-8"),
    }
    return _scitt_sign(
        payload=payload,
        protected=protected,
        unprotected={},
        sign_fn=issuer.sign_bytes,
    )


def parse_statement(
    statement: bytes,
    trusted_issuers: Mapping[bytes, Ed25519PublicKey],
    *,
    allow_receipts: bool = False,
) -> dict[str, Any]:
    """Verify a Signed Statement and return its decoded contents.

    Returns ``{"issuer", "subject", "statement_type", "issued_at",
    "claims", "raw"}``. The CWT ``sub`` claim must equal the payload's
    ``subject`` — a statement whose header and body disagree about what
    it is about is rejected. By default a statement already carrying
    receipts is refused (use ``verify_transparent_statement`` for those);
    pass ``allow_receipts=True`` when the caller handles receipts itself.
    """
    protected, unprotected, payload, iss, sub = _scitt_verify(
        statement, trusted_issuers, what="statement"
    )
    if unprotected.get(_LABEL_RECEIPTS) and not allow_receipts:
        raise SCITTError(
            "parse_statement refuses statements carrying receipts; "
            "use verify_transparent_statement"
        )
    try:
        body = cbor_loads(payload)
    except CBORError as exc:
        raise SCITTError(f"statement payload is not CBOR: {exc}") from exc
    if not isinstance(body, dict):
        raise SCITTError("statement payload must be a map")
    if body.get("subject") != sub:
        raise SCITTError("statement subject mismatch between header and payload")
    statement_type = body.get("statement_type")
    if statement_type not in KNOWN_STATEMENT_TYPES:
        raise SCITTError(f"unknown statement type in payload: {statement_type!r}")
    return {
        "issuer": iss,
        "subject": sub,
        "statement_type": statement_type,
        "issued_at": body.get("issued_at"),
        "claims": body.get("claims") or {},
        "raw": bytes(statement),
    }


def statement_hash(statement: bytes) -> bytes:
    """Leaf preimage hash input: the raw statement bytes (leaf = SHA256(0x00 || bytes))."""
    return hashlib.sha256(bytes(statement)).digest()


# ---------------------------------------------------------------------------
# transparency service
# ---------------------------------------------------------------------------


class TransparencyLog(ABC):
    """Injectable transparency-service boundary (cf. OTSCalendarClient).

    ``register`` takes a Signed Statement and returns a SCITT Receipt
    (COSE_Sign1, detached payload). Implementations MUST be append-only:
    once a receipt is issued for a statement, the statement stays in the
    verifiable data structure.
    """

    @abstractmethod
    def register(self, statement: bytes) -> bytes:
        """Register a statement; return its receipt. Raises SCITTError if the
        registration policy refuses it."""

    @property
    @abstractmethod
    def key_id(self) -> str:
        """The log's signing key id (the receipt's CWT iss)."""


class LocalTransparencyLog(TransparencyLog):
    """In-memory reference transparency service (tests / local deployments).

    Keeps an append-only list of statements, an RFC 6962 Merkle tree over
    them, and issues receipts whose detached payload is the tree root
    derived from the statement's inclusion proof. ``trusted_issuers`` —
    when given — restricts which issuers may register (fail closed);
    ``registration_policy`` is an extra hook receiving the verified
    statement view (raise :class:`SCITTError` to refuse). ``allowed_types``
    defaults to every known ANCHOR statement type.
    """

    def __init__(
        self,
        signer: Ed25519Signer,
        *,
        trusted_issuers: Mapping[bytes, Ed25519PublicKey] | None = None,
        allowed_types: frozenset[str] | set[str] | None = None,
        registration_policy: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        if not signer.key_id:
            raise SCITTError("transparency log key id must not be empty")
        self._signer = signer
        self._trusted_issuers = (
            dict(trusted_issuers) if trusted_issuers is not None else None
        )
        self._allowed_types = (
            frozenset(allowed_types) if allowed_types is not None else KNOWN_STATEMENT_TYPES
        )
        self._policy = registration_policy
        self._statements: list[bytes] = []
        self._leaf_hashes: list[bytes] = []

    @property
    def key_id(self) -> str:
        return self._signer.key_id

    @property
    def tree_size(self) -> int:
        return len(self._statements)

    def tree_root(self) -> bytes:
        if not self._leaf_hashes:
            raise SCITTError("empty transparency log has no root")
        return _mth(list(self._leaf_hashes))

    def register(self, statement: bytes) -> bytes:
        # Structural + (optional) issuer check, then the registration policy.
        if self._trusted_issuers is not None:
            view = parse_statement(statement, self._trusted_issuers)
        else:
            view = self._parse_untrusted(statement)
        if view["statement_type"] not in self._allowed_types:
            raise SCITTError(
                f"registration policy refuses type {view['statement_type']!r}"
            )
        if self._policy is not None:
            self._policy(view)

        raw = bytes(statement)
        self._statements.append(raw)
        self._leaf_hashes.append(_leaf(raw))
        leaf_index = len(self._statements) - 1
        tree_size = len(self._statements)
        root = _mth(list(self._leaf_hashes))
        proof = _audit_path(list(self._leaf_hashes), leaf_index)

        stmt_hash_hex = hashlib.sha256(raw).hexdigest()
        protected = {
            _LABEL_CWT_CLAIMS: {_CWT_ISS: self._signer.key_id, _CWT_SUB: stmt_hash_hex},
            _LABEL_ALG: _ALG_EDDSA,
            _LABEL_KID: self._signer.key_id.encode("utf-8"),
            _LABEL_VDS: _VDS_RFC9162_SHA256,
        }
        unprotected = {
            _LABEL_VDP: {
                "proof_type": _PROOF_TYPE_INCLUSION,
                "leaf_index": leaf_index,
                "tree_size": tree_size,
                "audit_path": [p.hex() for p in proof],
            }
        }
        # Detached payload: the tree root the proof derives to. The verifier
        # recomputes it and MUST NOT take a root as input.
        return _scitt_sign(
            payload=None,
            detached_payload=root,
            protected=protected,
            unprotected=unprotected,
            sign_fn=self._signer.sign_bytes,
        )

    def _parse_untrusted(self, statement: bytes) -> dict[str, Any]:
        """Parse structure without trusting any issuer (permissive local default)."""
        protected, _unprotected, payload, _sig, _pb = _scitt_parse(statement)
        _check_protected(protected, what="statement")
        try:
            body = cbor_loads(payload or b"")
        except CBORError as exc:
            raise SCITTError(f"statement payload is not CBOR: {exc}") from exc
        if not isinstance(body, dict):
            raise SCITTError("statement payload must be a map")
        return {
            "issuer": protected[_LABEL_CWT_CLAIMS][_CWT_ISS],
            "subject": protected[_LABEL_CWT_CLAIMS][_CWT_SUB],
            "statement_type": body.get("statement_type"),
            "issued_at": body.get("issued_at"),
            "claims": body.get("claims") or {},
            "raw": bytes(statement),
        }


# ---------------------------------------------------------------------------
# transparent statements (statement + receipts)
# ---------------------------------------------------------------------------


def add_receipt(statement: bytes, receipt: bytes) -> bytes:
    """Embed a receipt into the statement's unprotected header (label 394).

    This is what makes a Signed Statement a Transparent Statement
    (RFC 9943 §7). The issuer's signature is untouched — receipts live
    outside the integrity-protected header by design.
    """
    protected, unprotected, payload, signature, protected_bytes = _scitt_parse(statement)
    if payload is None:
        raise SCITTError("cannot attach a receipt to a detached-payload statement")
    # The receipt must at least parse as a COSE_Sign1.
    _scitt_parse(receipt)
    receipts = unprotected.get(_LABEL_RECEIPTS, [])
    if not isinstance(receipts, list):
        raise SCITTError("receipts header (394) must be a list")
    new_unprotected = dict(unprotected)
    new_unprotected[_LABEL_RECEIPTS] = [*receipts, bytes(receipt)]
    return cbor_dumps([protected_bytes, new_unprotected, payload, signature])


def _verify_receipt(
    receipt: bytes,
    statement: bytes,
    trusted_logs: Mapping[bytes, Ed25519PublicKey],
) -> dict[str, Any]:
    """Verify one receipt against its statement. Returns receipt metadata."""
    stmt_hash = hashlib.sha256(bytes(statement)).digest()
    # Detached payload unknown yet: parse first, derive root, then verify sig.
    protected, unprotected, _payload, _sig, _pb = _scitt_parse(receipt)
    kid, iss, sub = _check_protected(protected, what="receipt")
    if sub != stmt_hash.hex():
        raise SCITTError("receipt subject is not this statement's hash")
    if protected.get(_LABEL_VDS) != _VDS_RFC9162_SHA256:
        raise SCITTError(
            "receipt vds must be 1 (RFC9162_SHA256); "
            "verifier cannot interpret other verifiable data structures"
        )
    vdp = unprotected.get(_LABEL_VDP)
    if not isinstance(vdp, dict):
        raise SCITTError("receipt must carry its inclusion proof (vdp, label 396)")
    if vdp.get("proof_type") != _PROOF_TYPE_INCLUSION:
        raise SCITTError("receipt proof_type must be -1 (inclusion)")
    try:
        leaf_index = int(vdp["leaf_index"])
        tree_size = int(vdp["tree_size"])
        audit_path = [bytes.fromhex(p) for p in vdp["audit_path"]]
    except (KeyError, ValueError, TypeError) as exc:
        raise SCITTError(f"malformed inclusion proof: {exc}") from exc

    derived_root = _root_from_proof(_leaf(bytes(statement)), leaf_index, audit_path, tree_size)
    _scitt_verify(receipt, trusted_logs, detached_payload=derived_root, what="receipt")
    return {
        "log_key_id": iss,
        "leaf_index": leaf_index,
        "tree_size": tree_size,
    }


def verify_transparent_statement(
    transparent: bytes,
    trusted_issuers: Mapping[bytes, Ed25519PublicKey],
    trusted_logs: Mapping[bytes, Ed25519PublicKey],
) -> dict[str, Any]:
    """Verify a Transparent Statement: the issuer's signature AND every
    embedded receipt (RFC 9943 §7). Fails closed on any problem.

    Returns ``{"statement": <parse_statement view>, "receipts": [...]}``.
    A statement with no receipts is NOT transparent — it is rejected.
    """
    view = parse_statement(bytes(transparent), trusted_issuers, allow_receipts=True)
    _protected, unprotected, _payload, _sig, _pb = _scitt_parse(transparent)
    receipts = unprotected.get(_LABEL_RECEIPTS)
    if not isinstance(receipts, list) or not receipts:
        raise SCITTError(
            "not a transparent statement: no receipts in unprotected header (394)"
        )
    for r in receipts:
        if not isinstance(r, bytes):
            raise SCITTError("receipt entries must be byte strings")

    # The receipts bind the hash of the statement bytes AS REGISTERED — i.e.
    # the issuer-signed bytes without the receipts themselves. Recover them
    # by stripping label 394 (nothing else in the unprotected header changes
    # the registered bytes).
    _prot_b, _u, _pl, _sg, protected_bytes = _scitt_parse(transparent)
    bare_unprotected = {k: v for k, v in unprotected.items() if k != _LABEL_RECEIPTS}
    bare_statement = cbor_dumps([protected_bytes, bare_unprotected, _pl, _sg])

    verified_receipts = [
        _verify_receipt(r, bare_statement, trusted_logs) for r in receipts
    ]
    return {"statement": view, "receipts": verified_receipts}


# ---------------------------------------------------------------------------
# evidence mapping: ANCHOR events -> SCITT statements
# ---------------------------------------------------------------------------


def _action_subject(action_digest: str) -> str:
    return f"action:{action_digest}"


def decision_statement(preview: Any, issuer: Ed25519Signer) -> bytes:
    """A policy decision (EffectPreview) as a SCITT statement."""
    return issue_statement(
        statement_type=STATEMENT_DECISION,
        subject=_action_subject(preview.envelope_digest),
        claims={
            "preview_id": preview.preview_id,
            "allowed": bool(preview.allowed),
            "outcome": dict(preview.outcome),
            "state_version": preview.state_version,
            "state_digest": preview.state_digest,
            "read_keys": list(preview.read_keys),
            "preview_expires_at": preview.expires_at.isoformat(),
        },
        issuer=issuer,
    )


def approval_statement(action_receipt: Any, issuer: Ed25519Signer) -> bytes:
    """A multisig/governance approval (ActionReceipt) as a SCITT statement."""
    return issue_statement(
        statement_type=STATEMENT_APPROVAL,
        subject=f"action:{action_receipt.action}@{action_receipt.resource}",
        claims={
            "action": action_receipt.action,
            "resource": action_receipt.resource,
            "constitution_hash": action_receipt.constitution_hash,
            "created_at": action_receipt.created_at.isoformat(),
        },
        issuer=issuer,
    )


def mint_statement(payload: Any, issuer: Ed25519Signer) -> bytes:
    """A capability issuance as a SCITT statement."""
    holder = payload.holder_pubkey
    return issue_statement(
        statement_type=STATEMENT_MINT,
        subject=_action_subject(payload.action_digest),
        claims={
            "capability_id": payload.capability_id,
            "kind": payload.kind,
            "holder_pubkey_hex": bytes(holder).hex(),
            "spend_limit": payload.spend_limit,
            "spend_asset": payload.spend_asset,
            "issued_at": payload.issued_at,
            "expires_at": payload.expires_at,
            "parent_capability_id": payload.parent_capability_id,
        },
        issuer=issuer,
    )


def consume_statement(
    payload: Any, issuer: Ed25519Signer, *, state_version: int | None = None
) -> bytes:
    """A capability consumption as a SCITT statement."""
    claims: dict[str, Any] = {
        "capability_id": payload.capability_id,
        "kind": payload.kind,
    }
    if state_version is not None:
        claims["state_version"] = state_version
    return issue_statement(
        statement_type=STATEMENT_CONSUME,
        subject=_action_subject(payload.action_digest),
        claims=claims,
        issuer=issuer,
    )


def execution_statement(
    receipt: Any, issuer: Ed25519Signer, *, action_digest: str | None = None
) -> bytes:
    """An execution receipt as a SCITT statement."""
    subject = (
        _action_subject(action_digest)
        if action_digest
        else f"execution:{receipt.receipt_id}"
    )
    return issue_statement(
        statement_type=STATEMENT_EXECUTION,
        subject=subject,
        claims={
            "receipt_id": receipt.receipt_id,
            "tool_name": receipt.tool_name,
            "server_id": receipt.server_id,
            "args_digest": receipt.args_digest,
            "result_digest": receipt.result_digest,
            "capability_id": receipt.capability_id,
            "executed_at": receipt.executed_at.isoformat(),
            "gateway_key_id": receipt.gateway_key_id,
            "is_error": bool(receipt.is_error),
        },
        issuer=issuer,
    )


def revocation_statement(
    *,
    capability_id: str,
    revoked_at: str,
    epoch: int,
    issuer: Ed25519Signer,
) -> bytes:
    """A revocation as a SCITT statement."""
    return issue_statement(
        statement_type=STATEMENT_REVOCATION,
        subject=f"capability:{capability_id}",
        claims={
            "capability_id": capability_id,
            "revoked_at": revoked_at,
            "epoch": epoch,
        },
        issuer=issuer,
    )


def freeze_statement(
    *,
    action_digest: str,
    reason: str,
    frozen_at: str,
    epoch: int,
    issuer: Ed25519Signer,
) -> bytes:
    """An action freeze as a SCITT statement."""
    return issue_statement(
        statement_type=STATEMENT_FREEZE,
        subject=_action_subject(action_digest),
        claims={
            "action_digest": action_digest,
            "reason": reason,
            "frozen_at": frozen_at,
            "epoch": epoch,
        },
        issuer=issuer,
    )


def policy_change_statement(
    *,
    constitution_hash: str,
    previous_hash: str | None,
    changed_at: str,
    epoch: int,
    issuer: Ed25519Signer,
) -> bytes:
    """A governance policy change as a SCITT statement."""
    return issue_statement(
        statement_type=STATEMENT_POLICY_CHANGE,
        subject="policy:constitution",
        claims={
            "constitution_hash": constitution_hash,
            "previous_hash": previous_hash,
            "changed_at": changed_at,
            "epoch": epoch,
        },
        issuer=issuer,
    )


def epoch_statement(
    *,
    epoch: int,
    started_at: str,
    issuer: Ed25519Signer,
) -> bytes:
    """A revocation-epoch marker as a SCITT statement."""
    return issue_statement(
        statement_type=STATEMENT_EPOCH,
        subject=f"epoch:{epoch}",
        claims={
            "epoch": epoch,
            "started_at": started_at,
        },
        issuer=issuer,
    )
