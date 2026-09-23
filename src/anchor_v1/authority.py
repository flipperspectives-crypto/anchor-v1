"""ANCHOR v1 — holder-of-key capabilities (Wave 2, Revision B pivots 7, 8; blocker 2).

Two capability kinds, both holder-of-key (NOT bearer):

* ``MandateCapability`` — may mint constrained one-use children, and only by
  monotonic attenuation: a child's scope must be provably ⊆ the parent's.
  Amplification (broader spend, longer expiry, different action digest,
  wider revocation-staleness bound) is rejected structurally at mint time.
* ``ExecutionCapability`` — one-use, non-delegable, non-attenuable. Any
  attempt to mint a child from one is refused.

A capability is a COSE_Sign1 object whose payload binds:

* ``action_digest`` — the ActionEnvelope digest from ``envelope.py`` (THE
  binding point: policies, approvals, and capabilities all bind to it),
* ``holder_pubkey`` — raw 32-byte Ed25519 public key the capability is bound to,
* ``kind`` — "mandate" or "execution",
* caveats — ``spend_limit`` (integer minor units) + ``spend_asset``,
  ``expires_at``, ``nonce``,
* ``max_revocation_staleness`` — per-capability revocation-staleness bound
  (seconds) enforced by the store; see ``store.py`` for the CAP trade-off.

Per-request proof: to exercise a capability the holder signs
``capability_id || server_challenge_nonce`` with the holder key.
``verify_holder_proof`` checks it. A capability presented without a valid
holder proof is DENIED — presenting the COSE bytes alone is never enough,
so a stolen capability blob is useless without the holder private key
(no bearer replay).

This module is stateless: ``verify_capability`` performs COSE signature
verification plus structural checks only. Consumption state (one-use
enforcement, budgets, revocation, epoch) lives in ``store.py``, which
performs verify + epoch + revocation + consume + budget reserve as one
atomic transaction.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .cbor import CBORError, cbor_dumps, cbor_loads
from .cose import COSEError, cose_sign_bytes, cose_verify
from .crypto import Ed25519Signer
from .models import StrictModel

__all__ = [
    "CapabilityError",
    "CapabilityPayload",
    "KIND_MANDATE",
    "KIND_EXECUTION",
    "KIND_READ",
    "CAPABILITY_VERSION",
    "DEFAULT_REVOCATION_STALENESS_S",
    "issue_mandate",
    "issue_execution",
    "issue_read",
    "mint_child",
    "verify_capability",
    "make_holder_proof",
    "verify_holder_proof",
]

CAPABILITY_VERSION = 1
KIND_MANDATE = "mandate"
KIND_EXECUTION = "execution"
KIND_READ = "read"
_KINDS = (KIND_MANDATE, KIND_EXECUTION, KIND_READ)

#: Default per-capability revocation-staleness bound (seconds). The store
#: refuses consumption when its revocation view is older than the
#: capability's bound. See store.py for the CAP trade-off.
DEFAULT_REVOCATION_STALENESS_S = 300


class CapabilityError(ValueError):
    """Raised on ANY capability failure. Fail closed, always."""


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return _as_utc(value).isoformat()


def _parse_iso(value: str, name: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except (ValueError, TypeError) as exc:
        raise CapabilityError(f"capability {name} is not ISO-8601: {exc}") from exc
    return _as_utc(parsed)


def _check_pubkey(holder_pubkey: bytes) -> bytes:
    if not isinstance(holder_pubkey, (bytes, bytearray)) or len(holder_pubkey) != 32:
        raise CapabilityError("holder_pubkey must be 32 raw Ed25519 bytes")
    return bytes(holder_pubkey)


def _check_digest(action_digest: str) -> str:
    if not isinstance(action_digest, str) or len(action_digest) != 64:
        raise CapabilityError("action_digest must be a 64-char hex string")
    try:
        bytes.fromhex(action_digest)
    except ValueError as exc:
        raise CapabilityError("action_digest must be hex") from exc
    return action_digest.lower()


def _check_spend(spend_limit: int | None, spend_asset: str | None) -> None:
    if spend_limit is not None:
        if isinstance(spend_limit, bool) or not isinstance(spend_limit, int):
            raise CapabilityError("spend_limit must be an integer (minor units)")
        if spend_limit < 0:
            raise CapabilityError("spend_limit must be >= 0")
    if spend_asset is not None:
        if not isinstance(spend_asset, str) or not spend_asset:
            raise CapabilityError("spend_asset must be a non-empty string")
    if spend_limit is None and spend_asset is not None:
        raise CapabilityError("spend_asset without spend_limit is meaningless")


class CapabilityPayload(StrictModel):
    """Decoded, structurally-validated capability payload."""

    version: int = CAPABILITY_VERSION
    capability_id: str
    kind: str
    action_digest: str
    holder_pubkey: bytes
    spend_limit: int | None = None
    spend_asset: str | None = None
    issued_at: str
    expires_at: str
    nonce: str
    parent_capability_id: str | None = None
    max_revocation_staleness: int = DEFAULT_REVOCATION_STALENESS_S
    # Provenance-bound read caveats (only meaningful for kind == "read";
    # ignored for other kinds). A read capability MUST bind provenance:
    # at least one of read_trusted_writers / read_require_statement.
    read_key_prefix: str | None = None
    read_trusted_writers: list[str] | None = None
    read_min_version: int | None = None
    read_require_statement: bool = False


def _payload_bytes(payload: CapabilityPayload) -> bytes:
    """Deterministic CBOR encoding of the payload map (the COSE payload)."""
    return cbor_dumps(payload.model_dump())


def _sign_payload(payload: CapabilityPayload, issuer: Ed25519Signer) -> bytes:
    return cose_sign_bytes(
        _payload_bytes(payload),
        issuer.sign_bytes,
        issuer.key_id.encode("utf-8"),
    )


def _check_read_caveats(
    read_key_prefix: str | None,
    read_trusted_writers: list[str] | None,
    read_min_version: int | None,
    read_require_statement: bool,
) -> None:
    """Fail-closed validation for provenance-bound read caveats.

    A read capability that does not bind provenance is meaningless — and
    dangerous, because it would authorize reading data injected by an
    untrusted writer. So issuance REQUIRES at least one provenance anchor:
    a non-empty trusted-writer allowlist or a registered-statement
    requirement.
    """
    if not isinstance(read_key_prefix, str) or not read_key_prefix:
        raise CapabilityError("read_key_prefix must be a non-empty string")
    writers = read_trusted_writers
    if writers is not None:
        if not isinstance(writers, list) or not writers:
            raise CapabilityError(
                "read_trusted_writers must be a non-empty list when given"
            )
        for w in writers:
            if not isinstance(w, str) or not w:
                raise CapabilityError("read_trusted_writers entries must be non-empty strings")
    if read_min_version is not None:
        if isinstance(read_min_version, bool) or not isinstance(read_min_version, int):
            raise CapabilityError("read_min_version must be an integer")
        if read_min_version < 0:
            raise CapabilityError("read_min_version must be >= 0")
    if not isinstance(read_require_statement, bool):
        raise CapabilityError("read_require_statement must be a bool")
    if not writers and not read_require_statement:
        raise CapabilityError(
            "a read capability must bind provenance: provide a non-empty "
            "read_trusted_writers allowlist or set read_require_statement=True"
        )


def _issue(
    issuer: Ed25519Signer,
    *,
    kind: str,
    action_digest: str,
    holder_pubkey: bytes,
    spend_limit: int | None,
    spend_asset: str | None,
    ttl: timedelta,
    parent_capability_id: str | None,
    max_revocation_staleness: int,
    now: datetime | None,
    read_key_prefix: str | None = None,
    read_trusted_writers: list[str] | None = None,
    read_min_version: int | None = None,
    read_require_statement: bool = False,
) -> bytes:
    if kind not in _KINDS:
        raise CapabilityError(f"unknown capability kind: {kind!r}")
    _check_digest(action_digest)
    _check_pubkey(holder_pubkey)
    _check_spend(spend_limit, spend_asset)
    if not isinstance(max_revocation_staleness, int) or max_revocation_staleness < 0:
        raise CapabilityError("max_revocation_staleness must be an int >= 0")
    read_caveats: dict[str, object] = {}
    if kind == KIND_READ:
        _check_read_caveats(
            read_key_prefix, read_trusted_writers, read_min_version,
            read_require_statement,
        )
        read_caveats = {
            "read_key_prefix": read_key_prefix,
            "read_trusted_writers": list(read_trusted_writers)
            if read_trusted_writers is not None
            else None,
            "read_min_version": read_min_version,
            "read_require_statement": read_require_statement,
        }
    elif any(
        v is not None and v is not False
        for v in (read_key_prefix, read_trusted_writers, read_min_version)
    ) or read_require_statement:
        raise CapabilityError("read caveats are only valid for kind 'read'")
    moment = _as_utc(now) if now is not None else datetime.now(timezone.utc)
    payload = CapabilityPayload(
        capability_id=secrets.token_hex(16),
        kind=kind,
        action_digest=_check_digest(action_digest),
        holder_pubkey=bytes(holder_pubkey),
        spend_limit=spend_limit,
        spend_asset=spend_asset,
        issued_at=_iso(moment),
        expires_at=_iso(moment + ttl),
        nonce=secrets.token_hex(16),
        parent_capability_id=parent_capability_id,
        max_revocation_staleness=max_revocation_staleness,
        **read_caveats,  # type: ignore[arg-type]
    )
    return _sign_payload(payload, issuer)


def issue_mandate(
    issuer: Ed25519Signer,
    *,
    action_digest: str,
    holder_pubkey: bytes,
    spend_limit: int | None = None,
    spend_asset: str | None = None,
    ttl: timedelta = timedelta(hours=1),
    max_revocation_staleness: int = DEFAULT_REVOCATION_STALENESS_S,
    now: datetime | None = None,
) -> bytes:
    """Issue a MandateCapability (COSE_Sign1 bytes).

    A mandate may mint constrained one-use children via :func:`mint_child`,
    but only by monotonic attenuation — never amplification.
    """
    return _issue(
        issuer,
        kind=KIND_MANDATE,
        action_digest=action_digest,
        holder_pubkey=holder_pubkey,
        spend_limit=spend_limit,
        spend_asset=spend_asset,
        ttl=ttl,
        parent_capability_id=None,
        max_revocation_staleness=max_revocation_staleness,
        now=now,
    )


def issue_execution(
    issuer: Ed25519Signer,
    *,
    action_digest: str,
    holder_pubkey: bytes,
    spend_limit: int | None = None,
    spend_asset: str | None = None,
    ttl: timedelta = timedelta(minutes=15),
    max_revocation_staleness: int = DEFAULT_REVOCATION_STALENESS_S,
    now: datetime | None = None,
) -> bytes:
    """Issue an ExecutionCapability (COSE_Sign1 bytes).

    One-use, non-delegable, non-attenuable: :func:`mint_child` refuses any
    parent whose kind is not "mandate".
    """
    return _issue(
        issuer,
        kind=KIND_EXECUTION,
        action_digest=action_digest,
        holder_pubkey=holder_pubkey,
        spend_limit=spend_limit,
        spend_asset=spend_asset,
        ttl=ttl,
        parent_capability_id=None,
        max_revocation_staleness=max_revocation_staleness,
        now=now,
    )


def issue_read(
    issuer: Ed25519Signer,
    *,
    holder_pubkey: bytes,
    read_key_prefix: str,
    read_trusted_writers: list[str] | None = None,
    read_min_version: int | None = None,
    read_require_statement: bool = False,
    ttl: timedelta = timedelta(minutes=15),
    max_revocation_staleness: int = DEFAULT_REVOCATION_STALENESS_S,
    now: datetime | None = None,
) -> bytes:
    """Issue a provenance-bound ReadCapability (COSE_Sign1 bytes).

    Unlike execution capabilities, reads are non-mutating, so a read
    capability is REUSABLE until it expires (each read still requires a
    fresh holder proof and is audit-logged) — but it can ONLY read data
    whose provenance satisfies its caveats:

    * ``read_key_prefix``: the key must start with this prefix (scope).
    * ``read_trusted_writers``: the recorded writer's key id must be in
      this allowlist (fail closed: issuance requires a non-empty list
      unless ``read_require_statement`` is set).
    * ``read_min_version``: the record must be at least this fresh
      (defeats stale-read TOCTOU).
    * ``read_require_statement``: the write must be backed by a registered
      SCITT statement hash.

    The ``action_digest`` of a read capability is the SHA-256 of its read
    scope — it identifies what may be read, not an action to execute.
    Read capabilities can never mint children (``mint_child`` requires a
    mandate parent) and can never be consumed for execution.
    """
    from anchor_v1.canonical import sha256_hex

    scope_digest = sha256_hex(
        {
            "kind": KIND_READ,
            "read_key_prefix": read_key_prefix,
            "read_trusted_writers": sorted(read_trusted_writers or []),
            "read_min_version": read_min_version,
            "read_require_statement": read_require_statement,
        }
    )
    return _issue(
        issuer,
        kind=KIND_READ,
        action_digest=scope_digest,
        holder_pubkey=holder_pubkey,
        spend_limit=None,
        spend_asset=None,
        ttl=ttl,
        parent_capability_id=None,
        max_revocation_staleness=max_revocation_staleness,
        now=now,
        read_key_prefix=read_key_prefix,
        read_trusted_writers=read_trusted_writers,
        read_min_version=read_min_version,
        read_require_statement=read_require_statement,
    )


def verify_capability(
    data: bytes,
    trusted_issuers: Mapping[bytes, Ed25519PublicKey],
    *,
    now: datetime | None = None,
) -> CapabilityPayload:
    """Verify COSE_Sign1 bytes and return the capability payload.

    Checks: COSE structure, EdDSA allowlist, empty unprotected header, known
    kid, signature, payload schema, version, kind, digest/pubkey shape,
    spend caveat sanity, nonce presence, and the validity window. No state
    is consulted — one-use enforcement, revocation, and budgets are the
    store's job. Raises :class:`CapabilityError` on ANY failure.
    """
    try:
        raw_payload, _kid = cose_verify(data, trusted_issuers)
    except COSEError as exc:
        raise CapabilityError(f"capability COSE verification failed: {exc}") from exc

    try:
        raw_map = cbor_loads(raw_payload)
    except CBORError as exc:
        raise CapabilityError(f"capability payload is not valid CBOR: {exc}") from exc

    try:
        payload = CapabilityPayload.model_validate(raw_map)
    except Exception as exc:
        raise CapabilityError(f"capability payload schema invalid: {exc}") from exc

    # Structural checks (defense in depth — a hostile issuer key is outside
    # the trust set, but a buggy honest issuer must still fail closed).
    if payload.version != CAPABILITY_VERSION:
        raise CapabilityError(f"unsupported capability version: {payload.version!r}")
    if payload.kind not in _KINDS:
        raise CapabilityError(f"unknown capability kind: {payload.kind!r}")
    _check_digest(payload.action_digest)
    _check_pubkey(payload.holder_pubkey)
    _check_spend(payload.spend_limit, payload.spend_asset)
    if not payload.capability_id or not payload.nonce:
        raise CapabilityError("capability_id and nonce must be non-empty")
    if payload.kind == KIND_READ:
        # Re-enforce the issuance-time read invariants on the verify path
        # (defense in depth): a hand-built kind="read" capability with no
        # provenance binding — all-keys scope, no writer allowlist — must
        # fail closed here, exactly as issuance refuses it.
        _check_read_caveats(
            payload.read_key_prefix,
            payload.read_trusted_writers,
            payload.read_min_version,
            payload.read_require_statement,
        )
    if payload.max_revocation_staleness < 0:
        raise CapabilityError("max_revocation_staleness must be >= 0")

    moment = _as_utc(now) if now is not None else datetime.now(timezone.utc)
    issued_at = _parse_iso(payload.issued_at, "issued_at")
    expires_at = _parse_iso(payload.expires_at, "expires_at")
    if expires_at <= issued_at:
        raise CapabilityError("capability expires_at must be after issued_at")
    if moment > expires_at:
        raise CapabilityError("capability expired")

    return payload


def mint_child(
    parent_cose: bytes,
    issuer: Ed25519Signer,
    trusted_issuers: Mapping[bytes, Ed25519PublicKey],
    *,
    holder_pubkey: bytes | None = None,
    spend_limit: int | None = None,
    spend_asset: str | None = None,
    ttl: timedelta | None = None,
    max_revocation_staleness: int | None = None,
    now: datetime | None = None,
) -> bytes:
    """Mint a one-use ExecutionCapability child from a MandateCapability.

    Monotonic attenuation ONLY — every dimension is checked to be ⊆ the
    parent's, and any amplification is rejected structurally:

    * parent kind must be "mandate" (execution capabilities cannot delegate),
    * child ``action_digest`` must equal the parent's (no scope broadening),
    * child ``spend_limit`` must be ≤ the parent's (a parent without a limit
      is unbounded and may set any child limit; a bounded parent forces a
      bounded, no-larger child),
    * child ``spend_asset`` must equal the parent's when the parent sets one,
    * child ``expires_at`` must be ≤ the parent's,
    * child ``max_revocation_staleness`` must be ≤ the parent's.

    The child is always kind "execution" and records ``parent_capability_id``.
    """
    parent = verify_capability(parent_cose, trusted_issuers, now=now)
    if parent.kind != KIND_MANDATE:
        raise CapabilityError(
            f"cannot mint child: parent kind is {parent.kind!r}, not 'mandate' "
            "(execution capabilities are non-delegable)"
        )
    child_holder = parent.holder_pubkey if holder_pubkey is None else _check_pubkey(holder_pubkey)

    # --- attenuation checks: child ⊆ parent, structurally ---
    child_spend_limit = parent.spend_limit if spend_limit is None else spend_limit
    _check_spend(child_spend_limit, spend_asset if spend_asset is not None else parent.spend_asset)
    if parent.spend_limit is not None:
        if child_spend_limit is None:
            raise CapabilityError("attenuation violated: parent spend bound dropped")
        if child_spend_limit > parent.spend_limit:
            raise CapabilityError(
                f"attenuation violated: child spend_limit {child_spend_limit} "
                f"> parent {parent.spend_limit}"
            )
    child_spend_asset = parent.spend_asset if spend_asset is None else spend_asset
    if parent.spend_asset is not None and child_spend_asset != parent.spend_asset:
        raise CapabilityError("attenuation violated: spend_asset changed")

    moment = _as_utc(now) if now is not None else datetime.now(timezone.utc)
    parent_expiry = _parse_iso(parent.expires_at, "expires_at")
    child_expiry = moment + (ttl if ttl is not None else timedelta(minutes=15))
    if child_expiry > parent_expiry:
        raise CapabilityError(
            "attenuation violated: child expires_at beyond parent expiry"
        )

    child_staleness = (
        parent.max_revocation_staleness
        if max_revocation_staleness is None
        else max_revocation_staleness
    )
    if child_staleness > parent.max_revocation_staleness:
        raise CapabilityError(
            "attenuation violated: child max_revocation_staleness exceeds parent's"
        )

    child = CapabilityPayload(
        capability_id=secrets.token_hex(16),
        kind=KIND_EXECUTION,
        action_digest=parent.action_digest,  # pinned: no scope broadening
        holder_pubkey=child_holder,
        spend_limit=child_spend_limit,
        spend_asset=child_spend_asset,
        issued_at=_iso(moment),
        expires_at=_iso(child_expiry),
        nonce=secrets.token_hex(16),
        parent_capability_id=parent.capability_id,
        max_revocation_staleness=child_staleness,
    )
    return _sign_payload(child, issuer)


def make_holder_proof(
    holder: Ed25519Signer, capability_id: str, challenge: bytes
) -> bytes:
    """Per-request proof-of-possession.

    The holder signs ``capability_id || server_challenge_nonce`` with the
    bound holder key. The challenge is a fresh server-issued nonce per
    request, so a captured proof cannot be replayed against a new challenge.
    Returns the raw 64-byte Ed25519 signature.
    """
    if not isinstance(challenge, (bytes, bytearray)) or not challenge:
        raise CapabilityError("challenge must be a non-empty byte string")
    message = capability_id.encode("ascii") + bytes(challenge)
    return holder.sign_bytes(message)


def verify_holder_proof(
    holder_pubkey: bytes,
    capability_id: str,
    challenge: bytes,
    proof: bytes,
) -> None:
    """Verify a holder proof. Returns None on success; raises
    :class:`CapabilityError` on ANY failure (wrong key, wrong challenge,
    wrong capability, malformed signature)."""
    _check_pubkey(holder_pubkey)
    if not isinstance(proof, (bytes, bytearray)) or len(proof) != 64:
        raise CapabilityError("holder proof must be a 64-byte Ed25519 signature")
    message = capability_id.encode("ascii") + bytes(challenge)
    key = Ed25519PublicKey.from_public_bytes(bytes(holder_pubkey))
    try:
        key.verify(bytes(proof), message)
    except InvalidSignature as exc:
        raise CapabilityError("holder proof-of-possession failed") from exc
