"""ANCHOR v1 — agent identity: did:key DIDs, capability assertions, registry (AgentFacts-style).

This module answers "who is this agent, and what does it *claim* it can do?"
It does NOT answer "what is this agent *allowed* to do?" — that stays with
the governor. Conflating the two is the core failure mode this module is
built to prevent.

TRUST MODEL (read before integrating):

* A DID (``did:key``) is a *self-certifying identifier*: it is literally a
  fingerprint of an Ed25519 public key. Resolving a DID is pure math — parse
  the multibase string, check the multicodec prefix (``0xed01``), recover
  the 32-byte key. There is no directory, no registrar, no trust root.
  Trust in a DID means trust in the key holder, and nothing more.
* A *capability assertion* is a signed *claim* by an attester (the agent
  itself, or a third party) that the DID's holder can exercise certain
  capabilities. Self-issued assertions are claims, not authority. The
  GOVERNOR still mints capabilities; assertions are discovery and
  subject-authentication input only. A deployment that treats an assertion
  as a grant has built a confused deputy.
* Third-party assertions are only accepted when the attester's DID is in an
  explicit caller-supplied trusted-attester set. There is no transitive
  trust: attester A vouching for attester B is meaningless unless B is also
  in the set.
* The registry is a local discovery cache, not an authority. Every entry is
  re-verified on read: signatures, expiry, revocation, and a stored document
  hash that detects tampering of the in-memory entries.
* All verification is fail-closed: ``authorize_capability_claim`` returns a
  plain ``bool`` and returns ``False`` on ANY failure (bad signature, expiry,
  revocation, DID mismatch, pattern miss, registry tamper). Exceptions
  (all subclasses of ``ValueError``) carry the reason for diagnostics.

Wire formats:

* DID: ``did:key:z`` + base58(multicodec(0xed01) || 32-byte Ed25519 pubkey).
  Base58 is hand-rolled (stdlib only) — Bitcoin alphabet.
* Assertion: COSE_Sign1 (``anchor_v1.cose``) over the canonical JSON bytes
  (``anchor_v1.canonical``) of the assertion payload. The COSE ``kid`` is the
  attester's DID (UTF-8 bytes), which binds the signature to the attester
  and defeats key-substitution and DID-replay attacks.
* ``subject_id_for(did)`` returns the DID string itself, usable directly as
  ``ActionEnvelope.principal``.

Zero new dependencies: stdlib + ``cryptography`` + ``pydantic``.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import math
import uuid
from datetime import datetime, timedelta, timezone
from typing import Literal, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import field_validator

from anchor_v1.canonical import canonical_bytes
from anchor_v1.cose import COSEError, cose_sign_bytes, cose_verify
from anchor_v1.crypto import Ed25519Signer
from anchor_v1.models import StrictModel

__all__ = [
    "AgentIdentityError",
    "PatternError",
    "AssertionPayload",
    "CapabilityPattern",
    "DIDDocument",
    "ResolvedIdentity",
    "VerificationMethod",
    "AgentRegistry",
    "authorize_capability_claim",
    "base58_decode",
    "base58_encode",
    "did_for_pubkey",
    "issue_assertion",
    "resolve_did",
    "subject_id_for",
    "verify_assertion",
]


class AgentIdentityError(ValueError):
    """Fail-closed identity error: malformed DIDs, bad assertions, untrusted
    attesters, expired/revoked assertions, registry tampering."""


class PatternError(AgentIdentityError):
    """A capability target pattern is malformed or exceeds the documented
    complexity bound. Fail-closed: an over-complex pattern never matches."""


def _finite_float_validator(cls, v):
    """Shared pydantic validator: any float field must be finite.

    Non-finite floats (inf/nan) are not JSON-compliant: they would escape
    canonicalization as a raw ``ValueError`` instead of ``AgentIdentityError``,
    so they are rejected at model validation time.
    """
    if isinstance(v, float) and not math.isfinite(v):
        raise ValueError(f"non-finite float rejected: {v!r}")
    return v


# ---------------------------------------------------------------------------
# Base58 (Bitcoin alphabet), hand-rolled — stdlib only
# ---------------------------------------------------------------------------

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {ch: i for i, ch in enumerate(_B58_ALPHABET)}


def base58_encode(data: bytes) -> str:
    """Encode bytes to base58. Leading zero bytes become leading '1's."""
    if not isinstance(data, (bytes, bytearray)):
        raise AgentIdentityError("base58_encode requires bytes")
    data = bytes(data)
    # Count leading zero bytes (preserved as '1' characters).
    leading = 0
    for byte in data:
        if byte == 0:
            leading += 1
        else:
            break
    number = int.from_bytes(data, "big") if data else 0
    digits: list[str] = []
    while number > 0:
        number, rem = divmod(number, 58)
        digits.append(_B58_ALPHABET[rem])
    return "1" * leading + "".join(reversed(digits))


def base58_decode(text: str) -> bytes:
    """Decode a base58 string. Raises on any character outside the alphabet."""
    if not isinstance(text, str) or not text:
        raise AgentIdentityError("base58 value must be a non-empty string")
    number = 0
    for ch in text:
        digit = _B58_INDEX.get(ch)
        if digit is None:
            raise AgentIdentityError(f"invalid base58 character: {ch!r}")
        number = number * 58 + digit
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    # Restore leading zero bytes from leading '1's.
    leading = 0
    for ch in text:
        if ch == "1":
            leading += 1
        else:
            break
    return b"\x00" * leading + raw


# ---------------------------------------------------------------------------
# did:key (Ed25519)
# ---------------------------------------------------------------------------

_MULTICODEC_ED25519_PREFIX = b"\xed\x01"  # multicodec varint for ed25519-pub
_ED25519_PUBKEY_LEN = 32
_DID_METHOD = "did:key"
_MULTIBASE_BASE58BTC = "z"


def did_for_pubkey(public_key_bytes: bytes) -> str:
    """Build the ``did:key`` identifier for a raw 32-byte Ed25519 public key."""
    if not isinstance(public_key_bytes, (bytes, bytearray)) or len(public_key_bytes) != _ED25519_PUBKEY_LEN:
        raise AgentIdentityError(
            f"Ed25519 public key must be {_ED25519_PUBKEY_LEN} bytes"
        )
    fingerprint = _MULTICODEC_ED25519_PREFIX + bytes(public_key_bytes)
    return f"{_DID_METHOD}:{_MULTIBASE_BASE58BTC}" + base58_encode(fingerprint)


def _pubkey_bytes_for_did(did: str) -> bytes:
    """Parse a DID, recompute the key fingerprint, and return the 32-byte
    Ed25519 public key. Rejects method mismatch, bad multibase, wrong key-type
    prefix, and truncated/padded keys."""
    if not isinstance(did, str):
        raise AgentIdentityError("DID must be a string")
    parts = did.split(":")
    if len(parts) != 3 or parts[0] != "did" or parts[1] != "key":
        raise AgentIdentityError(f"unsupported DID method (expected did:key): {did!r}")
    multibase = parts[2]
    if not multibase.startswith(_MULTIBASE_BASE58BTC):
        raise AgentIdentityError(
            f"unsupported multibase (expected base58btc 'z' prefix): {did!r}"
        )
    fingerprint = base58_decode(multibase[1:])
    if not fingerprint.startswith(_MULTICODEC_ED25519_PREFIX):
        raise AgentIdentityError(
            f"wrong multicodec key-type prefix (expected 0xed01 ed25519-pub): {did!r}"
        )
    key_bytes = fingerprint[len(_MULTICODEC_ED25519_PREFIX):]
    if len(key_bytes) != _ED25519_PUBKEY_LEN:
        raise AgentIdentityError(
            f"Ed25519 public key must be {_ED25519_PUBKEY_LEN} bytes, "
            f"got {len(key_bytes)}: {did!r}"
        )
    return key_bytes


class VerificationMethod(StrictModel):
    id: str
    type: Literal["Ed25519VerificationKey2020"] = "Ed25519VerificationKey2020"
    controller: str
    publicKeyMultibase: str


class DIDDocument(StrictModel):
    id: str
    verificationMethod: list[VerificationMethod]
    authentication: list[str]


def resolve_did(did: str) -> DIDDocument:
    """Resolve a ``did:key`` DID to its DID document.

    Resolution is pure verification: the DID is parsed, the multibase
    fingerprint is decoded, the multicodec prefix and key length are checked,
    and the document is rebuilt from the recovered public key. Anything that
    does not round-trip exactly is rejected — a DID that does not resolve is
    not an identity.
    """
    key_bytes = _pubkey_bytes_for_did(did)
    # Recompute: the DID must be exactly the canonical encoding of its key.
    if did_for_pubkey(key_bytes) != did:
        raise AgentIdentityError(f"DID does not match its key fingerprint: {did!r}")
    method_id = f"{did}#{base58_encode(_MULTICODEC_ED25519_PREFIX + key_bytes)}"
    return DIDDocument(
        id=did,
        verificationMethod=[
            VerificationMethod(
                id=method_id,
                controller=did,
                publicKeyMultibase=_MULTIBASE_BASE58BTC
                + base58_encode(_MULTICODEC_ED25519_PREFIX + key_bytes),
            )
        ],
        authentication=[method_id],
    )


# ---------------------------------------------------------------------------
# Capability assertions (COSE_Sign1 over canonical assertion bytes)
# ---------------------------------------------------------------------------


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


class CapabilityPattern(StrictModel):
    """One claimed capability. ``target_pattern`` is a glob matched against
    the concrete target of a claim:

    * ``*`` matches any run of characters EXCEPT ``/`` (single path segment),
    * ``?`` matches one character except ``/``,
    * ``[...]`` matches one character of the class; ``[!...]`` negates the
      class and additionally never matches ``/``,
    * ``**`` matches anything INCLUDING ``/`` (multi-segment).

    ``*`` deliberately does not cross ``/``: ``/bin/*`` must not cover
    ``/bin/../etc/shadow``. Use ``**`` explicitly for multi-segment scope.

    Patterns longer than ``_MAX_TARGET_PATTERN_LEN`` characters are rejected
    (fail closed): matching is a linear-time engine with no regex
    backtracking, and the bound keeps worst-case evaluation cost
    predictable. Targets longer than ``_MAX_TARGET_LEN`` characters never
    match (fail closed): the ``**``-separated segmentation pass is quadratic
    in the target length, and 4096 characters covers every real-world
    capability target (paths, URLs, object names)."""

    plane: str
    verb: str
    target_pattern: str
    max_spend: float | None = None

    _reject_non_finite_floats = field_validator("*")(classmethod(_finite_float_validator))


class AssertionPayload(StrictModel):
    """The signed claim. ``attester_did`` is the DID whose key signed it:
    the subject itself (self-issued) or a trusted third party."""

    did: str  # subject DID this assertion is about
    capabilities: list[CapabilityPattern]
    issued_at: datetime
    expires_at: datetime
    assertion_id: str
    attester_did: str

    @field_validator("issued_at", "expires_at")
    @classmethod
    def _coerce_utc(cls, v: datetime) -> datetime:
        return _as_utc(v)

    _reject_non_finite_floats = field_validator("*")(classmethod(_finite_float_validator))


def _assertion_canonical_bytes(payload: AssertionPayload) -> bytes:
    """Canonical bytes covered by the COSE signature."""
    return canonical_bytes(payload.model_dump(mode="json"))


def issue_assertion(
    attester: Ed25519Signer,
    attester_did: str,
    subject_did: str,
    capabilities: Sequence[CapabilityPattern],
    *,
    issued_at: datetime | None = None,
    ttl: timedelta = timedelta(hours=1),
    assertion_id: str | None = None,
) -> bytes:
    """Issue a capability assertion as COSE_Sign1 bytes.

    The COSE ``kid`` is the attester's DID (UTF-8 bytes), cryptographically
    binding the signature to the attester's key. ``attester_did`` must resolve
    to the attester's own public key — an assertion whose kid does not match
    the signing key is unverifiable by construction.
    """
    attester_key = _pubkey_bytes_for_did(attester_did)
    if attester_key != attester.public_key_bytes():
        raise AgentIdentityError(
            "attester_did does not resolve to the attester signer's public key"
        )
    _pubkey_bytes_for_did(subject_did)  # validate subject DID up front
    moment = _as_utc(issued_at) if issued_at is not None else datetime.now(timezone.utc)
    payload = AssertionPayload(
        did=subject_did,
        capabilities=list(capabilities),
        issued_at=moment,
        expires_at=moment + ttl,
        assertion_id=assertion_id or f"assert-{uuid.uuid4().hex}",
        attester_did=attester_did,
    )
    return cose_sign_bytes(
        _assertion_canonical_bytes(payload),
        attester.sign_bytes,
        attester_did.encode("utf-8"),
    )


def verify_assertion(
    message: bytes,
    *,
    trusted_attesters: set[str] | frozenset[str] | None = None,
    now: datetime | None = None,
) -> AssertionPayload:
    """Verify a COSE_Sign1 capability assertion and return its payload.

    Checks, in order: COSE structure and algorithm allowlist (via
    ``anchor_v1.cose``), the kid resolves to a real ``did:key`` whose public
    key verifies the signature, the kid equals the payload's ``attester_did``
    (anti-replay under a different DID), the attester is the subject itself
    or a member of ``trusted_attesters``, and the validity window. Any
    failure raises ``AgentIdentityError`` — fail closed.
    """
    trusted = set(trusted_attesters or set())
    try:
        payload_bytes, kid = _verify_with_resolved_kid(message)
    except COSEError as exc:
        raise AgentIdentityError(f"assertion COSE verification failed: {exc}") from exc

    try:
        attester_did = kid.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AgentIdentityError("assertion kid is not a UTF-8 DID") from exc

    try:
        raw = json.loads(payload_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AgentIdentityError(f"assertion payload is not JSON: {exc}") from exc

    try:
        payload = AssertionPayload.model_validate(raw)
    except Exception as exc:
        raise AgentIdentityError(f"assertion payload schema invalid: {exc}") from exc

    # The payload must be exactly the canonical bytes the signature covers —
    # no JSON semantic malleability (duplicate keys, float spellings).
    # canonical_bytes raises a raw ValueError on non-JSON-compliant values
    # (e.g. inf/nan floats): that must surface as AgentIdentityError, never
    # leak raw.
    # canonical_bytes raises a raw ValueError on non-JSON-compliant values
    # (e.g. inf/nan floats): that must surface as AgentIdentityError, never
    # leak raw.
    try:
        canonical_form = canonical_bytes(raw)
    except ValueError as exc:
        raise AgentIdentityError(
            f"assertion payload contains non-JSON-compliant values: {exc}"
        ) from exc
    if canonical_form != payload_bytes:
        raise AgentIdentityError("assertion payload is not in canonical form")

    # kid/DID binding: the signature must come from the attester named inside.
    try:
        if payload.attester_did != attester_did:
            raise AgentIdentityError(
                "assertion kid does not match payload attester_did "
                "(possible DID replay / key substitution)"
            )

        if payload.attester_did != payload.did and payload.attester_did not in trusted:
            raise AgentIdentityError(
                f"third-party attester not in trusted set: {payload.attester_did!r}"
            )

        moment = _as_utc(now) if now is not None else datetime.now(timezone.utc)
        if moment < payload.issued_at:
            raise AgentIdentityError("assertion not yet valid (issued_at in the future)")
        if moment >= payload.expires_at:
            raise AgentIdentityError("assertion expired")
    except AgentIdentityError:
        raise
    except Exception as exc:
        # Fail closed: ANY unexpected validation problem (bad types, bad
        # time values, non-JSON-compliant payload data) is an identity
        # error, never a raw builtin exception.
        raise AgentIdentityError(f"assertion validation failed: {exc}") from exc
    return payload


def _verify_with_resolved_kid(message: bytes) -> tuple[bytes, bytes]:
    """COSE-verify using the public key recovered by resolving the kid DID.

    The kid is resolved (``did:key`` parse + recompute) BEFORE verification,
    so a signature can only verify against the exact key the kid names — an
    assertion signed by a different key than the DID simply cannot verify.
    """
    from anchor_v1.cbor import CBORError, cbor_loads

    try:
        outer = cbor_loads(bytes(message))
    except CBORError as exc:
        raise COSEError(f"malformed COSE_Sign1: {exc}") from exc
    if not isinstance(outer, list) or len(outer) != 4:
        raise COSEError("COSE_Sign1 must be an array of 4 elements")
    body_protected = outer[0]
    if not isinstance(body_protected, bytes):
        raise COSEError("body_protected must be a byte string")
    try:
        protected = cbor_loads(body_protected)
    except CBORError as exc:
        raise COSEError(f"malformed protected header: {exc}") from exc
    kid = protected.get(4) if isinstance(protected, dict) else None
    if not isinstance(kid, bytes) or not kid:
        raise COSEError("protected header must carry a non-empty kid")
    try:
        attester_did = kid.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise COSEError(f"kid is not valid UTF-8: {exc}") from exc
    try:
        key_bytes = _pubkey_bytes_for_did(attester_did)
    except AgentIdentityError as exc:
        raise COSEError(f"kid is not a resolvable did:key DID: {exc}") from exc
    public_key = Ed25519PublicKey.from_public_bytes(key_bytes)
    return cose_verify(message, {kid: public_key}, b"")


# ---------------------------------------------------------------------------
# Discovery registry (in-memory, re-verified on every read)
# ---------------------------------------------------------------------------


class ResolvedIdentity(StrictModel):
    """A registry entry after full re-verification: the DID document plus
    every currently live (signature-valid, unexpired, unrevoked) assertion."""

    did: str
    document: DIDDocument
    assertions: list[AssertionPayload]


class AgentRegistry:
    """In-memory agent discovery registry. Injectable (no I/O, no network).

    ``register`` verifies everything before storing: the DID resolves, the
    stored document matches the DID, each assertion COSE-verifies and names
    the registered DID as its subject. ``resolve`` re-verifies on every read:
    the stored document hash (tamper detection), each assertion's signature
    and expiry, and the revocation set. Revoked assertions never resolve.
    """

    def __init__(self, trusted_attesters: set[str] | frozenset[str] | None = None):
        self._trusted_attesters: set[str] = set(trusted_attesters or set())
        # did -> {"doc": DIDDocument, "doc_hash": str, "assertions": {id: bytes}, "revoked": set[str]}
        self._entries: dict[str, dict] = {}

    @staticmethod
    def _doc_hash(document: DIDDocument) -> str:
        return hashlib.sha256(canonical_bytes(document.model_dump(mode="json"))).hexdigest()

    def register(
        self,
        did: str,
        document: DIDDocument,
        assertions: Sequence[bytes],
        *,
        now: datetime | None = None,
    ) -> None:
        """Verify and store a registry entry. Raises ``AgentIdentityError``
        on any verification failure — nothing unverified is ever stored."""
        try:
            resolved = resolve_did(did)  # DID must parse and round-trip
            if document.id != did or document != resolved:
                raise AgentIdentityError(
                    "registry document does not match the resolved DID document"
                )
            stored: dict[str, bytes] = {}
            for message in assertions:
                payload = verify_assertion(
                    message, trusted_attesters=self._trusted_attesters, now=now
                )
                if payload.did != did:
                    raise AgentIdentityError(
                        "assertion subject does not match the registered DID "
                        "(possible assertion replay under a different DID)"
                    )
                if payload.assertion_id in stored:
                    raise AgentIdentityError(
                        f"duplicate assertion_id in registration: {payload.assertion_id!r}"
                    )
                stored[payload.assertion_id] = bytes(message)
        except AgentIdentityError:
            raise
        except Exception as exc:
            raise AgentIdentityError(f"registration failed: {exc}") from exc
        self._entries[did] = {
            "doc": document,
            "doc_hash": self._doc_hash(document),
            "assertions": stored,
            "revoked": set(),
        }

    def resolve(self, did: str, *, now: datetime | None = None) -> ResolvedIdentity:
        """Return the verified document plus all live assertions.

        Re-verifies everything: the DID still resolves, the stored document
        hash still matches (tamper detection), and every assertion still
        COSE-verifies, is unexpired, and is not revoked. Fail closed.
        """
        if not isinstance(did, str):
            raise AgentIdentityError(f"DID must be a string, got {type(did).__name__}")
        entry = self._entries.get(did)
        if entry is None:
            raise AgentIdentityError(f"unknown DID in registry: {did!r}")
        resolve_did(did)  # DID itself must still be well-formed
        document: DIDDocument = entry["doc"]
        if self._doc_hash(document) != entry["doc_hash"]:
            raise AgentIdentityError(
                "registry entry tampered: stored document hash mismatch"
            )
        live: list[AssertionPayload] = []
        for assertion_id, message in entry["assertions"].items():
            if assertion_id in entry["revoked"]:
                continue  # revoked assertions never resolve
            try:
                payload = verify_assertion(
                    message, trusted_attesters=self._trusted_attesters, now=now
                )
            except AgentIdentityError:
                continue  # expired or otherwise invalid -> not live
            live.append(payload)
        return ResolvedIdentity(did=did, document=document, assertions=live)

    def revoke_assertion(self, assertion_id: str) -> None:
        """Mark an assertion revoked across all entries. Revoked assertions
        never resolve again. Unknown ids raise — silent no-ops hide bugs."""
        if not isinstance(assertion_id, str):
            raise AgentIdentityError(
                f"assertion_id must be a string, got {type(assertion_id).__name__}"
            )
        found = False
        for entry in self._entries.values():
            if assertion_id in entry["assertions"]:
                entry["revoked"].add(assertion_id)
                found = True
        if not found:
            raise AgentIdentityError(f"unknown assertion_id: {assertion_id!r}")

    def __contains__(self, did: object) -> bool:
        return isinstance(did, str) and did in self._entries

    def __len__(self) -> int:
        return len(self._entries)


# ---------------------------------------------------------------------------
# Subject binding: DIDs as ActionEnvelope principals
# ---------------------------------------------------------------------------


def subject_id_for(did: str) -> str:
    """Return the subject id for a DID — the DID string itself.

    The DID is validated (parse + recompute) before use, so only resolvable
    identities can become ``ActionEnvelope.principal`` values.
    """
    resolve_did(did)
    return did


# ---------------------------------------------------------------------------
# Capability target patterns: linear-time glob engine (no regex, no ReDoS)
# ---------------------------------------------------------------------------
#
# The previous implementation translated globs to regexes with nested
# ``[^/]*`` quantifiers, which gave exponential backtracking on patterns
# like ``*a*a*a...`` (12 groups vs a 34-char target exceeded 6s) — a
# CPU-DoS any self-issuing agent could plant. This engine instead compiles
# the pattern to tokens and matches with a single-pass algorithm that keeps
# exactly one star bookmark: matching is O(len(pattern) + len(target)) for
# ``**``-free patterns and O(len(pattern) * len(target)) when ``**``
# segments are present — never exponential in the pattern.
#
# Documented bound: patterns longer than ``_MAX_TARGET_PATTERN_LEN``
# characters are rejected outright (``PatternError`` -> fail closed).
#
# Second documented bound: targets longer than ``_MAX_TARGET_LEN`` never
# match (fail closed). The ``**`` segmentation below scans each segment with
# a leftmost-shortest search that is quadratic in the target length
# (``**a**a**...**b`` vs a 64KB target measured 12.9s — not ReDoS, but a
# real CPU sink a self-issuing agent could plant). Capping the target at
# 4096 characters keeps the worst case at ~(tokens * 4096) character
# comparisons — single-digit milliseconds — while covering every legitimate
# capability target (paths, URLs, object names are all far shorter).
# Length is checked BEFORE tokenizing, so the hostile path is unreachable.

#: Maximum accepted ``target_pattern`` length (see above).
_MAX_TARGET_PATTERN_LEN = 2048

#: Maximum matched capability-target length. Longer targets fail closed
#: (no match) rather than burn CPU in the ``**`` segmentation pass.
_MAX_TARGET_LEN = 4096

# Token kinds: ("lit", ch) matches ch exactly; ("star",) matches any
# (possibly empty) run of non-"/" chars; ("q",) matches one non-"/" char;
# ("cls", frozenset, negate) matches one char by class membership —
# negated classes additionally never match "/"; ("dstar",) matches
# anything including "/".


def _parse_class_body(body: str) -> frozenset[str]:
    """Parse the inside of a ``[...]`` class into an explicit char set.

    Plain glob semantics: literal chars and ``a-z`` ranges. No regex
    escapes. Raises ``PatternError`` on an inverted range (``[z-a]``).
    """
    chars: set[str] = set()
    k, n = 0, len(body)
    while k < n:
        if k + 2 < n and body[k + 1] == "-":
            lo, hi = body[k], body[k + 2]
            if ord(lo) > ord(hi):
                raise PatternError(f"invalid character range {lo!r}-{hi!r} in pattern")
            chars.update(chr(c) for c in range(ord(lo), ord(hi) + 1))
            k += 3
        else:
            chars.add(body[k])
            k += 1
    return frozenset(chars)


def _tokenize_target_pattern(pattern: str) -> list[tuple]:
    """Compile a target pattern to tokens.

    Raises ``PatternError`` when the pattern is not a string, exceeds
    ``_MAX_TARGET_PATTERN_LEN``, or contains an invalid class range. An
    unterminated ``[`` is a literal (as before). Adjacent stars collapse:
    ``**`` absorbs a neighboring ``*`` (``***`` == ``**``).
    """
    if not isinstance(pattern, str):
        raise PatternError("target_pattern must be a string")
    if len(pattern) > _MAX_TARGET_PATTERN_LEN:
        raise PatternError(
            f"target_pattern exceeds maximum length {_MAX_TARGET_PATTERN_LEN}"
        )
    tokens: list[tuple] = []
    i, n = 0, len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "*":
            kind = "dstar" if i + 1 < n and pattern[i + 1] == "*" else "star"
            i += 2 if kind == "dstar" else 1
            if tokens and tokens[-1][0] in ("star", "dstar"):
                if kind == "dstar":
                    tokens[-1] = ("dstar",)
            else:
                tokens.append((kind,))
        elif ch == "?":
            tokens.append(("q",))
            i += 1
        elif ch == "[":
            j = i + 1
            negate = j < n and pattern[j] == "!"
            if negate:
                j += 1
            body_start = j
            if j < n and pattern[j] == "]":  # literal ] as first class char
                j += 1
            k = j
            while k < n and pattern[k] != "]":
                k += 1
            if k >= n:
                tokens.append(("lit", "["))
                i += 1
            else:
                tokens.append(("cls", _parse_class_body(pattern[body_start:k]), negate))
                i = k + 1
        else:
            tokens.append(("lit", ch))
            i += 1
    return tokens


def _token_char_match(tok: tuple, ch: str) -> bool:
    kind = tok[0]
    if kind == "lit":
        return ch == tok[1]
    if kind == "q":
        return ch != "/"
    if kind == "star":
        return ch != "/"
    if kind == "dstar":
        return True
    # ("cls", chars, negate): a negated class never matches "/" either.
    hit = ch in tok[1]
    return (not hit and ch != "/") if tok[2] else hit


def _match_tokens_prefix(toks: list[tuple], target: str, start: int) -> int | None:
    """Match ``toks`` against ``target[start:]`` in a single linear pass.

    Returns the SHORTEST end index ``r`` such that ``toks`` matches
    ``target[start:r]`` exactly, or ``None``. At most one star bookmark is
    kept (extended only forward), so this is O(len(toks) + matched length).
    A segment-bound ``*`` that would have to cross ``/`` fails the match.
    """
    ti, n, pi, m = start, len(target), 0, len(toks)
    star_pi, star_ti, star_kind = -1, start, ""
    while True:
        if pi == m:
            return ti
        if ti >= n:
            break
        kind = toks[pi][0]
        if kind == "star" or kind == "dstar":
            star_pi, star_ti, star_kind = pi, ti, kind
            pi += 1
            continue
        if _token_char_match(toks[pi], target[ti]):
            ti += 1
            pi += 1
            continue
        if star_pi == -1:
            return None
        if star_ti >= n:
            return None
        if star_kind == "star" and target[star_ti] == "/":
            return None
        star_ti += 1
        ti, pi = star_ti, star_pi + 1
    while pi < m and toks[pi][0] in ("star", "dstar"):
        pi += 1
    return ti if pi == m else None


def _match_tokens_full(toks: list[tuple], target: str) -> bool:
    """Full (both-ends-anchored) match in a single linear pass."""
    ti, n, pi, m = 0, len(target), 0, len(toks)
    star_pi, star_ti, star_kind = -1, 0, ""
    while ti < n:
        if pi < m:
            kind = toks[pi][0]
            if kind == "star" or kind == "dstar":
                star_pi, star_ti, star_kind = pi, ti, kind
                pi += 1
                continue
            if _token_char_match(toks[pi], target[ti]):
                ti += 1
                pi += 1
                continue
        if star_pi == -1:
            return False
        if star_ti >= n:
            return False
        if star_kind == "star" and target[star_ti] == "/":
            return False
        star_ti += 1
        ti, pi = star_ti, star_pi + 1
    while pi < m and toks[pi][0] in ("star", "dstar"):
        pi += 1
    return pi == m


def _find_segment(seg: list[tuple], target: str, pos: int) -> int | None:
    """Leftmost-shortest occurrence of ``seg`` at or after ``pos``.

    Tries start positions ``l`` from ``pos`` upward and takes the shortest
    end ``r`` for the first ``l`` that matches. This equals the minimal end
    position overall, which is the greedy choice that keeps a ``**``-split
    match complete (a ``**`` can always absorb the slack).
    """
    for l in range(pos, len(target) + 1):
        r = _match_tokens_prefix(seg, target, l)
        if r is not None:
            return r
    return None


def _match_suffix(seg: list[tuple], target: str, pos: int) -> bool:
    """True iff ``seg`` fully matches some suffix ``target[l:]`` with ``l >= pos``."""
    # Tokens are direction-symmetric, so reverse both sides and reuse the
    # linear prefix matcher: a suffix match becomes a prefix match.
    return (
        _match_tokens_prefix(seg[::-1], target[pos:][::-1], 0) is not None
    )


def _target_matches(pattern: str, target: str) -> bool:
    """Glob-match ``target`` against ``pattern`` without regex backtracking.

    ``**`` spans are handled by splitting the pattern into ``**``-free
    segments matched left to right: the first segment is anchored at the
    start (unless the pattern begins with ``**``), the last at the end
    (unless it ends with ``**``), and each segment takes its minimal end
    position so the surrounding ``**`` spans can absorb the slack. Every
    segment match is a single-pass scan, so there is no backtracking across
    wildcard groups and no ReDoS. Over-long or malformed patterns fail
    closed (``False``); targets longer than ``_MAX_TARGET_LEN`` also fail
    closed (``False``) before matching starts.
    """
    if not isinstance(target, str):
        return False
    if len(target) > _MAX_TARGET_LEN:
        # Fail closed: the **-segmentation pass below is quadratic in the
        # target length; an over-long target can never match.
        return False
    try:
        tokens = _tokenize_target_pattern(pattern)
    except PatternError:
        return False
    if not any(tok[0] == "dstar" for tok in tokens):
        return _match_tokens_full(tokens, target)
    segments: list[list[tuple]] = []
    current: list[tuple] = []
    for tok in tokens:
        if tok[0] == "dstar":
            segments.append(current)
            current = []
        else:
            current.append(tok)
    segments.append(current)
    leading_dstar = not segments[0]
    trailing_dstar = not segments[-1]
    core = [seg for seg in segments if seg]
    if not core:
        return True  # pattern is all "**": matches everything
    pos = 0
    last = len(core) - 1
    for index, seg in enumerate(core):
        if index == 0 and not leading_dstar:
            end = _match_tokens_prefix(seg, target, 0)
            if end is None:
                return False
            pos = end
        elif index == last and not trailing_dstar:
            if not _match_suffix(seg, target, pos):
                return False
            pos = len(target)
        else:
            end = _find_segment(seg, target, pos)
            if end is None:
                return False
            pos = end
    return True


def authorize_capability_claim(
    did: str,
    plane: str,
    verb: str,
    target: str,
    registry: AgentRegistry,
    *,
    now: datetime | None = None,
) -> bool:
    """True iff a live, verified registry assertion covers the claim.

    A claim is covered when some live assertion for ``did`` contains a
    capability with matching ``plane`` and ``verb`` whose ``target_pattern``
    glob-matches ``target``. Returns ``False`` on ANY failure — unknown DID,
    tampered registry, expired/revoked assertions, pattern miss. This is
    subject-authentication input for the governor, NOT a grant: the governor
    still mints the actual capability.
    """
    try:
        identity = registry.resolve(did, now=now)
        if identity.did != did:
            return False
        for payload in identity.assertions:
            if payload.did != did:
                continue  # belt-and-braces: assertion must name this subject
            for cap in payload.capabilities:
                if (
                    cap.plane == plane
                    and cap.verb == verb
                    and _target_matches(cap.target_pattern, target)
                ):
                    return True
        return False
    except Exception:
        # Contract: False on ANY failure — unknown DID, tampered registry,
        # expired/revoked assertions, pattern miss, malformed inputs.
        return False
