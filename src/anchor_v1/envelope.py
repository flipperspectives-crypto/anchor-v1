"""ANCHOR v1 — canonical ActionEnvelope + COSE (Wave 1, Revision B pivot 5).

The ActionEnvelope is the normative protocol object. Everything downstream —
policies, approvals, capabilities, evidence — binds to:

    ActionDigest = SHA-256(canonical_bytes(ActionEnvelope))

where ``canonical_bytes`` is the deterministic-CBOR encoding (RFC 8949) of the
envelope. Envelopes are signed as COSE_Sign1 (RFC 9052) with Ed25519; the
signature covers the Sig_structure, which binds the protected header
(alg + kid) to the exact canonical payload bytes.

This supersedes the v0 ``SignedEnvelope`` (signed canonical-JSON) from
``anchor_v1.models``. See ``migrate_from_signed_envelope`` for the upgrade path.

Wire format notes:

* Times are ISO-8601 UTC strings, UUIDs are canonical string form, the nonce
  is a hex string. All envelope fields encode as CBOR text/UTF-8, so the
  canonical bytes are stable across implementations and platforms.
* Map keys are CBOR text labels sorted by (length, lexicographic) per the
  deterministic encoder, so field insertion order never affects the digest.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import field_validator

from .cbor import CBORError, cbor_dumps, cbor_loads
from .cose import COSEError, cose_sign, cose_sign_bytes, cose_verify
from .crypto import Ed25519Signer
from .models import SignedEnvelope, StrictModel


class EnvelopeError(ValueError):
    """Raised when an ActionEnvelope is malformed, untrusted, or out of window."""


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


class Effect(StrictModel):
    """The exact effect being authorized. The args digest binds the full
    argument set without bloating the envelope."""

    plane: str   # e.g. "shell", "http", "mcp", "a2a", "github"
    verb: str    # e.g. "exec", "post", "call", "delegate"
    target: str  # e.g. command hash, URL, tool name
    args_digest: str  # hex SHA-256 of the canonical argument encoding


class ActionEnvelope(StrictModel):
    """Canonical action envelope. ``action_digest`` is THE binding point for
    policies, approvals, and capabilities."""

    action_id: UUID
    principal: str          # subject id (upstream identity: SPIFFE/OIDC sub, ...)
    effect: Effect
    policy_ref: str         # constitution version hash that governed issuance
    issued_at: datetime
    not_before: datetime
    not_after: datetime
    nonce: str              # unique per envelope; replay protection

    @field_validator("issued_at", "not_before", "not_after")
    @classmethod
    def _coerce_utc(cls, v: datetime) -> datetime:
        return _as_utc(v)

    def canonical_bytes(self) -> bytes:
        """Deterministic CBOR encoding of the envelope. Stable across
        implementations: same logical envelope -> same bytes -> same digest."""
        return cbor_dumps(self.model_dump(mode="json"))

    @property
    def action_digest(self) -> str:
        """SHA-256 hex of the canonical bytes. This digest is what policies,
        approvals, and capabilities bind to."""
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def sign_envelope(self, signer: Ed25519Signer, *, external_aad: bytes = b"") -> bytes:
        """Sign this envelope, returning COSE_Sign1 bytes.

        The signer's ``key_id`` becomes the COSE ``kid`` (UTF-8 bytes).
        """
        # Ed25519Signer.sign_bytes() signs the COSE Sig_structure bytes
        # directly (the signature covers Sig_structure, not canonical JSON).
        return cose_sign_bytes(
            self.canonical_bytes(),
            signer.sign_bytes,
            signer.key_id.encode("utf-8"),
            external_aad,
        )

    @classmethod
    def verify_envelope(
        cls,
        data: bytes,
        trusted_keys: Mapping[str, bytes],
        *,
        now: datetime | None = None,
        external_aad: bytes = b"",
    ) -> "ActionEnvelope":
        """Verify COSE_Sign1 bytes and return the ActionEnvelope.

        ``trusted_keys`` maps key-id strings to raw 32-byte Ed25519 public
        keys. Raises EnvelopeError if the COSE structure, algorithm, kid,
        signature, envelope schema, or validity window fails.
        """
        try:
            pubkeys = {
                kid.encode("utf-8"): Ed25519PublicKey.from_public_bytes(raw)
                for kid, raw in trusted_keys.items()
            }
        except (ValueError, TypeError) as exc:
            raise EnvelopeError(f"bad trusted key material: {exc}") from exc

        try:
            payload, _kid = cose_verify(data, pubkeys, external_aad)
        except COSEError as exc:
            raise EnvelopeError(str(exc)) from exc

        try:
            raw_envelope = cbor_loads(payload)
        except CBORError as exc:
            raise EnvelopeError(f"envelope payload is not valid CBOR: {exc}") from exc

        try:
            envelope = cls.model_validate(raw_envelope)
        except Exception as exc:
            raise EnvelopeError(f"envelope schema invalid: {exc}") from exc

        moment = _as_utc(now) if now is not None else datetime.now(timezone.utc)
        if moment < envelope.not_before:
            raise EnvelopeError("envelope not yet valid (not_before in the future)")
        if moment > envelope.not_after:
            raise EnvelopeError("envelope expired (not_after in the past)")
        return envelope


# ---------------------------------------------------------------------------
# v0 -> v1 migration
# ---------------------------------------------------------------------------

_MIGRATION_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "https://anchor.dev/action-envelope/v1")


def migrate_from_signed_envelope(se: SignedEnvelope) -> ActionEnvelope:
    """Upgrade a v0 ``SignedEnvelope`` (signed canonical JSON) to an
    ``ActionEnvelope``.

    Mapping (documented, best-effort — v0 payloads were free-form dicts):

    * ``action_id``: deterministic UUIDv5 over the canonical JSON bytes of the
      v0 payload, so the same v0 envelope always migrates to the same id.
    * ``principal``: ``payload["subject"]`` / ``payload["principal"]``, else
      the v0 ``key_id`` (the signer that vouched for it).
    * ``effect``: ``payload["effect"]`` verbatim when it is a dict with the
      four fields; otherwise a synthesized shell-plane placeholder whose
      ``args_digest`` is the SHA-256 of the v0 canonical payload bytes, so no
      information is silently dropped.
    * ``policy_ref``: ``payload["constitution"]`` / ``payload["policy_ref"]``,
      else ``"v0:unknown"`` — migrated envelopes are explicitly marked.
    * ``issued_at``: parsed from ``payload["issued_at"]`` when present, else
      now. ``not_before`` = issued_at (or payload override); ``not_after`` =
      issued_at + 1h (or payload override).
    * ``nonce``: ``payload["nonce"]`` when present, else the v0 signature
      (unique per signature).

    The returned envelope is UNSIGNED. The v0 signature covered canonical JSON,
    not canonical CBOR, so it cannot transfer: a v1 authority must re-issue
    (re-sign) the migrated envelope. ``verify_envelope`` will never accept a
    v0 JSON blob — cross-protocol verification is rejected by construction.
    """
    from .canonical import canonical_bytes as _v0_canonical

    payload: dict[str, Any] = dict(se.payload)
    v0_bytes = _v0_canonical(payload)

    action_id = uuid.uuid5(_MIGRATION_NAMESPACE, v0_bytes.hex())

    principal = payload.get("subject") or payload.get("principal") or se.key_id

    raw_effect = payload.get("effect")
    if isinstance(raw_effect, dict) and {"plane", "verb", "target", "args_digest"} <= set(raw_effect):
        effect = Effect(**{k: raw_effect[k] for k in ("plane", "verb", "target", "args_digest")})
    else:
        effect = Effect(
            plane="v0-migrated",
            verb="migrated",
            target=str(payload.get("action", "unknown")),
            args_digest=hashlib.sha256(v0_bytes).hexdigest(),
        )

    policy_ref = payload.get("constitution") or payload.get("policy_ref") or "v0:unknown"

    def _parse_time(value: Any) -> datetime | None:
        if isinstance(value, datetime):
            return _as_utc(value)
        if isinstance(value, str):
            try:
                return _as_utc(datetime.fromisoformat(value))
            except ValueError:
                return None
        return None

    issued_at = _parse_time(payload.get("issued_at")) or datetime.now(timezone.utc)
    not_before = _parse_time(payload.get("not_before")) or issued_at
    not_after = _parse_time(payload.get("not_after")) or (issued_at + timedelta(hours=1))

    nonce = str(payload.get("nonce") or se.signature)

    return ActionEnvelope(
        action_id=action_id,
        principal=str(principal),
        effect=effect,
        policy_ref=str(policy_ref),
        issued_at=issued_at,
        not_before=not_before,
        not_after=not_after,
        nonce=nonce,
    )
