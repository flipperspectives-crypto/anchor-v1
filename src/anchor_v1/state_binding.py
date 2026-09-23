"""ANCHOR v1 — state-bound Prepare/Commit (Wave 4, TOCTOU defense).

The TOCTOU problem: a capability authorizes an ACTION, but the authority's
decision depended on STATE (balances, flags, counters) at mint time. Between
mint and execution that state can change, and the action then executes
against stale assumptions — the classic time-of-check/time-of-use race.

The defense is a Prepare/Commit protocol with the state bound into the
authorization:

* **Prepare** (``prepare``): reads the current state snapshot, runs the
  deployment's policy function against it, and returns a signed
  :class:`EffectPreview` — what the authority *would* allow, the exact
  state version/digest the decision read, the projected outcome, and the
  planned state writes. The preview is Ed25519-signed by the authority, so
  it cannot be forged or altered.
* **Commit** (``commit``): atomically — inside ONE store transaction —
  (a) verifies the preview signature, expiry, and envelope binding,
  (b) runs the full capability consumption (verify + revocation + holder
  proof + one-use flip), (c) re-checks that the live state version AND
  digest still equal the preview's binding, and (d) applies the preview's
  planned writes with a version bump. If the state moved between prepare
  and commit, the commit raises :class:`StateChangedError` and NOTHING is
  consumed or written — fail closed.

Because the state check, the capability consumption, and the writes happen
in a single linearizable transaction, there is no window in which the
state can change between the check and the effect. The deployment's real
side effects (subprocess, egress) run through the PEP only after a
successful commit.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Mapping

from pydantic import Field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from anchor_v1.canonical import canonical_bytes, sha256_hex
from anchor_v1.crypto import Ed25519Signer
from anchor_v1.envelope import ActionEnvelope
from anchor_v1.models import StrictModel

__all__ = [
    "EffectPreview",
    "PolicyDecision",
    "StateBindingError",
    "StateChangedError",
    "StatePolicyDenied",
    "StateView",
    "commit",
    "prepare",
    "preview_signature_bytes",
]


class StateBindingError(ValueError):
    """Base error for state-bound prepare/commit failures (fail closed)."""


class StateChangedError(StateBindingError):
    """The state moved between prepare and commit: commit refused, nothing
    consumed, nothing written."""


class StatePolicyDenied(StateBindingError):
    """The policy function denied the action at prepare time."""


class StateView(StrictModel):
    """A point-in-time snapshot of governance-relevant state."""

    version: int = Field(ge=0)
    digest: str = Field(min_length=64, max_length=64)
    values: dict[str, Any] = Field(default_factory=dict)


class PolicyDecision(StrictModel):
    """The deployment policy's verdict on (state, action)."""

    allowed: bool
    outcome: dict[str, Any] = Field(default_factory=dict)
    planned_writes: dict[str, Any] = Field(default_factory=dict)


class EffectPreview(StrictModel):
    """Signed authority preview of an effect against a state snapshot.

    ``signature`` covers every field except itself (Ed25519, canonical
    bytes); ``authority_key_id`` names the signing key. The preview binds
    the exact state (``state_version`` + ``state_digest``) the policy
    decision read, so ``commit`` can re-verify nothing changed.
    """

    preview_id: str = Field(min_length=1)
    envelope_digest: str = Field(min_length=64, max_length=64)
    state_version: int = Field(ge=0)
    state_digest: str = Field(min_length=64, max_length=64)
    read_keys: tuple[str, ...] = Field(default_factory=tuple)
    outcome: dict[str, Any] = Field(default_factory=dict)
    planned_writes: dict[str, Any] = Field(default_factory=dict)
    allowed: bool = False
    previewed_at: datetime
    expires_at: datetime
    authority_key_id: str = Field(min_length=1)
    signature: str = Field(default="")

    def is_expired(self, now: datetime) -> bool:
        moment = now if now.tzinfo is not None else now.replace(tzinfo=timezone.utc)
        return moment >= self.expires_at


def preview_signature_bytes(preview: EffectPreview) -> bytes:
    """Canonical bytes the authority signs (all fields except ``signature``)."""
    data = preview.model_dump(mode="json")
    data.pop("signature", None)
    return canonical_bytes(data)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def prepare(
    store: Any,
    *,
    envelope: ActionEnvelope,
    read_keys: list[str],
    policy_fn: Callable[[dict[str, Any], ActionEnvelope], PolicyDecision],
    authority_signer: Ed25519Signer,
    ttl_seconds: int = 60,
    now: datetime | None = None,
) -> EffectPreview:
    """Prepare an effect: snapshot state, run policy, return a signed preview.

    ``policy_fn`` receives ``(state_values, envelope)`` and returns a
    :class:`PolicyDecision`. The preview records the decision, the state it
    was based on, and the planned writes — all signed by the authority.
    Raises :class:`StatePolicyDenied` if the policy denies (no preview is
    returned for a denied action: there is nothing to commit).
    """
    if not read_keys:
        raise StateBindingError("prepare requires at least one read key")
    if ttl_seconds <= 0:
        raise StateBindingError("preview ttl_seconds must be positive")
    moment = now if now is not None else _utcnow()
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)

    view: StateView = store.read_state(read_keys)
    decision = policy_fn(dict(view.values), envelope)
    if not isinstance(decision, PolicyDecision):
        raise StateBindingError("policy_fn must return a PolicyDecision")
    if not decision.allowed:
        raise StatePolicyDenied(
            f"policy denied action {envelope.action_digest[:16]}… against "
            f"state v{view.version}"
        )

    preview = EffectPreview(
        preview_id=f"preview_{secrets.token_hex(12)}",
        envelope_digest=envelope.action_digest,
        state_version=view.version,
        state_digest=view.digest,
        read_keys=tuple(read_keys),
        outcome=dict(decision.outcome),
        planned_writes=dict(decision.planned_writes),
        allowed=True,
        previewed_at=moment,
        expires_at=moment + timedelta(seconds=ttl_seconds),
        authority_key_id=authority_signer.key_id,
    )
    signature = authority_signer.sign_bytes(preview_signature_bytes(preview))
    return preview.model_copy(update={"signature": signature.hex()})


def verify_preview_signature(
    preview: EffectPreview,
    trusted_keys: Mapping[bytes, Ed25519PublicKey],
) -> None:
    """Verify the preview's authority signature. Raises on any failure."""
    if not preview.signature:
        raise StateBindingError("preview is not signed")
    try:
        raw_sig = bytes.fromhex(preview.signature)
    except ValueError as exc:
        raise StateBindingError(f"preview signature is not hex: {exc}") from exc
    if len(raw_sig) != 64:
        raise StateBindingError("preview signature must be 64 bytes")
    key = trusted_keys.get(preview.authority_key_id.encode("utf-8"))
    if key is None:
        raise StateBindingError(
            f"preview authority {preview.authority_key_id!r} is not trusted"
        )
    try:
        key.verify(raw_sig, preview_signature_bytes(preview))
    except InvalidSignature as exc:
        raise StateBindingError(
            f"preview signature invalid: {exc}"
        ) from exc


def commit(
    store: Any,
    *,
    envelope: ActionEnvelope,
    capability_cose: bytes,
    holder_proof: bytes,
    challenge: bytes,
    trusted_issuers: Mapping[bytes, Ed25519PublicKey],
    preview: EffectPreview,
    preview_trusted_keys: Mapping[bytes, Ed25519PublicKey],
    now: datetime | None = None,
) -> dict[str, Any]:
    """Commit a prepared effect: consume the capability and apply the state
    transition atomically, or refuse.

    Fail-closed ordering: (1) preview signature/expiry/envelope binding are
    verified statelessly; (2) inside ONE store transaction the capability is
    consumed (full existing checks), the live state version+digest are
    re-verified against the preview's binding, the planned writes are
    applied, and the state version is bumped. Any failure — including
    :class:`StateChangedError` when the state moved — rolls everything
    back: the capability stays ISSUED and no writes land.
    """
    moment = now if now is not None else _utcnow()
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)

    # (1) stateless preview checks — no state touched yet.
    verify_preview_signature(preview, preview_trusted_keys)
    if preview.is_expired(moment):
        raise StateBindingError("preview has expired")
    if not preview.allowed:
        raise StateBindingError("preview was not allowed")
    if preview.envelope_digest != envelope.action_digest:
        raise StateBindingError(
            "preview is bound to a different envelope/action_digest"
        )

    # (2) atomic commit inside the store.
    return store.commit_state_bound(
        envelope=envelope,
        capability_cose=capability_cose,
        holder_proof=holder_proof,
        challenge=challenge,
        trusted_issuers=trusted_issuers,
        preview=preview,
        now=moment,
    )
