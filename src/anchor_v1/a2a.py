"""ANCHOR v1 — A2A 1.0 delegation propagation (Wave 3, Revision B pivot 14).

Two layers live here:

* **Agent cards** — legacy ``build_agent_card`` / ``verify_agent_card``
  (moved verbatim from ``anchor_v1.planes`` during the Wave 3 reframe;
  re-exported by ``planes``), plus the NEW verifiable card:
  ``build_anchored_agent_card`` / ``verify_anchored_agent_card``.
* **Cross-agent delegation** — ``propagate_delegation`` /
  ``receive_delegation``.

The verifiable card follows the A2A Agent Card extension pattern: a
``capabilities`` block and a ``securitySchemes`` block declaring ANCHOR
enforcement, plus a verifiable ``anchor`` section carrying the guardian key
id and the policy ref. The anchor section is signed by the GUARDIAN key
(the authority asserting "this agent is governed"), not just by the agent's
own DID key — a card is trusted ONLY if the anchor section signature
verifies under a trusted guardian key. Unsigned or spoofed anchor sections
-> untrusted, fail closed.

Cross-agent delegation packages carry:

* ``principal`` — the subject the delegation ultimately serves,
* the delegation ``chain`` (``delegation_chains.py`` receipts, root-first),
* the ``mandate`` capability (authority-signed, holder = the delegator),
* a one-use ``child`` execution capability minted from the mandate via
  ``authority.mint_child`` — monotonic attenuation enforced at mint time
  (child scope provably ⊆ parent; amplification rejected structurally).

The receiving agent verifies the FULL chain offline before accepting
(``receive_delegation``): chain signatures + custody + hash links + the
asor-wimse narrowing invariant re-verified at every hop, the mandate's
authority signature, the child's parent binding (no scope broadening via
capability swap), the receiver binding (holder key + addressed key id),
the envelope digest binding, and the revocation view (a delegation from a
revoked mandate is rejected). Any failure -> ``DelegationRejected``.

Local only. No network calls.
"""

from __future__ import annotations

import base64
import secrets
from collections.abc import Collection, Mapping
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import Field, field_validator

from . import authority
from .authority import CapabilityError, KIND_EXECUTION, KIND_MANDATE
from .canonical import canonical_bytes
from .crypto import Ed25519Signer, public_key_from_b64, verify_envelope
from .delegation_chains import (
    DelegationError,
    DelegationReceipt,
    DelegationScope,
    VerifiedDelegationChain,
    verify_chain,
)
from .envelope import ActionEnvelope
from .models import SignedEnvelope, StrictModel
from .planes import SUPPORTED_PLANES

__all__ = [
    # legacy card API (moved from planes.py; re-exported there)
    "CardVerificationError",
    "EnforcementDeclaration",
    "AgentCardBody",
    "build_agent_card",
    "verify_agent_card",
    # verifiable anchored card
    "AnchorSection",
    "AnchoredAgentCard",
    "build_anchored_agent_card",
    "verify_anchored_agent_card",
    # cross-agent delegation propagation
    "DelegationPropagationError",
    "DelegationRejected",
    "DelegationPackage",
    "VerifiedDelegation",
    "propagate_delegation",
    "receive_delegation",
]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _require_aware_utc(value: datetime, field_name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value.astimezone(timezone.utc)


class CardVerificationError(ValueError):
    """Raised when an A2A agent card fails verification. Fail closed."""


# ---------------------------------------------------------------------------
# Legacy A2A enforcement declaration — moved verbatim from anchor_v1.planes
# ---------------------------------------------------------------------------


class EnforcementDeclaration(StrictModel):
    """The ``anchor_enforcement`` extension block of an A2A Agent Card."""

    governor_key: str = Field(description="base64 of the governor decision key (32 raw bytes)")
    planes: list[str] = Field(min_length=1)
    constitution_hash: str = Field(min_length=1)
    decision_verify_hint: str = Field(min_length=1)

    @field_validator("governor_key")
    @classmethod
    def _valid_pubkey(cls, v: str) -> str:
        raw = public_key_from_b64(v)
        if len(raw) != 32:
            raise ValueError("governor_key must decode to 32 bytes (raw Ed25519)")
        return v


class AgentCardBody(StrictModel):
    """Signed body of an ANCHOR-governed A2A agent card."""

    agent_id: str = Field(min_length=1)
    did: str = Field(min_length=1)
    anchor_enforcement: EnforcementDeclaration
    issued_at: datetime

    @field_validator("issued_at")
    @classmethod
    def _tz_aware(cls, v: datetime) -> datetime:
        return _require_aware_utc(v, "issued_at")


_DECISION_VERIFY_HINT = (
    "anchor_v1.planes.verify_decision(signed_envelope, "
    "base64.b64decode(anchor_enforcement.governor_key))"
)


def build_agent_card(
    agent_id: str,
    did: str,
    governor_pubkey: bytes,
    enforced_planes: list[str],
    policy_digest: str,
    *,
    agent_signer: Ed25519Signer,
    issued_at: datetime | None = None,
) -> dict[str, Any]:
    """Build an A2A agent card declaring ANCHOR enforcement, signed by the
    agent's DID key.

    ``enforced_planes`` must be a subset of SUPPORTED_PLANES — a card cannot
    claim enforcement the governor vocabulary does not define.
    """
    planes = sorted(set(enforced_planes))
    if not planes:
        raise ValueError("enforced_planes must be non-empty")
    unknown = [p for p in planes if p not in SUPPORTED_PLANES]
    if unknown:
        raise ValueError(f"enforced_planes contains unsupported planes: {unknown}")
    if len(governor_pubkey) != 32:
        raise ValueError("governor_pubkey must be 32 raw Ed25519 bytes")
    body = AgentCardBody(
        agent_id=agent_id,
        did=did,
        anchor_enforcement=EnforcementDeclaration(
            governor_key=base64.b64encode(governor_pubkey).decode("ascii"),
            planes=planes,
            constitution_hash=policy_digest,
            decision_verify_hint=_DECISION_VERIFY_HINT,
        ),
        issued_at=_require_aware_utc(issued_at or _utcnow(), "issued_at"),
    )
    envelope = agent_signer.sign_payload(body.model_dump(mode="json"))
    card = body.model_dump(mode="json")
    card["signature"] = envelope.model_dump(mode="json")
    return card


def verify_agent_card(
    card: dict[str, Any],
    *,
    trusted_dids: dict[str, bytes],
    supported_planes: set[str] | None = None,
    known_constitution_hashes: set[str] | None = None,
) -> AgentCardBody:
    """Verify an A2A agent card BEFORE delegating to the counterparty.

    Checks: (1) the card's Ed25519 signature verifies under the agent's DID key
    (the DID must resolve through ``trusted_dids``); (2) the declared planes
    are a subset of the planes the governor actually enforces — over-claims
    fail; (3) the declared constitution hash resolves against the set the
    verifier knows the governor to enforce under.
    """
    raw_sig = card.get("signature")
    if not isinstance(raw_sig, dict):
        raise CardVerificationError("card has no signature block")
    try:
        envelope = SignedEnvelope.model_validate(raw_sig)
    except Exception as exc:
        raise CardVerificationError(f"malformed card signature: {exc}") from exc
    did = card.get("did")
    if not isinstance(did, str) or not did:
        raise CardVerificationError("card has no did")
    did_pubkey = trusted_dids.get(did)
    if did_pubkey is None:
        raise CardVerificationError(f"untrusted DID: {did!r}")
    try:
        payload = verify_envelope(envelope, did_pubkey)
    except Exception as exc:
        raise CardVerificationError(f"card signature invalid: {exc}") from exc
    # The signature binds the body: the presented card must be byte-identical
    # (as a dict) to what was signed, or outer-field tampering goes unnoticed.
    presented = {k: v for k, v in card.items() if k != "signature"}
    if presented != payload:
        raise CardVerificationError("card body does not match signed content")
    try:
        body = AgentCardBody.model_validate(payload)
    except Exception as exc:
        raise CardVerificationError(f"card body malformed: {exc}") from exc
    if body.did != did:
        raise CardVerificationError("signed did does not match card did")
    allowed = supported_planes if supported_planes is not None else set(SUPPORTED_PLANES)
    overclaimed = [p for p in body.anchor_enforcement.planes if p not in allowed]
    if overclaimed:
        raise CardVerificationError(
            f"card over-claims enforcement on unsupported planes: {overclaimed}"
        )
    if known_constitution_hashes is not None:
        if body.anchor_enforcement.constitution_hash not in known_constitution_hashes:
            raise CardVerificationError(
                "card constitution hash does not resolve to a known governed version"
            )
    return body


# ---------------------------------------------------------------------------
# Verifiable anchored agent card (Wave 3)
# ---------------------------------------------------------------------------


class AnchorSection(StrictModel):
    """The verifiable ``anchor`` section of an A2A agent card.

    Signed by the GUARDIAN key — the authority asserting that this agent is
    ANCHOR-governed under ``policy_ref``. Trust flows from the guardian
    signature, never from the agent's self-assertion.
    """

    guardian_key_id: str = Field(min_length=1)
    guardian_pubkey: str = Field(
        min_length=1,
        description="base64 of the guardian Ed25519 public key (32 raw bytes)",
    )
    policy_ref: str = Field(min_length=1)
    enforced_planes: list[str] = Field(min_length=1)
    decision_verify_hint: str = Field(min_length=1)
    issued_at: datetime

    @field_validator("guardian_pubkey")
    @classmethod
    def _valid_pubkey(cls, v: str) -> str:
        raw = public_key_from_b64(v)
        if len(raw) != 32:
            raise ValueError("guardian_pubkey must decode to 32 bytes (raw Ed25519)")
        return v

    @field_validator("enforced_planes")
    @classmethod
    def _known_planes(cls, v: list[str]) -> list[str]:
        unknown = [p for p in v if p not in SUPPORTED_PLANES]
        if unknown:
            raise ValueError(f"enforced_planes contains unknown planes: {unknown}")
        return sorted(set(v))

    @field_validator("issued_at")
    @classmethod
    def _tz_aware(cls, v: datetime) -> datetime:
        return _require_aware_utc(v, "issued_at")


class AnchoredAgentCard(StrictModel):
    """A2A agent card with ANCHOR enforcement declared and guardian-verified.

    ``capabilities`` / ``securitySchemes`` follow the A2A Agent Card
    extension pattern; ``anchor`` is the guardian-signed enforcement
    section and ``anchor_signature`` its Ed25519 signature over the
    canonical section bytes.
    """

    agent_id: str = Field(min_length=1)
    did: str = Field(min_length=1)
    capabilities: dict[str, Any]
    securitySchemes: dict[str, Any]
    anchor: AnchorSection
    anchor_signature: str = Field(
        min_length=1,
        description="base64 Ed25519 signature over the canonical anchor "
        "section bytes, by the guardian key",
    )


_ANCHORED_DECISION_VERIFY_HINT = (
    "anchor_v1.a2a.verify_anchored_agent_card(card, "
    "trusted_guardians={<guardian_key_id>: <32 raw bytes>})"
)


def build_anchored_agent_card(
    agent_id: str,
    did: str,
    *,
    guardian_signer: Ed25519Signer,
    policy_ref: str,
    enforced_planes: list[str],
    capabilities: dict[str, Any] | None = None,
    security_schemes: dict[str, Any] | None = None,
    issued_at: datetime | None = None,
) -> dict[str, Any]:
    """Build an A2A agent card declaring ANCHOR enforcement.

    The ``anchor`` section (guardian key id + policy ref + enforced planes)
    is signed by the GUARDIAN key — ``guardian_signer`` is the authority
    asserting governance, and its ``key_id`` becomes the card's
    ``guardian_key_id``. ``capabilities``/``security_schemes`` accept
    caller-supplied extension entries merged over the ANCHOR defaults.
    """
    planes = sorted(set(enforced_planes))
    if not planes:
        raise ValueError("enforced_planes must be non-empty")
    unknown = [p for p in planes if p not in SUPPORTED_PLANES]
    if unknown:
        raise ValueError(f"enforced_planes contains unknown planes: {unknown}")
    if not policy_ref:
        raise ValueError("policy_ref is required")
    section = AnchorSection(
        guardian_key_id=guardian_signer.key_id,
        guardian_pubkey=guardian_signer.public_key_b64(),
        policy_ref=policy_ref,
        enforced_planes=planes,
        decision_verify_hint=_ANCHORED_DECISION_VERIFY_HINT,
        issued_at=_require_aware_utc(issued_at or _utcnow(), "issued_at"),
    )
    signature = guardian_signer.sign_bytes(
        canonical_bytes(section.model_dump(mode="json"))
    )
    merged_capabilities: dict[str, Any] = {
        "anchor": {
            "enforced": True,
            "planes": planes,
            "policy_ref": policy_ref,
            "capability": "holder-of-key-one-use",
        }
    }
    if capabilities:
        merged_capabilities.update(capabilities)
    merged_schemes: dict[str, Any] = {
        "anchorCapability": {
            "type": "holderOfKey",
            "description": (
                "One-use holder-of-key capabilities minted under the "
                "guardian's policy; presented with proof-of-possession "
                "per call. No bearer tokens."
            ),
        }
    }
    if security_schemes:
        merged_schemes.update(security_schemes)
    card = AnchoredAgentCard(
        agent_id=agent_id,
        did=did,
        capabilities=merged_capabilities,
        securitySchemes=merged_schemes,
        anchor=section,
        anchor_signature=base64.b64encode(signature).decode("ascii"),
    )
    return card.model_dump(mode="json")


def verify_anchored_agent_card(
    card: dict[str, Any],
    *,
    trusted_guardians: Mapping[str, bytes],
) -> AnchoredAgentCard:
    """Verify an anchored A2A agent card BEFORE delegating.

    The card is trusted ONLY if its ``anchor`` section carries a signature
    that verifies under a trusted guardian key id. Unsigned anchor sections
    (missing/empty signature), unknown guardian key ids, guardian pubkey
    substitution, and tampered sections (e.g. a rewritten ``policy_ref``)
    all raise ``CardVerificationError`` — the card is untrusted, fail closed.
    """
    if not isinstance(card, dict):
        raise CardVerificationError("card must be a mapping")
    raw_section = card.get("anchor")
    raw_signature = card.get("anchor_signature")
    if not isinstance(raw_section, dict) or not raw_signature:
        raise CardVerificationError("unsigned anchor section — card is untrusted")
    try:
        section = AnchorSection.model_validate(raw_section)
    except Exception as exc:
        raise CardVerificationError(f"anchor section malformed: {exc}") from exc
    trusted_pubkey = trusted_guardians.get(section.guardian_key_id)
    if trusted_pubkey is None:
        raise CardVerificationError(
            f"anchor guardian key id {section.guardian_key_id!r} is not trusted"
        )
    if bytes(public_key_from_b64(section.guardian_pubkey)) != bytes(trusted_pubkey):
        raise CardVerificationError(
            "anchor guardian pubkey does not match the trusted key "
            "(key substitution rejected)"
        )
    if not isinstance(raw_signature, str):
        raise CardVerificationError("anchor signature must be a base64 string")
    try:
        signature = base64.b64decode(raw_signature, validate=True)
    except Exception as exc:
        raise CardVerificationError(
            f"anchor signature is not valid base64: {exc}"
        ) from exc
    key = Ed25519PublicKey.from_public_bytes(bytes(trusted_pubkey))
    try:
        key.verify(signature, canonical_bytes(section.model_dump(mode="json")))
    except InvalidSignature as exc:
        raise CardVerificationError(
            "anchor section signature invalid — card is untrusted"
        ) from exc
    try:
        return AnchoredAgentCard.model_validate(card)
    except Exception as exc:
        raise CardVerificationError(f"card body malformed: {exc}") from exc


# ---------------------------------------------------------------------------
# Cross-agent delegation propagation
# ---------------------------------------------------------------------------


class DelegationPropagationError(ValueError):
    """Raised when a delegation package cannot be built. Fail closed."""


class DelegationRejected(ValueError):
    """Raised by the receiving agent on ANY delegation verification failure.
    Fail closed — the delegation is not accepted."""


class DelegationPackage(StrictModel):
    """What crosses the wire from the delegating agent to the delegatee.

    Carries the principal, the delegation chain (root-first receipt
    envelopes), the mandate capability (authority-signed, holder = the
    delegator), the one-use child execution capability minted from it, and
    the exact action envelope the delegatee may execute. Capabilities are
    hex-encoded COSE_Sign1 bytes.
    """

    principal: str = Field(min_length=1)
    delegatee_key_id: str = Field(min_length=1)
    chain: list[dict[str, Any]] = Field(min_length=1)
    mandate_capability_hex: str = Field(min_length=1)
    child_capability_hex: str = Field(min_length=1)
    action_envelope: dict[str, Any]
    action_digest: str = Field(min_length=64, max_length=64)
    propagated_at: datetime

    @field_validator("propagated_at")
    @classmethod
    def _tz_aware(cls, v: datetime) -> datetime:
        return _require_aware_utc(v, "propagated_at")


class VerifiedDelegation(StrictModel):
    """What the receiving agent holds after accepting a delegation."""

    principal: str
    delegatee_key_id: str
    effective_scope: DelegationScope
    chain: VerifiedDelegationChain
    mandate_id: str
    child_capability_id: str
    action_digest: str


def _coerce_pubkey(raw: Any, key_id: str) -> bytes:
    if isinstance(raw, (bytes, bytearray)):
        out = bytes(raw)
    elif isinstance(raw, str):
        try:
            out = base64.b64decode(raw, validate=True)
        except Exception as exc:
            raise DelegationRejected(
                f"public key for {key_id!r} is not valid base64"
            ) from exc
    else:
        raise DelegationRejected(
            f"public key for {key_id!r} has unsupported type {type(raw).__name__}"
        )
    if len(out) != 32:
        raise DelegationRejected(f"public key for {key_id!r} is not 32 bytes")
    return out


def propagate_delegation(
    *,
    principal: str,
    chain_envelopes: list[SignedEnvelope],
    mandate_cose: bytes,
    holder_signer: Ed25519Signer,
    trusted_issuers: Mapping[bytes, Ed25519PublicKey],
    delegatee_key_id: str,
    delegatee_pubkey: bytes,
    action_envelope: ActionEnvelope,
    spend_limit: int | None = None,
    ttl: timedelta = timedelta(minutes=15),
    now: datetime | None = None,
) -> DelegationPackage:
    """Build a cross-agent delegation package (delegator side).

    Verifies the mandate capability (must be kind ``"mandate"`` — execution
    capabilities are non-delegable), checks the holder really is the mandate
    holder, binds the exact action envelope to the mandate's digest, then
    mints a one-use child execution capability for the delegatee via
    ``authority.mint_child`` — monotonic attenuation enforced at mint time.

    The chain itself is NOT re-verified here; the receiving agent verifies
    the full chain offline before accepting (``receive_delegation``).
    """
    moment = _utcnow() if now is None else now
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    if not principal:
        raise DelegationPropagationError("principal is required")
    if not delegatee_key_id:
        raise DelegationPropagationError("delegatee_key_id is required")
    if len(bytes(delegatee_pubkey)) != 32:
        raise DelegationPropagationError("delegatee_pubkey must be 32 raw bytes")
    if not chain_envelopes:
        raise DelegationPropagationError("chain_envelopes must be non-empty")

    try:
        mandate = authority.verify_capability(
            bytes(mandate_cose), trusted_issuers, now=moment
        )
    except CapabilityError as exc:
        raise DelegationPropagationError(
            f"mandate capability invalid: {exc}"
        ) from exc
    if mandate.kind != KIND_MANDATE:
        raise DelegationPropagationError(
            f"cannot propagate delegation: capability kind is {mandate.kind!r}, "
            "not 'mandate' (execution capabilities are non-delegable)"
        )
    if bytes(mandate.holder_pubkey) != holder_signer.public_key_bytes():
        raise DelegationPropagationError(
            "holder_signer is not the mandate holder — only the holder may "
            "propagate delegation from this mandate"
        )
    if action_envelope.action_digest != mandate.action_digest:
        raise DelegationPropagationError(
            "action envelope is not bound to this mandate (digest mismatch)"
        )
    try:
        child_cose = authority.mint_child(
            bytes(mandate_cose),
            holder_signer,
            trusted_issuers,
            holder_pubkey=bytes(delegatee_pubkey),
            spend_limit=spend_limit,
            ttl=ttl,
            now=moment,
        )
    except CapabilityError as exc:
        raise DelegationPropagationError(
            f"child capability mint failed: {exc}"
        ) from exc

    return DelegationPackage(
        principal=principal,
        delegatee_key_id=delegatee_key_id,
        chain=[env.model_dump(mode="json") for env in chain_envelopes],
        mandate_capability_hex=bytes(mandate_cose).hex(),
        child_capability_hex=bytes(child_cose).hex(),
        action_envelope=action_envelope.model_dump(mode="json"),
        action_digest=action_envelope.action_digest,
        propagated_at=moment,
    )


def receive_delegation(
    package: DelegationPackage | dict[str, Any],
    *,
    trusted_authority_keys: Collection[str],
    key_registry: Mapping[str, Any],
    receiver_key_id: str,
    receiver_pubkey: bytes,
    revoked_ids: Collection[str] = frozenset(),
    now: datetime | None = None,
) -> VerifiedDelegation:
    """Accept a cross-agent delegation (delegatee side). Verifies the FULL
    chain offline before accepting anything.

    Checks, fail-closed: (1) the whole delegation chain verifies —
    signatures, custody, hash links, depth claims, and the asor-wimse
    narrowing invariant re-verified at every hop (chain amplification is
    rejected here); (2) the package is addressed to this receiver;
    (3) the mandate capability verifies under the AUTHORITY keys only and is
    kind ``"mandate"``; (4) the mandate holder is the chain's leaf delegator
    and signed the child capability; (5) the child is kind ``"execution"``,
    minted from THIS mandate (parent binding), with an identical action
    digest (no scope broadening via capability swap), and bound to the
    receiver's key; (6) the action envelope parses and its digest matches;
    (7) the chain's effective scope authorizes the envelope's effect
    (verb -> action, target -> resource); (8) neither the mandate nor the
    child is revoked.

    Returns the verified delegation, or raises ``DelegationRejected``.
    """
    moment = _utcnow() if now is None else now
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    else:
        moment = moment.astimezone(timezone.utc)

    if isinstance(package, dict):
        try:
            package = DelegationPackage.model_validate(package)
        except Exception as exc:
            raise DelegationRejected(f"delegation package malformed: {exc}") from exc

    # (1) the full chain, verified offline.
    envelopes: list[SignedEnvelope] = []
    for index, raw in enumerate(package.chain):
        try:
            envelopes.append(SignedEnvelope.model_validate(raw))
        except Exception as exc:
            raise DelegationRejected(
                f"chain[{index}] is not a valid receipt envelope: {exc}"
            ) from exc
    try:
        chain_info = verify_chain(
            envelopes,
            trusted_authority_keys=trusted_authority_keys,
            key_registry=key_registry,
            now=moment,
        )
    except DelegationError as exc:
        raise DelegationRejected(f"delegation chain rejected: {exc}") from exc

    # (2) addressed to this receiver.
    try:
        leaf = DelegationReceipt.model_validate(envelopes[-1].payload)
    except Exception as exc:
        raise DelegationRejected(f"leaf receipt malformed: {exc}") from exc
    if leaf.delegatee != receiver_key_id or package.delegatee_key_id != receiver_key_id:
        raise DelegationRejected("delegation is not addressed to this receiver")

    # (3) the mandate: authority-signed ONLY.
    authority_trusted: dict[bytes, Ed25519PublicKey] = {}
    for kid in trusted_authority_keys:
        raw_key = key_registry.get(kid)
        if raw_key is None:
            raise DelegationRejected(
                f"no public key registered for trusted authority {kid!r}"
            )
        authority_trusted[kid.encode("utf-8")] = Ed25519PublicKey.from_public_bytes(
            _coerce_pubkey(raw_key, kid)
        )
    try:
        mandate = authority.verify_capability(
            bytes.fromhex(package.mandate_capability_hex), authority_trusted, now=moment
        )
    except (CapabilityError, ValueError) as exc:
        raise DelegationRejected(f"mandate capability invalid: {exc}") from exc
    if mandate.kind != KIND_MANDATE:
        raise DelegationRejected(
            f"mandate capability kind is {mandate.kind!r}, not 'mandate'"
        )

    # (4) the delegator is the mandate holder, and signed the child: the
    # child's issuer key is trusted BECAUSE the verified chain proves the
    # delegator holds this mandate — never on bare assertion.
    delegator_key_id = leaf.delegator
    delegator_raw = key_registry.get(delegator_key_id)
    if delegator_raw is None:
        raise DelegationRejected(
            f"no public key registered for delegator {delegator_key_id!r}"
        )
    delegator_pubkey = _coerce_pubkey(delegator_raw, delegator_key_id)
    if bytes(mandate.holder_pubkey) != delegator_pubkey:
        raise DelegationRejected(
            "mandate holder is not the chain's leaf delegator — the chain "
            "does not authorize this mandate"
        )
    child_trusted = {
        delegator_key_id.encode("utf-8"): Ed25519PublicKey.from_public_bytes(
            delegator_pubkey
        )
    }
    try:
        child = authority.verify_capability(
            bytes.fromhex(package.child_capability_hex), child_trusted, now=moment
        )
    except (CapabilityError, ValueError) as exc:
        raise DelegationRejected(f"child capability invalid: {exc}") from exc

    # (5) monotonic attenuation across the capability hop: the child must be
    # a one-use execution capability minted from THIS mandate, with the
    # identical action digest (no scope broadening via capability swap),
    # and bound to the receiver's key.
    if child.kind != KIND_EXECUTION:
        raise DelegationRejected(
            f"child capability kind is {child.kind!r}, not 'execution'"
        )
    if child.parent_capability_id != mandate.capability_id:
        raise DelegationRejected(
            "child capability was not minted from this mandate "
            "(parent binding mismatch)"
        )
    if child.action_digest != mandate.action_digest:
        raise DelegationRejected(
            "child action digest differs from the mandate's — scope broadening "
            "via capability swap rejected"
        )
    if bytes(child.holder_pubkey) != bytes(receiver_pubkey):
        raise DelegationRejected("child capability is not bound to this receiver")

    # (6) the action envelope is exactly what the child authorizes.
    try:
        envelope = ActionEnvelope.model_validate(package.action_envelope)
    except Exception as exc:
        raise DelegationRejected(f"action envelope malformed: {exc}") from exc
    if envelope.action_digest != package.action_digest:
        raise DelegationRejected("package action_digest does not match the envelope")
    if envelope.action_digest != child.action_digest:
        raise DelegationRejected(
            "envelope digest does not match the child capability binding"
        )

    # (7) the chain's effective scope must authorize the delegated effect.
    if not chain_info.scope_allows(envelope.effect.verb, envelope.effect.target):
        raise DelegationRejected(
            "delegation chain scope does not authorize this effect "
            f"(verb={envelope.effect.verb!r}, target={envelope.effect.target!r})"
        )

    # (8) revocation: a delegation from a revoked mandate (or a revoked
    # child) is rejected.
    revoked = set(revoked_ids or ())
    if mandate.capability_id in revoked:
        raise DelegationRejected("the mandate behind this delegation was revoked")
    if child.capability_id in revoked:
        raise DelegationRejected("the child capability was revoked")

    return VerifiedDelegation(
        principal=package.principal,
        delegatee_key_id=receiver_key_id,
        effective_scope=chain_info.effective_scope,
        chain=chain_info,
        mandate_id=mandate.capability_id,
        child_capability_id=child.capability_id,
        action_digest=child.action_digest,
    )
