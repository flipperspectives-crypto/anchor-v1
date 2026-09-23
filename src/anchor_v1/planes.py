"""ANCHOR v1 — plane registry + one policy vocabulary (Wave 3 reframe).

This module is now TWO things and nothing else:

1. **The plane registry** — the canonical plane constants
   (``"shell"``, ``"http"``, ``"github"``, ``"mcp"``, ``"a2a"``) in
   ``SUPPORTED_PLANES`` / ``Plane``.
2. **The one-policy-vocabulary declaration** — ``UnifiedDecision``, the
   shared ``decide()`` core, ``DecisionGovernor``, ``evaluate_plane`` and
   ``verify_decision``. Every plane runs the same core, so planes cannot
   diverge in verdict.

Plane specifics moved out in Wave 3 (Revision B pivot 14):

* native MCP gateway -> ``anchor_v1.mcp_gateway`` (``NativeMCPGateway``,
  ``MCPBackend``, execution receipts; the v0 ``MCPGateway`` moved there too),
* A2A agent cards + cross-agent delegation propagation ->
  ``anchor_v1.a2a``.

The moved v0 names (``MCPGateway``, ``build_agent_card``,
``verify_agent_card``, ``AgentCardBody``, ``EnforcementDeclaration``,
``CardVerificationError``) are re-exported here LAZILY (PEP 562
``__getattr__``) so existing importers keep working without creating an
import cycle: the new modules import the registry/core from here, so this
module must not import them at top level.

Local only. No network calls.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import Field, field_validator

from anchor_v1.attenuated_tokens import (
    AuthorizationError,
    token_hash,
    verify as verify_token,
)
from anchor_v1.canonical import sha256_hex
from anchor_v1.crypto import Ed25519Signer, verify_envelope
from anchor_v1.models import SignedEnvelope, StrictModel
from anchor_v1.multisig_constitution import (
    Constitution,
    content_hash_of,
    governance_check,
)

__all__ = [
    # plane registry + one-policy-vocabulary (canonical home: this module)
    "SUPPORTED_PLANES",
    "Plane",
    "UnifiedDecision",
    "DecisionDeniedError",
    "DecisionVerificationError",
    "DecisionGovernor",
    "decide",
    "evaluate_plane",
    "verify_decision",
    # re-exported for compatibility (canonical homes: mcp_gateway / a2a)
    "MCPGateway",
    "CardVerificationError",
    "EnforcementDeclaration",
    "AgentCardBody",
    "build_agent_card",
    "verify_agent_card",
]

Plane = Literal["mcp", "a2a", "shell", "http", "github"]
SUPPORTED_PLANES: tuple[Plane, ...] = ("mcp", "a2a", "shell", "http", "github")

Verdict = Literal["ALLOW", "DENY", "APPROVAL_REQUIRED"]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _require_aware_utc(value: datetime, field_name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value.astimezone(timezone.utc)


# ---------------------------------------------------------------------------
# UnifiedDecision — the single cross-plane artifact
# ---------------------------------------------------------------------------


class UnifiedDecision(StrictModel):
    """One signed decision format, enforced identically on every plane.

    Emitted by the governor's decision key for every evaluated invocation;
    denials carry the signed decision too, so the denial itself is auditable.
    """

    decision_id: str = Field(min_length=1)
    # Plain str (not the Plane literal) so that a DENY decision can honestly
    # record an attempted plane the governor does not govern — fail closed
    # with an auditable artifact instead of raising on a bad caller value.
    plane: str = Field(min_length=1)
    subject: str = Field(min_length=1)
    action: str = Field(min_length=1)
    resource: str = Field(min_length=1)
    parameters_hash: str = Field(min_length=1)
    verdict: Verdict
    policy_refs: dict[str, str] = Field(
        description="constitution_hash, capability_id / token_hash; deny_reason when denied"
    )
    evaluated_at: datetime
    nonce: str = Field(min_length=1)

    @field_validator("evaluated_at")
    @classmethod
    def _tz_aware(cls, v: datetime) -> datetime:
        return _require_aware_utc(v, "evaluated_at")


class DecisionVerificationError(ValueError):
    """Raised when a signed decision fails offline verification. Fail closed."""


class DecisionDeniedError(Exception):
    """Raised by gateways on DENY (and APPROVAL_REQUIRED).

    The signed decision is attached so the denial itself is auditable.
    """

    def __init__(
        self,
        message: str,
        *,
        signed_decision: SignedEnvelope,
        decision: UnifiedDecision,
    ) -> None:
        super().__init__(message)
        self.signed_decision = signed_decision
        self.decision = decision


# ---------------------------------------------------------------------------
# The shared decision core — every plane runs this, so planes can't diverge
# ---------------------------------------------------------------------------


class DecisionGovernor:
    """Holds the governor's decision key, trusted token issuers, and replay state.

    One governor serves all planes; the decision key is distinct from the token
    issuer keys and the constitution signer keys.
    """

    def __init__(
        self,
        *,
        decision_key: Ed25519Signer,
        token_issuers: dict[str, bytes],
        constitution: Constitution,
        supported_planes: tuple[Plane, ...] = SUPPORTED_PLANES,
    ) -> None:
        self.decision_key = decision_key
        self.token_issuers = dict(token_issuers)
        self.constitution = constitution
        self.supported_planes = tuple(supported_planes)
        self.used_nonces: set[str] = set()

    @property
    def governor_pubkey_bytes(self) -> bytes:
        return self.decision_key.public_key_bytes()

    @property
    def constitution_hash(self) -> str:
        return content_hash_of(self.constitution)


def _sign_decision(governor: DecisionGovernor, decision: UnifiedDecision) -> SignedEnvelope:
    return governor.decision_key.sign_payload(decision.model_dump(mode="json"))


def verify_decision(envelope: SignedEnvelope, governor_pubkey: bytes) -> UnifiedDecision:
    """Offline verification of a signed decision. Returns the decision or raises.

    Any signature failure or malformed payload raises DecisionVerificationError
    — a tampered verdict can never verify.
    """
    try:
        payload = verify_envelope(envelope, governor_pubkey)
    except Exception as exc:
        raise DecisionVerificationError(f"decision signature invalid: {exc}") from exc
    try:
        return UnifiedDecision.model_validate(payload)
    except Exception as exc:
        raise DecisionVerificationError(f"decision payload malformed: {exc}") from exc


def decide(
    *,
    plane: str,
    subject: str,
    action: str,
    resource: str,
    invocation_params: dict[str, Any],
    constitution: Constitution,
    governor: DecisionGovernor,
    capability_envelope: SignedEnvelope | None,
    holder_proof: SignedEnvelope | None,
    now: datetime | None = None,
) -> SignedEnvelope:
    """The shared core: constitution check + capability token check, one verdict.

    Fail-closed ordering: unknown plane -> DENY; missing token -> DENY;
    constitution DENY -> DENY; token failure or any binding mismatch -> DENY;
    constitution APPROVAL_REQUIRED -> APPROVAL_REQUIRED; else ALLOW.
    """
    now = _require_aware_utc(now or _utcnow(), "now")
    constitution_hash = content_hash_of(constitution)
    parameters_hash = sha256_hex(invocation_params)
    policy_refs: dict[str, str] = {"constitution_hash": constitution_hash}

    def _deny(reason: str) -> SignedEnvelope:
        policy_refs["deny_reason"] = reason
        decision = UnifiedDecision(
            decision_id=f"dec_{secrets.token_hex(12)}",
            plane=plane,
            subject=subject,
            action=action,
            resource=resource,
            parameters_hash=parameters_hash,
            verdict="DENY",
            policy_refs=dict(policy_refs),
            evaluated_at=now,
            nonce=secrets.token_hex(16),
        )
        return _sign_decision(governor, decision)

    if plane not in SUPPORTED_PLANES or plane not in governor.supported_planes:
        return _deny(f"plane not governed: {plane!r}")

    # (1) constitutional policy
    verdict = governance_check(action, resource, constitution)
    if verdict == "DENY":
        return _deny("constitution:DENY")

    # (2) capability token — required, never optional
    if capability_envelope is None or holder_proof is None:
        return _deny("no capability token presented")
    try:
        token_payload = verify_token(
            capability_envelope,
            holder_proof=holder_proof,
            invocation_params=invocation_params,
            now=now,
            trusted_issuers=governor.token_issuers,
            used_nonces=governor.used_nonces,
        )
    except AuthorizationError as exc:
        return _deny(f"token verify failed: {exc}")
    except Exception as exc:  # never let a verify bug become a soft allow
        return _deny(f"token verify error: {exc}")

    # (3) cross-bindings: the token must name THIS plane, THIS action, THIS
    # resource, and the constitution that authorized its issuance.
    if token_payload.audience != plane:
        return _deny(
            f"token plane binding mismatch: token audience {token_payload.audience!r} != plane {plane!r}"
        )
    if token_payload.action != action:
        return _deny("token action binding mismatch")
    if token_payload.resource != resource:
        return _deny("token resource binding mismatch")
    if token_payload.constitution_hash != constitution_hash:
        return _deny("token constitution binding mismatch")

    policy_refs["capability_id"] = token_payload.capability_id
    policy_refs["token_hash"] = token_hash(capability_envelope)

    if verdict == "APPROVAL_REQUIRED":
        policy_refs["deny_reason"] = "constitution:APPROVAL_REQUIRED"
        decision = UnifiedDecision(
            decision_id=f"dec_{secrets.token_hex(12)}",
            plane=plane,
            subject=subject,
            action=action,
            resource=resource,
            parameters_hash=parameters_hash,
            verdict="APPROVAL_REQUIRED",
            policy_refs=dict(policy_refs),
            evaluated_at=now,
            nonce=secrets.token_hex(16),
        )
        return _sign_decision(governor, decision)

    # ALLOW — consume the single-use nonce only on success
    governor.used_nonces.add(token_payload.nonce)
    decision = UnifiedDecision(
        decision_id=f"dec_{secrets.token_hex(12)}",
        plane=plane,
        subject=subject,
        action=action,
        resource=resource,
        parameters_hash=parameters_hash,
        verdict="ALLOW",
        policy_refs=dict(policy_refs),
        evaluated_at=now,
        nonce=secrets.token_hex(16),
    )
    return _sign_decision(governor, decision)


def evaluate_plane(
    governor: DecisionGovernor,
    plane: Plane,
    *,
    subject: str,
    action: str,
    resource: str,
    invocation_params: dict[str, Any],
    capability_envelope: SignedEnvelope | None,
    holder_proof: SignedEnvelope | None,
    now: datetime | None = None,
) -> SignedEnvelope:
    """Per-plane entry point. Thin wrapper over the shared decide() core, so
    verdicts cannot diverge between planes for the same (action, resource,
    parameters) under the same constitution and token bindings."""
    return decide(
        plane=plane,
        subject=subject,
        action=action,
        resource=resource,
        invocation_params=invocation_params,
        constitution=governor.constitution,
        governor=governor,
        capability_envelope=capability_envelope,
        holder_proof=holder_proof,
        now=now,
    )


# ---------------------------------------------------------------------------
# Compatibility re-exports (lazy): the v0 plane specifics now live in
# anchor_v1.mcp_gateway (MCPGateway) and anchor_v1.a2a (agent cards).
# Imported lazily via PEP 562 so the new modules can import this module's
# registry/core at their top level without an import cycle.
# ---------------------------------------------------------------------------

_LAZY_REEXPORTS: dict[str, str] = {
    "MCPGateway": "mcp_gateway",
    "CardVerificationError": "a2a",
    "EnforcementDeclaration": "a2a",
    "AgentCardBody": "a2a",
    "build_agent_card": "a2a",
    "verify_agent_card": "a2a",
}


def __getattr__(name: str) -> Any:
    module_name = _LAZY_REEXPORTS.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib

    module = importlib.import_module(f"anchor_v1.{module_name}")
    return getattr(module, name)
