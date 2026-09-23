"""ANCHOR v1 — Multi-signer constitutions (Wave A, capability 1).

Portable constitutional AI: a constitution version is an immutable, content-hashed
payload carrying invariants / hard-deny / approval-required action policy. Each
version is authorized by m-of-n Ed25519 signatures over its canonical content
hash. Versions link into a supersedes hash chain; the trusted signer set may
rotate forward-only (a rotation proposed by version N takes effect for versions
> N, never retroactively). Everything verifies offline.

Local only. No network calls.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
from fnmatch import fnmatchcase
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from anchor_v1.canonical import sha256_hex
from anchor_v1.crypto import Ed25519Signer, verify_envelope
from anchor_v1.models import SignedEnvelope

__all__ = [
    "ActionReceipt",
    "Constitution",
    "ConstitutionRejected",
    "ConstitutionSignature",
    "ConstitutionalChain",
    "Decision",
    "SignedConstitution",
    "TrustConfig",
    "TrustedSigner",
    "adjudicate_receipt",
    "content_hash_of",
    "governance_check",
    "resolve_governed_version",
    "sign_constitution",
    "verify_constitution_signature",
]

Decision = Literal["ALLOW", "DENY", "APPROVAL_REQUIRED"]

_SIGNATURE_HASH_KEY = "constitution_hash"


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _require_aware_utc(value: datetime, field_name: str) -> datetime:
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value.astimezone(timezone.utc)


class TrustedSigner(StrictModel):
    """One member of a trusted signer set: key id + raw Ed25519 public key."""

    key_id: str = Field(min_length=1)
    public_key: str = Field(description="base64 of the 32-byte raw Ed25519 public key")

    @field_validator("public_key")
    @classmethod
    def _valid_pubkey(cls, v: str) -> str:
        try:
            raw = base64.b64decode(v, validate=True)
        except Exception as exc:
            raise ValueError("public_key must be valid base64") from exc
        if len(raw) != 32:
            raise ValueError("public_key must decode to 32 bytes (raw Ed25519)")
        return v


class TrustConfig(StrictModel):
    """The trusted signer set plus quorum m for m-of-n signing."""

    signers: list[TrustedSigner] = Field(min_length=1)
    quorum: int = Field(ge=1, description="m in m-of-n: distinct valid signatures required")

    @model_validator(mode="after")
    def _check_quorum(self) -> "TrustConfig":
        key_ids = [s.key_id for s in self.signers]
        if len(set(key_ids)) != len(key_ids):
            raise ValueError("signer key_ids must be unique")
        if self.quorum > len(self.signers):
            raise ValueError("quorum m cannot exceed signer count n")
        return self


class Constitution(StrictModel):
    """Immutable constitutional payload. Hash covers every field below."""

    version: int = Field(ge=1)
    previous_hash: str | None = Field(
        default=None,
        description="content hash of the superseded version; None only for genesis",
    )
    invariants: list[str] = Field(
        default_factory=list,
        description='always-on rules, each "deny:<pattern>" or "require-approval:<pattern>"',
    )
    hard_deny_actions: list[str] = Field(default_factory=list)
    approval_required_actions: list[str] = Field(default_factory=list)
    authority_epoch: int = Field(ge=0)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    proposed_trust: TrustConfig | None = Field(
        default=None,
        description="signer-set rotation proposal; takes effect for FUTURE versions only",
    )

    @field_validator("created_at")
    @classmethod
    def _tz_aware(cls, v: datetime) -> datetime:
        return _require_aware_utc(v, "created_at")

    @field_validator("invariants")
    @classmethod
    def _valid_invariants(cls, v: list[str]) -> list[str]:
        for item in v:
            if item.startswith("deny:"):
                pattern = item[len("deny:"):]
            elif item.startswith("require-approval:"):
                pattern = item[len("require-approval:"):]
            else:
                raise ValueError(
                    f"invariant must start with 'deny:' or 'require-approval:': {item!r}"
                )
            if not pattern:
                raise ValueError(f"invariant has empty action pattern: {item!r}")
        return v


class ConstitutionSignature(StrictModel):
    """One Ed25519 signature over the constitution's canonical content hash."""

    key_id: str = Field(min_length=1)
    signature: str = Field(description="base64 Ed25519 signature")


class SignedConstitution(StrictModel):
    """A constitution version plus its authorizing multi-signature."""

    constitution: Constitution
    signatures: list[ConstitutionSignature] = Field(min_length=1)

    @property
    def content_hash(self) -> str:
        return content_hash_of(self.constitution)


class ActionReceipt(StrictModel):
    """Attestation that an action was taken under a claimed constitution version."""

    action: str = Field(min_length=1)
    resource: str = Field(min_length=1)
    constitution_hash: str = Field(min_length=1)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("created_at")
    @classmethod
    def _tz_aware(cls, v: datetime) -> datetime:
        return _require_aware_utc(v, "created_at")


class ConstitutionRejected(ValueError):
    """Raised when a constitution version fails chain admission. Fail closed."""


# ---------------------------------------------------------------------------
# Hashing / signing
# ---------------------------------------------------------------------------


def content_hash_of(constitution: Constitution) -> str:
    """Immutable content hash: sha256 over the canonical payload bytes."""
    return sha256_hex(constitution.model_dump(mode="json"))


def sign_constitution(signer: Ed25519Signer, constitution: Constitution) -> ConstitutionSignature:
    """Sign the constitution's content hash with an Ed25519 signer."""
    envelope = signer.sign_payload({_SIGNATURE_HASH_KEY: content_hash_of(constitution)})
    return ConstitutionSignature(key_id=signer.key_id, signature=envelope.signature)


def verify_constitution_signature(
    sig: ConstitutionSignature, public_key_b64: str, constitution: Constitution
) -> bool:
    """True iff sig is a valid Ed25519 signature by public_key_b64 over the hash."""
    try:
        envelope = SignedEnvelope(
            key_id=sig.key_id,
            payload={_SIGNATURE_HASH_KEY: content_hash_of(constitution)},
            signature=sig.signature,
        )
        payload = verify_envelope(envelope, base64.b64decode(public_key_b64))
    except Exception:
        return False
    return payload.get(_SIGNATURE_HASH_KEY) == content_hash_of(constitution)


# ---------------------------------------------------------------------------
# Chain
# ---------------------------------------------------------------------------


class ConstitutionalChain:
    """Ordered, validated chain of constitution versions.

    The constructor admits the genesis version against the bootstrap trust
    config; append() admits each successor only if the supersedes link is
    intact and >= m signatures verify against the signer set active at that
    position. Rotation proposals take effect for future versions only.
    """

    def __init__(self, genesis: SignedConstitution, bootstrap: TrustConfig):
        self._bootstrap = bootstrap
        self._versions: list[SignedConstitution] = []
        self._by_hash: dict[str, SignedConstitution] = {}
        self._admit(genesis, active=bootstrap, is_genesis=True)

    def __len__(self) -> int:
        return len(self._versions)

    @property
    def head(self) -> SignedConstitution:
        return self._versions[-1]

    @property
    def versions(self) -> tuple[SignedConstitution, ...]:
        return tuple(self._versions)

    @property
    def bootstrap(self) -> TrustConfig:
        return self._bootstrap

    def trust_active_for_next(self) -> TrustConfig:
        """Signer set + quorum that the NEXT appended version must satisfy."""
        trust = self._bootstrap
        for v in self._versions:
            if v.constitution.proposed_trust is not None:
                trust = v.constitution.proposed_trust
        return trust

    def append(self, signed: SignedConstitution) -> SignedConstitution:
        """Admit a new head version. Raises ConstitutionRejected on any failure."""
        self._admit(signed, active=self.trust_active_for_next(), is_genesis=False)
        return signed

    def extend(self, versions: list[SignedConstitution]) -> None:
        for v in versions:
            self.append(v)

    def governed_version(self, constitution_hash: str) -> SignedConstitution | None:
        """Which chain version the hash pins to (walks supersedes links)."""
        return self._by_hash.get(constitution_hash)

    def verify_full_chain(self) -> bool:
        """Re-validate every version from genesis against its position-active set."""
        rebuilt = ConstitutionalChain(self._versions[0], self._bootstrap)
        for v in self._versions[1:]:
            rebuilt.append(v)
        return True

    # -- internals ----------------------------------------------------------

    def _admit(
        self, signed: SignedConstitution, active: TrustConfig, is_genesis: bool
    ) -> None:
        c = signed.constitution
        content_hash = signed.content_hash

        if content_hash in self._by_hash:
            raise ConstitutionRejected("duplicate constitution content hash")

        if is_genesis:
            if c.version != 1:
                raise ConstitutionRejected("genesis version must be 1")
            if c.previous_hash is not None:
                raise ConstitutionRejected("genesis previous_hash must be None")
        else:
            head = self._versions[-1]
            if c.version != head.constitution.version + 1:
                raise ConstitutionRejected(
                    f"version must be sequential: got {c.version}, "
                    f"expected {head.constitution.version + 1}"
                )
            if c.previous_hash != head.content_hash:
                raise ConstitutionRejected(
                    "previous_hash does not match current head content hash "
                    "(supersedes chain broken)"
                )

        self._verify_quorum(signed, active)

        self._versions.append(signed)
        self._by_hash[content_hash] = signed

    @staticmethod
    def _verify_quorum(signed: SignedConstitution, active: TrustConfig) -> None:
        keymap = {s.key_id: s for s in active.signers}
        seen: set[str] = set()
        valid = 0
        for sig in signed.signatures:
            if sig.key_id in seen:
                raise ConstitutionRejected(
                    f"duplicate signature from key_id {sig.key_id!r}"
                )
            seen.add(sig.key_id)
            signer = keymap.get(sig.key_id)
            if signer is None:
                raise ConstitutionRejected(
                    f"signature by key_id {sig.key_id!r} not in the active trusted set"
                )
            if not verify_constitution_signature(
                sig, signer.public_key, signed.constitution
            ):
                raise ConstitutionRejected(
                    f"invalid signature from key_id {sig.key_id!r}"
                )
            valid += 1
        if valid < active.quorum:
            raise ConstitutionRejected(
                f"quorum not met: {valid} valid signature(s), need {active.quorum}"
            )


def resolve_governed_version(
    versions: list[SignedConstitution],
    bootstrap: TrustConfig,
    constitution_hash: str,
) -> SignedConstitution | None:
    """Offline verification: rebuild the chain from untrusted input, validating
    every version against the signer set active at its position (rotations apply
    forward-only), then pin constitution_hash to the version that governed it.

    Returns None if the chain is illegitimate in any way or the hash matches no
    version — fail closed, never trust the claim alone.
    """
    try:
        if not versions:
            return None
        chain = ConstitutionalChain(versions[0], bootstrap)
        chain.extend(versions[1:])
    except (ConstitutionRejected, ValueError):
        return None
    return chain.governed_version(constitution_hash)


# ---------------------------------------------------------------------------
# Governance decisions
# ---------------------------------------------------------------------------


def _pattern_matches(patterns: list[str], action: str) -> bool:
    return any(fnmatchcase(action, p) for p in patterns)


def governance_check(action: str, resource: str, constitution: Constitution) -> Decision:
    """ALLOW / DENY / APPROVAL_REQUIRED for an action under a constitution.

    Precedence: DENY > APPROVAL_REQUIRED > ALLOW (fail-closed ordering).
    `resource` is reserved for future resource-scoped rules; current rules are
    action-scoped.
    """
    _ = resource  # reserved for future waves
    deny_patterns = [
        i[len("deny:"):] for i in constitution.invariants if i.startswith("deny:")
    ]
    require_patterns = [
        i[len("require-approval:"):]
        for i in constitution.invariants
        if i.startswith("require-approval:")
    ]
    if _pattern_matches(constitution.hard_deny_actions, action) or _pattern_matches(
        deny_patterns, action
    ):
        return "DENY"
    if _pattern_matches(constitution.approval_required_actions, action) or _pattern_matches(
        require_patterns, action
    ):
        return "APPROVAL_REQUIRED"
    return "ALLOW"


def adjudicate_receipt(chain: ConstitutionalChain, receipt: ActionReceipt) -> Decision:
    """Decide an action receipt: pin its constitution_hash to the chain, then
    apply that version's policy. Unknown hash -> DENY (fail closed)."""
    governed = chain.governed_version(receipt.constitution_hash)
    if governed is None:
        return "DENY"
    return governance_check(receipt.action, receipt.resource, governed.constitution)
