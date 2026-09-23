"""ANCHOR v1 — Capability 3: delegation chains at depth >= 2.

The asor-wimse invariant, enforced STRUCTURALLY (not as audit history):
authority at any hop MUST be a subset (⊆) of the granting hop, verifiable
offline by the final enforcement point. OAuth Token Exchange (RFC 8693)
cannot do this — its chain is audit history, not authority.

Design notes:
- Every DelegationReceipt is a SignedEnvelope signed by the DELEGATOR's key
  (the party granting authority). The root is signed by a trusted authority
  (the mandate issuer).
- Mint-time checks in delegate()/issue_root() are a courtesy for honest
  holders. verify_chain() re-verifies the narrowing invariant at every hop
  independently — a hostile delegator may have minted off-protocol.
- Resource-prefix matching is boundary/segment-aware, never raw startswith:
  "workspace://scope" does NOT authorize "workspace://scope-evil".
- Fail closed: any verification failure raises DelegationError.
"""

from __future__ import annotations

import base64
import secrets
from datetime import datetime, timezone
from typing import Any, Mapping

from .canonical import sha256_hex
from .crypto import Ed25519Signer, verify_envelope
from .models import SignedEnvelope, StrictModel

from pydantic import Field, field_validator


class DelegationError(Exception):
    """Raised on ANY delegation-chain failure. Fail closed, always."""


# ---------------------------------------------------------------------------
# Scope model
# ---------------------------------------------------------------------------
class DelegationScope(StrictModel):
    actions: list[str] = Field(default_factory=list)
    resource_prefixes: list[str] = Field(default_factory=list)
    caveats: list[Any] = Field(default_factory=list)


def _caveat_key(caveat: Any) -> str:
    """Canonical identity for a caveat, for set-style comparison."""
    return sha256_hex({"caveat": caveat})


def is_sub_prefix(child: str, parent: str) -> bool:
    """Boundary-aware prefix check.

    `child` is authorized by `parent` only when parent's '/'-separated
    segments are a leading subsequence of child's segments. Never raw
    startswith, so sibling prefixes like "workspace://scope-evil" under
    "workspace://scope" are rejected.
    """
    if not parent:
        return True
    p = parent.split("/")
    c = child.split("/")
    if len(c) < len(p):
        return False
    return c[: len(p)] == p


def is_scope_narrower_or_equal(child: DelegationScope, parent: DelegationScope) -> bool:
    """The asor-wimse narrowing check: child authority ⊆ parent authority.

    - actions: exact set inclusion.
    - resource_prefixes: every child prefix must sit within (>=) a parent
      prefix, boundary-aware.
    - caveats: the child must retain EVERY parent caveat (dropping a granted
      constraint widens authority). The child may add further caveats, which
      only constrains it more.
    """
    if not set(child.actions) <= set(parent.actions):
        return False
    for cp in child.resource_prefixes:
        if not any(is_sub_prefix(cp, pp) for pp in parent.resource_prefixes):
            return False
    parent_caveats = {_caveat_key(c) for c in parent.caveats}
    child_caveats = {_caveat_key(c) for c in child.caveats}
    if not parent_caveats <= child_caveats:
        return False
    return True


def _scope_violation_reason(child: DelegationScope, parent: DelegationScope) -> str:
    extra_actions = sorted(set(child.actions) - set(parent.actions))
    if extra_actions:
        return f"actions widened beyond parent: {extra_actions}"
    for cp in child.resource_prefixes:
        if not any(is_sub_prefix(cp, pp) for pp in parent.resource_prefixes):
            return f"resource prefix not within parent authority: {cp!r}"
    parent_caveats = {_caveat_key(c) for c in parent.caveats}
    child_caveats = {_caveat_key(c) for c in child.caveats}
    dropped = sorted(parent_caveats - child_caveats)
    if dropped:
        return f"parent caveats dropped (authority widened): {len(dropped)}"
    return "scope not narrower than parent"


# ---------------------------------------------------------------------------
# Receipt model
# ---------------------------------------------------------------------------
def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class DelegationReceipt(StrictModel):
    delegation_id: str
    parent_receipt_hash: str | None = None
    root_mandate_hash: str
    delegator: str  # key_id of the granting party
    delegatee: str  # key_id receiving authority
    scope: DelegationScope
    depth: int = Field(ge=0)
    max_depth: int = Field(ge=0)
    not_before: datetime
    expires_at: datetime
    nonce: str
    constitution_hash: str

    @field_validator("not_before", "expires_at", mode="before")
    @classmethod
    def _coerce_utc(cls, value: Any) -> Any:
        # Datetimes are UTC; naive inputs are assumed UTC, aware ones shifted.
        if isinstance(value, datetime):
            if value.tzinfo is None:
                return value.replace(tzinfo=timezone.utc)
            return value.astimezone(timezone.utc)
        return value

    @field_validator("not_before", "expires_at")
    @classmethod
    def _require_tz(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("datetimes must be timezone-aware (UTC)")
        return value


def receipt_hash(envelope: SignedEnvelope) -> str:
    """Tamper-evident hash of a receipt envelope (payload + signature + keys)."""
    return sha256_hex(envelope.model_dump(mode="json"))


def _payload_dict(receipt: DelegationReceipt) -> dict[str, Any]:
    return receipt.model_dump(mode="json")


# ---------------------------------------------------------------------------
# Minting (honest-holder path; verify_chain() trusts none of this)
# ---------------------------------------------------------------------------
def _new_receipt(
    *,
    delegation_id: str | None,
    parent_receipt_hash: str | None,
    root_mandate_hash: str,
    delegator: str,
    delegatee: str,
    scope: DelegationScope,
    depth: int,
    max_depth: int,
    not_before: datetime,
    expires_at: datetime,
    constitution_hash: str,
    signer: Any,
) -> SignedEnvelope:
    if delegator != signer.key_id:
        raise DelegationError(
            f"minting signer key {signer.key_id!r} is not the delegator {delegator!r}"
        )
    if not_before >= expires_at:
        raise DelegationError("not_before must be strictly before expires_at")
    receipt = DelegationReceipt(
        delegation_id=delegation_id or f"del-{secrets.token_hex(8)}",
        parent_receipt_hash=parent_receipt_hash,
        root_mandate_hash=root_mandate_hash,
        delegator=delegator,
        delegatee=delegatee,
        scope=scope,
        depth=depth,
        max_depth=max_depth,
        not_before=not_before,
        expires_at=expires_at,
        nonce=secrets.token_hex(16),
        constitution_hash=constitution_hash,
    )
    return signer.sign_payload(_payload_dict(receipt))


def issue_root(
    *,
    root_mandate_hash: str,
    constitution_hash: str,
    delegatee_key_id: str,
    scope: DelegationScope,
    max_depth: int,
    not_before: datetime,
    expires_at: datetime,
    authority_signer: Any,
    delegation_id: str | None = None,
) -> SignedEnvelope:
    """Mint the depth-0 root receipt, signed by the trusted authority key.

    The authority is the mandate issuer; it grants the root delegatee the
    given scope. max_depth bounds how deep the whole chain may go.
    """
    if max_depth < 0:
        raise DelegationError("max_depth must be >= 0")
    return _new_receipt(
        delegation_id=delegation_id,
        parent_receipt_hash=None,
        root_mandate_hash=root_mandate_hash,
        delegator=authority_signer.key_id,
        delegatee=delegatee_key_id,
        scope=scope,
        depth=0,
        max_depth=max_depth,
        not_before=not_before,
        expires_at=expires_at,
        constitution_hash=constitution_hash,
        signer=authority_signer,
    )


def delegate(
    parent_envelope: SignedEnvelope,
    delegatee_key_id: str,
    narrowed_scope: DelegationScope,
    signer: Any,
    *,
    not_before: datetime | None = None,
    expires_at: datetime | None = None,
    max_depth: int | None = None,
    delegation_id: str | None = None,
) -> SignedEnvelope:
    """Mint a child receipt at depth+1, signed by the parent's delegatee.

    Enforces the narrowing invariant at MINT time (courtesy for honest
    holders). verify_chain() enforces it again independently — a hostile
    delegator may have minted off-protocol, so mint-time checks are never
    trusted by the enforcement point.
    """
    parent = DelegationReceipt.model_validate(parent_envelope.payload)
    narrowed_scope = DelegationScope.model_validate(narrowed_scope)
    parent_scope = parent.scope

    # Custody: only the current holder (parent's delegatee) may delegate onward.
    if signer.key_id != parent.delegatee:
        raise DelegationError(
            f"only the current holder {parent.delegatee!r} may delegate onward, "
            f"not {signer.key_id!r}"
        )

    # Narrowing: child scope ⊆ parent scope.
    if not is_scope_narrower_or_equal(narrowed_scope, parent_scope):
        raise DelegationError(
            "child scope must be ⊆ parent scope: "
            + _scope_violation_reason(narrowed_scope, parent_scope)
        )

    child_not_before = not_before or parent.not_before
    child_expires_at = expires_at or parent.expires_at
    if child_not_before < parent.not_before:
        raise DelegationError("child not_before may not precede parent not_before")
    if child_expires_at > parent.expires_at:
        raise DelegationError("child expiry may not exceed parent expiry")

    child_depth = parent.depth + 1
    if child_depth > parent.max_depth:
        raise DelegationError(
            f"depth {child_depth} exceeds chain max_depth {parent.max_depth}"
        )
    child_max_depth = parent.max_depth if max_depth is None else max_depth
    if child_max_depth > parent.max_depth:
        raise DelegationError("child max_depth may not exceed parent max_depth")

    return _new_receipt(
        delegation_id=delegation_id,
        parent_receipt_hash=receipt_hash(parent_envelope),
        root_mandate_hash=parent.root_mandate_hash,
        delegator=parent.delegatee,
        delegatee=delegatee_key_id,
        scope=narrowed_scope,
        depth=child_depth,
        max_depth=child_max_depth,
        not_before=child_not_before,
        expires_at=child_expires_at,
        constitution_hash=parent.constitution_hash,
        signer=signer,
    )


# ---------------------------------------------------------------------------
# Offline verification — the final enforcement point
# ---------------------------------------------------------------------------
def _resolve_public_key(key_registry: Mapping[str, Any], key_id: str) -> bytes:
    try:
        raw = key_registry[key_id]
    except KeyError as exc:
        raise DelegationError(f"no public key registered for {key_id!r}") from exc
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw)
    if isinstance(raw, str):
        try:
            return base64.b64decode(raw, validate=True)
        except Exception as exc:
            raise DelegationError(f"public key for {key_id!r} is not valid base64") from exc
    raise DelegationError(f"public key for {key_id!r} has unsupported type {type(raw).__name__}")


def _verify_signature(envelope: SignedEnvelope, key_registry: Mapping[str, Any]) -> None:
    pub = _resolve_public_key(key_registry, envelope.key_id)
    try:
        verify_envelope(envelope, pub)
    except Exception as exc:
        raise DelegationError(
            f"signature verification failed for receipt signed by {envelope.key_id!r}: {exc}"
        ) from exc


class VerifiedDelegationChain(StrictModel):
    """What the enforcement point gets after a successful verify_chain()."""

    effective_scope: DelegationScope  # the leaf's scope, proven ⊆ every ancestor
    depth: int  # depth of the leaf receipt (position claim)
    chain_length: int  # number of receipts verified
    ancestor_hashes: list[str]  # receipt hashes, root-first — exactly which chain authorized
    delegatee_chain: list[str]  # delegatee key_id at each hop, root-first
    root_mandate_hash: str
    constitution_hash: str
    leaf_hash: str

    def scope_allows(self, action: str, resource: str) -> bool:
        """Convenience: does the effective scope authorize this action/resource?"""
        scope = self.effective_scope
        if action not in scope.actions:
            return False
        return any(is_sub_prefix(resource, p) for p in scope.resource_prefixes)


def verify_chain(
    receipt_envelopes_ordered_root_first: list[SignedEnvelope],
    *,
    trusted_authority_keys: Any,
    key_registry: Mapping[str, Any],
    now: datetime | None = None,
) -> VerifiedDelegationChain:
    """Verify the WHOLE chain offline. Returns the effective scope.

    Checks, in order:
    1. Root signed by a trusted authority key (signature verifies).
    2. Each receipt i>0 signed by the delegatee key of receipt i-1 (custody).
    3. parent_receipt_hash links match the actual parent envelope hashes.
    4. Depth claims consistent: depth == index, strictly increasing by 1.
    5. The narrowing invariant re-verified at EVERY hop independently.
    6. Expiry windows valid at `now` for every receipt.
    7. No receipt appears twice (no cycles).

    Anything wrong -> DelegationError. Fail closed.
    """
    envelopes = list(receipt_envelopes_ordered_root_first)
    if not envelopes:
        raise DelegationError("empty delegation chain")

    trusted = set(trusted_authority_keys)
    moment = now or _utc_now()
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    else:
        moment = moment.astimezone(timezone.utc)

    receipts: list[DelegationReceipt] = []
    hashes: list[str] = []
    seen_hashes: set[str] = set()
    seen_ids: set[str] = set()

    for index, envelope in enumerate(envelopes):
        # --- parse payload strictly ---
        try:
            receipt = DelegationReceipt.model_validate(envelope.payload)
        except Exception as exc:
            raise DelegationError(f"receipt {index}: malformed payload: {exc}") from exc

        # --- (7) no receipt twice / no cycles ---
        h = receipt_hash(envelope)
        if h in seen_hashes:
            raise DelegationError(f"receipt {index}: receipt appears twice (cycle)")
        seen_hashes.add(h)
        if receipt.delegation_id in seen_ids:
            raise DelegationError(f"receipt {index}: duplicate delegation_id")
        seen_ids.add(receipt.delegation_id)
        hashes.append(h)

        # --- signatures: (1) root, (2) custody for the rest ---
        _verify_signature(envelope, key_registry)
        if index == 0:
            if envelope.key_id not in trusted:
                raise DelegationError(
                    f"root not signed by a trusted authority key "
                    f"(signed by {envelope.key_id!r})"
                )
            if receipt.delegator != envelope.key_id:
                raise DelegationError("root delegator must be the signing authority key")
            if receipt.depth != 0:
                raise DelegationError("root receipt must have depth 0")
            if receipt.parent_receipt_hash is not None:
                raise DelegationError("root receipt must have parent_receipt_hash=None")
        else:
            prev = receipts[index - 1]
            # (2) custody: signed by the delegatee of the previous hop
            if envelope.key_id != prev.delegatee:
                raise DelegationError(
                    f"receipt {index}: signed by {envelope.key_id!r}, expected the "
                    f"delegatee of hop {index - 1} ({prev.delegatee!r}) — custody break"
                )
            if receipt.delegator != prev.delegatee:
                raise DelegationError(
                    f"receipt {index}: delegator {receipt.delegator!r} is not the "
                    f"delegatee of hop {index - 1} ({prev.delegatee!r})"
                )
            # (3) tamper-evident hash linking
            if receipt.parent_receipt_hash != hashes[index - 1]:
                raise DelegationError(
                    f"receipt {index}: parent_receipt_hash does not match hop "
                    f"{index - 1} content hash — link broken"
                )
            # (4) depth consistency
            if receipt.depth != index:
                raise DelegationError(
                    f"receipt {index}: depth claim {receipt.depth} != position {index}"
                )
            if receipt.depth != prev.depth + 1:
                raise DelegationError(
                    f"receipt {index}: depth not strictly increasing by 1 "
                    f"({prev.depth} -> {receipt.depth})"
                )
            # (5) re-verify the narrowing invariant independently
            if not is_scope_narrower_or_equal(receipt.scope, prev.scope):
                raise DelegationError(
                    f"receipt {index}: narrowing invariant violated: "
                    + _scope_violation_reason(receipt.scope, prev.scope)
                )
            if receipt.root_mandate_hash != prev.root_mandate_hash:
                raise DelegationError(
                    f"receipt {index}: root_mandate_hash changed mid-chain"
                )
            if receipt.constitution_hash != prev.constitution_hash:
                raise DelegationError(
                    f"receipt {index}: constitution_hash changed mid-chain"
                )
            if receipt.max_depth > prev.max_depth:
                raise DelegationError(
                    f"receipt {index}: max_depth increased mid-chain"
                )
            if receipt.depth > receipt.max_depth:
                raise DelegationError(
                    f"receipt {index}: depth {receipt.depth} exceeds max_depth "
                    f"{receipt.max_depth}"
                )
            if receipt.not_before < prev.not_before:
                raise DelegationError(
                    f"receipt {index}: not_before precedes parent not_before"
                )
            if receipt.expires_at > prev.expires_at:
                raise DelegationError(
                    f"receipt {index}: expiry exceeds parent expiry"
                )

        # --- (6) expiry window valid at `now`, for EVERY receipt ---
        if not (receipt.not_before <= moment <= receipt.expires_at):
            raise DelegationError(
                f"receipt {index}: not valid at {moment.isoformat()} "
                f"(window {receipt.not_before.isoformat()}..{receipt.expires_at.isoformat()})"
            )

        receipts.append(receipt)

    leaf = receipts[-1]
    return VerifiedDelegationChain(
        effective_scope=leaf.scope,
        depth=leaf.depth,
        chain_length=len(receipts),
        ancestor_hashes=hashes,
        delegatee_chain=[r.delegatee for r in receipts],
        root_mandate_hash=receipts[0].root_mandate_hash,
        constitution_hash=receipts[0].constitution_hash,
        leaf_hash=hashes[-1],
    )


__all__ = [
    "DelegationError",
    "DelegationScope",
    "DelegationReceipt",
    "VerifiedDelegationChain",
    "is_sub_prefix",
    "is_scope_narrower_or_equal",
    "receipt_hash",
    "issue_root",
    "delegate",
    "verify_chain",
]
