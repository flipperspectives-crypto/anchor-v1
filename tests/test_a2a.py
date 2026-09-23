"""Tests for Wave 3 A2A 1.0 delegation propagation: anchor_v1.a2a.

Adversarial coverage: anchored agent cards (guardian-signed anchor section),
cross-agent delegation propagation (propagate_delegation / receive_delegation),
monotonic attenuation across the mandate->child hop, wire round-trips, and
legacy card smoke tests (legacy is covered in depth by test_planes.py).

Fail-closed: every attack path must RAISE (CardVerificationError /
DelegationPropagationError / DelegationRejected / CapabilityError), never
silently succeed.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from anchor_v1 import authority, delegation_chains
from anchor_v1.a2a import (
    AnchoredAgentCard,
    CardVerificationError,
    DelegationPackage,
    DelegationPropagationError,
    DelegationRejected,
    build_agent_card,
    build_anchored_agent_card,
    propagate_delegation,
    receive_delegation,
    verify_agent_card,
    verify_anchored_agent_card,
)
from anchor_v1.authority import CapabilityError
from anchor_v1.crypto import Ed25519Signer
from anchor_v1.delegation_chains import DelegationScope
from anchor_v1.envelope import ActionEnvelope, Effect
from anchor_v1.models import SignedEnvelope

NOW = datetime(2026, 9, 23, 15, 0, 0, tzinfo=timezone.utc)
CONSTITUTION = "constitution:test-v1"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def make_envelope(
    *,
    verb: str = "read",
    target: str = "server/files/read",
    principal: str = "agent:alice",
    plane: str = "a2a",
    nonce: str = "test-nonce-1",
) -> ActionEnvelope:
    return ActionEnvelope(
        action_id=uuid.uuid4(),
        principal=principal,
        effect=Effect(
            plane=plane,
            verb=verb,
            target=target,
            args_digest=hashlib.sha256(target.encode()).hexdigest(),
        ),
        policy_ref=CONSTITUTION,
        issued_at=NOW,
        not_before=NOW,
        not_after=NOW + timedelta(hours=1),
        nonce=nonce,
    )


def _issuer_map(signer: Ed25519Signer) -> dict[bytes, Ed25519PublicKey]:
    return {
        signer.key_id.encode("utf-8"): Ed25519PublicKey.from_public_bytes(
            signer.public_key_bytes()
        )
    }


def _mandate(
    *,
    authority_signer: Ed25519Signer,
    envelope: ActionEnvelope,
    holder_pubkey: bytes,
    spend_limit: int | None = None,
    signer: Ed25519Signer | None = None,
    issued_at: datetime = NOW,
) -> bytes:
    return authority.issue_mandate(
        signer or authority_signer,
        action_digest=envelope.action_digest,
        holder_pubkey=holder_pubkey,
        spend_limit=spend_limit,
        ttl=timedelta(hours=1),
        now=issued_at,
    )


def _chain(
    *,
    authority_signer: Ed25519Signer,
    delegator_signer: Ed25519Signer,
    delegatee_signer: Ed25519Signer,
    mandate_cose: bytes,
    scope: DelegationScope | None = None,
) -> list[SignedEnvelope]:
    scope = scope or DelegationScope(actions=["read"], resource_prefixes=["server"])
    window = {"not_before": NOW - timedelta(hours=1), "expires_at": NOW + timedelta(hours=1)}
    root = delegation_chains.issue_root(
        root_mandate_hash=hashlib.sha256(bytes(mandate_cose)).hexdigest(),
        constitution_hash=CONSTITUTION,
        delegatee_key_id=delegator_signer.key_id,
        scope=scope,
        max_depth=3,
        authority_signer=authority_signer,
        **window,
    )
    leaf = delegation_chains.delegate(
        root,
        delegatee_signer.key_id,
        scope,
        delegator_signer,
        **window,
    )
    return [root, leaf]


def _propagate(
    *,
    chain: list[SignedEnvelope],
    mandate_cose: bytes,
    holder_signer: Ed25519Signer,
    trusted_issuers: dict[bytes, Ed25519PublicKey],
    delegatee_signer: Ed25519Signer,
    envelope: ActionEnvelope,
    principal: str = "agent:alice",
    spend_limit: int | None = None,
) -> DelegationPackage:
    return propagate_delegation(
        principal=principal,
        chain_envelopes=chain,
        mandate_cose=mandate_cose,
        holder_signer=holder_signer,
        trusted_issuers=trusted_issuers,
        delegatee_key_id=delegatee_signer.key_id,
        delegatee_pubkey=delegatee_signer.public_key_bytes(),
        action_envelope=envelope,
        spend_limit=spend_limit,
        ttl=timedelta(minutes=15),
        now=NOW,
    )


def _receive(
    package: DelegationPackage | dict,
    *,
    authority_signer: Ed25519Signer,
    key_registry: dict[str, bytes],
    receiver_signer: Ed25519Signer,
    receiver_key_id: str | None = None,
    receiver_pubkey: bytes | None = None,
    revoked_ids=frozenset(),
) -> object:
    return receive_delegation(
        package,
        trusted_authority_keys={authority_signer.key_id},
        key_registry=key_registry,
        receiver_key_id=receiver_key_id or receiver_signer.key_id,
        receiver_pubkey=(
            receiver_pubkey if receiver_pubkey is not None
            else receiver_signer.public_key_bytes()
        ),
        revoked_ids=revoked_ids,
        now=NOW,
    )


@pytest.fixture()
def guardian() -> Ed25519Signer:
    return Ed25519Signer.generate("guardian-1")


@pytest.fixture()
def authority_signer() -> Ed25519Signer:
    return Ed25519Signer.generate("authority-1")


@pytest.fixture()
def delegator_signer() -> Ed25519Signer:
    return Ed25519Signer.generate("delegator-1")


@pytest.fixture()
def delegatee_signer() -> Ed25519Signer:
    return Ed25519Signer.generate("delegatee-1")


@pytest.fixture()
def trusted_issuers(authority_signer) -> dict[bytes, Ed25519PublicKey]:
    return _issuer_map(authority_signer)


@pytest.fixture()
def key_registry(
    authority_signer, delegator_signer, delegatee_signer
) -> dict[str, bytes]:
    return {
        authority_signer.key_id: authority_signer.public_key_bytes(),
        delegator_signer.key_id: delegator_signer.public_key_bytes(),
        delegatee_signer.key_id: delegatee_signer.public_key_bytes(),
    }


@pytest.fixture()
def delegation_bundle(
    authority_signer, delegator_signer, delegatee_signer, trusted_issuers, key_registry
) -> dict:
    """A complete, valid happy-path setup: envelope, mandate, chain, package."""
    envelope = make_envelope()
    mandate_cose = _mandate(
        authority_signer=authority_signer,
        envelope=envelope,
        holder_pubkey=delegator_signer.public_key_bytes(),
    )
    chain = _chain(
        authority_signer=authority_signer,
        delegator_signer=delegator_signer,
        delegatee_signer=delegatee_signer,
        mandate_cose=mandate_cose,
    )
    package = _propagate(
        chain=chain,
        mandate_cose=mandate_cose,
        holder_signer=delegator_signer,
        trusted_issuers=trusted_issuers,
        delegatee_signer=delegatee_signer,
        envelope=envelope,
    )
    return {
        "envelope": envelope,
        "mandate_cose": mandate_cose,
        "chain": chain,
        "package": package,
    }


# ---------------------------------------------------------------------------
# A. anchored card happy path
# ---------------------------------------------------------------------------


class TestAnchoredCardHappyPath:
    def test_build_verify_fields(self, guardian):
        card = build_anchored_agent_card(
            "agent-7",
            "did:example:agent-7",
            guardian_signer=guardian,
            policy_ref=CONSTITUTION,
            enforced_planes=["a2a", "mcp"],
            issued_at=NOW,
        )
        verified = verify_anchored_agent_card(
            card, trusted_guardians={"guardian-1": guardian.public_key_bytes()}
        )
        assert isinstance(verified, AnchoredAgentCard)
        assert verified.agent_id == "agent-7"
        assert verified.did == "did:example:agent-7"
        assert verified.anchor.guardian_key_id == "guardian-1"
        assert verified.anchor.policy_ref == CONSTITUTION
        assert verified.anchor.enforced_planes == ["a2a", "mcp"]
        assert verified.anchor.guardian_pubkey == guardian.public_key_b64()
        assert verified.anchor_signature  # non-empty signature present

    def test_custom_capabilities_and_schemes_merged(self, guardian):
        card = build_anchored_agent_card(
            "agent-7",
            "did:example:agent-7",
            guardian_signer=guardian,
            policy_ref=CONSTITUTION,
            enforced_planes=["a2a"],
            capabilities={"custom": {"x": 1}},
            security_schemes={"customScheme": {"type": "apiKey"}},
            issued_at=NOW,
        )
        assert "anchor" in card["capabilities"]
        assert card["capabilities"]["custom"] == {"x": 1}
        assert "anchorCapability" in card["securitySchemes"]
        assert card["securitySchemes"]["customScheme"] == {"type": "apiKey"}
        verified = verify_anchored_agent_card(
            card, trusted_guardians={"guardian-1": guardian.public_key_bytes()}
        )
        assert verified.capabilities["custom"] == {"x": 1}

    def test_enforced_planes_sorted_and_deduped(self, guardian):
        card = build_anchored_agent_card(
            "agent-7",
            "did:example:agent-7",
            guardian_signer=guardian,
            policy_ref=CONSTITUTION,
            enforced_planes=["mcp", "a2a", "mcp"],
            issued_at=NOW,
        )
        assert card["anchor"]["enforced_planes"] == ["a2a", "mcp"]
        verified = verify_anchored_agent_card(
            card, trusted_guardians={"guardian-1": guardian.public_key_bytes()}
        )
        assert verified.anchor.enforced_planes == ["a2a", "mcp"]


# ---------------------------------------------------------------------------
# B. anchored card attacks
# ---------------------------------------------------------------------------


class TestAnchoredCardAttacks:
    def _card(self, guardian) -> dict:
        return build_anchored_agent_card(
            "agent-7",
            "did:example:agent-7",
            guardian_signer=guardian,
            policy_ref=CONSTITUTION,
            enforced_planes=["a2a"],
            issued_at=NOW,
        )

    def test_tampered_policy_ref_rejected(self, guardian):
        card = self._card(guardian)
        card["anchor"]["policy_ref"] = "constitution:evil-v9"
        with pytest.raises(CardVerificationError):
            verify_anchored_agent_card(
                card, trusted_guardians={"guardian-1": guardian.public_key_bytes()}
            )

    def test_guardian_pubkey_substitution_rejected(self, guardian):
        attacker = Ed25519Signer.generate("guardian-1")  # same key id, other key
        card = self._card(guardian)
        card["anchor"]["guardian_pubkey"] = attacker.public_key_b64()
        with pytest.raises(CardVerificationError, match="substitution"):
            verify_anchored_agent_card(
                card, trusted_guardians={"guardian-1": guardian.public_key_bytes()}
            )

    def test_unknown_guardian_key_id_rejected(self, guardian):
        card = self._card(guardian)
        with pytest.raises(CardVerificationError, match="not trusted"):
            verify_anchored_agent_card(card, trusted_guardians={})

    def test_missing_anchor_signature_rejected(self, guardian):
        card = self._card(guardian)
        del card["anchor_signature"]
        with pytest.raises(CardVerificationError, match="unsigned"):
            verify_anchored_agent_card(
                card, trusted_guardians={"guardian-1": guardian.public_key_bytes()}
            )

    def test_self_signed_by_agent_rejected(self, guardian):
        agent = Ed25519Signer.generate("agent-7-key")
        card = build_anchored_agent_card(
            "agent-7",
            "did:example:agent-7",
            guardian_signer=agent,  # agent signs its own "anchor" section
            policy_ref=CONSTITUTION,
            enforced_planes=["a2a"],
            issued_at=NOW,
        )
        with pytest.raises(CardVerificationError, match="not trusted"):
            verify_anchored_agent_card(
                card, trusted_guardians={"guardian-1": guardian.public_key_bytes()}
            )

    def test_anchor_section_none_rejected(self, guardian):
        card = self._card(guardian)
        card["anchor"] = None
        with pytest.raises(CardVerificationError, match="unsigned"):
            verify_anchored_agent_card(
                card, trusted_guardians={"guardian-1": guardian.public_key_bytes()}
            )

    def test_unknown_plane_rejected_at_build(self, guardian):
        with pytest.raises(ValueError, match="unknown planes"):
            build_anchored_agent_card(
                "agent-7",
                "did:example:agent-7",
                guardian_signer=guardian,
                policy_ref=CONSTITUTION,
                enforced_planes=["a2a", "nope-plane"],
                issued_at=NOW,
            )

    def test_empty_enforced_planes_rejected_at_build(self, guardian):
        with pytest.raises(ValueError, match="non-empty"):
            build_anchored_agent_card(
                "agent-7",
                "did:example:agent-7",
                guardian_signer=guardian,
                policy_ref=CONSTITUTION,
                enforced_planes=[],
                issued_at=NOW,
            )


# ---------------------------------------------------------------------------
# C. propagate happy path
# ---------------------------------------------------------------------------


class TestPropagateHappyPath:
    def test_propagate_fields_sane(self, delegation_bundle, trusted_issuers,
                                   delegator_signer, delegatee_signer):
        package = delegation_bundle["package"]
        envelope = delegation_bundle["envelope"]
        mandate = authority.verify_capability(
            bytes.fromhex(package.mandate_capability_hex), trusted_issuers, now=NOW
        )
        child = authority.verify_capability(
            bytes.fromhex(package.child_capability_hex),
            _issuer_map(delegator_signer),
            now=NOW,
        )
        assert isinstance(package, DelegationPackage)
        assert package.principal == "agent:alice"
        assert package.delegatee_key_id == delegatee_signer.key_id
        assert len(package.chain) == 2  # root + depth-1 leaf
        # child binds the receiver key...
        assert child.holder_pubkey == delegatee_signer.public_key_bytes()
        assert child.kind == "execution"
        # ...was minted from THIS mandate...
        assert child.parent_capability_id == mandate.capability_id
        # ...and all digests agree.
        assert mandate.kind == "mandate"
        assert mandate.action_digest == envelope.action_digest
        assert package.action_digest == envelope.action_digest
        assert child.action_digest == envelope.action_digest

    def test_propagate_attenuates_spend_limit(self, authority_signer, delegator_signer,
                                             delegatee_signer, trusted_issuers):
        envelope = make_envelope(nonce="spend-1")
        mandate_cose = _mandate(
            authority_signer=authority_signer,
            envelope=envelope,
            holder_pubkey=delegator_signer.public_key_bytes(),
            spend_limit=1000,
        )
        chain = _chain(
            authority_signer=authority_signer,
            delegator_signer=delegator_signer,
            delegatee_signer=delegatee_signer,
            mandate_cose=mandate_cose,
        )
        package = _propagate(
            chain=chain,
            mandate_cose=mandate_cose,
            holder_signer=delegator_signer,
            trusted_issuers=trusted_issuers,
            delegatee_signer=delegatee_signer,
            envelope=envelope,
            spend_limit=500,
        )
        child = authority.verify_capability(
            bytes.fromhex(package.child_capability_hex),
            _issuer_map(delegator_signer),
            now=NOW,
        )
        assert child.spend_limit == 500


# ---------------------------------------------------------------------------
# D. propagate attacks
# ---------------------------------------------------------------------------


class TestPropagateAttacks:
    def test_execution_capability_as_mandate_rejected(self, authority_signer,
                                                     delegator_signer, delegatee_signer,
                                                     trusted_issuers):
        envelope = make_envelope(nonce="exec-kind-1")
        execution_cose = authority.issue_execution(
            authority_signer,
            action_digest=envelope.action_digest,
            holder_pubkey=delegator_signer.public_key_bytes(),
            now=NOW,
        )
        chain = _chain(
            authority_signer=authority_signer,
            delegator_signer=delegator_signer,
            delegatee_signer=delegatee_signer,
            mandate_cose=execution_cose,
        )
        with pytest.raises(DelegationPropagationError, match="non-delegable"):
            _propagate(
                chain=chain,
                mandate_cose=execution_cose,
                holder_signer=delegator_signer,
                trusted_issuers=trusted_issuers,
                delegatee_signer=delegatee_signer,
                envelope=envelope,
            )

    def test_wrong_holder_signer_rejected(self, authority_signer, delegator_signer,
                                         delegatee_signer, trusted_issuers):
        envelope = make_envelope(nonce="holder-1")
        impostor = Ed25519Signer.generate("impostor")
        mandate_cose = _mandate(
            authority_signer=authority_signer,
            envelope=envelope,
            holder_pubkey=delegator_signer.public_key_bytes(),
        )
        chain = _chain(
            authority_signer=authority_signer,
            delegator_signer=delegator_signer,
            delegatee_signer=delegatee_signer,
            mandate_cose=mandate_cose,
        )
        with pytest.raises(DelegationPropagationError, match="not the mandate holder"):
            _propagate(
                chain=chain,
                mandate_cose=mandate_cose,
                holder_signer=impostor,
                trusted_issuers=trusted_issuers,
                delegatee_signer=delegatee_signer,
                envelope=envelope,
            )

    def test_envelope_digest_mismatch_rejected(self, authority_signer, delegator_signer,
                                              delegatee_signer, trusted_issuers):
        envelope = make_envelope(nonce="digest-a")
        other_envelope = make_envelope(nonce="digest-b")  # different digest
        assert other_envelope.action_digest != envelope.action_digest
        mandate_cose = _mandate(
            authority_signer=authority_signer,
            envelope=envelope,
            holder_pubkey=delegator_signer.public_key_bytes(),
        )
        chain = _chain(
            authority_signer=authority_signer,
            delegator_signer=delegator_signer,
            delegatee_signer=delegatee_signer,
            mandate_cose=mandate_cose,
        )
        with pytest.raises(DelegationPropagationError, match="digest mismatch"):
            _propagate(
                chain=chain,
                mandate_cose=mandate_cose,
                holder_signer=delegator_signer,
                trusted_issuers=trusted_issuers,
                delegatee_signer=delegatee_signer,
                envelope=other_envelope,
                principal="agent:alice",
            )

    def test_empty_principal_rejected(self, authority_signer, delegator_signer,
                                      delegatee_signer, trusted_issuers):
        envelope = make_envelope(nonce="principal-1")
        mandate_cose = _mandate(
            authority_signer=authority_signer,
            envelope=envelope,
            holder_pubkey=delegator_signer.public_key_bytes(),
        )
        chain = _chain(
            authority_signer=authority_signer,
            delegator_signer=delegator_signer,
            delegatee_signer=delegatee_signer,
            mandate_cose=mandate_cose,
        )
        with pytest.raises(DelegationPropagationError, match="principal"):
            _propagate(
                chain=chain,
                mandate_cose=mandate_cose,
                holder_signer=delegator_signer,
                trusted_issuers=trusted_issuers,
                delegatee_signer=delegatee_signer,
                envelope=envelope,
                principal="",
            )

    def test_bad_delegatee_pubkey_length_rejected(self, authority_signer,
                                                 delegator_signer, delegatee_signer,
                                                 trusted_issuers):
        envelope = make_envelope(nonce="pubkey-1")
        mandate_cose = _mandate(
            authority_signer=authority_signer,
            envelope=envelope,
            holder_pubkey=delegator_signer.public_key_bytes(),
        )
        chain = _chain(
            authority_signer=authority_signer,
            delegator_signer=delegator_signer,
            delegatee_signer=delegatee_signer,
            mandate_cose=mandate_cose,
        )
        with pytest.raises(DelegationPropagationError, match="32 raw bytes"):
            propagate_delegation(
                principal="agent:alice",
                chain_envelopes=chain,
                mandate_cose=mandate_cose,
                holder_signer=delegator_signer,
                trusted_issuers=trusted_issuers,
                delegatee_key_id=delegatee_signer.key_id,
                delegatee_pubkey=b"too-short",
                action_envelope=envelope,
                now=NOW,
            )

    def test_empty_delegatee_key_id_rejected(self, authority_signer, delegator_signer,
                                             delegatee_signer, trusted_issuers):
        envelope = make_envelope(nonce="kid-1")
        mandate_cose = _mandate(
            authority_signer=authority_signer,
            envelope=envelope,
            holder_pubkey=delegator_signer.public_key_bytes(),
        )
        chain = _chain(
            authority_signer=authority_signer,
            delegator_signer=delegator_signer,
            delegatee_signer=delegatee_signer,
            mandate_cose=mandate_cose,
        )
        with pytest.raises(DelegationPropagationError, match="delegatee_key_id"):
            propagate_delegation(
                principal="agent:alice",
                chain_envelopes=chain,
                mandate_cose=mandate_cose,
                holder_signer=delegator_signer,
                trusted_issuers=trusted_issuers,
                delegatee_key_id="",
                delegatee_pubkey=delegatee_signer.public_key_bytes(),
                action_envelope=envelope,
                now=NOW,
            )

    def test_empty_chain_rejected(self, authority_signer, delegator_signer,
                                  delegatee_signer, trusted_issuers):
        envelope = make_envelope(nonce="chain-1")
        mandate_cose = _mandate(
            authority_signer=authority_signer,
            envelope=envelope,
            holder_pubkey=delegator_signer.public_key_bytes(),
        )
        with pytest.raises(DelegationPropagationError, match="non-empty"):
            propagate_delegation(
                principal="agent:alice",
                chain_envelopes=[],
                mandate_cose=mandate_cose,
                holder_signer=delegator_signer,
                trusted_issuers=trusted_issuers,
                delegatee_key_id=delegatee_signer.key_id,
                delegatee_pubkey=delegatee_signer.public_key_bytes(),
                action_envelope=envelope,
                now=NOW,
            )

    def test_garbage_mandate_cose_rejected(self, authority_signer, delegator_signer,
                                          delegatee_signer, trusted_issuers):
        envelope = make_envelope(nonce="cose-1")
        real_mandate = _mandate(
            authority_signer=authority_signer,
            envelope=envelope,
            holder_pubkey=delegator_signer.public_key_bytes(),
        )
        chain = _chain(
            authority_signer=authority_signer,
            delegator_signer=delegator_signer,
            delegatee_signer=delegatee_signer,
            mandate_cose=real_mandate,
        )
        with pytest.raises(DelegationPropagationError, match="mandate capability invalid"):
            _propagate(
                chain=chain,
                mandate_cose=b"definitely-not-cose",
                holder_signer=delegator_signer,
                trusted_issuers=trusted_issuers,
                delegatee_signer=delegatee_signer,
                envelope=envelope,
            )

    def test_expired_mandate_rejected(self, authority_signer, delegator_signer,
                                     delegatee_signer, trusted_issuers):
        envelope = make_envelope(nonce="expired-1")
        stale = _mandate(
            authority_signer=authority_signer,
            envelope=envelope,
            holder_pubkey=delegator_signer.public_key_bytes(),
            issued_at=NOW - timedelta(hours=3),  # expired 2h before NOW
        )
        chain = _chain(
            authority_signer=authority_signer,
            delegator_signer=delegator_signer,
            delegatee_signer=delegatee_signer,
            mandate_cose=stale,
        )
        with pytest.raises(DelegationPropagationError, match="mandate capability invalid"):
            _propagate(
                chain=chain,
                mandate_cose=stale,
                holder_signer=delegator_signer,
                trusted_issuers=trusted_issuers,
                delegatee_signer=delegatee_signer,
                envelope=envelope,
            )


# ---------------------------------------------------------------------------
# E. receive happy path
# ---------------------------------------------------------------------------


class TestReceiveHappyPath:
    def test_receive_verified_delegation(self, delegation_bundle, authority_signer,
                                        delegator_signer, key_registry,
                                        delegatee_signer):
        package = delegation_bundle["package"]
        envelope = delegation_bundle["envelope"]
        verified = _receive(
            package,
            authority_signer=authority_signer,
            key_registry=key_registry,
            receiver_signer=delegatee_signer,
        )
        mandate = authority.verify_capability(
            bytes.fromhex(package.mandate_capability_hex),
            _issuer_map(authority_signer),
            now=NOW,
        )
        child = authority.verify_capability(
            bytes.fromhex(package.child_capability_hex),
            _issuer_map(delegator_signer),
            now=NOW,
        )
        assert verified.principal == "agent:alice"
        assert verified.delegatee_key_id == delegatee_signer.key_id
        assert verified.mandate_id == mandate.capability_id
        assert verified.child_capability_id == child.capability_id
        assert verified.action_digest == envelope.action_digest
        assert verified.effective_scope.actions == ["read"]
        assert verified.chain.chain_length == 2

    def test_receive_accepts_dict_package(self, delegation_bundle, authority_signer,
                                          key_registry, delegatee_signer):
        package_dict = delegation_bundle["package"].model_dump(mode="json")
        verified = _receive(
            package_dict,
            authority_signer=authority_signer,
            key_registry=key_registry,
            receiver_signer=delegatee_signer,
        )
        assert verified.delegatee_key_id == delegatee_signer.key_id

    def test_receive_with_base64_key_registry(self, delegation_bundle, authority_signer,
                                             key_registry, delegatee_signer):
        b64_registry = {
            kid: base64.b64encode(pub).decode("ascii")
            for kid, pub in key_registry.items()
        }
        verified = _receive(
            delegation_bundle["package"],
            authority_signer=authority_signer,
            key_registry=b64_registry,
            receiver_signer=delegatee_signer,
        )
        assert verified.delegatee_key_id == delegatee_signer.key_id


# ---------------------------------------------------------------------------
# F. receive gate attacks (one test per gate)
# ---------------------------------------------------------------------------


class TestReceiveGateAttacks:
    def test_gate1_tampered_chain_payload_rejected(self, delegation_bundle,
                                                  authority_signer, key_registry,
                                                  delegatee_signer):
        pkg = copy.deepcopy(delegation_bundle["package"].model_dump(mode="json"))
        pkg["chain"][0]["payload"]["scope"]["actions"] = ["admin"]
        with pytest.raises(DelegationRejected):
            _receive(pkg, authority_signer=authority_signer,
                     key_registry=key_registry, receiver_signer=delegatee_signer)

    def test_gate1_tampered_chain_signature_rejected(self, delegation_bundle,
                                                     authority_signer, key_registry,
                                                     delegatee_signer):
        pkg = copy.deepcopy(delegation_bundle["package"].model_dump(mode="json"))
        sig = pkg["chain"][1]["signature"]
        flipped = ("A" if sig[0] != "A" else "B") + sig[1:]
        pkg["chain"][1]["signature"] = flipped
        with pytest.raises(DelegationRejected):
            _receive(pkg, authority_signer=authority_signer,
                     key_registry=key_registry, receiver_signer=delegatee_signer)

    def test_gate2_wrong_receiver_key_id_rejected(self, delegation_bundle,
                                                 authority_signer, key_registry,
                                                 delegatee_signer):
        with pytest.raises(DelegationRejected, match="not addressed"):
            _receive(
                delegation_bundle["package"],
                authority_signer=authority_signer,
                key_registry=key_registry,
                receiver_signer=delegatee_signer,
                receiver_key_id="intruder-9",
            )

    def test_gate3_mandate_from_untrusted_issuer_rejected(
        self, authority_signer, delegator_signer, delegatee_signer, key_registry
    ):
        rogue = Ed25519Signer.generate("rogue-authority")
        envelope = make_envelope(nonce="rogue-1")
        mandate_cose = _mandate(
            authority_signer=authority_signer,
            envelope=envelope,
            holder_pubkey=delegator_signer.public_key_bytes(),
            signer=rogue,  # mandate signed by a non-authority key
        )
        chain = _chain(
            authority_signer=authority_signer,
            delegator_signer=delegator_signer,
            delegatee_signer=delegatee_signer,
            mandate_cose=mandate_cose,
        )
        package = _propagate(
            chain=chain,
            mandate_cose=mandate_cose,
            holder_signer=delegator_signer,
            trusted_issuers=_issuer_map(rogue),  # rogue trusted only at propagate
            delegatee_signer=delegatee_signer,
            envelope=envelope,
        )
        # receive trusts ONLY the real authority key -> rogue kid unknown
        with pytest.raises(DelegationRejected, match="mandate capability invalid"):
            _receive(
                package,
                authority_signer=authority_signer,
                key_registry=key_registry,
                receiver_signer=delegatee_signer,
            )

    def test_gate4_mandate_holder_not_leaf_delegator_rejected(
        self, authority_signer, delegator_signer, delegatee_signer,
        trusted_issuers, key_registry
    ):
        outsider = Ed25519Signer.generate("outsider-holder")
        envelope = make_envelope(nonce="holder-x-1")
        mandate_cose = _mandate(
            authority_signer=authority_signer,
            envelope=envelope,
            holder_pubkey=outsider.public_key_bytes(),  # holder != chain delegator
        )
        chain = _chain(
            authority_signer=authority_signer,
            delegator_signer=delegator_signer,
            delegatee_signer=delegatee_signer,
            mandate_cose=mandate_cose,
        )
        # propagate passes: the real mandate holder (outsider) is the signer
        package = _propagate(
            chain=chain,
            mandate_cose=mandate_cose,
            holder_signer=outsider,
            trusted_issuers=trusted_issuers,
            delegatee_signer=delegatee_signer,
            envelope=envelope,
        )
        with pytest.raises(DelegationRejected, match="not the chain's leaf delegator"):
            _receive(
                package,
                authority_signer=authority_signer,
                key_registry=key_registry,
                receiver_signer=delegatee_signer,
            )

    def test_gate5_swapped_child_parent_binding_rejected(
        self, authority_signer, delegator_signer, delegatee_signer,
        trusted_issuers, key_registry
    ):
        envelope = make_envelope(nonce="swap-1")

        def _pkg(nonce_suffix: str) -> DelegationPackage:
            mandate_cose = _mandate(
                authority_signer=authority_signer,
                envelope=envelope,
                holder_pubkey=delegator_signer.public_key_bytes(),
            )
            chain = _chain(
                authority_signer=authority_signer,
                delegator_signer=delegator_signer,
                delegatee_signer=delegatee_signer,
                mandate_cose=mandate_cose,
            )
            return _propagate(
                chain=chain,
                mandate_cose=mandate_cose,
                holder_signer=delegator_signer,
                trusted_issuers=trusted_issuers,
                delegatee_signer=delegatee_signer,
                envelope=envelope,
                principal=f"agent:{nonce_suffix}",
            )

        pkg1 = _pkg("one")
        pkg2 = _pkg("two")
        swapped = copy.deepcopy(pkg1.model_dump(mode="json"))
        swapped["child_capability_hex"] = pkg2.child_capability_hex
        with pytest.raises(DelegationRejected, match="parent binding mismatch"):
            _receive(swapped, authority_signer=authority_signer,
                     key_registry=key_registry, receiver_signer=delegatee_signer)

    def test_gate5_child_bound_to_different_key_rejected(self, delegation_bundle,
                                                        authority_signer,
                                                        key_registry, delegatee_signer):
        # correct key id (passes gate 2) but a receiver pubkey the child was
        # NOT minted for -> gate 5 receiver binding must fail
        impostor = Ed25519Signer.generate("impostor-receiver")
        with pytest.raises(DelegationRejected, match="not bound to this receiver"):
            _receive(
                delegation_bundle["package"],
                authority_signer=authority_signer,
                key_registry=key_registry,
                receiver_signer=delegatee_signer,
                receiver_pubkey=impostor.public_key_bytes(),
            )

    def test_gate6_tampered_envelope_digest_rejected(self, delegation_bundle,
                                                     authority_signer, key_registry,
                                                     delegatee_signer):
        pkg = copy.deepcopy(delegation_bundle["package"].model_dump(mode="json"))
        pkg["action_envelope"]["nonce"] = "tampered-nonce"  # digest now differs
        with pytest.raises(DelegationRejected, match="does not match"):
            _receive(pkg, authority_signer=authority_signer,
                     key_registry=key_registry, receiver_signer=delegatee_signer)

    def test_gate7_scope_action_not_authorized_rejected(
        self, authority_signer, delegator_signer, delegatee_signer,
        trusted_issuers, key_registry
    ):
        envelope = make_envelope(nonce="scope-1", verb="read", target="server/files")
        mandate_cose = _mandate(
            authority_signer=authority_signer,
            envelope=envelope,
            holder_pubkey=delegator_signer.public_key_bytes(),
        )
        narrow = DelegationScope(actions=["write"], resource_prefixes=["other"])
        chain = _chain(
            authority_signer=authority_signer,
            delegator_signer=delegator_signer,
            delegatee_signer=delegatee_signer,
            mandate_cose=mandate_cose,
            scope=narrow,
        )
        package = _propagate(
            chain=chain,
            mandate_cose=mandate_cose,
            holder_signer=delegator_signer,
            trusted_issuers=trusted_issuers,
            delegatee_signer=delegatee_signer,
            envelope=envelope,
        )
        with pytest.raises(DelegationRejected, match="does not authorize"):
            _receive(package, authority_signer=authority_signer,
                     key_registry=key_registry, receiver_signer=delegatee_signer)

    def test_gate7_scope_prefix_boundary_rejected(
        self, authority_signer, delegator_signer, delegatee_signer,
        trusted_issuers, key_registry
    ):
        # "server" prefix must NOT authorize the sibling "server-evil/..." path
        envelope = make_envelope(nonce="scope-2", verb="read", target="server-evil/files")
        mandate_cose = _mandate(
            authority_signer=authority_signer,
            envelope=envelope,
            holder_pubkey=delegator_signer.public_key_bytes(),
        )
        scope = DelegationScope(actions=["read"], resource_prefixes=["server"])
        chain = _chain(
            authority_signer=authority_signer,
            delegator_signer=delegator_signer,
            delegatee_signer=delegatee_signer,
            mandate_cose=mandate_cose,
            scope=scope,
        )
        package = _propagate(
            chain=chain,
            mandate_cose=mandate_cose,
            holder_signer=delegator_signer,
            trusted_issuers=trusted_issuers,
            delegatee_signer=delegatee_signer,
            envelope=envelope,
        )
        with pytest.raises(DelegationRejected, match="does not authorize"):
            _receive(package, authority_signer=authority_signer,
                     key_registry=key_registry, receiver_signer=delegatee_signer)

    def test_gate8_revoked_mandate_rejected(self, delegation_bundle, authority_signer,
                                           trusted_issuers, key_registry,
                                           delegatee_signer):
        mandate = authority.verify_capability(
            bytes.fromhex(delegation_bundle["package"].mandate_capability_hex),
            trusted_issuers,
            now=NOW,
        )
        with pytest.raises(DelegationRejected, match="mandate"):
            _receive(
                delegation_bundle["package"],
                authority_signer=authority_signer,
                key_registry=key_registry,
                receiver_signer=delegatee_signer,
                revoked_ids={mandate.capability_id},
            )

    def test_gate8_revoked_child_rejected(self, delegation_bundle, authority_signer,
                                         delegator_signer, key_registry,
                                         delegatee_signer):
        child = authority.verify_capability(
            bytes.fromhex(delegation_bundle["package"].child_capability_hex),
            _issuer_map(delegator_signer),
            now=NOW,
        )
        with pytest.raises(DelegationRejected, match="child capability was revoked"):
            _receive(
                delegation_bundle["package"],
                authority_signer=authority_signer,
                key_registry=key_registry,
                receiver_signer=delegatee_signer,
                revoked_ids={child.capability_id},
            )

    def test_authority_key_missing_from_registry_rejected(self, delegation_bundle,
                                                         authority_signer,
                                                         key_registry, delegatee_signer):
        # Gate (1) passes (the chain's root key IS registered), but gate (3)
        # iterates every trusted authority key id — the ghost id has no
        # registered key -> fail closed.
        with pytest.raises(DelegationRejected, match="no public key registered"):
            receive_delegation(
                delegation_bundle["package"],
                trusted_authority_keys={authority_signer.key_id, "ghost-authority"},
                key_registry=key_registry,
                receiver_key_id=delegatee_signer.key_id,
                receiver_pubkey=delegatee_signer.public_key_bytes(),
                now=NOW,
            )


# ---------------------------------------------------------------------------
# G. attenuation monotonicity
# ---------------------------------------------------------------------------


class TestAttenuationMonotonicity:
    def test_amplified_spend_limit_rejected(self, authority_signer, delegator_signer,
                                           delegatee_signer, trusted_issuers):
        envelope = make_envelope(nonce="atten-1")
        mandate_cose = _mandate(
            authority_signer=authority_signer,
            envelope=envelope,
            holder_pubkey=delegator_signer.public_key_bytes(),
            spend_limit=1000,
        )
        with pytest.raises(CapabilityError, match="attenuation violated"):
            authority.mint_child(
                mandate_cose,
                delegator_signer,
                trusted_issuers,
                holder_pubkey=delegatee_signer.public_key_bytes(),
                spend_limit=1500,  # amplification: 1500 > 1000
                ttl=timedelta(minutes=15),
                now=NOW,
            )

    def test_equal_spend_limit_allowed(self, authority_signer, delegator_signer,
                                      delegatee_signer, trusted_issuers):
        envelope = make_envelope(nonce="atten-2")
        mandate_cose = _mandate(
            authority_signer=authority_signer,
            envelope=envelope,
            holder_pubkey=delegator_signer.public_key_bytes(),
            spend_limit=1000,
        )
        child_cose = authority.mint_child(
            mandate_cose,
            delegator_signer,
            trusted_issuers,
            holder_pubkey=delegatee_signer.public_key_bytes(),
            spend_limit=1000,  # boundary: equal is not amplification
            ttl=timedelta(minutes=15),
            now=NOW,
        )
        child = authority.verify_capability(
            child_cose, _issuer_map(delegator_signer), now=NOW
        )
        assert child.spend_limit == 1000

    def test_unbounded_parent_may_set_child_limit(self, authority_signer,
                                                 delegator_signer, delegatee_signer,
                                                 trusted_issuers):
        envelope = make_envelope(nonce="atten-3")
        mandate_cose = _mandate(
            authority_signer=authority_signer,
            envelope=envelope,
            holder_pubkey=delegator_signer.public_key_bytes(),
            spend_limit=None,  # unbounded parent
        )
        child_cose = authority.mint_child(
            mandate_cose,
            delegator_signer,
            trusted_issuers,
            holder_pubkey=delegatee_signer.public_key_bytes(),
            spend_limit=250,
            ttl=timedelta(minutes=15),
            now=NOW,
        )
        child = authority.verify_capability(
            child_cose, _issuer_map(delegator_signer), now=NOW
        )
        assert child.spend_limit == 250


# ---------------------------------------------------------------------------
# H. wire round-trip
# ---------------------------------------------------------------------------


class TestWireRoundTrip:
    def test_package_json_round_trip_then_receive(self, delegation_bundle,
                                                 authority_signer, key_registry,
                                                 delegatee_signer):
        wire = json.dumps(delegation_bundle["package"].model_dump(mode="json"))
        restored = DelegationPackage.model_validate(json.loads(wire))
        verified = _receive(
            restored,
            authority_signer=authority_signer,
            key_registry=key_registry,
            receiver_signer=delegatee_signer,
        )
        assert verified.action_digest == delegation_bundle["envelope"].action_digest
        assert verified.delegatee_key_id == delegatee_signer.key_id


# ---------------------------------------------------------------------------
# I. legacy card smoke tests (deep coverage lives in test_planes.py)
# ---------------------------------------------------------------------------


class TestLegacyCardSmoke:
    def _card(self, agent, governor_pubkey):
        return build_agent_card(
            "agent-7",
            "did:example:agent-7",
            governor_pubkey,
            ["a2a", "mcp"],
            "constitution:hash-1",
            agent_signer=agent,
            issued_at=NOW,
        )

    def test_legacy_card_happy_path(self):
        agent = Ed25519Signer.generate("did-key-1")
        card = self._card(agent, agent.public_key_bytes())
        body = verify_agent_card(
            card, trusted_dids={"did:example:agent-7": agent.public_key_bytes()}
        )
        assert body.agent_id == "agent-7"
        assert body.anchor_enforcement.planes == ["a2a", "mcp"]

    def test_legacy_card_tampered_body_rejected(self):
        agent = Ed25519Signer.generate("did-key-1")
        card = self._card(agent, agent.public_key_bytes())
        card["agent_id"] = "agent-evil"  # mutate after signing
        with pytest.raises(CardVerificationError):
            verify_agent_card(
                card, trusted_dids={"did:example:agent-7": agent.public_key_bytes()}
            )
