"""Tests for state-bound Prepare/Commit (Wave 4, TOCTOU defense):
anchor_v1.state_binding + CapabilityStore.commit_state_bound.

Threat model: a capability authorizes an ACTION, but the authority's
decision depended on STATE at mint time. If the state changes between
prepare and commit, the effect must NOT execute — fail closed, with the
capability left ISSUED and no writes applied.

Every commit path is covered: the happy path, the TOCTOU race, preview
forgery/tampering/expiry/envelope-mismatch, writes outside the read set,
double-commit, and the full existing consume checks (holder proof,
double-spend) still applying inside the atomic commit.
"""

from __future__ import annotations

import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from anchor_v1 import authority
from anchor_v1.canonical import sha256_hex
from anchor_v1.crypto import Ed25519Signer
from anchor_v1.envelope import ActionEnvelope, Effect
from anchor_v1.state_binding import (
    EffectPreview,
    PolicyDecision,
    StateBindingError,
    StateChangedError,
    StatePolicyDenied,
    commit,
    prepare,
    preview_signature_bytes,
)
from anchor_v1.store import AuthorizationDenied, CapabilityStore, DoubleSpendError

NOW = datetime.now(timezone.utc)
POLICY_REF = "constitution-hash-abc"
ALICE = "acct:alice:balance"
BOB = "acct:bob:balance"


# ---------------------------------------------------------------------------
# fixtures / helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def authority_signer() -> Ed25519Signer:
    return Ed25519Signer.generate("authority-1")


@pytest.fixture
def holder_signer() -> Ed25519Signer:
    return Ed25519Signer.generate("holder-1")


@pytest.fixture
def store() -> CapabilityStore:
    s = CapabilityStore()
    s.sync_revocations()
    s.write_state({ALICE: 500, BOB: 100})
    return s


@pytest.fixture
def trusted(authority_signer: Ed25519Signer) -> dict:
    return {
        authority_signer.key_id.encode("utf-8"): Ed25519PublicKey.from_public_bytes(
            authority_signer.public_key_bytes()
        )
    }


def make_envelope(now: datetime = NOW) -> ActionEnvelope:
    return ActionEnvelope(
        action_id=uuid.uuid4(),
        principal="agent-1",
        effect=Effect(
            plane="ledger",
            verb="transfer",
            target="ledger-1",
            args_digest=sha256_hex({"to": "bob", "amount": 100}),
        ),
        policy_ref=POLICY_REF,
        issued_at=now,
        not_before=now,
        not_after=now + timedelta(minutes=5),
        nonce=secrets.token_hex(16),
    )


def transfer_policy(amount: int):
    """Policy: allow iff Alice's balance covers the amount."""

    def policy(state: dict, envelope: ActionEnvelope) -> PolicyDecision:
        balance = state.get(ALICE) or 0
        bob_balance = state.get(BOB) or 0
        if balance < amount:
            return PolicyDecision(allowed=False, outcome={"reason": "insufficient"})
        return PolicyDecision(
            allowed=True,
            outcome={
                "from": "alice",
                "to": "bob",
                "amount": amount,
                "balance_before": balance,
                "balance_after": balance - amount,
            },
            planned_writes={ALICE: balance - amount, BOB: bob_balance + amount},
        )

    return policy


def mint_for_envelope(store, authority_signer, holder_signer, trusted, envelope):
    cose = authority.issue_execution(
        issuer=authority_signer,
        action_digest=envelope.action_digest,
        holder_pubkey=holder_signer.public_key_bytes(),
    )
    payload = authority.verify_capability(cose, trusted, now=NOW)
    store.register_capability(payload)
    return cose, payload


def commit_materials(
    *,
    store,
    authority_signer,
    holder_signer,
    trusted,
    envelope=None,
    policy=None,
    preview=None,
    ttl_seconds: int = 60,
    now: datetime = NOW,
):
    """Build a full valid prepare -> commit bundle. Returns a dict with
    envelope, cose, payload, challenge, proof, preview."""
    envelope = envelope or make_envelope(now=now)
    policy = policy or transfer_policy(100)
    preview = preview or prepare(
        store,
        envelope=envelope,
        read_keys=[ALICE, BOB],
        policy_fn=policy,
        authority_signer=authority_signer,
        ttl_seconds=ttl_seconds,
        now=now,
    )
    cose, payload = mint_for_envelope(
        store, authority_signer, holder_signer, trusted, envelope
    )
    challenge = os.urandom(32)
    proof = authority.make_holder_proof(
        holder_signer, payload.capability_id, challenge
    )
    return {
        "envelope": envelope,
        "cose": cose,
        "payload": payload,
        "challenge": challenge,
        "proof": proof,
        "preview": preview,
    }


def do_commit(store, trusted, bundle, *, now: datetime = NOW):
    return commit(
        store,
        envelope=bundle["envelope"],
        capability_cose=bundle["cose"],
        holder_proof=bundle["proof"],
        challenge=bundle["challenge"],
        trusted_issuers=trusted,
        preview=bundle["preview"],
        preview_trusted_keys=trusted,
        now=now,
    )


# ---------------------------------------------------------------------------
# A. prepare
# ---------------------------------------------------------------------------


class TestPrepare:
    def test_preview_is_signed_and_verifies(self, store, authority_signer, trusted):
        envelope = make_envelope()
        preview = prepare(
            store,
            envelope=envelope,
            read_keys=[ALICE, BOB],
            policy_fn=transfer_policy(100),
            authority_signer=authority_signer,
            now=NOW,
        )
        assert preview.allowed is True
        assert preview.envelope_digest == envelope.action_digest
        assert preview.state_version == 1  # one write_state in fixture
        assert preview.outcome["balance_after"] == 400
        assert preview.planned_writes == {ALICE: 400, BOB: 200}
        assert preview.signature  # signed
        # Tampering with ANY signed field breaks verification.
        tampered = preview.model_copy(update={"outcome": {"evil": True}})
        with pytest.raises(StateBindingError, match="signature invalid"):
            from anchor_v1.state_binding import verify_preview_signature

            verify_preview_signature(tampered, trusted)

    def test_preview_binds_exact_state_values(self, store, authority_signer):
        envelope = make_envelope()
        p1 = prepare(
            store,
            envelope=envelope,
            read_keys=[ALICE],
            policy_fn=transfer_policy(100),
            authority_signer=authority_signer,
            now=NOW,
        )
        store.write_state({ALICE: 999})
        p2 = prepare(
            store,
            envelope=envelope,
            read_keys=[ALICE],
            policy_fn=transfer_policy(100),
            authority_signer=authority_signer,
            now=NOW,
        )
        assert p1.state_digest != p2.state_digest
        assert p1.state_version != p2.state_version

    def test_policy_denial_raises_and_mints_nothing(self, store, authority_signer):
        envelope = make_envelope()
        with pytest.raises(StatePolicyDenied):
            prepare(
                store,
                envelope=envelope,
                read_keys=[ALICE],
                policy_fn=transfer_policy(10_000),  # Alice has 500
                authority_signer=authority_signer,
                now=NOW,
            )

    def test_prepare_rejects_empty_read_keys(self, store, authority_signer):
        with pytest.raises(StateBindingError, match="read key"):
            prepare(
                store,
                envelope=make_envelope(),
                read_keys=[],
                policy_fn=transfer_policy(100),
                authority_signer=authority_signer,
                now=NOW,
            )

    def test_prepare_rejects_nonpositive_ttl(self, store, authority_signer):
        with pytest.raises(StateBindingError, match="ttl"):
            prepare(
                store,
                envelope=make_envelope(),
                read_keys=[ALICE],
                policy_fn=transfer_policy(100),
                authority_signer=authority_signer,
                ttl_seconds=0,
                now=NOW,
            )

    def test_prepare_rejects_bad_policy_return(self, store, authority_signer):
        with pytest.raises(StateBindingError, match="PolicyDecision"):
            prepare(
                store,
                envelope=make_envelope(),
                read_keys=[ALICE],
                policy_fn=lambda state, env: {"allowed": True},  # not a PolicyDecision
                authority_signer=authority_signer,
                now=NOW,
            )

    def test_preview_expiry(self, store, authority_signer):
        preview = prepare(
            store,
            envelope=make_envelope(now=NOW),
            read_keys=[ALICE],
            policy_fn=transfer_policy(100),
            authority_signer=authority_signer,
            ttl_seconds=60,
            now=NOW,
        )
        assert preview.is_expired(NOW + timedelta(seconds=59)) is False
        assert preview.is_expired(NOW + timedelta(seconds=60)) is True


# ---------------------------------------------------------------------------
# B. commit happy path
# ---------------------------------------------------------------------------


class TestCommitHappyPath:
    def test_commit_consumes_and_applies_writes_atomically(
        self, store, authority_signer, holder_signer, trusted
    ):
        bundle = commit_materials(
            store=store,
            authority_signer=authority_signer,
            holder_signer=holder_signer,
            trusted=trusted,
        )
        result = do_commit(store, trusted, bundle)
        assert result["capability_id"] == bundle["payload"].capability_id
        assert result["preview_id"] == bundle["preview"].preview_id
        assert result["applied_writes"] == {ALICE: 400, BOB: 200}
        # Capability is consumed.
        assert store.capability_state(bundle["payload"].capability_id) == "CONSUMED"
        # State moved exactly once, with the agreed values.
        assert store.state_version() == 2
        view = store.read_state([ALICE, BOB])
        assert view.values == {ALICE: 400, BOB: 200}

    def test_commit_without_planned_writes(self, store, authority_signer,
                                           holder_signer, trusted):
        def readonly_policy(state, envelope):
            return PolicyDecision(allowed=True, outcome={"seen": state[ALICE]})

        bundle = commit_materials(
            store=store,
            authority_signer=authority_signer,
            holder_signer=holder_signer,
            trusted=trusted,
            policy=readonly_policy,
        )
        result = do_commit(store, trusted, bundle)
        assert result["applied_writes"] == {}
        assert store.state_version() == 2  # version still bumps (commit happened)
        assert store.read_state([ALICE]).values[ALICE] == 500

    def test_double_commit_fails_second_time(
        self, store, authority_signer, holder_signer, trusted
    ):
        bundle = commit_materials(
            store=store,
            authority_signer=authority_signer,
            holder_signer=holder_signer,
            trusted=trusted,
        )
        do_commit(store, trusted, bundle)
        # Same preview + capability: the capability is CONSUMED now.
        # Fresh holder proof (challenge reuse is fine for this check).
        with pytest.raises(AuthorizationDenied):
            do_commit(store, trusted, bundle)
        # State was applied exactly once.
        assert store.read_state([ALICE]).values[ALICE] == 400


# ---------------------------------------------------------------------------
# C. the TOCTOU race — the core of this slice
# ---------------------------------------------------------------------------


class TestTOCTOU:
    def test_state_change_between_prepare_and_commit_denies(
        self, store, authority_signer, holder_signer, trusted
    ):
        bundle = commit_materials(
            store=store,
            authority_signer=authority_signer,
            holder_signer=holder_signer,
            trusted=trusted,
        )
        # ATTACK: another actor drains Alice's account after prepare.
        store.write_state({ALICE: 50})
        with pytest.raises(StateChangedError, match="state moved since prepare"):
            do_commit(store, trusted, bundle)
        # NOTHING happened: capability still ISSUED, writes not applied.
        assert store.capability_state(bundle["payload"].capability_id) == "ISSUED"
        assert store.read_state([ALICE, BOB]).values == {ALICE: 50, BOB: 100}

    def test_unrelated_key_change_still_denies(
        self, store, authority_signer, holder_signer, trusted
    ):
        # The version is global: ANY state write invalidates in-flight previews.
        bundle = commit_materials(
            store=store,
            authority_signer=authority_signer,
            holder_signer=holder_signer,
            trusted=trusted,
        )
        store.write_state({"some:other:key": "x"})
        with pytest.raises(StateChangedError):
            do_commit(store, trusted, bundle)
        assert store.capability_state(bundle["payload"].capability_id) == "ISSUED"

    def test_key_created_after_prepare_denies(
        self, store, authority_signer, holder_signer, trusted
    ):
        # Missing keys read as None and are digest-covered: creating the key
        # later changes the digest even though the version also moved.
        envelope = make_envelope()
        preview = prepare(
            store,
            envelope=envelope,
            read_keys=["acct:carol:balance"],  # does not exist yet
            policy_fn=lambda s, e: PolicyDecision(allowed=True),
            authority_signer=authority_signer,
            now=NOW,
        )
        cose, payload = mint_for_envelope(
            store, authority_signer, holder_signer, trusted, envelope
        )
        challenge = os.urandom(32)
        proof = authority.make_holder_proof(
            holder_signer, payload.capability_id, challenge
        )
        store.write_state({"acct:carol:balance": 1_000_000})
        with pytest.raises(StateChangedError):
            commit(
                store,
                envelope=envelope,
                capability_cose=cose,
                holder_proof=proof,
                challenge=challenge,
                trusted_issuers=trusted,
                preview=preview,
                preview_trusted_keys=trusted,
                now=NOW,
            )

    def test_interleaved_prepare_commit_prepare_commit(
        self, store, authority_signer, holder_signer, trusted
    ):
        # Two concurrent prepares for the same action: the first commits,
        # the second MUST fail — the state it was approved against is gone.
        b1 = commit_materials(
            store=store,
            authority_signer=authority_signer,
            holder_signer=holder_signer,
            trusted=trusted,
        )
        b2 = commit_materials(
            store=store,
            authority_signer=authority_signer,
            holder_signer=holder_signer,
            trusted=trusted,
        )
        do_commit(store, trusted, b1)
        assert store.read_state([ALICE]).values[ALICE] == 400
        with pytest.raises(StateChangedError):
            do_commit(store, trusted, b2)
        # b2's capability was NOT burned by the failed commit.
        assert store.capability_state(b2["payload"].capability_id) == "ISSUED"


# ---------------------------------------------------------------------------
# D. preview forgery / misuse — all fail closed
# ---------------------------------------------------------------------------


class TestPreviewMisuse:
    def test_forged_preview_signature_denied(
        self, store, authority_signer, holder_signer, trusted
    ):
        bundle = commit_materials(
            store=store,
            authority_signer=authority_signer,
            holder_signer=holder_signer,
            trusted=trusted,
        )
        # Attacker re-signs with their own key.
        attacker = Ed25519Signer.generate("attacker")
        forged = EffectPreview(
            **{
                **bundle["preview"].model_dump(),
                "signature": attacker.sign_bytes(
                    preview_signature_bytes(bundle["preview"])
                ).hex(),
                "authority_key_id": "attacker",
            }
        )
        bundle["preview"] = forged
        with pytest.raises(StateBindingError, match="not trusted"):
            do_commit(store, trusted, bundle)
        assert store.capability_state(bundle["payload"].capability_id) == "ISSUED"

    def test_tampered_planned_writes_denied(
        self, store, authority_signer, holder_signer, trusted
    ):
        bundle = commit_materials(
            store=store,
            authority_signer=authority_signer,
            holder_signer=holder_signer,
            trusted=trusted,
        )
        # Attacker inflates the payout but cannot re-sign.
        tampered = bundle["preview"].model_copy(
            update={"planned_writes": {ALICE: 0, BOB: 10_000_000}}
        )
        bundle["preview"] = tampered
        with pytest.raises(StateBindingError, match="signature invalid"):
            do_commit(store, trusted, bundle)
        assert store.read_state([BOB]).values[BOB] == 100

    def test_tampered_state_binding_denied(
        self, store, authority_signer, holder_signer, trusted
    ):
        bundle = commit_materials(
            store=store,
            authority_signer=authority_signer,
            holder_signer=holder_signer,
            trusted=trusted,
        )
        tampered = bundle["preview"].model_copy(
            update={"state_version": 999, "state_digest": "0" * 64}
        )
        bundle["preview"] = tampered
        with pytest.raises(StateBindingError, match="signature invalid"):
            do_commit(store, trusted, bundle)

    def test_preview_for_other_envelope_denied(
        self, store, authority_signer, holder_signer, trusted
    ):
        bundle = commit_materials(
            store=store,
            authority_signer=authority_signer,
            holder_signer=holder_signer,
            trusted=trusted,
        )
        # The preview belongs to a DIFFERENT envelope (different action).
        bundle["envelope"] = make_envelope()  # fresh action_id/nonce
        with pytest.raises(StateBindingError, match="different envelope"):
            do_commit(store, trusted, bundle)
        assert store.capability_state(bundle["payload"].capability_id) == "ISSUED"

    def test_expired_preview_denied(
        self, store, authority_signer, holder_signer, trusted
    ):
        bundle = commit_materials(
            store=store,
            authority_signer=authority_signer,
            holder_signer=holder_signer,
            trusted=trusted,
            ttl_seconds=60,
            now=NOW,
        )
        with pytest.raises(StateBindingError, match="expired"):
            do_commit(store, trusted, bundle, now=NOW + timedelta(seconds=61))
        assert store.capability_state(bundle["payload"].capability_id) == "ISSUED"

    def test_writes_outside_read_set_denied(
        self, store, authority_signer, holder_signer, trusted
    ):
        # A malicious/buggy policy that writes keys it never read would
        # escape the digest binding — refused at commit time.
        def evil_policy(state, envelope):
            return PolicyDecision(
                allowed=True, planned_writes={"acct:mallory:balance": 999}
            )

        bundle = commit_materials(
            store=store,
            authority_signer=authority_signer,
            holder_signer=holder_signer,
            trusted=trusted,
            policy=evil_policy,
        )
        with pytest.raises(StateChangedError, match="outside its read set"):
            do_commit(store, trusted, bundle)
        assert store.capability_state(bundle["payload"].capability_id) == "ISSUED"


# ---------------------------------------------------------------------------
# E. the existing consume checks still apply inside the atomic commit
# ---------------------------------------------------------------------------


class TestConsumeChecksPreserved:
    def test_wrong_holder_proof_denied(
        self, store, authority_signer, holder_signer, trusted
    ):
        bundle = commit_materials(
            store=store,
            authority_signer=authority_signer,
            holder_signer=holder_signer,
            trusted=trusted,
        )
        bundle["proof"] = os.urandom(64)  # garbage proof
        with pytest.raises(AuthorizationDenied):
            do_commit(store, trusted, bundle)
        # State untouched.
        assert store.read_state([ALICE]).values[ALICE] == 500
        assert store.state_version() == 1

    def test_capability_for_other_digest_denied(
        self, store, authority_signer, holder_signer, trusted
    ):
        bundle = commit_materials(
            store=store,
            authority_signer=authority_signer,
            holder_signer=holder_signer,
            trusted=trusted,
        )
        other_cose, _ = mint_for_envelope(
            store, authority_signer, holder_signer, trusted, make_envelope()
        )
        bundle["cose"] = other_cose  # capability bound to a different action
        with pytest.raises(AuthorizationDenied):
            do_commit(store, trusted, bundle)

    def test_unregistered_capability_denied(
        self, store, authority_signer, holder_signer, trusted
    ):
        bundle = commit_materials(
            store=store,
            authority_signer=authority_signer,
            holder_signer=holder_signer,
            trusted=trusted,
        )
        # Mint but never register with the store.
        cose = authority.issue_execution(
            issuer=authority_signer,
            action_digest=bundle["envelope"].action_digest,
            holder_pubkey=holder_signer.public_key_bytes(),
        )
        payload = authority.verify_capability(cose, trusted, now=NOW)
        challenge = os.urandom(32)
        proof = authority.make_holder_proof(
            holder_signer, payload.capability_id, challenge
        )
        with pytest.raises(AuthorizationDenied):
            commit(
                store,
                envelope=bundle["envelope"],
                capability_cose=cose,
                holder_proof=proof,
                challenge=challenge,
                trusted_issuers=trusted,
                preview=bundle["preview"],
                preview_trusted_keys=trusted,
                now=NOW,
            )

    def test_double_spend_across_commit_and_consume(
        self, store, authority_signer, holder_signer, trusted
    ):
        bundle = commit_materials(
            store=store,
            authority_signer=authority_signer,
            holder_signer=holder_signer,
            trusted=trusted,
        )
        # Burn the capability through the plain consume path first...
        store.consume_capability(
            capability_cose=bundle["cose"],
            holder_proof=bundle["proof"],
            challenge=bundle["challenge"],
            trusted_issuers=trusted,
            envelope=bundle["envelope"],
        )
        # ...then the state-bound commit must refuse it.
        with pytest.raises(DoubleSpendError):
            do_commit(store, trusted, bundle)
        assert store.read_state([ALICE]).values[ALICE] == 500


# ---------------------------------------------------------------------------
# F. store state primitives
# ---------------------------------------------------------------------------


class TestStatePrimitives:
    def test_read_state_digest_is_stable(self, store):
        v1 = store.read_state([ALICE, BOB])
        v2 = store.read_state([BOB, ALICE])  # key order irrelevant
        assert v1.digest == v2.digest
        assert v1.version == v2.version == 1

    def test_write_state_bumps_version(self, store):
        assert store.write_state({ALICE: 1}) == 2
        assert store.write_state({ALICE: 2}) == 3
        assert store.read_state([ALICE]).values[ALICE] == 2

    def test_read_state_rejects_empty_keys(self, store):
        with pytest.raises(Exception):
            store.read_state([])

    def test_missing_key_reads_as_none_and_is_bound(self, store):
        view = store.read_state(["nope:missing"])
        assert view.values == {"nope:missing": None}
        store.write_state({"nope:missing": 1})
        view2 = store.read_state(["nope:missing"])
        assert view2.digest != view.digest
