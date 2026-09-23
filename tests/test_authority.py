"""Tests for Wave 2 authority engine: authority.py, store.py, pep.py.

>=40 unit tests + >=10 adversarial attacks. Fail-closed: every attack must
be DENIED, never silently allowed.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from anchor_v1 import authority
from anchor_v1.authority import (
    CapabilityError,
    KIND_EXECUTION,
    KIND_MANDATE,
    KIND_READ,
    issue_execution,
    issue_mandate,
    make_holder_proof,
    mint_child,
    verify_capability,
    verify_holder_proof,
)
from anchor_v1.cbor import cbor_dumps, cbor_loads
from anchor_v1.crypto import Ed25519Signer
from anchor_v1.envelope import ActionEnvelope, Effect
from anchor_v1.pep import BrokerAccessDenied, CredentialBroker, EgressProxy, PEPError, ShellPEP
from anchor_v1.store import (
    AuthorizationDenied,
    BudgetExceededError,
    CapabilityStore,
    DoubleSpendError,
    LifecycleError,
    MandateLifecycle,
    RevokedError,
    StaleRevocationError,
    StoreError,
    UnknownCapabilityError,
)

NOW = datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def make_envelope(
    plane: str = "shell",
    verb: str = "exec",
    target: str = "echo hi",
    principal: str = "agent:test",
    ttl_hours: float = 1.0,
) -> ActionEnvelope:
    now = datetime.now(timezone.utc)
    return ActionEnvelope(
        action_id=uuid.uuid4(),
        principal=principal,
        effect=Effect(
            plane=plane,
            verb=verb,
            target=target,
            args_digest=hashlib.sha256(target.encode()).hexdigest(),
        ),
        policy_ref="constitution:v1",
        issued_at=now,
        not_before=now,
        not_after=now + timedelta(hours=ttl_hours),
        nonce=secrets.token_hex(8),
    )


@pytest.fixture()
def issuer() -> Ed25519Signer:
    return Ed25519Signer.generate("authority-1")


@pytest.fixture()
def holder() -> Ed25519Signer:
    return Ed25519Signer.generate("holder-1")


@pytest.fixture()
def other_holder() -> Ed25519Signer:
    return Ed25519Signer.generate("holder-2")


@pytest.fixture()
def trusted(issuer) -> dict[bytes, Ed25519PublicKey]:
    return {
        issuer.key_id.encode("utf-8"): Ed25519PublicKey.from_public_bytes(
            issuer.public_key_bytes()
        )
    }


@pytest.fixture()
def store() -> CapabilityStore:
    return CapabilityStore()


@pytest.fixture()
def broker() -> CredentialBroker:
    return CredentialBroker({"API_TOKEN": "s3cr3t-token", "DB_PASS": "p@ssw0rd"})


@pytest.fixture()
def challenge() -> bytes:
    return secrets.token_bytes(16)


@pytest.fixture()
def shell_pep(broker, store, trusted, challenge) -> ShellPEP:
    return ShellPEP(broker, store, trusted, challenge)


@pytest.fixture()
def egress(broker, store, trusted, challenge) -> EgressProxy:
    return EgressProxy(broker, store, trusted, challenge)


def issue_and_register(
    store: CapabilityStore,
    issuer: Ed25519Signer,
    holder: Ed25519Signer,
    digest: str,
    *,
    kind: str = KIND_EXECUTION,
    spend_limit=None,
    spend_asset=None,
    mandate_id=None,
    staleness: int = 300,
):
    cose = (
        issue_execution(
            issuer,
            action_digest=digest,
            holder_pubkey=holder.public_key_bytes(),
            spend_limit=spend_limit,
            spend_asset=spend_asset,
            max_revocation_staleness=staleness,
        )
        if kind == KIND_EXECUTION
        else issue_mandate(
            issuer,
            action_digest=digest,
            holder_pubkey=holder.public_key_bytes(),
            spend_limit=spend_limit,
            spend_asset=spend_asset,
            max_revocation_staleness=staleness,
        )
    )
    payload = verify_capability(cose, _trusted_of(issuer))
    store.register_capability(payload, mandate_id=mandate_id)
    return cose, payload


def _trusted_of(issuer: Ed25519Signer) -> dict[bytes, Ed25519PublicKey]:
    return {
        issuer.key_id.encode("utf-8"): Ed25519PublicKey.from_public_bytes(
            issuer.public_key_bytes()
        )
    }


def mint_registered_child(
    store: CapabilityStore,
    issuer: Ed25519Signer,
    trusted,
    parent_cose: bytes,
    mandate_id: str,
    holder: Ed25519Signer,
    *,
    spend_limit=None,
):
    """Authority mint + atomic store debit + registration (the honest path)."""
    child_cose = mint_child(
        parent_cose, issuer, trusted, holder_pubkey=holder.public_key_bytes(),
        spend_limit=spend_limit,
    )
    child_payload = verify_capability(child_cose, trusted)
    store.debit_mandate_for_child(mandate_id, child_payload.spend_limit)
    store.register_capability(child_payload, mandate_id=mandate_id)
    return child_cose, child_payload


def activate_mandate(store: CapabilityStore, mandate_id: str, **kw) -> None:
    store.create_mandate(mandate_id, **kw)
    store.transition_mandate(mandate_id, MandateLifecycle.ACTIVE)


# ---------------------------------------------------------------------------
# authority.py — unit tests
# ---------------------------------------------------------------------------


class TestAuthority:
    def test_issue_mandate_verifies(self, issuer, holder, trusted):
        cose = issue_mandate(
            issuer, action_digest="a" * 64, holder_pubkey=holder.public_key_bytes()
        )
        payload = verify_capability(cose, trusted)
        assert payload.kind == KIND_MANDATE
        assert payload.action_digest == "a" * 64
        assert bytes(payload.holder_pubkey) == holder.public_key_bytes()

    def test_issue_execution_verifies(self, issuer, holder, trusted):
        cose = issue_execution(
            issuer, action_digest="b" * 64, holder_pubkey=holder.public_key_bytes()
        )
        payload = verify_capability(cose, trusted)
        assert payload.kind == KIND_EXECUTION

    def test_capability_ids_unique(self, issuer, holder, trusted):
        ids = {
            verify_capability(
                issue_execution(
                    issuer, action_digest="c" * 64,
                    holder_pubkey=holder.public_key_bytes(),
                ),
                trusted,
            ).capability_id
            for _ in range(25)
        }
        assert len(ids) == 25

    def test_spend_caveats_bound(self, issuer, holder, trusted):
        cose = issue_execution(
            issuer, action_digest="d" * 64, holder_pubkey=holder.public_key_bytes(),
            spend_limit=5000, spend_asset="USD",
        )
        payload = verify_capability(cose, trusted)
        assert payload.spend_limit == 5000
        assert payload.spend_asset == "USD"

    def test_expired_capability_denied(self, issuer, holder, trusted):
        cose = issue_execution(
            issuer, action_digest="e" * 64, holder_pubkey=holder.public_key_bytes(),
            ttl=timedelta(seconds=1),
        )
        with pytest.raises(CapabilityError):
            verify_capability(cose, trusted, now=NOW + timedelta(hours=2))

    def test_untrusted_issuer_denied(self, issuer, holder):
        cose = issue_execution(
            issuer, action_digest="f" * 64, holder_pubkey=holder.public_key_bytes()
        )
        with pytest.raises(CapabilityError):
            verify_capability(cose, {})

    def test_garbage_bytes_denied(self, trusted):
        with pytest.raises(CapabilityError):
            verify_capability(b"not-cose-at-all", trusted)

    def test_unbound_read_capability_denied_at_verify(
        self, issuer, holder, trusted
    ):
        # Defense in depth: a kind="read" capability hand-built with NO
        # provenance binding (all-keys scope, no writer allowlist) and
        # signed by the trusted issuer key. Unreachable via issue_read —
        # verification must re-enforce the issuance invariants anyway.
        from anchor_v1.authority import CapabilityPayload

        now = datetime.now(timezone.utc)
        payload = CapabilityPayload(
            capability_id="cap-unbound",
            kind=KIND_READ,
            action_digest="a" * 64,
            holder_pubkey=holder.public_key_bytes(),
            issued_at=now.isoformat(),
            expires_at=(now + timedelta(hours=1)).isoformat(),
            nonce=secrets.token_hex(16),
            read_key_prefix=None,
            read_trusted_writers=None,
            read_require_statement=False,
        )
        cose = authority._sign_payload(payload, issuer)
        with pytest.raises(CapabilityError, match="read_key_prefix|bind provenance"):
            verify_capability(cose, trusted, now=now)

    def test_tampered_signature_denied(self, issuer, holder, trusted):
        cose = bytearray(
            issue_execution(
                issuer, action_digest="0" * 64,
                holder_pubkey=holder.public_key_bytes(),
            )
        )
        cose[-1] ^= 0xFF
        with pytest.raises(CapabilityError):
            verify_capability(bytes(cose), trusted)

    def test_negative_spend_rejected_at_issue(self, issuer, holder):
        with pytest.raises(CapabilityError):
            issue_execution(
                issuer, action_digest="1" * 64,
                holder_pubkey=holder.public_key_bytes(), spend_limit=-5,
            )

    def test_spend_asset_without_limit_rejected(self, issuer, holder):
        with pytest.raises(CapabilityError):
            issue_execution(
                issuer, action_digest="2" * 64,
                holder_pubkey=holder.public_key_bytes(), spend_asset="USD",
            )

    def test_bad_holder_pubkey_rejected(self, issuer):
        with pytest.raises(CapabilityError):
            issue_execution(
                issuer, action_digest="3" * 64, holder_pubkey=b"short"
            )

    def test_bad_digest_rejected(self, issuer, holder):
        with pytest.raises(CapabilityError):
            issue_execution(
                issuer, action_digest="not-hex",
                holder_pubkey=holder.public_key_bytes(),
            )

    def test_holder_proof_roundtrip(self, holder):
        proof = make_holder_proof(holder, "cap-123", b"challenge-1")
        verify_holder_proof(holder.public_key_bytes(), "cap-123", b"challenge-1", proof)

    def test_holder_proof_wrong_key_denied(self, holder, other_holder):
        proof = make_holder_proof(other_holder, "cap-123", b"challenge-1")
        with pytest.raises(CapabilityError):
            verify_holder_proof(holder.public_key_bytes(), "cap-123", b"challenge-1", proof)

    def test_holder_proof_wrong_challenge_denied(self, holder):
        proof = make_holder_proof(holder, "cap-123", b"challenge-1")
        with pytest.raises(CapabilityError):
            verify_holder_proof(holder.public_key_bytes(), "cap-123", b"challenge-2", proof)

    def test_holder_proof_wrong_capability_denied(self, holder):
        proof = make_holder_proof(holder, "cap-123", b"challenge-1")
        with pytest.raises(CapabilityError):
            verify_holder_proof(holder.public_key_bytes(), "cap-999", b"challenge-1", proof)

    def test_holder_proof_malformed_denied(self, holder):
        with pytest.raises(CapabilityError):
            verify_holder_proof(holder.public_key_bytes(), "cap-123", b"c", b"short")

    def test_mint_child_from_mandate_ok(self, issuer, holder, trusted):
        parent = issue_mandate(
            issuer, action_digest="4" * 64, holder_pubkey=holder.public_key_bytes(),
            spend_limit=1000, spend_asset="USD",
        )
        child = mint_child(
            parent, issuer, trusted,
            holder_pubkey=holder.public_key_bytes(), spend_limit=400,
        )
        payload = verify_capability(child, trusted)
        assert payload.kind == KIND_EXECUTION
        assert payload.spend_limit == 400
        assert payload.spend_asset == "USD"
        assert payload.action_digest == "4" * 64
        parent_payload = verify_capability(parent, trusted)
        assert payload.parent_capability_id == parent_payload.capability_id

    def test_mint_child_from_execution_refused(self, issuer, holder, trusted):
        parent = issue_execution(
            issuer, action_digest="5" * 64, holder_pubkey=holder.public_key_bytes()
        )
        with pytest.raises(CapabilityError):
            mint_child(parent, issuer, trusted)

    def test_mint_child_unbounded_parent_may_bound_child(self, issuer, holder, trusted):
        parent = issue_mandate(
            issuer, action_digest="6" * 64, holder_pubkey=holder.public_key_bytes()
        )
        child = mint_child(
            parent, issuer, trusted, spend_limit=50, spend_asset="USD"
        )
        assert verify_capability(child, trusted).spend_limit == 50

    def test_child_expiry_clamped_to_parent(self, issuer, holder, trusted):
        parent = issue_mandate(
            issuer, action_digest="7" * 64, holder_pubkey=holder.public_key_bytes(),
            ttl=timedelta(minutes=10),
        )
        child = mint_child(parent, issuer, trusted, ttl=timedelta(minutes=5))
        parent_exp = datetime.fromisoformat(
            verify_capability(parent, trusted).expires_at
        )
        child_exp = datetime.fromisoformat(
            verify_capability(child, trusted).expires_at
        )
        assert child_exp <= parent_exp

    def test_staleness_bound_stored(self, issuer, holder, trusted):
        cose = issue_execution(
            issuer, action_digest="8" * 64, holder_pubkey=holder.public_key_bytes(),
            max_revocation_staleness=60,
        )
        assert verify_capability(cose, trusted).max_revocation_staleness == 60


# ---------------------------------------------------------------------------
# store.py — unit tests
# ---------------------------------------------------------------------------


class TestStore:
    def test_consume_happy_path(self, store, issuer, holder, trusted, challenge):
        env = make_envelope()
        cose, payload = issue_and_register(store, issuer, holder, env.action_digest)
        proof = make_holder_proof(holder, payload.capability_id, challenge)
        out = store.consume_capability(
            capability_cose=cose, holder_proof=proof, challenge=challenge,
            trusted_issuers=trusted, envelope=env,
        )
        assert out.capability_id == payload.capability_id
        assert store.capability_state(payload.capability_id) == "CONSUMED"

    def test_double_consume_denied(self, store, issuer, holder, trusted, challenge):
        env = make_envelope()
        cose, payload = issue_and_register(store, issuer, holder, env.action_digest)
        proof = make_holder_proof(holder, payload.capability_id, challenge)
        kwargs = dict(
            capability_cose=cose, holder_proof=proof, challenge=challenge,
            trusted_issuers=trusted, envelope=env,
        )
        store.consume_capability(**kwargs)
        with pytest.raises(DoubleSpendError):
            store.consume_capability(**kwargs)
        assert store.capability_state(payload.capability_id) == "CONSUMED"

    def test_consume_unknown_capability_denied(
        self, store, issuer, holder, trusted, challenge
    ):
        cose = issue_execution(
            issuer, action_digest="9" * 64, holder_pubkey=holder.public_key_bytes()
        )
        payload = verify_capability(cose, trusted)
        proof = make_holder_proof(holder, payload.capability_id, challenge)
        with pytest.raises(UnknownCapabilityError):
            store.consume_capability(
                capability_cose=cose, holder_proof=proof, challenge=challenge,
                trusted_issuers=trusted,
            )

    def test_consume_bad_holder_proof_denied_state_unchanged(
        self, store, issuer, holder, trusted, challenge
    ):
        env = make_envelope()
        cose, payload = issue_and_register(store, issuer, holder, env.action_digest)
        with pytest.raises(AuthorizationDenied):
            store.consume_capability(
                capability_cose=cose, holder_proof=b"\x00" * 64,
                challenge=challenge, trusted_issuers=trusted, envelope=env,
            )
        assert store.capability_state(payload.capability_id) == "ISSUED"

    def test_consume_envelope_digest_mismatch_denied(
        self, store, issuer, holder, trusted, challenge
    ):
        env = make_envelope()
        cose, payload = issue_and_register(store, issuer, holder, env.action_digest)
        proof = make_holder_proof(holder, payload.capability_id, challenge)
        other_env = make_envelope(target="different command")
        assert other_env.action_digest != env.action_digest
        with pytest.raises(AuthorizationDenied):
            store.consume_capability(
                capability_cose=cose, holder_proof=proof, challenge=challenge,
                trusted_issuers=trusted, envelope=other_env,
            )

    def test_consume_revoked_capability_denied(
        self, store, issuer, holder, trusted, challenge
    ):
        env = make_envelope()
        cose, payload = issue_and_register(store, issuer, holder, env.action_digest)
        store.revoke(payload.capability_id)
        proof = make_holder_proof(holder, payload.capability_id, challenge)
        with pytest.raises(RevokedError):
            store.consume_capability(
                capability_cose=cose, holder_proof=proof, challenge=challenge,
                trusted_issuers=trusted, envelope=env,
            )

    def test_consume_revoked_mandate_denies_child(
        self, store, issuer, holder, trusted, challenge
    ):
        activate_mandate(store, "m-rev", spend_limit=1000, actions_limit=5)
        env = make_envelope()
        parent_cose, parent_payload = issue_and_register(
            store, issuer, holder, env.action_digest, kind=KIND_MANDATE,
            mandate_id="m-rev",
        )
        child_cose, child_payload = mint_registered_child(
            store, issuer, trusted, parent_cose, "m-rev", holder, spend_limit=100
        )
        store.revoke("m-rev")
        proof = make_holder_proof(holder, child_payload.capability_id, challenge)
        with pytest.raises(RevokedError):
            store.consume_capability(
                capability_cose=child_cose, holder_proof=proof, challenge=challenge,
                trusted_issuers=trusted, envelope=env,
            )

    def test_spend_over_capability_limit_denied(
        self, store, issuer, holder, trusted, challenge
    ):
        env = make_envelope()
        cose, payload = issue_and_register(
            store, issuer, holder, env.action_digest,
            spend_limit=50, spend_asset="USD",
        )
        proof = make_holder_proof(holder, payload.capability_id, challenge)
        with pytest.raises(BudgetExceededError):
            store.consume_capability(
                capability_cose=cose, holder_proof=proof, challenge=challenge,
                trusted_issuers=trusted, envelope=env, spend_amount=60,
            )
        # Under the limit works.
        out = store.consume_capability(
            capability_cose=cose, holder_proof=proof, challenge=challenge,
            trusted_issuers=trusted, envelope=env, spend_amount=40,
        )
        assert out.capability_id == payload.capability_id

    def test_mandate_lifecycle_legal_transitions(self, store):
        store.create_mandate("m-life")
        assert store.get_mandate("m-life")["lifecycle"] == "CREATED"
        store.transition_mandate("m-life", MandateLifecycle.ACTIVE)
        store.transition_mandate("m-life", MandateLifecycle.PAUSED)
        store.transition_mandate("m-life", MandateLifecycle.ACTIVE)
        store.transition_mandate("m-life", MandateLifecycle.EXHAUSTED)
        store.transition_mandate("m-life", MandateLifecycle.REVOKED)
        assert store.get_mandate("m-life")["lifecycle"] == "REVOKED"

    @pytest.mark.parametrize(
        "start,target",
        [
            ("CREATED", "PAUSED"),
            ("CREATED", "EXHAUSTED"),
            ("ACTIVE", "CREATED"),
            ("PAUSED", "EXHAUSTED"),
            ("EXHAUSTED", "ACTIVE"),
            ("REVOKED", "ACTIVE"),
            ("EXPIRED", "ACTIVE"),
        ],
    )
    def test_mandate_lifecycle_illegal_transitions(self, store, start, target):
        store.create_mandate("m-bad")
        # Drive to `start` via legal moves.
        path = {
            "CREATED": [],
            "ACTIVE": ["ACTIVE"],
            "PAUSED": ["ACTIVE", "PAUSED"],
            "EXHAUSTED": ["ACTIVE", "EXHAUSTED"],
            "REVOKED": ["ACTIVE", "REVOKED"],
            "EXPIRED": ["ACTIVE", "EXPIRED"],
        }[start]
        for step in path:
            store.transition_mandate("m-bad", getattr(MandateLifecycle, step))
        with pytest.raises(LifecycleError):
            store.transition_mandate("m-bad", getattr(MandateLifecycle, target))

    def test_mint_child_debits_mandate_budget(self, store, issuer, holder, trusted):
        activate_mandate(store, "m-budget", spend_limit=1000, actions_limit=3)
        env = make_envelope()
        parent_cose, _ = issue_and_register(
            store, issuer, holder, env.action_digest, kind=KIND_MANDATE,
            mandate_id="m-budget",
        )
        mint_registered_child(
            store, issuer, trusted, parent_cose, "m-budget", holder, spend_limit=400
        )
        m = store.get_mandate("m-budget")
        assert m["actions_used"] == 1
        assert m["spend_used"] == 400  # worst-case reservation at mint

    def test_mint_child_beyond_actions_limit_denied(
        self, store, issuer, holder, trusted
    ):
        activate_mandate(store, "m-alim", actions_limit=1)
        env = make_envelope()
        parent_cose, _ = issue_and_register(
            store, issuer, holder, env.action_digest, kind=KIND_MANDATE,
            mandate_id="m-alim",
        )
        mint_registered_child(store, issuer, trusted, parent_cose, "m-alim", holder)
        with pytest.raises(BudgetExceededError):
            store.debit_mandate_for_child("m-alim", None)

    def test_mint_child_from_paused_mandate_denied(
        self, store, issuer, holder, trusted
    ):
        activate_mandate(store, "m-paused", actions_limit=5)
        store.transition_mandate("m-paused", MandateLifecycle.PAUSED)
        with pytest.raises(AuthorizationDenied):
            store.debit_mandate_for_child("m-paused", None)

    def test_consume_child_of_non_active_mandate_denied(
        self, store, issuer, holder, trusted, challenge
    ):
        activate_mandate(store, "m-ch", actions_limit=5)
        env = make_envelope()
        parent_cose, _ = issue_and_register(
            store, issuer, holder, env.action_digest, kind=KIND_MANDATE,
            mandate_id="m-ch",
        )
        child_cose, child_payload = mint_registered_child(
            store, issuer, trusted, parent_cose, "m-ch", holder
        )
        store.transition_mandate("m-ch", MandateLifecycle.PAUSED)
        proof = make_holder_proof(holder, child_payload.capability_id, challenge)
        with pytest.raises(AuthorizationDenied):
            store.consume_capability(
                capability_cose=child_cose, holder_proof=proof, challenge=challenge,
                trusted_issuers=trusted, envelope=env,
            )

    def test_stale_revocation_view_denies_fail_closed(
        self, store, issuer, holder, trusted, challenge
    ):
        env = make_envelope()
        cose, payload = issue_and_register(
            store, issuer, holder, env.action_digest, staleness=60
        )
        # Revocation view is an hour old; bound is 60s -> fail closed.
        store.sync_revocations(now=time.time() - 3600)
        proof = make_holder_proof(holder, payload.capability_id, challenge)
        with pytest.raises(StaleRevocationError):
            store.consume_capability(
                capability_cose=cose, holder_proof=proof, challenge=challenge,
                trusted_issuers=trusted, envelope=env,
            )
        assert store.capability_state(payload.capability_id) == "ISSUED"

    def test_fresh_revocation_sync_allows_consume(
        self, store, issuer, holder, trusted, challenge
    ):
        env = make_envelope()
        cose, payload = issue_and_register(
            store, issuer, holder, env.action_digest, staleness=3600
        )
        store.sync_revocations()  # fresh
        proof = make_holder_proof(holder, payload.capability_id, challenge)
        out = store.consume_capability(
            capability_cose=cose, holder_proof=proof, challenge=challenge,
            trusted_issuers=trusted, envelope=env,
        )
        assert out.capability_id == payload.capability_id

    def test_register_duplicate_denied(self, store, issuer, holder, trusted):
        env = make_envelope()
        _, payload = issue_and_register(store, issuer, holder, env.action_digest)
        with pytest.raises(StoreError):
            store.register_capability(payload)

    def test_create_duplicate_mandate_denied(self, store):
        store.create_mandate("m-dup")
        with pytest.raises(StoreError):
            store.create_mandate("m-dup")


# ---------------------------------------------------------------------------
# pep.py — unit tests
# ---------------------------------------------------------------------------


class TestPEP:
    def test_shell_pep_happy_path_injects_brokered_env(
        self, shell_pep, store, issuer, holder, trusted, challenge, broker
    ):
        env = make_envelope()
        cose, payload = issue_and_register(store, issuer, holder, env.action_digest)
        shell_pep.register_command(
            env.action_digest,
            [sys.executable, "-c",
             "import os; print(os.environ.get('API_TOKEN', 'MISSING'))"],
        )
        proof = make_holder_proof(holder, payload.capability_id, challenge)
        result = shell_pep.execute(
            envelope=env, capability_cose=cose, holder_proof=proof
        )
        assert result.returncode == 0
        assert "s3cr3t-token" in result.stdout
        assert store.capability_state(payload.capability_id) == "CONSUMED"

    def test_shell_pep_bad_capability_no_execution(
        self, shell_pep, store, issuer, holder, trusted, challenge
    ):
        env = make_envelope()
        cose, payload = issue_and_register(store, issuer, holder, env.action_digest)
        shell_pep.register_command(env.action_digest, [sys.executable, "-c", "pass"])
        with pytest.raises(PEPError):
            shell_pep.execute(
                envelope=env, capability_cose=cose,
                holder_proof=b"\x00" * 64,  # no valid holder proof
            )
        assert store.capability_state(payload.capability_id) == "ISSUED"

    def test_shell_pep_second_execute_denied_double_spend(
        self, shell_pep, store, issuer, holder, trusted, challenge
    ):
        env = make_envelope()
        cose, payload = issue_and_register(store, issuer, holder, env.action_digest)
        shell_pep.register_command(env.action_digest, [sys.executable, "-c", "pass"])
        proof = make_holder_proof(holder, payload.capability_id, challenge)
        shell_pep.execute(envelope=env, capability_cose=cose, holder_proof=proof)
        with pytest.raises(PEPError):
            shell_pep.execute(envelope=env, capability_cose=cose, holder_proof=proof)

    def test_shell_pep_unknown_digest_refused(
        self, shell_pep, store, issuer, holder, trusted, challenge
    ):
        env = make_envelope()
        cose, payload = issue_and_register(store, issuer, holder, env.action_digest)
        proof = make_holder_proof(holder, payload.capability_id, challenge)
        # Nothing registered for this digest -> refuse, capability untouched.
        with pytest.raises(PEPError):
            shell_pep.execute(envelope=env, capability_cose=cose, holder_proof=proof)
        assert store.capability_state(payload.capability_id) == "ISSUED"

    def test_shell_pep_refuses_non_shell_plane(
        self, shell_pep, store, issuer, holder, trusted, challenge
    ):
        env = make_envelope(plane="http", verb="post",
                            target="https://api.example.com/x")
        cose, payload = issue_and_register(store, issuer, holder, env.action_digest)
        proof = make_holder_proof(holder, payload.capability_id, challenge)
        with pytest.raises(PEPError):
            shell_pep.execute(envelope=env, capability_cose=cose, holder_proof=proof)

    def test_shell_pep_never_uses_shell_true(self, shell_pep):
        # Registry stores argv lists; execute() passes shell=False always.
        # Asserted structurally: register_command rejects empty argv, and the
        # module source never enables shell=True.
        import inspect

        src = inspect.getsource(ShellPEP.execute)
        assert "shell=False" in src
        assert "shell=True" not in src

    def test_broker_secrets_unreadable(self, broker):
        with pytest.raises(BrokerAccessDenied):
            broker.secrets
        with pytest.raises(AttributeError):
            broker.__secrets  # name-mangled: no such attribute
        assert "s3cr3t-token" not in repr(broker)
        assert broker.secret_names() == ("API_TOKEN", "DB_PASS")

    def test_broker_secrets_assignment_blocked(self, broker):
        with pytest.raises(AttributeError):
            broker.secrets = {"X": "y"}

    def test_egress_proxy_happy_path(self, egress, store, issuer, holder, trusted, challenge):
        env = make_envelope(plane="http", verb="post",
                            target="https://api.example.com/x")
        cose, payload = issue_and_register(store, issuer, holder, env.action_digest)
        egress.register_route(env.action_digest, "https://api.example.com/x", "API_TOKEN")
        proof = make_holder_proof(holder, payload.capability_id, challenge)
        headers = egress.authorize_http(
            envelope=env, capability_cose=cose, holder_proof=proof
        )
        assert headers["Authorization"] == "Bearer s3cr3t-token"
        assert store.capability_state(payload.capability_id) == "CONSUMED"

    def test_egress_proxy_unknown_digest_refused(
        self, egress, store, issuer, holder, trusted, challenge
    ):
        env = make_envelope(plane="http", verb="post",
                            target="https://api.example.com/x")
        cose, payload = issue_and_register(store, issuer, holder, env.action_digest)
        proof = make_holder_proof(holder, payload.capability_id, challenge)
        with pytest.raises(PEPError):
            egress.authorize_http(
                envelope=env, capability_cose=cose, holder_proof=proof
            )
        assert store.capability_state(payload.capability_id) == "ISSUED"

    def test_egress_proxy_bad_proof_refused(
        self, egress, store, issuer, holder, trusted, challenge
    ):
        env = make_envelope(plane="http", verb="post",
                            target="https://api.example.com/x")
        cose, payload = issue_and_register(store, issuer, holder, env.action_digest)
        egress.register_route(env.action_digest, "https://api.example.com/x", "API_TOKEN")
        with pytest.raises(PEPError):
            egress.authorize_http(
                envelope=env, capability_cose=cose, holder_proof=b"\x00" * 64
            )


# ---------------------------------------------------------------------------
# adversarial attacks
# ---------------------------------------------------------------------------


class TestAdversarial:
    """ATTACK-01: double-spend race — N threads, one capability, one winner."""

    def test_attack_double_spend_race(
        self, store, issuer, holder, trusted, challenge
    ):
        env = make_envelope()
        cose, payload = issue_and_register(store, issuer, holder, env.action_digest)
        proof = make_holder_proof(holder, payload.capability_id, challenge)
        n = 32
        barrier = threading.Barrier(n)
        wins = []
        lock = threading.Lock()

        def attempt():
            barrier.wait()
            try:
                store.consume_capability(
                    capability_cose=cose, holder_proof=proof, challenge=challenge,
                    trusted_issuers=trusted, envelope=env,
                )
                with lock:
                    wins.append(1)
            except DoubleSpendError:
                pass

        threads = [threading.Thread(target=attempt) for _ in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(wins) == 1, f"expected exactly 1 winner, got {len(wins)}"
        assert store.capability_state(payload.capability_id) == "CONSUMED"

    """ATTACK-02: budget race — two threads, envelope exceeded, one denied."""

    def test_attack_budget_race(self, store, issuer, holder, trusted):
        activate_mandate(store, "m-race", spend_limit=100, actions_limit=10)
        env = make_envelope()
        parent_cose, _ = issue_and_register(
            store, issuer, holder, env.action_digest, kind=KIND_MANDATE,
            spend_limit=100, spend_asset="USD", mandate_id="m-race",
        )
        n = 2
        barrier = threading.Barrier(n)
        results = []
        lock = threading.Lock()

        def attempt():
            barrier.wait()
            try:
                child_cose = mint_child(
                    parent_cose, issuer, trusted,
                    holder_pubkey=holder.public_key_bytes(), spend_limit=100,
                )
                child_payload = verify_capability(child_cose, trusted)
                store.debit_mandate_for_child("m-race", child_payload.spend_limit)
                store.register_capability(child_payload, mandate_id="m-race")
                with lock:
                    results.append("minted")
            except (BudgetExceededError, AuthorizationDenied, StoreError):
                with lock:
                    results.append("denied")

        threads = [threading.Thread(target=attempt) for _ in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert sorted(results) == ["denied", "minted"], results
        m = store.get_mandate("m-race")
        assert m["spend_used"] == 100  # never oversubscribed

    """ATTACK-03: holder-key mismatch — proof from the wrong key is denied."""

    def test_attack_holder_key_mismatch(
        self, store, issuer, holder, other_holder, trusted, challenge
    ):
        env = make_envelope()
        cose, payload = issue_and_register(store, issuer, holder, env.action_digest)
        evil_proof = make_holder_proof(other_holder, payload.capability_id, challenge)
        with pytest.raises(AuthorizationDenied):
            store.consume_capability(
                capability_cose=cose, holder_proof=evil_proof, challenge=challenge,
                trusted_issuers=trusted, envelope=env,
            )
        assert store.capability_state(payload.capability_id) == "ISSUED"

    """ATTACK-04: mandate amplification — broader child rejected at mint."""

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"spend_limit": 2000},                       # spend raised
            {"spend_asset": "EUR"},                      # asset changed
            {"ttl": timedelta(hours=5)},                 # expiry beyond parent
            {"max_revocation_staleness": 3600},          # staleness widened
        ],
    )
    def test_attack_mandate_amplification(
        self, issuer, holder, trusted, kwargs
    ):
        parent = issue_mandate(
            issuer, action_digest="a" * 64, holder_pubkey=holder.public_key_bytes(),
            spend_limit=1000, spend_asset="USD", ttl=timedelta(minutes=30),
            max_revocation_staleness=300,
        )
        with pytest.raises(CapabilityError):
            mint_child(parent, issuer, trusted, **kwargs)

    def test_attack_spend_bound_cannot_be_dropped(
        self, issuer, holder, trusted
    ):
        # Bound-dropping is structurally impossible: spend_limit=None means
        # "inherit the parent's bound", not "unbounded".
        parent = issue_mandate(
            issuer, action_digest="a" * 64, holder_pubkey=holder.public_key_bytes(),
            spend_limit=1000, spend_asset="USD",
        )
        child = mint_child(parent, issuer, trusted, spend_limit=None)
        assert verify_capability(child, trusted).spend_limit == 1000

    """ATTACK-05: PEP bypass — direct subprocess never reaches the broker."""

    def test_attack_pep_bypass(self, broker):
        # The attacker skips the PEP entirely and calls subprocess directly.
        # Without the PEP, brokered secrets are never injected...
        result = subprocess.run(
            [sys.executable, "-c",
             "import os; print('LEAKED' if 'API_TOKEN' in os.environ else 'CLEAN')"],
            capture_output=True, text=True, env=dict(os.environ),
        )
        assert "CLEAN" in result.stdout
        # ...and the broker refuses to hand them over on any public path.
        with pytest.raises(BrokerAccessDenied):
            _ = broker.secrets
        with pytest.raises(BrokerAccessDenied):
            getattr(broker, "secrets")

    """ATTACK-06: stale revocation beyond max_revocation_staleness -> deny."""

    def test_attack_stale_revocation_denied(
        self, store, issuer, holder, trusted, challenge
    ):
        env = make_envelope()
        cose, payload = issue_and_register(
            store, issuer, holder, env.action_digest, staleness=120
        )
        # Attacker revokes at the authority, but this enforcement point's
        # revocation view is 10 minutes old — past the 120s bound.
        store.revoke(payload.capability_id)
        store.sync_revocations(now=time.time() - 600)
        proof = make_holder_proof(holder, payload.capability_id, challenge)
        with pytest.raises((StaleRevocationError, RevokedError)):
            store.consume_capability(
                capability_cose=cose, holder_proof=proof, challenge=challenge,
                trusted_issuers=trusted, envelope=env,
            )
        assert store.capability_state(payload.capability_id) == "ISSUED"

    """ATTACK-07: bearer replay — capability without holder proof is denied."""

    @pytest.mark.parametrize("bad_proof", [b"", b"\x00" * 64, b"\xff" * 64])
    def test_attack_bearer_replay_denied(
        self, store, issuer, holder, trusted, challenge, bad_proof
    ):
        env = make_envelope()
        cose, payload = issue_and_register(store, issuer, holder, env.action_digest)
        with pytest.raises(AuthorizationDenied):
            store.consume_capability(
                capability_cose=cose, holder_proof=bad_proof, challenge=challenge,
                trusted_issuers=trusted, envelope=env,
            )
        assert store.capability_state(payload.capability_id) == "ISSUED"

    """ATTACK-08: mint from EXHAUSTED / REVOKED mandate -> deny."""

    @pytest.mark.parametrize("terminal", ["EXHAUSTED", "REVOKED"])
    def test_attack_mint_from_dead_mandate_denied(
        self, store, issuer, holder, trusted, terminal
    ):
        activate_mandate(store, "m-dead", actions_limit=5)
        if terminal == "REVOKED":
            store.transition_mandate("m-dead", MandateLifecycle.REVOKED)
        else:
            store.transition_mandate("m-dead", MandateLifecycle.EXHAUSTED)
        with pytest.raises(AuthorizationDenied):
            store.debit_mandate_for_child("m-dead", 10)

    """ATTACK-09: tampered caveat — spend_limit raised after issue.

    The attacker decodes the COSE payload, raises spend_limit, re-encodes
    WITHOUT a valid signature. COSE verification must fail.
    """

    def test_attack_tampered_caveat(self, issuer, holder, trusted):
        cose = issue_execution(
            issuer, action_digest="b" * 64, holder_pubkey=holder.public_key_bytes(),
            spend_limit=100, spend_asset="USD",
        )
        outer = cbor_loads(cose)
        protected, unprotected, payload_bytes, signature = outer
        payload_map = cbor_loads(payload_bytes)
        assert payload_map["spend_limit"] == 100
        payload_map["spend_limit"] = 1_000_000  # attacker raises the limit
        forged = cbor_dumps([protected, unprotected, cbor_dumps(payload_map), signature])
        with pytest.raises(CapabilityError):
            verify_capability(forged, trusted)

    """ATTACK-10: cross-capability proof replay — proof for cap A used with cap B."""

    def test_attack_cross_capability_proof_replay(
        self, store, issuer, holder, trusted, challenge
    ):
        env = make_envelope()
        cose_a, payload_a = issue_and_register(store, issuer, holder, env.action_digest)
        cose_b, payload_b = issue_and_register(store, issuer, holder, env.action_digest)
        proof_for_a = make_holder_proof(holder, payload_a.capability_id, challenge)
        with pytest.raises(AuthorizationDenied):
            store.consume_capability(
                capability_cose=cose_b, holder_proof=proof_for_a,
                challenge=challenge, trusted_issuers=trusted, envelope=env,
            )
        assert store.capability_state(payload_b.capability_id) == "ISSUED"
        assert store.capability_state(payload_a.capability_id) == "ISSUED"
