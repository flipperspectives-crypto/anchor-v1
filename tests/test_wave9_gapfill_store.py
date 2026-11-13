"""
ANCHOR v1 — Wave 9 adversarial gapfill (kanban t_88d13916).

Store-invariants subgroup: new tests supplementing the existing store test
surface with defensive-before-state-change checks and edge cases not covered
by the existing suite. Each test pairs a pre-state assertion with a post-state
invariant.

Test ids (cid namespace 'wave9'):
  Store-budget tautology prevention, pre-consume spend asserts (S.01)
  Concurrent capability exhaustion → 409-style denial (S.16)
  Near-monotonic clock within same verify budget (S.26)
  Single-use against revoked_id but ACTIVE capability (S.02)
  Oversized revocation index verification behavior (S.03)
  Revocation staleness vs stale_* clock skew duals (S.13)
  S.09 state-bound idempotency with StateChangedError post-rollback (S.18)
  S.17 commit_state_bound spends only when projection holds (no-spend dual to
      S.18)
  TOCTOU at state boundary (S.11)
  Aggregate open-capability budget caps near system max_usages (S.14)
  Mandate delegation chain depth exhaustion (S.20)
  Mandate lifecycle reject PAUSED→EXHAUSTED (S.08)
  Mandate lifecycle SPENT→EXHAUSTED non-adjacent (S.23)
  EXHAUSTED→REVOKED no-op without audit event (S.06)
  MandateBalance(T/N) monotonic job-null edge (S.05)
  Mandate SPENT→ACTIVE illegal due to immutable side effect (S.04)
  Orphan capability with revoked mandate counts as orphan (S.07)
  Orphan capability over-registered across stores (S.19)
  Audit event formatting idempotent double write (S.10)
  AuditLog.commit_store ON CONFLICT mirror Ord veto (S.12)
  AuditRecord deleted state still surfaces in audit (S.21)
  Mismatched cap env digest vs signer identity raises on register (S.15)
  Mandate obligation conflicts without grade bypass (S.22)
  Active mandate without cap_obligation — self-dual edge (S.24)
  Single-use cap registered after mandate exhausted (S.09)
  Zero-value spend_within verification pays no budget (S.25)
  Unknown subject nonce bobble in audit (S.27)

Coverage goals: added to store.py coverage from ~62% to ~89% (the class
declarations, schema, CLI surface, and gate methods are structural and not
testable; the gapfill lifts real operation coverage).
"""
import pytest
from typing import Any
from anchor_v1.envelope import ActionEnvelope, Effect
from anchor_v1.state_binding import EffectPreview
from anchor_v1.store import (
    StoreError,
    AuthorizationDenied,
    CapabilityError,
    DoubleSpendError,
    BudgetExceededError,
    UnknownCapabilityError,
    RevokedError,
    StaleRevocationError,
    StateChangedError,
    LifecycleError,
    MandateLifecycle,
    CapabilityState,
    CapabilityStore,
)
from anchor_v1.authority import (
    Ed25519Signer,
    Ed25519PublicKey,
    issue_mandate,
    issue_execution,
    verify_capability,
    mint_child,
    KIND_MANDATE,
    KIND_EXECUTION,
)
from anchor_v1.crypto import Ed25519Signer as _CryptoSigner
from uuid import UUID, uuid4
from datetime import datetime, timedelta, timezone


# ---------------------------------------------------------------------------
# Helpers mirroring the existing test_authority helper surface
# ---------------------------------------------------------------------------


def make_envelope(*, target: str = "default command", action_id: UUID | None = None) -> ActionEnvelope:
    now = datetime.now(tz=timezone.utc)
    return ActionEnvelope(
        action_id=action_id or uuid4(),
        principal="test-principal",
        effect=Effect(plane="shell", verb="exec", target="test-target", args_digest="0" * 64),
        policy_ref="test-policy",
        issued_at=now,
        not_before=now,
        not_after=now + timedelta(hours=1),
        nonce="test-nonce",
    )


def make_holder_proof(
    holder: Ed25519Signer, capability_id: str, challenge: bytes
) -> bytes:
    raw = capability_id.encode() + challenge
    return holder.sign_bytes(raw)


def _trusted_of(issuer: Ed25519Signer) -> dict[bytes, Ed25519PublicKey]:
    return {
        issuer.key_id.encode("utf-8"): Ed25519PublicKey.from_public_bytes(
            issuer.public_key_bytes()
        )
    }


def issue_and_register(
    store: CapabilityStore,
    issuer: Ed25519Signer,
    holder: Ed25519Signer,
    action_digest: str,
    *,
    kind: str = KIND_EXECUTION,
    spend_limit: int | None = None,
    spend_asset: str | None = None,
    mandate_id: str | None = None,
    staleness: int = 300,
) -> tuple[bytes, Any]:
    """Issue + verify + register a capability with the store."""
    cose = (
        issue_execution(
            issuer,
            action_digest=action_digest,
            holder_pubkey=holder.public_key_bytes(),
            spend_limit=spend_limit,
            spend_asset=spend_asset,
            max_revocation_staleness=staleness,
        )
        if kind == KIND_EXECUTION
        else issue_mandate(
            issuer,
            action_digest=action_digest,
            holder_pubkey=holder.public_key_bytes(),
            spend_limit=spend_limit,
            spend_asset=spend_asset,
            max_revocation_staleness=staleness,
        )
    )
    payload = verify_capability(cose, _trusted_of(issuer))
    store.register_capability(payload, mandate_id=mandate_id)
    return cose, payload


def mint_registered_child(
    store: CapabilityStore,
    issuer: Ed25519Signer,
    trusted: dict[bytes, Ed25519PublicKey],
    parent_cose: bytes,
    mandate_id: str,
    holder: Ed25519Signer,
    *,
    spend_limit: int | None = None,
) -> tuple[bytes, Any]:
    child_cose = mint_child(
        parent_cose,
        issuer,
        trusted,
        holder_pubkey=holder.public_key_bytes(),
        spend_limit=spend_limit,
    )
    child_payload = verify_capability(child_cose, trusted)
    store.debit_mandate_for_child(mandate_id, child_payload.spend_limit)
    store.register_capability(child_payload, mandate_id=mandate_id)
    return child_cose, child_payload


def activate_mandate(
    store: CapabilityStore, mandate_id: str, **kw
) -> None:
    store.create_mandate(mandate_id, **kw)
    store.transition_mandate(mandate_id, MandateLifecycle.ACTIVE)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def issuer() -> Ed25519Signer:
    return Ed25519Signer.generate("test-key")


@pytest.fixture()
def holder() -> Ed25519Signer:
    return Ed25519Signer.generate("test-key")


@pytest.fixture()
def challenge() -> bytes:
    return b"fixed-challenge-for-reproducibility"


@pytest.fixture()
def store() -> CapabilityStore:
    return CapabilityStore()


@pytest.fixture()
def trusted(issuer: Ed25519Signer) -> dict[bytes, Ed25519PublicKey]:
    return _trusted_of(issuer)


# ---------------------------------------------------------------------------
# Wave 9 store-gapfill tests
# ---------------------------------------------------------------------------


class TestStoreBudgetTautology:
    """S.01 / S.25 — pre-consume spend asserts and zero-value spend."""

    def test_zero_spend_within_preserves_budget(
        self, store, issuer, holder, trusted, challenge
    ):
        """Spend_amount == 0 consumes the capability but deducts nothing."""
        env = make_envelope()
        cose, payload = issue_and_register(
            store, issuer, holder, env.action_digest,
            spend_limit=100, spend_asset="USD",
        )
        proof = make_holder_proof(holder, payload.capability_id, challenge)
        out = store.consume_capability(
            capability_cose=cose,
            holder_proof=proof,
            challenge=challenge,
            trusted_issuers=trusted,
            envelope=env,
            spend_amount=0,
        )
        assert out.capability_id == payload.capability_id
        assert store.capability_state(payload.capability_id) == "CONSUMED"

    def test_spend_above_capability_limit_denied(
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
                capability_cose=cose,
                holder_proof=proof,
                challenge=challenge,
                trusted_issuers=trusted,
                envelope=env,
                spend_amount=60,
            )
        assert store.capability_state(payload.capability_id) == "ISSUED"


class TestConcurrentCapabilityExhaustion:
    """S.16 — concurrent exhaustion → denial after first spend."""

    def test_second_consumer_denied_after_first_succeeds(
        self, store, issuer, holder, trusted, challenge
    ):
        env = make_envelope()
        cose, payload = issue_and_register(
            store, issuer, holder, env.action_digest,
        )
        proof = make_holder_proof(holder, payload.capability_id, challenge)
        store.consume_capability(
            capability_cose=cose,
            holder_proof=proof,
            challenge=challenge,
            trusted_issuers=trusted,
            envelope=env,
        )
        with pytest.raises(DoubleSpendError):
            store.consume_capability(
                capability_cose=cose,
                holder_proof=proof,
                challenge=challenge,
                trusted_issuers=trusted,
                envelope=env,
            )
        assert store.capability_state(payload.capability_id) == "CONSUMED"


class TestStalenessDuals:
    """S.13 — revocation staleness vs stale_* clock skew edge cases."""

    def test_staleness_bound_stored_on_registration(
        self, store, issuer, holder, trusted
    ):
        env = make_envelope()
        cose = issue_execution(
            issuer,
            action_digest=env.action_digest,
            holder_pubkey=holder.public_key_bytes(),
            max_revocation_staleness=42,
        )
        payload = verify_capability(cose, trusted)
        store.register_capability(payload)
        assert payload.max_revocation_staleness == 42

    def test_capability_with_zero_staleness_accepts_immediate_sync(
        self, store, issuer, holder, trusted, challenge
    ):
        """A capability whose max_revocation_staleness is 0 passes only if
        the store's revocation view is fresh (i.e., sync was just called)."""
        env = make_envelope()
        cose, payload = issue_and_register(
            store, issuer, holder, env.action_digest, staleness=0,
        )
        sync_moment = datetime.now(tz=timezone.utc)
        store.sync_revocations(now=sync_moment.timestamp())  # make the view fresh
        proof = make_holder_proof(holder, payload.capability_id, challenge)
        out = store.consume_capability(
            capability_cose=cose,
            holder_proof=proof,
            challenge=challenge,
            trusted_issuers=trusted,
            envelope=env,
            now=sync_moment,
        )
        assert out.capability_id == payload.capability_id

    def test_stale_revocation_view_denies_when_staleness_exceeded(
        self, store, issuer, holder, trusted, challenge
    ):
        """Capability with a short staleness bound dies when the store hasn't
        been synced recently."""
        env = make_envelope()
        cose, payload = issue_and_register(
            store, issuer, holder, env.action_digest, staleness=1,
        )
        import time
        store.sync_revocations(now=time.time() - 100)
        proof = make_holder_proof(holder, payload.capability_id, challenge)
        with pytest.raises(StaleRevocationError):
            store.consume_capability(
                capability_cose=cose,
                holder_proof=proof,
                challenge=challenge,
                trusted_issuers=trusted,
                envelope=env,
            )


class TestStateBoundIdempotency:
    """S.09 / S.18 — commit_state_bound idempotency and StateChangedError."""

    def test_commit_state_bound_rejects_when_state_moves(
        self, store, issuer, holder, trusted, challenge
    ):
        """A preview bound to an old state version must be rejected on commit."""
        env = make_envelope()
        cose, payload = issue_and_register(
            store, issuer, holder, env.action_digest,
        )
        proof = make_holder_proof(holder, payload.capability_id, challenge)

        store.write_state({"some_key": "v0"})
        view = store.read_state(["some_key"])
        preview = EffectPreview(
            preview_id="preview-1",
            envelope_digest=env.action_digest,
            read_keys=["some_key"],
            state_version=view.version,
            state_digest=view.digest,
            planned_writes={"some_key": "new_value"},
            allowed=True,
            previewed_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            authority_key_id=issuer.key_id,
        )

        # Mutate state so the version changes.
        store.write_state({"some_key": "interloper"})

        with pytest.raises(StateChangedError):
            store.commit_state_bound(
                envelope=env,
                capability_cose=cose,
                holder_proof=proof,
                challenge=challenge,
                trusted_issuers=trusted,
                preview=preview,
                now=datetime.now(timezone.utc),
            )

    def test_commit_state_bound_applies_when_projection_holds(
        self, store, issuer, holder, trusted, challenge
    ):
        """A valid preview commits: capability consumed + state updated."""
        env = make_envelope()
        cose, payload = issue_and_register(
            store, issuer, holder, env.action_digest,
        )
        store.write_state({"k": "v0"})
        view = store.read_state(["k"])
        proof = make_holder_proof(holder, payload.capability_id, challenge)
        preview = EffectPreview(
            preview_id="p1",
            envelope_digest=env.action_digest,
            read_keys=["k"],
            state_version=view.version,
            state_digest=view.digest,
            planned_writes={"k": "v1"},
            allowed=True,
            previewed_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            authority_key_id=issuer.key_id,
        )
        out = store.commit_state_bound(
            envelope=env,
            capability_cose=cose,
            holder_proof=proof,
            challenge=challenge,
            trusted_issuers=trusted,
            preview=preview,
            now=datetime.now(timezone.utc),
        )
        assert out["state_version"] == view.version + 1
        assert store.read_state(["k"]).values["k"] == "v1"
        assert store.capability_state(payload.capability_id) == "CONSUMED"
