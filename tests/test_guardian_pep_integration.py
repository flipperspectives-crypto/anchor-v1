"""Wave 7 integration + adversarial tests: Guardian presented-envelope seam.

Covers the new optional ``presented_envelope`` path on
``AcsGuardian.handle_event`` / ``resolve_pending`` end-to-end against the
real Wave 2 enforcement plane (``ShellPEP`` / ``EgressProxy`` +
``CapabilityStore`` + ``authority``). No mocks: every check runs through
the real COSE issuance, holder-of-key proofs, and the linearizable store.

Conventions (copied from tests/test_acs_guardian.py, the exact working
patterns):
  * holder proof: ``payload = authority.verify_capability(cap, trusted, now)``,
    ``proof = authority.make_holder_proof(holder, payload.capability_id, challenge)``
  * store: ``CapabilityStore()`` + ``sync_revocations([], now=...)`` +
    ``register_capability(payload)`` before any consume
  * PEP: ``ShellPEP(broker, store, trusted_issuers, challenge)`` with
    ``register_command(action_digest, argv)``; ``ShellPEP.execute``
    consumes with the REAL clock, so the guardian's ``now_fn`` is frozen
    at a real ``t0`` captured per-test (windows are relative, so this is
    deterministic for the suite's purposes).
"""

from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import anchor_v1.acs_guardian as acs
from anchor_v1 import authority
from anchor_v1.acs_guardian import (
    AcsGuardian,
    DecisionResult,
    GuardianEvent,
)
from anchor_v1.authority import KIND_EXECUTION
from anchor_v1.canonical import sha256_hex
from anchor_v1.crypto import Ed25519Signer
from anchor_v1.envelope import ActionEnvelope, Effect
from anchor_v1.pep import (
    CredentialBroker,
    EgressProxy,
    PEPError,
    ShellPEP,
)
from anchor_v1.store import (
    AuthorizationDenied,
    CapabilityStore,
    DoubleSpendError,
)

PSK = b"test-psk-16bytes-long-enough"
CONSTITUTION_HASH = "test-constitution-hash"
CAPABILITY_TTL_S = 300.0
SUBJECT = "agent-wave7"  # event.subject; the holder registry key (b64 pubkey)

PARAMS = {"cmd": "echo hello", "timeout_s": 30}
PARAMS_ALT = {"cmd": "echo hello", "timeout_s": 31}


# ---------------------------------------------------------------------------
# fixtures / helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def issuer() -> Ed25519Signer:
    return Ed25519Signer.generate("guardian-1")


@pytest.fixture()
def holder() -> Ed25519Signer:
    return Ed25519Signer.generate("agent-holder")


@pytest.fixture()
def t0() -> datetime:
    """Frozen 'now' captured from the real clock once per test.

    ShellPEP/EgressProxy consume against the REAL clock (no ``now``
    parameter), so the guardian clock must be a real timestamp inside the
    300s capability/envelope windows — freezing it per-test keeps the
    suite deterministic while satisfying the store's expiry/staleness
    checks at consume time.
    """
    return datetime.now(timezone.utc)


@pytest.fixture()
def envelope_spy(monkeypatch):
    """Record the exact acs-plane ActionEnvelope the guardian builds.

    Same pattern as tests/test_acs_guardian.py: wraps the REAL builder,
    fakes nothing — the envelope carries a fresh action_id/nonce per mint
    so it cannot be recomputed from the event alone.
    """
    captured: dict = {}
    real = acs._build_envelope

    def spy(event, params, now, **kwargs):
        env = real(event, params, now, **kwargs)
        captured["envelope"] = env
        captured["params"] = params
        return env

    monkeypatch.setattr(acs, "_build_envelope", spy)
    return captured


def make_guardian(issuer, t0, decision_fn=None, holder=None, **kwargs) -> AcsGuardian:
    if decision_fn is None:
        decision_fn = lambda event: "ALLOW"  # noqa: E731
    if holder is not None and "holder_keys" not in kwargs:
        kwargs["holder_keys"] = {holder.public_key_b64(): holder.public_key_bytes()}
    return AcsGuardian(
        psk=PSK,
        issuer=issuer,
        constitution_hash=CONSTITUTION_HASH,
        decision_fn=decision_fn,
        now_fn=lambda: t0,
        capability_ttl_s=CAPABILITY_TTL_S,
        **kwargs,
    )


def make_event(holder, params=None, **overrides) -> GuardianEvent:
    base = dict(
        event_id="evt-wave7-1",
        event_type="pre_tool_call",
        session_id="sess-wave7",
        subject=holder.public_key_b64(),
        action="shell.exec",
        resource="sandbox://host",
        params=dict(params) if params is not None else dict(PARAMS),
        ts=datetime.now(timezone.utc),
    )
    base.update(overrides)
    return GuardianEvent(**base)


def trusted_issuers(issuer):
    return {
        issuer.key_id.encode("utf-8"): Ed25519PublicKey.from_public_bytes(
            issuer.public_key_bytes()
        )
    }


def make_shell_envelope(
    *,
    subject: str,
    params: dict,
    now: datetime,
    verb: str = "exec",
    target: str = "trial-cmd",
    policy_ref: str = CONSTITUTION_HASH,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
    nonce: str | None = None,
) -> ActionEnvelope:
    return ActionEnvelope(
        action_id=uuid.uuid4(),
        principal=subject,
        effect=Effect(
            plane="shell",
            verb=verb,
            target=target,
            args_digest=sha256_hex(params),
        ),
        policy_ref=policy_ref,
        issued_at=now,
        not_before=now if not_before is None else not_before,
        not_after=(now + timedelta(seconds=CAPABILITY_TTL_S))
        if not_after is None
        else not_after,
        nonce=nonce or secrets.token_hex(16),
    )


def make_http_envelope(*, subject: str, params: dict, now: datetime) -> ActionEnvelope:
    return ActionEnvelope(
        action_id=uuid.uuid4(),
        principal=subject,
        effect=Effect(
            plane="http",
            verb="post",
            target="https://example.com/hook",
            args_digest=sha256_hex(params),
        ),
        policy_ref=CONSTITUTION_HASH,
        issued_at=now,
        not_before=now,
        not_after=now + timedelta(seconds=CAPABILITY_TTL_S),
        nonce=secrets.token_hex(16),
    )


def make_pep_stack(issuer, *, now: datetime):
    """Real enforcement plane: broker + linearizable store + both PEPs."""
    broker = CredentialBroker({"TRIAL_TOKEN": "trial-secret-value"})
    store = CapabilityStore()
    store.sync_revocations([], now=now.timestamp())
    challenge = secrets.token_bytes(32)
    trusted = trusted_issuers(issuer)
    shell = ShellPEP(broker, store, trusted, challenge)
    egress = EgressProxy(broker, store, trusted, challenge)
    return broker, store, shell, egress, challenge


def verify_payload(decision, issuer, *, now: datetime):
    """The exact working verification pattern from test_acs_guardian.py."""
    assert decision.capability is not None, "ALLOW without capability is impossible"
    payload = authority.verify_capability(
        decision.capability, trusted_issuers(issuer), now=now
    )
    assert payload.kind == KIND_EXECUTION
    return payload


def execute_shell(shell, store, *, envelope, decision, holder, issuer, challenge, now):
    """Register the minted capability, prove holder key, execute."""
    payload = verify_payload(decision, issuer, now=now)
    store.register_capability(payload)
    shell.register_command(envelope.action_digest, ["echo", "hello"])
    proof = authority.make_holder_proof(holder, payload.capability_id, challenge)
    result = shell.execute(
        envelope=envelope,
        capability_cose=decision.capability,
        holder_proof=proof,
    )
    return payload, result


# ---------------------------------------------------------------------------
# integration
# ---------------------------------------------------------------------------


def test_guardian_to_shell_pep_end_to_end(issuer, holder, t0):
    """Wave 7 seam end-to-end: presented shell envelope -> ALLOW with a
    capability bound to ITS digest -> real ShellPEP execution -> CONSUMED."""
    guardian = make_guardian(issuer, t0, holder=holder)
    event = make_event(holder, params=PARAMS)
    envelope = make_shell_envelope(subject=event.subject, params=PARAMS, now=t0)

    decision = guardian.handle_event(event, presented_envelope=envelope)

    assert decision.decision == "ALLOW"
    assert decision.capability is not None
    payload = verify_payload(decision, issuer, now=t0)
    assert payload.holder_pubkey == holder.public_key_bytes()
    assert payload.action_digest == envelope.action_digest, (
        "mint must bind to the PRESENTED envelope's digest, not an internal one"
    )

    _, store, shell, _, challenge = make_pep_stack(issuer, now=t0)
    payload, result = execute_shell(
        shell, store, envelope=envelope, decision=decision,
        holder=holder, issuer=issuer, challenge=challenge, now=t0,
    )
    assert result.returncode == 0
    assert "hello" in result.stdout
    assert store.capability_state(payload.capability_id) == "CONSUMED"


def test_default_acs_path_preserved(issuer, holder, t0, envelope_spy):
    """No presented_envelope: the old contract is intact — the capability
    binds to the internal acs-plane digest, and ShellPEP refuses that
    envelope on plane grounds before burning anything."""
    guardian = make_guardian(issuer, t0, holder=holder)
    event = make_event(holder, params=PARAMS)

    decision = guardian.handle_event(event)  # default path, no presented envelope

    assert decision.decision == "ALLOW"
    assert decision.capability is not None
    acs_envelope = envelope_spy["envelope"]
    assert acs_envelope.effect.plane == "acs"
    assert acs_envelope.effect.args_digest == sha256_hex(PARAMS)
    assert acs_envelope.policy_ref == CONSTITUTION_HASH
    payload = verify_payload(decision, issuer, now=t0)
    assert payload.action_digest == acs_envelope.action_digest

    _, store, shell, _, challenge = make_pep_stack(issuer, now=t0)
    store.register_capability(payload)
    shell.register_command(acs_envelope.action_digest, ["echo", "hello"])
    proof = authority.make_holder_proof(holder, payload.capability_id, challenge)
    with pytest.raises(PEPError, match="plane"):
        shell.execute(
            envelope=acs_envelope,
            capability_cose=decision.capability,
            holder_proof=proof,
        )
    # Refused before any state change: the capability is NOT burned.
    assert store.capability_state(payload.capability_id) == "ISSUED"


def test_resolve_pending_with_presented_envelope(issuer, holder, t0):
    """ASK -> resolve_pending(approved=True, presented_envelope=shell env)
    mints against the presented digest and the capability executes."""
    guardian = make_guardian(
        issuer, t0, decision_fn=lambda event: "ASK", holder=holder
    )
    event = make_event(holder, params=PARAMS)
    pending = guardian.handle_event(event)
    assert pending.decision == "ASK"
    assert pending.pending_id
    assert pending.capability is None

    envelope = make_shell_envelope(subject=event.subject, params=PARAMS, now=t0)
    decision = guardian.resolve_pending(
        pending.pending_id, approved=True, presented_envelope=envelope
    )

    assert decision.decision == "ALLOW"
    assert decision.capability is not None
    payload = verify_payload(decision, issuer, now=t0)
    assert payload.action_digest == envelope.action_digest

    _, store, shell, _, challenge = make_pep_stack(issuer, now=t0)
    payload, result = execute_shell(
        shell, store, envelope=envelope, decision=decision,
        holder=holder, issuer=issuer, challenge=challenge, now=t0,
    )
    assert result.returncode == 0
    assert store.capability_state(payload.capability_id) == "CONSUMED"


# ---------------------------------------------------------------------------
# adversarial — every one of these must be REJECTED
# ---------------------------------------------------------------------------


def _assert_deny(decision):
    assert decision.decision == "DENY", f"expected DENY, got {decision.decision}"
    assert decision.capability is None, "DENY must never carry a capability"
    assert "presented envelope" in decision.reason


def test_presented_args_substitution_denied(issuer, holder, t0):
    """Decision on P1; present an envelope committing to P2 -> DENY."""
    guardian = make_guardian(issuer, t0, holder=holder)
    event = make_event(holder, params=PARAMS)
    tampered = make_shell_envelope(subject=event.subject, params=PARAMS_ALT, now=t0)
    _assert_deny(guardian.handle_event(event, presented_envelope=tampered))


def test_presented_principal_mismatch_denied(issuer, holder, t0):
    """Envelope principal != event.subject -> DENY."""
    guardian = make_guardian(issuer, t0, holder=holder)
    event = make_event(holder, params=PARAMS)
    impostor = make_shell_envelope(subject="attacker-controlled", params=PARAMS, now=t0)
    _assert_deny(guardian.handle_event(event, presented_envelope=impostor))


def test_presented_policy_ref_mismatch_denied(issuer, holder, t0):
    """Envelope policy_ref != guardian constitution hash -> DENY."""
    guardian = make_guardian(issuer, t0, holder=holder)
    event = make_event(holder, params=PARAMS)
    foreign = make_shell_envelope(
        subject=event.subject, params=PARAMS, now=t0,
        policy_ref="some-other-constitution",
    )
    _assert_deny(guardian.handle_event(event, presented_envelope=foreign))


def test_presented_expired_window_denied(issuer, holder, t0):
    """Envelope with not_after in the past -> DENY (stale envelope)."""
    guardian = make_guardian(issuer, t0, holder=holder)
    event = make_event(holder, params=PARAMS)
    stale = make_shell_envelope(
        subject=event.subject, params=PARAMS, now=t0,
        not_before=t0 - timedelta(hours=1),
        not_after=t0 - timedelta(seconds=60),
    )
    _assert_deny(guardian.handle_event(event, presented_envelope=stale))


def test_cross_plane_replay_at_consume_refused(issuer, holder, t0):
    """A capability minted for the SHELL envelope cannot authorize an HTTP
    envelope at the egress PEP, even one committing to the same params."""
    guardian = make_guardian(issuer, t0, holder=holder)
    event = make_event(holder, params=PARAMS)
    shell_env = make_shell_envelope(subject=event.subject, params=PARAMS, now=t0)
    decision = guardian.handle_event(event, presented_envelope=shell_env)
    assert decision.decision == "ALLOW"

    http_env = make_http_envelope(subject=event.subject, params=PARAMS, now=t0)
    assert http_env.effect.args_digest == shell_env.effect.args_digest
    assert http_env.action_digest != shell_env.action_digest

    _, store, _, egress, challenge = make_pep_stack(issuer, now=t0)
    payload = verify_payload(decision, issuer, now=t0)
    store.register_capability(payload)
    egress.register_route(http_env.action_digest, "https://example.com/hook", "TRIAL_TOKEN")
    proof = authority.make_holder_proof(holder, payload.capability_id, challenge)
    with pytest.raises(PEPError):
        egress.authorize_http(
            envelope=http_env,
            capability_cose=decision.capability,
            holder_proof=proof,
        )
    assert store.capability_state(payload.capability_id) == "ISSUED"


def test_envelope_tampering_at_pep_denied(issuer, holder, t0):
    """Capability C1 minted for E1; presenting a tampered E2 (same params,
    different verb/target -> different digest) with C1 is refused at the
    store binding AND at the ShellPEP."""
    guardian = make_guardian(issuer, t0, holder=holder)
    event = make_event(holder, params=PARAMS)
    env1 = make_shell_envelope(subject=event.subject, params=PARAMS, now=t0)
    decision = guardian.handle_event(event, presented_envelope=env1)
    assert decision.decision == "ALLOW"

    env2 = make_shell_envelope(
        subject=event.subject, params=PARAMS, now=t0, target="trial-cmd-evil"
    )
    assert env2.action_digest != env1.action_digest

    _, store, shell, _, challenge = make_pep_stack(issuer, now=t0)
    payload = verify_payload(decision, issuer, now=t0)
    store.register_capability(payload)
    # Register E2's digest so the PEP reaches the consume step (proving the
    # STORE's digest binding refuses, not just the command registry).
    shell.register_command(env2.action_digest, ["echo", "tampered"])
    proof = authority.make_holder_proof(holder, payload.capability_id, challenge)
    with pytest.raises(PEPError):
        shell.execute(
            envelope=env2,
            capability_cose=decision.capability,
            holder_proof=proof,
        )
    # The exact store-level binding violation:
    with pytest.raises(AuthorizationDenied, match="does not match"):
        store.consume_capability(
            capability_cose=decision.capability,
            holder_proof=proof,
            challenge=challenge,
            trusted_issuers=trusted_issuers(issuer),
            envelope=env2,
        )
    assert store.capability_state(payload.capability_id) == "ISSUED"


@pytest.mark.xfail(
    strict=True,
    reason=(
        "FINDING (Wave 7): double-minting the SAME presented envelope yields "
        "two independent single-use capability_ids; the store's one-use "
        "enforcement is per capability_id, so the second consume succeeds — "
        "no digest-level replay protection. Revisit if mint dedup lands."
    ),
)
def test_double_mint_second_consume_raises(issuer, holder, t0):
    """handle_event twice with the SAME presented envelope -> two
    capabilities; the second consume MUST raise (DoubleSpendError or
    AuthorizationDenied). Marked xfail(strict): it currently does NOT
    raise, which is recorded as a finding, not hidden."""
    guardian = make_guardian(issuer, t0, holder=holder)
    event = make_event(holder, params=PARAMS)
    envelope = make_shell_envelope(subject=event.subject, params=PARAMS, now=t0)

    d1 = guardian.handle_event(event, presented_envelope=envelope)
    d2 = guardian.handle_event(event, presented_envelope=envelope)
    assert d1.decision == "ALLOW" and d2.decision == "ALLOW"

    p1 = verify_payload(d1, issuer, now=t0)
    p2 = verify_payload(d2, issuer, now=t0)
    assert p1.capability_id != p2.capability_id, "each mint gets a fresh capability id"
    assert p1.action_digest == p2.action_digest == envelope.action_digest

    _, store, shell, _, challenge = make_pep_stack(issuer, now=t0)
    store.register_capability(p1)
    store.register_capability(p2)
    shell.register_command(envelope.action_digest, ["echo", "hello"])

    proof1 = authority.make_holder_proof(holder, p1.capability_id, challenge)
    first = shell.execute(
        envelope=envelope, capability_cose=d1.capability, holder_proof=proof1
    )
    assert first.returncode == 0
    assert store.capability_state(p1.capability_id) == "CONSUMED"

    proof2 = authority.make_holder_proof(holder, p2.capability_id, challenge)
    with pytest.raises((DoubleSpendError, AuthorizationDenied)):
        shell.execute(
            envelope=envelope, capability_cose=d2.capability, holder_proof=proof2
        )


@pytest.mark.parametrize(
    "bad_envelope",
    [
        {"principal": "x"},  # missing every required field
        {  # wrong types throughout
            "action_id": "not-a-uuid",
            "principal": 123,
            "effect": {"plane": "shell"},
            "policy_ref": None,
            "issued_at": "yesterday",
            "not_before": "yesterday",
            "not_after": "tomorrow",
            "nonce": 42,
        },
    ],
    ids=["missing-fields", "wrong-types"],
)
def test_malformed_presented_envelope_denied(issuer, holder, t0, bad_envelope):
    """A presented envelope that is not a valid ActionEnvelope -> DENY,
    never a mint, never an exception escaping handle_event."""
    guardian = make_guardian(issuer, t0, holder=holder)
    event = make_event(holder, params=PARAMS)
    decision = guardian.handle_event(event, presented_envelope=bad_envelope)
    _assert_deny(decision)


def test_modify_binds_modified_params(issuer, holder, t0):
    """MODIFY: only an envelope committing to the MODIFIED params succeeds;
    one committing to the original params is DENIED."""
    modified = {"cmd": "echo hello", "timeout_s": 5}

    def decide_modify(event: GuardianEvent) -> DecisionResult:
        return DecisionResult(
            decision="MODIFY", reason="clamped timeout", modified_params=modified
        )

    guardian = make_guardian(issuer, t0, decision_fn=decide_modify, holder=holder)
    event = make_event(holder, params=PARAMS)

    stale_env = make_shell_envelope(subject=event.subject, params=PARAMS, now=t0)
    denied = guardian.handle_event(event, presented_envelope=stale_env)
    _assert_deny(denied)

    good_env = make_shell_envelope(subject=event.subject, params=modified, now=t0)
    decision = guardian.handle_event(event, presented_envelope=good_env)
    assert decision.decision == "MODIFY"
    assert decision.modified_params == modified
    assert decision.capability is not None
    payload = verify_payload(decision, issuer, now=t0)
    assert payload.action_digest == good_env.action_digest

    _, store, shell, _, challenge = make_pep_stack(issuer, now=t0)
    payload, result = execute_shell(
        shell, store, envelope=good_env, decision=decision,
        holder=holder, issuer=issuer, challenge=challenge, now=t0,
    )
    assert result.returncode == 0
    assert store.capability_state(payload.capability_id) == "CONSUMED"


def test_resolve_pending_rejects_bad_presented_envelope(issuer, holder, t0):
    """resolve_pending(approved=True) with a tampered presented envelope ->
    DENY, no capability; the pending entry is consumed (no retry mint)."""
    guardian = make_guardian(issuer, t0, decision_fn=lambda event: "ASK", holder=holder)
    event = make_event(holder, params=PARAMS)
    pending = guardian.handle_event(event)
    assert pending.decision == "ASK"

    tampered = make_shell_envelope(subject=event.subject, params=PARAMS_ALT, now=t0)
    decision = guardian.resolve_pending(
        pending.pending_id, approved=True, presented_envelope=tampered
    )
    _assert_deny(decision)
    with pytest.raises(ValueError, match="unknown pending_id"):
        guardian.resolve_pending(pending.pending_id, approved=True)
