"""Tests for anchor_v1.acs_guardian: every rule + adversarial attacks.

The Guardian mints holder-of-key ExecutionCapabilities (COSE_Sign1) via the
Wave 2 authority layer, bound to the ActionEnvelope digest of the exact
event params. Verification at the simulated PEP goes through
``authority.verify_capability`` (COSE) + ``authority.verify_holder_proof``,
and consumption through the real linearizable ``CapabilityStore``.

All attacks must end DENY (or WireAuthError on the peer side) — never a
silent allow, never a bare ALLOW without a minted capability, never a
pass-through on a disabled hook.
"""

from __future__ import annotations

import base64
import secrets
import struct
import time
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import anchor_v1.acs_guardian as acs
from anchor_v1 import authority
from anchor_v1.acs_guardian import (
    KNOWN_HOOKS,
    AcsGuardian,
    DecisionResult,
    GuardianDecision,
    GuardianEvent,
    WireAuthError,
    WirePeer,
)
from anchor_v1.authority import KIND_EXECUTION, CapabilityError
from anchor_v1.canonical import sha256_hex
from anchor_v1.crypto import Ed25519Signer
from anchor_v1.store import AuthorizationDenied, CapabilityStore, DoubleSpendError

NOW = datetime(2026, 9, 23, 12, 0, 0, tzinfo=timezone.utc)
PSK = b"test-psk-16bytes-long-enough"
WRONG_PSK = b"wrong-psk-16bytes-long-enough"
CONSTITUTION_HASH = "test-constitution-hash"
CAPABILITY_TTL_S = 300.0


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
def now_fn():
    return lambda: NOW


@pytest.fixture()
def envelope_spy(monkeypatch):
    """Capture the ActionEnvelope the guardian builds at mint time.

    The envelope carries a fresh action_id/nonce per mint, so its digest
    cannot be recomputed from the event alone — the spy records the exact
    envelope the capability was bound to, letting tests assert the
    capability's action_digest equals the envelope digest of the exact
    event params.
    """
    captured: dict = {"calls": 0}
    real = acs._build_envelope

    def spy(event, params, now, **kwargs):
        env = real(event, params, now, **kwargs)
        captured["calls"] += 1
        captured["envelope"] = env
        captured["params"] = params
        return env

    monkeypatch.setattr(acs, "_build_envelope", spy)
    return captured


def allow_all(event: GuardianEvent) -> str:
    return "ALLOW"


def deny_all(event: GuardianEvent) -> str:
    return "DENY"


def make_guardian(issuer, now_fn, decision_fn=allow_all, holder=None, **kwargs) -> AcsGuardian:
    # By default the subject's holder key is registered (out-of-band
    # registry the SPIFFE/OIDC adapters will feed in Wave 5). Tests for the
    # fail-closed registry pass holder_keys explicitly.
    if holder is not None and "holder_keys" not in kwargs:
        kwargs["holder_keys"] = {holder.public_key_b64(): holder.public_key_bytes()}
    return AcsGuardian(
        psk=PSK,
        issuer=issuer,
        constitution_hash=CONSTITUTION_HASH,
        decision_fn=decision_fn,
        now_fn=now_fn,
        **kwargs,
    )


def make_peer(now_fn) -> WirePeer:
    return WirePeer(psk=PSK, now_fn=now_fn)


def make_event(holder, event_type: str = "pre_tool_call", **overrides) -> GuardianEvent:
    base = dict(
        event_id="evt-1",
        event_type=event_type,
        session_id="sess-1",
        subject=holder.public_key_b64(),
        action="shell.exec",
        resource="sandbox://host",
        params={"cmd": "ls -la", "timeout_s": 30},
        ts=NOW,
    )
    base.update(overrides)
    return GuardianEvent(**base)


def trusted_issuers(issuer):
    return {
        issuer.key_id.encode("utf-8"): Ed25519PublicKey.from_public_bytes(
            issuer.public_key_bytes()
        )
    }


def verify_capability(decision, event, holder, issuer, *, now=NOW, challenge=None):
    """Verify an ALLOW/MODIFY capability end-to-end at a simulated PEP.

    Verifies the COSE_Sign1 bytes via ``authority.verify_capability`` and
    the per-request holder proof via ``authority.verify_holder_proof``.
    Asserts the capability is an execution capability bound to the
    subject's registered holder key. Returns (payload, proof).
    """
    assert decision.capability is not None, "ALLOW without capability is impossible"
    assert isinstance(
        decision.capability, bytes
    ), "capability must be COSE_Sign1 bytes"
    payload = authority.verify_capability(
        decision.capability, trusted_issuers(issuer), now=now
    )
    assert payload.kind == KIND_EXECUTION, "guardian mints execution capabilities"
    assert (
        payload.holder_pubkey == holder.public_key_bytes()
    ), "capability must be bound to the subject's holder key"
    challenge = secrets.token_bytes(32) if challenge is None else challenge
    proof = authority.make_holder_proof(holder, payload.capability_id, challenge)
    authority.verify_holder_proof(
        holder.public_key_bytes(), payload.capability_id, challenge, proof
    )
    return payload, proof


def assert_digest_binding(decision, event, holder, issuer, envelope_spy, *, params=None):
    """Assert the capability's action_digest equals the digest of the
    ActionEnvelope the guardian built for the exact event params.

    Also asserts the envelope's shape: principal, acs-plane effect, verb,
    target, args digest committing to the exact params, and the
    constitution policy ref. Returns (payload, envelope).
    """
    params = event.params if params is None else params
    assert envelope_spy["params"] == params, "envelope built for the exact params"
    envelope = envelope_spy["envelope"]
    payload, _proof = verify_capability(decision, event, holder, issuer)
    assert (
        payload.action_digest == envelope.action_digest
    ), "capability action_digest must equal the envelope digest of the exact event params"
    assert envelope.principal == event.subject
    assert envelope.effect.plane == "acs"
    assert envelope.effect.verb == event.action
    assert envelope.effect.target == event.resource
    assert envelope.effect.args_digest == sha256_hex(params), (
        "envelope args_digest must commit to the exact invocation params"
    )
    assert envelope.policy_ref == CONSTITUTION_HASH
    return payload, envelope


def make_pep_store(now=NOW) -> CapabilityStore:
    """A simulated PEP: the real linearizable store with a fresh
    revocation view, so consumption is verify+revocation+proof+one-use,
    atomically."""
    store = CapabilityStore()
    store.sync_revocations([], now=now.timestamp())
    return store


def pep_attempt(store, payload, decision, holder_signer, issuer, *, challenge, envelope, now=NOW):
    """One PEP consumption attempt: holder proof + atomic consume."""
    proof = authority.make_holder_proof(holder_signer, payload.capability_id, challenge)
    return store.consume_capability(
        capability_cose=decision.capability,
        holder_proof=proof,
        challenge=challenge,
        trusted_issuers=trusted_issuers(issuer),
        envelope=envelope,
        now=now,
    )


# ---------------------------------------------------------------------------
# unit: lifecycle model + hook registry
# ---------------------------------------------------------------------------


def test_known_hooks_cover_full_lifecycle():
    assert set(KNOWN_HOOKS) == {
        "session_start",
        "pre_tool_call",
        "post_tool_call",
        "pre_delegation",
        "human_approval_request",
        "policy_change",
        "freeze",
        "revocation",
        "session_end",
    }
    assert len(KNOWN_HOOKS) == 9


@pytest.mark.parametrize("hook", KNOWN_HOOKS)
def test_each_hook_allow_mints_verifiable_capability(
    issuer, holder, now_fn, hook, envelope_spy
):
    guardian = make_guardian(issuer, now_fn, holder=holder)
    event = make_event(holder, event_type=hook, event_id=f"evt-{hook}")
    decision = guardian.handle_event(event)
    assert decision.decision == "ALLOW"
    assert decision.event_id == f"evt-{hook}"
    payload, envelope = assert_digest_binding(
        decision, event, holder, issuer, envelope_spy
    )
    assert payload.action_digest == envelope.action_digest  # exact binding


def test_default_config_enables_all_hooks(issuer, now_fn):
    guardian = make_guardian(issuer, now_fn)
    assert guardian.enabled_hooks == frozenset(KNOWN_HOOKS)


def test_unknown_event_type_denied_in_process(issuer, holder, now_fn):
    guardian = make_guardian(issuer, now_fn)
    decision = guardian.handle_event(make_event(holder, event_type="nuke_everything"))
    assert decision.decision == "DENY"
    assert decision.capability is None
    assert "unknown event type" in decision.reason


def test_unknown_event_type_denied_over_wire(issuer, holder, now_fn):
    guardian = make_guardian(issuer, now_fn)
    peer = make_peer(now_fn)
    decision = peer.send_event(
        guardian, make_event(holder, event_type="backdoor_hook")
    )
    assert decision.decision == "DENY"
    assert decision.capability is None


def test_disabled_hook_denied_not_passed_through(issuer, holder, now_fn):
    called = []

    def spy(event):
        called.append(event)
        return "ALLOW"

    enabled = [h for h in KNOWN_HOOKS if h != "pre_tool_call"]
    guardian = make_guardian(issuer, now_fn, decision_fn=spy, enabled_hooks=enabled)
    decision = guardian.handle_event(make_event(holder, event_type="pre_tool_call"))
    assert decision.decision == "DENY"
    assert decision.capability is None
    assert "disabled" in decision.reason
    assert called == [], "decision_fn must not run for a disabled hook"


def test_disabled_hook_denied_over_wire(issuer, holder, now_fn):
    guardian = make_guardian(
        issuer, now_fn, enabled_hooks=["session_start", "session_end"]
    )
    peer = make_peer(now_fn)
    decision = peer.send_event(guardian, make_event(holder, event_type="pre_tool_call"))
    assert decision.decision == "DENY"
    assert decision.capability is None


def test_unknown_hook_in_config_raises_at_construction(issuer, now_fn):
    with pytest.raises(ValueError, match="unknown hooks"):
        make_guardian(issuer, now_fn, enabled_hooks=["pre_tool_call", "bogus_hook"])


def test_malformed_event_dict_denied(issuer, holder, now_fn):
    guardian = make_guardian(issuer, now_fn)
    decision = guardian.handle_event({"event_type": "pre_tool_call"})  # missing fields
    assert decision.decision == "DENY"
    assert decision.capability is None


def test_event_with_extra_fields_denied_strict_model(issuer, now_fn):
    guardian = make_guardian(issuer, now_fn)
    raw = make_event(Ed25519Signer.generate("x"), event_type="pre_tool_call").model_dump(
        mode="json"
    )
    raw["injected"] = "evil"
    decision = guardian.handle_event(raw)
    assert decision.decision == "DENY"


# ---------------------------------------------------------------------------
# unit: decision function failures -> DENY
# ---------------------------------------------------------------------------


def test_decision_fn_exception_denied(issuer, holder, now_fn):
    def boom(event):
        raise RuntimeError("policy engine exploded")

    guardian = make_guardian(issuer, now_fn, decision_fn=boom)
    decision = guardian.handle_event(make_event(holder))
    assert decision.decision == "DENY"
    assert decision.capability is None
    assert "decision-function failure" in decision.reason


def test_decision_fn_timeout_denied(issuer, holder, now_fn):
    def slow(event):
        time.sleep(5)
        return "ALLOW"

    guardian = make_guardian(
        issuer, now_fn, decision_fn=slow, decision_timeout_s=0.2
    )
    decision = guardian.handle_event(make_event(holder))
    assert decision.decision == "DENY"
    assert decision.capability is None


def test_decision_fn_unknown_string_denied(issuer, holder, now_fn):
    guardian = make_guardian(issuer, now_fn, decision_fn=lambda e: "MAYBE")
    decision = guardian.handle_event(make_event(holder))
    assert decision.decision == "DENY"
    assert decision.capability is None


def test_decision_fn_bad_return_type_denied(issuer, holder, now_fn):
    guardian = make_guardian(issuer, now_fn, decision_fn=lambda e: 42)
    decision = guardian.handle_event(make_event(holder))
    assert decision.decision == "DENY"
    assert decision.capability is None


def test_decision_fn_dict_return_accepted(issuer, holder, now_fn):
    guardian = make_guardian(
        issuer, now_fn, decision_fn=lambda e: {"decision": "DENY", "reason": "nope"}
    )
    decision = guardian.handle_event(make_event(holder))
    assert decision.decision == "DENY"
    assert decision.reason == "nope"


def test_decision_result_object_accepted(issuer, holder, now_fn):
    guardian = make_guardian(
        issuer,
        now_fn,
        decision_fn=lambda e: DecisionResult(decision="ALLOW", reason="ok"),
        holder=holder,
    )
    decision = guardian.handle_event(make_event(holder))
    assert decision.decision == "ALLOW"
    assert decision.capability is not None


# ---------------------------------------------------------------------------
# unit: decision types
# ---------------------------------------------------------------------------


def test_deny_carries_no_capability(issuer, holder, now_fn):
    guardian = make_guardian(issuer, now_fn, decision_fn=deny_all)
    decision = guardian.handle_event(make_event(holder))
    assert decision.decision == "DENY"
    assert decision.capability is None
    assert decision.modified_params is None


def test_ask_records_pending_no_capability(issuer, holder, now_fn):
    guardian = make_guardian(issuer, now_fn, decision_fn=lambda e: "ASK")
    decision = guardian.handle_event(make_event(holder))
    assert decision.decision == "ASK"
    assert decision.capability is None
    assert decision.pending_id is not None
    assert decision.pending_id in guardian.pending


def test_defer_records_pending_no_capability(issuer, holder, now_fn):
    guardian = make_guardian(issuer, now_fn, decision_fn=lambda e: "DEFER")
    decision = guardian.handle_event(make_event(holder))
    assert decision.decision == "DEFER"
    assert decision.capability is None
    assert decision.pending_id is not None
    assert guardian.pending[decision.pending_id]["kind"] == "DEFER"


def test_modify_mints_capability_bound_to_modified_digest(
    issuer, holder, now_fn, envelope_spy
):
    modified = {"cmd": "ls /safe", "timeout_s": 10}
    guardian = make_guardian(
        issuer,
        now_fn,
        holder=holder,
        decision_fn=lambda e: DecisionResult(
            decision="MODIFY", modified_params=modified, reason="sanitized"
        ),
    )
    event = make_event(holder)
    decision = guardian.handle_event(event)
    assert decision.decision == "MODIFY"
    assert decision.modified_params == modified
    # the capability's digest equals the envelope digest of the MODIFIED params
    payload, modified_envelope = assert_digest_binding(
        decision, event, holder, issuer, envelope_spy, params=modified
    )
    # PEP-side: an envelope built from the ORIGINAL (unmodified) params does
    # NOT match the binding -> denied...
    original_envelope = acs._build_envelope(
        event,
        event.params,
        NOW,
        ttl_s=CAPABILITY_TTL_S,
        constitution_hash=CONSTITUTION_HASH,
    )
    assert original_envelope.action_digest != modified_envelope.action_digest
    store = make_pep_store()
    store.register_capability(payload)
    with pytest.raises(AuthorizationDenied, match="does not match capability binding"):
        pep_attempt(
            store,
            payload,
            decision,
            holder,
            issuer,
            challenge=secrets.token_bytes(32),
            envelope=original_envelope,
        )
    # ...while the MODIFIED envelope consumes cleanly (one-shot)
    store2 = make_pep_store()
    store2.register_capability(payload)
    consumed = pep_attempt(
        store2,
        payload,
        decision,
        holder,
        issuer,
        challenge=secrets.token_bytes(32),
        envelope=modified_envelope,
    )
    assert consumed.capability_id == payload.capability_id


def test_modify_without_modified_params_denied(issuer, holder, now_fn):
    guardian = make_guardian(
        issuer, now_fn, decision_fn=lambda e: DecisionResult(decision="MODIFY")
    )
    decision = guardian.handle_event(make_event(holder))
    assert decision.decision == "DENY"
    assert decision.capability is None


def test_ask_over_wire_roundtrip(issuer, holder, now_fn):
    guardian = make_guardian(issuer, now_fn, decision_fn=lambda e: "ASK")
    peer = make_peer(now_fn)
    decision = peer.send_event(
        guardian, make_event(holder, event_type="human_approval_request")
    )
    assert decision.decision == "ASK"
    assert decision.capability is None
    assert decision.pending_id


# ---------------------------------------------------------------------------
# unit: capability properties
# ---------------------------------------------------------------------------


def test_capability_is_single_use(issuer, holder, now_fn, envelope_spy):
    guardian = make_guardian(issuer, now_fn, holder=holder)
    peer = make_peer(now_fn)
    event = make_event(holder)
    decision = peer.send_event(guardian, event)
    assert decision.decision == "ALLOW"
    payload, envelope = assert_digest_binding(
        decision, event, holder, issuer, envelope_spy
    )
    # the linearizable PEP consumes it exactly once...
    store = make_pep_store()
    store.register_capability(payload)
    pep_attempt(
        store,
        payload,
        decision,
        holder,
        issuer,
        challenge=secrets.token_bytes(32),
        envelope=envelope,
    )
    # ...the second presentation is a double-spend -> denied
    with pytest.raises(DoubleSpendError):
        pep_attempt(
            store,
            payload,
            decision,
            holder,
            issuer,
            challenge=secrets.token_bytes(32),
            envelope=envelope,
        )


def test_capability_rejected_under_wrong_issuer_trust(issuer, holder, now_fn):
    """A capability is honored only inside the trust domain that minted it.

    NOTE (intent adapted from v0): the old attenuated tokens carried an
    ``audience`` caveat ("minted for anchor-pep"). Holder-of-key v1
    capabilities have no bearer audience; the equivalent binding is the
    PEP's trusted-issuer set — a PEP that does not trust this guardian's
    issuer key rejects the capability outright.
    """
    guardian = make_guardian(issuer, now_fn, holder=holder)
    decision = guardian.handle_event(make_event(holder))
    assert decision.decision == "ALLOW"
    rogue = Ed25519Signer.generate("rogue-guardian")
    rogue_issuers = trusted_issuers(rogue)
    with pytest.raises(CapabilityError):
        authority.verify_capability(decision.capability, rogue_issuers, now=NOW)


def test_capability_expires_with_ttl(issuer, holder, now_fn):
    guardian = make_guardian(issuer, now_fn, holder=holder, capability_ttl_s=60)
    decision = guardian.handle_event(make_event(holder))
    assert isinstance(decision.capability, bytes)
    issuers = trusted_issuers(issuer)
    # still valid just before expiry...
    authority.verify_capability(
        decision.capability, issuers, now=NOW + timedelta(seconds=59)
    )
    # ...expired one second past the ttl
    late = NOW + timedelta(seconds=61)
    with pytest.raises(CapabilityError, match="expired"):
        authority.verify_capability(decision.capability, issuers, now=late)


def test_capability_bound_to_constitution_hash(
    issuer, holder, now_fn, envelope_spy
):
    guardian = make_guardian(issuer, now_fn, holder=holder)
    event = make_event(holder)
    decision = guardian.handle_event(event)
    payload, envelope = assert_digest_binding(
        decision, event, holder, issuer, envelope_spy
    )
    # the digest commits to the constitution-bound envelope
    assert envelope.policy_ref == CONSTITUTION_HASH
    assert payload.action_digest == envelope.action_digest


def test_two_allows_mint_distinct_capabilities(issuer, holder, now_fn):
    guardian = make_guardian(issuer, now_fn, holder=holder)
    d1 = guardian.handle_event(make_event(holder, event_id="e1"))
    d2 = guardian.handle_event(make_event(holder, event_id="e2"))
    assert d1.capability != d2.capability
    issuers = trusted_issuers(issuer)
    p1 = authority.verify_capability(d1.capability, issuers, now=NOW)
    p2 = authority.verify_capability(d2.capability, issuers, now=NOW)
    assert p1.capability_id != p2.capability_id
    assert p1.nonce != p2.nonce
    assert p1.action_digest != p2.action_digest  # fresh envelope per mint


# ---------------------------------------------------------------------------
# unit: holder-key registry (fail closed)
# ---------------------------------------------------------------------------


def test_unknown_subject_denied_fail_closed(issuer, holder, now_fn):
    """A subject with no registered holder key can never be issued a
    capability: the mint raises, the decision is DENY."""
    guardian = make_guardian(issuer, now_fn, holder_keys={})
    decision = guardian.handle_event(make_event(holder))
    assert decision.decision == "DENY"
    assert decision.capability is None
    assert "holder key" in decision.reason


def test_malformed_holder_key_denied_fail_closed(issuer, holder, now_fn):
    """A registered but malformed holder key (not 32 raw Ed25519 bytes)
    makes the mint raise -> DENY. No bearer fallback, no unsigned path."""
    guardian = make_guardian(
        issuer, now_fn, holder_keys={holder.public_key_b64(): b"too-short"}
    )
    decision = guardian.handle_event(make_event(holder))
    assert decision.decision == "DENY"
    assert decision.capability is None
    assert "holder key" in decision.reason


def test_holder_proof_from_wrong_key_denied_at_pep(
    issuer, holder, now_fn, envelope_spy
):
    """A stolen capability blob is useless without the holder private key:
    a proof made with the wrong key is denied at the PEP."""
    guardian = make_guardian(issuer, now_fn, holder=holder)
    event = make_event(holder)
    decision = guardian.handle_event(event)
    payload, envelope = assert_digest_binding(
        decision, event, holder, issuer, envelope_spy
    )
    impostor = Ed25519Signer.generate("impostor")
    # authority level: proof from the wrong key fails verification
    bad_proof = authority.make_holder_proof(
        impostor, payload.capability_id, b"challenge-1"
    )
    with pytest.raises(CapabilityError):
        authority.verify_holder_proof(
            holder.public_key_bytes(), payload.capability_id, b"challenge-1", bad_proof
        )
    # PEP level: the full consumption path denies it too
    store = make_pep_store()
    store.register_capability(payload)
    with pytest.raises(AuthorizationDenied, match="holder proof failed"):
        pep_attempt(
            store,
            payload,
            decision,
            impostor,
            issuer,
            challenge=secrets.token_bytes(32),
            envelope=envelope,
        )


# ---------------------------------------------------------------------------
# unit: ASK/DEFER resolution API
# ---------------------------------------------------------------------------


def test_resolve_pending_approve_mints_capability(
    issuer, holder, now_fn, envelope_spy
):
    guardian = make_guardian(
        issuer, now_fn, holder=holder, decision_fn=lambda e: "ASK"
    )
    event = make_event(holder)
    pending = guardian.handle_event(event)
    assert pending.decision == "ASK"
    pid = pending.pending_id
    assert pid in guardian.pending
    decision = guardian.resolve_pending(pid, True)
    assert decision.decision == "ALLOW"
    assert decision.event_id == event.event_id
    assert pid not in guardian.pending, "resolving consumes the pending entry"
    # the approved capability is minted through the same path: verifiable
    # and bound to the exact event params
    payload, envelope = assert_digest_binding(
        decision, event, holder, issuer, envelope_spy
    )
    assert envelope_spy["calls"] == 1
    # ...and spendable at the PEP
    store = make_pep_store()
    store.register_capability(payload)
    consumed = pep_attempt(
        store,
        payload,
        decision,
        holder,
        issuer,
        challenge=secrets.token_bytes(32),
        envelope=envelope,
    )
    assert consumed.capability_id == payload.capability_id


def test_resolve_pending_reject_denies_and_clears(issuer, holder, now_fn):
    guardian = make_guardian(
        issuer, now_fn, holder=holder, decision_fn=lambda e: "DEFER"
    )
    pending = guardian.handle_event(make_event(holder))
    pid = pending.pending_id
    decision = guardian.resolve_pending(pid, False)
    assert decision.decision == "DENY"
    assert decision.capability is None
    assert pid not in guardian.pending, "rejection clears the pending entry"


def test_resolve_pending_unknown_id_raises(issuer, holder, now_fn):
    guardian = make_guardian(issuer, now_fn, holder=holder)
    with pytest.raises(ValueError, match="unknown pending_id"):
        guardian.resolve_pending("ask-deadbeef", True)


def test_resolve_pending_double_resolve_raises_no_double_mint(
    issuer, holder, now_fn, envelope_spy
):
    guardian = make_guardian(
        issuer, now_fn, holder=holder, decision_fn=lambda e: "ASK"
    )
    pending = guardian.handle_event(make_event(holder))
    pid = pending.pending_id
    first = guardian.resolve_pending(pid, True)
    assert first.decision == "ALLOW"
    assert first.capability is not None
    # the entry is consumed: a second resolve is an error, not a second mint
    with pytest.raises(ValueError, match="unknown pending_id"):
        guardian.resolve_pending(pid, True)
    assert envelope_spy["calls"] == 1, "no double mint on double resolve"


def test_resolve_pending_approve_mint_failure_denied(
    issuer, holder, now_fn, monkeypatch
):
    """Approving a pending request whose mint fails is DENY — the approval
    path uses the same fail-closed mint as the live path."""
    guardian = make_guardian(
        issuer, now_fn, holder=holder, decision_fn=lambda e: "ASK"
    )
    pending = guardian.handle_event(make_event(holder))

    def mint_boom(*a, **k):
        raise RuntimeError("HSM unreachable")

    monkeypatch.setattr(acs, "issue_execution", mint_boom)
    decision = guardian.resolve_pending(pending.pending_id, True)
    assert decision.decision == "DENY"
    assert decision.capability is None


# ---------------------------------------------------------------------------
# unit: wire protocol
# ---------------------------------------------------------------------------


def test_wire_roundtrip_allow_end_to_end(issuer, holder, now_fn, envelope_spy):
    guardian = make_guardian(issuer, now_fn, holder=holder)
    peer = make_peer(now_fn)
    event = make_event(holder)
    decision = peer.send_event(guardian, event)
    assert decision.decision == "ALLOW"
    assert isinstance(decision, GuardianDecision)
    assert isinstance(decision.capability, bytes), "capability crosses the wire"
    assert_digest_binding(decision, event, holder, issuer, envelope_spy)


def test_wire_roundtrip_deny_end_to_end(issuer, holder, now_fn):
    guardian = make_guardian(issuer, now_fn, decision_fn=deny_all)
    peer = make_peer(now_fn)
    decision = peer.send_event(guardian, make_event(holder))
    assert decision.decision == "DENY"
    assert decision.capability is None


def test_wire_bad_hmac_denied(issuer, holder, now_fn):
    guardian = make_guardian(issuer, now_fn)
    peer = make_peer(now_fn)
    raw = peer.build_event_frame(make_event(holder), key=WRONG_PSK)
    decision = peer.parse_decision_frame(guardian.handle_frame(raw))
    assert decision.decision == "DENY"
    assert "wire auth failed" in decision.reason
    assert decision.capability is None


def test_wire_replayed_nonce_denied(issuer, holder, now_fn):
    guardian = make_guardian(issuer, now_fn, holder=holder)
    peer = make_peer(now_fn)
    event = make_event(holder)
    raw = peer.build_event_frame(event, nonce="fixed-nonce-abc123")
    first = peer.parse_decision_frame(guardian.handle_frame(raw))
    assert first.decision == "ALLOW"
    # exact same bytes again -> replay -> DENY
    second = peer.parse_decision_frame(guardian.handle_frame(raw))
    assert second.decision == "DENY"
    assert second.capability is None


def test_wire_stale_timestamp_denied(issuer, holder, now_fn):
    guardian = make_guardian(issuer, now_fn)
    peer = make_peer(now_fn)
    raw = peer.build_event_frame(
        make_event(holder), ts=NOW - timedelta(seconds=301)
    )
    decision = peer.parse_decision_frame(guardian.handle_frame(raw))
    assert decision.decision == "DENY"
    assert decision.capability is None


def test_wire_future_timestamp_denied(issuer, holder, now_fn):
    guardian = make_guardian(issuer, now_fn)
    peer = make_peer(now_fn)
    raw = peer.build_event_frame(
        make_event(holder), ts=NOW + timedelta(seconds=301)
    )
    decision = peer.parse_decision_frame(guardian.handle_frame(raw))
    assert decision.decision == "DENY"
    assert decision.capability is None


def test_wire_naive_timestamp_denied(issuer, holder, now_fn):
    guardian = make_guardian(issuer, now_fn)
    peer = make_peer(now_fn)
    raw = peer.build_event_frame(make_event(holder), ts="2026-09-23T12:00:00")
    decision = peer.parse_decision_frame(guardian.handle_frame(raw))
    assert decision.decision == "DENY"
    assert decision.capability is None


def test_wire_truncated_frame_denied(issuer, holder, now_fn):
    guardian = make_guardian(issuer, now_fn)
    peer = make_peer(now_fn)
    raw = peer.build_event_frame(make_event(holder))
    for cut in (1, 10, len(raw) - 9):
        decision = peer.parse_decision_frame(guardian.handle_frame(raw[:cut]))
        assert decision.decision == "DENY", f"cut={cut}"
        assert decision.capability is None


def test_wire_bad_magic_denied(issuer, holder, now_fn):
    guardian = make_guardian(issuer, now_fn)
    peer = make_peer(now_fn)
    raw = bytearray(peer.build_event_frame(make_event(holder)))
    raw[0:4] = b"EVIL"
    decision = peer.parse_decision_frame(guardian.handle_frame(bytes(raw)))
    assert decision.decision == "DENY"
    assert decision.capability is None


def test_wire_length_mismatch_trailing_bytes_denied(issuer, holder, now_fn):
    guardian = make_guardian(issuer, now_fn)
    peer = make_peer(now_fn)
    raw = peer.build_event_frame(make_event(holder)) + b"TRAIL"
    decision = peer.parse_decision_frame(guardian.handle_frame(raw))
    assert decision.decision == "DENY"
    assert decision.capability is None


def test_wire_malformed_json_denied(issuer, holder, now_fn):
    guardian = make_guardian(issuer, now_fn)
    peer = make_peer(now_fn)
    body = b"{not valid json"
    raw = acs.FRAME_MAGIC + struct.pack(">I", len(body)) + body
    decision = peer.parse_decision_frame(guardian.handle_frame(raw))
    assert decision.decision == "DENY"
    assert decision.capability is None


def test_wire_oversized_length_denied(issuer, holder, now_fn):
    guardian = make_guardian(issuer, now_fn)
    peer = make_peer(now_fn)
    raw = acs.FRAME_MAGIC + struct.pack(">I", acs.MAX_FRAME_BYTES + 1) + b"{}"
    decision = peer.parse_decision_frame(guardian.handle_frame(raw))
    assert decision.decision == "DENY"
    assert decision.capability is None


def test_wire_wrong_kind_denied(issuer, holder, now_fn):
    guardian = make_guardian(issuer, now_fn)
    peer = make_peer(now_fn)
    # a peer must never send a "decision" frame; guardian must deny it
    payload = make_event(holder).model_dump(mode="json")
    body = {
        "v": acs.WIRE_VERSION,
        "kind": "decision",
        "nonce": "nonce-kind-evil",
        "ts": NOW.isoformat(),
        "payload": payload,
    }
    body["hmac"] = acs._compute_hmac(PSK, body)
    raw = acs._encode_frame(body)
    decision = peer.parse_decision_frame(guardian.handle_frame(raw))
    assert decision.decision == "DENY"
    assert decision.capability is None


def test_wire_missing_field_denied(issuer, holder, now_fn):
    guardian = make_guardian(issuer, now_fn)
    peer = make_peer(now_fn)
    body = {
        "v": acs.WIRE_VERSION,
        "kind": "event",
        "nonce": "nonce-missing-field",
        "ts": NOW.isoformat(),
        # "payload" deliberately absent
    }
    body["hmac"] = acs._compute_hmac(PSK, {**body, "payload": {}})
    raw = acs._encode_frame(body)
    decision = peer.parse_decision_frame(guardian.handle_frame(raw))
    assert decision.decision == "DENY"
    assert decision.capability is None


def test_empty_and_garbage_frames_denied(issuer, holder, now_fn):
    guardian = make_guardian(issuer, now_fn)
    peer = make_peer(now_fn)
    for junk in (b"", b"\x00", b"\xff" * 100, b"hello world"):
        decision = peer.parse_decision_frame(guardian.handle_frame(junk))
        assert decision.decision == "DENY"
        assert decision.capability is None


def test_guardian_internal_error_still_signed_deny(issuer, holder, now_fn, monkeypatch):
    guardian = make_guardian(issuer, now_fn)
    peer = make_peer(now_fn)

    def broken(self, data):
        raise RuntimeError("auth subsystem exploded")

    monkeypatch.setattr(AcsGuardian, "_authenticate_frame", broken)
    raw = peer.build_event_frame(make_event(holder))
    response = guardian.handle_frame(raw)  # must not raise
    decision = peer.parse_decision_frame(response)  # still a signed frame
    assert decision.decision == "DENY"
    assert "guardian error" in decision.reason
    assert decision.capability is None


def test_peer_rejects_tampered_decision_frame(issuer, holder, now_fn):
    guardian = make_guardian(issuer, now_fn, holder=holder)
    peer = make_peer(now_fn)
    raw = peer.build_event_frame(make_event(holder))
    response = bytearray(guardian.handle_frame(raw))
    response[40] ^= 0xFF  # flip a body byte -> HMAC no longer verifies
    with pytest.raises(WireAuthError):
        peer.parse_decision_frame(bytes(response))


def test_peer_rejects_decision_frame_signed_with_wrong_key(issuer, holder, now_fn):
    guardian = make_guardian(issuer, now_fn, holder=holder)
    peer = make_peer(now_fn)
    raw = peer.build_event_frame(make_event(holder))
    response = guardian.handle_frame(raw)
    evil_peer = WirePeer(psk=WRONG_PSK, now_fn=now_fn)
    with pytest.raises(WireAuthError):
        evil_peer.parse_decision_frame(response)


def test_peer_rejects_replayed_decision_frame(issuer, holder, now_fn):
    guardian = make_guardian(issuer, now_fn, holder=holder)
    peer = make_peer(now_fn)
    raw = peer.build_event_frame(make_event(holder))
    response = guardian.handle_frame(raw)
    first = peer.parse_decision_frame(response)
    assert first.decision == "ALLOW"
    with pytest.raises(WireAuthError, match="already seen"):
        peer.parse_decision_frame(response)


@pytest.mark.parametrize(
    "evil_blob",
    [
        b"not-a-cose-object",  # not CBOR at all
        b"\xa1\x61a\x01",  # valid CBOR, but a map — not a COSE_Sign1 array
    ],
)
def test_peer_rejects_non_cose_capability_in_decision_frame(
    issuer, holder, now_fn, evil_blob
):
    """A decision frame carrying a non-COSE capability blob is rejected by
    the peer (WireAuthError) — it must never be treated as an authorization."""
    guardian = make_guardian(issuer, now_fn, holder=holder)
    peer = make_peer(now_fn)
    response = guardian.handle_frame(peer.build_event_frame(make_event(holder)))
    body = acs._decode_frame(response)
    evil = dict(body)
    evil_payload = dict(body["payload"])
    evil_payload["capability"] = base64.b64encode(evil_blob).decode("ascii")
    evil["payload"] = evil_payload
    evil["nonce"] = secrets.token_hex(16)  # fresh nonce, valid HMAC
    evil["hmac"] = acs._compute_hmac(PSK, evil)
    with pytest.raises(WireAuthError):
        peer.parse_decision_frame(acs._encode_frame(evil))


def test_peer_rejects_malformed_base64_capability_in_decision_frame(
    issuer, holder, now_fn
):
    """A decision frame whose capability is not even valid base64 is
    rejected (WireAuthError)."""
    guardian = make_guardian(issuer, now_fn, holder=holder)
    peer = make_peer(now_fn)
    response = guardian.handle_frame(peer.build_event_frame(make_event(holder)))
    body = acs._decode_frame(response)
    evil = dict(body)
    evil_payload = dict(body["payload"])
    evil_payload["capability"] = "!!! not base64 !!!"
    evil["payload"] = evil_payload
    evil["nonce"] = secrets.token_hex(16)
    evil["hmac"] = acs._compute_hmac(PSK, evil)
    with pytest.raises(WireAuthError):
        peer.parse_decision_frame(acs._encode_frame(evil))


# ---------------------------------------------------------------------------
# fail-closed matrix: every failure mode -> DENY, no fail-open path
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "mode",
    [
        "fn-raises",
        "fn-timeout",
        "fn-bad-string",
        "fn-bad-type",
        "mint-fails",
        "unknown-event",
        "disabled-hook",
        "malformed-event",
        "modify-no-params",
        "unknown-subject",
        "malformed-holder-key",
    ],
)
def test_fail_closed_matrix(issuer, holder, now_fn, monkeypatch, mode):
    def boom(event):
        raise RuntimeError("boom")

    def slow(event):
        time.sleep(5)
        return "ALLOW"

    decision_fn = allow_all
    kwargs: dict = {}
    event: object = make_event(holder)
    if mode == "fn-raises":
        decision_fn = boom
    elif mode == "fn-timeout":
        decision_fn = slow
        kwargs["decision_timeout_s"] = 0.2
    elif mode == "fn-bad-string":
        decision_fn = lambda e: "SURE"  # noqa: E731
    elif mode == "fn-bad-type":
        decision_fn = lambda e: None  # noqa: E731
    elif mode == "unknown-event":
        event = make_event(holder, event_type="mystery_hook")
    elif mode == "disabled-hook":
        kwargs["enabled_hooks"] = ["session_start"]
    elif mode == "malformed-event":
        event = {"event_type": "pre_tool_call", "nope": True}
    elif mode == "modify-no-params":
        decision_fn = lambda e: DecisionResult(decision="MODIFY")  # noqa: E731
    elif mode == "unknown-subject":
        kwargs["holder_keys"] = {}  # subject has no registered holder key
    elif mode == "malformed-holder-key":
        kwargs["holder_keys"] = {holder.public_key_b64(): b"short"}

    # the default registry covers the event subject unless the mode overrides it
    if "holder_keys" not in kwargs:
        kwargs["holder_keys"] = {holder.public_key_b64(): holder.public_key_bytes()}
    guardian = make_guardian(issuer, now_fn, decision_fn=decision_fn, **kwargs)

    if mode == "mint-fails":

        def mint_boom(*a, **k):
            raise RuntimeError("HSM unreachable")

        monkeypatch.setattr(acs, "issue_execution", mint_boom)

    decision = guardian.handle_event(event)
    assert decision.decision == "DENY", f"mode={mode} was not fail-closed"
    assert decision.capability is None, f"mode={mode} leaked a capability"


def test_no_bare_allow_without_capability_possible(
    issuer, holder, now_fn, monkeypatch
):
    """Even with an ALLOW-happy decision function, sabotaging the mint must
    produce DENY — an ALLOW decision object without a capability cannot be
    constructed by the guardian."""
    guardian = make_guardian(issuer, now_fn, decision_fn=allow_all, holder=holder)

    def mint_boom(*a, **k):
        raise RuntimeError("mint sabotaged")

    monkeypatch.setattr(acs, "issue_execution", mint_boom)
    for hook in KNOWN_HOOKS:
        decision = guardian.handle_event(
            make_event(holder, event_type=hook, event_id=f"evt-{hook}")
        )
        assert decision.decision == "DENY", f"bare ALLOW escaped on {hook}"
        assert decision.capability is None


def test_modify_over_wire_capability_verifies(issuer, holder, now_fn, envelope_spy):
    modified = {"cmd": "echo hi", "timeout_s": 5}
    guardian = make_guardian(
        issuer,
        now_fn,
        holder=holder,
        decision_fn=lambda e: DecisionResult(
            decision="MODIFY", modified_params=modified
        ),
    )
    peer = make_peer(now_fn)
    event = make_event(holder)
    decision = peer.send_event(guardian, event)
    assert decision.decision == "MODIFY"
    assert decision.modified_params == modified
    assert_digest_binding(decision, event, holder, issuer, envelope_spy, params=modified)


# ---------------------------------------------------------------------------
# adversarial attacks (must all end DENY / rejected)
# ---------------------------------------------------------------------------


def test_ADV01_forged_wire_signature(issuer, holder, now_fn):
    """Attacker signs the frame with the wrong PSK. Must be DENY."""
    guardian = make_guardian(issuer, now_fn)
    peer = make_peer(now_fn)
    raw = peer.build_event_frame(make_event(holder), key=WRONG_PSK)
    decision = peer.parse_decision_frame(guardian.handle_frame(raw))
    assert decision.decision == "DENY"
    assert decision.capability is None
    print("ADV-01 forged wire signature -> DENY: PASS")


def test_ADV02_replayed_message_exact_bytes(issuer, holder, now_fn):
    """Attacker captures valid wire bytes and resends them verbatim."""
    guardian = make_guardian(issuer, now_fn, holder=holder)
    peer = make_peer(now_fn)
    raw = peer.build_event_frame(make_event(holder))
    assert peer.parse_decision_frame(guardian.handle_frame(raw)).decision == "ALLOW"
    replay = peer.parse_decision_frame(guardian.handle_frame(raw))
    assert replay.decision == "DENY"  # nonce reuse -> replay denied
    assert replay.capability is None
    print("ADV-02 replayed message (nonce reuse) -> DENY: PASS")


def test_ADV03_timestamp_outside_window(issuer, holder, now_fn):
    """Attacker replays an old signed frame, or pre-signs a future one."""
    guardian = make_guardian(issuer, now_fn)
    peer = make_peer(now_fn)
    for evil_ts in (NOW - timedelta(hours=2), NOW + timedelta(hours=2)):
        raw = peer.build_event_frame(make_event(holder), ts=evil_ts)
        decision = peer.parse_decision_frame(guardian.handle_frame(raw))
        assert decision.decision == "DENY"
        assert decision.capability is None
    print("ADV-03 timestamp outside window -> DENY: PASS")


def test_ADV04_unknown_event_type_smuggled_over_wire(issuer, holder, now_fn):
    """Attacker invents a hook the guardian never defined."""
    guardian = make_guardian(issuer, now_fn)
    peer = make_peer(now_fn)
    decision = peer.send_event(
        guardian, make_event(holder, event_type="pre_exfiltration")
    )
    assert decision.decision == "DENY"
    assert decision.capability is None
    print("ADV-04 unknown event type -> DENY: PASS")


def test_ADV05_decision_function_raises(issuer, holder, now_fn):
    """Policy engine throws. Must be DENY, not a crash, not an allow."""

    def policy_engine(event):
        raise ValueError("policy backend unreachable")

    guardian = make_guardian(issuer, now_fn, decision_fn=policy_engine)
    peer = make_peer(now_fn)
    decision = peer.send_event(guardian, make_event(holder))
    assert decision.decision == "DENY"
    assert decision.capability is None
    print("ADV-05 decision-function raising -> DENY: PASS")


def test_ADV06_mint_sabotage_cannot_yield_bare_allow(
    issuer, holder, now_fn, monkeypatch
):
    """Attacker breaks capability issuance (or a bug does). The guardian must
    answer DENY — an ALLOW decision without a capability must be impossible."""

    def mint_boom(*a, **k):
        raise RuntimeError("HSM unreachable")

    monkeypatch.setattr(acs, "issue_execution", mint_boom)
    guardian = make_guardian(issuer, now_fn, decision_fn=allow_all, holder=holder)
    peer = make_peer(now_fn)
    decision = peer.send_event(guardian, make_event(holder))
    assert decision.decision == "DENY"
    assert decision.capability is None
    print("ADV-06 ALLOW without capability mint impossible -> DENY: PASS")


def test_ADV07_hook_bypass_on_disabled_hook(issuer, holder, now_fn):
    """Attacker fires an event on a hook the operator disabled."""
    seen = []
    guardian = make_guardian(
        issuer,
        now_fn,
        decision_fn=lambda e: seen.append(e) or "ALLOW",
        enabled_hooks=["session_start", "session_end"],
    )
    peer = make_peer(now_fn)
    decision = peer.send_event(
        guardian, make_event(holder, event_type="pre_delegation")
    )
    assert decision.decision == "DENY"
    assert decision.capability is None
    assert seen == []
    print("ADV-07 hook bypass (disabled hook) -> DENY: PASS")


def test_ADV08_frame_truncation(issuer, holder, now_fn):
    """Attacker truncates the frame mid-body hoping for a partial parse."""
    guardian = make_guardian(issuer, now_fn)
    peer = make_peer(now_fn)
    raw = peer.build_event_frame(make_event(holder))
    truncated = raw[: len(raw) // 2]
    decision = peer.parse_decision_frame(guardian.handle_frame(truncated))
    assert decision.decision == "DENY"
    assert decision.capability is None
    print("ADV-08 frame truncation -> DENY: PASS")


def test_ADV09_body_tampering(issuer, holder, now_fn):
    """Attacker flips bytes in the signed body (e.g. swaps the command).
    HMAC must fail -> DENY."""
    guardian = make_guardian(issuer, now_fn)
    peer = make_peer(now_fn)
    raw = bytearray(peer.build_event_frame(make_event(holder)))
    # flip several bytes deep inside the JSON body
    for i in (30, 60, 90):
        raw[i] ^= 0xFF
    decision = peer.parse_decision_frame(guardian.handle_frame(bytes(raw)))
    assert decision.decision == "DENY"
    assert decision.capability is None
    print("ADV-09 body tampering -> DENY: PASS")


def test_ADV10_forged_decision_frame_to_peer(issuer, holder, now_fn):
    """Attacker forges a guardian 'ALLOW' frame to trick the agent-side peer.
    The peer must reject it (WireAuthError), not deliver a fake ALLOW."""
    peer = make_peer(now_fn)
    fake_payload = {
        "event_id": "evt-1",
        "decision": "ALLOW",
        "reason": "",
        "capability": None,
        "modified_params": None,
        "pending_id": None,
    }
    body = {
        "v": acs.WIRE_VERSION,
        "kind": "decision",
        "nonce": "forged-nonce",
        "ts": NOW.isoformat(),
        "payload": fake_payload,
    }
    body["hmac"] = acs._compute_hmac(WRONG_PSK, body)  # attacker key
    raw = acs._encode_frame(body)
    with pytest.raises(WireAuthError):
        peer.parse_decision_frame(raw)
    print("ADV-10 forged decision frame rejected by peer: PASS")


def test_ADV11_capability_double_spend_at_pep(issuer, holder, now_fn, envelope_spy):
    """Attacker replays a minted one-use capability at the enforcement point.
    The linearizable store must reject the second presentation."""
    guardian = make_guardian(issuer, now_fn, holder=holder)
    event = make_event(holder)
    decision = guardian.handle_event(event)
    assert decision.decision == "ALLOW"
    payload, envelope = assert_digest_binding(
        decision, event, holder, issuer, envelope_spy
    )
    store = make_pep_store()
    store.register_capability(payload)
    pep_attempt(
        store,
        payload,
        decision,
        holder,
        issuer,
        challenge=secrets.token_bytes(32),
        envelope=envelope,
    )
    with pytest.raises(DoubleSpendError):
        pep_attempt(
            store,
            payload,
            decision,
            holder,
            issuer,
            challenge=secrets.token_bytes(32),
            envelope=envelope,
        )
    print("ADV-11 capability double-spend rejected: PASS")


def test_ADV12_capability_parameter_substitution(
    issuer, holder, now_fn, envelope_spy
):
    """Attacker presents a valid capability but the PEP is asked to execute
    different params (e.g. swaps 'ls /safe' for 'rm -rf /'). The envelope
    the PEP would execute does not match the bound digest -> denied."""
    guardian = make_guardian(issuer, now_fn, holder=holder)
    event = make_event(holder)
    decision = guardian.handle_event(event)
    assert decision.decision == "ALLOW"
    payload, _envelope = assert_digest_binding(
        decision, event, holder, issuer, envelope_spy
    )
    evil_envelope = acs._build_envelope(
        event,
        {"cmd": "rm -rf /", "timeout_s": 30},
        NOW,
        ttl_s=CAPABILITY_TTL_S,
        constitution_hash=CONSTITUTION_HASH,
    )
    assert evil_envelope.action_digest != payload.action_digest
    store = make_pep_store()
    store.register_capability(payload)
    with pytest.raises(AuthorizationDenied, match="does not match capability binding"):
        pep_attempt(
            store,
            payload,
            decision,
            holder,
            issuer,
            challenge=secrets.token_bytes(32),
            envelope=evil_envelope,
        )
    print("ADV-12 capability parameter substitution rejected: PASS")
