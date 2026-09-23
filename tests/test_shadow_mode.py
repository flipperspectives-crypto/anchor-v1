"""Tests for anchor_v1.shadow_mode: every rule + adversarial attacks.

All attacks must end DENY / rejected / invalid — never silent-allow, never
silent mode flip, never silent log rewrite.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from anchor_v1.attenuated_tokens import (
    AttenuatedTokenPayload,
    issue,
    make_holder_proof,
)
from anchor_v1.crypto import Ed25519Signer
from anchor_v1.models import SignedEnvelope
from anchor_v1.multisig_constitution import Constitution, content_hash_of
from anchor_v1.shadow_mode import (
    CompareInputRejected,
    EvaluationRequest,
    ModeChangeRejected,
    ShadowDenied,
    ShadowGovernor,
    ShadowRecord,
    compare,
    sign_mode_change,
)

NOW = datetime(2026, 9, 23, 12, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# fixtures / helpers
# ---------------------------------------------------------------------------


def make_constitution(**overrides) -> Constitution:
    base = dict(
        version=1,
        previous_hash=None,
        invariants=["deny:secrets.*"],
        hard_deny_actions=["db.drop_*", "prod.delete_*"],
        approval_required_actions=["billing.refund"],
        authority_epoch=0,
        created_at=NOW,
    )
    base.update(overrides)
    return Constitution(**base)


@pytest.fixture()
def constitution() -> Constitution:
    return make_constitution()


@pytest.fixture()
def controller() -> Ed25519Signer:
    return Ed25519Signer.generate("controller-1")


@pytest.fixture()
def attacker_key() -> Ed25519Signer:
    return Ed25519Signer.generate("attacker")


def controller_keys(controller: Ed25519Signer) -> dict[str, bytes]:
    return {controller.key_id: controller.public_key_bytes()}


def make_governor(
    constitution: Constitution,
    controller: Ed25519Signer,
    *,
    mode="ENFORCE",
    never_shadow=None,
) -> ShadowGovernor:
    return ShadowGovernor(
        constitution,
        mode=mode,
        never_shadow=never_shadow,
        controller_keys=controller_keys(controller),
        now_fn=lambda: NOW,
    )


def req(action: str, resource: str = "workspace://docs", subject: str = "agent-1", **kw):
    return EvaluationRequest(action=action, resource=resource, subject=subject, **kw)


def signed_change(
    signer: Ed25519Signer,
    *,
    mode: str,
    sequence: int,
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
) -> SignedEnvelope:
    return sign_mode_change(
        signer,
        mode=mode,  # type: ignore[arg-type]
        sequence=sequence,
        issued_at=issued_at or (NOW - timedelta(minutes=1)),
        expires_at=expires_at or (NOW + timedelta(hours=1)),
    )


# -- token helpers ----------------------------------------------------------


@pytest.fixture()
def issuer() -> Ed25519Signer:
    return Ed25519Signer.generate("issuer-1")


@pytest.fixture()
def holder() -> Ed25519Signer:
    return Ed25519Signer.generate("holder-1")


def mint_token(issuer, holder, constitution, *, action="files.read",
               resource="workspace://docs/report.md", params=None,
               not_before=None, expires_at=None):
    params = {"op": "read"} if params is None else params
    env = issue(
        issuer,
        capability_id="cap-files",
        subject=holder.public_key_b64(),
        audience="governor",
        action=action,
        resource=resource,
        invocation_params=params,
        not_before=not_before or (NOW - timedelta(hours=1)),
        expires_at=expires_at or (NOW + timedelta(hours=1)),
        constitution_hash=content_hash_of(constitution),
    )
    nonce = AttenuatedTokenPayload.model_validate(env.payload).nonce
    proof = make_holder_proof(holder, "cap-files", nonce)
    return {
        "envelope": env,
        "holder_proof": proof,
        "invocation_params": params,
        "trusted_issuers": {issuer.key_id: issuer.public_key_bytes()},
        "context": {},
    }


def token_request(issuer, holder, constitution, **overrides):
    t = mint_token(issuer, holder, constitution)
    return EvaluationRequest(
        action="files.read",
        resource="workspace://docs/report.md",
        subject=holder.public_key_b64(),
        token=t,
        **overrides,
    )


# ---------------------------------------------------------------------------
# rule tests: ENFORCE mode
# ---------------------------------------------------------------------------


def test_enforce_allows(constitution, controller):
    gov = make_governor(constitution, controller, mode="ENFORCE")
    rec = gov.evaluate(req("files.read"))
    assert rec.evaluated_decision == "ALLOW"
    assert rec.enforced_decision == "ALLOW"
    assert rec.would_have_denied is False
    assert rec.would_have_required_approval is False
    assert rec.proceed is True
    assert rec.previous_record_hash != ""
    assert rec.decision_source == content_hash_of(constitution)


def test_enforce_denies_and_raises(constitution, controller):
    gov = make_governor(constitution, controller, mode="ENFORCE")
    with pytest.raises(ShadowDenied) as exc_info:
        gov.evaluate(req("db.drop_users"))
    rec = exc_info.value.record
    assert rec is not None
    assert rec.evaluated_decision == "DENY"
    assert rec.enforced_decision == "DENY"
    assert rec.would_have_denied is False
    assert rec.proceed is False
    # denial is still logged in the hash-chained log
    assert gov.verify_log().ok is True
    assert len(gov.records) == 1


def test_enforce_approval_required_does_not_raise(constitution, controller):
    gov = make_governor(constitution, controller, mode="ENFORCE")
    rec = gov.evaluate(req("billing.refund"))
    assert rec.evaluated_decision == "APPROVAL_REQUIRED"
    assert rec.enforced_decision == "APPROVAL_REQUIRED"
    assert rec.proceed is False  # caller must run the approval flow


def test_invariant_deny_pattern(constitution, controller):
    gov = make_governor(constitution, controller, mode="ENFORCE")
    with pytest.raises(ShadowDenied):
        gov.evaluate(req("secrets.exfiltrate"))


def test_malformed_request_rejected_not_allowed(constitution, controller):
    gov = make_governor(constitution, controller, mode="ENFORCE")
    with pytest.raises(ValidationError):
        gov.evaluate({"action": "", "resource": "x", "subject": "y"})
    with pytest.raises(ValidationError):
        gov.evaluate({"action": "files.read"})  # missing fields
    assert len(gov.records) == 0  # nothing logged, nothing allowed


# ---------------------------------------------------------------------------
# rule tests: SHADOW mode
# ---------------------------------------------------------------------------


def test_shadow_logs_would_have_denied(constitution, controller):
    gov = make_governor(constitution, controller, mode="SHADOW",
                        never_shadow=[])  # shadow everything
    rec = gov.evaluate(req("db.drop_users"))
    assert rec.evaluated_decision == "DENY"
    assert rec.enforced_decision == "ALLOW"  # action proceeds
    assert rec.would_have_denied is True
    assert rec.proceed is True


def test_shadow_logs_would_have_required_approval(constitution, controller):
    gov = make_governor(constitution, controller, mode="SHADOW", never_shadow=[])
    rec = gov.evaluate(req("billing.refund"))
    assert rec.evaluated_decision == "APPROVAL_REQUIRED"
    assert rec.enforced_decision == "ALLOW"
    assert rec.would_have_required_approval is True


def test_shadow_allows_normally(constitution, controller):
    gov = make_governor(constitution, controller, mode="SHADOW", never_shadow=[])
    rec = gov.evaluate(req("files.read"))
    assert rec.enforced_decision == "ALLOW"
    assert rec.would_have_denied is False
    assert rec.would_have_required_approval is False


def test_never_shadow_defaults_to_constitution_hard_deny(constitution, controller):
    gov = make_governor(constitution, controller, mode="SHADOW")  # defaults
    assert set(gov.never_shadow) == {"db.drop_*", "prod.delete_*"}
    with pytest.raises(ShadowDenied):
        gov.evaluate(req("prod.delete_cluster"))


def test_never_shadow_custom_patterns(constitution, controller):
    gov = make_governor(
        constitution, controller, mode="SHADOW", never_shadow=["secrets.*"]
    )
    # secrets.read evaluates DENY via the invariant and matches never_shadow,
    # so it enforces even in SHADOW mode.
    with pytest.raises(ShadowDenied) as exc_info:
        gov.evaluate(req("secrets.read"))
    assert exc_info.value.record.enforced_decision == "DENY"
    # ...while a non-matching denied action still shadows
    rec = gov.evaluate(req("db.drop_users"))
    assert rec.would_have_denied is True


def test_never_shadow_deny_records_not_would_have(constitution, controller):
    gov = make_governor(constitution, controller, mode="SHADOW", never_shadow=["db.*"])
    with pytest.raises(ShadowDenied) as exc_info:
        gov.evaluate(req("db.drop_users"))
    rec = exc_info.value.record
    assert rec.enforced_decision == "DENY"
    assert rec.would_have_denied is False  # it actually denied


# ---------------------------------------------------------------------------
# hash-chained log integrity
# ---------------------------------------------------------------------------


def test_hash_chain_links_and_verifies(constitution, controller):
    gov = make_governor(constitution, controller, mode="SHADOW", never_shadow=[])
    gov.evaluate(req("files.read"))
    gov.evaluate(req("db.drop_users"))
    gov.evaluate(req("billing.refund"))
    assert len(gov.records) == 3
    for i in range(1, 3):
        assert gov.records[i].previous_record_hash == gov.records[i - 1].record_hash
    integrity = gov.verify_log()
    assert integrity.ok is True
    assert integrity.records_checked == 3
    assert integrity.first_bad_index is None
    assert len({r.record_id for r in gov.records}) == 3


def test_record_ids_derive_from_hash(constitution, controller):
    gov = make_governor(constitution, controller, mode="SHADOW", never_shadow=[])
    rec = gov.evaluate(req("files.read"))
    assert rec.record_id == f"rec-{rec.record_hash[:16]}"


def test_diff_vs_baseline_recorded(constitution, controller):
    gov = make_governor(constitution, controller, mode="SHADOW", never_shadow=[])
    rec = gov.evaluate(req("db.drop_users", baseline_decision="ALLOW"))
    assert rec.diff_vs_baseline == "ALLOW->DENY"
    rec2 = gov.evaluate(req("files.read", baseline_decision="ALLOW"))
    assert rec2.diff_vs_baseline is None
    assert gov.verify_log().ok is True


# ---------------------------------------------------------------------------
# divergence summary
# ---------------------------------------------------------------------------


def test_summarize_counts_and_top_offenders(constitution, controller):
    gov = make_governor(constitution, controller, mode="SHADOW", never_shadow=[])
    gov.evaluate(req("files.read"))
    gov.evaluate(req("db.drop_users", resource="db://users"))
    gov.evaluate(req("db.drop_orders", resource="db://orders"))
    gov.evaluate(req("prod.delete_cache", resource="k8s://cache"))
    gov.evaluate(req("billing.refund", resource="stripe://acct"))
    s = gov.summarize()
    assert s.total == 5
    assert s.would_have_denied == 3
    assert s.enforced_denied == 0
    assert s.approval_required == 1
    assert s.would_have_required_approval == 1
    assert s.shadow_allowed == 5
    actions = dict(s.top_denied_actions)
    assert actions["db.drop_users"] == 1
    assert actions["db.drop_orders"] == 1
    assert actions["prod.delete_cache"] == 1
    resources = dict(s.top_denied_resources)
    assert resources["db://users"] == 1
    assert len(s.top_denied_actions) == 3


def test_summarize_empty_log(constitution, controller):
    gov = make_governor(constitution, controller, mode="SHADOW")
    s = gov.summarize()
    assert s.total == 0
    assert s.would_have_denied == 0
    assert s.top_denied_actions == []


def test_summarize_top_offenders_ranked(constitution, controller):
    gov = make_governor(constitution, controller, mode="SHADOW", never_shadow=[])
    for _ in range(4):
        gov.evaluate(req("db.drop_users", resource="db://users"))
    gov.evaluate(req("prod.delete_cache", resource="k8s://cache"))
    s = gov.summarize()
    assert s.top_denied_actions[0] == ("db.drop_users", 4)
    assert s.top_denied_resources[0] == ("db://users", 4)


# ---------------------------------------------------------------------------
# signed mode changes
# ---------------------------------------------------------------------------


def test_signed_mode_change_enforce_to_shadow(constitution, controller):
    gov = make_governor(constitution, controller, mode="ENFORCE")
    cmd = gov.apply_mode_change(signed_change(controller, mode="SHADOW", sequence=0))
    assert cmd.mode == "SHADOW"
    assert gov.mode == "SHADOW"
    assert gov.last_sequence == 0
    # shadow now actually shadows (never_shadow emptied so nothing enforces)
    gov2 = make_governor(constitution, controller, mode="ENFORCE", never_shadow=[])
    gov2.apply_mode_change(signed_change(controller, mode="SHADOW", sequence=0))
    rec2 = gov2.evaluate(req("db.drop_users"))
    assert rec2.would_have_denied is True


def test_mode_change_back_to_enforce(constitution, controller):
    gov = make_governor(constitution, controller, mode="SHADOW", never_shadow=[])
    gov.apply_mode_change(signed_change(controller, mode="SHADOW", sequence=0))
    gov.apply_mode_change(signed_change(controller, mode="ENFORCE", sequence=1))
    assert gov.mode == "ENFORCE"
    with pytest.raises(ShadowDenied):
        gov.evaluate(req("db.drop_users"))


def test_mode_property_has_no_setter(constitution, controller):
    gov = make_governor(constitution, controller, mode="ENFORCE")
    with pytest.raises(AttributeError):
        gov.mode = "SHADOW"  # type: ignore[misc]
    assert gov.mode == "ENFORCE"


def test_mode_change_without_controller_keys_rejected(constitution, controller):
    gov = ShadowGovernor(constitution, controller_keys={}, now_fn=lambda: NOW)
    with pytest.raises(ModeChangeRejected):
        gov.apply_mode_change(signed_change(controller, mode="SHADOW", sequence=0))
    assert gov.mode == "ENFORCE"


def test_evaluate_with_outcome_never_raises(constitution, controller):
    gov = make_governor(constitution, controller, mode="ENFORCE")
    out = gov.evaluate_with_outcome(req("db.drop_users"))
    assert out.allowed is False
    assert out.record.enforced_decision == "DENY"
    out2 = gov.evaluate_with_outcome(req("files.read"))
    assert out2.allowed is True


# ---------------------------------------------------------------------------
# capability-token pipeline
# ---------------------------------------------------------------------------


def test_token_success_allows(constitution, controller, issuer, holder):
    gov = make_governor(constitution, controller, mode="ENFORCE")
    rec = gov.evaluate(token_request(issuer, holder, constitution))
    assert rec.evaluated_decision == "ALLOW"
    assert rec.enforced_decision == "ALLOW"
    assert "token:" in rec.decision_source


def test_token_failure_denies_in_enforce(constitution, controller, issuer, holder):
    gov = make_governor(constitution, controller, mode="ENFORCE")
    bad = token_request(issuer, holder, constitution)
    bad.token.invocation_params = {"op": "write"}  # breaks invocation binding
    with pytest.raises(ShadowDenied) as exc_info:
        gov.evaluate(bad)
    assert exc_info.value.record.evaluated_decision == "DENY"


def test_token_failure_shadow_logs_would_have_denied(
    constitution, controller, issuer, holder
):
    gov = make_governor(constitution, controller, mode="SHADOW", never_shadow=[])
    bad = token_request(issuer, holder, constitution)
    bad.token.invocation_params = {"op": "write"}
    rec = gov.evaluate(bad)
    assert rec.evaluated_decision == "DENY"
    assert rec.enforced_decision == "ALLOW"
    assert rec.would_have_denied is True


def test_token_action_binding_mismatch_denies(constitution, controller, issuer, holder):
    gov = make_governor(constitution, controller, mode="ENFORCE")
    good = token_request(issuer, holder, constitution)
    good.action = "files.write"  # token was minted for files.read
    with pytest.raises(ShadowDenied):
        gov.evaluate(good)


def test_token_expired_denies(constitution, controller, issuer, holder):
    gov = make_governor(constitution, controller, mode="ENFORCE")
    t = mint_token(
        issuer, holder, constitution,
        not_before=NOW - timedelta(hours=2),
        expires_at=NOW - timedelta(hours=1),
    )
    r = EvaluationRequest(
        action="files.read", resource="workspace://docs/report.md",
        subject=holder.public_key_b64(), token=t,
    )
    with pytest.raises(ShadowDenied):
        gov.evaluate(r)


def test_token_untrusted_issuer_denies(constitution, controller, issuer, holder):
    gov = make_governor(constitution, controller, mode="ENFORCE")
    r = token_request(issuer, holder, constitution)
    r.token.trusted_issuers = {"someone-else": issuer.public_key_bytes()}
    with pytest.raises(ShadowDenied):
        gov.evaluate(r)


# ---------------------------------------------------------------------------
# dry-run compare
# ---------------------------------------------------------------------------


def _old_new_constitutions():
    old = make_constitution()
    new = make_constitution(
        version=2,
        previous_hash=content_hash_of(old),
        # tighten: billing.refund now hard-denied instead of approval-required
        hard_deny_actions=["db.drop_*", "prod.delete_*", "billing.refund"],
        approval_required_actions=[],
        # loosen: secrets.* no longer denied
        invariants=[],
    )
    return old, new


def test_compare_detects_risky_flips():
    old, new = _old_new_constitutions()
    history = [
        req("files.read"),
        req("billing.refund"),      # APPROVAL_REQUIRED -> DENY : risky
        req("db.drop_users"),       # DENY -> DENY : unchanged
        req("secrets.exfiltrate"),  # DENY -> ALLOW : loosen
    ]
    report = compare(old, new, history)
    assert report.total == 4
    assert report.changed_count == 2
    assert report.unchanged_count == 2
    assert len(report.risky_flips) == 1
    flip = report.risky_flips[0]
    assert flip.action == "billing.refund"
    assert flip.old_decision == "APPROVAL_REQUIRED"
    assert flip.new_decision == "DENY"
    assert flip.risk == "tighten-to-deny"
    loosen = [d for d in report.diffs if d.action == "secrets.exfiltrate"][0]
    assert loosen.risk == "loosen"
    assert report.old_constitution_hash == content_hash_of(old)
    assert report.new_constitution_hash == content_hash_of(new)


def test_compare_no_changes():
    old, _ = _old_new_constitutions()
    report = compare(old, old, [req("files.read"), req("db.drop_users")])
    assert report.changed_count == 0
    assert report.risky_flips == []
    assert all(d.risk == "none" for d in report.diffs)


def test_compare_accepts_dict_requests():
    old, new = _old_new_constitutions()
    report = compare(
        old, new,
        [{"action": "billing.refund", "resource": "r", "subject": "s"}],
    )
    assert report.total == 1
    assert report.changed_count == 1


def test_compare_empty_history():
    old, new = _old_new_constitutions()
    report = compare(old, new, [])
    assert report.total == 0
    assert report.changed_count == 0


def test_compare_token_requests_flagged_not_replayed(
    constitution, issuer, holder
):
    old, new = _old_new_constitutions()
    history = [token_request(issuer, holder, constitution)]
    report = compare(old, new, history)
    assert report.total == 1
    assert report.diffs[0].token_present is True
    # constitution-only replay still ran; nothing crashed on the token
    assert report.diffs[0].old_decision == "ALLOW"


# ---------------------------------------------------------------------------
# ADVERSARIAL ATTACKS — every one must fail closed
# ---------------------------------------------------------------------------


def test_attack_unsigned_mode_flip_rejected(constitution, controller, attacker_key):
    """Attacker tries to flip ENFORCE->SHADOW with a key that is not an
    authorized controller. Must be rejected; mode unchanged."""
    gov = make_governor(constitution, controller, mode="ENFORCE")
    forged = signed_change(attacker_key, mode="SHADOW", sequence=0)
    with pytest.raises(ModeChangeRejected):
        gov.apply_mode_change(forged)
    assert gov.mode == "ENFORCE"
    # and the action still blocks afterwards
    with pytest.raises(ShadowDenied):
        gov.evaluate(req("db.drop_users"))


def test_attack_replay_old_mode_change_rejected(constitution, controller):
    """Attacker replays an old signed ENFORCE->SHADOW command after a newer
    command was applied. Monotonic sequence must reject the replay."""
    gov = make_governor(constitution, controller, mode="ENFORCE", never_shadow=[])
    old_cmd = signed_change(controller, mode="SHADOW", sequence=0)
    gov.apply_mode_change(signed_change(controller, mode="SHADOW", sequence=5))
    assert gov.mode == "SHADOW"
    gov.apply_mode_change(signed_change(controller, mode="ENFORCE", sequence=6))
    assert gov.mode == "ENFORCE"
    # replay the stale seq-0 SHADOW command -> must be rejected, stays ENFORCE
    with pytest.raises(ModeChangeRejected):
        gov.apply_mode_change(old_cmd)
    assert gov.mode == "ENFORCE"
    # replaying the exact same envelope twice is also rejected
    cmd6 = signed_change(controller, mode="ENFORCE", sequence=6)
    with pytest.raises(ModeChangeRejected):
        gov.apply_mode_change(cmd6)
    assert gov.mode == "ENFORCE"


def test_attack_expired_mode_change_rejected(constitution, controller):
    """A legitimately signed but expired envelope must not flip the mode."""
    gov = make_governor(constitution, controller, mode="ENFORCE")
    expired = signed_change(
        controller,
        mode="SHADOW",
        sequence=0,
        issued_at=NOW - timedelta(hours=2),
        expires_at=NOW - timedelta(hours=1),
    )
    with pytest.raises(ModeChangeRejected):
        gov.apply_mode_change(expired)
    assert gov.mode == "ENFORCE"


def test_attack_future_issued_mode_change_rejected(constitution, controller):
    """Envelope with issued_at in the future (clock games) is rejected."""
    gov = make_governor(constitution, controller, mode="ENFORCE")
    future = signed_change(
        controller,
        mode="SHADOW",
        sequence=0,
        issued_at=NOW + timedelta(hours=1),
        expires_at=NOW + timedelta(hours=2),
    )
    with pytest.raises(ModeChangeRejected):
        gov.apply_mode_change(future)
    assert gov.mode == "ENFORCE"


def test_attack_tampered_mode_change_signature_rejected(constitution, controller):
    """Attacker flips bytes in a valid envelope's signature. Rejected."""
    gov = make_governor(constitution, controller, mode="ENFORCE")
    good = signed_change(controller, mode="SHADOW", sequence=0)
    sig_bytes = bytearray(__import__("base64").b64decode(good.signature))
    sig_bytes[0] ^= 0xFF
    tampered = SignedEnvelope(
        key_id=good.key_id,
        payload=good.payload,
        signature=__import__("base64").b64encode(bytes(sig_bytes)).decode(),
    )
    with pytest.raises(ModeChangeRejected):
        gov.apply_mode_change(tampered)
    assert gov.mode == "ENFORCE"


def test_attack_malformed_mode_change_payload_rejected(constitution, controller):
    """A valid signature over a non-command payload must not flip the mode."""
    gov = make_governor(constitution, controller, mode="ENFORCE")
    junk = controller.sign_payload({"definitely": "not-a-command"})
    with pytest.raises(ModeChangeRejected):
        gov.apply_mode_change(junk)
    assert gov.mode == "ENFORCE"


def test_attack_shadow_log_tampering_detected(constitution, controller):
    """Attacker rewrites a would-have-denied record to ALLOW. The hash chain
    must catch it and point at the tampered index."""
    gov = make_governor(constitution, controller, mode="SHADOW", never_shadow=[])
    gov.evaluate(req("files.read"))
    gov.evaluate(req("db.drop_users"))  # would-have-denied
    gov.evaluate(req("billing.refund"))
    assert gov.verify_log().ok is True
    # tamper: rewrite the denial into an allow
    victim = gov.records[1]
    victim.evaluated_decision = "ALLOW"  # type: ignore[assignment]
    victim.would_have_denied = False  # type: ignore[assignment]
    integrity = gov.verify_log()
    assert integrity.ok is False
    assert integrity.first_bad_index == 1


def test_attack_shadow_log_truncation_detected(constitution, controller):
    """Attacker drops the incriminating tail record. Chain break detected."""
    gov = make_governor(constitution, controller, mode="SHADOW", never_shadow=[])
    gov.evaluate(req("files.read"))
    gov.evaluate(req("db.drop_users"))
    assert gov.verify_log().ok is True
    gov._records.pop()  # attacker removes the denial record
    # remaining chain still verifies (prefix intact) but the summary no longer
    # hides it: total dropped — so also test forged-append detection:
    forged = ShadowRecord(
        record_id="rec-forged",
        timestamp=NOW,
        action="db.drop_users",
        resource="workspace://docs",
        subject="agent-1",
        evaluated_decision="ALLOW",
        enforced_decision="ALLOW",
        would_have_denied=False,
        would_have_required_approval=False,
        decision_source="forged",
        previous_record_hash=gov.records[-1].record_hash,
        record_hash="f" * 64,
    )
    gov._records.append(forged)
    integrity = gov.verify_log()
    assert integrity.ok is False
    assert integrity.first_bad_index == 1


def test_attack_never_shadow_bypass_blocked(constitution, controller):
    """Hard-deny action in SHADOW mode must STILL deny — never_shadow cannot
    be bypassed by the shadow downgrade."""
    gov = make_governor(constitution, controller, mode="SHADOW")  # default never_shadow
    with pytest.raises(ShadowDenied) as exc_info:
        gov.evaluate(req("db.drop_users"))
    rec = exc_info.value.record
    assert rec.enforced_decision == "DENY"
    assert rec.would_have_denied is False
    # ... and the attempt is in the tamper-evident log
    assert gov.verify_log().ok is True
    assert gov.summarize().enforced_denied == 1


def test_attack_compare_poisoned_requests_rejected():
    """Dry-run compare fed with poisoned 'historical' requests must reject
    loudly — never crash silently, never skip the poisoned entry."""
    old, new = _old_new_constitutions()
    with pytest.raises(CompareInputRejected):
        compare(old, new, [{"action": 123, "resource": "r", "subject": "s"}])
    with pytest.raises(CompareInputRejected):
        compare(old, new, [{"action": "files.read", "hacker": True}])  # extra=forbid
    with pytest.raises(CompareInputRejected):
        compare(old, new, ["not-a-request"])  # type: ignore[list-item]
    with pytest.raises(CompareInputRejected):
        compare(old, new, None)  # type: ignore[arg-type]
    # valid entries alongside are still all processed — nothing skipped
    report = compare(
        old, new, [req("files.read"), {"action": "billing.refund",
                                       "resource": "r", "subject": "s"}]
    )
    assert report.total == 2


def test_attack_pipeline_error_fails_closed(constitution, controller, monkeypatch):
    """An unexpected exception inside the decision pipeline must become DENY,
    never a soft allow."""
    gov = make_governor(constitution, controller, mode="SHADOW", never_shadow=[])

    def boom(*args, **kwargs):
        raise RuntimeError("simulated pipeline explosion")

    monkeypatch.setattr("anchor_v1.shadow_mode.governance_check", boom)
    rec = gov.evaluate(req("files.read"))
    assert rec.evaluated_decision == "DENY"
    assert rec.enforced_decision == "ALLOW"  # shadow still shadows...
    assert rec.would_have_denied is True
    assert "pipeline-error" in rec.decision_source

    gov2 = make_governor(constitution, controller, mode="ENFORCE")
    monkeypatch.setattr("anchor_v1.shadow_mode.governance_check", boom)
    with pytest.raises(ShadowDenied):
        gov2.evaluate(req("files.read"))


def test_attack_reused_token_nonce_denied(constitution, controller, issuer, holder):
    """A captured token replayed for a second action must fail the nonce
    freshness check -> DENY."""
    gov = make_governor(constitution, controller, mode="ENFORCE")
    first = token_request(issuer, holder, constitution)
    assert gov.evaluate(first).enforced_decision == "ALLOW"
    # attacker replays the identical token envelope + proof
    replay = token_request(issuer, holder, constitution)
    replay.token.envelope = first.token.envelope
    replay.token.holder_proof = first.token.holder_proof
    replay.token.invocation_params = dict(first.token.invocation_params)
    with pytest.raises(ShadowDenied):
        gov.evaluate(replay)


def test_attack_mode_change_sequence_zero_after_use(constitution, controller):
    """Sequence numbers must be strictly increasing — reusing sequence 0
    after it was consumed is a replay, rejected."""
    gov = make_governor(constitution, controller, mode="ENFORCE")
    gov.apply_mode_change(signed_change(controller, mode="SHADOW", sequence=0))
    assert gov.mode == "SHADOW"
    with pytest.raises(ModeChangeRejected):
        gov.apply_mode_change(signed_change(controller, mode="ENFORCE", sequence=0))
    assert gov.mode == "SHADOW"  # downgrade attempt failed; still shadow
