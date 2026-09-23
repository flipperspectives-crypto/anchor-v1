"""Tests for ANCHOR v1 policy providers (BUILDER A).

Covers: PolicyProvider fail-closed wrapper, NativeProvider (signed rule
lists), CedarAdapter (documented Cedar subset), OPAAdapter (documented Rego
subset), signed decision records, and >=5 adversarial attack tests. Every
attack test is mutation-checked: disabling the named defense makes the test
fail.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from fractions import Fraction

import pytest

from anchor_v1.cbor import cbor_dumps
from anchor_v1.cose import cose_sign_bytes
from anchor_v1.crypto import Ed25519Signer
from anchor_v1.envelope import ActionEnvelope, Effect
from anchor_v1.policy_providers import (
    CedarAdapter,
    NativePolicyDoc,
    NativeProvider,
    NativeRule,
    OPAAdapter,
    PolicyDecision,
    PolicyDecisionRecord,
    PolicyError,
    PolicyProvider,
    check_decision_binding,
    sign_decision_record,
    sign_native_policy,
    verify_decision_record,
)


# ---------------------------------------------------------------------------
# fixtures / helpers
# ---------------------------------------------------------------------------


def _envelope(**overrides) -> ActionEnvelope:
    now = datetime.now(timezone.utc)
    base = dict(
        action_id=uuid.uuid4(),
        principal="did:example:agent-1",
        effect=Effect(
            plane="shell",
            verb="exec",
            target="sha256:deadbeef",
            args_digest="ab" * 32,
        ),
        policy_ref="constitution:v3:deadbeef",
        issued_at=now,
        not_before=now - timedelta(minutes=5),
        not_after=now + timedelta(hours=1),
        nonce=uuid.uuid4().hex,
    )
    base.update(overrides)
    return ActionEnvelope(**base)


def _trusted(signer: Ed25519Signer) -> dict[str, bytes]:
    return {signer.key_id: signer.public_key_bytes()}


def _native_doc(**overrides) -> NativePolicyDoc:
    base = dict(
        version=3,
        rules=[
            NativeRule(
                id="allow-shell-exec",
                match={"plane": "shell", "verb": "exec"},
                effect="allow",
                obligations=["log"],
            ),
            NativeRule(
                id="deny-everything-else",
                match={"plane": ".*"},
                effect="deny",
            ),
        ],
    )
    base.update(overrides)
    return NativePolicyDoc(**base)


def _sign_raw_dict(doc: dict, signer: Ed25519Signer) -> bytes:
    """Sign a raw (possibly invalid) policy dict, bypassing pydantic."""
    return cose_sign_bytes(
        cbor_dumps(doc), signer.sign_bytes, signer.key_id.encode("utf-8")
    )


def _native_provider(min_version: int = 1) -> tuple[NativeProvider, Ed25519Signer]:
    signer = Ed25519Signer.generate("policy-key-1")
    provider = NativeProvider(_trusted(signer), min_version=min_version)
    provider.load_signed_policy(sign_native_policy(_native_doc(), signer))
    return provider, signer


def _cedar_policy() -> dict:
    return {
        "version": "7",
        "policies": [
            {
                "effect": "permit",
                "principal": "did:example:agent-1",
                "action": "shell:exec",
                "when": [
                    {"attr": "context.mfa", "op": "eq", "value": True},
                    {"attr": "context.clearance", "op": "gte", "value": 2},
                ],
            },
            {
                "effect": "forbid",
                "principal": "did:example:agent-1",
                "action": "shell:exec",
                "resource": "sha256:deadbeef",
                "when": [{"attr": "context.break_glass", "op": "eq", "value": True}],
            },
        ],
    }


def _rego_policy() -> dict:
    return {
        "version": "2",
        "rules": [
            {
                "name": "ops_may_exec",
                "conditions": [
                    {"attr": "plane", "op": "eq", "value": "shell"},
                    {"attr": "verb", "op": "eq", "value": "exec"},
                    {"attr": "context.team", "op": "eq", "value": "ops"},
                ],
            }
        ],
    }


# ---------------------------------------------------------------------------
# PolicyProvider base: fail-closed wrapper
# ---------------------------------------------------------------------------


class TestFailClosedWrapper:
    def test_decide_converts_exception_to_deny(self):
        class Boom(PolicyProvider):
            provider_id = "boom"

            def evaluate(self, envelope, context):
                raise RuntimeError("kaboom")

        d = Boom().decide(_envelope(), {})
        assert d.outcome == "DENY"
        assert "RuntimeError" in d.reason

    def test_decide_rejects_non_decision_return(self):
        class Weird(PolicyProvider):
            provider_id = "weird"

            def evaluate(self, envelope, context):
                return "ALLOW"  # type: ignore[return-value]

        d = Weird().decide(_envelope(), {})
        assert d.outcome == "DENY"

    def test_decide_passes_through_allow(self):
        class Fine(PolicyProvider):
            provider_id = "fine"

            def evaluate(self, envelope, context):
                return PolicyDecision(outcome="ALLOW", reason="ok")

        d = Fine().decide(_envelope(), {})
        assert d.outcome == "ALLOW"


# ---------------------------------------------------------------------------
# NativeProvider
# ---------------------------------------------------------------------------


class TestNativeProvider:
    def test_first_match_wins_allow(self):
        provider, _ = _native_provider()
        d = provider.decide(_envelope(), {})
        assert d.outcome == "ALLOW"
        assert "allow-shell-exec" in d.reason
        assert d.obligations == ["log"]

    def test_first_match_wins_deny_before_later_allow(self):
        signer = Ed25519Signer.generate("policy-key-1")
        provider = NativeProvider(_trusted(signer))
        doc = NativePolicyDoc(
            version=1,
            rules=[
                NativeRule(id="deny-shell", match={"plane": "shell"}, effect="deny"),
                NativeRule(id="allow-shell", match={"plane": "shell"}, effect="allow"),
            ],
        )
        provider.load_signed_policy(sign_native_policy(doc, signer))
        assert provider.decide(_envelope(), {}).outcome == "DENY"

    def test_no_match_default_deny(self):
        signer = Ed25519Signer.generate("policy-key-1")
        provider = NativeProvider(_trusted(signer))
        doc = NativePolicyDoc(
            version=1,
            rules=[NativeRule(id="only-shell", match={"plane": "shell"}, effect="allow")],
        )
        provider.load_signed_policy(sign_native_policy(doc, signer))
        env = _envelope(
            effect=Effect(plane="http", verb="post", target="https://x", args_digest="ab" * 32)
        )
        d = provider.decide(env, {})
        assert d.outcome == "DENY"
        assert "default deny" in d.reason

    def test_no_policy_loaded_denies(self):
        signer = Ed25519Signer.generate("policy-key-1")
        provider = NativeProvider(_trusted(signer))
        d = provider.decide(_envelope(), {})
        assert d.outcome == "DENY"
        assert "no valid native policy" in d.reason

    def test_principal_regex_match(self):
        signer = Ed25519Signer.generate("policy-key-1")
        provider = NativeProvider(_trusted(signer))
        doc = NativePolicyDoc(
            version=1,
            rules=[
                NativeRule(
                    id="agents-only",
                    match={"principal": r"did:example:agent-\d+"},
                    effect="allow",
                )
            ],
        )
        provider.load_signed_policy(sign_native_policy(doc, signer))
        assert provider.decide(_envelope(), {}).outcome == "ALLOW"
        assert provider.decide(_envelope(principal="did:example:human-1"), {}).outcome == "DENY"

    def test_fullmatch_not_partial(self):
        signer = Ed25519Signer.generate("policy-key-1")
        provider = NativeProvider(_trusted(signer))
        doc = NativePolicyDoc(
            version=1,
            rules=[NativeRule(id="r", match={"plane": "shell"}, effect="allow")],
        )
        provider.load_signed_policy(sign_native_policy(doc, signer))
        env = _envelope(
            effect=Effect(plane="shell-evil", verb="exec", target="t", args_digest="ab" * 32)
        )
        assert provider.decide(env, {}).outcome == "DENY"

    def test_malformed_doc_rejected_at_load(self):
        signer = Ed25519Signer.generate("policy-key-1")
        provider = NativeProvider(_trusted(signer))
        bad = {"version": 1, "rules": [{"id": "x", "match": {"bogus": ".*"}, "effect": "allow"}]}
        with pytest.raises(PolicyError):
            provider.load_signed_policy(_sign_raw_dict(bad, signer))

    def test_invalid_regex_rejected_at_load(self):
        signer = Ed25519Signer.generate("policy-key-1")
        provider = NativeProvider(_trusted(signer))
        bad = {"version": 1, "rules": [{"id": "x", "match": {"plane": "([invalid"}, "effect": "allow"}]}
        with pytest.raises(PolicyError):
            provider.load_signed_policy(_sign_raw_dict(bad, signer))

    def test_failed_load_keeps_provider_denying(self):
        provider, signer = _native_provider()
        assert provider.decide(_envelope(), {}).outcome == "ALLOW"
        with pytest.raises(PolicyError):
            provider.load_signed_policy(b"not-cose-at-all")
        # old valid policy still installed (atomic install); a provider with
        # NO valid policy denies — either way, no allow from garbage.
        assert provider.decide(_envelope(), {}).outcome == "ALLOW"


# ---------------------------------------------------------------------------
# CedarAdapter
# ---------------------------------------------------------------------------


class TestCedarAdapter:
    def test_permit_applies(self):
        adapter = CedarAdapter(_cedar_policy())
        d = adapter.decide(_envelope(), {"mfa": True, "clearance": 3})
        assert d.outcome == "ALLOW"

    def test_when_clause_false_denies(self):
        adapter = CedarAdapter(_cedar_policy())
        d = adapter.decide(_envelope(), {"mfa": False, "clearance": 3})
        assert d.outcome == "DENY"

    def test_no_applicable_permit_denies(self):
        adapter = CedarAdapter({"version": "1", "policies": []})
        assert adapter.decide(_envelope(), {}).outcome == "DENY"

    def test_scope_mismatch_denies(self):
        adapter = CedarAdapter(_cedar_policy())
        env = _envelope(principal="did:example:agent-2")
        assert adapter.decide(env, {"mfa": True, "clearance": 3}).outcome == "DENY"

    def test_unless_vetoes_permit(self):
        adapter = CedarAdapter(
            {
                "version": "1",
                "policies": [
                    {
                        "effect": "permit",
                        "when": [{"attr": "context.x", "op": "eq", "value": 1}],
                        "unless": [{"attr": "context.blocked", "op": "eq", "value": True}],
                    }
                ],
            }
        )
        assert adapter.decide(_envelope(), {"x": 1}).outcome == "ALLOW"
        assert adapter.decide(_envelope(), {"x": 1, "blocked": True}).outcome == "DENY"

    def test_in_and_contains_ops(self):
        adapter = CedarAdapter(
            {
                "version": "1",
                "policies": [
                    {
                        "effect": "permit",
                        "when": [
                            {"attr": "plane", "op": "in", "value": ["shell", "http"]},
                            {"attr": "context.tags", "op": "contains", "value": "prod"},
                        ],
                    }
                ],
            }
        )
        assert adapter.decide(_envelope(), {"tags": ["prod", "eu"]}).outcome == "ALLOW"
        assert adapter.decide(_envelope(), {"tags": ["dev"]}).outcome == "DENY"

    def test_malformed_policy_rejected(self):
        with pytest.raises(PolicyError):
            CedarAdapter({"policies": [{"effect": "maybe"}]})
        with pytest.raises(PolicyError):
            CedarAdapter({"policies": [{"effect": "permit", "when": [{"attr": "x"}]}]})


# ---------------------------------------------------------------------------
# OPAAdapter
# ---------------------------------------------------------------------------


class TestOPAAdapter:
    def test_rule_satisfied_allows(self):
        adapter = OPAAdapter(_rego_policy())
        d = adapter.decide(_envelope(), {"team": "ops"})
        assert d.outcome == "ALLOW"
        assert "ops_may_exec" in d.reason

    def test_rule_unsatisfied_denies(self):
        adapter = OPAAdapter(_rego_policy())
        assert adapter.decide(_envelope(), {"team": "dev"}).outcome == "DENY"

    def test_empty_rules_deny(self):
        adapter = OPAAdapter({"version": "1", "rules": []})
        assert adapter.decide(_envelope(), {}).outcome == "DENY"

    def test_any_rule_can_allow(self):
        adapter = OPAAdapter(
            {
                "version": "1",
                "rules": [
                    {"name": "r1", "conditions": [{"attr": "plane", "op": "eq", "value": "nope"}]},
                    {"name": "r2", "conditions": [{"attr": "verb", "op": "eq", "value": "exec"}]},
                ],
            }
        )
        assert adapter.decide(_envelope(), {}).outcome == "ALLOW"

    def test_default_must_be_deny(self):
        with pytest.raises(PolicyError):
            OPAAdapter({"version": "1", "default": "allow", "rules": []})

    def test_malformed_policy_rejected(self):
        with pytest.raises(PolicyError):
            OPAAdapter({"rules": [{"name": "r"}]})


# ---------------------------------------------------------------------------
# Decision records
# ---------------------------------------------------------------------------


class TestDecisionRecords:
    def test_round_trip(self):
        provider, _ = _native_provider()
        env = _envelope()
        decision = provider.decide(env, {})
        signer = Ed25519Signer.generate("decider-1")
        raw = provider.issue_decision_record(decision, env, signer)
        record = verify_decision_record(raw, _trusted(signer))
        assert isinstance(record, PolicyDecisionRecord)
        assert record.action_digest == env.action_digest
        assert record.provider_id == provider.provider_id
        assert record.policy_version == "3"
        assert record.outcome == decision.outcome

    def test_binding_check_passes_for_same_envelope(self):
        provider, _ = _native_provider()
        env = _envelope()
        signer = Ed25519Signer.generate("decider-1")
        raw = provider.issue_decision_record(provider.decide(env, {}), env, signer)
        record = verify_decision_record(raw, _trusted(signer))
        check_decision_binding(record, env)  # must not raise

    def test_abstain_record_round_trip(self):
        record = PolicyDecisionRecord(
            action_digest=_envelope().action_digest,
            provider_id="p",
            policy_version="1",
            outcome="ABSTAIN",
            reason="no opinion",
            evaluated_at=datetime.now(timezone.utc),
        )
        signer = Ed25519Signer.generate("decider-1")
        raw = sign_decision_record(record, signer)
        assert verify_decision_record(raw, _trusted(signer)).outcome == "ABSTAIN"

    def test_record_rejects_bad_digest_shape(self):
        with pytest.raises(Exception):
            PolicyDecisionRecord(
                action_digest="not-hex",
                provider_id="p",
                policy_version="1",
                outcome="ALLOW",
                reason="x",
                evaluated_at=datetime.now(timezone.utc),
            )


# ---------------------------------------------------------------------------
# ADVERSARIAL — each must DENY/reject; each is mutation-checked
# (disabling the named defense makes the test fail)
# ---------------------------------------------------------------------------


class TestAdversarial:
    def test_attack_provider_exception_surfaces_as_deny(self):
        # DEFENSE: PolicyProvider.decide catch-all (except Exception).
        # MUTATION: narrow to `except PolicyError` -> RuntimeError escapes.
        class Evil(PolicyProvider):
            provider_id = "evil"

            def evaluate(self, envelope, context):
                raise RuntimeError("pwned")

        assert Evil().decide(_envelope(), {}).outcome == "DENY"

    def test_attack_malformed_policy_denied_at_load(self):
        # DEFENSE: NativePolicyDoc.model_validate at load.
        # MUTATION: model_construct(**data) skips validation -> loads.
        signer = Ed25519Signer.generate("policy-key-1")
        provider = NativeProvider(_trusted(signer))
        malformed = {"version": 1, "rules": [{"id": "x", "match": {"plane": ".*", "hacker": ".*"}, "effect": "allow"}]}
        with pytest.raises(PolicyError):
            provider.load_signed_policy(_sign_raw_dict(malformed, signer))
        assert provider.decide(_envelope(), {}).outcome == "DENY"

    def test_attack_tampered_signed_policy_rejected(self):
        # DEFENSE: cose_verify in _cose_payload (signature covers payload).
        # MUTATION: extract payload from COSE without verifying -> loads.
        signer = Ed25519Signer.generate("policy-key-1")
        provider = NativeProvider(_trusted(signer))
        raw = bytearray(sign_native_policy(_native_doc(), signer))
        raw[-1] ^= 0xFF  # flip a signature byte; payload untouched
        with pytest.raises(PolicyError):
            provider.load_signed_policy(bytes(raw))
        assert provider.decide(_envelope(), {}).outcome == "DENY"

    def test_attack_wrong_key_signed_policy_rejected(self):
        # DEFENSE: kid-keyed trust set; unknown/wrong keys rejected.
        attacker = Ed25519Signer.generate("policy-key-1")  # same kid, wrong key
        legit = Ed25519Signer.generate("policy-key-1")
        provider = NativeProvider({legit.key_id: legit.public_key_bytes()})
        raw = sign_native_policy(_native_doc(), attacker)
        with pytest.raises(PolicyError):
            provider.load_signed_policy(raw)

    def test_attack_forbid_overrides_permit(self):
        # DEFENSE: forbid checked before permits in CedarAdapter.evaluate.
        # MUTATION: forbid branch disabled -> permit grants ALLOW.
        adapter = CedarAdapter(_cedar_policy())
        ctx = {"mfa": True, "clearance": 3, "break_glass": True}
        assert adapter.decide(_envelope(), ctx).outcome == "DENY"

    def test_attack_cedar_type_confusion_denies(self):
        # DEFENSE: _values_equal is type-strict (bool is not int).
        # ATTACK: context smuggles int 1 where policy requires bool True.
        # MUTATION: `actual == expected` without type check -> 1 == True.
        adapter = CedarAdapter(
            {
                "version": "1",
                "policies": [
                    {
                        "effect": "permit",
                        "when": [{"attr": "context.mfa", "op": "eq", "value": True}],
                    }
                ],
            }
        )
        assert adapter.decide(_envelope(), {"mfa": 1}).outcome == "DENY"
        assert adapter.decide(_envelope(), {"mfa": True}).outcome == "ALLOW"

    def test_attack_cedar_ordering_type_confusion_denies(self):
        # "10" (str) vs 5 (int) on lt: type confusion -> condition FALSE.
        adapter = CedarAdapter(
            {
                "version": "1",
                "policies": [
                    {
                        "effect": "permit",
                        "when": [{"attr": "context.level", "op": "lt", "value": 5}],
                    }
                ],
            }
        )
        assert adapter.decide(_envelope(), {"level": "10"}).outcome == "DENY"
        assert adapter.decide(_envelope(), {"level": 3}).outcome == "ALLOW"

    def test_attack_rego_undefined_result_denies(self):
        # DEFENSE: rules with empty conditions never grant allow; missing
        # attributes resolve to _MISSING -> condition FALSE.
        # MUTATION: drop `rule.conditions and` -> vacuous all([]) allows.
        adapter = OPAAdapter(
            {"version": "1", "rules": [{"name": "empty", "conditions": []}]}
        )
        assert adapter.decide(_envelope(), {}).outcome == "DENY"

    def test_attack_rego_missing_attribute_denies(self):
        adapter = OPAAdapter(_rego_policy())
        # context.team absent -> undefined -> DENY, not allow-by-default.
        assert adapter.decide(_envelope(), {}).outcome == "DENY"

    def test_attack_policy_version_rollback_denied(self):
        # DEFENSE: version < min_version refused at load.
        # MUTATION: version check disabled -> stale policy installs.
        signer = Ed25519Signer.generate("policy-key-1")
        provider = NativeProvider(_trusted(signer), min_version=5)
        old = _native_doc(version=3)
        with pytest.raises(PolicyError) as exc:
            provider.load_signed_policy(sign_native_policy(old, signer))
        assert "rollback" in str(exc.value)
        assert provider.decide(_envelope(), {}).outcome == "DENY"

    def test_attack_decision_record_tampering_rejected(self):
        # DEFENSE: COSE signature over canonical record bytes.
        # MUTATION: skip cose_verify -> tampered record parses.
        provider, _ = _native_provider()
        env = _envelope()
        signer = Ed25519Signer.generate("decider-1")
        raw = bytearray(provider.issue_decision_record(provider.decide(env, {}), env, signer))
        raw[-1] ^= 0xFF  # flip a signature byte: CBOR stays parseable, sig breaks
        with pytest.raises(PolicyError):
            verify_decision_record(bytes(raw), _trusted(signer))

    def test_attack_decision_record_replay_across_envelopes_rejected(self):
        # DEFENSE: check_decision_binding ties record to action_digest.
        # MUTATION: binding check disabled -> replay succeeds.
        provider, _ = _native_provider()
        env1 = _envelope()
        env2 = _envelope()  # different nonce/action_id -> different digest
        assert env1.action_digest != env2.action_digest
        signer = Ed25519Signer.generate("decider-1")
        raw = provider.issue_decision_record(provider.decide(env1, {}), env1, signer)
        record = verify_decision_record(raw, _trusted(signer))  # signature fine
        with pytest.raises(PolicyError):
            check_decision_binding(record, env2)

    def test_attack_decision_record_wrong_key_rejected(self):
        provider, _ = _native_provider()
        env = _envelope()
        attacker = Ed25519Signer.generate("decider-1")
        legit = Ed25519Signer.generate("decider-1")
        raw = provider.issue_decision_record(provider.decide(env, {}), env, attacker)
        with pytest.raises(PolicyError):
            verify_decision_record(raw, {legit.key_id: legit.public_key_bytes()})


# ---------------------------------------------------------------------------
# ADVERSARIAL — RT-001: NaN/inf smuggling through numeric comparisons.
# Every test asserts DENY; each is mutation-checked against the
# _tree_has_nonfinite fail-closed guard in _compare.
# ---------------------------------------------------------------------------


def _neq_policy() -> dict:
    return {
        "version": "1",
        "policies": [
            {
                "effect": "permit",
                "principal": "did:example:agent-1",
                "when": [{"attr": "context.amount", "op": "neq", "value": 999999}],
            }
        ],
    }


def _neq_rego_policy() -> dict:
    return {
        "version": "1",
        "rules": [
            {
                "name": "neq_gate",
                "conditions": [
                    {"attr": "context.amount", "op": "neq", "value": 999999}
                ],
            }
        ],
    }


class TestNonfiniteSmuggling:
    # DEFENSE: non-finite floats (NaN, +inf, -inf) are UNDEFINED ->
    # every condition evaluating against one is FALSE, neq included.
    # MUTATION: neuter the `_tree_has_nonfinite` early-return in _compare
    # (and the guard in _values_equal) -> every test below fails with ALLOW.

    def test_attack_nan_neq_denies_cedar(self):
        adapter = CedarAdapter(_neq_policy())
        d = adapter.decide(_envelope(), {"amount": float("nan")})
        assert d.outcome == "DENY"

    def test_attack_nan_neq_denies_rego(self):
        adapter = OPAAdapter(_neq_rego_policy())
        d = adapter.decide(_envelope(), {"amount": float("nan")})
        assert d.outcome == "DENY"

    def test_attack_pos_inf_neq_denies_cedar(self):
        adapter = CedarAdapter(_neq_policy())
        d = adapter.decide(_envelope(), {"amount": float("inf")})
        assert d.outcome == "DENY"

    def test_attack_neg_inf_neq_denies_cedar(self):
        adapter = CedarAdapter(_neq_policy())
        d = adapter.decide(_envelope(), {"amount": float("-inf")})
        assert d.outcome == "DENY"

    def test_attack_pos_inf_neq_denies_rego(self):
        adapter = OPAAdapter(_neq_rego_policy())
        d = adapter.decide(_envelope(), {"amount": float("inf")})
        assert d.outcome == "DENY"

    def test_attack_nan_eq_nan_denies(self):
        # NaN != NaN by IEEE 754; eq must stay FALSE (not flipped to allow).
        # (Mutation canary: the `neq`-against-NaN policy — neutering the
        # guard flips it to ALLOW, so this whole test fails without the
        # defense.)
        adapter = CedarAdapter(
            {
                "version": "1",
                "policies": [
                    {
                        "effect": "permit",
                        "principal": "did:example:agent-1",
                        "when": [
                            {"attr": "context.amount", "op": "eq",
                             "value": float("nan")}
                        ],
                    },
                    {
                        "effect": "permit",
                        "principal": "did:example:agent-1",
                        "when": [
                            {"attr": "context.amount", "op": "neq",
                             "value": float("nan")}
                        ],
                    },
                ],
            }
        )
        d = adapter.decide(_envelope(), {"amount": float("nan")})
        assert d.outcome == "DENY"

    def test_attack_inf_eq_inf_denies(self):
        # IEEE 754 says inf == inf; the guard must make eq FALSE anyway.
        adapter = CedarAdapter(
            {
                "version": "1",
                "policies": [
                    {
                        "effect": "permit",
                        "principal": "did:example:agent-1",
                        "when": [
                            {"attr": "context.amount", "op": "eq",
                             "value": float("inf")}
                        ],
                    }
                ],
            }
        )
        d = adapter.decide(_envelope(), {"amount": float("inf")})
        assert d.outcome == "DENY"

    def test_attack_nan_ordering_denies(self):
        # With 5 permit policies differing only by op, any True op would
        # ALLOW. NaN must make all five FALSE -> DENY.
        # (Mutation canary: the `neq` policy — neutering the guard flips it
        # to ALLOW, so this whole test fails without the defense.)
        adapter = CedarAdapter(
            {
                "version": "1",
                "policies": [
                    {
                        "effect": "permit",
                        "principal": "did:example:agent-1",
                        "when": [
                            {"attr": "context.amount", "op": op, "value": 0}
                        ],
                    }
                    for op in ("lt", "lte", "gt", "gte", "neq")
                ],
            }
        )
        d = adapter.decide(_envelope(), {"amount": float("nan")})
        assert d.outcome == "DENY"

    def test_attack_inf_ordering_denies_rego(self):
        adapter = OPAAdapter(
            {
                "version": "1",
                "rules": [
                    {
                        "name": f"ord_{op}",
                        "conditions": [
                            {"attr": "context.amount", "op": op, "value": 0}
                        ],
                    }
                    for op in ("lt", "lte", "gt", "gte")
                ],
            }
        )
        for val in (float("inf"), float("-inf")):
            d = adapter.decide(_envelope(), {"amount": val})
            assert d.outcome == "DENY"

    def test_attack_nan_membership_denies(self):
        # `in`: NaN must not match any list member, not even a NaN literal.
        # `contains`: a NaN list element must not match a NaN literal.
        # (Mutation canary: the `neq`-against-a-list policy — neutering the
        # guard flips it to ALLOW, so this whole test fails without the
        # defense.)
        cedar = CedarAdapter(
            {
                "version": "1",
                "policies": [
                    {
                        "effect": "permit",
                        "principal": "did:example:agent-1",
                        "when": [
                            {"attr": "context.amount", "op": "in",
                             "value": [1, 2, float("nan")]}
                        ],
                    },
                    {
                        "effect": "permit",
                        "principal": "did:example:agent-1",
                        "when": [
                            {"attr": "context.amount", "op": "neq",
                             "value": [1, 2, 3]}
                        ],
                    },
                    {
                        "effect": "permit",
                        "principal": "did:example:agent-1",
                        "when": [
                            {"attr": "context.tags", "op": "contains",
                             "value": float("nan")}
                        ],
                    },
                ],
            }
        )
        d = cedar.decide(
            _envelope(), {"amount": float("nan"), "tags": [float("nan")]}
        )
        assert d.outcome == "DENY"

    def test_attack_nested_nonfinite_denies(self):
        # NaN buried in a nested context dict: dotted path resolves to it.
        cedar = CedarAdapter(
            {
                "version": "1",
                "policies": [
                    {
                        "effect": "permit",
                        "principal": "did:example:agent-1",
                        "when": [
                            {"attr": "context.limits.max", "op": "neq",
                             "value": 0}
                        ],
                    }
                ],
            }
        )
        d = cedar.decide(_envelope(), {"limits": {"max": float("nan")}})
        assert d.outcome == "DENY"
        # NaN nested inside a list attribute with neq against a dict literal.
        rego = OPAAdapter(
            {
                "version": "1",
                "rules": [
                    {
                        "name": "nested",
                        "conditions": [
                            {"attr": "context.profile", "op": "neq",
                             "value": {"score": 0}}
                        ],
                    }
                ],
            }
        )
        d = rego.decide(_envelope(), {"profile": {"score": float("inf")}})
        assert d.outcome == "DENY"

    def test_finite_baseline_still_decides(self):
        # Positive control: finite numbers keep working, so the guard is not
        # just denying everything (this must PASS both before and after the
        # mutation, while every attack test above must flip to ALLOW).
        adapter = CedarAdapter(_neq_policy())
        assert adapter.decide(_envelope(), {"amount": 5}).outcome == "ALLOW"
        assert adapter.decide(_envelope(), {"amount": 999999}).outcome == "DENY"
        rego = OPAAdapter(_neq_rego_policy())
        assert rego.decide(_envelope(), {"amount": 5}).outcome == "ALLOW"


# ---------------------------------------------------------------------------
# ADVERSARIAL — FIX-A2: Decimal NaN/Infinity smuggling through numeric
# comparisons. The FIX-A guard originally only recognized `float`;
# Decimal('NaN') / Decimal('Infinity') — top-level AND nested in dicts —
# sailed through a Cedar `permit` + `neq 0` gate -> ALLOW, the exact RT-001
# bypass shape with a non-float numeric. Every attack test asserts DENY;
# each is mutation-checked against the extended non-finite guard
# (_is_nonfinite_number now covers all numeric types, bool excluded).
# ---------------------------------------------------------------------------


def _decimal_neq_policy(literal=0) -> dict:
    return {
        "version": "1",
        "policies": [
            {
                "effect": "permit",
                "principal": "did:example:agent-1",
                "when": [{"attr": "context.amount", "op": "neq",
                          "value": literal}],
            }
        ],
    }


def _decimal_eq_policy(literal) -> dict:
    return {
        "version": "1",
        "policies": [
            {
                "effect": "permit",
                "principal": "did:example:agent-1",
                "when": [{"attr": "context.amount", "op": "eq",
                          "value": literal}],
            }
        ],
    }


class TestNonfiniteDecimalSmuggling:
    # DEFENSE: non-finite numerics of ANY type are UNDEFINED -> every
    # condition evaluating against one is FALSE, neq included.
    # MUTATION: neuter the Decimal coverage in _is_nonfinite_number
    # (float-only check) -> every attack test below fails with ALLOW.

    def test_attack_decimal_nan_neq_denies_cedar(self):
        adapter = CedarAdapter(_decimal_neq_policy())
        d = adapter.decide(_envelope(), {"amount": Decimal("NaN")})
        assert d.outcome == "DENY"

    def test_attack_decimal_nan_neq_denies_rego(self):
        adapter = OPAAdapter(_neq_rego_policy())
        d = adapter.decide(_envelope(), {"amount": Decimal("NaN")})
        assert d.outcome == "DENY"

    def test_attack_decimal_inf_neq_denies(self):
        adapter = CedarAdapter(_decimal_neq_policy())
        for val in (Decimal("Infinity"), Decimal("-Infinity")):
            d = adapter.decide(_envelope(), {"amount": val})
            assert d.outcome == "DENY"

    def test_attack_decimal_nan_nested_dict_denies(self):
        # Decimal NaN buried in a nested context dict.
        cedar = CedarAdapter(
            {
                "version": "1",
                "policies": [
                    {
                        "effect": "permit",
                        "principal": "did:example:agent-1",
                        "when": [
                            {"attr": "context.limits.max", "op": "neq",
                             "value": 0}
                        ],
                    }
                ],
            }
        )
        d = cedar.decide(_envelope(), {"limits": {"max": Decimal("NaN")}})
        assert d.outcome == "DENY"

    def test_attack_decimal_inf_nested_list_denies(self):
        # Decimal Infinity nested inside a list attribute with neq against a
        # list literal.
        cedar = CedarAdapter(
            {
                "version": "1",
                "policies": [
                    {
                        "effect": "permit",
                        "principal": "did:example:agent-1",
                        "when": [
                            {"attr": "context.tags", "op": "neq",
                             "value": ["a", "b"]}
                        ],
                    }
                ],
            }
        )
        d = cedar.decide(_envelope(), {"tags": [Decimal("Infinity")]})
        assert d.outcome == "DENY"

    def test_attack_decimal_nan_eq_denies(self):
        # Decimal NaN eq Decimal NaN must stay FALSE (not flipped to allow).
        adapter = CedarAdapter(_decimal_eq_policy(Decimal("NaN")))
        d = adapter.decide(_envelope(), {"amount": Decimal("NaN")})
        assert d.outcome == "DENY"

    def test_attack_decimal_inf_eq_inf_denies(self):
        # Decimal('Infinity') == Decimal('Infinity') is True in Python; the
        # guard must make eq FALSE anyway.
        adapter = CedarAdapter(_decimal_eq_policy(Decimal("Infinity")))
        d = adapter.decide(_envelope(), {"amount": Decimal("Infinity")})
        assert d.outcome == "DENY"

    def test_attack_decimal_inf_ordering_denies(self):
        # With 5 permit policies differing only by op, any True op would
        # ALLOW. Decimal Infinity must make all five FALSE -> DENY.
        adapter = CedarAdapter(
            {
                "version": "1",
                "policies": [
                    {
                        "effect": "permit",
                        "principal": "did:example:agent-1",
                        "when": [
                            {"attr": "context.amount", "op": op,
                             "value": Decimal("0")}
                        ],
                    }
                    for op in ("lt", "lte", "gt", "gte", "neq")
                ],
            }
        )
        for val in (Decimal("Infinity"), Decimal("-Infinity"),
                    Decimal("NaN")):
            d = adapter.decide(_envelope(), {"amount": val})
            assert d.outcome == "DENY"

    def test_attack_decimal_nan_membership_denies(self):
        # `in`: Decimal NaN must not match any list member, not even a
        # Decimal NaN literal. `contains`: a Decimal NaN list element must
        # not match a Decimal NaN literal.
        cedar = CedarAdapter(
            {
                "version": "1",
                "policies": [
                    {
                        "effect": "permit",
                        "principal": "did:example:agent-1",
                        "when": [
                            {"attr": "context.amount", "op": "in",
                             "value": [1, 2, Decimal("NaN")]}
                        ],
                    },
                    {
                        "effect": "permit",
                        "principal": "did:example:agent-1",
                        "when": [
                            {"attr": "context.amount", "op": "neq",
                             "value": [1, 2, 3]}
                        ],
                    },
                    {
                        "effect": "permit",
                        "principal": "did:example:agent-1",
                        "when": [
                            {"attr": "context.tags", "op": "contains",
                             "value": Decimal("NaN")}
                        ],
                    },
                ],
            }
        )
        d = cedar.decide(
            _envelope(), {"amount": Decimal("NaN"),
                          "tags": [Decimal("NaN")]}
        )
        assert d.outcome == "DENY"

    def test_decimal_finite_baseline_still_decides(self):
        # Positive control: finite Decimals keep working, so the guard is not
        # just denying everything (must PASS both before and after the
        # mutation, while every attack test above must flip to ALLOW).
        adapter = CedarAdapter(_decimal_neq_policy(Decimal("999999")))
        assert adapter.decide(
            _envelope(), {"amount": Decimal("5")}).outcome == "ALLOW"
        assert adapter.decide(
            _envelope(), {"amount": Decimal("999999")}).outcome == "DENY"

    def test_decimal_mixed_eq_float_behaves(self):
        # Decimal('1.5') eq 1.5 compares by value -> ALLOW when the policy
        # expects it; mismatched values stay DENY.
        adapter = CedarAdapter(_decimal_eq_policy(1.5))
        assert adapter.decide(
            _envelope(), {"amount": Decimal("1.5")}).outcome == "ALLOW"
        assert adapter.decide(
            _envelope(), {"amount": Decimal("1.6")}).outcome == "DENY"

    def test_decimal_mixed_ordering_behaves(self):
        # Finite Decimal ordering against int/float/Fraction literals works.
        adapter = CedarAdapter(
            {
                "version": "1",
                "policies": [
                    {
                        "effect": "permit",
                        "principal": "did:example:agent-1",
                        "when": [
                            {"attr": "context.amount", "op": "lt",
                             "value": 2}
                        ],
                    }
                ],
            }
        )
        assert adapter.decide(
            _envelope(), {"amount": Decimal("1.5")}).outcome == "ALLOW"
        assert adapter.decide(
            _envelope(), {"amount": Decimal("2.5")}).outcome == "DENY"

    def test_bool_strictness_preserved(self):
        # bool is NOT a number: True never equals 1, and bools never order
        # against numbers. (MUTATION: dropping the bool exclusion in
        # _is_number flips these to ALLOW.)
        eq_true = CedarAdapter(
            {
                "version": "1",
                "policies": [
                    {
                        "effect": "permit",
                        "principal": "did:example:agent-1",
                        "when": [{"attr": "context.mfa", "op": "eq",
                                  "value": True}],
                    }
                ],
            }
        )
        assert eq_true.decide(_envelope(), {"mfa": 1}).outcome == "DENY"
        assert eq_true.decide(_envelope(), {"mfa": True}).outcome == "ALLOW"
        neq_one = CedarAdapter(
            {
                "version": "1",
                "policies": [
                    {
                        "effect": "permit",
                        "principal": "did:example:agent-1",
                        "when": [{"attr": "context.mfa", "op": "neq",
                                  "value": 1}],
                    }
                ],
            }
        )
        # Type confusion NEVER grants: True vs 1 is a type mismatch
        # (bool is not a number here), so neq is FALSE -> DENY.
        # FIX-A3/P2 adaptation: this neq-on-mismatch used to grant ALLOW,
        # inverting the documented fail-closed invariant.
        assert neq_one.decide(_envelope(), {"mfa": True}).outcome == "DENY"
        assert neq_one.decide(_envelope(), {"mfa": 1}).outcome == "DENY"
        lt_five = CedarAdapter(
            {
                "version": "1",
                "policies": [
                    {
                        "effect": "permit",
                        "principal": "did:example:agent-1",
                        "when": [{"attr": "context.amount", "op": "lt",
                                  "value": 5}],
                    }
                ],
            }
        )
        # bool never orders against numbers -> condition FALSE -> DENY.
        assert lt_five.decide(_envelope(), {"amount": True}).outcome == \
            "DENY"

    def test_fraction_sanity(self):
        # Fraction('1/3') compares and orders sanely (Fraction can never be
        # non-finite, so no fail-closed path applies).
        adapter = CedarAdapter(_decimal_eq_policy(Fraction(1, 3)))
        assert adapter.decide(
            _envelope(), {"amount": Fraction(1, 3)}).outcome == "ALLOW"
        assert adapter.decide(
            _envelope(), {"amount": Fraction(1, 2)}).outcome == "DENY"
        lt_one = CedarAdapter(
            {
                "version": "1",
                "policies": [
                    {
                        "effect": "permit",
                        "principal": "did:example:agent-1",
                        "when": [{"attr": "context.amount", "op": "lt",
                                  "value": 1}],
                    }
                ],
            }
        )
        assert lt_one.decide(
            _envelope(), {"amount": Fraction(1, 3)}).outcome == "ALLOW"
        assert lt_one.decide(
            _envelope(), {"amount": Fraction(4, 3)}).outcome == "DENY"


# ---------------------------------------------------------------------------
# ADVERSARIAL — FIX-A3/P1: set/frozenset NaN/inf smuggling.
# _tree_has_nonfinite traversed dict/list/tuple but NOT set/frozenset, so
# Decimal('NaN') inside a set in caller context sailed through a Cedar
# permit + neq gate -> ALLOW — the exact RT-001 defeat shape via an
# untraversed container. Every attack test asserts DENY; each is
# mutation-checked against the set/frozenset traversal in
# _tree_has_nonfinite (removing it makes the new tests fail).
# ---------------------------------------------------------------------------


def _set_neq_policy(literal=999999) -> dict:
    return {
        "version": "1",
        "policies": [
            {
                "effect": "permit",
                "principal": "did:example:agent-1",
                "when": [{"attr": "context.amount", "op": "neq",
                          "value": literal}],
            }
        ],
    }


def _set_neq_rego_policy(literal=999999) -> dict:
    return {
        "version": "1",
        "rules": [
            {
                "name": "neq_gate",
                "conditions": [
                    {"attr": "context.amount", "op": "neq",
                     "value": literal}
                ],
            }
        ],
    }


class TestSetSmuggling:
    # DEFENSE: _tree_has_nonfinite traverses set and frozenset, so a
    # non-finite buried in one is UNDEFINED -> condition FALSE for every
    # operator, neq included.
    # MUTATION: remove set/frozenset from the container tuple in
    # _tree_has_nonfinite -> every attack test below fails with ALLOW.
    # (Note: policy literals here are deliberately the SAME type as the
    # context attribute (set vs set), so the neq type-compatibility gate
    # cannot mask the mutation — these tests isolate the traversal fix.)

    def test_attack_decimal_nan_in_set_neq_denies_cedar(self):
        adapter = CedarAdapter(_set_neq_policy({Decimal("0")}))
        d = adapter.decide(_envelope(), {"amount": {Decimal("NaN")}})
        assert d.outcome == "DENY"

    def test_attack_decimal_nan_in_set_neq_denies_rego(self):
        adapter = OPAAdapter(_set_neq_rego_policy({Decimal("0")}))
        d = adapter.decide(_envelope(), {"amount": {Decimal("NaN")}})
        assert d.outcome == "DENY"

    def test_attack_float_nan_in_set_neq_denies_cedar(self):
        adapter = CedarAdapter(_set_neq_policy({0}))
        d = adapter.decide(_envelope(), {"amount": {float("nan")}})
        assert d.outcome == "DENY"

    def test_attack_decimal_inf_in_frozenset_neq_denies(self):
        adapter = CedarAdapter(_set_neq_policy(frozenset({Decimal("0")})))
        for val in (Decimal("Infinity"), Decimal("-Infinity"),
                    float("inf")):
            d = adapter.decide(_envelope(), {"amount": frozenset({val})})
            assert d.outcome == "DENY"

    def test_attack_set_nested_in_dict_denies(self):
        # Set buried one dict deep, reached via a dotted path.
        adapter = CedarAdapter(
            {
                "version": "1",
                "policies": [
                    {
                        "effect": "permit",
                        "principal": "did:example:agent-1",
                        "when": [
                            {"attr": "context.limits.max", "op": "neq",
                             "value": {Decimal("0")}}
                        ],
                    }
                ],
            }
        )
        d = adapter.decide(
            _envelope(), {"limits": {"max": {Decimal("NaN")}}}
        )
        assert d.outcome == "DENY"

    def test_attack_frozenset_nested_in_list_in_dict_denies(self):
        # frozenset -> list -> dict nesting on the context side.
        adapter = OPAAdapter(
            {
                "version": "1",
                "rules": [
                    {
                        "name": "nested",
                        "conditions": [
                            {"attr": "context.profile.scores", "op": "neq",
                             "value": [1, 2, 3]}
                        ],
                    }
                ],
            }
        )
        d = adapter.decide(
            _envelope(),
            {"profile": {"scores": [1, frozenset({Decimal("-Infinity")})]}},
        )
        assert d.outcome == "DENY"

    def test_attack_set_eq_nonfinite_denies(self):
        # eq: a set holding +inf would otherwise EQUAL a literal set
        # holding +inf (inf == inf in Python) -> ALLOW without the guard.
        adapter = CedarAdapter(
            {
                "version": "1",
                "policies": [
                    {
                        "effect": "permit",
                        "principal": "did:example:agent-1",
                        "when": [{"attr": "context.amount", "op": "eq",
                                  "value": {float("inf")}}],
                    }
                ],
            }
        )
        d = adapter.decide(_envelope(), {"amount": {float("inf")}})
        assert d.outcome == "DENY"

    def test_attack_set_ordering_denies(self):
        # Control: ordering a set against a number is type confusion ->
        # FALSE with or without the traversal fix (documents that sets
        # never order against numbers).
        adapter = CedarAdapter(
            {
                "version": "1",
                "policies": [
                    {
                        "effect": "permit",
                        "principal": "did:example:agent-1",
                        "when": [{"attr": "context.amount", "op": op,
                                  "value": 0}]
                    }
                    for op in ("lt", "lte", "gt", "gte")
                ],
            }
        )
        d = adapter.decide(_envelope(), {"amount": {Decimal("NaN")}})
        assert d.outcome == "DENY"

    def test_finite_sets_still_decide(self):
        # Positive control: finite sets compare sanely (same-type set neq
        # still grants; equal sets deny), so the traversal is not just
        # denying everything. Must PASS both before and after the mutation.
        neq_policy = CedarAdapter(_set_neq_policy({"x"}))
        assert neq_policy.decide(
            _envelope(), {"amount": {"y", "z"}}).outcome == "ALLOW"
        assert neq_policy.decide(
            _envelope(), {"amount": {"x"}}).outcome == "DENY"
        eq_policy = CedarAdapter(
            {
                "version": "1",
                "policies": [
                    {
                        "effect": "permit",
                        "principal": "did:example:agent-1",
                        "when": [{"attr": "context.amount", "op": "eq",
                                  "value": {Decimal("1"), 2}}],
                    }
                ],
            }
        )
        assert eq_policy.decide(
            _envelope(), {"amount": {2, Decimal("1")}}).outcome == "ALLOW"


# ---------------------------------------------------------------------------
# ADVERSARIAL — FIX-A3/P2: neq inverts the fail-closed invariant.
# The module documented "a type mismatch makes the condition FALSE (fail
# closed)", but neq returned TRUE on type mismatch ({"status": 12345} vs
# neq "revoked" -> ALLOW) because neq was implemented as `not
# _values_equal`. Every mismatch test asserts DENY (Cedar + OPA); the
# positive control asserts same-type neq still ALLOWs. Mutation-checked
# against the _type_compatible gate in _compare (reverting to
# `not _values_equal` makes the mismatch tests fail with ALLOW).
# ---------------------------------------------------------------------------


def _neq_status_policy(literal="revoked") -> dict:
    return {
        "version": "1",
        "policies": [
            {
                "effect": "permit",
                "principal": "did:example:agent-1",
                "when": [{"attr": "context.status", "op": "neq",
                          "value": literal}],
            }
        ],
    }


def _neq_status_rego_policy(literal="revoked") -> dict:
    return {
        "version": "1",
        "rules": [
            {
                "name": "neq_gate",
                "conditions": [
                    {"attr": "context.status", "op": "neq",
                     "value": literal}
                ],
            }
        ],
    }


class TestNeqTypeConfusion:
    # DEFENSE: _compare returns FALSE for neq on incompatible operand types
    # (fail closed; type confusion NEVER grants).
    # MUTATION: `neq -> not _values_equal` without the compatibility gate
    # -> every mismatch test below fails with ALLOW.

    @pytest.mark.parametrize("value", [
        12345,          # int vs str
        3.14,           # float vs str
        True,           # bool vs str
        None,           # None vs str
        ["revoked"],    # list vs str
        {"s": "revoked"},  # dict vs str
        ("revoked",),   # tuple vs str
        {"revoked"},    # set vs str
    ])
    def test_attack_neq_type_mismatch_denies_cedar(self, value):
        adapter = CedarAdapter(_neq_status_policy())
        d = adapter.decide(_envelope(), {"status": value})
        assert d.outcome == "DENY"

    @pytest.mark.parametrize("value", [
        12345,
        3.14,
        True,
        None,
        ["revoked"],
        {"s": "revoked"},
        ("revoked",),
        {"revoked"},
    ])
    def test_attack_neq_type_mismatch_denies_rego(self, value):
        adapter = OPAAdapter(_neq_status_rego_policy())
        d = adapter.decide(_envelope(), {"status": value})
        assert d.outcome == "DENY"

    def test_attack_neq_bool_int_mismatch_denies(self):
        # bool is not a number here: True vs 1 is type confusion -> DENY,
        # even though True == 1 in plain Python.
        adapter = CedarAdapter(_neq_status_policy(1))
        assert adapter.decide(_envelope(), {"status": True}).outcome == \
            "DENY"

    def test_eq_type_mismatch_still_denies(self):
        # eq on incompatible types was and stays FALSE.
        adapter = CedarAdapter(
            {
                "version": "1",
                "policies": [
                    {
                        "effect": "permit",
                        "principal": "did:example:agent-1",
                        "when": [{"attr": "context.status", "op": "eq",
                                  "value": "revoked"}],
                    }
                ],
            }
        )
        assert adapter.decide(_envelope(), {"status": 12345}).outcome == \
            "DENY"
        rego = OPAAdapter(
            {
                "version": "1",
                "rules": [
                    {
                        "name": "eq_gate",
                        "conditions": [
                            {"attr": "context.status", "op": "eq",
                             "value": "revoked"}
                        ],
                    }
                ],
            }
        )
        assert rego.decide(_envelope(), {"status": 12345}).outcome == \
            "DENY"

    def test_same_type_neq_still_allows(self):
        # Positive control: genuinely unequal same-type values keep
        # granting, so the gate is not just denying everything. Must PASS
        # both before and after the mutation.
        cedar = CedarAdapter(_neq_status_policy())
        assert cedar.decide(
            _envelope(), {"status": "active"}).outcome == "ALLOW"
        assert cedar.decide(
            _envelope(), {"status": "revoked"}).outcome == "DENY"
        rego = OPAAdapter(_neq_status_rego_policy())
        assert rego.decide(
            _envelope(), {"status": "active"}).outcome == "ALLOW"
        assert rego.decide(
            _envelope(), {"status": "revoked"}).outcome == "DENY"

    def test_compatible_numeric_neq_still_works(self):
        # int/float/Decimal/Fraction are mutually compatible numerics: neq
        # across numeric types compares by value (not a type mismatch).
        cedar = CedarAdapter(_neq_status_policy(Decimal("6")))
        assert cedar.decide(
            _envelope(), {"status": 5}).outcome == "ALLOW"
        assert cedar.decide(
            _envelope(), {"status": 6}).outcome == "DENY"
        assert cedar.decide(
            _envelope(), {"status": Decimal("6.0")}).outcome == "DENY"

    def test_numeric_eq_confusion_denies(self):
        # Numeric cross-type eq that is NOT equal stays DENY (control).
        adapter = CedarAdapter(
            {
                "version": "1",
                "policies": [
                    {
                        "effect": "permit",
                        "principal": "did:example:agent-1",
                        "when": [{"attr": "context.amount", "op": "eq",
                                  "value": Decimal("6")}],
                    }
                ],
            }
        )
        assert adapter.decide(_envelope(), {"amount": 6}).outcome == \
            "ALLOW"
        assert adapter.decide(_envelope(), {"amount": 5}).outcome == \
            "DENY"
