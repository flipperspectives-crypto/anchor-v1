"""ANCHOR v1 — public conformance suite (Wave 6).

Each test in this file is a NAMED GUARANTEE: a public, adversarially-shaped
contract statement that the implementation MUST satisfy. Every guarantee
carries a docstring with exactly these fields::

    GUARANTEE-ID, THREAT, PRECONDITION, ATTACK, INVARIANT, TEST VECTOR,
    EXPECTED RECEIPT

Most guarantees are thin, clearly-labeled WRAPPERS over an existing
adversarial test in ``tests/`` — they re-execute the same attack path and
assert the same fail-closed outcome, and they cite the original test. A few
guarantees (LEDGER-FORK-009) cover attack paths with no existing test and are
written as full attacks here.

Every guarantee in this suite was mutation-checked: neutering the guard on a
throwaway copy of the package makes the corresponding test FAIL. Do not weaken
these tests — a green suite here is the public contract.
"""

from __future__ import annotations

import secrets
import threading
import time
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# ---------------------------------------------------------------------------
# Public API under test
# ---------------------------------------------------------------------------
from anchor_v1.agent_identity import (
    AgentIdentityError,
    _target_matches,
    authorize_capability_claim,
    verify_assertion,
)
from anchor_v1.authority import (
    KIND_MANDATE,
    make_holder_proof,
    mint_child,
    verify_capability,
)
from anchor_v1.crypto import Ed25519Signer
from anchor_v1.delegation_chains import (
    DelegationError,
    DelegationReceipt,
    is_scope_narrower_or_equal,
    receipt_hash,
)
from anchor_v1.identity_adapters import IdentityError, OidcAdapter, SpiffeAdapter
from anchor_v1.policy_providers import CedarAdapter, OPAAdapter
from anchor_v1.scitt import (
    STATEMENT_MINT,
    LocalTransparencyLog,
    SCITTError,
    add_receipt,
    issue_statement,
    verify_transparent_statement,
)
from anchor_v1.state_binding import StateChangedError
from anchor_v1.stepup import (
    CredentialRecord,
    QuorumApproval,
    QuorumError,
    WebAuthnVerifier,
)
from anchor_v1.store import (
    AuthorizationDenied,
    BudgetExceededError,
    CapabilityStore,
    DoubleSpendError,
    StoreError,
)

# ---------------------------------------------------------------------------
# Attack-path helpers imported from the original adversarial test modules.
# The conformance tests are wrappers: they re-execute the SAME attack path
# the original test used. (Each original test is cited in the docstring.)
# ---------------------------------------------------------------------------
from tests.test_authority import (  # noqa: E402
    activate_mandate,
    issue_and_register,
    make_envelope as authority_make_envelope,
)
from tests.test_state_binding import (  # noqa: E402
    ALICE,
    BOB,
    commit_materials,
    do_commit,
)
from tests.test_stepup import (  # noqa: E402
    ORIGIN,
    RP_ID,
    _craft_assertion,
    _ctx as stepup_ctx,
    _digest,
    _software,
)
from tests.test_identity_adapters import (  # noqa: E402
    AUD,
    ISS,
    JWKS,
    RSA_KEY,
    SPIFFE_ID,
    TRUST_DOMAIN,
    _jwt,
    _make_ca,
    _make_svid,
    _pem,
    _rsa_ca_key,
)
from tests.test_agent_identity import (  # noqa: E402
    NOW as AGENT_NOW,
    _nonfinite_assertion_message,
    _registered,
    _self_assertion,
    _signer as agent_signer,
)
from tests.test_policy_providers import _envelope as policy_envelope  # noqa: E402
from tests.test_delegation_chains import (  # noqa: E402
    _build_chain,
    _forge,
    _verify as delegation_verify,
)


# ---------------------------------------------------------------------------
# Module-level index: guarantee ID -> (threat one-liner, covering test name)
# ---------------------------------------------------------------------------
CONFORMANCE_INDEX = {
    "CAP-REPLAY-001": (
        "capability replay / double-spend",
        "test_guarantee_cap_replay_001",
    ),
    "AUTHZ-TOCTOU-007": (
        "prepare/commit time-of-check-time-of-use race",
        "test_guarantee_authz_toctou_007",
    ),
    "BUDGET-RACE-008": (
        "concurrent consumes racing a spend limit",
        "test_guarantee_budget_race_008",
    ),
    "LEDGER-FORK-009": (
        "SCITT transparency log fork",
        "test_guarantee_ledger_fork_009",
    ),
    "POL-NAN-010": (
        "non-finite smuggling in policy context",
        "test_guarantee_pol_nan_010",
    ),
    "POL-NEQTYPE-011": (
        "neq with type-mismatched operands",
        "test_guarantee_pol_neqtype_011",
    ),
    "ID-SVIDPATH-012": (
        "X.509 pathlen-violating SPIFFE chain",
        "test_guarantee_id_svidpath_012",
    ),
    "ID-JWTEXP-013": (
        "non-finite or absurdly-skewed JWT times",
        "test_guarantee_id_jwtexp_013",
    ),
    "STEPUP-XQUORUM-014": (
        "cross-quorum assertion replay",
        "test_guarantee_stepup_xquorum_014",
    ),
    "AGID-REDOS-015": (
        "ReDoS via pathological glob patterns",
        "test_guarantee_agid_redos_015",
    ),
    "AGID-SPENDTYPE-016": (
        "non-finite max_spend in agent assertion",
        "test_guarantee_agid_spendtype_016",
    ),
    "DELEG-DEPTH-017": (
        "delegation chain at depth >= 2 with asor-wimse narrowing",
        "test_guarantee_deleg_depth_017",
    ),
}


def _ed25519_trusted(signer: Ed25519Signer) -> dict:
    return {
        signer.key_id.encode("utf-8"): Ed25519PublicKey.from_public_bytes(
            signer.public_key_bytes()
        )
    }


# ===========================================================================
# CAP-REPLAY-001 — capability replay / double-spend
# ===========================================================================


def test_guarantee_cap_replay_001():
    """GUARANTEE-ID: CAP-REPLAY-001
    THREAT: An attacker replays a consumed one-use execution capability to
        execute the same action twice (double-spend).
    PRECONDITION: A one-use execution capability is issued, registered, and
        legitimately consumed once (state CONSUMED).
    ATTACK: The identical (capability, holder proof, challenge, envelope)
        tuple is submitted to the store a second time.
    INVARIANT: Store consume is atomic: the ISSUED -> CONSUMED flip happens
        at most once per capability.
    TEST VECTOR: Re-executes the attack path of
        tests/test_authority.py::TestStore::test_double_consume_denied.
    EXPECTED RECEIPT: The second consume raises DoubleSpendError; the
        capability remains CONSUMED (no second execution).
    """
    store = CapabilityStore()
    issuer = Ed25519Signer.generate("authority-1")
    holder = Ed25519Signer.generate("holder-1")
    trusted = _ed25519_trusted(issuer)
    challenge = secrets.token_bytes(16)
    env = authority_make_envelope()
    cose, payload = issue_and_register(store, issuer, holder, env.action_digest)
    proof = make_holder_proof(holder, payload.capability_id, challenge)
    kwargs = dict(
        capability_cose=cose,
        holder_proof=proof,
        challenge=challenge,
        trusted_issuers=trusted,
        envelope=env,
    )
    store.consume_capability(**kwargs)  # the honest first consume
    with pytest.raises(DoubleSpendError):
        store.consume_capability(**kwargs)  # the replay
    assert store.capability_state(payload.capability_id) == "CONSUMED"


# ===========================================================================
# AUTHZ-TOCTOU-007 — state changed between prepare and commit
# ===========================================================================


def test_guarantee_authz_toctou_007():
    """GUARANTEE-ID: AUTHZ-TOCTOU-007
    THREAT: An attacker changes governed state between the authorization
        preview (prepare) and the commit, so the commit executes against a
        state the policy never approved.
    PRECONDITION: A valid prepare -> commit bundle exists (signed preview,
        minted capability, holder proof) bound to a state version.
    ATTACK: Another actor writes to governed state after prepare (drains
        Alice's account), then the stale bundle is committed.
    INVARIANT: The commit re-checks the bound state version; any movement
        refuses the commit with zero side effects.
    TEST VECTOR: Re-executes the attack path of
        tests/test_state_binding.py::TestTOCTOU::
        test_state_change_between_prepare_and_commit_denies.
    EXPECTED RECEIPT: Commit raises StateChangedError ("state moved since
        prepare"); the capability stays ISSUED; none of the planned writes
        are applied (read-back shows only the attacker's write).
    """
    authority_signer = Ed25519Signer.generate("authority-1")
    holder_signer = Ed25519Signer.generate("holder-1")
    store = CapabilityStore()
    store.sync_revocations()
    store.write_state({ALICE: 500, BOB: 100})
    trusted = _ed25519_trusted(authority_signer)
    bundle = commit_materials(
        store=store,
        authority_signer=authority_signer,
        holder_signer=holder_signer,
        trusted=trusted,
    )
    store.write_state({ALICE: 50})  # ATTACK: state moves after prepare
    with pytest.raises(StateChangedError, match="state moved since prepare"):
        do_commit(store, trusted, bundle)
    assert store.capability_state(bundle["payload"].capability_id) == "ISSUED"
    assert store.read_state([ALICE, BOB]).values == {ALICE: 50, BOB: 100}


# ===========================================================================
# BUDGET-RACE-008 — concurrent consumes racing a spend limit
# ===========================================================================


def test_guarantee_budget_race_008():
    """GUARANTEE-ID: BUDGET-RACE-008
    THREAT: Two (or more) threads race to mint children against the same
        mandate spend limit; without atomic reservation the budget is
        oversubscribed.
    PRECONDITION: Mandate "m-conf" is ACTIVE with spend_limit=100 and a
        parent capability carrying spend_limit=100.
    ATTACK: N threads simultaneously mint a child (spend_limit=100) and
        debit the mandate, synchronized on a barrier for a true race.
    INVARIANT: The budget debit is a guarded atomic UPDATE: exactly one
        reservation can win; total spend never exceeds the mandate budget.
    TEST VECTOR: Re-executes the attack path of
        tests/test_authority.py::TestAdversarial::test_attack_budget_race
        (here with 8 racing threads instead of 2).
    EXPECTED RECEIPT: Exactly one thread mints; the rest are denied
        (BudgetExceededError/AuthorizationDenied/StoreError); the mandate's
        spend_used is <= 100.
    """
    store = CapabilityStore()
    issuer = Ed25519Signer.generate("authority-1")
    holder = Ed25519Signer.generate("holder-1")
    trusted = _ed25519_trusted(issuer)
    activate_mandate(store, "m-conf", spend_limit=100, actions_limit=10)
    env = authority_make_envelope()
    parent_cose, _ = issue_and_register(
        store,
        issuer,
        holder,
        env.action_digest,
        kind=KIND_MANDATE,
        spend_limit=100,
        spend_asset="USD",
        mandate_id="m-conf",
    )
    n = 8
    barrier = threading.Barrier(n)
    results = []
    lock = threading.Lock()

    def attempt():
        barrier.wait()
        try:
            child_cose = mint_child(
                parent_cose,
                issuer,
                trusted,
                holder_pubkey=holder.public_key_bytes(),
                spend_limit=100,
            )
            child_payload = verify_capability(child_cose, trusted)
            store.debit_mandate_for_child("m-conf", child_payload.spend_limit)
            store.register_capability(child_payload, mandate_id="m-conf")
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
    assert sorted(results).count("minted") == 1, results
    assert sorted(results).count("denied") == n - 1, results
    m = store.get_mandate("m-conf")
    assert m["spend_used"] <= 100, f"budget oversubscribed: {m['spend_used']}"


# ===========================================================================
# LEDGER-FORK-009 — SCITT transparency log fork  (NEW attack, no prior test)
# ===========================================================================


def test_guarantee_ledger_fork_009():
    """GUARANTEE-ID: LEDGER-FORK-009
    THREAT: A forked transparency log reuses the canonical log's identity
        (kid) with a divergent tree and its own key, issuing receipts that
        a victim might accept as canonical.
    PRECONDITION: The verifier pins the canonical log's public key under its
        kid; the statement issuer is trusted.
    ATTACK: A fork log (same kid "scitt-log-1", different key) registers the
        statement, mints a receipt, and the receipt is embedded in the
        transparent statement presented for verification.
    INVARIANT: Receipts are verified against the pinned canonical log key;
        a receipt that does not derive from the canonical log's signed root
        fails, no matter how well-formed it is.
    TEST VECTOR: Full attack (no existing fork test; the closest relatives
        are tests/test_scitt.py::test_receipt_with_wrong_vds_rejected and
        test_receipt_from_untrusted_log_rejected, which cover tampered and
        different-kid receipts, not a fork squatting the canonical kid).
    EXPECTED RECEIPT: verify_transparent_statement raises SCITTError
        ("signature verification failed") against the canonical pin; the
        same receipt verifies under the fork's own key, proving the failure
        is fork detection, not malformed bytes.
    """
    issuer = Ed25519Signer.generate("fork-issuer-1")
    canon_signer = Ed25519Signer.generate("scitt-log-1")  # canonical log key
    fork_signer = Ed25519Signer.generate("scitt-log-1")  # FORK: same kid, new key
    trusted_issuers = _ed25519_trusted(issuer)
    canonical_logs = _ed25519_trusted(canon_signer)
    fork_logs = _ed25519_trusted(fork_signer)

    statement = issue_statement(
        statement_type=STATEMENT_MINT,
        subject="action:abc123",
        claims={"k": "v"},
        issuer=issuer,
    )
    # Control: the canonical log's own receipt verifies.
    canon_log = LocalTransparencyLog(canon_signer)
    control = add_receipt(statement, canon_log.register(statement))
    ok = verify_transparent_statement(control, trusted_issuers, canonical_logs)
    assert ok["receipts"][0]["log_key_id"] == "scitt-log-1"

    # ATTACK: the forked log issues a receipt under the canonical kid.
    fork_log = LocalTransparencyLog(fork_signer)
    evil = add_receipt(statement, fork_log.register(statement))
    with pytest.raises(SCITTError, match="signature verification failed"):
        verify_transparent_statement(evil, trusted_issuers, canonical_logs)

    # The fork's receipt is well-formed under the fork's own key: the
    # rejection above is key-pinned fork detection, not a parse failure.
    fork_view = verify_transparent_statement(evil, trusted_issuers, fork_logs)
    assert fork_view["receipts"][0]["log_key_id"] == "scitt-log-1"


# ===========================================================================
# POL-NAN-010 — non-finite smuggling in policy context
# ===========================================================================


def _nan_neq_cedar_policy(attr: str = "context.amount", value: object = 999999):
    return {
        "version": "1",
        "policies": [
            {
                "effect": "permit",
                "principal": "did:example:agent-1",
                "when": [{"attr": attr, "op": "neq", "value": value}],
            }
        ],
    }


def test_guarantee_pol_nan_010():
    """GUARANTEE-ID: POL-NAN-010
    THREAT: An attacker smuggles NaN/Infinity into policy context. IEEE 754
        makes ``NaN != x`` true for every x, so a single NaN sailing through
        a ``neq`` gate would grant ALLOW on every comparison.
    PRECONDITION: A permit policy gated on ``neq`` (the operator most
        vulnerable to the NaN inversion).
    ATTACK: Four smuggling vectors — float NaN top-level, Decimal NaN
        top-level, Decimal NaN nested inside a dict, float NaN inside a
        frozenset — each fed to the policy decision.
    INVARIANT: Non-finite numerics of ANY type are UNDEFINED: every
        condition evaluating against one is FALSE, ``neq`` included.
    TEST VECTOR: Re-executes the attack paths of
        tests/test_policy_providers.py::TestNonfiniteSmuggling::
        test_attack_nan_neq_denies_cedar,
        test_attack_decimal_nan_neq_denies_cedar,
        test_attack_decimal_nan_nested_dict_denies, and
        TestSetSmuggling::test_attack_float_nan_in_set_neq_denies_cedar.
    EXPECTED RECEIPT: Every vector yields a DENY decision (never ALLOW,
        never an exception).
    """
    vectors = [
        ("float NaN top-level", {"amount": float("nan")},
         _nan_neq_cedar_policy()),
        ("Decimal NaN top-level", {"amount": Decimal("NaN")},
         _nan_neq_cedar_policy()),
        ("Decimal NaN nested in dict", {"limits": {"max": Decimal("NaN")}},
         _nan_neq_cedar_policy("context.limits.max")),
        ("float NaN in frozenset", {"amount": frozenset({float("nan")})},
         _nan_neq_cedar_policy(value=frozenset({0}))),
    ]
    for label, context, policy in vectors:
        d = CedarAdapter(policy).decide(policy_envelope(), context)
        assert d.outcome == "DENY", f"smuggling vector granted: {label}"
        # The OPA provider must agree on the headline vector too.
        if label == "float NaN top-level":
            rego = OPAAdapter(
                {
                    "version": "1",
                    "rules": [
                        {
                            "name": "neq_gate",
                            "conditions": [
                                {"attr": "context.amount", "op": "neq",
                                 "value": 999999}
                            ],
                        }
                    ],
                }
            )
            assert rego.decide(policy_envelope(), context).outcome == "DENY"


# ===========================================================================
# POL-NEQTYPE-011 — neq with type-mismatched operands
# ===========================================================================


def test_guarantee_pol_neqtype_011():
    """GUARANTEE-ID: POL-NEQTYPE-011
    THREAT: An attacker passes a wrongly-typed context value (int where the
        policy expects a string) so that ``neq`` evaluates TRUE on type
        confusion and grants ALLOW.
    PRECONDITION: A permit policy gated on ``neq`` against a string literal.
    ATTACK: Context values of every mismatched type (int, float, bool,
        None, list, dict, tuple, set) plus the bool-vs-int trap (True vs 1).
    INVARIANT: Type confusion makes the condition FALSE for EVERY operator,
        ``neq`` included — type confusion NEVER grants.
    TEST VECTOR: Re-executes the attack paths of
        tests/test_policy_providers.py::TestNeqTypeConfusion::
        test_attack_neq_type_mismatch_denies_cedar,
        test_attack_neq_type_mismatch_denies_rego, and
        test_attack_neq_bool_int_mismatch_denies.
    EXPECTED RECEIPT: Every mismatched vector yields DENY on both the Cedar
        and OPA adapters; the positive control (same-type unequal values)
        still ALLOWs, proving the gate is not just denying everything.
    """
    cedar_policy = {
        "version": "1",
        "policies": [
            {
                "effect": "permit",
                "principal": "did:example:agent-1",
                "when": [{"attr": "context.status", "op": "neq",
                          "value": "revoked"}],
            }
        ],
    }
    rego_policy = {
        "version": "1",
        "rules": [
            {
                "name": "neq_gate",
                "conditions": [{"attr": "context.status", "op": "neq",
                                "value": "revoked"}],
            }
        ],
    }
    mismatches = [12345, 3.14, True, None, ["revoked"],
                  {"s": "revoked"}, ("revoked",), {"revoked"}]
    for value in mismatches:
        d = CedarAdapter(cedar_policy).decide(
            policy_envelope(), {"status": value})
        assert d.outcome == "DENY", f"type confusion granted: {value!r}"
        d = OPAAdapter(rego_policy).decide(policy_envelope(), {"status": value})
        assert d.outcome == "DENY", f"type confusion granted (rego): {value!r}"
    # The bool-vs-int trap: True is not the number 1 here.
    bool_policy = {
        "version": "1",
        "policies": [
            {
                "effect": "permit",
                "principal": "did:example:agent-1",
                "when": [{"attr": "context.status", "op": "neq", "value": 1}],
            }
        ],
    }
    assert CedarAdapter(bool_policy).decide(
        policy_envelope(), {"status": True}).outcome == "DENY"
    # Positive control: genuinely unequal same-type values still grant.
    assert CedarAdapter(cedar_policy).decide(
        policy_envelope(), {"status": "active"}).outcome == "ALLOW"


# ===========================================================================
# ID-SVIDPATH-012 — X.509 pathlen-violating chain
# ===========================================================================


def test_guarantee_id_svidpath_012():
    """GUARANTEE-ID: ID-SVIDPATH-012
    THREAT: An attacker builds a SPIFFE SVID chain that violates an
        intermediate CA's BasicConstraints.path_length budget, smuggling an
        unauthorized sub-CA (and its leaf identities) under a trusted root.
    PRECONDITION: Trust is pinned to the root CA only.
    ATTACK: root(pathlen=1) -> mid(pathlen=0) -> sub-CA (no pathlen) ->
        leaf. The sub-CA beneath mid exceeds mid's path_length=0 budget.
    INVARIANT: RFC 5280 S4.2.1.9 path-length enforcement: an intermediate
        with path_length=N may have at most N CA certificates below it.
    TEST VECTOR: Re-executes the attack path of
        tests/test_identity_adapters.py::
        test_attack_svid_pathlen_zero_intermediate_issues_sub_ca_rejected.
    EXPECTED RECEIPT: authenticate() raises IdentityError (the chain is
        refused; no subject is ever returned).
    """
    root_key = _rsa_ca_key()
    root = _make_ca("CONF Root", root_key, path_length=1)
    mid_key = _rsa_ca_key()
    mid = _make_ca("CONF Mid", mid_key, issuer_cert=root, issuer_key=root_key,
                   path_length=0)
    sub_key = _rsa_ca_key()
    sub = _make_ca("CONF Sub CA", sub_key, issuer_cert=mid, issuer_key=mid_key)
    from cryptography.hazmat.primitives.asymmetric import ec

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = _make_svid(leaf_key, SPIFFE_ID, sub, sub_key)
    adapter = SpiffeAdapter(trust_bundle=[root], trust_domain=TRUST_DOMAIN)
    with pytest.raises(IdentityError):
        adapter.authenticate(_pem(leaf, sub, mid))


# ===========================================================================
# ID-JWTEXP-013 — non-finite or absurdly-skewed JWT times
# ===========================================================================


def test_guarantee_id_jwtexp_013():
    """GUARANTEE-ID: ID-JWTEXP-013
    THREAT: A non-finite ``exp`` (Infinity) compares greater than any clock
        time and never expires; NaN defeats every time comparison; an
        absurdly large ``clock_skew`` silently disables expiry checking.
    PRECONDITION: OIDC adapter with pinned issuer/audience and a signed JWT
        (the token parses fine — JSON round-trips Infinity).
    ATTACK: (a) A token with exp=+Infinity (and one with exp=NaN) is
        presented for authentication. (b) The adapter is constructed with
        clock_skew=inf and with clock_skew=10**18 seconds (> 24h).
    INVARIANT: Time claims must be finite and sane; clock_skew has a hard
        24h upper bound enforced at construction.
    TEST VECTOR: Re-executes the attack paths of
        tests/test_identity_adapters.py::test_attack_oidc_exp_infinity_rejected
        and test_fixb2_clock_skew_above_24h_rejected_at_construction.
    EXPECTED RECEIPT: (a) authenticate() raises IdentityError for exp=inf
        and exp=nan. (b) OidcAdapter construction raises ValueError for
        clock_skew=inf and clock_skew=10**18.
    """
    adapter = OidcAdapter(jwks=JWKS, issuer=ISS, audience=AUD)
    for bad_exp in (float("inf"), float("nan")):
        token = _jwt("RS256", "rsa1", RSA_KEY, exp=bad_exp)
        with pytest.raises(IdentityError):
            adapter.authenticate(token)
    for bad_skew in (float("inf"), 10**18):
        with pytest.raises(ValueError):
            OidcAdapter(jwks=JWKS, issuer=ISS, audience=AUD,
                        clock_skew=bad_skew)


# ===========================================================================
# STEPUP-XQUORUM-014 — cross-quorum assertion replay
# ===========================================================================


def test_guarantee_stepup_xquorum_014():
    """GUARANTEE-ID: STEPUP-XQUORUM-014
    THREAT: An attacker replays a step-up assertion across quorums: the same
        challenge (and even the same assertion bytes) used to satisfy a
        second quorum — before or after the first quorum finalizes.
    PRECONDITION: Quorum A is live (approved, not finalized) over challenge
        C for action A.
    ATTACK: (a) The SAME assertion bytes, minted for action A, are replayed
        into a second quorum for action B through a FRESH verifier while A
        is still live. (b) A second live quorum binds the same challenge C
        and collects its first approval.
    INVARIANT: Challenges are one-time-use process-wide: the in-flight
        registry rejects a second live quorum sharing a challenge, and the
        burned ledger rejects any reuse after finalize.
    TEST VECTOR: Re-executes the attack paths of
        tests/test_stepup.py::TestInFlightChallenges::
        test_cross_action_replay_before_first_finalize_rejected and
        test_two_live_quorums_sharing_challenge_second_approve_raises.
    EXPECTED RECEIPT: Both replays raise QuorumError; the attacker's quorum
        records zero approvals and is not satisfied; the honest quorum is
        unaffected.
    """
    # Half (a): cross-action assertion replay through a fresh verifier.
    signer = Ed25519Signer.generate("approver-a")
    cred = CredentialRecord(key_type="EdDSA", public_key=signer.public_key_bytes())
    challenge = secrets.token_bytes(32)
    digest_a, digest_b = _digest("action-A"), _digest("action-B")
    verifier_a = WebAuthnVerifier(RP_ID, ORIGIN, {"approver-a": cred})
    qa = QuorumApproval(1, 1)
    assertion_for_a = _craft_assertion(
        key_id="approver-a", sign_key=signer, key_type="EdDSA",
        challenge=challenge, sign_count=1,
    )
    qa.approve(verifier_a, challenge, assertion_for_a, digest_a, stepup_ctx())
    verifier_b = WebAuthnVerifier(RP_ID, ORIGIN, {"approver-a": cred})
    qb = QuorumApproval(1, 1)
    with pytest.raises(QuorumError):
        qb.approve(verifier_b, challenge, assertion_for_a, digest_b,
                   stepup_ctx())
    assert qb.approval_count == 0
    assert not qb.is_satisfied()

    # Half (b): second live quorum sharing a challenge.
    challenge2 = secrets.token_bytes(32)
    digest = _digest("action")
    q1 = QuorumApproval(1, 2)
    auth1, _ = _software("a1")
    q1.approve(auth1, challenge2,
               auth1.create_assertion(challenge2, action_digest=digest),
               digest, stepup_ctx())
    q2 = QuorumApproval(1, 1)
    auth2, _ = _software("a2")
    with pytest.raises(QuorumError):
        q2.approve(auth2, challenge2,
                   auth2.create_assertion(challenge2, action_digest=digest),
                   digest, stepup_ctx())
    assert q2.approval_count == 0
    assert not q2.is_satisfied()


# ===========================================================================
# AGID-REDOS-015 — pathological glob patterns
# ===========================================================================


def test_guarantee_agid_redos_015():
    """GUARANTEE-ID: AGID-REDOS-015
    THREAT: An attacker plants a pathological glob (``*a`` x 12) as a
        capability target pattern; a backtracking matcher takes seconds per
        authorization check (ReDoS), stalling the governor.
    PRECONDITION: A target pattern with 12 ``*a`` groups and a 34-char
        target, plus the ``**``-separated variant.
    ATTACK: Match the pathological patterns; also present an overlong
        pattern past the documented length bound.
    INVARIANT: The glob engine is linear-time: pathological patterns
        complete in well under 1s and match correctly; overlong patterns
        fail closed (never match).
    TEST VECTOR: Re-executes the attack paths of
        tests/test_agent_identity.py::
        test_target_matches_pathological_star_groups_completes_fast,
        test_target_matches_pathological_double_star_groups_completes_fast,
        and test_target_matches_rejects_overlong_pattern_fail_closed.
    EXPECTED RECEIPT: Both pathological matches complete in < 1.0s with
        correct results; the overlong pattern returns False (fail closed).
    """
    start = time.perf_counter()
    assert _target_matches("*a" * 12, "a" * 33 + "b") is False
    assert _target_matches("*a" * 12, "a" * 34) is True
    assert _target_matches("**a" * 12, "a" * 33 + "b") is False
    assert _target_matches("**a" * 12, "x/y/" + "a" * 34) is True
    elapsed = time.perf_counter() - start
    assert elapsed < 1.0, f"glob matching took {elapsed:.2f}s (ReDoS?)"
    from anchor_v1.agent_identity import _MAX_TARGET_PATTERN_LEN

    assert _target_matches("a" * (_MAX_TARGET_PATTERN_LEN + 1), "a") is False


# ===========================================================================
# AGID-SPENDTYPE-016 — non-finite max_spend in an assertion
# ===========================================================================


def test_guarantee_agid_spendtype_016():
    """GUARANTEE-ID: AGID-SPENDTYPE-016
    THREAT: An attacker hand-rolls a validly self-signed assertion whose
        max_spend is inf/nan (bypassing model validation via raw JSON),
        hoping a raw ValueError escapes or the assertion authorizes spend.
    PRECONDITION: A hostile assertion with non-finite max_spend, planted
        either directly for verification or inside the registry store.
    ATTACK: (a) verify_assertion() on the hostile message. (b) A hostile
        assertion (pattern "**", max_spend=inf) planted in the registry
        store, then authorize_capability_claim() for an arbitrary target.
    INVARIANT: Non-finite max_spend is dead on arrival: verification raises
        the domain error (never a raw ValueError); authorization fails
        closed (False) and never raises.
    TEST VECTOR: Re-executes the attack paths of
        tests/test_agent_identity.py::
        test_attack_nonfinite_max_spend_verify_raises_agent_identity_error
        and test_attack_nonfinite_assertion_authorize_returns_false_never_raises.
    EXPECTED RECEIPT: (a) AgentIdentityError (not a raw ValueError).
        (b) authorize_capability_claim returns False; the pre-existing good
        assertion still authorizes.
    """
    signer = agent_signer()
    _, message = _nonfinite_assertion_message(signer, float("inf"))
    with pytest.raises(AgentIdentityError):
        verify_assertion(message, now=AGENT_NOW)

    did, good_message = _self_assertion(signer)
    _, bad_message = _nonfinite_assertion_message(
        signer, float("inf"), target_pattern="**"
    )
    registry = _registered(did, good_message)
    registry._entries[did]["assertions"]["planted-evil"] = bad_message
    assert (
        authorize_capability_claim(
            did, "http", "post", "https://anything.example.com/x",
            registry, now=AGENT_NOW,
        )
        is False
    )
    assert authorize_capability_claim(
        did, "shell", "exec", "/bin/ls", registry, now=AGENT_NOW
    )


# ===========================================================================
# DELEG-DEPTH-017 — delegation chain at depth >= 2, asor-wimse narrowing
# ===========================================================================


def test_guarantee_deleg_depth_017():
    """GUARANTEE-ID: DELEG-DEPTH-017
    THREAT: A hostile delegator at hop 2 widens authority beyond what hop 1
        granted (scope escalation / amplification), e.g. adding "shell.exec"
        and "db.drop" to a narrowed hop-1 scope.
    PRECONDITION: An honest depth-2 chain (authority -> hop1 -> hop2) whose
        scopes narrow at every hop per the asor-wimse invariant.
    ATTACK: The real hop-2 holder signs a forged receipt off-protocol that
        keeps the valid hash-link and depth but widens the action set; the
        chain is presented for verification.
    INVARIANT: asor-wimse — authority at any hop MUST be a subset of the
        granting hop — is enforced STRUCTURALLY by verify_chain at every
        hop, not trusted from mint-time checks.
    TEST VECTOR: Re-executes the attack path of
        tests/test_delegation_chains.py::TestAdversarial::
        test_a1_scope_escalation_attack (depth-2 honest chain from
        _build_chain, honest narrowing checked pairwise as well).
    EXPECTED RECEIPT: The honest chain verifies; the widened hop raises
        DelegationError at verification.
    """
    (authority, hop1, hop2, hop3, hop4, attacker,
     registry, trusted, chain) = _build_chain(2)
    # The honest depth-2 chain verifies, and narrowing holds at every hop.
    result = delegation_verify(chain, registry, trusted)
    assert result.depth == 2
    scopes = [DelegationReceipt.model_validate(r.payload).scope
              for r in chain]
    for child_scope, parent_scope in zip(scopes[1:], scopes):
        assert is_scope_narrower_or_equal(child_scope, parent_scope)
    assert result.scope_allows("http.get", "https://api.example.com/v1/status")
    assert not result.scope_allows("shell.exec",
                                   "https://api.example.com/v1/status")

    # ATTACK: hop 2 (signed by the real hop-2 key, off-protocol) widens
    # actions beyond hop 1's grant. Verification must refuse it.
    forged = dict(chain[1].payload)
    forged["delegation_id"] = "del-forged-conf"
    forged["parent_receipt_hash"] = receipt_hash(chain[1])
    forged["delegator"] = hop2.key_id
    forged["delegatee"] = attacker.key_id
    forged["depth"] = 2
    forged["scope"] = dict(forged["scope"])
    forged["scope"]["actions"] = ["http.get", "shell.exec", "db.drop"]
    forged["nonce"] = "cf" * 16
    evil = _forge(forged, hop2)
    with pytest.raises(DelegationError):
        delegation_verify(chain[:2] + [evil], registry, trusted)
