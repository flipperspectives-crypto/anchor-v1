#!/usr/bin/env python3
"""ANCHOR v1 — Wave A adversarial verification harness.

Attacks all three Wave A capabilities end-to-end as a hostile actor would:
  1. multisig_constitution  (ConstitutionalChain, governance_check, adjudicate_receipt)
  2. attenuated_tokens      (issue, attenuate, verify, make_holder_proof)
  3. delegation_chains      (issue_root, delegate, verify_chain)
plus CROSS-MODULE attacks no unit test covers (constitution rotation vs token
pinning, delegation scope vs token scope, PoP proof binding, unknown-hash
receipts).

Report shape mirrors the v0 harness: per-scenario PASS/FAIL/FLAG, summary
table, totals. Exit 0 only if 0 FAIL (FLAGs allowed but listed).

Local only. No network calls. Read-only against module sources.
Run:  cd ~/workspace/anchor-v1 && <venv>/bin/python adversarial_harness.py
"""

from __future__ import annotations

import base64
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from anchor_v1.crypto import Ed25519Signer
from anchor_v1.models import SignedEnvelope
from anchor_v1.multisig_constitution import (
    ActionReceipt,
    Constitution,
    ConstitutionalChain,
    ConstitutionRejected,
    ConstitutionSignature,
    TrustConfig,
    TrustedSigner,
    adjudicate_receipt,
    content_hash_of,
    governance_check,
    resolve_governed_version,
    sign_constitution,
)
from anchor_v1.attenuated_tokens import (
    AuthorizationError,
    Caveat,
    attenuate,
    issue,
    make_holder_proof,
    token_hash,
    verify,
)
from anchor_v1.delegation_chains import (
    DelegationError,
    DelegationReceipt,
    DelegationScope,
    delegate,
    is_sub_prefix,
    issue_root,
    receipt_hash,
    verify_chain,
)

# ---------------------------------------------------------------------------
# report plumbing (v0 shape)
# ---------------------------------------------------------------------------

RESULTS: list[dict] = []


def record(name: str, capability: str, method: str, expected: str,
           observed: str, verdict: str) -> None:
    assert verdict in ("PASS", "FAIL", "FLAG"), verdict
    RESULTS.append({"attack": name, "capability": capability, "method": method,
                    "expected": expected, "observed": observed, "verdict": verdict})
    print(f"[{verdict}] {name}: {observed}", flush=True)


FAIL_CLOSED = (AuthorizationError, DelegationError, ConstitutionRejected, ValueError)


def expect_deny(name, capability, method, expected, fn, *args, **kwargs):
    """Attack should fail closed: raise a fail-closed exception. Silent allow
    (no exception) or an ambiguous non-fail-closed exception => FAIL/FLAG."""
    try:
        result = fn(*args, **kwargs)
    except FAIL_CLOSED as e:
        record(name, capability, method, expected,
               f"denied fail-closed: {type(e).__name__}: {e}", "PASS")
    except Exception as e:  # ambiguous failure mode — needs human eyes
        record(name, capability, method, expected,
               f"AMBIGUOUS failure ({type(e).__name__}: {e}) — not a clean deny", "FLAG")
    else:
        record(name, capability, method, expected,
               f"ATTACK SUCCEEDED — silent allow, returned {type(result).__name__}", "FAIL")


def expect_decision_deny(name, capability, method, fn, *args, **kwargs):
    """Attack should resolve to a DENY decision (adjudication layer)."""
    try:
        decision = fn(*args, **kwargs)
    except FAIL_CLOSED as e:
        record(name, capability, method, "DENY (or fail-closed exception)",
               f"denied fail-closed: {type(e).__name__}: {e}", "PASS")
    except Exception as e:
        record(name, capability, method, "DENY (or fail-closed exception)",
               f"AMBIGUOUS failure ({type(e).__name__}: {e})", "FLAG")
    else:
        record(name, capability, method, "DENY (or fail-closed exception)",
               f"decision={decision}",
               "PASS" if decision == "DENY" else "FAIL")


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------

NOW = datetime.now(timezone.utc)
NB = NOW - timedelta(hours=1)
EA = NOW + timedelta(hours=1)


def b64(pub: bytes) -> str:
    return base64.b64encode(pub).decode()


# constitution governors (m-of-n)
gov1 = Ed25519Signer.generate("gov-1")
gov2 = Ed25519Signer.generate("gov-2")
gov3 = Ed25519Signer.generate("gov-3")
gov4 = Ed25519Signer.generate("gov-4")
rogue_gov = Ed25519Signer.generate("rogue-gov")


def trust_of(*signers, quorum):
    return TrustConfig(
        signers=[TrustedSigner(key_id=s.key_id, public_key=b64(s.public_key_bytes()))
                 for s in signers],
        quorum=quorum,
    )


BOOTSTRAP = trust_of(gov1, gov2, gov3, quorum=2)


def signed_constitution(constitution: Constitution, *signers) -> "SignedConstitution":
    from anchor_v1.multisig_constitution import SignedConstitution
    return SignedConstitution(
        constitution=constitution,
        signatures=[sign_constitution(s, constitution) for s in signers],
    )


def fresh_chain():
    """Genesis v1: hard-deny vault.selfdestruct, approval-required funds.transfer."""
    v1 = Constitution(
        version=1,
        previous_hash=None,
        hard_deny_actions=["vault.selfdestruct"],
        approval_required_actions=["funds.transfer"],
        authority_epoch=1,
    )
    return ConstitutionalChain(signed_constitution(v1, gov1, gov2), BOOTSTRAP)


# token issuers / holders
issuer = Ed25519Signer.generate("issuer-1")
rogue_issuer = Ed25519Signer.generate("rogue-issuer")
compromised = Ed25519Signer.generate("issuer-2")  # valid key, later revoked
alice = Ed25519Signer.generate("alice")
bob = Ed25519Signer.generate("bob")
mallory = Ed25519Signer.generate("mallory")

TRUSTED_ISSUERS = {issuer.key_id: issuer.public_key_bytes()}


def holder_b64(signer) -> str:
    return b64(signer.public_key_bytes())


def mint_token(signing_key=None, subject=None, action="vault.read",
               resource="workspace://vault/acct-1",
               invocation_params=None, caveats=None, audience="gateway-a",
               constitution_hash="chash-v1", not_before=NB, expires_at=EA,
               capability_id="cap-test-1"):
    sk = signing_key or issuer
    return issue(
        sk,
        capability_id=capability_id,
        subject=subject or holder_b64(alice),
        audience=audience,
        action=action,
        resource=resource,
        invocation_params=invocation_params or {"op": "read", "id": 1},
        caveats=caveats,
        not_before=not_before,
        expires_at=expires_at,
        constitution_hash=constitution_hash,
    )


def token_payload(env):
    from anchor_v1.attenuated_tokens import AttenuatedTokenPayload
    return AttenuatedTokenPayload.model_validate(env.payload)


def proof_for(signer, env):
    p = token_payload(env)
    return make_holder_proof(signer, p.capability_id, p.nonce)


def resign_token(signing_key, payload_dict) -> SignedEnvelope:
    """Off-protocol mint: hostile party with a signing key crafts a payload."""
    return signing_key.sign_payload(payload_dict)


# delegation fixtures
auth = Ed25519Signer.generate("authority")
drogue = Ed25519Signer.generate("deleg-rogue")

KEY_REGISTRY = {
    auth.key_id: auth.public_key_bytes(),
    alice.key_id: b64(alice.public_key_bytes()),
    bob.key_id: bob.public_key_bytes(),
    mallory.key_id: mallory.public_key_bytes(),
    drogue.key_id: drogue.public_key_bytes(),
}
TRUSTED_AUTH = {auth.key_id}

ROOT_SCOPE = DelegationScope(actions=["read", "write"],
                             resource_prefixes=["workspace://scope"], caveats=[])
CHASH = "constitution-hash-v1"


def mint_root(delegatee="alice", scope=None, signer=None, max_depth=5):
    return issue_root(
        root_mandate_hash="mandate-001",
        constitution_hash=CHASH,
        delegatee_key_id=delegatee,
        scope=scope or ROOT_SCOPE,
        max_depth=max_depth,
        not_before=NB,
        expires_at=EA,
        authority_signer=signer or auth,
    )


def craft_receipt(*, delegator, delegatee, scope, depth, max_depth,
                  parent_hash, signer, not_before=NB, expires_at=EA,
                  constitution_hash=CHASH, root_mandate_hash="mandate-001"):
    """Off-protocol receipt: hostile delegator holding a real key mints
    whatever payload they want. verify_chain() must still catch it."""
    import secrets
    r = DelegationReceipt(
        delegation_id=f"del-{secrets.token_hex(8)}",
        parent_receipt_hash=parent_hash,
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
    return signer.sign_payload(r.model_dump(mode="json"))


# ===========================================================================
# CAPABILITY 1 — multisig constitutions
# ===========================================================================

# C01: version skip
chain = fresh_chain()
v3 = Constitution(version=3, previous_hash=chain.head.content_hash, authority_epoch=1)
expect_deny("C01 version-skip", "multisig-constitution",
            "append v3 directly over v1 (skip v2)",
            "ConstitutionRejected (sequential versions only)",
            chain.append, signed_constitution(v3, gov1, gov2))

# C02: constitution replay (duplicate content hash)
chain = fresh_chain()
expect_deny("C02 constitution-replay", "multisig-constitution",
            "re-append the genesis version (duplicate hash = downgrade)",
            "ConstitutionRejected (duplicate content hash)",
            chain.append, chain.head)

# C03: quorum not met
chain = fresh_chain()
v2 = Constitution(version=2, previous_hash=chain.head.content_hash, authority_epoch=1)
expect_deny("C03 quorum-not-met", "multisig-constitution",
            "v2 signed by only 1 of required 2 governors",
            "ConstitutionRejected (quorum not met)",
            chain.append, signed_constitution(v2, gov1))

# C04: signature by non-trusted key
chain = fresh_chain()
expect_deny("C04 untrusted-signer", "multisig-constitution",
            "v2 signed by gov-1 + rogue-gov (not in trusted set)",
            "ConstitutionRejected (signer not in active set)",
            chain.append, signed_constitution(v2, gov1, rogue_gov))

# C05: duplicate signature from the same key_id counted twice
chain = fresh_chain()
sc = signed_constitution(v2, gov1, gov2)
dup = sc.model_copy(update={"signatures": [sc.signatures[0], sc.signatures[0]]})
expect_deny("C05 duplicate-signature", "multisig-constitution",
            "v2 carrying gov-1's signature twice",
            "ConstitutionRejected (duplicate signature)",
            chain.append, dup)

# C06: forked previous_hash (points nowhere on this chain)
chain = fresh_chain()
v2_fork = Constitution(version=2, previous_hash="00" * 32, authority_epoch=1)
expect_deny("C06 forked-previous-hash", "multisig-constitution",
            "v2.previous_hash = 00..00, signed by quorum",
            "ConstitutionRejected (supersedes chain broken)",
            chain.append, signed_constitution(v2_fork, gov1, gov2))

# C07: rotation is forward-only — removed signer cannot authorize new versions
chain = fresh_chain()
v2_rot = Constitution(version=2, previous_hash=chain.head.content_hash,
                      authority_epoch=1,
                      proposed_trust=trust_of(gov2, gov3, gov4, quorum=2))
chain.append(signed_constitution(v2_rot, gov1, gov2))  # old quorum rotates forward
v3_old = Constitution(version=3, previous_hash=chain.head.content_hash, authority_epoch=1)
expect_deny("C07 rotation-forward-only", "multisig-constitution",
            "v3 signed by gov-1+gov-2 after gov-1 was rotated out at v2",
            "ConstitutionRejected (gov-1 not in active set)",
            chain.append, signed_constitution(v3_old, gov1, gov2))
# control: the NEW set can still advance the chain
try:
    chain.append(signed_constitution(v3_old, gov2, gov3))
    record("C07b rotation-control", "multisig-constitution",
           "v3 signed by gov-2+gov-3 (active set) after rotation",
           "chain must keep advancing under the new set",
           "advanced to v3", "PASS")
except FAIL_CLOSED as e:
    record("C07b rotation-control", "multisig-constitution",
           "v3 signed by gov-2+gov-3 (active set) after rotation",
           "chain must keep advancing under the new set",
           f"legit rotation BLOCKED: {e}", "FAIL")

# C08: DENY precedence (hard-deny beats approval-required)
chain = fresh_chain()
c_precedence = Constitution(version=1, previous_hash=None,
                            hard_deny_actions=["funds.transfer"],
                            approval_required_actions=["funds.*"],
                            authority_epoch=1)
d = governance_check("funds.transfer", "ledger", c_precedence)
record("C08 deny-precedence", "multisig-constitution",
       "constitution both requires-approval and hard-denies funds.transfer",
       "DENY must win (fail-closed ordering)",
       f"decision={d}", "PASS" if d == "DENY" else "FAIL")

# C09: receipt pinned to a constitution that never existed
chain = fresh_chain()
ghost = ActionReceipt(action="vault.read", resource="x",
                      constitution_hash="ff" * 32)
expect_decision_deny("C09 receipt-ghost-hash", "multisig-constitution",
                     "adjudicate receipt whose constitution_hash matches no version",
                     adjudicate_receipt, chain, ghost)

# C10: approval-required path still resolves (not silently allowed)
chain = fresh_chain()
d = governance_check("funds.transfer", "ledger", chain.head.constitution)
record("C10 approval-required", "multisig-constitution",
       "governance_check on approval-gated action",
       "APPROVAL_REQUIRED (never a silent ALLOW)",
       f"decision={d}", "PASS" if d == "APPROVAL_REQUIRED" else "FAIL")

# ===========================================================================
# CAPABILITY 2 — attenuated tokens
# ============================================================================

INV = {"op": "read", "id": 1}

# T01: forged issuer signature
env = mint_token()
forged = SignedEnvelope(key_id=env.key_id, payload=env.payload,
                        signature=("A" if env.signature[0] != "A" else "B") + env.signature[1:])
expect_deny("T01 forged-issuer-signature", "attenuated-tokens",
            "flip a char in the issuer signature",
            "AuthorizationError (issuer signature verification failed)",
            verify, forged, holder_proof=proof_for(alice, env),
            invocation_params=INV, now=NOW, trusted_issuers=TRUSTED_ISSUERS)

# T02: token signed by an untrusted (rogue) issuer key
env = mint_token(signing_key=rogue_issuer, capability_id="cap-rogue-1")
expect_deny("T02 untrusted-issuer", "attenuated-tokens",
            "token signed by rogue-issuer (not in trusted_issuers)",
            "AuthorizationError (untrusted issuer)",
            verify, env, holder_proof=proof_for(alice, env),
            invocation_params=INV, now=NOW, trusted_issuers=TRUSTED_ISSUERS)

# T03: nonce replay
env = mint_token(capability_id="cap-replay-1")
used = set()
verify(env, holder_proof=proof_for(alice, env), invocation_params=INV,
       now=NOW, trusted_issuers=TRUSTED_ISSUERS, used_nonces=used)
used.add(token_payload(env).nonce)
expect_deny("T03 nonce-replay", "attenuated-tokens",
            "verify the same token twice with a used-nonce set",
            "AuthorizationError (nonce already consumed)",
            verify, env, holder_proof=proof_for(alice, env),
            invocation_params=INV, now=NOW, trusted_issuers=TRUSTED_ISSUERS,
            used_nonces=used)

# T04: holder PoP proof replayed from one token against a DIFFERENT token
# (same holder bound to both, so only the (nonce || capability_id) binding
# can catch it — this is the sharp proof-binding test)
env_a = mint_token(capability_id="cap-A-1")
env_b = mint_token(capability_id="cap-B-1")  # also bound to alice
proof_a = proof_for(alice, env_a)  # binds (nonceA || cap-A-1)
expect_deny("T04 pop-proof-replay", "attenuated-tokens",
            "present token B with the PoP proof minted for token A",
            "AuthorizationError (proof binds the wrong capability/nonce)",
            verify, env_b, holder_proof=proof_a,
            invocation_params=INV, now=NOW, trusted_issuers=TRUSTED_ISSUERS)

# T05: PoP signed by the wrong holder key
env = mint_token(capability_id="cap-holder-1")
wrong_proof = make_holder_proof(mallory, "cap-holder-1", token_payload(env).nonce)
expect_deny("T05 wrong-holder-proof", "attenuated-tokens",
            "PoP for the right (capability_id, nonce) but signed by mallory, not alice",
            "AuthorizationError (holder proof-of-possession failed)",
            verify, env, holder_proof=wrong_proof,
            invocation_params=INV, now=NOW, trusted_issuers=TRUSTED_ISSUERS)

# T06: invocation parameter binding
env = mint_token(capability_id="cap-params-1")
expect_deny("T06 invocation-binding", "attenuated-tokens",
            "verify with altered invocation parameters",
            "AuthorizationError (parameters do not match token binding)",
            verify, env, holder_proof=proof_for(alice, env),
            invocation_params={"op": "read", "id": 2}, now=NOW,
            trusted_issuers=TRUSTED_ISSUERS)

# T07: attenuate() must refuse resource widening at mint time
parent = mint_token(capability_id="cap-narrow-1", resource="workspace://scope/docs")
expect_deny("T07 attenuate-resource-widen", "attenuated-tokens",
            "attenuate() to resource workspace://other",
            "ValueError (resource must narrow)",
            attenuate, parent, issuer, [], holder_b64(bob),
            resource="workspace://other")

# T08: off-protocol widened child — subsumption must catch it at verify time
parent = mint_token(capability_id="cap-spend-1",
                    caveats=[Caveat(kind="spend_limit",
                                    params={"max_amount": 100, "currency": "USD"})])
pp = token_payload(parent)
wide_dict = parent.payload.copy()
wide_caveats = [dict(c) for c in wide_dict["caveats"]]
wide_caveats[0] = {"kind": "spend_limit",
                   "params": {"max_amount": 10000, "currency": "USD"}}
wide_dict.update({
    "capability_id": "cap-wide-1",
    "subject": holder_b64(mallory),
    "caveats": wide_caveats,
    "nonce": "wide-nonce-001",
    "parent_token_hash": token_hash(parent),
})
wide_env = resign_token(issuer, wide_dict)  # hostile mint with a VALID issuer key
wide_proof = make_holder_proof(mallory, "cap-wide-1", "wide-nonce-001")
expect_deny("T08 subsumption-widened-child", "attenuated-tokens",
            "child re-signed by the real issuer key but spend_limit 100 -> 10000",
            "AuthorizationError (subsumption violated: spend_limit widened)",
            verify, wide_env, holder_proof=wide_proof,
            invocation_params=INV, now=NOW, trusted_issuers=TRUSTED_ISSUERS,
            parent_envelope=parent,
            holder_proofs={pp.capability_id: proof_for(alice, parent)},
            context={"spend_amount": 50, "spend_currency": "USD"})

# T09: off-protocol child that DROPS a parent caveat
drop_dict = parent.payload.copy()
drop_dict.update({
    "capability_id": "cap-drop-1",
    "subject": holder_b64(mallory),
    "caveats": [],
    "nonce": "drop-nonce-001",
    "parent_token_hash": token_hash(parent),
})
drop_env = resign_token(issuer, drop_dict)
drop_proof = make_holder_proof(mallory, "cap-drop-1", "drop-nonce-001")
expect_deny("T09 subsumption-caveat-drop", "attenuated-tokens",
            "child silently drops the parent's spend_limit caveat",
            "AuthorizationError (parent caveat dropped)",
            verify, drop_env, holder_proof=drop_proof,
            invocation_params=INV, now=NOW, trusted_issuers=TRUSTED_ISSUERS,
            parent_envelope=parent,
            holder_proofs={pp.capability_id: proof_for(alice, parent)})

# T10: widening then re-narrowing — subsumption must catch the middle hop
# honest parent -> WIDE child (compromised-but-valid signer) -> narrowed grandchild
grandchild = attenuate(wide_env, issuer,
                       [Caveat(kind="expiry",
                               params={"expires_at": (NOW + timedelta(minutes=30)).isoformat()})],
                       holder_b64(bob), capability_id="cap-grand-1")
gp = token_payload(grandchild)
chain_map = {token_hash(parent): parent, token_hash(wide_env): wide_env}
proofs = {pp.capability_id: proof_for(alice, parent),
          "cap-wide-1": wide_proof}
expect_deny("T10 widen-then-renarrow", "attenuated-tokens",
            "wide middle token re-narrowed by a later hop; full-chain verify",
            "AuthorizationError at the widened hop (subsumption is per-hop)",
            verify, grandchild, holder_proof=make_holder_proof(bob, gp.capability_id, gp.nonce),
            invocation_params=INV, now=NOW, trusted_issuers=TRUSTED_ISSUERS,
            chain=chain_map, holder_proofs=proofs,
            context={"spend_amount": 50, "spend_currency": "USD"})

# T11: unknown caveat kind — unevaluable => deny
unk_dict = mint_token(capability_id="cap-unk-1").payload.copy()
unk_dict["caveats"] = [{"kind": "teleport", "params": {"where": "anywhere"}}]
unk_env = resign_token(issuer, unk_dict)
expect_deny("T11 unknown-caveat-kind", "attenuated-tokens",
            "token carrying caveat kind 'teleport' (no evaluator)",
            "AuthorizationError (unevaluable caveat kind)",
            verify, unk_env, holder_proof=proof_for(alice, unk_env),
            invocation_params=INV, now=NOW, trusted_issuers=TRUSTED_ISSUERS)

# T12: expired token
env = mint_token(capability_id="cap-exp-1", not_before=NOW - timedelta(hours=2),
                 expires_at=NOW - timedelta(hours=1))
expect_deny("T12 expired-token", "attenuated-tokens",
            "verify after expires_at",
            "AuthorizationError (token expired)",
            verify, env, holder_proof=proof_for(alice, env),
            invocation_params=INV, now=NOW, trusted_issuers=TRUSTED_ISSUERS)

# T13: single-use token without a replay-tracking set
env = mint_token(capability_id="cap-once-1",
                 caveats=[Caveat(kind="uses", params={"max_uses": 1})])
expect_deny("T13 single-use-no-nonceset", "attenuated-tokens",
            "max_uses=1 token verified with used_nonces=None",
            "AuthorizationError (single-use requires a used-nonce set)",
            verify, env, holder_proof=proof_for(alice, env),
            invocation_params=INV, now=NOW, trusted_issuers=TRUSTED_ISSUERS,
            used_nonces=None)

# T14: audience binding is NOT enforced by verify() — caller-side gap
env = mint_token(capability_id="cap-aud-1", audience="gateway-a")
try:
    payload = verify(env, holder_proof=proof_for(alice, env),
                     invocation_params=INV, now=NOW,
                     trusted_issuers=TRUSTED_ISSUERS)
    record("T14 audience-not-enforced", "attenuated-tokens",
           "verify() a gateway-a token with no audience check available",
           "verify() takes no expected-audience parameter",
           f"returned payload (audience={payload.audience!r}); enforcement point "
           "MUST check payload.audience itself — gap if it doesn't", "FLAG")
except FAIL_CLOSED as e:
    record("T14 audience-not-enforced", "attenuated-tokens",
           "verify() a gateway-a token with no audience check available",
           "verify() takes no expected-audience parameter",
           f"unexpected deny: {e}", "FLAG")

# T15: chain deeper than MAX_CHAIN_DEPTH
from anchor_v1.attenuated_tokens import MAX_CHAIN_DEPTH
deep_envs = [mint_token(capability_id="cap-deep-0")]
# NOTE: attenuate() enforces subsumption pairwise per caveat kind at mint, so a
# second expiry caveat can never be tighter than the first — honest deep chains
# carry the single expiry and narrow via empty caveat lists afterwards.
deep_envs.append(attenuate(
    deep_envs[-1], issuer,
    [Caveat(kind="expiry",
            params={"expires_at": (EA - timedelta(minutes=30)).isoformat()})],
    holder_b64(alice), capability_id="cap-deep-1"))
for i in range(2, MAX_CHAIN_DEPTH + 2):  # one hop past the limit
    deep_envs.append(attenuate(deep_envs[-1], issuer, [], holder_b64(alice),
                               capability_id=f"cap-deep-{i}"))
deep_chain = {token_hash(e): e for e in deep_envs[:-1]}
deep_proofs = {}
for e in deep_envs[:-1]:
    p = token_payload(e)
    deep_proofs[p.capability_id] = make_holder_proof(alice, p.capability_id, p.nonce)
leaf = deep_envs[-1]
lp = token_payload(leaf)
expect_deny("T15 chain-too-deep", "attenuated-tokens",
            f"verify a {len(deep_envs)}-token chain (limit {MAX_CHAIN_DEPTH})",
            "AuthorizationError (delegation chain too deep)",
            verify, leaf, holder_proof=make_holder_proof(alice, lp.capability_id, lp.nonce),
            invocation_params=INV, now=NOW, trusted_issuers=TRUSTED_ISSUERS,
            chain=deep_chain, holder_proofs=deep_proofs)

# T16: compromised-but-valid signer, key REVOKED from the trust set
bad_env = mint_token(signing_key=compromised, capability_id="cap-comp-1",
                     subject=holder_b64(mallory))
bad_proof = make_holder_proof(mallory, "cap-comp-1", token_payload(bad_env).nonce)
expect_deny("T16 revoked-issuer", "attenuated-tokens",
            "token minted by compromised key AFTER its removal from trusted_issuers",
            "AuthorizationError (untrusted issuer)",
            verify, bad_env, holder_proof=bad_proof,
            invocation_params=INV, now=NOW, trusted_issuers=TRUSTED_ISSUERS)

# T17: compromised-but-valid signer, key STILL trusted — out-of-band revocation gap
try:
    verify(bad_env, holder_proof=bad_proof, invocation_params=INV, now=NOW,
           trusted_issuers={**TRUSTED_ISSUERS,
                            compromised.key_id: compromised.public_key_bytes()})
    record("T17 compromised-still-trusted", "attenuated-tokens",
           "verify a compromised-key token while the key is still trusted",
           "token layer has no in-band revocation list; rotation lives in the "
           "constitution layer",
           "VERIFIED (expected — key is trusted; revocation is out-of-band). "
           "Human review: confirm incident response rotates compromised issuer keys.", "FLAG")
except FAIL_CLOSED as e:
    record("T17 compromised-still-trusted", "attenuated-tokens",
           "verify a compromised-key token while the key is still trusted",
           "token layer has no in-band revocation list",
           f"unexpected deny: {e}", "FLAG")

# ===========================================================================
# CAPABILITY 3 — delegation chains
# ============================================================================

# D01: custody break — receipt signed by someone other than the delegatee
root = mint_root(delegatee=alice.key_id)
r1 = delegate(root, bob.key_id,
              DelegationScope(actions=["read"], resource_prefixes=["workspace://scope"],
                              caveats=[]),
              signer=alice)
evil_r2 = craft_receipt(delegator=bob.key_id, delegatee=mallory.key_id,
                        scope=DelegationScope(actions=["read"],
                                              resource_prefixes=["workspace://scope"],
                                              caveats=[]),
                        depth=2, max_depth=5, parent_hash=receipt_hash(r1),
                        signer=mallory)  # mallory signs, but bob is the holder
expect_deny("D01 custody-break", "delegation-chains",
            "hop 2 signed by mallory instead of the holder bob",
            "DelegationError (custody break)",
            verify_chain, [root, r1, evil_r2],
            trusted_authority_keys=TRUSTED_AUTH, key_registry=KEY_REGISTRY, now=NOW)

# D02: off-protocol action widening by a hostile (but legitimate) holder
evil_wide = craft_receipt(
    delegator=bob.key_id, delegatee=mallory.key_id,
    scope=DelegationScope(actions=["read", "write", "delete"],
                          resource_prefixes=["workspace://scope"], caveats=[]),
    depth=2, max_depth=5, parent_hash=receipt_hash(r1), signer=bob)
expect_deny("D02 action-widening", "delegation-chains",
            "holder bob crafts a child granting delete (never granted)",
            "DelegationError (narrowing invariant violated)",
            verify_chain, [root, r1, evil_wide],
            trusted_authority_keys=TRUSTED_AUTH, key_registry=KEY_REGISTRY, now=NOW)

# D03: resource prefix sibling escape
evil_prefix = craft_receipt(
    delegator=bob.key_id, delegatee=mallory.key_id,
    scope=DelegationScope(actions=["read"],
                          resource_prefixes=["workspace://scope-evil"], caveats=[]),
    depth=2, max_depth=5, parent_hash=receipt_hash(r1), signer=bob)
expect_deny("D03 prefix-sibling-escape", "delegation-chains",
            "child prefix workspace://scope-evil under parent workspace://scope",
            "DelegationError (boundary-aware prefix rejection)",
            verify_chain, [root, r1, evil_prefix],
            trusted_authority_keys=TRUSTED_AUTH, key_registry=KEY_REGISTRY, now=NOW)

# D04: hash-link tamper — re-signed mid receipt breaks the child's link
r1_prime_dict = r1.payload.copy()
r1_prime_dict["nonce"] = "tampered-nonce-xyz"
r1_prime = alice.sign_payload(r1_prime_dict)
r2 = delegate(r1, mallory.key_id,
              DelegationScope(actions=["read"],
                              resource_prefixes=["workspace://scope/docs"], caveats=[]),
              signer=bob)
expect_deny("D04 hash-link-tamper", "delegation-chains",
            "mid receipt re-signed with a new nonce; child link now dangling",
            "DelegationError (parent_receipt_hash does not match)",
            verify_chain, [root, r1_prime, r2],
            trusted_authority_keys=TRUSTED_AUTH, key_registry=KEY_REGISTRY, now=NOW)

# D05: root signed by an untrusted key
evil_root = mint_root(signer=drogue)
expect_deny("D05 untrusted-root", "delegation-chains",
            "root receipt signed by deleg-rogue (not a trusted authority)",
            "DelegationError (root not signed by trusted authority)",
            verify_chain, [evil_root],
            trusted_authority_keys=TRUSTED_AUTH, key_registry=KEY_REGISTRY, now=NOW)

# D06: depth claim inconsistent with position
evil_depth = craft_receipt(
    delegator=bob.key_id, delegatee=mallory.key_id,
    scope=DelegationScope(actions=["read"],
                          resource_prefixes=["workspace://scope"], caveats=[]),
    depth=7, max_depth=9, parent_hash=receipt_hash(r1), signer=bob)
expect_deny("D06 depth-skip", "delegation-chains",
            "hop at position 1 claims depth 7",
            "DelegationError (depth != position)",
            verify_chain, [root, r1, evil_depth],
            trusted_authority_keys=TRUSTED_AUTH, key_registry=KEY_REGISTRY, now=NOW)

# D07: cycle — same receipt presented twice
expect_deny("D07 receipt-cycle", "delegation-chains",
            "chain [root, r1, r1] (receipt appears twice)",
            "DelegationError (receipt appears twice)",
            verify_chain, [root, r1, r1],
            trusted_authority_keys=TRUSTED_AUTH, key_registry=KEY_REGISTRY, now=NOW)

# D08: expired middle receipt
stale_r1 = delegate(root, bob.key_id,
                    DelegationScope(actions=["read"],
                                    resource_prefixes=["workspace://scope"], caveats=[]),
                    signer=alice,
                    not_before=NB,
                    expires_at=NOW - timedelta(minutes=30))
expect_deny("D08 expired-mid-receipt", "delegation-chains",
            "middle receipt expired an hour ago, leaf still fresh",
            "DelegationError (receipt not valid at now)",
            verify_chain, [root, stale_r1],
            trusted_authority_keys=TRUSTED_AUTH, key_registry=KEY_REGISTRY, now=NOW)

# D09: constitution_hash changed mid-chain
evil_const = craft_receipt(
    delegator=bob.key_id, delegatee=mallory.key_id,
    scope=DelegationScope(actions=["read"],
                          resource_prefixes=["workspace://scope"], caveats=[]),
    depth=2, max_depth=5, parent_hash=receipt_hash(r1), signer=bob,
    constitution_hash="ab" * 32)
expect_deny("D09 constitution-changed-midchain", "delegation-chains",
            "hop 2 switches constitution_hash to ab..ab",
            "DelegationError (constitution_hash changed mid-chain)",
            verify_chain, [root, r1, evil_const],
            trusted_authority_keys=TRUSTED_AUTH, key_registry=KEY_REGISTRY, now=NOW)

# D10: parent caveats dropped off-protocol
root_cav = mint_root(scope=DelegationScope(actions=["read"],
                                           resource_prefixes=["workspace://scope"],
                                           caveats=["no-exfil"]))
r1_cav = delegate(root_cav, bob.key_id,
                  DelegationScope(actions=["read"],
                                  resource_prefixes=["workspace://scope"],
                                  caveats=["no-exfil"]),
                  signer=alice)
evil_drop = craft_receipt(
    delegator=bob.key_id, delegatee=mallory.key_id,
    scope=DelegationScope(actions=["read"],
                          resource_prefixes=["workspace://scope"], caveats=[]),
    depth=2, max_depth=5, parent_hash=receipt_hash(r1_cav), signer=bob)
expect_deny("D10 caveats-dropped", "delegation-chains",
            "holder bob crafts a child dropping the no-exfil caveat",
            "DelegationError (parent caveats dropped)",
            verify_chain, [root_cav, r1_cav, evil_drop],
            trusted_authority_keys=TRUSTED_AUTH, key_registry=KEY_REGISTRY, now=NOW)

# ===========================================================================
# CROSS-MODULE attacks
# ===========================================================================

def _resolve_pubkey_bytes(key_id: str) -> bytes:
    raw = KEY_REGISTRY[key_id]
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw)
    return base64.b64decode(raw, validate=True)


def _token_holder_pubkey(subject: str) -> bytes:
    try:
        raw = base64.b64decode(subject, validate=True)
    except Exception:
        raw = b""
    if len(raw) == 32:
        return raw
    raise AuthorizationError("subject holder key is not resolvable")


def enforce_delegated_token(token_env, holder_proof, invocation_params,
                            chain_envs, used_nonces=None, context=None):
    """Reference enforcement point composing all three capabilities:
    verify the delegation chain, verify the token, then cross-bind them —
    token (action, resource, holder) must sit inside the leaf scope and the
    leaf delegatee. Anything off => AuthorizationError. Fail closed."""
    verified = verify_chain(chain_envs, trusted_authority_keys=TRUSTED_AUTH,
                            key_registry=KEY_REGISTRY, now=NOW)
    payload = verify(token_env, holder_proof=holder_proof,
                     invocation_params=invocation_params, now=NOW,
                     trusted_issuers=TRUSTED_ISSUERS, used_nonces=used_nonces,
                     context=context)
    leaf_delegatee = verified.delegatee_chain[-1]
    if _token_holder_pubkey(payload.subject) != _resolve_pubkey_bytes(leaf_delegatee):
        raise AuthorizationError(
            "cross-binding: token holder is not the delegation leaf delegatee")
    if payload.action not in verified.effective_scope.actions:
        raise AuthorizationError(
            "cross-binding: token action exceeds delegation leaf scope")
    if not any(is_sub_prefix(payload.resource, p)
               for p in verified.effective_scope.resource_prefixes):
        raise AuthorizationError(
            "cross-binding: token resource exceeds delegation leaf scope")
    return payload


# X01: token minted under v1; constitution superseded by v2 — pinning must hold
chain = fresh_chain()
chash_v1 = chain.head.content_hash
tok_v1 = mint_token(capability_id="cap-pin-1", constitution_hash=chash_v1)
v2_deny = Constitution(version=2, previous_hash=chash_v1,
                       hard_deny_actions=["vault.read"], authority_epoch=1)
chain.append(signed_constitution(v2_deny, gov1, gov2))  # supersede: v2 denies vault.read
pinned = resolve_governed_version(
    [chain.versions[0], chain.versions[1]], BOOTSTRAP,
    token_payload(tok_v1).constitution_hash)
record("X01 supersede-pinning", "cross-module",
       "token minted under v1; v2 supersedes and denies the action; resolve pin",
       "must pin to v1 (the governing version), never silently to head v2",
       f"pinned version={pinned.constitution.version if pinned else None}",
       "PASS" if pinned is not None and pinned.constitution.version == 1 else "FAIL")

# X02: delegation leaf scope used to mint a WIDER capability token
leaf_scope = DelegationScope(actions=["read"],
                             resource_prefixes=["workspace://scope"], caveats=[])
root_x = mint_root(delegatee=alice.key_id,
                   scope=DelegationScope(actions=["read", "write"],
                                         resource_prefixes=["workspace://scope"],
                                         caveats=[]))
r1_x = delegate(root_x, bob.key_id, leaf_scope, signer=alice)  # alice->bob, depth 1
wide_tok = mint_token(capability_id="cap-xwide-1", subject=holder_b64(bob),
                      action="write", resource="workspace://other")
expect_deny("X02 token-wider-than-leaf", "cross-module",
            "chain verifies, but token grants write@workspace://other beyond leaf scope",
            "AuthorizationError at the enforcement cross-binding (fail closed)",
            enforce_delegated_token, wide_tok, proof_for(bob, wide_tok), INV,
            [root_x, r1_x])

# X03: chain receipt with valid signatures, constitution_hash of a ghost constitution
ghost_receipt = craft_receipt(
    delegator=alice.key_id, delegatee=bob.key_id,
    scope=DelegationScope(actions=["read"],
                          resource_prefixes=["workspace://scope"], caveats=[]),
    depth=1, max_depth=5, parent_hash=receipt_hash(root_x), signer=alice,
    constitution_hash="cc" * 32)  # never existed
try:
    verified = verify_chain([root_x, ghost_receipt],
                            trusted_authority_keys=TRUSTED_AUTH,
                            key_registry=KEY_REGISTRY, now=NOW)
    chain_for_adj = ConstitutionalChain(
        signed_constitution(Constitution(version=1, previous_hash=None,
                                        authority_epoch=1), gov1, gov2), BOOTSTRAP)
    expect_decision_deny("X03 ghost-constitution-receipt", "cross-module",
                         "valid-signature receipt pinned to constitution cc..cc (never existed)",
                         adjudicate_receipt, chain_for_adj,
                         ActionReceipt(action="vault.read", resource="x",
                                       constitution_hash=verified.constitution_hash))
except FAIL_CLOSED as e:
    record("X03 ghost-constitution-receipt", "cross-module",
           "valid-signature receipt pinned to constitution cc..cc (never existed)",
           "chain verify itself must also fail closed on unknown constitution",
           f"verify_chain denied: {e}", "PASS")

# X04: token holder vs delegation leaf delegatee mismatch (leaf is bob)
tok_mallory = mint_token(capability_id="cap-xholder-1", subject=holder_b64(mallory),
                         action="read", resource="workspace://scope/docs")
expect_deny("X04 holder-leaf-mismatch", "cross-module",
            "mallory's token presented against a chain whose leaf delegatee is bob",
            "AuthorizationError (holder != leaf delegatee)",
            enforce_delegated_token, tok_mallory,
            proof_for(mallory, tok_mallory), INV, [root_x, r1_x])

# X05: control — legitimate composition (token inside leaf scope) must ALLOW
tok_ok = mint_token(capability_id="cap-xok-1", subject=holder_b64(bob),
                    action="read", resource="workspace://scope/docs")
try:
    enforce_delegated_token(tok_ok, proof_for(bob, tok_ok), INV, [root_x, r1_x])
    record("X05 legit-composition", "cross-module",
           "token (read, workspace://scope/docs, holder bob) inside leaf scope",
           "enforcement must ALLOW the legitimate composition",
           "allowed", "PASS")
except FAIL_CLOSED as e:
    record("X05 legit-composition", "cross-module",
           "token (read, workspace://scope/docs, holder alice) inside leaf scope",
           "enforcement must ALLOW the legitimate composition",
           f"legitimate composition DENIED: {e}", "FAIL")

# X06: attenuation chain under a rotated constitution — end-to-end pinning
chain = fresh_chain()
ch_v1 = chain.head.content_hash
tok_chain = mint_token(capability_id="cap-rot-1", constitution_hash=ch_v1)
child_rot = attenuate(tok_chain, issuer,
                      [Caveat(kind="resource_prefix",
                              params={"prefix": "workspace://vault/acct-1"})],
                      holder_b64(bob), capability_id="cap-rot-2")
v2b = Constitution(version=2, previous_hash=ch_v1,
                   hard_deny_actions=["vault.read"], authority_epoch=1)
chain.append(signed_constitution(v2b, gov1, gov2))
pinned2 = resolve_governed_version([chain.versions[0], chain.versions[1]],
                                   BOOTSTRAP, token_payload(tok_chain).constitution_hash)
try:
    assert pinned2 is not None and pinned2.constitution.version == 1
    cp = token_payload(child_rot)
    gp_proof = make_holder_proof(bob, cp.capability_id, cp.nonce)
    verified_child = verify(child_rot, holder_proof=gp_proof,
                            invocation_params=INV, now=NOW,
                            trusted_issuers=TRUSTED_ISSUERS,
                            parent_envelope=tok_chain,
                            holder_proofs={"cap-rot-1": proof_for(alice, tok_chain)},
                            context={"resource": "workspace://vault/acct-1"})
    dec = governance_check(verified_child.action, verified_child.resource,
                           pinned2.constitution)
    record("X06 rotation-end-to-end", "cross-module",
           "attenuated child verified after v2 rotation; governance under pinned v1",
           "child verifies; v1 still governs it (ALLOW); v2 must NOT retro-apply",
           f"child verified, pinned v={pinned2.constitution.version}, decision={dec}",
           "PASS" if dec == "ALLOW" else "FAIL")
except FAIL_CLOSED as e:
    record("X06 rotation-end-to-end", "cross-module",
           "attenuated child verified after v2 rotation; governance under pinned v1",
           "child verifies; v1 still governs it (ALLOW); v2 must NOT retro-apply",
           f"denied: {e}", "FAIL")

# X07: receipt claims the NEW (denying) constitution hash for a v1-era action
chain = fresh_chain()
ch1 = chain.head.content_hash
v2c = Constitution(version=2, previous_hash=ch1,
                   hard_deny_actions=["vault.read"], authority_epoch=1)
chain.append(signed_constitution(v2c, gov1, gov2))
sneaky = ActionReceipt(action="vault.read", resource="x",
                       constitution_hash=chain.head.content_hash)
expect_decision_deny("X07 receipt-claims-denying-version", "cross-module",
                     "receipt pins vault.read to v2 (which hard-denies it)",
                     adjudicate_receipt, chain, sneaky)

# ---------------------------------------------------------------------------
# summary
# ---------------------------------------------------------------------------

print("\n==== SUMMARY ====")
name_w = max(len(r["attack"]) for r in RESULTS)
print(f"{'ATTACK':<{name_w}}  {'CAPABILITY':<22} {'VERDICT'}")
for r in RESULTS:
    print(f"{r['attack']:<{name_w}}  {r['capability']:<22} {r['verdict']}")
passes = sum(1 for r in RESULTS if r["verdict"] == "PASS")
fails = sum(1 for r in RESULTS if r["verdict"] == "FAIL")
flags = sum(1 for r in RESULTS if r["verdict"] == "FLAG")
print(f"\nPASS={passes} FAIL={fails} FLAG={flags} TOTAL={len(RESULTS)}")
if flags:
    print("Flags needing human review:")
    for r in RESULTS:
        if r["verdict"] == "FLAG":
            print(f"  - {r['attack']}: {r['observed']}")
print()
print(json.dumps(RESULTS, indent=1))
sys.exit(1 if fails else 0)
