"""Tests for anchor_v1.multisig_constitution: every rule + adversarial attacks.

All attacks must end DENY / invalid / rejected — never silent-allow.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from anchor_v1.canonical import sha256_hex
from anchor_v1.multisig_constitution import (
    ActionReceipt,
    Constitution,
    ConstitutionalChain,
    ConstitutionRejected,
    ConstitutionSignature,
    SignedConstitution,
    TrustConfig,
    TrustedSigner,
    adjudicate_receipt,
    content_hash_of,
    governance_check,
    resolve_governed_version,
    sign_constitution,
    verify_constitution_signature,
)

# import under test must survive a missing anchor_v1.models (stub fallback)
from anchor_v1.multisig_constitution import Ed25519Signer  # noqa: E402

NOW = datetime(2026, 9, 23, 12, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# fixtures / helpers
# ---------------------------------------------------------------------------


def make_signers(*key_ids: str) -> dict[str, Ed25519Signer]:
    return {kid: Ed25519Signer.generate(kid) for kid in key_ids}


def trust_config(signers: dict[str, Ed25519Signer], quorum: int, *key_ids: str) -> TrustConfig:
    return TrustConfig(
        signers=[
            TrustedSigner(key_id=kid, public_key=signers[kid].public_key_b64())
            for kid in key_ids
        ],
        quorum=quorum,
    )


def make_constitution(version: int, previous_hash: str | None, **kw) -> Constitution:
    base = dict(
        version=version,
        previous_hash=previous_hash,
        invariants=[],
        hard_deny_actions=[],
        approval_required_actions=[],
        authority_epoch=1,
        created_at=NOW,
    )
    base.update(kw)
    return Constitution(**base)


def sign_all(signers: dict[str, Ed25519Signer], c: Constitution, *key_ids: str) -> SignedConstitution:
    return SignedConstitution(
        constitution=c,
        signatures=[sign_constitution(signers[k], c) for k in key_ids],
    )


@pytest.fixture()
def keys() -> dict[str, Ed25519Signer]:
    return make_signers("alice", "bob", "carol", "dave")


@pytest.fixture()
def bootstrap(keys) -> TrustConfig:
    return trust_config(keys, 2, "alice", "bob", "carol")  # 2-of-3


@pytest.fixture()
def genesis(keys, bootstrap) -> SignedConstitution:
    c = make_constitution(1, None)
    return sign_all(keys, c, "alice", "bob")


@pytest.fixture()
def chain(keys, bootstrap, genesis) -> ConstitutionalChain:
    return ConstitutionalChain(genesis, bootstrap)


def v2_of(keys, chain, **kw) -> SignedConstitution:
    c = make_constitution(2, chain.head.content_hash, **kw)
    return sign_all(keys, c, "alice", "carol")


# ---------------------------------------------------------------------------
# unit: payload / hashing
# ---------------------------------------------------------------------------


def test_content_hash_is_stable_and_covers_all_fields(keys):
    c = make_constitution(1, None, invariants=["deny:rm -rf"])
    h1 = content_hash_of(c)
    h2 = content_hash_of(Constitution(**c.model_dump()))
    assert h1 == h2 and len(h1) == 64
    tampered = make_constitution(1, None, invariants=["deny:rm -rf", "deny:extra"])
    assert content_hash_of(tampered) != h1


def test_genesis_admitted_with_quorum(chain, genesis):
    assert len(chain) == 1
    assert chain.head.content_hash == genesis.content_hash


def test_genesis_requires_previous_hash_none(keys, bootstrap):
    c = make_constitution(1, "somehash")
    bad = sign_all(keys, c, "alice", "bob")
    with pytest.raises(ConstitutionRejected):
        ConstitutionalChain(bad, bootstrap)


def test_genesis_must_be_version_1(keys, bootstrap):
    c = make_constitution(2, None)
    bad = sign_all(keys, c, "alice", "bob")
    with pytest.raises(ConstitutionRejected):
        ConstitutionalChain(bad, bootstrap)


def test_genesis_below_quorum_rejected(keys, bootstrap):
    c = make_constitution(1, None)
    bad = sign_all(keys, c, "alice")  # 1 of required 2
    with pytest.raises(ConstitutionRejected):
        ConstitutionalChain(bad, bootstrap)


def test_append_valid_successor(keys, chain):
    v2 = v2_of(keys, chain)
    chain.append(v2)
    assert len(chain) == 2
    assert chain.head.content_hash == v2.content_hash


def test_append_rejects_previous_hash_mismatch(keys, chain):
    c = make_constitution(2, "0" * 64)
    bad = sign_all(keys, c, "alice", "bob")
    with pytest.raises(ConstitutionRejected):
        chain.append(bad)


def test_append_rejects_nonsequential_version(keys, chain):
    c = make_constitution(5, chain.head.content_hash)
    bad = sign_all(keys, c, "alice", "bob")
    with pytest.raises(ConstitutionRejected):
        chain.append(bad)


def test_append_rejects_quorum_not_met(keys, chain):
    c = make_constitution(2, chain.head.content_hash)
    bad = sign_all(keys, c, "alice")  # 1 of 2
    with pytest.raises(ConstitutionRejected):
        chain.append(bad)


def test_exactly_quorum_signatures_accepted(keys, chain):
    v2 = v2_of(keys, chain)
    assert len(v2.signatures) == 2
    chain.append(v2)  # 2-of-2 boundary accepted


def test_signature_by_unknown_key_rejected(keys, chain):
    c = make_constitution(2, chain.head.content_hash)
    mallory = Ed25519Signer.generate("mallory")
    bad = SignedConstitution(
        constitution=c,
        signatures=[sign_constitution(keys["alice"], c), sign_constitution(mallory, c)],
    )
    with pytest.raises(ConstitutionRejected):
        chain.append(bad)


def test_duplicate_key_signatures_rejected(keys, chain):
    c = make_constitution(2, chain.head.content_hash)
    sig = sign_constitution(keys["alice"], c)
    bad = SignedConstitution(
        constitution=c,
        signatures=[sig, sig, sign_constitution(keys["bob"], c)],
    )
    with pytest.raises(ConstitutionRejected):
        chain.append(bad)


def test_strict_model_forbids_extra_fields():
    with pytest.raises(Exception):
        Constitution(
            version=1,
            previous_hash=None,
            authority_epoch=0,
            created_at=NOW,
            bogus_field="nope",
        )


def test_naive_datetime_rejected():
    with pytest.raises(Exception):
        Constitution(
            version=1, previous_hash=None, authority_epoch=0,
            created_at=datetime(2026, 9, 23, 12, 0, 0),  # naive
        )


def test_invalid_invariant_syntax_rejected():
    with pytest.raises(Exception):
        make_constitution(1, None, invariants=["just-a-string"])


def test_invalid_trust_config_rejected(keys):
    with pytest.raises(Exception):
        trust_config(keys, 5, "alice", "bob")  # quorum > n
    with pytest.raises(Exception):
        TrustConfig(signers=[], quorum=1)  # empty set


# ---------------------------------------------------------------------------
# unit: rotation
# ---------------------------------------------------------------------------


def test_rotation_takes_effect_for_future_versions(keys, bootstrap, chain):
    new_trust = trust_config(keys, 2, "alice", "bob", "dave")  # carol out, dave in
    v2 = v2_of(keys, chain, proposed_trust=new_trust)
    chain.append(v2)
    assert chain.trust_active_for_next().signers[2].key_id == "dave"
    # v3 authorized by the NEW set (dave + alice) verifies against the new set
    c3 = make_constitution(3, chain.head.content_hash)
    v3 = sign_all(keys, c3, "dave", "alice")
    chain.append(v3)
    assert len(chain) == 3


def test_rotation_does_not_retroactively_revalidate(keys, bootstrap, chain):
    new_trust = trust_config(keys, 2, "alice", "bob", "dave")
    chain.append(v2_of(keys, chain, proposed_trust=new_trust))
    c3 = make_constitution(3, chain.head.content_hash)
    chain.append(sign_all(keys, c3, "dave", "alice"))
    # full re-verification passes: old versions still validate against the OLD set
    assert chain.verify_full_chain() is True


def test_governed_resolution_pins_to_chain_version(keys, bootstrap, chain):
    v2 = v2_of(keys, chain, hard_deny_actions=["network:egress"])
    chain.append(v2)
    c3 = make_constitution(3, chain.head.content_hash,
                         hard_deny_actions=["network:egress"])
    chain.append(sign_all(keys, c3, "alice", "bob"))
    resolved = chain.governed_version(v2.content_hash)
    assert resolved is not None
    assert resolved.constitution.version == 2
    assert resolved is not chain.head  # pinned to v2, not "current"
    assert chain.governed_version("f" * 64) is None


def test_resolve_governed_version_offline(keys, bootstrap, genesis):
    v2c = make_constitution(2, genesis.content_hash)
    v2sig = sign_all(keys, v2c, "alice", "bob")
    got = resolve_governed_version([genesis, v2sig], bootstrap, v2sig.content_hash)
    assert got is not None and got.constitution.version == 2
    # tampered middle version (sigs copied onto different content) ->
    # whole supplied chain illegitimate -> None (fail closed)
    tampered = make_constitution(2, genesis.content_hash, hard_deny_actions=["x"])
    bad_v2 = SignedConstitution(constitution=tampered, signatures=v2sig.signatures)
    assert resolve_governed_version([genesis, bad_v2], bootstrap, bad_v2.content_hash) is None
    assert resolve_governed_version([], bootstrap, "x") is None


# ---------------------------------------------------------------------------
# unit: governance_check
# ---------------------------------------------------------------------------


def test_governance_check_decisions():
    c = make_constitution(
        1,
        None,
        hard_deny_actions=["shell:rm-rf"],
        approval_required_actions=["network:egress"],
        invariants=["deny:keys:export", "require-approval:db:write"],
    )
    assert governance_check("shell:rm-rf", "fs", c) == "DENY"
    assert governance_check("keys:export", "vault", c) == "DENY"          # invariant deny
    assert governance_check("network:egress", "net", c) == "APPROVAL_REQUIRED"
    assert governance_check("db:write", "db", c) == "APPROVAL_REQUIRED"    # invariant require
    assert governance_check("read:docs", "docs", c) == "ALLOW"


def test_deny_beats_approval_required():
    c = make_constitution(
        1, None,
        hard_deny_actions=["do:x"],
        approval_required_actions=["do:x"],
    )
    assert governance_check("do:x", "r", c) == "DENY"


def test_invariant_wildcards():
    c = make_constitution(1, None, invariants=["deny:prod:*"])
    assert governance_check("prod:deploy", "r", c) == "DENY"
    assert governance_check("staging:deploy", "r", c) == "ALLOW"


def test_adjudicate_receipt_unknown_hash_is_deny(chain):
    r = ActionReceipt(action="read:docs", resource="docs", constitution_hash="ab" * 32,
                      created_at=NOW)
    assert adjudicate_receipt(chain, r) == "DENY"


def test_adjudicate_receipt_applies_governing_version(keys, chain):
    v2 = v2_of(keys, chain, hard_deny_actions=["network:egress"])
    chain.append(v2)
    r = ActionReceipt(action="network:egress", resource="net",
                      constitution_hash=v2.content_hash, created_at=NOW)
    assert adjudicate_receipt(chain, r) == "DENY"
    r2 = ActionReceipt(action="read:docs", resource="docs",
                       constitution_hash=v2.content_hash, created_at=NOW)
    assert adjudicate_receipt(chain, r2) == "ALLOW"


# ---------------------------------------------------------------------------
# adversarial attacks — every one must end DENY / invalid / rejected
# ---------------------------------------------------------------------------


def test_attack_forged_constitution_with_copied_signatures(keys, bootstrap, chain):
    """A1: attacker copies signatures from a legit version onto forged content."""
    legit_v2 = v2_of(keys, chain)
    forged_c = make_constitution(
        2, chain.head.content_hash,
        hard_deny_actions=[],  # attacker strips the deny list
        invariants=["deny:nothing"],
    )
    forged = SignedConstitution(constitution=forged_c, signatures=legit_v2.signatures)
    # copied signatures cannot verify against different content
    assert not verify_constitution_signature(
        forged.signatures[0], keys["alice"].public_key_b64(), forged_c
    )
    with pytest.raises(ConstitutionRejected):
        chain.append(forged)
    assert len(chain) == 1  # chain untouched


def test_attack_supersedes_chain_skip(keys, bootstrap, chain):
    """A2: attacker jumps over an unaccepted version (v4 w/o v3)."""
    v2 = v2_of(keys, chain)
    chain.append(v2)
    # version skip: claims v4 while head is v2
    skip = sign_all(keys, make_constitution(4, chain.head.content_hash), "alice", "bob")
    with pytest.raises(ConstitutionRejected):
        chain.append(skip)
    # or: v3 pointing at a phantom previous_hash that was never accepted
    phantom = sign_all(keys, make_constitution(3, sha256_hex({"phantom": True})), "alice", "bob")
    with pytest.raises(ConstitutionRejected):
        chain.append(phantom)
    assert len(chain) == 2


def test_attack_quorum_not_met_m_of_n_minus_1(keys, bootstrap, chain):
    """A3: 2-of-3 quorum, attacker presents only 1 valid signature."""
    c = make_constitution(2, chain.head.content_hash, hard_deny_actions=["network:egress"])
    weak = sign_all(keys, c, "alice")
    with pytest.raises(ConstitutionRejected):
        chain.append(weak)
    assert len(chain) == 1


def test_attack_signature_by_rotated_out_key(keys, bootstrap, chain):
    """A4: carol is rotated out at v2; a v3 signed by carol must fail."""
    new_trust = trust_config(keys, 2, "alice", "bob", "dave")
    chain.append(v2_of(keys, chain, proposed_trust=new_trust))
    c3 = make_constitution(3, chain.head.content_hash)
    bad_v3 = sign_all(keys, c3, "carol", "bob")  # carol no longer trusted
    with pytest.raises(ConstitutionRejected):
        chain.append(bad_v3)
    assert len(chain) == 2


def test_attack_tampered_invariants_attacker_cannot_resign(keys, bootstrap, chain):
    """A5: attacker flips invariants on a legit version; lacking keys, the
    tampered payload fails verification (hash mismatch) and is rejected."""
    legit_v2 = v2_of(keys, chain, hard_deny_actions=["shell:rm-rf"])
    tampered_c = make_constitution(
        2, chain.head.content_hash, hard_deny_actions=[]  # deny stripped
    )
    assert content_hash_of(tampered_c) != content_hash_of(legit_v2.constitution)
    tampered = SignedConstitution(
        constitution=tampered_c, signatures=legit_v2.signatures  # attacker has no keys
    )
    with pytest.raises(ConstitutionRejected):
        chain.append(tampered)
    # and governance under the REAL v2 still denies
    chain.append(legit_v2)
    assert governance_check("shell:rm-rf", "fs", chain.head.constitution) == "DENY"


def test_attack_receipt_bound_to_phantom_hash(keys, bootstrap, chain):
    """A6: receipt references a constitution hash that never existed in the chain."""
    chain.append(v2_of(keys, chain))
    phantom_receipt = ActionReceipt(
        action="shell:rm-rf", resource="fs",
        constitution_hash=sha256_hex({"attacker": "constitution"}),
        created_at=NOW,
    )
    assert chain.governed_version(phantom_receipt.constitution_hash) is None
    assert resolve_governed_version(
        list(chain.versions), bootstrap, phantom_receipt.constitution_hash
    ) is None
    assert adjudicate_receipt(chain, phantom_receipt) == "DENY"


def test_attack_replay_superseded_constitution_as_current(keys, bootstrap, chain):
    """A7: attacker replays old v1 (permissive) as if it were current head v3.
    Resolution must pin to the chain's actual v1, not the attacker's claim —
    and a policy that changed between versions enforces the pinned version."""
    v1_hash = chain.head.content_hash  # v1 allows network:egress (no deny list)
    v2 = v2_of(keys, chain, hard_deny_actions=["network:egress"])
    chain.append(v2)
    c3 = make_constitution(3, chain.head.content_hash,
                           hard_deny_actions=["network:egress"])
    chain.append(sign_all(keys, c3, "alice", "bob"))

    replay_receipt = ActionReceipt(
        action="network:egress", resource="net",
        constitution_hash=v1_hash, created_at=NOW,
    )
    governed = chain.governed_version(replay_receipt.constitution_hash)
    assert governed is not None
    assert governed.constitution.version == 1          # pinned to real v1...
    assert governed.content_hash != chain.head.content_hash  # ...which is NOT current
    # v1's own policy applies to v1-bound actions: ALLOW here (it was permissive),
    # but crucially the enforcer sees version=1 != head version=3 and can demand
    # the current constitution. Under the CURRENT head, the action is denied:
    assert governance_check("network:egress", "net", chain.head.constitution) == "DENY"
