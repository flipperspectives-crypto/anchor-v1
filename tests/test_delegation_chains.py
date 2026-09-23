"""Unit + adversarial tests for capability 3: delegation chains.

Happy path: mint/verify at depths 0-3.
Adversarial (all must fail closed with DelegationError):
  A1 scope-escalation attack: hop 2 widens actions beyond hop 1
  A2 sibling-prefix attack: "workspace://scope-evil" under "workspace://scope"
  A3 swapped middle receipt (hash-link break)
  A4 receipt signed by the wrong key (custody break)
  A5 depth claim lying (depth=1 on the third receipt)
  A6 expired intermediate receipt with valid leaf
  A7 cycle: a receipt appearing twice in the chain
  A8 URL boundary attack: "https://api.example.com.invalid" under
     "https://api.example.com" allowlist
Also: mint-time enforcement tests (delegate() raises before verify).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

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

UTC = timezone.utc


def _now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def _signers():
    from anchor_v1.delegation_chains import Ed25519Signer

    authority = Ed25519Signer.generate("authority")
    hop1 = Ed25519Signer.generate("agent-hop1")
    hop2 = Ed25519Signer.generate("agent-hop2")
    hop3 = Ed25519Signer.generate("agent-hop3")
    hop4 = Ed25519Signer.generate("agent-hop4")
    attacker = Ed25519Signer.generate("attacker")
    return authority, hop1, hop2, hop3, hop4, attacker


def _registry(*signers):
    return {s.key_id: s.public_key_bytes() for s in signers}


def _root_scope() -> DelegationScope:
    return DelegationScope(
        actions=["shell.exec", "http.get", "http.post", "fs.read"],
        resource_prefixes=["workspace://scope", "https://api.example.com"],
        caveats=[{"kind": "rate-limit", "max_per_minute": 10}],
    )


def _build_chain(depth: int):
    """Build an honest chain of the given max hop index (0..3)."""
    authority, hop1, hop2, hop3, hop4, attacker = _signers()
    registry = _registry(authority, hop1, hop2, hop3, hop4, attacker)
    trusted = {authority.key_id}
    now = _now()
    start, end = now - timedelta(hours=1), now + timedelta(days=7)

    root = issue_root(
        root_mandate_hash="mandate-abc",
        constitution_hash="constitution-xyz",
        delegatee_key_id=hop1.key_id,
        scope=_root_scope(),
        max_depth=3,
        not_before=start,
        expires_at=end,
        authority_signer=authority,
        delegation_id="del-root",
    )
    chain = [root]
    holders = [authority, hop1, hop2, hop3, hop4]
    scopes = [
        DelegationScope(
            actions=["shell.exec", "http.get", "fs.read"],
            resource_prefixes=["workspace://scope", "https://api.example.com/v1"],
            caveats=[{"kind": "rate-limit", "max_per_minute": 10}],
        ),
        DelegationScope(
            actions=["http.get", "fs.read"],
            resource_prefixes=["workspace://scope/jobs", "https://api.example.com/v1/status"],
            caveats=[
                {"kind": "rate-limit", "max_per_minute": 10},
                {"kind": "purpose", "only": "status-checks"},
            ],
        ),
        DelegationScope(
            actions=["http.get"],
            resource_prefixes=["https://api.example.com/v1/status"],
            caveats=[
                {"kind": "rate-limit", "max_per_minute": 10},
                {"kind": "purpose", "only": "status-checks"},
            ],
        ),
    ]
    for i in range(depth):
        nxt = delegate(
            chain[-1],
            holders[i + 2].key_id,
            scopes[i],
            holders[i + 1],
            delegation_id=f"del-hop{i + 1}",
        )
        chain.append(nxt)
    return authority, hop1, hop2, hop3, hop4, attacker, registry, trusted, chain


def _verify(chain, registry, trusted, now=None):
    return verify_chain(
        chain, trusted_authority_keys=trusted, key_registry=registry, now=now or _now()
    )


def _forge(payload: dict, signer):
    """Mint off-protocol: sign an arbitrary receipt dict (hostile delegator)."""
    return signer.sign_payload(payload)


# ---------------------------------------------------------------------------
# Boundary-aware prefix matching (unit)
# ---------------------------------------------------------------------------
class TestIsSubPrefix:
    def test_equal(self):
        assert is_sub_prefix("workspace://scope", "workspace://scope")

    def test_proper_subpath(self):
        assert is_sub_prefix("workspace://scope/jobs/42", "workspace://scope")

    def test_sibling_prefix_rejected(self):
        assert not is_sub_prefix("workspace://scope-evil", "workspace://scope")

    def test_sibling_prefix_rejected_reverse_dash(self):
        assert not is_sub_prefix("workspace://scope", "workspace://scope-evil")

    def test_url_boundary_rejected(self):
        assert not is_sub_prefix(
            "https://api.example.com.invalid", "https://api.example.com"
        )

    def test_url_subpath_allowed(self):
        assert is_sub_prefix(
            "https://api.example.com/v1/status", "https://api.example.com"
        )

    def test_unrelated_rejected(self):
        assert not is_sub_prefix("other://x", "workspace://scope")

    def test_shorter_child_rejected(self):
        assert not is_sub_prefix("workspace://scop", "workspace://scope")

    def test_empty_parent_allows_anything(self):
        assert is_sub_prefix("anything://here", "")


# ---------------------------------------------------------------------------
# Happy path: mint/verify depths 0-3
# ---------------------------------------------------------------------------
class TestHappyPath:
    @pytest.mark.parametrize("depth", [0, 1, 2, 3])
    def test_mint_and_verify_depth(self, depth):
        authority, hop1, hop2, hop3, hop4, attacker, registry, trusted, chain = _build_chain(depth)
        result = _verify(chain, registry, trusted)

        assert result.chain_length == depth + 1
        assert result.depth == depth
        assert len(result.ancestor_hashes) == depth + 1
        assert result.leaf_hash == result.ancestor_hashes[-1]
        assert result.root_mandate_hash == "mandate-abc"
        assert result.constitution_hash == "constitution-xyz"
        # ancestor hashes are the actual receipt hashes, root-first
        assert result.ancestor_hashes == [receipt_hash(e) for e in chain]
        # effective scope is the leaf's scope, proven subset of every ancestor
        leaf = DelegationReceipt.model_validate(chain[-1].payload)
        assert result.effective_scope == leaf.scope
        for env in chain:
            anc = DelegationReceipt.model_validate(env.payload)
            assert set(result.effective_scope.actions) <= set(anc.scope.actions)
        # position claims logged for the enforcement point
        assert result.delegatee_chain[0] == hop1.key_id

    def test_effective_scope_gate(self):
        authority, hop1, hop2, hop3, hop4, attacker, registry, trusted, chain = _build_chain(3)
        result = _verify(chain, registry, trusted)
        assert result.scope_allows("http.get", "https://api.example.com/v1/status")
        assert not result.scope_allows("shell.exec", "https://api.example.com/v1/status")
        assert not result.scope_allows("http.get", "https://api.example.com.invalid")
        assert not result.scope_allows("http.get", "workspace://scope/jobs")

    def test_empty_chain_rejected(self):
        authority, hop1, hop2, hop3, hop4, attacker, registry, trusted, chain = _build_chain(0)
        with pytest.raises(DelegationError):
            verify_chain([], trusted_authority_keys=trusted, key_registry=registry)

    def test_delegation_id_uniqueness_enforced(self):
        authority, hop1, hop2, hop3, hop4, attacker, registry, trusted, chain = _build_chain(1)
        dup = delegate(chain[0], hop2.key_id, chain[1].payload["scope"], hop1,
                       delegation_id="del-root")  # same id as root
        with pytest.raises(DelegationError):
            _verify(chain[:1] + [dup], registry, trusted)


# ---------------------------------------------------------------------------
# Mint-time enforcement (honest-holder guardrails)
# ---------------------------------------------------------------------------
class TestMintTimeEnforcement:
    def setup_method(self):
        (self.authority, self.hop1, self.hop2, self.hop3, self.hop4, self.attacker,
         self.registry, self.trusted, self.chain) = _build_chain(1)

    def test_widened_actions_rejected_at_mint(self):
        bad = DelegationScope(
            actions=["http.get", "shell.exec", "db.drop"],  # db.drop not granted
            resource_prefixes=["https://api.example.com/v1/status"],
            caveats=[{"kind": "rate-limit", "max_per_minute": 10}],
        )
        with pytest.raises(DelegationError):
            delegate(self.chain[1], self.hop3.key_id, bad, self.hop2)

    def test_sibling_prefix_rejected_at_mint(self):
        bad = DelegationScope(
            actions=["http.get"],
            resource_prefixes=["workspace://scope-evil"],
            caveats=[{"kind": "rate-limit", "max_per_minute": 10}],
        )
        with pytest.raises(DelegationError):
            delegate(self.chain[1], self.hop3.key_id, bad, self.hop2)

    def test_child_expiry_beyond_parent_rejected(self):
        bad = DelegationScope(
            actions=["http.get"],
            resource_prefixes=["https://api.example.com/v1/status"],
            caveats=[{"kind": "rate-limit", "max_per_minute": 10}],
        )
        with pytest.raises(DelegationError):
            delegate(
                self.chain[1], self.hop3.key_id, bad, self.hop2,
                expires_at=_now() + timedelta(days=30),
            )

    def test_dropped_caveat_rejected(self):
        bad = DelegationScope(
            actions=["http.get"],
            resource_prefixes=["https://api.example.com/v1/status"],
            caveats=[],  # drops the granted rate-limit + purpose caveats
        )
        with pytest.raises(DelegationError):
            delegate(self.chain[1], self.hop3.key_id, bad, self.hop2)

    def test_depth_beyond_max_rejected(self):
        authority, hop1, hop2, hop3, hop4, attacker, registry, trusted, chain = _build_chain(3)
        scope = DelegationScope(
            actions=["http.get"],
            resource_prefixes=["https://api.example.com/v1/status"],
            caveats=[
                {"kind": "rate-limit", "max_per_minute": 10},
                {"kind": "purpose", "only": "status-checks"},
            ],
        )
        # depth 3 == max_depth 3; one more hop must fail at mint
        with pytest.raises(DelegationError):
            delegate(chain[-1], "extra", scope, hop4)

    def test_non_holder_cannot_delegate(self):
        scope = DelegationScope(
            actions=["http.get"],
            resource_prefixes=["https://api.example.com/v1/status"],
            caveats=[{"kind": "rate-limit", "max_per_minute": 10}],
        )
        with pytest.raises(DelegationError):
            delegate(self.chain[1], self.hop3.key_id, scope, self.attacker)

    def test_max_depth_increase_rejected(self):
        scope = DelegationScope(
            actions=["http.get"],
            resource_prefixes=["https://api.example.com/v1/status"],
            caveats=[{"kind": "rate-limit", "max_per_minute": 10}],
        )
        with pytest.raises(DelegationError):
            delegate(self.chain[1], self.hop3.key_id, scope, self.hop2, max_depth=99)


# ---------------------------------------------------------------------------
# Adversarial: fail closed, every attack must raise DelegationError
# ---------------------------------------------------------------------------
class TestAdversarial:
    """Hostile-delegator forgeries: mint-time checks were bypassed, the
    enforcement point must still reject."""

    def _ctx(self):
        return _build_chain(2)

    def _hop_payload(self, chain, i):
        return dict(chain[i].payload)

    # A1: scope-escalation — hop 2 widens actions beyond hop 1
    def test_a1_scope_escalation_attack(self):
        authority, hop1, hop2, hop3, hop4, attacker, registry, trusted, chain = self._ctx()
        hop1_receipt = DelegationReceipt.model_validate(chain[1].payload)
        forged = self._hop_payload(chain, 1)
        forged["delegation_id"] = "del-forged-a1"
        forged["parent_receipt_hash"] = receipt_hash(chain[1])
        forged["delegator"] = hop2.key_id
        forged["delegatee"] = attacker.key_id
        forged["depth"] = 2
        forged["scope"] = dict(forged["scope"])
        forged["scope"]["actions"] = ["http.get", "shell.exec", "db.drop"]  # widened!
        forged["nonce"] = "a1" * 16
        evil = _forge(forged, hop2)  # signed by the real hop-2 holder, off-protocol
        with pytest.raises(DelegationError):
            _verify(chain[:2] + [evil], registry, trusted)

    # A2: sibling-prefix attack under a workspace prefix
    def test_a2_sibling_prefix_attack(self):
        authority, hop1, hop2, hop3, hop4, attacker, registry, trusted, chain = self._ctx()
        forged = self._hop_payload(chain, 1)
        forged["delegation_id"] = "del-forged-a2"
        forged["parent_receipt_hash"] = receipt_hash(chain[1])
        forged["delegator"] = hop2.key_id
        forged["delegatee"] = attacker.key_id
        forged["depth"] = 2
        forged["scope"] = dict(forged["scope"])
        forged["scope"]["actions"] = ["http.get", "fs.read"]
        forged["scope"]["resource_prefixes"] = ["workspace://scope-evil"]  # sibling!
        forged["nonce"] = "a2" * 16
        evil = _forge(forged, hop2)
        with pytest.raises(DelegationError):
            _verify(chain[:2] + [evil], registry, trusted)

    # A3: swapped middle receipt — hash link must break
    def test_a3_swapped_middle_receipt(self):
        authority, hop1, hop2, hop3, hop4, attacker, registry, trusted, chain = self._ctx()
        swapped = [chain[0], chain[2], chain[1]]  # middle two swapped
        with pytest.raises(DelegationError):
            _verify(swapped, registry, trusted)

    # A4: custody break — receipt signed by a key that was never the delegatee
    def test_a4_wrong_signer_custody_break(self):
        authority, hop1, hop2, hop3, hop4, attacker, registry, trusted, chain = self._ctx()
        forged = self._hop_payload(chain, 1)
        forged["delegation_id"] = "del-forged-a4"
        forged["parent_receipt_hash"] = receipt_hash(chain[1])
        forged["delegator"] = hop2.key_id
        forged["delegatee"] = hop3.key_id
        forged["depth"] = 2
        forged["nonce"] = "a4" * 16
        evil = _forge(forged, attacker)  # signed by an outsider, never a delegatee
        with pytest.raises(DelegationError):
            _verify(chain[:2] + [evil], registry, trusted)

    # A5: depth claim lying — third receipt claims depth=1
    def test_a5_depth_claim_lying(self):
        authority, hop1, hop2, hop3, hop4, attacker, registry, trusted, chain = self._ctx()
        forged = self._hop_payload(chain, 1)
        forged["delegation_id"] = "del-forged-a5"
        forged["parent_receipt_hash"] = receipt_hash(chain[1])
        forged["delegator"] = hop2.key_id
        forged["delegatee"] = hop3.key_id
        forged["depth"] = 1  # lies: this is the third receipt
        forged["nonce"] = "a5" * 16
        evil = _forge(forged, hop2)
        with pytest.raises(DelegationError):
            _verify(chain[:2] + [evil], registry, trusted)

    # A6: expired intermediate receipt with an otherwise-valid leaf
    def test_a6_expired_intermediate(self):
        authority, hop1, hop2, hop3, hop4, attacker, registry, trusted, chain = self._ctx()
        now = _now()
        past_start = now - timedelta(days=10)
        past_end = now - timedelta(days=1)
        short_root = issue_root(
            root_mandate_hash="m", constitution_hash="c",
            delegatee_key_id=hop1.key_id, scope=_root_scope(), max_depth=3,
            not_before=past_start, expires_at=now + timedelta(hours=1),
            authority_signer=authority, delegation_id="del-r6",
        )
        expired_mid = delegate(
            short_root, hop2.key_id,
            DelegationScope(actions=["http.get"],
                            resource_prefixes=["https://api.example.com"],
                            caveats=[{"kind": "rate-limit", "max_per_minute": 10}]),
            hop1, not_before=past_start, expires_at=past_end,
            delegation_id="del-m6",
        )
        # leaf minted honestly with a fresh window — but it must still die
        # because its parent was expired at enforcement time
        forged = dict(expired_mid.payload)
        forged["delegation_id"] = "del-l6"
        forged["parent_receipt_hash"] = receipt_hash(expired_mid)
        forged["delegator"] = hop2.key_id
        forged["delegatee"] = hop3.key_id
        forged["depth"] = 2
        forged["not_before"] = (now - timedelta(hours=1)).isoformat()
        forged["expires_at"] = (now + timedelta(hours=1)).isoformat()
        forged["nonce"] = "a6" * 16
        leaf = _forge(forged, hop2)
        with pytest.raises(DelegationError):
            _verify([short_root, expired_mid, leaf], registry, trusted, now=now)

    # A7: cycle — the same receipt re-delegated / appearing twice
    def test_a7_cycle_duplicate_receipt(self):
        authority, hop1, hop2, hop3, hop4, attacker, registry, trusted, chain = self._ctx()
        forged = self._hop_payload(chain, 1)
        forged["delegation_id"] = "del-forged-a7"
        forged["parent_receipt_hash"] = receipt_hash(chain[1])
        forged["delegator"] = hop2.key_id
        forged["delegatee"] = hop1.key_id  # back to an ancestor holder
        forged["depth"] = 2
        forged["nonce"] = "a7" * 16
        back_edge = _forge(forged, hop2)
        # re-presenting hop-1's receipt again at the end = a cycle
        with pytest.raises(DelegationError):
            _verify(chain[:2] + [back_edge, chain[1]], registry, trusted)

    # A8: URL boundary attack on an allowlisted API prefix
    def test_a8_url_boundary_attack(self):
        authority, hop1, hop2, hop3, hop4, attacker, registry, trusted, chain = self._ctx()
        forged = self._hop_payload(chain, 1)
        forged["delegation_id"] = "del-forged-a8"
        forged["parent_receipt_hash"] = receipt_hash(chain[1])
        forged["delegator"] = hop2.key_id
        forged["delegatee"] = attacker.key_id
        forged["depth"] = 2
        forged["scope"] = dict(forged["scope"])
        forged["scope"]["actions"] = ["http.get", "fs.read"]
        forged["scope"]["resource_prefixes"] = ["https://api.example.com.invalid"]
        forged["nonce"] = "a8" * 16
        evil = _forge(forged, hop2)
        with pytest.raises(DelegationError):
            _verify(chain[:2] + [evil], registry, trusted)

    # A9: untrusted root — chain signed by a self-proclaimed authority
    def test_a9_untrusted_root_authority(self):
        authority, hop1, hop2, hop3, hop4, attacker, registry, trusted, chain = self._ctx()
        fake_root = issue_root(
            root_mandate_hash="m", constitution_hash="c",
            delegatee_key_id=hop1.key_id, scope=_root_scope(), max_depth=3,
            not_before=_now() - timedelta(hours=1),
            expires_at=_now() + timedelta(days=1),
            authority_signer=attacker,  # not in trusted set
            delegation_id="del-r9",
        )
        with pytest.raises(DelegationError):
            _verify([fake_root], registry, trusted)

    # A10: tampered root payload re-linked (hash-link forgery)
    def test_a10_tampered_parent_relink(self):
        authority, hop1, hop2, hop3, hop4, attacker, registry, trusted, chain = self._ctx()
        forged = self._hop_payload(chain, 1)
        forged["delegation_id"] = "del-forged-a10"
        forged["parent_receipt_hash"] = receipt_hash(chain[0])  # skip hop 1!
        forged["delegator"] = hop1.key_id
        forged["delegatee"] = hop3.key_id
        forged["depth"] = 1
        forged["nonce"] = "a10" * 16
        evil = _forge(forged, hop1)
        # presented as [root, evil, hop2-receipt]: custody + link both break
        with pytest.raises(DelegationError):
            _verify([chain[0], evil, chain[2]], registry, trusted)
