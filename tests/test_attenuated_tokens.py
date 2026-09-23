"""Tests for attenuated capability tokens v2.

Unit tests: issuance, attenuation, verification pipeline, caveat evaluation.
Adversarial tests (>=5): fail-closed claims attacked — every attack must
raise/deny, never softly allow.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from anchor_v1.attenuated_tokens import (
    AuthorizationError,
    Caveat,
    Ed25519Signer,
    SignedEnvelope,
    attenuate,
    issue,
    make_holder_proof,
    token_hash,
    verify,
)
from anchor_v1.canonical import sha256_hex

NOW = datetime(2026, 9, 23, 12, 0, 0, tzinfo=timezone.utc)
CONSTITUTION = "constitution-hash-abc123"

INVOCATION: dict[str, Any] = {
    "tool": "shell.exec",
    "command": "ls -la /tmp",
    "resource": "workspace://scope/docs",
}


def _signers():
    issuer = Ed25519Signer.generate("issuer-1")
    holder_a = Ed25519Signer.generate("holder-a")
    holder_b = Ed25519Signer.generate("holder-b")
    attacker = Ed25519Signer.generate("attacker")
    return issuer, holder_a, holder_b, attacker


def _trusted(issuer: Ed25519Signer) -> dict[str, bytes]:
    return {issuer.key_id: issuer.public_key_bytes()}


def _root(
    issuer: Ed25519Signer,
    holder: Ed25519Signer,
    caveats: list[Caveat] | None = None,
    not_before: datetime | None = None,
    expires_at: datetime | None = None,
    invocation: dict[str, Any] | None = None,
) -> SignedEnvelope:
    return issue(
        issuer,
        capability_id="cap-001",
        subject=holder.public_key_b64(),
        audience="gateway-1",
        action="shell.exec",
        resource="workspace://scope",
        invocation_params=invocation if invocation is not None else INVOCATION,
        caveats=caveats,
        not_before=not_before or NOW - timedelta(hours=1),
        expires_at=expires_at or NOW + timedelta(hours=1),
        constitution_hash=CONSTITUTION,
    )


def _verify_root(
    envelope: SignedEnvelope,
    issuer: Ed25519Signer,
    holder: Ed25519Signer,
    **kwargs: Any,
):
    params = {
        "holder_proof": make_holder_proof(
            holder, envelope.payload["capability_id"], envelope.payload["nonce"]
        ),
        "invocation_params": INVOCATION,
        "now": NOW,
        "trusted_issuers": _trusted(issuer),
    }
    params.update(kwargs)
    return verify(envelope, **params)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# unit: issuance / happy-path verify
# ---------------------------------------------------------------------------


def test_issue_and_verify_root_token():
    issuer, holder_a, _, _ = _signers()
    env = _root(issuer, holder_a)
    payload = _verify_root(env, issuer, holder_a)
    assert payload.capability_id == "cap-001"
    assert payload.issuer == "issuer-1"
    assert payload.subject == holder_a.public_key_b64()
    assert payload.parent_token_hash is None
    assert payload.parameters_hash == sha256_hex(INVOCATION)


def test_subject_as_key_id_resolves_via_holder_keys():
    issuer, holder_a, _, _ = _signers()
    env = issue(
        issuer,
        capability_id="cap-kid",
        subject="holder-a",  # key_id, not raw pubkey
        audience="gateway-1",
        action="shell.exec",
        resource="workspace://scope",
        invocation_params=INVOCATION,
        not_before=NOW - timedelta(hours=1),
        expires_at=NOW + timedelta(hours=1),
        constitution_hash=CONSTITUTION,
    )
    payload = _verify_root(
        env, issuer, holder_a, holder_keys={"holder-a": holder_a.public_key_b64()}
    )
    assert payload.subject == "holder-a"


def test_attenuate_child_verifies_with_chain():
    issuer, holder_a, holder_b, _ = _signers()
    parent = _root(
        issuer,
        holder_a,
        caveats=[Caveat(kind="spend_limit", params={"max_amount": 100, "currency": "USD"})],
    )
    child = attenuate(
        parent,
        issuer,
        [Caveat(kind="spend_limit", params={"max_amount": 40, "currency": "USD"})],
        holder_b.public_key_b64(),
        capability_id="cap-001/delegate",
        resource="workspace://scope/docs",
        expires_at=NOW + timedelta(minutes=30),
    )
    child_payload = verify(
        child,
        holder_proof=make_holder_proof(
            holder_b, child.payload["capability_id"], child.payload["nonce"]
        ),
        invocation_params=INVOCATION,
        now=NOW,
        trusted_issuers=_trusted(issuer),
        parent_envelope=parent,
        holder_proofs={
            "cap-001": make_holder_proof(
                holder_a, parent.payload["capability_id"], parent.payload["nonce"]
            )
        },
        context={"spend_amount": 10, "spend_currency": "USD"},
    )
    assert child_payload.parent_token_hash == token_hash(parent)
    assert child_payload.resource == "workspace://scope/docs"
    assert child_payload.subject == holder_b.public_key_b64()
    # parent caveat carried over verbatim (conjunction => narrowing only)
    assert any(c.kind == "spend_limit" and c.params["max_amount"] == 100 for c in child_payload.caveats)


def test_attenuation_clamps_expiry_and_not_before():
    issuer, holder_a, holder_b, _ = _signers()
    parent = _root(issuer, holder_a)
    # requesting a WIDER window must be clamped, never honored
    child = attenuate(
        parent,
        issuer,
        [],
        holder_b.public_key_b64(),
        expires_at=NOW + timedelta(days=30),
        not_before=NOW - timedelta(days=30),
    )
    assert child.payload["expires_at"] == parent.payload["expires_at"]
    assert child.payload["not_before"] == parent.payload["not_before"]


def test_delegation_chain_depth_two():
    issuer, holder_a, holder_b, _ = _signers()
    holder_c = Ed25519Signer.generate("holder-c")
    root = _root(issuer, holder_a)
    mid = attenuate(root, issuer, [Caveat(kind="uses", params={"max_uses": 5})], holder_b.public_key_b64())
    leaf = attenuate(
        mid,
        issuer,
        [Caveat(kind="resource_prefix", params={"prefix": "workspace://scope/docs"})],
        holder_c.public_key_b64(),
    )
    chain = {
        token_hash(root): root,
        token_hash(mid): mid,
    }
    proofs = {
        root.payload["capability_id"]: make_holder_proof(
            holder_a, root.payload["capability_id"], root.payload["nonce"]
        ),
        mid.payload["capability_id"]: make_holder_proof(
            holder_b, mid.payload["capability_id"], mid.payload["nonce"]
        ),
    }
    payload = verify(
        leaf,
        holder_proof=make_holder_proof(
            holder_c, leaf.payload["capability_id"], leaf.payload["nonce"]
        ),
        invocation_params=INVOCATION,
        now=NOW,
        trusted_issuers=_trusted(issuer),
        chain=chain,
        holder_proofs=proofs,
        context={"uses_consumed": 0, "resource": "workspace://scope/docs"},
    )
    assert payload.capability_id == leaf.payload["capability_id"]


def test_caveat_expiry_evaluated():
    issuer, holder_a, _, _ = _signers()
    env = _root(
        issuer,
        holder_a,
        caveats=[
            Caveat(
                kind="expiry",
                params={"expires_at": (NOW + timedelta(minutes=10)).isoformat()},
            )
        ],
    )
    _verify_root(env, issuer, holder_a)  # fine now
    with pytest.raises(AuthorizationError):
        _verify_root(env, issuer, holder_a, now=NOW + timedelta(minutes=11))


def test_caveat_uses_single_use_requires_nonce_tracking():
    issuer, holder_a, _, _ = _signers()
    env = _root(
        issuer, holder_a, caveats=[Caveat(kind="uses", params={"max_uses": 1})]
    )
    with pytest.raises(AuthorizationError):
        _verify_root(env, issuer, holder_a)  # no used_nonces supplied => deny
    used: set[str] = set()
    _verify_root(env, issuer, holder_a, used_nonces=used)  # ok once
    used.add(env.payload["nonce"])
    with pytest.raises(AuthorizationError):
        _verify_root(env, issuer, holder_a, used_nonces=used)  # replay => deny


def test_caveat_http_allowlist():
    issuer, holder_a, _, _ = _signers()
    env = _root(
        issuer,
        holder_a,
        caveats=[Caveat(kind="http_allowlist", params={"hosts": ["api.example.com"]})],
    )
    _verify_root(env, issuer, holder_a, context={"http_host": "api.example.com"})
    with pytest.raises(AuthorizationError):
        _verify_root(env, issuer, holder_a, context={"http_host": "evil.example.com"})
    with pytest.raises(AuthorizationError):
        _verify_root(env, issuer, holder_a)  # no http context => deny


def test_caveat_spend_limit():
    issuer, holder_a, _, _ = _signers()
    env = _root(
        issuer,
        holder_a,
        caveats=[
            Caveat(kind="spend_limit", params={"max_amount": 50, "currency": "USD"})
        ],
    )
    _verify_root(
        env, issuer, holder_a, context={"spend_amount": 25, "spend_currency": "USD"}
    )
    with pytest.raises(AuthorizationError):
        _verify_root(
            env, issuer, holder_a, context={"spend_amount": 51, "spend_currency": "USD"}
        )
    with pytest.raises(AuthorizationError):
        _verify_root(env, issuer, holder_a, context={"spend_amount": 25})  # no currency
    with pytest.raises(AuthorizationError):
        _verify_root(env, issuer, holder_a)  # no spend context at all


def test_caveat_resource_prefix_boundary():
    issuer, holder_a, _, _ = _signers()
    inv = dict(INVOCATION, resource="workspace://scope/docs/report.md")
    env = _root(
        issuer,
        holder_a,
        caveats=[Caveat(kind="resource_prefix", params={"prefix": "workspace://scope"})],
        invocation=inv,
    )
    _verify_root(env, issuer, holder_a, invocation_params=inv)  # segment match ok
    evil = dict(INVOCATION, resource="workspace://scope-evil")
    env2 = _root(
        issuer,
        holder_a,
        caveats=[Caveat(kind="resource_prefix", params={"prefix": "workspace://scope"})],
        invocation=evil,
    )
    with pytest.raises(AuthorizationError):
        _verify_root(env2, issuer, holder_a, invocation_params=evil)


def test_unknown_caveat_kind_denies_at_verify():
    issuer, holder_a, _, _ = _signers()
    payload_dict = _root(issuer, holder_a).payload
    payload_dict["caveats"] = [{"kind": "mind_control", "params": {}}]
    forged = issuer.sign_payload(payload_dict)  # even issuer-signed...
    with pytest.raises(AuthorizationError):
        _verify_root(forged, issuer, holder_a)


def test_attenuate_rejects_unknown_caveat_kind():
    issuer, holder_a, holder_b, _ = _signers()
    parent = _root(issuer, holder_a)
    with pytest.raises(ValueError):
        attenuate(
            parent, issuer, [Caveat(kind="mind_control", params={})], holder_b.public_key_b64()
        )


def test_attenuate_rejects_resource_widening():
    issuer, holder_a, holder_b, _ = _signers()
    parent = _root(issuer, holder_a)
    with pytest.raises(ValueError):
        attenuate(
            parent,
            issuer,
            [],
            holder_b.public_key_b64(),
            resource="workspace://other",
        )


def test_token_not_yet_valid_denies():
    issuer, holder_a, _, _ = _signers()
    env = _root(issuer, holder_a, not_before=NOW + timedelta(hours=1))
    with pytest.raises(AuthorizationError):
        _verify_root(env, issuer, holder_a)


def test_missing_parent_envelope_denies():
    issuer, holder_a, holder_b, _ = _signers()
    parent = _root(issuer, holder_a)
    child = attenuate(parent, issuer, [], holder_b.public_key_b64())
    with pytest.raises(AuthorizationError):
        verify(
            child,
            holder_proof=make_holder_proof(
                holder_b, child.payload["capability_id"], child.payload["nonce"]
            ),
            invocation_params=INVOCATION,
            now=NOW,
            trusted_issuers=_trusted(issuer),
            # no parent_envelope / chain supplied
        )


# ---------------------------------------------------------------------------
# adversarial: every attack must raise/deny
# ---------------------------------------------------------------------------


def test_attack_different_holder_key_pop_bypass():
    """ATTACK 1: token bound to holder A, proof signed by holder B's key."""
    issuer, holder_a, holder_b, _ = _signers()
    env = _root(issuer, holder_a)
    evil_proof = make_holder_proof(
        holder_b, env.payload["capability_id"], env.payload["nonce"]
    )
    with pytest.raises(AuthorizationError):
        verify(
            env,
            holder_proof=evil_proof,
            invocation_params=INVOCATION,
            now=NOW,
            trusted_issuers=_trusted(issuer),
        )


def test_attack_tampered_invocation_params():
    """ATTACK 2: invocation parameters altered after issuance."""
    issuer, holder_a, _, _ = _signers()
    env = _root(issuer, holder_a)
    tampered = dict(INVOCATION, command="rm -rf /")
    with pytest.raises(AuthorizationError):
        _verify_root(env, issuer, holder_a, invocation_params=tampered)


def test_attack_child_widens_expiry():
    """ATTACK 3: compromised minter signs a child with a LATER expiry."""
    issuer, holder_a, holder_b, _ = _signers()
    parent = _root(
        issuer,
        holder_a,
        caveats=[
            Caveat(kind="expiry", params={"expires_at": (NOW + timedelta(hours=1)).isoformat()})
        ],
    )
    child_dict = dict(attenuate(parent, issuer, [], holder_b.public_key_b64()).payload)
    # attacker rewrites the carried expiry caveat to a later time, re-signed by
    # the (compromised) issuer key — signatures alone must not save it.
    child_dict["caveats"] = [
        {"kind": "expiry", "params": {"expires_at": (NOW + timedelta(days=7)).isoformat()}}
    ]
    widened = issuer.sign_payload(child_dict)
    with pytest.raises(AuthorizationError):
        verify(
            widened,
            holder_proof=make_holder_proof(
                holder_b, widened.payload["capability_id"], widened.payload["nonce"]
            ),
            invocation_params=INVOCATION,
            now=NOW,
            trusted_issuers=_trusted(issuer),
            parent_envelope=parent,
            holder_proofs={
                "cap-001": make_holder_proof(
                    holder_a, parent.payload["capability_id"], parent.payload["nonce"]
                )
            },
        )


def test_attack_child_widens_resource_prefix():
    """ATTACK 4: child claims a BROADER resource prefix than the parent."""
    issuer, holder_a, holder_b, _ = _signers()
    parent = _root(
        issuer,
        holder_a,
        caveats=[
            Caveat(kind="resource_prefix", params={"prefix": "workspace://scope/docs"})
        ],
    )
    child_dict = dict(attenuate(parent, issuer, [], holder_b.public_key_b64()).payload)
    child_dict["caveats"] = [
        {"kind": "resource_prefix", "params": {"prefix": "workspace://"}}
    ]
    widened = issuer.sign_payload(child_dict)
    with pytest.raises(AuthorizationError):
        verify(
            widened,
            holder_proof=make_holder_proof(
                holder_b, widened.payload["capability_id"], widened.payload["nonce"]
            ),
            invocation_params=INVOCATION,
            now=NOW,
            trusted_issuers=_trusted(issuer),
            parent_envelope=parent,
            holder_proofs={
                "cap-001": make_holder_proof(
                    holder_a, parent.payload["capability_id"], parent.payload["nonce"]
                )
            },
        )


def test_attack_child_drops_parent_caveat():
    """ATTACK 5: child silently drops the parent's spend_limit caveat."""
    issuer, holder_a, holder_b, _ = _signers()
    parent = _root(
        issuer,
        holder_a,
        caveats=[
            Caveat(kind="spend_limit", params={"max_amount": 10, "currency": "USD"})
        ],
    )
    child_dict = dict(attenuate(parent, issuer, [], holder_b.public_key_b64()).payload)
    child_dict["caveats"] = []  # dropped
    stripped = issuer.sign_payload(child_dict)
    with pytest.raises(AuthorizationError):
        verify(
            stripped,
            holder_proof=make_holder_proof(
                holder_b, stripped.payload["capability_id"], stripped.payload["nonce"]
            ),
            invocation_params=INVOCATION,
            now=NOW,
            trusted_issuers=_trusted(issuer),
            parent_envelope=parent,
            holder_proofs={
                "cap-001": make_holder_proof(
                    holder_a, parent.payload["capability_id"], parent.payload["nonce"]
                )
            },
        )


def test_attack_replayed_single_use_token():
    """ATTACK 6: capture a used token and replay it."""
    issuer, holder_a, _, _ = _signers()
    env = _root(issuer, holder_a)
    used: set[str] = set()
    _verify_root(env, issuer, holder_a, used_nonces=used)
    used.add(env.payload["nonce"])  # enforcement point consumes the nonce
    with pytest.raises(AuthorizationError):
        _verify_root(env, issuer, holder_a, used_nonces=used)


def test_attack_forged_issuer_signature():
    """ATTACK 7: attacker signs with their own key but claims the issuer's key_id."""
    issuer, holder_a, _, attacker = _signers()
    payload_dict = _root(issuer, holder_a).payload
    forged = attacker.sign_payload(payload_dict).model_copy(
        update={"key_id": issuer.key_id}
    )
    with pytest.raises(AuthorizationError):
        _verify_root(forged, issuer, holder_a)


def test_attack_expired_token_with_backdated_not_before():
    """ATTACK 8: expired token; backdating not_before does not help."""
    issuer, holder_a, _, _ = _signers()
    env = _root(
        issuer,
        holder_a,
        not_before=NOW - timedelta(days=30),
        expires_at=NOW - timedelta(seconds=1),
    )
    with pytest.raises(AuthorizationError):
        _verify_root(env, issuer, holder_a)


def test_attack_caveat_stripped_no_resign():
    """ATTACK 9: attacker strips a caveat without the issuer key — signature dies."""
    issuer, holder_a, _, _ = _signers()
    env = _root(
        issuer,
        holder_a,
        caveats=[
            Caveat(kind="spend_limit", params={"max_amount": 1, "currency": "USD"})
        ],
    )
    stripped_payload = dict(env.payload)
    stripped_payload["caveats"] = []
    stripped = env.model_copy(update={"payload": stripped_payload})
    with pytest.raises(AuthorizationError):
        _verify_root(stripped, issuer, holder_a)


def test_attack_wrong_parent_token_hash():
    """ATTACK 10: child presented with a parent envelope that is not its parent."""
    issuer, holder_a, holder_b, _ = _signers()
    parent = _root(issuer, holder_a)
    other_parent = _root(issuer, holder_a)  # different nonce => different hash
    child = attenuate(parent, issuer, [], holder_b.public_key_b64())
    with pytest.raises(AuthorizationError):
        verify(
            child,
            holder_proof=make_holder_proof(
                holder_b, child.payload["capability_id"], child.payload["nonce"]
            ),
            invocation_params=INVOCATION,
            now=NOW,
            trusted_issuers=_trusted(issuer),
            parent_envelope=other_parent,  # wrong parent
            holder_proofs={
                "cap-001": make_holder_proof(
                    holder_a, other_parent.payload["capability_id"],
                    other_parent.payload["nonce"],
                )
            },
        )


def test_attack_holder_proof_for_wrong_token():
    """ATTACK 11: valid proof, but for a different capability/nonce."""
    issuer, holder_a, _, _ = _signers()
    env = _root(issuer, holder_a)
    other = _root(issuer, holder_a)
    proof_for_other = make_holder_proof(
        holder_a, other.payload["capability_id"], other.payload["nonce"]
    )
    with pytest.raises(AuthorizationError):
        verify(
            env,
            holder_proof=proof_for_other,
            invocation_params=INVOCATION,
            now=NOW,
            trusted_issuers=_trusted(issuer),
        )


def test_attack_untrusted_issuer():
    """ATTACK 12: token from an issuer not in the trust set."""
    _, holder_a, _, attacker = _signers()
    env = issue(
        attacker,
        capability_id="cap-evil",
        subject=holder_a.public_key_b64(),
        audience="gateway-1",
        action="shell.exec",
        resource="workspace://scope",
        invocation_params=INVOCATION,
        not_before=NOW - timedelta(hours=1),
        expires_at=NOW + timedelta(hours=1),
        constitution_hash=CONSTITUTION,
    )
    real_issuer = Ed25519Signer.generate("issuer-1")
    with pytest.raises(AuthorizationError):
        _verify_root(env, real_issuer, holder_a)


# ---------------------------------------------------------------------------
# perf: offline root-token verify vs ~2ms target
# ---------------------------------------------------------------------------


def test_verify_root_token_perf():
    issuer, holder_a, _, _ = _signers()
    env = _root(issuer, holder_a)
    proof = make_holder_proof(
        holder_a, env.payload["capability_id"], env.payload["nonce"]
    )
    trusted = _trusted(issuer)
    # warm up
    for _ in range(5):
        verify(
            env,
            holder_proof=proof,
            invocation_params=INVOCATION,
            now=NOW,
            trusted_issuers=trusted,
        )
    runs = 100
    start = time.perf_counter()
    for _ in range(runs):
        verify(
            env,
            holder_proof=proof,
            invocation_params=INVOCATION,
            now=NOW,
            trusted_issuers=trusted,
        )
    mean_ms = (time.perf_counter() - start) / runs * 1000
    # measured ~0.35 ms mean on this machine (2026-09-23), vs ~2ms target;
    # generous bound 50ms keeps CI honest without flaking.
    print(f"\nroot token offline verify: {mean_ms:.2f} ms mean over {runs} runs")
    assert mean_ms < 50, f"verify too slow: {mean_ms:.2f} ms mean"


# ---------------------------------------------------------------------------
# regression: audience binding (harness FLAG T14)
# ---------------------------------------------------------------------------


def test_verify_enforces_expected_audience():
    issuer, holder_a, _, _ = _signers()
    env = _root(issuer, holder_a)  # audience="gateway-1"
    # wrong audience denied
    with pytest.raises(AuthorizationError):
        _verify_root(env, issuer, holder_a, expected_audience="gateway-2")
    # correct audience allowed
    payload = _verify_root(env, issuer, holder_a, expected_audience="gateway-1")
    assert payload.audience == "gateway-1"
    # omitted audience still verifies (caller performs its own check)
    payload = _verify_root(env, issuer, holder_a)
    assert payload.audience == "gateway-1"
