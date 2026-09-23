"""Tests for ANCHOR v1 capability 7: one policy vocabulary across planes.

Covers: the signed decision format, MCP allow/deny flows, the A2A agent-card
enforcement declaration, cross-plane verdict consistency, and >=5 adversarial
attacks — every attack must deny/fail.
"""

from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone

import pytest

from anchor_v1.attenuated_tokens import issue, make_holder_proof
from anchor_v1.canonical import sha256_hex
from anchor_v1.crypto import Ed25519Signer
from anchor_v1.models import SignedEnvelope
from anchor_v1.multisig_constitution import (
    Constitution,
    content_hash_of,
    sign_constitution,
)
from anchor_v1.planes import (
    SUPPORTED_PLANES,
    AgentCardBody,
    CardVerificationError,
    DecisionDeniedError,
    DecisionGovernor,
    DecisionVerificationError,
    EnforcementDeclaration,
    MCPGateway,
    UnifiedDecision,
    build_agent_card,
    decide,
    evaluate_plane,
    verify_agent_card,
    verify_decision,
)


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _window() -> tuple[datetime, datetime]:
    now = _utcnow()
    return now - timedelta(hours=1), now + timedelta(hours=1)


@pytest.fixture()
def keys() -> dict[str, Ed25519Signer]:
    return {
        "const-a": Ed25519Signer.generate("const-a"),
        "const-b": Ed25519Signer.generate("const-b"),
        "governor": Ed25519Signer.generate("governor-decision"),
        "issuer": Ed25519Signer.generate("token-issuer"),
        "holder": Ed25519Signer.generate("agent-holder"),
        "agent-did": Ed25519Signer.generate("agent-did"),
        "attacker": Ed25519Signer.generate("attacker"),
    }


def _make_constitution(keys: dict[str, Ed25519Signer]) -> Constitution:
    # Single-signer quorum documents which authority minted this constitution.
    const = Constitution(
        version=1,
        authority_epoch=0,
        hard_deny_actions=["mcp.tool.untrusted.*"],
        approval_required_actions=["shell.exec.rm *", "mcp.tool.files.delete"],
    )
    sig = sign_constitution(keys["const-a"], const)
    assert sig.key_id == "const-a"
    return const


@pytest.fixture()
def constitution(keys: dict[str, Ed25519Signer]) -> Constitution:
    return _make_constitution(keys)


@pytest.fixture()
def governor(
    keys: dict[str, Ed25519Signer], constitution: Constitution
) -> DecisionGovernor:
    return DecisionGovernor(
        decision_key=keys["governor"],
        token_issuers={"token-issuer": keys["issuer"].public_key_bytes()},
        constitution=constitution,
    )


@pytest.fixture()
def gateway(governor: DecisionGovernor) -> MCPGateway:
    gw = MCPGateway(governor=governor)
    gw.register_tool("files", "read", resource_scope="fs://docs", description="read a doc")
    gw.register_tool("files", "delete", resource_scope="fs://docs", description="delete a doc")
    gw.register_tool("untrusted", "x", resource_scope="net://evil", description="evil tool")
    return gw


def _mint(
    keys: dict[str, Ed25519Signer],
    constitution: Constitution,
    *,
    capability_id: str,
    audience: str,
    action: str,
    resource: str,
    args: dict,
    constitution_hash: str | None = None,
) -> tuple[SignedEnvelope, SignedEnvelope]:
    nb, ea = _window()
    env = issue(
        keys["issuer"],
        capability_id=capability_id,
        subject=keys["holder"].public_key_b64(),
        audience=audience,
        action=action,
        resource=resource,
        invocation_params=args,
        not_before=nb,
        expires_at=ea,
        constitution_hash=(
            constitution_hash if constitution_hash is not None else content_hash_of(constitution)
        ),
    )
    proof = make_holder_proof(keys["holder"], capability_id, env.payload["nonce"])
    return env, proof


# ---------------------------------------------------------------------------
# decision format + signature
# ---------------------------------------------------------------------------


def test_decision_format_and_signature(
    governor: DecisionGovernor, constitution: Constitution, keys: dict[str, Ed25519Signer]
) -> None:
    args = {"cmd": "ls", "dir": "/tmp"}
    env, proof = _mint(
        keys,
        constitution,
        capability_id="cap-1",
        audience="shell",
        action="shell.exec.ls",
        resource="host",
        args=args,
    )
    signed = evaluate_plane(
        governor,
        "shell",
        subject="agent-1",
        action="shell.exec.ls",
        resource="host",
        invocation_params=args,
        capability_envelope=env,
        holder_proof=proof,
    )
    decision = verify_decision(signed, keys["governor"].public_key_bytes())
    assert isinstance(decision, UnifiedDecision)
    assert decision.verdict == "ALLOW"
    assert decision.plane == "shell"
    assert decision.action == "shell.exec.ls"
    assert decision.resource == "host"
    assert decision.parameters_hash == sha256_hex(args)
    assert decision.policy_refs["constitution_hash"] == content_hash_of(constitution)
    assert decision.policy_refs["capability_id"] == "cap-1"
    assert "token_hash" in decision.policy_refs
    assert signed.key_id == "governor-decision"
    assert signed.alg == "Ed25519"


def test_verify_decision_wrong_key_fails(
    governor: DecisionGovernor, constitution: Constitution, keys: dict[str, Ed25519Signer]
) -> None:
    args = {"cmd": "ls"}
    env, proof = _mint(
        keys, constitution, capability_id="cap-2", audience="shell",
        action="shell.exec.ls", resource="host", args=args,
    )
    signed = evaluate_plane(
        governor, "shell", subject="a", action="shell.exec.ls", resource="host",
        invocation_params=args, capability_envelope=env, holder_proof=proof,
    )
    with pytest.raises(DecisionVerificationError):
        verify_decision(signed, keys["attacker"].public_key_bytes())


# ---------------------------------------------------------------------------
# MCP flows
# ---------------------------------------------------------------------------


def test_mcp_allow_flow(
    gateway: MCPGateway, constitution: Constitution, keys: dict[str, Ed25519Signer]
) -> None:
    args = {"path": "/a.txt"}
    env, proof = _mint(
        keys, constitution, capability_id="cap-mcp-1", audience="mcp",
        action="mcp.tool.files.read", resource="fs://docs", args=args,
    )
    signed = gateway.handle_tool_call(
        "files", "read", args, capability_envelope=env, holder_proof=proof
    )
    decision = verify_decision(signed, keys["governor"].public_key_bytes())
    assert decision.verdict == "ALLOW"
    assert decision.plane == "mcp"
    assert decision.action == "mcp.tool.files.read"
    assert decision.resource == "fs://docs"


def test_mcp_constitution_deny_carries_signed_decision(
    gateway: MCPGateway, constitution: Constitution, keys: dict[str, Ed25519Signer]
) -> None:
    args = {"target": "x"}
    env, proof = _mint(
        keys, constitution, capability_id="cap-mcp-2", audience="mcp",
        action="mcp.tool.untrusted.x", resource="net://evil", args=args,
    )
    with pytest.raises(DecisionDeniedError) as exc_info:
        gateway.handle_tool_call(
            "untrusted", "x", args, capability_envelope=env, holder_proof=proof
        )
    err = exc_info.value
    assert err.decision.verdict == "DENY"
    # the denial itself is auditable: it verifies under the governor key
    audited = verify_decision(err.signed_decision, keys["governor"].public_key_bytes())
    assert audited.verdict == "DENY"
    assert "deny_reason" in audited.policy_refs


def test_mcp_approval_required_flow(
    gateway: MCPGateway, constitution: Constitution, keys: dict[str, Ed25519Signer]
) -> None:
    args = {"path": "/a.txt"}
    env, proof = _mint(
        keys, constitution, capability_id="cap-mcp-3", audience="mcp",
        action="mcp.tool.files.delete", resource="fs://docs", args=args,
    )
    with pytest.raises(DecisionDeniedError) as exc_info:
        gateway.handle_tool_call(
            "files", "delete", args, capability_envelope=env, holder_proof=proof
        )
    err = exc_info.value
    assert err.decision.verdict == "APPROVAL_REQUIRED"
    audited = verify_decision(err.signed_decision, keys["governor"].public_key_bytes())
    assert audited.verdict == "APPROVAL_REQUIRED"


def test_mcp_missing_token_denies(
    gateway: MCPGateway, keys: dict[str, Ed25519Signer]
) -> None:
    with pytest.raises(DecisionDeniedError) as exc_info:
        gateway.handle_tool_call(
            "files", "read", {"path": "/a.txt"},
            capability_envelope=None, holder_proof=None,
        )
    assert exc_info.value.decision.verdict == "DENY"
    assert exc_info.value.decision.policy_refs["deny_reason"] == "no capability token presented"


# ---------------------------------------------------------------------------
# A2A agent card
# ---------------------------------------------------------------------------


def test_agent_card_build_and_verify(
    keys: dict[str, Ed25519Signer], constitution: Constitution
) -> None:
    chash = content_hash_of(constitution)
    card = build_agent_card(
        "agent-1",
        "did:anchor:agent-1",
        keys["governor"].public_key_bytes(),
        ["mcp", "a2a", "shell"],
        chash,
        agent_signer=keys["agent-did"],
    )
    assert card["anchor_enforcement"]["governor_key"] == keys["governor"].public_key_b64()
    assert card["anchor_enforcement"]["constitution_hash"] == chash
    assert "decision_verify_hint" in card["anchor_enforcement"]
    body = verify_agent_card(
        card,
        trusted_dids={"did:anchor:agent-1": keys["agent-did"].public_key_bytes()},
        supported_planes=set(SUPPORTED_PLANES),
        known_constitution_hashes={chash},
    )
    assert isinstance(body, AgentCardBody)
    assert body.agent_id == "agent-1"
    assert sorted(body.anchor_enforcement.planes) == ["a2a", "mcp", "shell"]


def test_agent_card_unknown_constitution_hash_fails(
    keys: dict[str, Ed25519Signer], constitution: Constitution
) -> None:
    card = build_agent_card(
        "agent-1",
        "did:anchor:agent-1",
        keys["governor"].public_key_bytes(),
        ["mcp"],
        content_hash_of(constitution),
        agent_signer=keys["agent-did"],
    )
    with pytest.raises(CardVerificationError):
        verify_agent_card(
            card,
            trusted_dids={"did:anchor:agent-1": keys["agent-did"].public_key_bytes()},
            supported_planes=set(SUPPORTED_PLANES),
            known_constitution_hashes={"deadbeef" * 8},
        )


# ---------------------------------------------------------------------------
# cross-plane consistency
# ---------------------------------------------------------------------------


def test_cross_plane_consistency_allow(
    governor: DecisionGovernor, constitution: Constitution, keys: dict[str, Ed25519Signer]
) -> None:
    args = {"path": "/a.txt"}
    env_mcp, proof_mcp = _mint(
        keys, constitution, capability_id="cap-x-mcp", audience="mcp",
        action="mcp.tool.files.read", resource="fs://docs", args=args,
    )
    env_shell, proof_shell = _mint(
        keys, constitution, capability_id="cap-x-shell", audience="shell",
        action="mcp.tool.files.read", resource="fs://docs", args=args,
    )
    signed_mcp = evaluate_plane(
        governor, "mcp", subject="agent-1", action="mcp.tool.files.read",
        resource="fs://docs", invocation_params=args,
        capability_envelope=env_mcp, holder_proof=proof_mcp,
    )
    signed_shell = evaluate_plane(
        governor, "shell", subject="agent-1", action="mcp.tool.files.read",
        resource="fs://docs", invocation_params=args,
        capability_envelope=env_shell, holder_proof=proof_shell,
    )
    d_mcp = verify_decision(signed_mcp, keys["governor"].public_key_bytes())
    d_shell = verify_decision(signed_shell, keys["governor"].public_key_bytes())
    assert d_mcp.verdict == d_shell.verdict == "ALLOW"
    assert d_mcp.action == d_shell.action
    assert d_mcp.resource == d_shell.resource
    assert d_mcp.parameters_hash == d_shell.parameters_hash
    assert d_mcp.plane == "mcp" and d_shell.plane == "shell"


def test_cross_plane_consistency_deny(
    governor: DecisionGovernor, keys: dict[str, Ed25519Signer]
) -> None:
    # constitution hard-denies mcp.tool.untrusted.* on every plane alike
    for plane in ("mcp", "shell", "http"):
        signed = evaluate_plane(
            governor, plane, subject="agent-1", action="mcp.tool.untrusted.x",
            resource="net://evil", invocation_params={"t": 1},
            capability_envelope=None, holder_proof=None,
        )
        d = verify_decision(signed, keys["governor"].public_key_bytes())
        assert d.verdict == "DENY", f"plane {plane} diverged"


def test_unknown_plane_denies(
    governor: DecisionGovernor, keys: dict[str, Ed25519Signer]
) -> None:
    signed = decide(
        plane="teleport",  # type: ignore[arg-type]
        subject="agent-1",
        action="x",
        resource="y",
        invocation_params={},
        constitution=governor.constitution,
        governor=governor,
        capability_envelope=None,
        holder_proof=None,
    )
    d = verify_decision(signed, keys["governor"].public_key_bytes())
    assert d.verdict == "DENY"


# ---------------------------------------------------------------------------
# adversarial attacks — every one must deny/fail
# ---------------------------------------------------------------------------


def test_attack_swapped_arguments_after_mint(
    gateway: MCPGateway, constitution: Constitution, keys: dict[str, Ed25519Signer]
) -> None:
    """Invocation binding: token minted for /a.txt cannot authorize /etc/passwd."""
    env, proof = _mint(
        keys, constitution, capability_id="cap-atk-1", audience="mcp",
        action="mcp.tool.files.read", resource="fs://docs", args={"path": "/a.txt"},
    )
    with pytest.raises(DecisionDeniedError) as exc_info:
        gateway.handle_tool_call(
            "files", "read", {"path": "/etc/passwd"},
            capability_envelope=env, holder_proof=proof,
        )
    assert exc_info.value.decision.verdict == "DENY"
    assert "token verify failed" in exc_info.value.decision.policy_refs["deny_reason"]


def test_attack_unregistered_tool(
    gateway: MCPGateway, constitution: Constitution, keys: dict[str, Ed25519Signer]
) -> None:
    """Fail closed: a valid token for a registered tool cannot authorize an
    unregistered one — unknown tools deny before any token is considered."""
    env, proof = _mint(
        keys, constitution, capability_id="cap-atk-2", audience="mcp",
        action="mcp.tool.files.read", resource="fs://docs", args={"path": "/a.txt"},
    )
    with pytest.raises(DecisionDeniedError) as exc_info:
        gateway.handle_tool_call(
            "evil", "pwn", {"path": "/a.txt"},
            capability_envelope=env, holder_proof=proof,
        )
    assert exc_info.value.decision.verdict == "DENY"
    audited = verify_decision(
        exc_info.value.signed_decision, keys["governor"].public_key_bytes()
    )
    assert audited.verdict == "DENY"


def test_attack_forged_did_signature(
    keys: dict[str, Ed25519Signer], constitution: Constitution
) -> None:
    """A card whose enforcement block was tampered with (or signed by someone
    else's DID key) must fail verification."""
    card = build_agent_card(
        "agent-1",
        "did:anchor:agent-1",
        keys["governor"].public_key_bytes(),
        ["mcp"],
        content_hash_of(constitution),
        agent_signer=keys["agent-did"],
    )
    # tamper: claim more planes, keep the original signature
    forged = copy.deepcopy(card)
    forged["anchor_enforcement"]["planes"] = ["mcp", "a2a", "shell", "http", "github"]
    with pytest.raises(CardVerificationError):
        verify_agent_card(
            forged,
            trusted_dids={"did:anchor:agent-1": keys["agent-did"].public_key_bytes()},
        )
    # re-sign with the attacker's key under the victim's DID
    body = {k: v for k, v in card.items() if k != "signature"}
    attacker_envelope = keys["attacker"].sign_payload(body)
    resigned = dict(body)
    resigned["signature"] = attacker_envelope.model_dump(mode="json")
    with pytest.raises(CardVerificationError):
        verify_agent_card(
            resigned,
            trusted_dids={"did:anchor:agent-1": keys["agent-did"].public_key_bytes()},
        )


def test_attack_overclaimed_planes(
    keys: dict[str, Ed25519Signer], constitution: Constitution
) -> None:
    """Card declares enforcement on planes the governor does not support."""
    body = AgentCardBody(
        agent_id="agent-1",
        did="did:anchor:agent-1",
        anchor_enforcement=EnforcementDeclaration(
            governor_key=keys["governor"].public_key_b64(),
            planes=["mcp", "teleport"],
            constitution_hash=content_hash_of(constitution),
            decision_verify_hint="x",
        ),
        issued_at=_utcnow(),
    )
    envelope = keys["agent-did"].sign_payload(body.model_dump(mode="json"))
    card = body.model_dump(mode="json")
    card["signature"] = envelope.model_dump(mode="json")
    # signature is genuinely the agent's — but the claim exceeds the governor
    with pytest.raises(CardVerificationError):
        verify_agent_card(
            card,
            trusted_dids={"did:anchor:agent-1": keys["agent-did"].public_key_bytes()},
            supported_planes={"mcp", "a2a"},
        )


def test_attack_tampered_decision_verdict(
    governor: DecisionGovernor, constitution: Constitution, keys: dict[str, Ed25519Signer]
) -> None:
    """Flipping the verdict inside a signed decision (without re-signing)
    must fail verification — the attacker does not hold the decision key."""
    args = {"cmd": "ls"}
    env, proof = _mint(
        keys, constitution, capability_id="cap-atk-5", audience="shell",
        action="shell.exec.ls", resource="host", args=args,
    )
    signed = evaluate_plane(
        governor, "shell", subject="a", action="shell.exec.ls", resource="host",
        invocation_params=args, capability_envelope=env, holder_proof=proof,
    )
    tampered = SignedEnvelope.model_validate(copy.deepcopy(signed.model_dump(mode="json")))
    tampered.payload["verdict"] = "ALLOW" if signed.payload["verdict"] != "ALLOW" else "DENY"
    with pytest.raises(DecisionVerificationError):
        verify_decision(tampered, keys["governor"].public_key_bytes())


def test_attack_token_replayed_across_planes(
    governor: DecisionGovernor, constitution: Constitution, keys: dict[str, Ed25519Signer]
) -> None:
    """Plane binding: a token minted for audience 'shell' cannot authorize an
    invocation evaluated on the 'mcp' plane."""
    args = {"cmd": "ls"}
    env, proof = _mint(
        keys, constitution, capability_id="cap-atk-6", audience="shell",
        action="shell.exec.ls", resource="host", args=args,
    )
    signed = evaluate_plane(
        governor, "mcp", subject="agent-1", action="shell.exec.ls", resource="host",
        invocation_params=args, capability_envelope=env, holder_proof=proof,
    )
    d = verify_decision(signed, keys["governor"].public_key_bytes())
    assert d.verdict == "DENY"
    assert "plane binding" in d.policy_refs["deny_reason"]


def test_attack_token_action_mismatch(
    governor: DecisionGovernor, constitution: Constitution, keys: dict[str, Ed25519Signer]
) -> None:
    """A token for mcp.tool.files.read cannot authorize mcp.tool.files.write."""
    args = {"path": "/a.txt"}
    env, proof = _mint(
        keys, constitution, capability_id="cap-atk-7", audience="mcp",
        action="mcp.tool.files.read", resource="fs://docs", args=args,
    )
    signed = evaluate_plane(
        governor, "mcp", subject="agent-1", action="mcp.tool.files.write",
        resource="fs://docs", invocation_params=args,
        capability_envelope=env, holder_proof=proof,
    )
    d = verify_decision(signed, keys["governor"].public_key_bytes())
    assert d.verdict == "DENY"
    assert "action binding" in d.policy_refs["deny_reason"]


def test_attack_token_wrong_constitution(
    keys: dict[str, Ed25519Signer], constitution: Constitution
) -> None:
    """A token minted under constitution A cannot be spent under constitution B."""
    other = Constitution(version=1, authority_epoch=0, hard_deny_actions=[])  # different content hash
    assert content_hash_of(other) != content_hash_of(constitution)
    gov_b = DecisionGovernor(
        decision_key=keys["governor"],
        token_issuers={"token-issuer": keys["issuer"].public_key_bytes()},
        constitution=other,
    )
    args = {"cmd": "ls"}
    env, proof = _mint(
        keys, constitution, capability_id="cap-atk-8", audience="shell",
        action="shell.exec.ls", resource="host", args=args,
    )
    signed = evaluate_plane(
        gov_b, "shell", subject="agent-1", action="shell.exec.ls", resource="host",
        invocation_params=args, capability_envelope=env, holder_proof=proof,
    )
    d = verify_decision(signed, keys["governor"].public_key_bytes())
    assert d.verdict == "DENY"
    assert "constitution binding" in d.policy_refs["deny_reason"]


def test_attack_replayed_token_nonce(
    governor: DecisionGovernor, constitution: Constitution, keys: dict[str, Ed25519Signer]
) -> None:
    """Single-use nonces: replaying a consumed token denies the second time."""
    args = {"cmd": "ls"}
    env, proof = _mint(
        keys, constitution, capability_id="cap-atk-9", audience="shell",
        action="shell.exec.ls", resource="host", args=args,
    )
    kwargs = dict(
        subject="agent-1", action="shell.exec.ls", resource="host",
        invocation_params=args, capability_envelope=env, holder_proof=proof,
    )
    first = verify_decision(
        evaluate_plane(governor, "shell", **kwargs), keys["governor"].public_key_bytes()
    )
    assert first.verdict == "ALLOW"
    second = verify_decision(
        evaluate_plane(governor, "shell", **kwargs), keys["governor"].public_key_bytes()
    )
    assert second.verdict == "DENY"
