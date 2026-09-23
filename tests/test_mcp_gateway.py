"""Tests for the NATIVE MCP gateway (Wave 3): anchor_v1.mcp_gateway.NativeMCPGateway.

Covers MCP 2026-07-28 wire shapes: tool registration, tools/list pagination,
tools/call holder-of-key interception, execution receipts, backend dispatch,
and envelope binding. Every deny path is fail-closed: denial raises
MCPDeniedError and the backend is never dispatched on that path.

The legacy v0 ``MCPGateway`` is covered by tests/test_planes.py and is NOT
tested here.

Envelope binding: ``store.consume_capability`` binds the *full* envelope
``action_digest`` (which covers the random ``action_id`` and ``nonce``), so
``NativeMCPGateway.tools_call`` cannot rebuild the envelope at call time —
a fresh build always has a different digest. The documented flow is: the
issuer calls ``gateway.build_envelope(...)``, mints the capability against
``envelope.action_digest``, and the caller presents that SAME envelope to
``tools_call``. The gateway validates the presented envelope against the
call (plane/verb/target/args/principal/policy/window) and the store
checks the cryptographic digest binding. Section G pins this contract.
"""

from __future__ import annotations

import base64
import copy
import json
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from anchor_v1 import authority
from anchor_v1.canonical import sha256_hex
from anchor_v1.crypto import Ed25519Signer
from anchor_v1.envelope import ActionEnvelope, Effect
from anchor_v1.mcp_gateway import (
    ExecutionReceipt,
    InMemoryMCPBackend,
    MCPBackend,
    MCPDeniedError,
    MCPGatewayError,
    NativeMCPGateway,
    ToolAnnotations,
    anchor_tool_meta,
    verify_execution_receipt,
)
from anchor_v1.store import (
    AuthorizationDenied,
    CapabilityStore,
    DoubleSpendError,
    UnknownCapabilityError,
)

NOW = datetime.now(timezone.utc)
POLICY_REF = "constitution-hash-abc"
ARGS = {"path": "/tmp/x", "mode": "r"}


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def authority_signer() -> Ed25519Signer:
    return Ed25519Signer.generate("authority-1")


@pytest.fixture
def holder_signer() -> Ed25519Signer:
    return Ed25519Signer.generate("holder-1")


@pytest.fixture
def gateway_signer() -> Ed25519Signer:
    return Ed25519Signer.generate("gateway-1")


@pytest.fixture
def store() -> CapabilityStore:
    s = CapabilityStore()
    # Fresh revocation view: consume_capability fails closed on a stale view.
    s.sync_revocations()
    return s


@pytest.fixture
def trusted(authority_signer: Ed25519Signer) -> dict:
    return {
        authority_signer.key_id.encode("utf-8"): Ed25519PublicKey.from_public_bytes(
            authority_signer.public_key_bytes()
        )
    }


@pytest.fixture
def backend() -> InMemoryMCPBackend:
    return InMemoryMCPBackend({"files.read": lambda args: {"content": "ok"}})


@pytest.fixture
def gateway(
    gateway_signer: Ed25519Signer,
    store: CapabilityStore,
    trusted: dict,
    backend: InMemoryMCPBackend,
) -> NativeMCPGateway:
    g = NativeMCPGateway(
        gateway_signer=gateway_signer,
        store=store,
        trusted_issuers=trusted,
        policy_ref=POLICY_REF,
    )
    g.register_tool("fs", "files.read", description="Read a file", backend=backend)
    return g


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def mint_capability(
    *,
    gateway: NativeMCPGateway,
    store: CapabilityStore,
    authority_signer: Ed25519Signer,
    holder_signer: Ed25519Signer,
    trusted: dict,
    tool_name: str = "files.read",
    args: dict | None = None,
    now: datetime = NOW,
    ttl: timedelta = timedelta(minutes=15),
    plane: str | None = None,
):
    """Mint a one-use execution capability for ``tool_name``/``args`` and
    register it with the store. Returns (envelope, cose, payload).

    With plane=None the envelope is built by ``gateway.build_envelope`` (the
    documented flow); with plane set, a hand-built envelope for that plane
    is used (for cross-plane replay tests).
    """
    args = dict(ARGS) if args is None else args
    if plane is None:
        envelope = gateway.build_envelope(tool_name, args, now=now)
        target = "fs"
    else:
        envelope = ActionEnvelope(
            action_id=uuid.uuid4(),
            principal="mcp-agent",
            effect=Effect(
                plane=plane,
                verb=tool_name,
                target="fs",
                args_digest=sha256_hex(args),
            ),
            policy_ref=POLICY_REF,
            issued_at=now,
            not_before=now,
            not_after=now + timedelta(minutes=5),
            nonce=secrets.token_hex(16),
        )
    cose = authority.issue_execution(
        authority_signer,
        action_digest=envelope.action_digest,
        holder_pubkey=holder_signer.public_key_bytes(),
        ttl=ttl,
        now=now,
    )
    payload = authority.verify_capability(cose, trusted, now=now)
    store.register_capability(payload)
    return envelope, cose, payload


def call_materials(holder_signer: Ed25519Signer, payload):
    """Fresh challenge + holder proof bound to the capability id."""
    challenge = os.urandom(32)
    proof = authority.make_holder_proof(holder_signer, payload.capability_id, challenge)
    return challenge, proof


def authorized_call(
    *,
    gateway: NativeMCPGateway,
    store: CapabilityStore,
    authority_signer: Ed25519Signer,
    holder_signer: Ed25519Signer,
    trusted: dict,
    tool_name: str = "files.read",
    args: dict | None = None,
    now: datetime = NOW,
    request_id=2,
):
    """Full authorized tools/call through the real envelope binding.

    Mints against ``gateway.build_envelope`` and presents the SAME envelope
    to ``tools_call`` — the documented flow, no stubs.
    """
    args = dict(ARGS) if args is None else args
    envelope, cose, payload = mint_capability(
        gateway=gateway,
        store=store,
        authority_signer=authority_signer,
        holder_signer=holder_signer,
        trusted=trusted,
        tool_name=tool_name,
        args=args,
        now=now,
    )
    challenge, proof = call_materials(holder_signer, payload)
    result = gateway.tools_call(
        tool_name=tool_name,
        arguments=args,
        capability_cose=cose,
        holder_proof=proof,
        challenge=challenge,
        envelope=envelope,
        request_id=request_id,
        now=now,
    )
    return result, payload, cose


def assert_denied(excinfo, *, tool_name, reason):
    err = excinfo.value
    assert isinstance(err, MCPDeniedError)
    assert err.tool_name == tool_name
    assert err.reason == reason


# ---------------------------------------------------------------------------
# A. registration
# ---------------------------------------------------------------------------


class TestRegistration:
    def test_register_tool_happy_path(self, gateway):
        assert "files.read" in gateway.registered_tool_names
        entry = gateway.tools_list()["result"]["tools"][0]
        assert entry["name"] == "files.read"
        assert entry["title"] == "files.read"  # default title = name
        assert entry["description"] == "Read a file"
        assert entry["inputSchema"] == {"type": "object"}

    @pytest.mark.parametrize("bad_name", ["bad name!", "", "a" * 129, "x/y", "tool;drop"])
    def test_register_tool_invalid_names_rejected(self, gateway, bad_name):
        with pytest.raises(ValueError):
            gateway.register_tool("fs", bad_name)

    def test_register_tool_duplicate_rejected(self, gateway, backend):
        with pytest.raises(ValueError, match="already registered"):
            gateway.register_tool("fs", "files.read", backend=backend)

    def test_register_tool_requires_server_id(self, gateway):
        with pytest.raises(ValueError):
            gateway.register_tool("", "new.tool")

    @pytest.mark.parametrize("bad_backend", ["not-a-backend", object(), 42])
    def test_register_tool_backend_must_be_mcpbackend(self, gateway, bad_backend):
        with pytest.raises(ValueError, match="MCPBackend"):
            gateway.register_tool("fs", "new.tool", backend=bad_backend)

    def test_register_tool_default_backend_is_inmemory(self, gateway):
        gateway.register_tool("fs", "plain.tool")
        entry = gateway.tools_list()["result"]["tools"]
        assert "plain.tool" in [t["name"] for t in entry]

    def test_register_tool_input_schema_must_be_dict(self, gateway):
        with pytest.raises(ValueError):
            gateway.register_tool("fs", "new.tool", input_schema=["not", "a", "dict"])

    def test_tools_list_meta_anchor_declaration(self, gateway, gateway_signer):
        entry = gateway.tools_list()["result"]["tools"][0]
        anchor = entry["_meta"]["anchor"]
        assert anchor["enforced"] is True
        assert anchor["policy_ref"] == POLICY_REF
        assert anchor["gateway_key_id"] == gateway_signer.key_id
        assert anchor["capability"] == "holder-of-key-one-use"

    def test_anchor_tool_meta_standalone(self, gateway_signer):
        meta = anchor_tool_meta(policy_ref=POLICY_REF, gateway_key_id=gateway_signer.key_id)
        assert meta["anchor"]["enforced"] is True
        assert meta["anchor"]["policy_ref"] == POLICY_REF
        assert meta["anchor"]["gateway_key_id"] == gateway_signer.key_id
        assert meta["anchor"]["capability"] == "holder-of-key-one-use"

    def test_tools_list_sorted_deterministically(self, gateway):
        for name in ["zeta.op", "alpha.op", "mike.op"]:
            gateway.register_tool("s", name)
        names = [t["name"] for t in gateway.tools_list()["result"]["tools"]]
        assert names == sorted(names)
        assert names == ["alpha.op", "files.read", "mike.op", "zeta.op"]


# ---------------------------------------------------------------------------
# B. pagination
# ---------------------------------------------------------------------------


@pytest.fixture
def five_tool_gateway(gateway: NativeMCPGateway) -> NativeMCPGateway:
    for name in ["zeta.op", "alpha.op", "mike.op", "beta.op", "gamma.op"]:
        gateway.register_tool("s", name)
    return gateway


class TestPagination:
    def test_walk_pages_via_next_cursor(self, five_tool_gateway):
        seen: list[str] = []
        cursor = None
        pages = 0
        while True:
            resp = five_tool_gateway.tools_list(cursor=cursor, page_size=2)
            assert resp["jsonrpc"] == "2.0"
            page_names = [t["name"] for t in resp["result"]["tools"]]
            seen.extend(page_names)
            pages += 1
            cursor = resp["result"].get("nextCursor")
            if cursor is None:
                break
            # cursor is opaque: not a bare offset string
            assert isinstance(cursor, str) and "offset" not in cursor
        assert pages == 3
        assert seen == sorted(seen)  # sorted order preserved across pages
        assert len(set(seen)) == 6  # no duplicates
        assert set(seen) == {
            "files.read",
            "alpha.op",
            "beta.op",
            "gamma.op",
            "mike.op",
            "zeta.op",
        }

    def test_last_page_has_no_next_cursor(self, five_tool_gateway):
        first = five_tool_gateway.tools_list(page_size=2)
        second = five_tool_gateway.tools_list(
            cursor=first["result"]["nextCursor"], page_size=2
        )
        third = five_tool_gateway.tools_list(
            cursor=second["result"]["nextCursor"], page_size=2
        )
        assert "nextCursor" in first["result"]
        assert "nextCursor" in second["result"]
        assert "nextCursor" not in third["result"]
        assert [t["name"] for t in third["result"]["tools"]] == ["mike.op", "zeta.op"]

    def test_single_page_default_has_no_next_cursor(self, five_tool_gateway):
        resp = five_tool_gateway.tools_list()
        assert len(resp["result"]["tools"]) == 6
        assert "nextCursor" not in resp["result"]

    def test_request_id_passthrough(self, five_tool_gateway):
        resp = five_tool_gateway.tools_list(request_id=99)
        assert resp["id"] == 99
        assert resp["jsonrpc"] == "2.0"

    @pytest.mark.parametrize(
        "bad_cursor", ["!!not-base64!!", "offset:-1", "", "offset:abc", "offset:"]
    )
    def test_invalid_cursor_rejected(self, five_tool_gateway, bad_cursor):
        with pytest.raises(MCPGatewayError, match="cursor"):
            five_tool_gateway.tools_list(cursor=bad_cursor)

    def test_cursor_past_end_rejected(self, five_tool_gateway):
        past_end = base64.urlsafe_b64encode(b"offset:999").decode("ascii")
        with pytest.raises(MCPGatewayError, match="past the end"):
            five_tool_gateway.tools_list(cursor=past_end)

    def test_cursor_at_exact_end_returns_empty_page(self, five_tool_gateway):
        at_end = base64.urlsafe_b64encode(b"offset:6").decode("ascii")
        resp = five_tool_gateway.tools_list(cursor=at_end)
        assert resp["result"]["tools"] == []
        assert "nextCursor" not in resp["result"]

    @pytest.mark.parametrize("bad_size", [0, -1, 1001, "x", True, None])
    def test_bad_page_size_rejected(self, five_tool_gateway, bad_size):
        with pytest.raises(MCPGatewayError, match="page_size"):
            five_tool_gateway.tools_list(page_size=bad_size)

    def test_page_size_one_walks_every_tool(self, five_tool_gateway):
        names = []
        cursor = None
        while True:
            resp = five_tool_gateway.tools_list(cursor=cursor, page_size=1)
            names.extend(t["name"] for t in resp["result"]["tools"])
            cursor = resp["result"].get("nextCursor")
            if cursor is None:
                break
        assert names == ["alpha.op", "beta.op", "files.read", "gamma.op", "mike.op", "zeta.op"]


# ---------------------------------------------------------------------------
# C. tools/call happy path (post-authorization behavior; binding stubbed)
# ---------------------------------------------------------------------------


class TestToolsCallHappyPath:
    def test_result_shape(
        self, monkeypatch, gateway, store, authority_signer, holder_signer, trusted
    ):
        result, _, _ = authorized_call(
            gateway=gateway,
            store=store,
            authority_signer=authority_signer,
            holder_signer=holder_signer,
            trusted=trusted,
            request_id=7,
        )
        assert result["jsonrpc"] == "2.0"
        assert result["id"] == 7
        body = result["result"]
        assert body["isError"] is False
        assert body["content"] == [
            {"type": "text", "text": '{"content":"ok"}'}
        ]
        assert body["structuredContent"] == {"content": "ok"}
        assert body["_meta"]["anchor"]["enforced"] is True
        assert body["_meta"]["anchor"]["policy_ref"] == POLICY_REF
        receipt = body["_meta"]["anchor"]["receipt"]
        assert isinstance(receipt["signature"], str) and receipt["signature"]

    def test_receipt_verifies_and_fields(
        self, monkeypatch, gateway, store, authority_signer, holder_signer,
        trusted, gateway_signer,
    ):
        result, payload, _ = authorized_call(
            gateway=gateway,
            store=store,
            authority_signer=authority_signer,
            holder_signer=holder_signer,
            trusted=trusted,
        )
        receipt_dict = result["result"]["_meta"]["anchor"]["receipt"]
        receipt = verify_execution_receipt(
            receipt_dict, gateway_signer.public_key_bytes()
        )
        assert isinstance(receipt, ExecutionReceipt)
        assert receipt.tool_name == "files.read"
        assert receipt.server_id == "fs"
        assert receipt.args_digest == sha256_hex(ARGS)
        assert receipt.result_digest == sha256_hex({"content": "ok"})
        assert receipt.capability_id == payload.capability_id
        assert receipt.is_error is False
        assert receipt.gateway_key_id == gateway_signer.key_id
        assert receipt.executed_at == NOW

    def test_backend_receives_authorized_args(
        self, monkeypatch, gateway, store, authority_signer, holder_signer,
        trusted, backend,
    ):
        args = {"path": "/tmp/x", "mode": "r"}
        authorized_call(
            gateway=gateway,
            store=store,
            authority_signer=authority_signer,
            holder_signer=holder_signer,
            trusted=trusted,
            args=args,
        )
        assert backend.calls == [("files.read", args)]


# ---------------------------------------------------------------------------
# D. every deny path
# ---------------------------------------------------------------------------


class TestDenyPaths:
    def test_unknown_tool_denied_and_nothing_consumed(
        self, gateway, store, authority_signer, holder_signer, trusted, backend
    ):
        # Mint a VALID capability for the registered tool, then call an
        # unregistered one: the gateway must deny before touching anything.
        _, cose, payload = mint_capability(
            gateway=gateway,
            store=store,
            authority_signer=authority_signer,
            holder_signer=holder_signer,
            trusted=trusted,
        )
        challenge, proof = call_materials(holder_signer, payload)
        with pytest.raises(MCPDeniedError) as excinfo:
            gateway.tools_call(
                tool_name="nope.tool",
                arguments=dict(ARGS),
                capability_cose=cose,
                holder_proof=proof,
                challenge=challenge,
                now=NOW,
            )
        assert_denied(excinfo, tool_name="nope.tool", reason="unknown-tool")
        assert backend.calls == []
        assert store.capability_state(payload.capability_id) == "ISSUED"

    def test_no_capability_denied(self, gateway):
        envelope = gateway.build_envelope("files.read", dict(ARGS), now=NOW)
        with pytest.raises(MCPDeniedError) as excinfo:
            gateway.tools_call(
                tool_name="files.read",
                arguments=dict(ARGS),
                capability_cose=None,
                holder_proof=None,
                challenge=None,
                envelope=envelope,
                now=NOW,
            )
        assert_denied(excinfo, tool_name="files.read", reason="no-capability")

    def test_garbage_capability_denied(self, gateway):
        envelope = gateway.build_envelope("files.read", dict(ARGS), now=NOW)
        with pytest.raises(MCPDeniedError) as excinfo:
            gateway.tools_call(
                tool_name="files.read",
                arguments=dict(ARGS),
                capability_cose=b"\xff\xfe not cose",
                holder_proof=b"\x00" * 64,
                challenge=os.urandom(32),
                envelope=envelope,
                now=NOW,
            )
        assert_denied(excinfo, tool_name="files.read", reason="bad-capability")

    def test_capability_from_unknown_issuer_denied(
        self, gateway, store, holder_signer, trusted
    ):
        rogue = Ed25519Signer.generate("rogue-authority")
        env = gateway.build_envelope("files.read", dict(ARGS), now=NOW)
        cose = authority.issue_execution(
            rogue,
            action_digest=env.action_digest,
            holder_pubkey=holder_signer.public_key_bytes(),
            now=NOW,
        )
        # Registered under its own id (the store doesn't care who signed),
        # but the gateway's trusted_issuers set rejects the signature.
        payload = authority.verify_capability(
            cose,
            {rogue.key_id.encode(): Ed25519PublicKey.from_public_bytes(
                rogue.public_key_bytes())},
            now=NOW,
        )
        store.register_capability(payload)
        challenge, proof = call_materials(holder_signer, payload)
        with pytest.raises(MCPDeniedError) as excinfo:
            gateway.tools_call(
                tool_name="files.read",
                arguments=dict(ARGS),
                capability_cose=cose,
                holder_proof=proof,
                challenge=challenge,
                envelope=env,
                now=NOW,
            )
        assert_denied(excinfo, tool_name="files.read", reason="bad-capability")

    @pytest.mark.parametrize("which", ["proof", "challenge", "both"])
    def test_missing_holder_proof_denied(
        self, gateway, store, authority_signer, holder_signer, trusted, which
    ):
        env, cose, payload = mint_capability(
            gateway=gateway,
            store=store,
            authority_signer=authority_signer,
            holder_signer=holder_signer,
            trusted=trusted,
        )
        challenge, proof = call_materials(holder_signer, payload)
        with pytest.raises(MCPDeniedError) as excinfo:
            gateway.tools_call(
                tool_name="files.read",
                arguments=dict(ARGS),
                capability_cose=cose,
                holder_proof=None if which in ("proof", "both") else proof,
                challenge=None if which in ("challenge", "both") else challenge,
                envelope=env,
                now=NOW,
            )
        assert_denied(excinfo, tool_name="files.read", reason="no-holder-proof")

    def test_holder_proof_wrong_key_denied(
        self, gateway, store, authority_signer, holder_signer, trusted
    ):
        env, cose, payload = mint_capability(
            gateway=gateway,
            store=store,
            authority_signer=authority_signer,
            holder_signer=holder_signer,
            trusted=trusted,
        )
        impostor = Ed25519Signer.generate("impostor")
        challenge = os.urandom(32)
        bad_proof = authority.make_holder_proof(
            impostor, payload.capability_id, challenge
        )
        with pytest.raises(MCPDeniedError) as excinfo:
            gateway.tools_call(
                tool_name="files.read",
                arguments=dict(ARGS),
                capability_cose=cose,
                holder_proof=bad_proof,
                challenge=challenge,
                envelope=env,
                now=NOW,
            )
        assert_denied(excinfo, tool_name="files.read", reason="bad-proof")
        # The capability was not consumed by the failed proof.
        assert store.capability_state(payload.capability_id) == "ISSUED"

    def test_holder_proof_for_different_capability_denied(
        self, gateway, store, authority_signer, holder_signer, trusted
    ):
        env, cose, payload = mint_capability(
            gateway=gateway,
            store=store,
            authority_signer=authority_signer,
            holder_signer=holder_signer,
            trusted=trusted,
        )
        challenge = os.urandom(32)
        wrong_proof = authority.make_holder_proof(
            holder_signer, "capability-id-that-is-not-this", challenge
        )
        assert len(wrong_proof) == 64
        with pytest.raises(MCPDeniedError) as excinfo:
            gateway.tools_call(
                tool_name="files.read",
                arguments=dict(ARGS),
                capability_cose=cose,
                holder_proof=wrong_proof,
                challenge=challenge,
                envelope=env,
                now=NOW,
            )
        assert_denied(excinfo, tool_name="files.read", reason="bad-proof")

    def test_expired_capability_denied(
        self, gateway, authority_signer, holder_signer, trusted
    ):
        # ttl negative: expires_at <= issued_at -> structurally invalid; it
        # can never pass verify_capability, so the gateway denies at the
        # structural fast-fail (step 3) before the store is even reached.
        from anchor_v1.authority import CapabilityPayload
        from anchor_v1.cbor import cbor_loads
        from anchor_v1.cose import cose_verify

        env = gateway.build_envelope("files.read", dict(ARGS), now=NOW)
        cose = authority.issue_execution(
            authority_signer,
            action_digest=env.action_digest,
            holder_pubkey=holder_signer.public_key_bytes(),
            ttl=timedelta(seconds=-1),
            now=NOW,
        )
        # Decode WITHOUT the expiry check (signature + schema only) to get
        # the capability id for a well-formed holder proof.
        raw_payload, _kid = cose_verify(cose, trusted)
        payload = CapabilityPayload.model_validate(cbor_loads(raw_payload))
        challenge, proof = call_materials(holder_signer, payload)
        with pytest.raises(MCPDeniedError) as excinfo:
            gateway.tools_call(
                tool_name="files.read",
                arguments=dict(ARGS),
                capability_cose=cose,
                holder_proof=proof,
                challenge=challenge,
                envelope=env,
                now=NOW,
            )
        # Reason observed: "bad-capability" (verify_capability rejects before
        # the store is reached).
        assert_denied(excinfo, tool_name="files.read", reason="bad-capability")

    def test_expired_capability_far_future_now_denied(
        self, gateway, store, authority_signer, holder_signer, trusted
    ):
        env, cose, payload = mint_capability(
            gateway=gateway,
            store=store,
            authority_signer=authority_signer,
            holder_signer=holder_signer,
            trusted=trusted,
            ttl=timedelta(minutes=15),
        )
        challenge, proof = call_materials(holder_signer, payload)
        far_future = NOW + timedelta(hours=2)
        with pytest.raises(MCPDeniedError) as excinfo:
            gateway.tools_call(
                tool_name="files.read",
                arguments=dict(ARGS),
                capability_cose=cose,
                holder_proof=proof,
                challenge=challenge,
                envelope=env,
                now=far_future,
            )
        # The envelope's 5-minute validity window lapses before the
        # capability's 15-minute TTL, so the envelope gate fires first.
        assert_denied(excinfo, tool_name="files.read", reason="bad-envelope")

    def test_invalid_arguments_denied(self, gateway):
        with pytest.raises(MCPDeniedError) as excinfo:
            gateway.tools_call(
                tool_name="files.read",
                arguments="not-a-dict",
                capability_cose=None,
                holder_proof=None,
                challenge=None,
                now=NOW,
            )
        assert_denied(excinfo, tool_name="files.read", reason="invalid-arguments")

    def test_build_envelope_non_dict_args_rejected(self, gateway):
        with pytest.raises(MCPGatewayError):
            gateway.build_envelope("files.read", "not-a-dict", now=NOW)

    def test_args_tampered_post_approval_denied(
        self, gateway, store, authority_signer, holder_signer, trusted, backend
    ):
        # Capability minted for args A; call arrives with args B. The
        # presented envelope's args_digest no longer matches the call
        # arguments -> denied before the store is even reached.
        env, cose, payload = mint_capability(
            gateway=gateway,
            store=store,
            authority_signer=authority_signer,
            holder_signer=holder_signer,
            trusted=trusted,
            args={"path": "/tmp/a"},
        )
        challenge, proof = call_materials(holder_signer, payload)
        with pytest.raises(MCPDeniedError) as excinfo:
            gateway.tools_call(
                tool_name="files.read",
                arguments={"path": "/tmp/b"},
                capability_cose=cose,
                holder_proof=proof,
                challenge=challenge,
                envelope=env,
                now=NOW,
            )
        assert_denied(excinfo, tool_name="files.read", reason="bad-envelope")
        assert backend.calls == []
        # The capability was not consumed by the denied call.
        assert store.capability_state(payload.capability_id) == "ISSUED"

    def test_cross_plane_replay_denied(
        self, gateway, store, authority_signer, holder_signer, trusted, backend
    ):
        # Capability bound to an http-plane envelope digest (same verb/target/
        # args, different plane): the mcp-plane call must not honor it. The
        # gateway's plane check denies before the store is reached.
        env, cose, payload = mint_capability(
            gateway=gateway,
            store=store,
            authority_signer=authority_signer,
            holder_signer=holder_signer,
            trusted=trusted,
            plane="http",
        )
        assert env.effect.plane == "http"
        challenge, proof = call_materials(holder_signer, payload)
        with pytest.raises(MCPDeniedError) as excinfo:
            gateway.tools_call(
                tool_name="files.read",
                arguments=dict(ARGS),
                capability_cose=cose,
                holder_proof=proof,
                challenge=challenge,
                envelope=env,
                now=NOW,
            )
        assert_denied(excinfo, tool_name="files.read", reason="bad-envelope")
        assert backend.calls == []

    def test_store_level_one_use_double_spend_denied(
        self, gateway, store, authority_signer, holder_signer, trusted
    ):
        # The store itself enforces one-use: the same envelope object consumes
        # once; the second consume (same bytes, same proof) must fail.
        env, cose, payload = mint_capability(
            gateway=gateway,
            store=store,
            authority_signer=authority_signer,
            holder_signer=holder_signer,
            trusted=trusted,
        )
        challenge = os.urandom(32)
        proof = authority.make_holder_proof(holder_signer, payload.capability_id, challenge)
        consumed = store.consume_capability(
            capability_cose=cose,
            holder_proof=proof,
            challenge=challenge,
            trusted_issuers=trusted,
            envelope=env,
            now=NOW,
        )
        assert consumed.capability_id == payload.capability_id
        assert store.capability_state(payload.capability_id) == "CONSUMED"
        with pytest.raises(DoubleSpendError):
            store.consume_capability(
                capability_cose=cose,
                holder_proof=proof,
                challenge=challenge,
                trusted_issuers=trusted,
                envelope=env,
                now=NOW,
            )

    def test_store_level_unregistered_capability_denied(
        self, gateway, authority_signer, holder_signer, trusted
    ):
        # Capability never registered with the store: unknown id => deny.
        fresh_store = CapabilityStore()
        fresh_store.sync_revocations()
        env = gateway.build_envelope("files.read", dict(ARGS), now=NOW)
        cose = authority.issue_execution(
            authority_signer,
            action_digest=env.action_digest,
            holder_pubkey=holder_signer.public_key_bytes(),
            now=NOW,
        )
        payload = authority.verify_capability(cose, trusted, now=NOW)
        challenge, proof = call_materials(holder_signer, payload)
        with pytest.raises(UnknownCapabilityError):
            fresh_store.consume_capability(
                capability_cose=cose,
                holder_proof=proof,
                challenge=challenge,
                trusted_issuers=trusted,
                envelope=env,
                now=NOW,
            )

    def test_gateway_replay_second_call_denied(
        self, gateway, store, authority_signer, holder_signer, trusted, backend
    ):
        # One-use capability: the first authorized call succeeds and consumes
        # it; replaying the same capability+envelope denies with
        # consume-failed and never dispatches again.
        env, cose, payload = mint_capability(
            gateway=gateway,
            store=store,
            authority_signer=authority_signer,
            holder_signer=holder_signer,
            trusted=trusted,
        )
        challenge = os.urandom(32)
        proof = authority.make_holder_proof(holder_signer, payload.capability_id, challenge)
        kwargs = dict(
            tool_name="files.read",
            arguments=dict(ARGS),
            capability_cose=cose,
            holder_proof=proof,
            challenge=challenge,
            envelope=env,
            now=NOW,
        )
        result = gateway.tools_call(**kwargs)
        assert result["result"]["structuredContent"] == {"content": "ok"}
        assert store.capability_state(payload.capability_id) == "CONSUMED"
        with pytest.raises(MCPDeniedError) as excinfo:
            gateway.tools_call(**kwargs)
        assert_denied(excinfo, tool_name="files.read", reason="consume-failed")
        assert backend.calls == [("files.read", dict(ARGS))]


# ---------------------------------------------------------------------------
# E. receipt tamper
# ---------------------------------------------------------------------------


@pytest.fixture
def signed_receipt_dict(
    monkeypatch, gateway, store, authority_signer, holder_signer, trusted
):
    result, _, _ = authorized_call(
        gateway=gateway,
        store=store,
        authority_signer=authority_signer,
        holder_signer=holder_signer,
        trusted=trusted,
    )
    return result["result"]["_meta"]["anchor"]["receipt"]


class TestReceiptTamper:
    def test_flip_result_digest_detected(self, signed_receipt_dict, gateway_signer):
        tampered = copy.deepcopy(signed_receipt_dict)
        digest = tampered["result_digest"]
        tampered["result_digest"] = ("0" if digest[0] != "0" else "1") + digest[1:]
        with pytest.raises(MCPGatewayError):
            verify_execution_receipt(tampered, gateway_signer.public_key_bytes())

    def test_flip_tool_name_detected(self, signed_receipt_dict, gateway_signer):
        tampered = copy.deepcopy(signed_receipt_dict)
        tampered["tool_name"] = "files.write"
        with pytest.raises(MCPGatewayError):
            verify_execution_receipt(tampered, gateway_signer.public_key_bytes())

    def test_blank_tool_name_rejected(self, signed_receipt_dict, gateway_signer):
        tampered = copy.deepcopy(signed_receipt_dict)
        tampered["tool_name"] = ""
        with pytest.raises(MCPGatewayError):
            verify_execution_receipt(tampered, gateway_signer.public_key_bytes())

    def test_missing_signature_rejected(self, signed_receipt_dict, gateway_signer):
        tampered = copy.deepcopy(signed_receipt_dict)
        del tampered["signature"]
        with pytest.raises(MCPGatewayError, match="[Ss]ignature"):
            verify_execution_receipt(tampered, gateway_signer.public_key_bytes())

    def test_wrong_gateway_pubkey_rejected(self, signed_receipt_dict):
        other = Ed25519Signer.generate("other-gateway")
        with pytest.raises(MCPGatewayError):
            verify_execution_receipt(signed_receipt_dict, other.public_key_bytes())

    def test_non_dict_receipt_rejected(self, gateway_signer):
        with pytest.raises(MCPGatewayError):
            verify_execution_receipt("not-a-dict", gateway_signer.public_key_bytes())
        with pytest.raises(MCPGatewayError):
            verify_execution_receipt(None, gateway_signer.public_key_bytes())

    def test_bad_base64_signature_rejected(self, signed_receipt_dict, gateway_signer):
        tampered = copy.deepcopy(signed_receipt_dict)
        tampered["signature"] = "!!!not-base64!!!"
        with pytest.raises(MCPGatewayError, match="base64"):
            verify_execution_receipt(tampered, gateway_signer.public_key_bytes())

    def test_short_pubkey_rejected(self, signed_receipt_dict):
        with pytest.raises(MCPGatewayError):
            verify_execution_receipt(signed_receipt_dict, b"\x01" * 31)


# ---------------------------------------------------------------------------
# F. backend behavior
# ---------------------------------------------------------------------------


class TestBackendBehavior:
    def test_backend_exception_becomes_iserror_result(
        self, monkeypatch, gateway, store, authority_signer, holder_signer,
        trusted, backend, gateway_signer,
    ):
        def boom(args):
            raise RuntimeError("disk on fire")

        backend.register_handler("boom.tool", boom)
        gateway.register_tool("s", "boom.tool", backend=backend)
        result, _, _ = authorized_call(
            gateway=gateway,
            store=store,
            authority_signer=authority_signer,
            holder_signer=holder_signer,
            trusted=trusted,
            tool_name="boom.tool",
            args={"x": 1},
        )
        body = result["result"]
        assert body["isError"] is True
        assert body["structuredContent"] == {"error": "RuntimeError: disk on fire"}
        assert json.loads(body["content"][0]["text"]) == {
            "error": "RuntimeError: disk on fire"
        }
        # The failure is recorded on the receipt: never silent.
        receipt = verify_execution_receipt(
            body["_meta"]["anchor"]["receipt"], gateway_signer.public_key_bytes()
        )
        assert receipt.is_error is True
        assert receipt.tool_name == "boom.tool"

    def test_backend_non_dict_result_raises(
        self, monkeypatch, gateway, store, authority_signer, holder_signer,
        trusted, backend,
    ):
        backend.register_handler("weird.tool", lambda args: "a string, not a dict")
        gateway.register_tool("s", "weird.tool", backend=backend)
        with pytest.raises(MCPGatewayError, match="result dict"):
            authorized_call(
                gateway=gateway,
                store=store,
                authority_signer=authority_signer,
                holder_signer=holder_signer,
                trusted=trusted,
                tool_name="weird.tool",
            )

    def test_backend_audit_trail_records_calls(
        self, monkeypatch, gateway, store, authority_signer, holder_signer,
        trusted, backend,
    ):
        authorized_call(
            gateway=gateway,
            store=store,
            authority_signer=authority_signer,
            holder_signer=holder_signer,
            trusted=trusted,
            args={"path": "/a"},
        )
        assert backend.calls == [("files.read", {"path": "/a"})]

    def test_backend_args_isolation_deep_copy(
        self, monkeypatch, gateway, store, authority_signer, holder_signer,
        trusted, backend,
    ):
        def mutating(args):
            args["injected"] = True  # top-level mutation of the handler's copy
            args["path"] = "/evil"
            return {"ok": True}

        backend.register_handler("mut.tool", mutating)
        gateway.register_tool("s", "mut.tool", backend=backend)
        caller_args = {"path": "/a", "nested": {"x": 0}}
        authorized_call(
            gateway=gateway,
            store=store,
            authority_signer=authority_signer,
            holder_signer=holder_signer,
            trusted=trusted,
            tool_name="mut.tool",
            args=caller_args,
        )
        # The caller's dict is untouched: the backend got a deep copy.
        assert caller_args == {"path": "/a", "nested": {"x": 0}}
        # The audit trail reflects the dispatched (pre-mutation) snapshot.
        assert backend.calls == [("mut.tool", {"path": "/a", "nested": {"x": 0}})]

    def test_backend_without_handler_echoes(
        self, monkeypatch, gateway, store, authority_signer, holder_signer, trusted
    ):
        gateway.register_tool("s", "echo.tool")  # default in-memory backend
        result, _, _ = authorized_call(
            gateway=gateway,
            store=store,
            authority_signer=authority_signer,
            holder_signer=holder_signer,
            trusted=trusted,
            tool_name="echo.tool",
            args={"k": "v"},
        )
        assert result["result"]["structuredContent"] == {"echo": {"k": "v"}}
        assert result["result"]["isError"] is False


# ---------------------------------------------------------------------------
# G. envelope binding
#
# `build_envelope` stamps a fresh random action_id and nonce into every
# envelope, and ActionEnvelope.action_digest covers the WHOLE canonical
# envelope. `store.consume_capability` compares that full digest to the
# capability's bound digest — so `tools_call` must be presented with the
# EXACT envelope the issuer minted the capability against (it can never
# rebuild it). These tests pin that contract: the happy path threads the
# envelope through, and every envelope/call mismatch denies fail-closed.
# ---------------------------------------------------------------------------


class TestEnvelopeBinding:
    def test_build_envelope_digests_differ_across_builds(self, gateway):
        # action_digest covers action_id + nonce, so two builds of the "same"
        # action are never digest-equal.
        e1 = gateway.build_envelope("files.read", dict(ARGS), now=NOW)
        e2 = gateway.build_envelope("files.read", dict(ARGS), now=NOW)
        assert e1.action_digest != e2.action_digest
        assert e1.action_id != e2.action_id
        assert e1.nonce != e2.nonce

    def test_args_digest_binds_canonical_args(self, gateway):
        e1 = gateway.build_envelope("files.read", {"b": 2, "a": 1}, now=NOW)
        e2 = gateway.build_envelope("files.read", {"a": 1, "b": 2}, now=NOW)
        # Key order does not change the args digest (canonical encoding).
        assert e1.effect.args_digest == e2.effect.args_digest
        assert e1.effect.args_digest == sha256_hex({"a": 1, "b": 2})

    def test_build_envelope_shape(self, gateway):
        e = gateway.build_envelope("files.read", dict(ARGS), now=NOW)
        assert e.effect.plane == "mcp"
        assert e.effect.verb == "files.read"
        assert e.effect.target == "fs"
        assert e.policy_ref == POLICY_REF
        assert e.principal == "mcp-agent"

    def test_build_envelope_unknown_tool_target_unknown(self, gateway):
        e = gateway.build_envelope("ghost.tool", dict(ARGS), now=NOW)
        assert e.effect.target == "unknown"

    def test_happy_path_authorized_call_succeeds(
        self, gateway, store, authority_signer, holder_signer, trusted,
        backend, gateway_signer,
    ):
        # The documented flow: mint against build_envelope, then tools_call
        # presenting the SAME envelope. The store's digest binding matches,
        # the backend dispatches exactly once, and the signed receipt
        # verifies under the gateway key.
        env, cose, payload = mint_capability(
            gateway=gateway,
            store=store,
            authority_signer=authority_signer,
            holder_signer=holder_signer,
            trusted=trusted,
        )
        challenge, proof = call_materials(holder_signer, payload)
        result = gateway.tools_call(
            tool_name="files.read",
            arguments=dict(ARGS),
            capability_cose=cose,
            holder_proof=proof,
            challenge=challenge,
            envelope=env,
            now=NOW,
        )
        body = result["result"]
        assert body["structuredContent"] == {"content": "ok"}
        assert body["isError"] is False
        assert backend.calls == [("files.read", dict(ARGS))]
        assert store.capability_state(payload.capability_id) == "CONSUMED"
        receipt = verify_execution_receipt(
            body["_meta"]["anchor"]["receipt"], gateway_signer.public_key_bytes()
        )
        assert receipt.tool_name == "files.read"
        assert receipt.capability_id == payload.capability_id
        assert receipt.args_digest == sha256_hex(ARGS)

    def test_happy_path_envelope_as_dict_accepted(
        self, gateway, store, authority_signer, holder_signer, trusted, backend
    ):
        # The envelope may arrive as a plain dict (e.g. over the wire); the
        # gateway validates it into an ActionEnvelope.
        env, cose, payload = mint_capability(
            gateway=gateway,
            store=store,
            authority_signer=authority_signer,
            holder_signer=holder_signer,
            trusted=trusted,
        )
        challenge, proof = call_materials(holder_signer, payload)
        result = gateway.tools_call(
            tool_name="files.read",
            arguments=dict(ARGS),
            capability_cose=cose,
            holder_proof=proof,
            challenge=challenge,
            envelope=env.model_dump(mode="json"),
            now=NOW,
        )
        assert result["result"]["structuredContent"] == {"content": "ok"}
        assert backend.calls == [("files.read", dict(ARGS))]

    def test_store_binding_compares_full_envelope_digest(
        self, gateway, store, authority_signer, holder_signer, trusted
    ):
        # Same args, same tool — but a REBUILT envelope has a different digest
        # (fresh action_id/nonce) and fails the store's envelope binding.
        # This is why the gateway must be presented with the exact envelope
        # the capability was minted against, never a rebuild.
        _, cose, payload = mint_capability(
            gateway=gateway,
            store=store,
            authority_signer=authority_signer,
            holder_signer=holder_signer,
            trusted=trusted,
        )
        other_envelope = gateway.build_envelope("files.read", dict(ARGS), now=NOW)
        challenge = os.urandom(32)
        proof = authority.make_holder_proof(
            holder_signer, payload.capability_id, challenge
        )
        with pytest.raises(AuthorizationDenied, match="does not match"):
            store.consume_capability(
                capability_cose=cose,
                holder_proof=proof,
                challenge=challenge,
                trusted_issuers=trusted,
                envelope=other_envelope,
                now=NOW,
            )

    def test_no_envelope_denied(
        self, gateway, store, authority_signer, holder_signer, trusted, backend
    ):
        # The envelope is required: without it the gateway cannot check the
        # capability binding, so it denies instead of rebuilding.
        _, cose, payload = mint_capability(
            gateway=gateway,
            store=store,
            authority_signer=authority_signer,
            holder_signer=holder_signer,
            trusted=trusted,
        )
        challenge, proof = call_materials(holder_signer, payload)
        with pytest.raises(MCPDeniedError) as excinfo:
            gateway.tools_call(
                tool_name="files.read",
                arguments=dict(ARGS),
                capability_cose=cose,
                holder_proof=proof,
                challenge=challenge,
                now=NOW,
            )
        assert_denied(excinfo, tool_name="files.read", reason="no-envelope")
        assert backend.calls == []
        assert store.capability_state(payload.capability_id) == "ISSUED"

    def test_envelope_wrong_type_denied(
        self, gateway, store, authority_signer, holder_signer, trusted, backend
    ):
        _, cose, payload = mint_capability(
            gateway=gateway,
            store=store,
            authority_signer=authority_signer,
            holder_signer=holder_signer,
            trusted=trusted,
        )
        challenge, proof = call_materials(holder_signer, payload)
        with pytest.raises(MCPDeniedError) as excinfo:
            gateway.tools_call(
                tool_name="files.read",
                arguments=dict(ARGS),
                capability_cose=cose,
                holder_proof=proof,
                challenge=challenge,
                envelope="not-an-envelope",
                now=NOW,
            )
        assert_denied(excinfo, tool_name="files.read", reason="bad-envelope")
        assert backend.calls == []

    def test_envelope_verb_mismatch_denied(
        self, gateway, store, authority_signer, holder_signer, trusted, backend
    ):
        # Envelope minted for files.read, presented for other.tool.
        env, cose, payload = mint_capability(
            gateway=gateway,
            store=store,
            authority_signer=authority_signer,
            holder_signer=holder_signer,
            trusted=trusted,
        )
        gateway.register_tool("s", "other.tool")
        challenge, proof = call_materials(holder_signer, payload)
        with pytest.raises(MCPDeniedError) as excinfo:
            gateway.tools_call(
                tool_name="other.tool",
                arguments=dict(ARGS),
                capability_cose=cose,
                holder_proof=proof,
                challenge=challenge,
                envelope=env,
                now=NOW,
            )
        assert_denied(excinfo, tool_name="other.tool", reason="bad-envelope")
        assert backend.calls == []

    def test_envelope_target_mismatch_denied(
        self, gateway, store, authority_signer, holder_signer, trusted, backend
    ):
        # Envelope bound to a different server id than the registered tool's.
        env = ActionEnvelope(
            action_id=uuid.uuid4(),
            principal="mcp-agent",
            effect=Effect(
                plane="mcp",
                verb="files.read",
                target="wrong-server",
                args_digest=sha256_hex(ARGS),
            ),
            policy_ref=POLICY_REF,
            issued_at=NOW,
            not_before=NOW,
            not_after=NOW + timedelta(minutes=5),
            nonce=secrets.token_hex(16),
        )
        cose = authority.issue_execution(
            authority_signer,
            action_digest=env.action_digest,
            holder_pubkey=holder_signer.public_key_bytes(),
            now=NOW,
        )
        payload = authority.verify_capability(cose, trusted, now=NOW)
        store.register_capability(payload)
        challenge, proof = call_materials(holder_signer, payload)
        with pytest.raises(MCPDeniedError) as excinfo:
            gateway.tools_call(
                tool_name="files.read",
                arguments=dict(ARGS),
                capability_cose=cose,
                holder_proof=proof,
                challenge=challenge,
                envelope=env,
                now=NOW,
            )
        assert_denied(excinfo, tool_name="files.read", reason="bad-envelope")
        assert backend.calls == []

    def test_envelope_principal_mismatch_denied(
        self, gateway, store, authority_signer, holder_signer, trusted, backend
    ):
        env = ActionEnvelope(
            action_id=uuid.uuid4(),
            principal="someone-else",
            effect=Effect(
                plane="mcp",
                verb="files.read",
                target="fs",
                args_digest=sha256_hex(ARGS),
            ),
            policy_ref=POLICY_REF,
            issued_at=NOW,
            not_before=NOW,
            not_after=NOW + timedelta(minutes=5),
            nonce=secrets.token_hex(16),
        )
        cose = authority.issue_execution(
            authority_signer,
            action_digest=env.action_digest,
            holder_pubkey=holder_signer.public_key_bytes(),
            now=NOW,
        )
        payload = authority.verify_capability(cose, trusted, now=NOW)
        store.register_capability(payload)
        challenge, proof = call_materials(holder_signer, payload)
        with pytest.raises(MCPDeniedError) as excinfo:
            gateway.tools_call(
                tool_name="files.read",
                arguments=dict(ARGS),
                capability_cose=cose,
                holder_proof=proof,
                challenge=challenge,
                envelope=env,
                now=NOW,
            )
        assert_denied(excinfo, tool_name="files.read", reason="bad-envelope")
        assert backend.calls == []

    def test_envelope_policy_ref_mismatch_denied(
        self, gateway, store, authority_signer, holder_signer, trusted, backend
    ):
        env = ActionEnvelope(
            action_id=uuid.uuid4(),
            principal="mcp-agent",
            effect=Effect(
                plane="mcp",
                verb="files.read",
                target="fs",
                args_digest=sha256_hex(ARGS),
            ),
            policy_ref="some-other-policy",
            issued_at=NOW,
            not_before=NOW,
            not_after=NOW + timedelta(minutes=5),
            nonce=secrets.token_hex(16),
        )
        cose = authority.issue_execution(
            authority_signer,
            action_digest=env.action_digest,
            holder_pubkey=holder_signer.public_key_bytes(),
            now=NOW,
        )
        payload = authority.verify_capability(cose, trusted, now=NOW)
        store.register_capability(payload)
        challenge, proof = call_materials(holder_signer, payload)
        with pytest.raises(MCPDeniedError) as excinfo:
            gateway.tools_call(
                tool_name="files.read",
                arguments=dict(ARGS),
                capability_cose=cose,
                holder_proof=proof,
                challenge=challenge,
                envelope=env,
                now=NOW,
            )
        assert_denied(excinfo, tool_name="files.read", reason="bad-envelope")
        assert backend.calls == []

    def test_envelope_expired_window_denied(
        self, gateway, store, authority_signer, holder_signer, trusted, backend
    ):
        # Capability still valid (15 min TTL) but the envelope's 5-minute
        # window has lapsed -> denied.
        env, cose, payload = mint_capability(
            gateway=gateway,
            store=store,
            authority_signer=authority_signer,
            holder_signer=holder_signer,
            trusted=trusted,
            ttl=timedelta(minutes=15),
        )
        challenge, proof = call_materials(holder_signer, payload)
        with pytest.raises(MCPDeniedError) as excinfo:
            gateway.tools_call(
                tool_name="files.read",
                arguments=dict(ARGS),
                capability_cose=cose,
                holder_proof=proof,
                challenge=challenge,
                envelope=env,
                now=NOW + timedelta(minutes=10),
            )
        assert_denied(excinfo, tool_name="files.read", reason="bad-envelope")
        assert backend.calls == []
        assert store.capability_state(payload.capability_id) == "ISSUED"

    def test_envelope_swapped_post_issuance_denied(
        self, gateway, store, authority_signer, holder_signer, trusted, backend
    ):
        # Same tool, same args, same principal/policy — but a DIFFERENT
        # envelope (fresh action_id/nonce) than the capability was minted
        # against. The gateway's field checks pass; the store's digest
        # binding catches the swap.
        env, cose, payload = mint_capability(
            gateway=gateway,
            store=store,
            authority_signer=authority_signer,
            holder_signer=holder_signer,
            trusted=trusted,
        )
        swapped = gateway.build_envelope("files.read", dict(ARGS), now=NOW)
        assert swapped.action_digest != env.action_digest
        challenge, proof = call_materials(holder_signer, payload)
        with pytest.raises(MCPDeniedError) as excinfo:
            gateway.tools_call(
                tool_name="files.read",
                arguments=dict(ARGS),
                capability_cose=cose,
                holder_proof=proof,
                challenge=challenge,
                envelope=swapped,
                now=NOW,
            )
        assert_denied(excinfo, tool_name="files.read", reason="consume-failed")
        assert backend.calls == []
        assert store.capability_state(payload.capability_id) == "ISSUED"


# ---------------------------------------------------------------------------
# H. annotations are advisory
# ---------------------------------------------------------------------------


class TestAnnotationsAdvisory:
    def test_destructive_hint_does_not_block(
        self, monkeypatch, gateway, store, authority_signer, holder_signer, trusted
    ):
        gateway.register_tool(
            "s",
            "wipe.disk",
            annotations={"destructiveHint": True, "readOnlyHint": False},
        )
        result, _, _ = authorized_call(
            gateway=gateway,
            store=store,
            authority_signer=authority_signer,
            holder_signer=holder_signer,
            trusted=trusted,
            tool_name="wipe.disk",
            args={},
        )
        # Hints are never authorization: the call is allowed like any other.
        assert result["result"]["isError"] is False
        entry = [
            t
            for t in gateway.tools_list()["result"]["tools"]
            if t["name"] == "wipe.disk"
        ][0]
        assert entry["annotations"]["destructiveHint"] is True
        # ...and hints stay OUT of the enforcement declaration.
        assert "destructiveHint" not in entry["_meta"]["anchor"]

    def test_annotations_model_instance_accepted(self, gateway):
        gateway.register_tool(
            "s",
            "ann.tool",
            annotations=ToolAnnotations(
                title="Ann", readOnlyHint=True, idempotentHint=True
            ),
        )
        entry = [
            t
            for t in gateway.tools_list()["result"]["tools"]
            if t["name"] == "ann.tool"
        ][0]
        assert entry["title"] == "Ann"
        assert entry["annotations"]["readOnlyHint"] is True
        assert entry["annotations"]["idempotentHint"] is True

    def test_annotations_defaults(self, gateway):
        entry = gateway.tools_list()["result"]["tools"][0]
        assert entry["annotations"]["readOnlyHint"] is False
        assert entry["annotations"]["destructiveHint"] is False
        assert entry["annotations"]["idempotentHint"] is False
        assert entry["annotations"]["openWorldHint"] is True

    @pytest.mark.parametrize(
        "bad_annotations",
        [{"readOnlyHint": [1, 2]}, {"bogusHint": True}, "not-a-mapping"],
    )
    def test_invalid_annotations_rejected(self, gateway, bad_annotations):
        with pytest.raises(ValueError, match="annotations"):
            gateway.register_tool(
                "s", "badann.tool", annotations=bad_annotations
            )
