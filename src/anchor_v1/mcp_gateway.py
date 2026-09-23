"""ANCHOR v1 — native MCP gateway (Wave 3, Revision B pivot 14; blocker 5).

Two gateways live here:

* ``MCPGateway`` — the v0 capability-7 gateway (moved verbatim from
  ``anchor_v1.planes`` during the Wave 3 reframe). It gates MCP tool calls
  through the shared ``DecisionGovernor`` core. ``anchor_v1.planes``
  re-exports it so existing callers keep working.
* ``NativeMCPGateway`` — the NEW native MCP shim. It speaks the MCP
  2026-07-28 wire shapes and enforces ANCHOR's holder-of-key capability
  discipline on every ``tools/call``.

MCP 2026-07-28 wire shapes implemented here (grounded in the spec):

* ``tools/list`` — JSON-RPC ``{"jsonrpc": "2.0", "id": N, "method":
  "tools/list", "params": {"cursor": ...}}``; response ``result.tools[]``
  entries carry ``name`` / ``title`` / ``description`` / ``inputSchema`` /
  ``outputSchema?`` / ``annotations`` / ``_meta``, plus ``nextCursor`` when
  paginating. Servers SHOULD return tools in deterministic order and MUST
  NOT vary the set per-connection.
* ``tools/call`` — JSON-RPC ``{"jsonrpc": "2.0", "id": N, "method":
  "tools/call", "params": {"name": ..., "arguments": {...}, "_meta": ...}}``;
  response ``result`` carries ``content[]`` / ``structuredContent?`` /
  ``isError``. Unknown tools are PROTOCOL errors (fail closed).
* Tool ``annotations``: ``title``, ``readOnlyHint``, ``destructiveHint``,
  ``idempotentHint``, ``openWorldHint`` (hints are advisory only — they are
  never authorization).

Spec source: https://modelcontextprotocol.io/specification/draft/server/tools
(fetched 2026-09-23; the 2026-07-28 revision page). The 2026-07-28 revision
is stateless (no ``initialize`` handshake, no ``Mcp-Session-Id``); every
request is self-contained, which is exactly what a capability-per-call
gateway wants.

ANCHOR enforcement declaration: every tool in ``tools/list`` carries
``_meta: {"anchor": {"enforced": true, "policy_ref": ..., "gateway_key_id":
..., "capability": "holder-of-key-one-use"}}``. A client can verify BEFORE
calling that the tool is governor-enforced.

``tools/call`` interception (fail-closed ordering):

1. Unknown tool -> deny. No capability is consumed, nothing is dispatched.
2. Build the canonical ``ActionEnvelope``: plane ``"mcp"``, verb = tool
   name, target = server id, ``args_digest`` = SHA-256 over the canonical
   argument encoding.
3. ``authority.verify_capability`` (structural fast-fail) then
   ``authority.verify_holder_proof`` (proof-of-possession fast-fail).
4. ``store.consume_capability`` — atomic verify + revocation/epoch check +
   holder-proof check + one-use consume + envelope digest binding. An args
   digest that does not match the capability's bound digest (args tampered
   post-approval) or a capability minted for another plane (cross-plane
   replay: the digest binds ``plane="mcp"``) -> deny, NO dispatch.
5. Dispatch to the pluggable ``MCPBackend``. Backend failures become
   ``isError: true`` tool results (per the spec's tool-execution-error
   reporting), never silent success.
6. Sign an execution receipt (tool name, args digest, result digest,
   capability id, timestamp, gateway key id) with the gateway key.
   ``verify_execution_receipt`` detects any tampering offline.

Local only. No network calls. The backend connector is in-process.
"""

from __future__ import annotations

import base64
import copy
import json
import re
import secrets
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import Field, field_validator

from . import authority
from .authority import CapabilityError
from .canonical import canonical_bytes, sha256_hex
from .crypto import Ed25519Signer
from .envelope import ActionEnvelope, Effect
from .models import SignedEnvelope, StrictModel
from .planes import (
    DecisionDeniedError,
    DecisionGovernor,
    decide,
    evaluate_plane,
    verify_decision,
)
from .store import AuthorizationDenied, CapabilityStore, StoreError

__all__ = [
    # spec grounding
    "MCP_SPEC_URL",
    "MCP_PROTOCOL_VERSION",
    # legacy v0 gateway (moved from planes.py)
    "MCPGateway",
    # native gateway errors
    "MCPGatewayError",
    "MCPDeniedError",
    # backend connector
    "MCPBackend",
    "InMemoryMCPBackend",
    # native gateway
    "ToolAnnotations",
    "NativeMCPGateway",
    "anchor_tool_meta",
    # execution receipts
    "ExecutionReceipt",
    "verify_execution_receipt",
]

#: The MCP specification page the wire shapes below are grounded in.
MCP_SPEC_URL = "https://modelcontextprotocol.io/specification/draft/server/tools"

_PAGE_SIZE_DEFAULT = 100
_PAGE_SIZE_MAX = 1000


def _encode_cursor(offset: int) -> str:
    """Opaque pagination cursor encoding a tool-list offset."""
    return base64.urlsafe_b64encode(f"offset:{offset}".encode("utf-8")).decode("ascii")


def _decode_cursor(cursor: str) -> int:
    """Decode a ``tools/list`` cursor, fail closed on anything malformed."""
    if not isinstance(cursor, str) or not cursor:
        raise MCPGatewayError("invalid tools/list cursor")
    try:
        raw = base64.urlsafe_b64decode(cursor.encode("ascii")).decode("utf-8")
        if not raw.startswith("offset:"):
            raise ValueError("bad cursor prefix")
        offset = int(raw.split(":", 1)[1])
    except Exception as exc:
        raise MCPGatewayError(f"invalid tools/list cursor: {exc}") from exc
    if offset < 0:
        raise MCPGatewayError("invalid tools/list cursor: negative offset")
    return offset
#: The MCP protocol revision this shim targets (stateless, no sessions).
MCP_PROTOCOL_VERSION = "2026-07-28"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Legacy v0 MCP gateway — moved verbatim from anchor_v1.planes (Wave 3 reframe)
# ---------------------------------------------------------------------------


class MCPGateway:
    """Policy gateway for MCP tool calls: one policy vocabulary, same as shell.

    A tool call maps to action ``mcp.tool.<server>.<tool>`` with the resource
    taken from the tool's declared resource scope. Tools not present in the
    registered registry are DENY by default — fail closed, no implicit tools.
    """

    def __init__(self, *, governor: DecisionGovernor) -> None:
        self.governor = governor
        self._tools: dict[str, dict[str, Any]] = {}

    def register_tool(
        self,
        server_name: str,
        tool_name: str,
        *,
        resource_scope: str,
        description: str = "",
    ) -> None:
        """Register a tool the gateway is allowed to consider. Unregistered
        tools can never be invoked through this gateway."""
        if not server_name or not tool_name or not resource_scope:
            raise ValueError("server_name, tool_name and resource_scope are required")
        self._tools[f"{server_name}/{tool_name}"] = {
            "server": server_name,
            "tool": tool_name,
            "resource_scope": resource_scope,
            "description": description,
        }

    @property
    def registered_tools(self) -> tuple[str, ...]:
        return tuple(sorted(self._tools))

    def handle_tool_call(
        self,
        server_name: str,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        capability_envelope: SignedEnvelope | None,
        holder_proof: SignedEnvelope | None,
        now: datetime | None = None,
    ) -> SignedEnvelope:
        """Gate one MCP tool call. Returns the signed ALLOW decision.

        On DENY or APPROVAL_REQUIRED raises DecisionDeniedError carrying the
        signed decision, so the denial itself is auditable offline.
        """
        key = f"{server_name}/{tool_name}"
        spec = self._tools.get(key)
        if spec is None:
            # Fail closed before any token is even considered: there is no
            # capability that can authorize an unregistered tool.
            signed = decide(
                plane="mcp",
                subject="unknown",
                action=f"mcp.tool.{server_name}.{tool_name}",
                resource="unregistered",
                invocation_params=arguments,
                constitution=self.governor.constitution,
                governor=self.governor,
                capability_envelope=None,
                holder_proof=None,
                now=now,
            )
            raise DecisionDeniedError(
                f"unregistered MCP tool: {server_name}.{tool_name} (fail closed)",
                signed_decision=signed,
                decision=verify_decision(signed, self.governor.governor_pubkey_bytes),
            )
        action = f"mcp.tool.{server_name}.{tool_name}"
        resource = spec["resource_scope"]
        signed = evaluate_plane(
            self.governor,
            "mcp",
            subject="mcp-holder",
            action=action,
            resource=resource,
            invocation_params=arguments,
            capability_envelope=capability_envelope,
            holder_proof=holder_proof,
            now=now,
        )
        decision = verify_decision(signed, self.governor.governor_pubkey_bytes)
        if decision.verdict != "ALLOW":
            raise DecisionDeniedError(
                f"MCP tool call {decision.verdict}: {server_name}.{tool_name}",
                signed_decision=signed,
                decision=decision,
            )
        return signed


# ---------------------------------------------------------------------------
# Native gateway errors
# ---------------------------------------------------------------------------


class MCPGatewayError(Exception):
    """Base class for native MCP gateway failures."""


class MCPDeniedError(MCPGatewayError):
    """Fail-closed denial of a tools/call: unknown tool, bad capability,
    digest mismatch, replay, or any other authorization failure. The backend
    is never dispatched on this path."""

    def __init__(self, message: str, *, tool_name: str | None = None, reason: str = "") -> None:
        super().__init__(message)
        self.tool_name = tool_name
        self.reason = reason or message


# ---------------------------------------------------------------------------
# Backend connector (pluggable)
# ---------------------------------------------------------------------------


class MCPBackend(ABC):
    """Pluggable tool-execution connector.

    The gateway authorizes; the backend executes. Implementations may wrap a
    real MCP server (stdio, Streamable HTTP) — this module ships only the
    in-memory test backend, so there are no network calls here.
    """

    @abstractmethod
    def call_tool(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        """Execute ``name`` with ``args``. Returns a JSON-serializable result
        dict. May raise on tool execution failure (surfaced as an
        ``isError`` result, never as silent success)."""


class InMemoryMCPBackend(MCPBackend):
    """In-memory test backend: handler registry plus an audit trail.

    Tools without an explicit handler get a deterministic echo result, so
    the gateway path can be exercised without wiring handlers for every
    registered tool.
    """

    def __init__(
        self, handlers: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] | None = None
    ) -> None:
        self._handlers: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = dict(
            handlers or {}
        )
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def register_handler(
        self, name: str, handler: Callable[[dict[str, Any]], dict[str, Any]]
    ) -> None:
        self._handlers[name] = handler

    def call_tool(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        # Deep-copy: the backend must not be able to mutate the authorized
        # arguments, and the audit trail must reflect what was dispatched.
        snapshot = copy.deepcopy(args)
        self.calls.append((name, snapshot))
        handler = self._handlers.get(name)
        if handler is None:
            return {"echo": snapshot}
        return handler(dict(snapshot))


# ---------------------------------------------------------------------------
# Tool inventory: annotations + ANCHOR enforcement declaration
# ---------------------------------------------------------------------------

_TOOL_NAME_RE = re.compile(r"[A-Za-z0-9_.\-]{1,128}")


class ToolAnnotations(StrictModel):
    """MCP tool annotations (spec: title + behavioral hints).

    Hints are ADVISORY — they describe the tool for clients and models.
    They are never authorization; ANCHOR enforcement is declared separately
    in ``_meta.anchor``.
    """

    title: str | None = None
    readOnlyHint: bool = False
    destructiveHint: bool = False
    idempotentHint: bool = False
    openWorldHint: bool = True


def anchor_tool_meta(*, policy_ref: str, gateway_key_id: str) -> dict[str, Any]:
    """The ``_meta.anchor`` enforcement declaration attached to every tool in
    ``tools/list``. A client can verify BEFORE calling that the tool is
    governor-enforced and under which policy."""
    return {
        "anchor": {
            "enforced": True,
            "policy_ref": policy_ref,
            "gateway_key_id": gateway_key_id,
            "capability": "holder-of-key-one-use",
            "mcp_protocol": MCP_PROTOCOL_VERSION,
        }
    }


class _ToolRegistration:
    """Internal inventory record: spec fields + the executing backend."""

    def __init__(
        self,
        *,
        server_id: str,
        name: str,
        description: str,
        input_schema: dict[str, Any],
        annotations: ToolAnnotations,
        backend: MCPBackend,
    ) -> None:
        self.server_id = server_id
        self.name = name
        self.description = description
        self.input_schema = input_schema
        self.annotations = annotations
        self.backend = backend


# ---------------------------------------------------------------------------
# Execution receipts
# ---------------------------------------------------------------------------


class ExecutionReceipt(StrictModel):
    """Signed evidence of one authorized tool execution.

    Binds the tool name, the canonical args digest, the result digest, the
    consumed capability id, and the timestamp. ``is_error`` marks executions
    whose backend raised (reported as ``isError`` results, never silent).
    """

    receipt_id: str = Field(min_length=1)
    tool_name: str = Field(min_length=1)
    server_id: str = Field(min_length=1)
    args_digest: str = Field(min_length=64, max_length=64)
    result_digest: str = Field(min_length=64, max_length=64)
    capability_id: str = Field(min_length=1)
    executed_at: datetime
    gateway_key_id: str = Field(min_length=1)
    is_error: bool = False

    @field_validator("executed_at")
    @classmethod
    def _tz_aware(cls, v: datetime) -> datetime:
        if not isinstance(v, datetime) or v.tzinfo is None:
            raise ValueError("executed_at must be timezone-aware")
        return v.astimezone(timezone.utc)


def verify_execution_receipt(
    signed_receipt: dict[str, Any], gateway_pubkey: bytes
) -> ExecutionReceipt:
    """Offline verification of a signed execution receipt.

    Any tampering — including a flipped ``result_digest`` — invalidates the
    Ed25519 signature over the canonical receipt bytes and raises
    ``MCPGatewayError``. Returns the verified receipt.
    """
    if not isinstance(signed_receipt, dict):
        raise MCPGatewayError("receipt must be a mapping")
    raw = dict(signed_receipt)
    sig_b64 = raw.pop("signature", None)
    if not sig_b64 or not isinstance(sig_b64, str):
        raise MCPGatewayError("receipt has no signature — untrusted")
    try:
        receipt = ExecutionReceipt.model_validate(raw)
    except Exception as exc:
        raise MCPGatewayError(f"receipt body malformed: {exc}") from exc
    try:
        signature = base64.b64decode(sig_b64, validate=True)
    except Exception as exc:
        raise MCPGatewayError(f"receipt signature is not valid base64: {exc}") from exc
    if len(gateway_pubkey) != 32:
        raise MCPGatewayError("gateway_pubkey must be 32 raw Ed25519 bytes")
    key = Ed25519PublicKey.from_public_bytes(bytes(gateway_pubkey))
    try:
        key.verify(signature, canonical_bytes(receipt.model_dump(mode="json")))
    except InvalidSignature as exc:
        raise MCPGatewayError(
            "execution receipt signature invalid — receipt was tampered with"
        ) from exc
    return receipt


# ---------------------------------------------------------------------------
# NativeMCPGateway — the Wave 3 native shim
# ---------------------------------------------------------------------------


class NativeMCPGateway:
    """Native MCP 2026-07-28 gateway shim with holder-of-key enforcement.

    ``tools/list`` advertises the inventory with ANCHOR enforcement declared
    in each tool's ``_meta.anchor``. ``tools/call`` intercepts every
    invocation: the caller presents the exact ``ActionEnvelope`` the
    capability was minted against (plane ``"mcp"``, verb = tool name,
    target = server id, ``args_digest`` = SHA-256 of the canonical args);
    the gateway validates that envelope against the call, then requires a
    consumed holder-of-key capability via ``store.consume_capability`` +
    ``authority.verify_holder_proof`` BEFORE dispatching, and signs an
    execution receipt with the gateway key.

    The envelope cannot be rebuilt at call time: ``ActionEnvelope.
    action_digest`` covers the whole canonical envelope, including the
    random ``action_id`` and ``nonce``, so a rebuilt envelope never matches
    the minted binding. The caller carries the authorized envelope from
    issuance to invocation; the store's digest comparison is the
    cryptographic binding, and the gateway's field checks give precise
    deny reasons for envelope/call mismatches.

    Denials raise ``MCPDeniedError`` and never dispatch to the backend.
    """

    def __init__(
        self,
        *,
        gateway_signer: Ed25519Signer,
        store: CapabilityStore,
        trusted_issuers: Mapping[bytes, Ed25519PublicKey],
        policy_ref: str,
        principal: str = "mcp-agent",
    ) -> None:
        if not policy_ref:
            raise ValueError("policy_ref is required")
        if not principal:
            raise ValueError("principal is required")
        self._signer = gateway_signer
        self._store = store
        self._trusted_issuers = dict(trusted_issuers)
        if not self._trusted_issuers:
            raise ValueError("trusted_issuers must be non-empty")
        self._policy_ref = policy_ref
        self._principal = principal
        self._tools: dict[str, _ToolRegistration] = {}

    # -- inventory ------------------------------------------------------

    def register_tool(
        self,
        server_id: str,
        tool_name: str,
        *,
        description: str = "",
        input_schema: dict[str, Any] | None = None,
        annotations: dict[str, Any] | ToolAnnotations | None = None,
        backend: MCPBackend | None = None,
    ) -> None:
        """Register a tool. Names follow the spec (1-128 chars,
        ``[A-Za-z0-9_.-]``, case-sensitive, unique within the gateway);
        duplicates and invalid names are rejected — fail closed at
        registration time, not at call time."""
        if not server_id:
            raise ValueError("server_id is required")
        if not isinstance(tool_name, str) or not _TOOL_NAME_RE.fullmatch(tool_name):
            raise ValueError(
                f"invalid tool name {tool_name!r}: must match [A-Za-z0-9_.-]{{1,128}}"
            )
        if tool_name in self._tools:
            raise ValueError(f"tool {tool_name!r} is already registered")
        schema = {"type": "object"} if input_schema is None else input_schema
        if not isinstance(schema, dict):
            raise ValueError("input_schema must be a JSON Schema object (dict)")
        if isinstance(annotations, ToolAnnotations):
            ann = annotations
        else:
            try:
                ann = ToolAnnotations.model_validate(annotations or {})
            except Exception as exc:
                raise ValueError(f"invalid tool annotations: {exc}") from exc
        if backend is not None and not isinstance(backend, MCPBackend):
            raise ValueError("backend must be an MCPBackend")
        self._tools[tool_name] = _ToolRegistration(
            server_id=server_id,
            name=tool_name,
            description=description,
            input_schema=schema,
            annotations=ann,
            backend=backend if backend is not None else InMemoryMCPBackend(),
        )

    @property
    def registered_tool_names(self) -> tuple[str, ...]:
        return tuple(sorted(self._tools))

    def tools_list(
        self,
        *,
        request_id: Any = 1,
        cursor: str | None = None,
        page_size: int = _PAGE_SIZE_DEFAULT,
    ) -> dict[str, Any]:
        """Answer an MCP ``tools/list`` request.

        Returns the JSON-RPC response: ``result.tools`` in deterministic
        (sorted) order per the spec's caching guidance, each tool carrying
        its ``_meta.anchor`` enforcement declaration. When the inventory
        exceeds ``page_size``, ``result.nextCursor`` carries an opaque
        cursor; pass it back as ``cursor`` to walk the remaining pages.
        The inventory is stable across pages (sorted order, no per-page
        variation).
        """
        if isinstance(page_size, bool) or not isinstance(page_size, int):
            raise MCPGatewayError("page_size must be an integer")
        if page_size < 1 or page_size > _PAGE_SIZE_MAX:
            raise MCPGatewayError(
                f"page_size must be between 1 and {_PAGE_SIZE_MAX}"
            )
        names = sorted(self._tools)
        start = _decode_cursor(cursor) if cursor is not None else 0
        if start > len(names):
            raise MCPGatewayError("tools/list cursor is past the end of the inventory")
        tools: list[dict[str, Any]] = []
        for name in names[start : start + page_size]:
            reg = self._tools[name]
            tools.append(
                {
                    "name": reg.name,
                    "title": reg.annotations.title or reg.name,
                    "description": reg.description,
                    "inputSchema": reg.input_schema,
                    "annotations": reg.annotations.model_dump(exclude_none=True),
                    "_meta": anchor_tool_meta(
                        policy_ref=self._policy_ref,
                        gateway_key_id=self._signer.key_id,
                    ),
                }
            )
        result: dict[str, Any] = {"tools": tools}
        if start + page_size < len(names):
            result["nextCursor"] = _encode_cursor(start + page_size)
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    # -- envelope construction (shared by issuers and the call path) ----

    def build_envelope(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        now: datetime | None = None,
    ) -> ActionEnvelope:
        """Build the canonical ``ActionEnvelope`` for a tool invocation.

        plane ``"mcp"``, verb = tool name, target = server id,
        ``args_digest`` = SHA-256 over the canonical argument encoding.
        Capability issuers mint against ``envelope.action_digest``; the
        caller presents this SAME envelope object to ``tools_call`` — the
        gateway cannot rebuild it, because ``action_digest`` covers the
        random ``action_id`` and ``nonce``. Any post-approval argument
        tampering changes ``args_digest`` and denies at call time.
        """
        if not isinstance(arguments, dict):
            raise MCPGatewayError("tools/call arguments must be an object")
        moment = now if now is not None else _utcnow()
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        reg = self._tools.get(tool_name)
        return ActionEnvelope(
            action_id=uuid.uuid4(),
            principal=self._principal,
            effect=Effect(
                plane="mcp",
                verb=tool_name,
                target=reg.server_id if reg is not None else "unknown",
                args_digest=sha256_hex(arguments),
            ),
            policy_ref=self._policy_ref,
            issued_at=moment,
            not_before=moment,
            not_after=moment + timedelta(minutes=5),
            nonce=secrets.token_hex(16),
        )

    # -- envelope resolution (caller presents the authorized envelope) --

    def _resolve_call_envelope(
        self,
        *,
        tool_name: str,
        arguments: dict[str, Any],
        envelope: ActionEnvelope | dict[str, Any] | None,
        now: datetime,
    ) -> ActionEnvelope:
        """Validate the caller-presented ``ActionEnvelope`` for this call.

        The capability authorizes exactly one envelope: its
        ``action_digest`` binds the full canonical envelope, including the
        random ``action_id`` and ``nonce``. The gateway cannot rebuild that
        envelope — a fresh build always has a different digest — so the
        caller presents the exact envelope the issuer minted the capability
        against. This method checks the presented envelope describes THIS
        call; the store's digest comparison then provides the cryptographic
        binding to the capability. Any mismatch -> ``MCPDeniedError``
        (fail closed, nothing dispatched).
        """
        reg = self._tools[tool_name]  # validated by the caller before this runs
        if envelope is None:
            raise MCPDeniedError(
                "no envelope presented: the caller must present the exact "
                "ActionEnvelope the capability was minted against",
                tool_name=tool_name,
                reason="no-envelope",
            )
        if isinstance(envelope, dict):
            try:
                envelope = ActionEnvelope.model_validate(envelope)
            except Exception as exc:
                raise MCPDeniedError(
                    f"envelope is not a valid ActionEnvelope: {exc}",
                    tool_name=tool_name,
                    reason="bad-envelope",
                ) from exc
        if not isinstance(envelope, ActionEnvelope):
            raise MCPDeniedError(
                "envelope must be an ActionEnvelope",
                tool_name=tool_name,
                reason="bad-envelope",
            )
        effect = envelope.effect
        if effect.plane != "mcp":
            raise MCPDeniedError(
                f"envelope plane {effect.plane!r} is not 'mcp': cross-plane "
                "replay denied",
                tool_name=tool_name,
                reason="bad-envelope",
            )
        if effect.verb != tool_name:
            raise MCPDeniedError(
                f"envelope verb {effect.verb!r} does not match called tool "
                f"{tool_name!r}",
                tool_name=tool_name,
                reason="bad-envelope",
            )
        if effect.target != reg.server_id:
            raise MCPDeniedError(
                f"envelope target {effect.target!r} does not match registered "
                f"server {reg.server_id!r}",
                tool_name=tool_name,
                reason="bad-envelope",
            )
        if effect.args_digest != sha256_hex(arguments):
            raise MCPDeniedError(
                "envelope args_digest does not match the call arguments: "
                "post-approval argument tampering denied",
                tool_name=tool_name,
                reason="bad-envelope",
            )
        if envelope.principal != self._principal:
            raise MCPDeniedError(
                f"envelope principal {envelope.principal!r} does not match "
                f"this gateway's principal {self._principal!r}",
                tool_name=tool_name,
                reason="bad-envelope",
            )
        if envelope.policy_ref != self._policy_ref:
            raise MCPDeniedError(
                "envelope policy_ref does not match this gateway's policy",
                tool_name=tool_name,
                reason="bad-envelope",
            )
        if not (envelope.not_before <= now <= envelope.not_after):
            raise MCPDeniedError(
                "envelope is outside its validity window",
                tool_name=tool_name,
                reason="bad-envelope",
            )
        return envelope

    # -- tools/call interception -----------------------------------------

    def tools_call(
        self,
        *,
        tool_name: str,
        arguments: dict[str, Any],
        capability_cose: bytes | None,
        holder_proof: bytes | None,
        challenge: bytes | None,
        envelope: ActionEnvelope | dict[str, Any] | None = None,
        request_id: Any = 2,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Intercept an MCP ``tools/call``. Returns the JSON-RPC result.

        Fail-closed ordering: unknown tool -> deny (no consume, no
        dispatch); invalid arguments -> deny; envelope/call mismatch ->
        deny; bad capability or holder proof -> deny; digest mismatch
        (envelope swapped post-issuance) -> deny via the store's envelope
        binding. Only then is the backend dispatched, and the signed
        execution receipt returned in ``result._meta.anchor.receipt``.

        ``envelope`` is the exact ``ActionEnvelope`` the capability was
        minted against (see ``build_envelope``); it is required.
        """
        moment = now if now is not None else _utcnow()
        reg = self._tools.get(tool_name)
        if reg is None:
            # Unknown tool: deny BEFORE any capability is touched. There is
            # no capability that can authorize a tool the gateway never
            # registered (spec: unknown tool is a protocol error).
            raise MCPDeniedError(
                f"unknown MCP tool: {tool_name!r} (fail closed)",
                tool_name=tool_name,
                reason="unknown-tool",
            )
        if not isinstance(arguments, dict):
            raise MCPDeniedError(
                "tools/call arguments must be an object",
                tool_name=tool_name,
                reason="invalid-arguments",
            )
        # (2b) the caller presents the exact envelope the capability was
        # minted against; it must describe this call.
        envelope = self._resolve_call_envelope(
            tool_name=tool_name,
            arguments=arguments,
            envelope=envelope,
            now=moment,
        )

        # (3) structural fast-fail: the capability must parse and verify.
        if not capability_cose:
            raise MCPDeniedError(
                "no capability presented", tool_name=tool_name, reason="no-capability"
            )
        try:
            payload = authority.verify_capability(
                bytes(capability_cose), self._trusted_issuers, now=moment
            )
        except CapabilityError as exc:
            raise MCPDeniedError(
                f"capability verification failed: {exc}",
                tool_name=tool_name,
                reason="bad-capability",
            ) from exc

        # (4) holder-of-key fast-fail: proof-of-possession before consumption.
        if not holder_proof or not challenge:
            raise MCPDeniedError(
                "holder proof and challenge are required",
                tool_name=tool_name,
                reason="no-holder-proof",
            )
        try:
            authority.verify_holder_proof(
                bytes(payload.holder_pubkey),
                payload.capability_id,
                bytes(challenge),
                bytes(holder_proof),
            )
        except CapabilityError as exc:
            raise MCPDeniedError(
                f"holder proof failed: {exc}", tool_name=tool_name, reason="bad-proof"
            ) from exc

        # (5) atomic consume + envelope digest binding. The presented
        # envelope already describes this call (checked above); here the
        # store verifies its digest equals the capability's bound digest —
        # an envelope swapped post-issuance (same tool/args, different
        # action_id/nonce) raises here and NOTHING is dispatched.
        try:
            consumed = self._store.consume_capability(
                capability_cose=bytes(capability_cose),
                holder_proof=bytes(holder_proof),
                challenge=bytes(challenge),
                trusted_issuers=self._trusted_issuers,
                envelope=envelope,
                now=moment,
            )
        except (AuthorizationDenied, StoreError, CapabilityError) as exc:
            raise MCPDeniedError(
                f"capability consumption failed: {exc}",
                tool_name=tool_name,
                reason="consume-failed",
            ) from exc

        # (6) dispatch — authorization is complete; only now may the tool run.
        is_error = False
        try:
            result = reg.backend.call_tool(tool_name, arguments)
        except Exception as exc:  # tool execution errors -> isError result
            is_error = True
            result = {"error": f"{type(exc).__name__}: {exc}"}
        if not isinstance(result, dict):
            raise MCPGatewayError("backend must return a result dict")

        # (7) signed execution receipt.
        receipt = ExecutionReceipt(
            receipt_id=f"rcpt_{secrets.token_hex(12)}",
            tool_name=tool_name,
            server_id=reg.server_id,
            args_digest=envelope.effect.args_digest,
            result_digest=sha256_hex(result),
            capability_id=consumed.capability_id,
            executed_at=moment,
            gateway_key_id=self._signer.key_id,
            is_error=is_error,
        )
        signed_receipt = receipt.model_dump(mode="json")
        signed_receipt["signature"] = base64.b64encode(
            self._signer.sign_bytes(canonical_bytes(receipt.model_dump(mode="json")))
        ).decode("ascii")

        text = json.dumps(result, sort_keys=True, separators=(",", ":"))
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "content": [{"type": "text", "text": text}],
                "structuredContent": result,
                "isError": is_error,
                "_meta": {
                    "anchor": {
                        "enforced": True,
                        "policy_ref": self._policy_ref,
                        "receipt": signed_receipt,
                    }
                },
            },
        }
