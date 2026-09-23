"""ANCHOR v1 — ACS Guardian (Wave 0, blocker 4).

The hardened OWASP ACS Guardian: an external authority that intercepts agent
lifecycle events over the wire and answers allow/deny/modify/ask/defer.

Where the reference ACS Guardian is weak (no wire auth, fail-open default,
2/19 hooks live), this one is:

  * **Wire-authenticated** — every frame is HMAC-signed under a pre-shared
    key with a fresh nonce and a timestamp window (replay protection).
  * **Fail-closed** — guardian error, decision-function exception, decision
    timeout, malformed frame, bad HMAC, stale timestamp, unknown event type,
    or an event on a disabled hook ALL produce DENY. There is no fail-open
    path in this module; the test suite asserts that property behaviorally.
  * **Full hook coverage** — all 9 lifecycle hooks below are live and
    explicit; disabled hooks are not silently skipped.

One authority primitive: **every ALLOW mints a one-use holder-of-key
capability** via ``authority.issue_execution``, bound to the
``action_digest`` of a canonical ``ActionEnvelope`` built from the event
(``plane="acs"``, ``verb=event.action``, ``target=event.resource``,
``args_digest=sha256(canonical(params))``). The capability is a COSE_Sign1
object bound to the subject's registered holder public key — presenting the
COSE bytes alone is never enough; the holder must also prove possession of
the holder key per request. There are no two execution paths
(easy→direct, hard→capability): the capability IS the authorization. An
ALLOW decision without a minted capability is impossible by construction —
the mint step failing turns the decision into DENY.

Holder keys are an out-of-band registry (``holder_keys`` constructor arg,
subject → 32-byte Ed25519 public key; the SPIFFE/OIDC adapters in Wave 5
will feed this). An unknown subject or a malformed holder key makes the
mint raise, which becomes DENY: fail closed, no bearer fallback.

Wire protocol (testable stand-in):
  * Frame: ``b"ACS1"`` magic + 4-byte big-endian body length + JSON body.
  * Body: ``{"v":1, "kind":"event"|"decision", "nonce":hex, "ts":iso8601,
    "payload":{...}, "hmac":hex}``.
  * ``hmac`` = HMAC-SHA256(psk, canonical_bytes({v,kind,nonce,ts,payload})).
  * Nonces are single-use per guardian (replays are DENY); timestamps must
    fall inside ``replay_window_s`` of the guardian clock.

  **Production note:** this HMAC-PSK wire auth is the testable stand-in for a
  mutually-authenticated channel. In production the transport MUST be mTLS
  (or a DPoP-bound channel) with the same nonce/timestamp replay discipline
  on top. The PSK here must never be a long-lived production credential.

Local only. No network calls. The ``WirePeer`` class is the test harness that
speaks the same bytes so tests exercise real framing/auth, not in-process
shortcuts.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import secrets
import struct
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from pydantic import Field

from .authority import CapabilityError, issue_execution
from .canonical import canonical_bytes, sha256_hex
from .cbor import CBORError, cbor_loads
from .crypto import Ed25519Signer
from .envelope import ActionEnvelope, Effect
from .models import StrictModel

__all__ = [
    "SESSION_START",
    "PRE_TOOL_CALL",
    "POST_TOOL_CALL",
    "PRE_DELEGATION",
    "HUMAN_APPROVAL_REQUEST",
    "POLICY_CHANGE",
    "FREEZE",
    "REVOCATION",
    "SESSION_END",
    "KNOWN_HOOKS",
    "Decision",
    "GuardianEvent",
    "DecisionResult",
    "GuardianDecision",
    "DecisionTimeoutError",
    "WireAuthError",
    "AcsGuardian",
    "WirePeer",
    "FRAME_MAGIC",
    "WIRE_VERSION",
    "MAX_FRAME_BYTES",
]

# ---------------------------------------------------------------------------
# lifecycle hooks + decisions
# ---------------------------------------------------------------------------

SESSION_START = "session_start"
PRE_TOOL_CALL = "pre_tool_call"
POST_TOOL_CALL = "post_tool_call"
PRE_DELEGATION = "pre_delegation"
HUMAN_APPROVAL_REQUEST = "human_approval_request"
POLICY_CHANGE = "policy_change"
FREEZE = "freeze"
REVOCATION = "revocation"
SESSION_END = "session_end"

#: The full lifecycle surface this Guardian intercepts. Unknown/undefined
#: event types are NOT in this tuple and are DENIED (fail closed).
KNOWN_HOOKS: tuple[str, ...] = (
    SESSION_START,
    PRE_TOOL_CALL,
    POST_TOOL_CALL,
    PRE_DELEGATION,
    HUMAN_APPROVAL_REQUEST,
    POLICY_CHANGE,
    FREEZE,
    REVOCATION,
    SESSION_END,
)

Decision = Literal["ALLOW", "DENY", "MODIFY", "ASK", "DEFER"]


class GuardianEvent(StrictModel):
    """One agent lifecycle event submitted to the Guardian."""

    event_id: str = Field(min_length=1)
    event_type: str = Field(min_length=1)  # unknown types -> DENY at the guardian
    session_id: str = Field(min_length=1)
    subject: str = Field(min_length=1)  # agent identity; holder binding of the capability
    action: str = Field(min_length=1)  # e.g. tool name for pre_tool_call
    resource: str = Field(min_length=1)
    params: dict[str, Any] = Field(default_factory=dict)  # exact invocation params
    audience: str | None = Field(default=None)  # enforcement point; defaults to guardian's
    ts: datetime


class DecisionResult(StrictModel):
    """Rich return value a decision function may produce.

    ``modified_params`` is REQUIRED for MODIFY (the capability is then bound
    to the modified digest). It is ignored for other decisions.
    """

    decision: Decision
    reason: str = ""
    modified_params: dict[str, Any] | None = None


class GuardianDecision(StrictModel):
    """The Guardian's answer. On ALLOW/MODIFY ``capability`` is ALWAYS set:
    the one-use holder-of-key ExecutionCapability (COSE_Sign1 bytes) that
    authorizes the exact action digest. There is no ALLOW-without-capability
    path."""

    event_id: str
    decision: Decision
    reason: str = ""
    capability: bytes | None = None
    modified_params: dict[str, Any] | None = None
    pending_id: str | None = None


class DecisionTimeoutError(Exception):
    """The pluggable decision function exceeded its time budget."""


class WireAuthError(Exception):
    """A received frame failed wire authentication (magic, length, HMAC,
    nonce, timestamp, or kind). The peer must treat the exchange as denied."""


# ---------------------------------------------------------------------------
# wire protocol
# ---------------------------------------------------------------------------

FRAME_MAGIC = b"ACS1"
WIRE_VERSION = 1
MAX_FRAME_BYTES = 1_000_000  # 1 MiB body cap; oversized frames are DENY
_KIND_EVENT = "event"
_KIND_DECISION = "decision"


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_wire_ts(value: Any) -> datetime:
    if not isinstance(value, str):
        raise WireAuthError("wire ts must be an ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(value)
    except (ValueError, TypeError) as exc:
        raise WireAuthError("wire ts is not valid ISO-8601") from exc
    if parsed.tzinfo is None or parsed.tzinfo.utcoffset(parsed) is None:
        raise WireAuthError("wire ts must be timezone-aware")
    return parsed.astimezone(timezone.utc)


def _compute_hmac(psk: bytes, body: dict[str, Any]) -> str:
    """HMAC over the canonical unsigned portion of the wire body."""
    unsigned = {
        "v": body["v"],
        "kind": body["kind"],
        "nonce": body["nonce"],
        "ts": body["ts"],
        "payload": body["payload"],
    }
    return hmac.new(psk, canonical_bytes(unsigned), hashlib.sha256).hexdigest()


def _encode_frame(body: dict[str, Any]) -> bytes:
    raw = canonical_bytes(body)
    if len(raw) > MAX_FRAME_BYTES:
        raise ValueError("frame body exceeds MAX_FRAME_BYTES")
    return FRAME_MAGIC + struct.pack(">I", len(raw)) + raw


def _decode_frame(data: bytes | bytearray) -> dict[str, Any]:
    """Parse a frame WITHOUT authenticating it. Raises WireAuthError."""
    buf = bytes(data)
    if len(buf) < 8:
        raise WireAuthError("frame too short for magic+length")
    if buf[:4] != FRAME_MAGIC:
        raise WireAuthError("bad frame magic")
    (body_len,) = struct.unpack(">I", buf[4:8])
    if body_len > MAX_FRAME_BYTES:
        raise WireAuthError("frame body length exceeds cap")
    if len(buf) != 8 + body_len:
        raise WireAuthError("frame length mismatch (truncated or trailing bytes)")
    try:
        body = json.loads(buf[8:].decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise WireAuthError("frame body is not valid JSON") from exc
    if not isinstance(body, dict):
        raise WireAuthError("frame body must be a JSON object")
    for field in ("v", "kind", "nonce", "ts", "payload", "hmac"):
        if field not in body:
            raise WireAuthError(f"frame body missing field {field!r}")
    return body


# ---------------------------------------------------------------------------
# capability minting (holder-of-key, bound to the ActionEnvelope digest)
# ---------------------------------------------------------------------------


def _build_envelope(
    event: GuardianEvent,
    params: dict[str, Any],
    now: datetime,
    *,
    ttl_s: float,
    constitution_hash: str,
) -> ActionEnvelope:
    """Build the canonical ActionEnvelope a minted capability binds to.

    ``principal`` is the event subject; the effect is the ACS-plane action;
    ``args_digest`` commits to the exact (possibly modified) params; the
    policy ref records which constitution governed the mint. Fresh
    ``action_id`` and ``nonce`` per envelope so no two digests collide.
    """
    ttl = timedelta(seconds=ttl_s)
    return ActionEnvelope(
        action_id=uuid.uuid4(),
        principal=event.subject,
        effect=Effect(
            plane="acs",
            verb=event.action,
            target=event.resource,
            args_digest=sha256_hex(params),
        ),
        policy_ref=constitution_hash,
        issued_at=now,
        not_before=now,
        not_after=now + ttl,
        nonce=secrets.token_hex(16),
    )


def _validate_presented_envelope(
    envelope: ActionEnvelope | dict[str, Any],
    *,
    event: GuardianEvent,
    params: dict[str, Any],
    now: datetime,
    constitution_hash: str,
) -> ActionEnvelope:
    """Validate a caller-presented execution-plane envelope (Wave 7 seam).

    Contract (integration seam, additive and fail-closed):

    * The deployment shim builds this envelope from the SAME decided intent
      the guardian decided on — the guardian never guesses or rebuilds the
      execution-plane envelope (it cannot: the acs-plane builder is a
      different plane, and a fresh build would never match the shim's
      digest).
    * The four validations below bind who (principal), what-exact-args
      (args_digest of the DECIDED params — ``modified_params`` when the
      decision was MODIFY, else ``event.params``), which-policy
      (policy_ref == the guardian's constitution hash), and when
      (validity window around the mint moment). Post-decision substitution
      of args, principal, or policy is denied.
    * verb/target are the PRESENTING PLANE's labels (e.g. the shell shim's
      ``verb="exec"`` / ``target="trial-cmd"`` for a guardian event with
      ``action="shell.exec"`` / ``resource="sandbox://host"``). The
      guardian deliberately does NOT equate them with the acs-plane
      ``event.action`` / ``event.resource``: no cross-plane verb/target
      mapping exists in the protocol, so there is no ground truth to
      validate against (red-team-2 P5, documented residual risk — see
      docs/THREAT_MODEL.md item 12). The what/where binding end-to-end is
      ``args_digest`` → ``action_digest`` → the PEP's digest→command
      registry, which refuses digests it never registered.
    * The remaining chain links complete outside this function: the store's
      ``envelope.action_digest == payload.action_digest`` binding ties the
      minted capability to this exact envelope, the PEP's plane check ties
      the envelope to the execution plane, and the PEP's digest->command
      registry ties the digest to the concrete command. Any mismatch →
      ``CapabilityError`` → the caller converts it to DENY; no capability
      is minted, ever.
    * The wire protocol does NOT carry presented envelopes — the wire path
      (``handle_frame``) keeps the original acs-plane default behavior.
      This is an in-process integration seam only.
    """
    if isinstance(envelope, dict):
        try:
            envelope = ActionEnvelope.model_validate(envelope)
        except Exception as exc:
            raise CapabilityError(
                f"presented envelope is not a valid ActionEnvelope: {exc}"
            ) from exc
    if not isinstance(envelope, ActionEnvelope):
        raise CapabilityError(
            "presented envelope must be an ActionEnvelope or a dict, "
            f"got {type(envelope).__name__}"
        )
    if envelope.principal != event.subject:
        raise CapabilityError(
            f"presented envelope principal {envelope.principal!r} does not match "
            f"event subject {event.subject!r}: presented envelope principal mismatch"
        )
    if envelope.effect.args_digest != sha256_hex(params):
        raise CapabilityError(
            "presented envelope args_digest does not match the decided params: "
            "post-decision substitution denied"
        )
    if envelope.policy_ref != constitution_hash:
        raise CapabilityError(
            "presented envelope policy_ref does not match the guardian's "
            "constitution hash"
        )
    try:
        inside_window = envelope.not_before <= now <= envelope.not_after
    except Exception as exc:
        raise CapabilityError(
            f"presented envelope validity window is not comparable: {exc}"
        ) from exc
    if not inside_window:
        raise CapabilityError("presented envelope outside validity window")
    return envelope


def _require_cose_capability(data: bytes) -> None:
    """Structural check that decision-frame capability bytes are a
    COSE_Sign1-shaped object. Raises WireAuthError if not.

    (Signature verification is NOT done here — it is the PEP's job, against
    its trusted-issuer set, at consumption time. This check only stops a
    peer from accepting a non-COSE blob as a capability on the wire.)
    """
    try:
        outer = cbor_loads(bytes(data))
    except CBORError as exc:
        raise WireAuthError(f"decision capability is not COSE: {exc}") from exc
    if not isinstance(outer, list) or len(outer) != 4:
        raise WireAuthError("decision capability is not a COSE_Sign1 array")
    protected, unprotected, payload, signature = outer
    if not (
        isinstance(protected, bytes)
        and isinstance(unprotected, dict)
        and isinstance(payload, bytes)
        and isinstance(signature, bytes)
    ):
        raise WireAuthError("decision capability is not a well-formed COSE_Sign1")


# ---------------------------------------------------------------------------
# guardian
# ---------------------------------------------------------------------------


class AcsGuardian:
    """Hardened ACS Guardian.

    ``decision_fn`` is pluggable: it receives a :class:`GuardianEvent` and
    returns a ``Decision`` string or a :class:`DecisionResult`. ANY failure of
    that function (exception, timeout, bad return value) becomes DENY.

    ``enabled_hooks`` is the explicit hook registry: which lifecycle events
    are live. An event arriving on a disabled hook is DENIED, never passed
    through. Unknown hook names in the config raise ``ValueError`` at
    construction (fail fast on programmer error).

    ``issuer`` is the guardian's Ed25519 key used to mint one-use
    capabilities on ALLOW/MODIFY. ``constitution_hash`` records which
    constitution authorized the mint (bind it at construction from
    ``multisig_constitution.content_hash_of``).

    ``holder_keys`` is the out-of-band holder-key registry: subject →
    32-byte Ed25519 holder public key. A capability is bound to the holder
    key, never a bearer token. Unknown subject or malformed key makes the
    mint raise, which the decision pipeline converts to DENY (fail closed).
    The SPIFFE/OIDC adapters (Wave 5) will feed this registry.
    """

    def __init__(
        self,
        *,
        psk: bytes,
        issuer: Ed25519Signer,
        constitution_hash: str,
        decision_fn,
        holder_keys: dict[str, bytes] | None = None,
        enabled_hooks: Any = None,
        replay_window_s: float = 300.0,
        decision_timeout_s: float = 2.0,
        capability_ttl_s: float = 300.0,
        audience: str = "anchor-pep",
        now_fn=None,
        wire_allowed_subjects: frozenset[str] | set[str] | None = None,
    ):
        if not isinstance(psk, (bytes, bytearray)) or len(psk) < 16:
            raise ValueError("psk must be bytes of length >= 16")
        if not constitution_hash:
            raise ValueError("constitution_hash is required")
        if not callable(decision_fn):
            raise ValueError("decision_fn must be callable")
        hooks = tuple(KNOWN_HOOKS) if enabled_hooks is None else tuple(enabled_hooks)
        unknown = [h for h in hooks if h not in KNOWN_HOOKS]
        if unknown:
            raise ValueError(f"unknown hooks in enabled_hooks: {unknown!r}")
        self._psk = bytes(psk)
        self._issuer = issuer
        self._constitution_hash = constitution_hash
        self._decision_fn = decision_fn
        self._holder_keys = dict(holder_keys) if holder_keys is not None else {}
        self._enabled_hooks = frozenset(hooks)
        self._window = timedelta(seconds=replay_window_s)
        self._decision_timeout_s = float(decision_timeout_s)
        self._capability_ttl_s = float(capability_ttl_s)
        self._audience = audience
        self._now_fn = now_fn
        self._seen_nonces: dict[str, datetime] = {}
        # Guards _seen_nonces AND _pending against concurrent wire/in-process
        # access (red-team-2 P1b: _prune_nonces raised RuntimeError under
        # concurrency; the lock also closes the check-then-set race on
        # _seen_nonces structurally). Held only for short dict operations —
        # never while running decision_fn.
        self._nonce_lock = threading.Lock()
        # Optional wire subject allowlist (red-team-2 P3 mitigation, default
        # OFF). The wire protocol is HMAC-PSK: any PSK holder can assert ANY
        # subject. When set, wire frames whose event subject is not in the
        # allowlist are DENY'd at the authentication layer. This is a
        # deployment backstop, not channel identity — production MUST bind
        # subjects to a mutually-authenticated channel (mTLS/DPoP), as the
        # module docstring's production note requires.
        self._wire_allowed_subjects = (
            frozenset(wire_allowed_subjects)
            if wire_allowed_subjects is not None
            else None
        )
        self._pending: dict[str, dict[str, Any]] = {}
        # Daemon threads; a timed-out decision_fn keeps running in the
        # background but its result is discarded (documented limitation:
        # production should isolate decision logic in a separate process).
        self._executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="acs-decide")

    # -- introspection ------------------------------------------------------

    @property
    def enabled_hooks(self) -> frozenset:
        return self._enabled_hooks

    @property
    def pending(self) -> dict[str, dict[str, Any]]:
        # Deep copy: callers must not be able to alias and mutate the
        # stored ASK/DEFER intents pre-approval (red-team-2 P4). A shallow
        # copy shares the inner dicts, letting a caller rewrite a stored
        # intent's params through the public property before resolve.
        return copy.deepcopy(self._pending)

    def _now(self) -> datetime:
        now = self._now_fn() if self._now_fn else datetime.now(timezone.utc)
        if now.tzinfo is None:
            raise ValueError("now_fn must return a timezone-aware datetime")
        return now.astimezone(timezone.utc)

    # -- decision pipeline (fail-closed) ------------------------------------

    def _deny(self, event_id: str, reason: str) -> GuardianDecision:
        return GuardianDecision(event_id=event_id, decision="DENY", reason=reason)

    def _run_decision_fn(self, event: GuardianEvent):
        """Call the pluggable decision function with a time budget.

        Raises DecisionTimeoutError on timeout; any other exception from the
        function propagates to the caller (which converts it to DENY).

        LIMITATION (red-team-2 P8): the budget is enforced via
        ``ThreadPoolExecutor.result(timeout=...)``. A CPU-bound,
        GIL-holding decision function (e.g. catastrophic-backtracking
        regex in a policy rule) can delay the timeout's own enforcement
        and pin worker threads; the outcome still fails closed (DENY) but
        availability degrades. Production MUST isolate decision logic in a
        separate process (see class docstring / docs/THREAT_MODEL.md item
        11) — in-process timeouts are a backstop, not a guarantee.
        """
        future = self._executor.submit(self._decision_fn, event)
        try:
            return future.result(timeout=self._decision_timeout_s)
        except FuturesTimeoutError as exc:
            future.cancel()
            raise DecisionTimeoutError(
                f"decision_fn exceeded {self._decision_timeout_s}s budget"
            ) from exc

    def _normalize_decision(self, raw: Any, event_id: str) -> DecisionResult:
        """Coerce the decision function's return. Anything unrecognized
        is a programmer error -> the caller converts it to DENY."""
        if isinstance(raw, str):
            if raw not in ("ALLOW", "DENY", "MODIFY", "ASK", "DEFER"):
                raise ValueError(f"decision_fn returned unknown decision {raw!r}")
            return DecisionResult(decision=raw)  # type: ignore[arg-type]
        if isinstance(raw, DecisionResult):
            return raw
        if isinstance(raw, dict):
            return DecisionResult.model_validate(raw)
        raise ValueError(
            f"decision_fn returned unsupported type {type(raw).__name__}"
        )

    def _mint_capability(
        self,
        event: GuardianEvent,
        params: dict[str, Any],
        now: datetime,
        *,
        presented_envelope: ActionEnvelope | dict[str, Any] | None = None,
    ) -> bytes:
        """Mint the one-use holder-of-key ExecutionCapability bound to the
        exact action digest.

        Default (``presented_envelope=None``): builds the canonical
        ActionEnvelope for the event (principal, acs-plane effect, args
        digest of the exact params, constitution policy ref, validity
        window, fresh nonce), then mints via the Wave 2 authority layer:
        ``authority.issue_execution`` bound to ``envelope.action_digest``
        and the subject's registered holder key.

        With ``presented_envelope`` (Wave 7 integration seam): the envelope
        is validated via :func:`_validate_presented_envelope` instead of
        built, and the SAME holder-key lookup and ``issue_execution`` run
        against the presented envelope's ``action_digest``. Validation
        failure raises ``CapabilityError``; no capability is minted, ever.
        The capability IS the authorization in both paths — there is no
        second execution path.

        Raises on ANY failure (envelope build, presented-envelope
        validation, unknown subject, malformed holder key, authority mint
        failure) — the caller converts that into DENY, so an ALLOW without
        a minted capability can never be produced. Returns the COSE_Sign1
        bytes.
        """
        if presented_envelope is None:
            try:
                envelope = _build_envelope(
                    event,
                    params,
                    now,
                    ttl_s=self._capability_ttl_s,
                    constitution_hash=self._constitution_hash,
                )
            except Exception as exc:
                raise CapabilityError(f"envelope build failed: {exc}") from exc
        else:
            envelope = _validate_presented_envelope(
                presented_envelope,
                event=event,
                params=params,
                now=now,
                constitution_hash=self._constitution_hash,
            )
        holder_pubkey = self._holder_keys.get(event.subject)
        if holder_pubkey is None:
            raise CapabilityError(
                f"no holder key registered for subject {event.subject!r} "
                "(fail closed: mint denied)"
            )
        if not isinstance(holder_pubkey, (bytes, bytearray)) or len(holder_pubkey) != 32:
            raise CapabilityError(
                f"malformed holder key for subject {event.subject!r} "
                "(fail closed: mint denied)"
            )
        return issue_execution(
            self._issuer,
            action_digest=envelope.action_digest,
            holder_pubkey=bytes(holder_pubkey),
            ttl=timedelta(seconds=self._capability_ttl_s),
            now=now,
        )

    def handle_event(
        self,
        event: GuardianEvent | dict[str, Any],
        *,
        presented_envelope: ActionEnvelope | dict[str, Any] | None = None,
    ) -> GuardianDecision:
        """Decide an event in-process. Fail-closed: every failure mode below
        yields DENY, and ALLOW always carries a freshly minted capability.

        ``presented_envelope`` (optional, keyword-only): the Wave 7
        integration seam. The deployment shim may present the
        execution-plane :class:`ActionEnvelope` it built from the same
        decided intent; it is validated (principal / args_digest /
        policy_ref / validity window — see :func:`_validate_presented_envelope`)
        and the mint binds to ITS ``action_digest``. The default
        (``None``) keeps the original acs-plane envelope behavior exactly.
        Validation failure becomes DENY; no capability is minted. The wire
        path (:meth:`handle_frame`) never carries presented envelopes.
        """
        try:
            ev = (
                event
                if isinstance(event, GuardianEvent)
                else GuardianEvent.model_validate(event)
            )
        except Exception:
            return self._deny("unknown", "malformed event: validation failed")

        # Unknown event types fail closed BEFORE the decision function runs.
        if ev.event_type not in KNOWN_HOOKS:
            return self._deny(ev.event_id, f"unknown event type {ev.event_type!r}")
        # Disabled hooks are denied, never silently skipped or passed through.
        if ev.event_type not in self._enabled_hooks:
            return self._deny(ev.event_id, f"hook {ev.event_type!r} is disabled")

        try:
            raw = self._run_decision_fn(ev)
            result = self._normalize_decision(raw, ev.event_id)
        except Exception as exc:
            return self._deny(ev.event_id, f"decision-function failure: {exc}")

        now = self._now()
        if result.decision == "DENY":
            return GuardianDecision(
                event_id=ev.event_id, decision="DENY", reason=result.reason
            )
        if result.decision == "ASK":
            pending_id = f"ask-{secrets.token_hex(8)}"
            self._pending[pending_id] = {"kind": "ASK", "event": ev.model_dump(mode="json")}
            return GuardianDecision(
                event_id=ev.event_id,
                decision="ASK",
                reason=result.reason or "human approval required",
                pending_id=pending_id,
            )
        if result.decision == "DEFER":
            pending_id = f"defer-{secrets.token_hex(8)}"
            self._pending[pending_id] = {"kind": "DEFER", "event": ev.model_dump(mode="json")}
            return GuardianDecision(
                event_id=ev.event_id,
                decision="DEFER",
                reason=result.reason or "decision deferred",
                pending_id=pending_id,
            )

        # ALLOW and MODIFY both mint: the capability IS the authorization.
        params = ev.params
        if result.decision == "MODIFY":
            if not isinstance(result.modified_params, dict):
                return self._deny(
                    ev.event_id, "MODIFY requires modified_params (fail closed)"
                )
            params = result.modified_params
        try:
            capability = self._mint_capability(ev, params, now, presented_envelope=presented_envelope)
        except Exception as exc:
            # The mint IS the authorization. If it fails, this is a DENY —
            # there is no ALLOW-without-capability path.
            return self._deny(ev.event_id, f"capability mint failed: {exc}")
        assert capability is not None  # belt and suspenders: no bare ALLOW
        return GuardianDecision(
            event_id=ev.event_id,
            decision=result.decision,
            reason=result.reason,
            capability=capability,
            modified_params=params if result.decision == "MODIFY" else None,
        )

    def resolve_pending(
        self,
        pending_id: str,
        approved: bool,
        *,
        now: datetime | None = None,
        presented_envelope: ActionEnvelope | dict[str, Any] | None = None,
    ) -> GuardianDecision:
        """Resolve a deferred ASK/DEFER decision recorded by :meth:`handle_event`.

        * ``approved=True`` — mints the capability for the stored event
          through the SAME fail-closed mint path as an immediate ALLOW
          (mint failure → DENY, never a bare approval).
        * ``approved=False`` — returns DENY and clears the pending entry.
        * Unknown ``pending_id`` → ``ValueError``.
        * Resolving twice → ``ValueError`` on the second call (the entry is
          consumed by the first resolve, so no double mint is possible).

        ``presented_envelope`` (optional, keyword-only): the Wave 7 seam —
        threads through to the approved-mint path exactly as in
        :meth:`handle_event` (validated; mint binds to its
        ``action_digest``; validation failure → DENY).
        """
        try:
            entry = self._pending.pop(pending_id)
        except KeyError:
            raise ValueError(f"unknown pending_id {pending_id!r}") from None
        event = GuardianEvent.model_validate(entry["event"])
        if not approved:
            return GuardianDecision(
                event_id=event.event_id,
                decision="DENY",
                reason=f"{entry['kind']} request rejected",
            )
        moment = now if now is not None else self._now()
        try:
            capability = self._mint_capability(
                event, event.params, moment, presented_envelope=presented_envelope
            )
        except Exception as exc:
            # Same rule as the live path: the mint IS the authorization.
            return self._deny(event.event_id, f"capability mint failed: {exc}")
        assert capability is not None  # belt and suspenders: no bare approval
        return GuardianDecision(
            event_id=event.event_id,
            decision="ALLOW",
            reason=f"{entry['kind']} approved",
            capability=capability,
        )

    # -- wire path ----------------------------------------------------------

    def _prune_nonces(self, now: datetime) -> None:
        """Thread-safe nonce pruning (acquires the nonce lock)."""
        with self._nonce_lock:
            self._prune_nonces_locked(now)

    def _prune_nonces_locked(self, now: datetime) -> None:
        # Caller MUST hold self._nonce_lock. Kept separate so the wire
        # path can prune + check + record in a single critical section.
        # Red-team-2 P1b: the unlocked version raised RuntimeError
        # ("dictionary changed size during iteration") under concurrent
        # load and spuriously DENY'd legitimate requests.
        cutoff = now - 2 * self._window
        stale = [n for n, ts in self._seen_nonces.items() if ts < cutoff]
        for n in stale:
            del self._seen_nonces[n]

    def _authenticate_frame(self, data: bytes | bytearray) -> dict[str, Any]:
        """Parse + authenticate an inbound frame. Returns the payload dict.
        Raises WireAuthError on ANY problem (fail closed at the caller)."""
        body = _decode_frame(data)
        if body["v"] != WIRE_VERSION:
            raise WireAuthError(f"unsupported wire version {body['v']!r}")
        if body["kind"] != _KIND_EVENT:
            raise WireAuthError(f"unexpected frame kind {body['kind']!r}")
        if not isinstance(body["nonce"], str) or not body["nonce"]:
            raise WireAuthError("wire nonce must be a non-empty string")
        if not isinstance(body["hmac"], str):
            raise WireAuthError("wire hmac must be a string")
        expected = _compute_hmac(self._psk, body)
        if not hmac.compare_digest(expected, body["hmac"]):
            raise WireAuthError("wire HMAC verification failed")
        ts = _parse_wire_ts(body["ts"])
        now = self._now()
        if abs((now - ts).total_seconds()) > self._window.total_seconds():
            raise WireAuthError("wire timestamp outside replay window")
        # The whole nonce check-then-set (prune, seen-check, record) is one
        # critical section: red-team-2 P1b (RuntimeError / spurious DENYs)
        # and the P1 same-nonce race window are both closed structurally.
        with self._nonce_lock:
            self._prune_nonces_locked(now)
            if body["nonce"] in self._seen_nonces:
                raise WireAuthError("wire nonce already seen: replay denied")
            self._seen_nonces[body["nonce"]] = ts
        if not isinstance(body["payload"], dict):
            raise WireAuthError("event payload must be a JSON object")
        if self._wire_allowed_subjects is not None:
            # Red-team-2 P3 backstop (default off): the PSK channel does not
            # bind the asserted subject to a channel identity, so a PSK
            # holder can name any subject. Deployments with a known subject
            # set can DENY everything else at the wire layer. Production
            # MUST still use a mutually-authenticated channel (mTLS/DPoP).
            subject = body["payload"].get("subject")
            if subject not in self._wire_allowed_subjects:
                raise WireAuthError(
                    f"wire subject {subject!r} not in wire_allowed_subjects"
                )
        return body["payload"]

    def _sign_decision_frame(self, decision: GuardianDecision) -> bytes:
        # The COSE_Sign1 capability bytes are base64'd into the JSON payload.
        # (pydantic's default JSON encoding of bytes is UTF-8 text, which
        # arbitrary COSE bytes are not; the explicit base64 here is the wire
        # contract, verified structurally on parse.)
        payload = decision.model_dump(mode="json", exclude={"capability"})
        capability = decision.capability
        payload["capability"] = (
            base64.b64encode(capability).decode("ascii")
            if capability is not None
            else None
        )
        body = {
            "v": WIRE_VERSION,
            "kind": _KIND_DECISION,
            "nonce": secrets.token_hex(16),
            "ts": self._now().isoformat(),
            "payload": payload,
        }
        body["hmac"] = _compute_hmac(self._psk, body)
        return _encode_frame(body)

    def handle_frame(self, data: bytes | bytearray) -> bytes:
        """Full wire path: authenticate the frame, decide the event, return a
        signed decision frame. NEVER raises on protocol input — every failure
        mode produces a signed DENY decision frame (fail closed)."""
        try:
            payload = self._authenticate_frame(data)
            decision = self.handle_event(payload)
        except WireAuthError as exc:
            decision = self._deny("unknown", f"wire auth failed: {exc}")
        except Exception as exc:  # guardian-internal error -> DENY, never propagate
            decision = self._deny("unknown", f"guardian error: {exc}")
        try:
            return self._sign_decision_frame(decision)
        except Exception:
            # Even signing must not become a fail-open hole: with no signed
            # frame the peer cannot obtain a capability, so the action stays
            # unauthorized. Return empty bytes; the peer treats it as denied.
            return b""


# ---------------------------------------------------------------------------
# wire peer (test harness)
# ---------------------------------------------------------------------------


class WirePeer:
    """Test harness that speaks the ACS wire protocol with real framing and
    real HMAC bytes — no in-process shortcuts.

    ``send_event(guardian, event, ...)`` builds a signed event frame, feeds
    the raw bytes to ``guardian.handle_frame``, then parses and authenticates
    the guardian's signed decision frame. Keyword overrides (``key``,
    ``nonce``, ``ts``, ``raw_body``) exist for adversarial tests.
    """

    def __init__(
        self,
        psk: bytes,
        *,
        peer_id: str = "test-agent",
        replay_window_s: float = 300.0,
        now_fn=None,
    ):
        if not isinstance(psk, (bytes, bytearray)) or len(psk) < 16:
            raise ValueError("psk must be bytes of length >= 16")
        self._psk = bytes(psk)
        self.peer_id = peer_id
        self._window = timedelta(seconds=replay_window_s)
        self._now_fn = now_fn
        self._seen_nonces: set[str] = set()

    def _now(self) -> datetime:
        now = self._now_fn() if self._now_fn else datetime.now(timezone.utc)
        return now.astimezone(timezone.utc)

    def build_event_frame(
        self,
        event: GuardianEvent | dict[str, Any],
        *,
        key: bytes | None = None,
        nonce: str | None = None,
        ts: datetime | str | None = None,
    ) -> bytes:
        """Build a signed event frame. ``key`` overrides the HMAC key
        (adversarial: forged signature); ``nonce``/``ts`` override the
        replay-protection fields."""
        payload = (
            event.model_dump(mode="json")
            if isinstance(event, GuardianEvent)
            else dict(event)
        )
        if ts is None:
            ts_str = self._now().isoformat()
        elif isinstance(ts, datetime):
            ts_str = ts.isoformat()
        else:
            ts_str = ts
        body = {
            "v": WIRE_VERSION,
            "kind": _KIND_EVENT,
            "nonce": nonce if nonce is not None else secrets.token_hex(16),
            "ts": ts_str,
            "payload": payload,
        }
        body["hmac"] = _compute_hmac(key if key is not None else self._psk, body)
        return _encode_frame(body)

    def parse_decision_frame(self, data: bytes | bytearray) -> GuardianDecision:
        """Parse + authenticate a guardian decision frame. Raises
        WireAuthError if the guardian's response fails authentication."""
        body = _decode_frame(data)
        if body["v"] != WIRE_VERSION:
            raise WireAuthError(f"unsupported wire version {body['v']!r}")
        if body["kind"] != _KIND_DECISION:
            raise WireAuthError(f"unexpected frame kind {body['kind']!r}")
        if not isinstance(body["hmac"], str):
            raise WireAuthError("wire hmac must be a string")
        expected = _compute_hmac(self._psk, body)
        if not hmac.compare_digest(expected, body["hmac"]):
            raise WireAuthError("decision frame HMAC verification failed")
        ts = _parse_wire_ts(body["ts"])
        now = self._now()
        if abs((now - ts).total_seconds()) > self._window.total_seconds():
            raise WireAuthError("decision frame timestamp outside replay window")
        if body["nonce"] in self._seen_nonces:
            raise WireAuthError("decision frame nonce already seen: replay denied")
        self._seen_nonces.add(body["nonce"])
        if not isinstance(body["payload"], dict):
            raise WireAuthError("decision payload must be a JSON object")
        raw_payload = dict(body["payload"])
        raw_capability = raw_payload.get("capability")
        if raw_capability is None:
            raw_payload["capability"] = None
        elif isinstance(raw_capability, str):
            try:
                cose_bytes = base64.b64decode(
                    raw_capability.encode("ascii"), validate=True
                )
            except ValueError as exc:
                raise WireAuthError(
                    f"decision capability is not valid base64: {exc}"
                ) from exc
            # A decision frame carrying a non-COSE capability is rejected
            # here — the peer must never treat the blob as an authorization.
            _require_cose_capability(cose_bytes)
            raw_payload["capability"] = cose_bytes
        else:
            raise WireAuthError("decision capability must be base64 or null")
        try:
            return GuardianDecision.model_validate(raw_payload)
        except Exception as exc:
            raise WireAuthError(f"malformed decision payload: {exc}") from exc

    def send_event(
        self,
        guardian: AcsGuardian,
        event: GuardianEvent | dict[str, Any],
        **frame_kwargs,
    ) -> GuardianDecision:
        """Full round trip over real wire bytes: build -> guardian ->
        parse. Any wire-auth failure on the response raises WireAuthError."""
        raw = self.build_event_frame(event, **frame_kwargs)
        response = guardian.handle_frame(raw)
        return self.parse_decision_frame(response)
