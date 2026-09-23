"""ANCHOR v1 — Shadow-mode policy evaluation (Wave B, capability 6).

The safe enterprise rollout path: run a policy in SHADOW mode first — every
request is evaluated through the real decision pipeline (constitution
governance_check AND capability-token verification when a token is supplied),
but nothing is denied. Would-be decisions are recorded in a tamper-evident,
hash-chained log. Operators review the divergence report, dry-run a
constitution upgrade with :func:`compare`, and only then flip to ENFORCE.

Fail-closed properties (each is attacked in tests/test_shadow_mode.py):
  * Mode changes take effect ONLY via a signed ModeChangeCommand from an
    authorized controller key. Envelopes carry a monotonic sequence number
    and an expiry — replays and stale downgrades are rejected.
  * The shadow log is hash-chained (previous_record_hash). Rewriting any
    record breaks :meth:`ShadowGovernor.verify_log`.
  * ``never_shadow`` action patterns always enforce, even in SHADOW mode.
  * Any pipeline failure (bad token, malformed request, unexpected error)
    evaluates to DENY, never to a soft allow.

Local only. No network calls.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from datetime import datetime, timezone
from fnmatch import fnmatchcase
from typing import Any, Literal

from pydantic import Field, ValidationError, field_validator, model_validator

from anchor_v1.attenuated_tokens import (
    AuthorizationError,
    token_hash,
    verify as verify_token,
)
from anchor_v1.canonical import sha256_hex
from anchor_v1.crypto import Ed25519Signer, verify_envelope
from anchor_v1.models import SignedEnvelope, StrictModel
from anchor_v1.multisig_constitution import (
    Constitution,
    SignedConstitution,
    content_hash_of,
    governance_check,
)

__all__ = [
    "Mode",
    "Decision",
    "ShadowDenied",
    "ModeChangeRejected",
    "CompareInputRejected",
    "TokenEvaluation",
    "EvaluationRequest",
    "ShadowRecord",
    "ModeChangeCommand",
    "LogIntegrity",
    "DivergenceSummary",
    "DecisionDiff",
    "CompareReport",
    "EvaluationOutcome",
    "ShadowGovernor",
    "sign_mode_change",
    "compare",
]

Mode = Literal["ENFORCE", "SHADOW"]
Decision = Literal["ALLOW", "DENY", "APPROVAL_REQUIRED"]

_GENESIS_PREV_HASH = "GENESIS:" + "0" * 64


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ShadowDenied(Exception):
    """Raised when an action is actually denied (blocked).

    Carries the :class:`ShadowRecord` for forensics. In SHADOW mode this is
    raised only for ``never_shadow`` actions; in ENFORCE mode for every DENY.
    """

    def __init__(self, message: str, record: "ShadowRecord | None" = None):
        super().__init__(message)
        self.record = record


class ModeChangeRejected(ValueError):
    """A mode-change envelope was invalid, unauthorized, stale, or replayed."""


class CompareInputRejected(ValueError):
    """A dry-run compare input failed validation. Fail closed: reject loudly,
    never silently skip a poisoned request."""


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


def _require_aware_utc(value: datetime, field_name: str) -> datetime:
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value.astimezone(timezone.utc)


class TokenEvaluation(StrictModel):
    """Everything needed to verify a capability token at the enforcement point."""

    envelope: SignedEnvelope
    holder_proof: SignedEnvelope
    invocation_params: dict[str, Any] = Field(default_factory=dict)
    trusted_issuers: dict[str, bytes] = Field(
        description="key_id -> raw Ed25519 public key bytes"
    )
    context: dict[str, Any] = Field(default_factory=dict)


class EvaluationRequest(StrictModel):
    """One action submitted to the shadow governor."""

    action: str = Field(min_length=1)
    resource: str = Field(min_length=1)
    subject: str = Field(min_length=1)
    token: TokenEvaluation | None = None
    baseline_decision: Decision | None = Field(
        default=None,
        description="expected decision from the previous policy; used for diff_vs_baseline",
    )


class ShadowRecord(StrictModel):
    """One evaluated request, hash-chained into the tamper-evident shadow log."""

    record_id: str = Field(min_length=1)
    timestamp: datetime
    action: str
    resource: str
    subject: str
    evaluated_decision: Decision
    enforced_decision: Decision
    would_have_denied: bool
    would_have_required_approval: bool
    decision_source: str = Field(
        description="constitution content hash, plus token id when a token was evaluated"
    )
    diff_vs_baseline: str | None = None
    previous_record_hash: str = Field(min_length=1)
    record_hash: str = Field(min_length=1)

    @field_validator("timestamp")
    @classmethod
    def _tz_aware(cls, v: datetime) -> datetime:
        return _require_aware_utc(v, "timestamp")

    @property
    def proceed(self) -> bool:
        """True iff the action was actually allowed to run."""
        return self.enforced_decision == "ALLOW"


class ModeChangeCommand(StrictModel):
    """Signed control command that flips the governor mode.

    ``sequence`` is monotonic per governor (replays rejected); the envelope
    expires at ``expires_at``.
    """

    mode: Mode
    sequence: int = Field(ge=0)
    issued_at: datetime
    expires_at: datetime

    @field_validator("issued_at", "expires_at")
    @classmethod
    def _tz_aware(cls, v: datetime) -> datetime:
        return _require_aware_utc(v, "issued_at/expires_at")

    @model_validator(mode="after")
    def _window_sane(self) -> "ModeChangeCommand":
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be after issued_at")
        return self


class LogIntegrity(StrictModel):
    ok: bool
    records_checked: int
    first_bad_index: int | None = None


class DivergenceSummary(StrictModel):
    total: int
    would_have_denied: int
    enforced_denied: int
    approval_required: int
    would_have_required_approval: int
    shadow_allowed: int
    top_denied_actions: list[tuple[str, int]]
    top_denied_resources: list[tuple[str, int]]


class DecisionDiff(StrictModel):
    action: str
    resource: str
    subject: str
    old_decision: Decision
    new_decision: Decision
    changed: bool
    risk: Literal["tighten-to-deny", "tighten", "loosen", "none"]
    token_present: bool


class CompareReport(StrictModel):
    old_constitution_hash: str
    new_constitution_hash: str
    total: int
    changed_count: int
    unchanged_count: int
    risky_flips: list[DecisionDiff]
    diffs: list[DecisionDiff]


class EvaluationOutcome(StrictModel):
    """Convenience view returned alongside the record by evaluate_with_outcome."""

    record: ShadowRecord
    allowed: bool
    mode: Mode


# ---------------------------------------------------------------------------
# Mode-change signing
# ---------------------------------------------------------------------------


def sign_mode_change(
    signer: Ed25519Signer,
    *,
    mode: Mode,
    sequence: int,
    issued_at: datetime,
    expires_at: datetime,
) -> SignedEnvelope:
    """Build a signed mode-change envelope with an authorized controller key."""
    command = ModeChangeCommand(
        mode=mode, sequence=sequence, issued_at=issued_at, expires_at=expires_at
    )
    return signer.sign_payload(command.model_dump(mode="json"))


# ---------------------------------------------------------------------------
# Governor
# ---------------------------------------------------------------------------


class ShadowGovernor:
    """Evaluates actions against the real decision pipeline in ENFORCE or
    SHADOW mode, recording every decision in a hash-chained shadow log.

    * ENFORCE: evaluated decisions block as normal (DENY raises ShadowDenied).
    * SHADOW: nothing is denied — the action proceeds and the would-be
      decision is recorded (would_have_denied / would_have_required_approval).
    * ``never_shadow`` action patterns always enforce, even in SHADOW mode.
    """

    def __init__(
        self,
        constitution: Constitution,
        *,
        mode: Mode = "ENFORCE",
        never_shadow: list[str] | None = None,
        controller_keys: dict[str, bytes] | None = None,
        now_fn: Callable[[], datetime] | None = None,
    ):
        self._constitution = constitution
        self._mode: Mode = mode
        self._never_shadow = (
            list(never_shadow)
            if never_shadow is not None
            else list(constitution.hard_deny_actions)
        )
        self._controller_keys = dict(controller_keys or {})
        self._now_fn = now_fn
        self._records: list[ShadowRecord] = []
        self._used_nonces: set[str] = set()
        self._last_sequence: int = -1

    # -- read-only state ----------------------------------------------------

    @property
    def mode(self) -> Mode:
        return self._mode

    @property
    def constitution(self) -> Constitution:
        return self._constitution

    @property
    def never_shadow(self) -> tuple[str, ...]:
        return tuple(self._never_shadow)

    @property
    def records(self) -> tuple[ShadowRecord, ...]:
        return tuple(self._records)

    @property
    def last_sequence(self) -> int:
        return self._last_sequence

    def _now(self) -> datetime:
        now = self._now_fn() if self._now_fn else datetime.now(timezone.utc)
        return _require_aware_utc(now, "now")

    # -- evaluation ---------------------------------------------------------

    def evaluate(self, request: EvaluationRequest | dict[str, Any]) -> ShadowRecord:
        """Run the decision pipeline, apply the mode, log, and return the record.

        Raises ShadowDenied when the action is actually blocked (ENFORCE-mode
        DENY, or a never_shadow DENY in SHADOW mode). Raises pydantic
        ValidationError for malformed requests — fail closed, no silent allow.
        """
        req = (
            request
            if isinstance(request, EvaluationRequest)
            else EvaluationRequest.model_validate(request)
        )
        evaluated, source = self._run_pipeline(req)

        bypasses_shadow = self._never_shadow_match(req.action)
        if self._mode == "ENFORCE" or bypasses_shadow:
            enforced = evaluated
        else:
            enforced = "ALLOW"

        would_have_denied = evaluated == "DENY" and enforced == "ALLOW"
        would_have_required_approval = (
            evaluated == "APPROVAL_REQUIRED" and enforced == "ALLOW"
        )

        record = self._append_record(
            req, evaluated, enforced, would_have_denied,
            would_have_required_approval, source,
        )
        if enforced == "DENY":
            raise ShadowDenied(
                f"action denied: {req.action!r} on {req.resource!r} "
                f"(evaluated={evaluated}, mode={self._mode})",
                record,
            )
        return record

    def evaluate_with_outcome(
        self, request: EvaluationRequest | dict[str, Any]
    ) -> EvaluationOutcome:
        """Like evaluate(), but never raises on denial — returns allowed=False."""
        try:
            record = self.evaluate(request)
        except ShadowDenied as exc:
            assert exc.record is not None
            return EvaluationOutcome(
                record=exc.record, allowed=False, mode=self._mode
            )
        return EvaluationOutcome(record=record, allowed=record.proceed, mode=self._mode)

    def _never_shadow_match(self, action: str) -> bool:
        return any(fnmatchcase(action, p) for p in self._never_shadow)

    def _run_pipeline(self, req: EvaluationRequest) -> tuple[Decision, str]:
        """Fail-closed decision pipeline. ANY failure -> DENY, never soft allow."""
        try:
            decision = governance_check(req.action, req.resource, self._constitution)
            source = content_hash_of(self._constitution)
            if req.token is not None:
                token_decision = self._evaluate_token(req)
                decision = _combine(decision, token_decision)
                source = f"{source}+token:{token_hash(req.token.envelope)}"
            return decision, source
        except Exception:
            # Defense in depth: an unexpected pipeline error must not become
            # an allow. The source tag marks the record as a pipeline failure.
            return "DENY", f"{content_hash_of(self._constitution)}+pipeline-error"

    def _evaluate_token(self, req: EvaluationRequest) -> Decision:
        assert req.token is not None
        tok = req.token
        try:
            payload = verify_token(
                tok.envelope,
                holder_proof=tok.holder_proof,
                invocation_params=tok.invocation_params,
                now=self._now(),
                trusted_issuers=tok.trusted_issuers,
                used_nonces=self._used_nonces,
                context=tok.context,
            )
        except AuthorizationError:
            return "DENY"
        # Capability binding: the token authorizes THIS action/resource/subject.
        if (
            payload.action != req.action
            or payload.resource != req.resource
            or payload.subject != req.subject
        ):
            return "DENY"
        # Single-use: a token that verifies and binds is consumed, even if the
        # constitution independently denies the action. The token authorized
        # this invocation, so it must not be replayable.
        self._used_nonces.add(payload.nonce)
        return "ALLOW"

    # -- shadow log ----------------------------------------------------------

    def _record_body(
        self,
        req: EvaluationRequest,
        evaluated: Decision,
        enforced: Decision,
        would_have_denied: bool,
        would_have_required_approval: bool,
        source: str,
        timestamp: datetime,
        previous_record_hash: str,
    ) -> dict[str, Any]:
        diff = None
        if req.baseline_decision is not None and req.baseline_decision != evaluated:
            diff = f"{req.baseline_decision}->{evaluated}"
        return {
            "timestamp": timestamp.isoformat(),
            "action": req.action,
            "resource": req.resource,
            "subject": req.subject,
            "evaluated_decision": evaluated,
            "enforced_decision": enforced,
            "would_have_denied": would_have_denied,
            "would_have_required_approval": would_have_required_approval,
            "decision_source": source,
            "diff_vs_baseline": diff,
            "previous_record_hash": previous_record_hash,
        }

    def _append_record(
        self,
        req: EvaluationRequest,
        evaluated: Decision,
        enforced: Decision,
        would_have_denied: bool,
        would_have_required_approval: bool,
        source: str,
    ) -> ShadowRecord:
        previous = self._records[-1].record_hash if self._records else _GENESIS_PREV_HASH
        timestamp = self._now()
        body = self._record_body(
            req, evaluated, enforced, would_have_denied,
            would_have_required_approval, source, timestamp, previous,
        )
        record_hash = sha256_hex(body)
        record_id = f"rec-{record_hash[:16]}"
        record = ShadowRecord(
            record_id=record_id,
            timestamp=timestamp,
            action=req.action,
            resource=req.resource,
            subject=req.subject,
            evaluated_decision=evaluated,
            enforced_decision=enforced,
            would_have_denied=would_have_denied,
            would_have_required_approval=would_have_required_approval,
            decision_source=source,
            diff_vs_baseline=body["diff_vs_baseline"],
            previous_record_hash=previous,
            record_hash=record_hash,
        )
        self._records.append(record)
        return record

    def verify_log(self) -> LogIntegrity:
        """Recompute the hash chain. Any tampering -> ok=False with the first
        bad index. Fail closed: verification never trusts stored hashes alone."""
        for i, rec in enumerate(self._records):
            expected_prev = (
                self._records[i - 1].record_hash if i > 0 else _GENESIS_PREV_HASH
            )
            if rec.previous_record_hash != expected_prev:
                return LogIntegrity(
                    ok=False, records_checked=len(self._records), first_bad_index=i
                )
            body = self._record_body(
                EvaluationRequest(
                    action=rec.action,
                    resource=rec.resource,
                    subject=rec.subject,
                    baseline_decision=(
                        rec.diff_vs_baseline.split("->")[0]  # type: ignore[union-attr]
                        if rec.diff_vs_baseline
                        else None
                    ),
                ),
                rec.evaluated_decision,
                rec.enforced_decision,
                rec.would_have_denied,
                rec.would_have_required_approval,
                rec.decision_source,
                rec.timestamp,
                rec.previous_record_hash,
            )
            # The stored diff string must round-trip exactly.
            if body["diff_vs_baseline"] != rec.diff_vs_baseline:
                return LogIntegrity(
                    ok=False, records_checked=len(self._records), first_bad_index=i
                )
            recomputed = sha256_hex(body)
            if recomputed != rec.record_hash or rec.record_id != f"rec-{recomputed[:16]}":
                return LogIntegrity(
                    ok=False, records_checked=len(self._records), first_bad_index=i
                )
        return LogIntegrity(ok=True, records_checked=len(self._records))

    # -- signed mode changes -------------------------------------------------

    def apply_mode_change(self, envelope: SignedEnvelope) -> ModeChangeCommand:
        """Apply a signed mode-change envelope. Fail closed: any problem with
        the envelope (unknown key, bad signature, stale/replayed sequence,
        expiry, future issued_at, malformed payload) raises ModeChangeRejected
        and the mode is left untouched."""
        if not self._controller_keys:
            raise ModeChangeRejected("no controller keys configured")
        public_key = self._controller_keys.get(envelope.key_id)
        if public_key is None:
            raise ModeChangeRejected(
                f"unknown controller key_id {envelope.key_id!r}"
            )
        try:
            payload = verify_envelope(envelope, public_key)
        except Exception as exc:
            raise ModeChangeRejected("invalid mode-change signature") from exc
        try:
            command = ModeChangeCommand.model_validate(payload)
        except ValidationError as exc:
            raise ModeChangeRejected(
                f"malformed mode-change payload: {exc.errors()[0]['msg']}"
            ) from exc

        now = self._now()
        if command.sequence <= self._last_sequence:
            raise ModeChangeRejected(
                f"stale or replayed sequence {command.sequence} "
                f"(last applied: {self._last_sequence})"
            )
        if now >= command.expires_at:
            raise ModeChangeRejected("mode-change envelope expired")
        if command.issued_at > now:
            raise ModeChangeRejected("mode-change issued_at is in the future")

        self._mode = command.mode
        self._last_sequence = command.sequence
        return command

    # -- divergence report ----------------------------------------------------

    def summarize(
        self, records: Iterable[ShadowRecord] | None = None
    ) -> DivergenceSummary:
        """Divergence report: what an enterprise reviews before SHADOW->ENFORCE."""
        recs = list(records) if records is not None else list(self._records)
        denied = [r for r in recs if r.evaluated_decision == "DENY"]

        def top(values: list[str], limit: int = 5) -> list[tuple[str, int]]:
            counts: dict[str, int] = {}
            for v in values:
                counts[v] = counts.get(v, 0) + 1
            return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:limit]

        return DivergenceSummary(
            total=len(recs),
            would_have_denied=sum(1 for r in recs if r.would_have_denied),
            enforced_denied=sum(1 for r in recs if r.enforced_decision == "DENY"),
            approval_required=sum(
                1 for r in recs if r.evaluated_decision == "APPROVAL_REQUIRED"
            ),
            would_have_required_approval=sum(
                1 for r in recs if r.would_have_required_approval
            ),
            shadow_allowed=sum(1 for r in recs if r.enforced_decision == "ALLOW"),
            top_denied_actions=top([r.action for r in denied]),
            top_denied_resources=top([r.resource for r in denied]),
        )


# ---------------------------------------------------------------------------
# Decision combination + dry-run compare
# ---------------------------------------------------------------------------


def _combine(constitution_decision: Decision, token_decision: Decision) -> Decision:
    """Fail-closed precedence: DENY > APPROVAL_REQUIRED > ALLOW."""
    order: dict[Decision, int] = {"ALLOW": 0, "APPROVAL_REQUIRED": 1, "DENY": 2}
    return (
        constitution_decision
        if order[constitution_decision] >= order[token_decision]
        else token_decision
    )


def _classify_risk(old: Decision, new: Decision) -> Literal[
    "tighten-to-deny", "tighten", "loosen", "none"
]:
    if old == new:
        return "none"
    if new == "DENY":
        return "tighten-to-deny"
    if old == "DENY":
        return "loosen"
    # ALLOW <-> APPROVAL_REQUIRED
    return "tighten" if new == "APPROVAL_REQUIRED" else "loosen"


def compare(
    old_constitution: Constitution | SignedConstitution,
    new_constitution: Constitution | SignedConstitution,
    historical_requests: list[EvaluationRequest | dict[str, Any]],
) -> CompareReport:
    """Dry-run a constitution upgrade: replay historical requests under both
    constitutions and report every decision that would CHANGE.

    The constitution decision pipeline is replayed; capability tokens are NOT
    re-verified (single-use nonces cannot be replayed) — requests carrying a
    token are flagged with ``token_present=True`` so reviewers know the token
    dimension was out of scope. Poisoned inputs raise CompareInputRejected —
    they are never silently skipped.
    """
    old = (
        old_constitution.constitution
        if isinstance(old_constitution, SignedConstitution)
        else old_constitution
    )
    new = (
        new_constitution.constitution
        if isinstance(new_constitution, SignedConstitution)
        else new_constitution
    )
    if not isinstance(historical_requests, list):
        raise CompareInputRejected(
            f"historical_requests must be a list, got {type(historical_requests).__name__}"
        )

    validated: list[EvaluationRequest] = []
    for i, raw in enumerate(historical_requests):
        if isinstance(raw, EvaluationRequest):
            validated.append(raw)
            continue
        try:
            validated.append(EvaluationRequest.model_validate(raw))
        except ValidationError as exc:
            raise CompareInputRejected(
                f"historical request #{i} failed validation: {exc.errors()[0]['msg']}"
            ) from exc

    diffs: list[DecisionDiff] = []
    for req in validated:
        old_d = governance_check(req.action, req.resource, old)
        new_d = governance_check(req.action, req.resource, new)
        risk = _classify_risk(old_d, new_d)
        diffs.append(
            DecisionDiff(
                action=req.action,
                resource=req.resource,
                subject=req.subject,
                old_decision=old_d,
                new_decision=new_d,
                changed=old_d != new_d,
                risk=risk,
                token_present=req.token is not None,
            )
        )

    risky = [d for d in diffs if d.risk == "tighten-to-deny"]
    return CompareReport(
        old_constitution_hash=content_hash_of(old),
        new_constitution_hash=content_hash_of(new),
        total=len(diffs),
        changed_count=sum(1 for d in diffs if d.changed),
        unchanged_count=sum(1 for d in diffs if not d.changed),
        risky_flips=risky,
        diffs=diffs,
    )
