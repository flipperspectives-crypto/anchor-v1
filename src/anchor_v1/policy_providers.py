"""ANCHOR v1 — pluggable policy providers (BUILDER A).

A policy provider answers one question for a given :class:`ActionEnvelope`:

    "May this action proceed?" -> ALLOW | DENY | ABSTAIN

Fail-closed by construction:

* The public entry point is :meth:`PolicyProvider.decide`, which wraps the
  provider's :meth:`PolicyProvider.evaluate` in a catch-all. ANY exception
  raised inside a provider (bad regex, missing context key, corrupt policy,
  programming bug) surfaces as a ``DENY`` decision — it can never propagate
  as an allow.
* Every provider defaults to DENY: no matching rule, no applicable permit,
  undefined result, stale policy version, or bad signature all deny.
* Decisions leave the provider as a signed
  :class:`PolicyDecisionRecord` (COSE_Sign1 over canonical bytes binding
  ``action_digest`` + ``provider_id`` + ``policy_version`` + ``outcome``).
  The Guardian consumes the record; on ALLOW the Guardian (not this module)
  mints the capability.

Providers shipped here:

* :class:`NativeProvider` — ordered first-match-wins rules over regex
  matches on plane/verb/target/principal. The policy document is itself
  COSE_Sign1-signed by a trusted policy key; wrong signature or a version
  below the pinned minimum refuses to load (fail closed).
* :class:`CedarAdapter` — pure-Python evaluator for a DOCUMENTED SUBSET of
  Cedar (see "Cedar subset" below).
* :class:`OPAAdapter` — pure-Python evaluator for a DOCUMENTED SUBSET of
  Rego (see "Rego subset" below).

Cedar subset
------------
Policies are declared as data (dicts), not parsed from Cedar text:

    {"effect": "permit" | "forbid",
     "principal": <exact string> | omitted (= Any),
     "action": <exact "plane:verb"> | omitted (= Any),
     "resource": <exact target string> | omitted (= Any),
     "when":   [conditions...],   # ALL must hold for the policy to apply
     "unless": [conditions...]}   # ANY holding vetoes the policy

A condition is ``{"attr": <dotted path into the input>, "op": <op>,
"value": <literal>}``. The input document is::

    {"principal": ..., "plane": ..., "verb": ..., "target": ...,
     "context": {<caller-supplied attributes>}}

Supported ops: ``eq, neq, lt, lte, gt, gte, in, contains``.

NOT supported (rejected at load): hierarchical entity relations, ``like``
patterns, ``is``/``in`` principal scoping over entity sets, Cedar functions
(``decimal()``, ``ip()``...), extension types, ``forbid`` with
``unless``-only bodies beyond the boolean subset above, templates/links,
partial evaluation. Anything outside the subset raises
:class:`PolicyError` at load time — never silently ignored.

Semantics (Cedar-faithful):

* ``forbid`` beats ``permit``: any applicable forbid -> DENY.
* No applicable permit -> DENY (default deny).
* Comparisons are TYPE-STRICT: a string never equals an int, ordering
  requires both sides numeric (bool excluded) or both strings. A type
  mismatch makes the condition FALSE (fail closed) for EVERY operator,
  ``neq`` included — type confusion NEVER grants — never an error that a
  caller could misread as allow. Missing attributes are undefined ->
  condition FALSE.
* NUMERIC TYPES: context attributes and policy literals may be ``int``,
  ``float``, ``decimal.Decimal``, or ``fractions.Fraction``. ``bool`` is
  NOT a number here (even though ``bool`` subclasses ``int``): ``True``
  never equals ``1`` and never orders against numbers. Mixed numerics
  compare by value; when either side is a ``Decimal`` both sides are
  compared as ``Decimal`` (``Decimal(int)`` is exact, ``Decimal(float)``
  is the exact binary value, ``Decimal(Fraction)`` is exact). Other
  numeric-like objects (e.g. ``complex``) are not numbers for policy
  purposes -> type confusion -> condition FALSE.
* NON-FINITE NUMERICS (NaN, +inf, -inf) of ANY numeric type — ``float``
  AND ``decimal.Decimal`` — are UNDEFINED: any condition whose resolved
  attribute value or literal operand contains one — at the top level or
  nested inside a dict/list — evaluates FALSE for EVERY operator,
  including ``neq`` (fail closed). IEEE 754 makes ``NaN != x`` true for
  all ``x``, so without this rule a single NaN in caller-supplied context
  would sail through every ``neq`` gate and force an ALLOW (red team
  RT-001). (``Fraction`` cannot represent non-finite values.)

Rego subset
-----------
Policies are declared as nested dicts, not parsed from Rego text:

    {"version": <str>, "rules": [{"name": <str>, "conditions": [conditions...]}]}

A condition has the same shape as the Cedar subset above and is evaluated
over the same input document (principal/plane/verb/target/context).

* ``allow`` holds iff ANY rule has ALL of its conditions true.
* Default is DENY. An empty rule list, a rule with no satisfied conditions,
  or an undefined/empty evaluation result -> DENY.
* Conditions are evaluated by the SAME shared machinery as the Cedar subset
  above, including the non-finite fail-closed rule: NaN / +inf / -inf of
  any numeric type (``float``, ``Decimal``) anywhere in an attribute value
  or literal operand makes the condition FALSE for every operator,
  ``neq`` included.
* NOT supported (rejected at load): negation (``not``), disjunction inside
  a rule body beyond the implicit AND, iteration (``some x in xs``),
  arithmetic, functions, ``else`` chains, partial rules/sets, imports,
  packages, default-override semantics. ``default`` must be ``"deny"``.

Security notes
--------------
* Regexes in native rules use ``re.fullmatch`` (no partial-match smuggling)
  and are compiled at load; an invalid pattern fails the load, not an
  evaluation.
* Context values are compared by value with strict types; no ``eval``,
  no attribute access on live objects — dotted paths walk plain dicts only.
"""

from __future__ import annotations

import math
import numbers
import re
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from decimal import Decimal
from fractions import Fraction
from typing import Any, Literal, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import field_validator

from .cbor import cbor_dumps, cbor_loads
from .cose import COSEError, cose_sign_bytes, cose_verify
from .crypto import Ed25519Signer
from .envelope import ActionEnvelope
from .models import StrictModel

__all__ = [
    "PolicyError",
    "PolicyOutcome",
    "PolicyDecision",
    "PolicyDecisionRecord",
    "PolicyProvider",
    "NativeRule",
    "NativePolicyDoc",
    "NativeProvider",
    "CedarCondition",
    "CedarPolicy",
    "CedarPolicySet",
    "CedarAdapter",
    "RegoCondition",
    "RegoRule",
    "RegoPolicy",
    "OPAAdapter",
    "sign_native_policy",
    "sign_decision_record",
    "verify_decision_record",
    "check_decision_binding",
]

PolicyOutcome = Literal["ALLOW", "DENY", "ABSTAIN"]


class PolicyError(ValueError):
    """Fail-closed policy error. Raised on malformed policy, bad signature,
    stale version, or decision-record verification failure."""


# ---------------------------------------------------------------------------
# Core decision types
# ---------------------------------------------------------------------------


class PolicyDecision(StrictModel):
    """In-memory verdict from a provider."""

    outcome: PolicyOutcome
    reason: str
    obligations: list[str] = []


class PolicyDecisionRecord(StrictModel):
    """Signed, serializable verdict the Guardian consumes.

    The canonical bytes bind ``action_digest`` (THE envelope binding point)
    together with the provider identity, policy version, and outcome, so a
    record cannot be replayed against a different envelope or a different
    policy.
    """

    action_digest: str  # sha256 hex of the envelope canonical bytes
    provider_id: str
    policy_version: str
    outcome: PolicyOutcome
    reason: str
    evaluated_at: datetime

    @field_validator("evaluated_at")
    @classmethod
    def _coerce_utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)

    @field_validator("action_digest")
    @classmethod
    def _digest_shape(cls, v: str) -> str:
        if not re.fullmatch(r"[0-9a-f]{64}", v):
            raise ValueError("action_digest must be 64 lowercase hex chars")
        return v

    def canonical_bytes(self) -> bytes:
        return cbor_dumps(self.model_dump(mode="json"))


# ---------------------------------------------------------------------------
# Provider ABC — fail-closed wrapper
# ---------------------------------------------------------------------------


class PolicyProvider(ABC):
    """Base class for policy providers.

    Implement :meth:`evaluate`. Callers (the Guardian) MUST use
    :meth:`decide`, which converts ANY exception — including bugs inside the
    provider — into a DENY decision. There is no path from an exception to
    an allow.
    """

    provider_id: str = "base"
    policy_version: str = "0"

    @abstractmethod
    def evaluate(self, envelope: ActionEnvelope, context: dict) -> PolicyDecision:
        """Return the verdict. May raise; :meth:`decide` converts to DENY."""
        raise NotImplementedError

    def decide(self, envelope: ActionEnvelope, context: dict) -> PolicyDecision:
        """Fail-closed evaluation entry point."""
        try:
            decision = self.evaluate(envelope, context)
        except Exception as exc:  # noqa: BLE001 — fail closed on everything
            return PolicyDecision(
                outcome="DENY",
                reason=f"provider {self.provider_id} raised "
                f"{type(exc).__name__}: {exc}",
                obligations=[],
            )
        if not isinstance(decision, PolicyDecision):
            return PolicyDecision(
                outcome="DENY",
                reason=f"provider {self.provider_id} returned non-decision "
                f"{type(decision).__name__}",
                obligations=[],
            )
        if decision.outcome not in ("ALLOW", "DENY", "ABSTAIN"):
            return PolicyDecision(
                outcome="DENY",
                reason=f"provider {self.provider_id} returned invalid outcome",
                obligations=[],
            )
        return decision

    def issue_decision_record(
        self,
        decision: PolicyDecision,
        envelope: ActionEnvelope,
        signer: Ed25519Signer,
    ) -> bytes:
        """Sign a PolicyDecisionRecord binding this decision to the envelope.

        The record binds ``envelope.action_digest`` so it cannot be replayed
        against a different action.
        """
        record = PolicyDecisionRecord(
            action_digest=envelope.action_digest,
            provider_id=self.provider_id,
            policy_version=self.policy_version,
            outcome=decision.outcome,
            reason=decision.reason,
            evaluated_at=datetime.now(timezone.utc),
        )
        return sign_decision_record(record, signer)


# ---------------------------------------------------------------------------
# Shared condition machinery (Cedar + Rego subsets)
# ---------------------------------------------------------------------------

_CONDITION_OPS = ("eq", "neq", "lt", "lte", "gt", "gte", "in", "contains")

_MISSING = object()  # sentinel for undefined attribute paths


def _resolve_path(document: Mapping[str, Any], path: str) -> Any:
    """Walk dotted path through plain dicts. Non-dict traversal or a missing
    key yields the _MISSING sentinel (undefined -> condition FALSE)."""
    current: Any = document
    for part in path.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return _MISSING
        current = current[part]
    return current


def _is_number(value: Any) -> bool:
    """Numeric types accepted in context/policy literals: int, float,
    Decimal, Fraction — i.e. ``numbers.Real`` plus ``Decimal`` (Decimal is
    only registered as ``numbers.Number``, not ``Real``). ``bool`` is
    explicitly NOT a number (bool subclasses int; the suite asserts
    type-strictness, e.g. ``True`` never equals ``1``)."""
    if isinstance(value, bool):
        return False
    return isinstance(value, (numbers.Real, Decimal))


def _is_nonfinite_number(value: Any) -> bool:
    """True for NaN / +inf / -inf of ANY numeric type (float, Decimal,
    Fraction — Fraction can never be non-finite, but the check is uniform).
    Ints are always finite; bools are not numbers here at all."""
    if isinstance(value, bool):
        return False
    return isinstance(value, (numbers.Real, Decimal)) and not math.isfinite(
        value
    )


def _tree_has_nonfinite(value: Any) -> bool:
    """Recursively scan a scalar or container for non-finite numerics of any
    type (float NaN/inf, Decimal('NaN')/Decimal('Infinity'), ...).

    Catches non-finites smuggled at the top level of a context attribute or
    nested inside dicts/lists/tuples/sets/frozensets (e.g. ``context.limits``
    resolving to ``{"max": {Decimal("NaN")}}``). Sets and frozensets are
    traversable containers a caller context can carry, so an untraversed
    set would otherwise be an RT-001-shaped smuggling lane (FIX-A3/P1).
    """
    if _is_nonfinite_number(value):
        return True
    if isinstance(value, Mapping):
        return any(_tree_has_nonfinite(v) for v in value.values())
    if isinstance(value, (list, tuple, set, frozenset)):
        return any(_tree_has_nonfinite(v) for v in value)
    return False


def _to_decimal(value: Any) -> Decimal:
    """Lossless-ish common representation for mixed numeric comparison.

    Only called on finite numbers (the non-finite guard runs first):
    ``Decimal(int)`` is exact, ``Decimal(float)`` is the exact binary value,
    ``Decimal(Fraction)`` is spelled out via numerator/denominator because
    the Decimal constructor does not accept Fraction directly. Caller
    guarantees finiteness, so the constructor cannot raise on NaN/inf.
    """
    if isinstance(value, Decimal):
        return value
    if isinstance(value, Fraction):
        return Decimal(value.numerator) / Decimal(value.denominator)
    return Decimal(value)


def _type_compatible(actual: Any, expected: Any) -> bool:
    """Type-compatibility for comparison. Numeric types (int/float/Decimal/
    Fraction, bool excluded) are mutually compatible and compare by value;
    every other value is compatible only with its exact type. This mirrors
    the compatibility rule inside :func:`_values_equal`, so that ``neq``
    cannot grant on type confusion: type confusion NEVER grants (FIX-A3/P2).
    """
    if _is_number(actual) and _is_number(expected):
        return True
    return type(actual) is type(expected)


def _values_equal(actual: Any, expected: Any) -> bool:
    """Type-strict equality. Strings never equal ints; bools never equal
    numbers. Numerics (int/float/Decimal/Fraction, bool excluded) compare by
    value; when either side is a Decimal both sides are compared as Decimal.
    Non-finite numerics (NaN, +inf, -inf) of ANY type are UNDEFINED and
    therefore never equal to anything — not even themselves (NaN != NaN, and
    inf == inf would otherwise be a smuggling vector for ``eq``)."""
    if _is_number(actual) and _is_number(expected):
        if _is_nonfinite_number(actual) or _is_nonfinite_number(expected):
            return False
        if isinstance(actual, Decimal) or isinstance(expected, Decimal):
            return _to_decimal(actual) == _to_decimal(expected)
        return actual == expected
    return type(actual) is type(expected) and actual == expected


def _numeric_ordering(op: str, actual: Any, expected: Any) -> bool:
    """Ordering on two finite numbers (non-finite already excluded by the
    caller). Decimal/Fraction-vs-float mixes are compared via Decimal; any
    comparison that still cannot be performed (e.g. an exotic Real whose
    constructor or comparison raises) fails closed to FALSE."""
    try:
        if isinstance(actual, Decimal) or isinstance(expected, Decimal):
            left, right = _to_decimal(actual), _to_decimal(expected)
        else:
            left, right = actual, expected
        if op == "lt":
            return left < right
        if op == "lte":
            return left <= right
        if op == "gt":
            return left > right
        return left >= right
    except (TypeError, ArithmeticError, ValueError):
        return False


def _compare(op: str, actual: Any, expected: Any) -> bool:
    """Evaluate one condition. Undefined actual -> False. Type confusion ->
    False (fail closed), never an exception that could be misread."""
    if actual is _MISSING:
        return False
    # RT-001 fail-closed rule: non-finite numerics of ANY type (float NaN/inf,
    # Decimal('NaN')/Decimal('Infinity'), ...) are UNDEFINED, so the condition
    # is FALSE for EVERY operator, ``neq`` included. Without this, IEEE 754
    # makes ``NaN != x`` true for all ``x`` and a single NaN in
    # caller-supplied context sails through every ``neq`` gate -> ALLOW.
    if _tree_has_nonfinite(actual) or _tree_has_nonfinite(expected):
        return False
    if op == "eq":
        return _values_equal(actual, expected)
    if op == "neq":
        # FIX-A3/P2: neq used to return TRUE on type confusion
        # (not _values_equal -> True). Per the documented fail-closed
        # invariant, type confusion makes the condition FALSE for EVERY
        # operator, neq included — type confusion NEVER grants.
        if not _type_compatible(actual, expected):
            return False
        return not _values_equal(actual, expected)
    if op in ("lt", "lte", "gt", "gte"):
        if _is_number(actual) and _is_number(expected):
            return _numeric_ordering(op, actual, expected)
        if isinstance(actual, str) and isinstance(expected, str):
            if op == "lt":
                return actual < expected
            if op == "lte":
                return actual <= expected
            if op == "gt":
                return actual > expected
            return actual >= expected
        return False  # type confusion -> condition does not hold
    if op == "in":
        if not isinstance(expected, list):
            return False
        return any(_values_equal(actual, item) for item in expected)
    if op == "contains":
        if isinstance(actual, list):
            return any(_values_equal(item, expected) for item in actual)
        if isinstance(actual, str) and isinstance(expected, str):
            return expected in actual
        return False
    return False  # unknown op (rejected at load; defense in depth)


class _Condition(StrictModel):
    attr: str
    op: Literal["eq", "neq", "lt", "lte", "gt", "gte", "in", "contains"]
    value: Any

    def holds(self, document: Mapping[str, Any]) -> bool:
        return _compare(self.op, _resolve_path(document, self.attr), self.value)


def _input_document(envelope: ActionEnvelope, context: dict) -> dict[str, Any]:
    return {
        "principal": envelope.principal,
        "plane": envelope.effect.plane,
        "verb": envelope.effect.verb,
        "target": envelope.effect.target,
        "context": dict(context),
    }


# ---------------------------------------------------------------------------
# Native provider — signed first-match-wins rule list
# ---------------------------------------------------------------------------


class NativeRule(StrictModel):
    """One ordered rule. ``match`` maps a subset of
    {principal, plane, verb, target} to regexes (fullmatch semantics).
    First matching rule wins; ``effect`` decides."""

    id: str = ""
    match: dict[str, str]
    effect: Literal["allow", "deny"]
    obligations: list[str] = []

    @field_validator("match")
    @classmethod
    def _match_keys(cls, v: dict[str, str]) -> dict[str, str]:
        allowed = {"principal", "plane", "verb", "target"}
        for key in v:
            if key not in allowed:
                raise ValueError(f"unknown match key {key!r}; allowed: {sorted(allowed)}")
        if not v:
            raise ValueError("match must not be empty (a match-all rule must say so explicitly)")
        return v

    def compiled(self) -> dict[str, "re.Pattern[str]"]:
        try:
            return {k: re.compile(p) for k, p in self.match.items()}
        except re.error as exc:
            raise PolicyError(f"invalid regex in rule {self.id!r}: {exc}") from exc


class NativePolicyDoc(StrictModel):
    """The signed native policy document."""

    version: int
    rules: list[NativeRule]

    @field_validator("version")
    @classmethod
    def _version_positive(cls, v: int) -> int:
        if v < 1:
            raise ValueError("version must be >= 1")
        return v


def sign_native_policy(doc: NativePolicyDoc, signer: Ed25519Signer) -> bytes:
    """COSE_Sign1-sign the canonical CBOR of a native policy document."""
    payload = cbor_dumps(doc.model_dump(mode="json"))
    return cose_sign_bytes(payload, signer.sign_bytes, signer.key_id.encode("utf-8"))


def _cose_payload(raw: bytes, trusted_keys: Mapping[str, bytes], what: str) -> bytes:
    """Verify COSE_Sign1 and return the payload. Any failure -> PolicyError."""
    key_map = {}
    for kid, pub in trusted_keys.items():
        try:
            key_map[kid.encode("utf-8")] = Ed25519PublicKey.from_public_bytes(pub)
        except Exception as exc:
            raise PolicyError(f"{what}: bad trusted key {kid!r}: {exc}") from exc
    try:
        payload, _kid = cose_verify(raw, key_map)
    except COSEError as exc:
        raise PolicyError(f"{what}: signature verification failed: {exc}") from exc
    return payload


class NativeProvider(PolicyProvider):
    """Ordered regex rules from a COSE-signed policy document.

    Load is fail-closed: bad signature, malformed document, invalid regex,
    or a version below the pinned minimum raises :class:`PolicyError` and
    the provider evaluates every envelope as DENY until a valid policy is
    loaded. Evaluation is first-match-wins; no match -> DENY (default deny).
    """

    def __init__(
        self,
        trusted_policy_keys: Mapping[str, bytes],
        *,
        provider_id: str = "native",
        min_version: int = 1,
    ) -> None:
        self.provider_id = provider_id
        self._trusted_keys = dict(trusted_policy_keys)
        self._min_version = min_version
        self._doc: NativePolicyDoc | None = None
        self._compiled: list[tuple[NativeRule, dict[str, "re.Pattern[str]"]]] = []
        self.policy_version = "0"

    def load_signed_policy(self, raw: bytes) -> None:
        """Verify, parse, and pin a signed policy document. Raises
        PolicyError on anything wrong; the old policy (if any) is kept only
        when the new document verifies — a failed load never installs a
        half-parsed policy, and with no valid policy loaded the provider
        denies everything."""
        payload = _cose_payload(raw, self._trusted_keys, "native policy")
        try:
            data = cbor_loads(payload)
        except Exception as exc:
            raise PolicyError(f"native policy: payload is not valid CBOR: {exc}") from exc
        try:
            doc = NativePolicyDoc.model_validate(data)
        except Exception as exc:
            raise PolicyError(f"native policy: malformed document: {exc}") from exc
        if doc.version < self._min_version:
            raise PolicyError(
                f"native policy: version {doc.version} below pinned minimum "
                f"{self._min_version} (rollback refused)"
            )
        compiled = [(rule, rule.compiled()) for rule in doc.rules]
        # Install atomically only after everything verified.
        self._doc = doc
        self._compiled = compiled
        self.policy_version = str(doc.version)

    def evaluate(self, envelope: ActionEnvelope, context: dict) -> PolicyDecision:
        if self._doc is None:
            return PolicyDecision(
                outcome="DENY",
                reason="no valid native policy loaded",
                obligations=[],
            )
        fields = {
            "principal": envelope.principal,
            "plane": envelope.effect.plane,
            "verb": envelope.effect.verb,
            "target": envelope.effect.target,
        }
        for rule, patterns in self._compiled:
            if all(pat.fullmatch(fields[key]) for key, pat in patterns.items()):
                outcome = "ALLOW" if rule.effect == "allow" else "DENY"
                label = rule.id or "<unnamed>"
                return PolicyDecision(
                    outcome=outcome,
                    reason=f"native rule {label} matched ({rule.effect})",
                    obligations=list(rule.obligations),
                )
        return PolicyDecision(
            outcome="DENY",
            reason="no native rule matched (default deny)",
            obligations=[],
        )


# ---------------------------------------------------------------------------
# Cedar adapter (documented subset)
# ---------------------------------------------------------------------------


class CedarCondition(_Condition):
    """A when/unless clause condition (see module docstring for the subset)."""


class CedarPolicy(StrictModel):
    effect: Literal["permit", "forbid"]
    principal: str | None = None
    action: str | None = None  # exact "plane:verb"
    resource: str | None = None  # exact target
    when: list[CedarCondition] = []
    unless: list[CedarCondition] = []


class CedarPolicySet(StrictModel):
    version: str = "1"
    policies: list[CedarPolicy]


class CedarAdapter(PolicyProvider):
    """Pure-Python evaluator for the documented Cedar subset.

    Fail-closed: malformed policy -> PolicyError at construction; forbid
    beats permit; no applicable permit -> DENY; type confusion or undefined
    attributes make conditions FALSE.
    """

    def __init__(self, policy: dict, *, provider_id: str = "cedar") -> None:
        self.provider_id = provider_id
        try:
            self._policy_set = CedarPolicySet.model_validate(policy)
        except Exception as exc:
            raise PolicyError(f"cedar policy: malformed: {exc}") from exc
        self.policy_version = self._policy_set.version

    def _applies(self, policy: CedarPolicy, doc: Mapping[str, Any]) -> bool:
        if policy.principal is not None and policy.principal != doc["principal"]:
            return False
        if policy.action is not None and policy.action != f"{doc['plane']}:{doc['verb']}":
            return False
        if policy.resource is not None and policy.resource != doc["target"]:
            return False
        if not all(cond.holds(doc) for cond in policy.when):
            return False
        if any(cond.holds(doc) for cond in policy.unless):
            return False
        return True

    def evaluate(self, envelope: ActionEnvelope, context: dict) -> PolicyDecision:
        doc = _input_document(envelope, context)
        applicable_permits = 0
        for policy in self._policy_set.policies:
            if not self._applies(policy, doc):
                continue
            if policy.effect == "forbid":
                return PolicyDecision(
                    outcome="DENY",
                    reason="cedar forbid policy applied (forbid overrides permit)",
                    obligations=[],
                )
            applicable_permits += 1
        if applicable_permits:
            return PolicyDecision(
                outcome="ALLOW",
                reason=f"cedar permit applied ({applicable_permits} applicable)",
                obligations=[],
            )
        return PolicyDecision(
            outcome="DENY",
            reason="no applicable cedar permit (default deny)",
            obligations=[],
        )


# ---------------------------------------------------------------------------
# OPA adapter (documented subset of Rego-as-data)
# ---------------------------------------------------------------------------


class RegoCondition(_Condition):
    """A rule-body condition (see module docstring for the subset)."""


class RegoRule(StrictModel):
    name: str
    conditions: list[RegoCondition]


class RegoPolicy(StrictModel):
    version: str = "1"
    default: Literal["deny"] = "deny"
    rules: list[RegoRule]


class OPAAdapter(PolicyProvider):
    """Pure-Python evaluator for the documented Rego subset.

    ``allow`` iff ANY rule has ALL conditions true over the input document;
    otherwise DENY (default deny; undefined/empty result -> DENY).
    """

    def __init__(self, policy: dict, *, provider_id: str = "opa") -> None:
        self.provider_id = provider_id
        try:
            self._policy = RegoPolicy.model_validate(policy)
        except Exception as exc:
            raise PolicyError(f"rego policy: malformed: {exc}") from exc
        self.policy_version = self._policy.version

    def evaluate(self, envelope: ActionEnvelope, context: dict) -> PolicyDecision:
        doc = _input_document(envelope, context)
        for rule in self._policy.rules:
            # Empty rule bodies are undefined, never allow: vacuous truth
            # (all([]) is True) would otherwise grant allow-by-default.
            if rule.conditions and all(cond.holds(doc) for cond in rule.conditions):
                return PolicyDecision(
                    outcome="ALLOW",
                    reason=f"rego rule {rule.name!r} satisfied",
                    obligations=[],
                )
        return PolicyDecision(
            outcome="DENY",
            reason="no rego rule satisfied (default deny)",
            obligations=[],
        )


# ---------------------------------------------------------------------------
# Signed decision records
# ---------------------------------------------------------------------------


def sign_decision_record(record: PolicyDecisionRecord, signer: Ed25519Signer) -> bytes:
    """COSE_Sign1-sign the canonical bytes of a decision record."""
    return cose_sign_bytes(
        record.canonical_bytes(), signer.sign_bytes, signer.key_id.encode("utf-8")
    )


def verify_decision_record(
    raw: bytes, trusted_keys: Mapping[str, bytes]
) -> PolicyDecisionRecord:
    """Verify a signed decision record and return the parsed record.

    Raises :class:`PolicyError` on bad COSE structure, unknown kid,
    bad signature, or malformed record fields. Tampering with ANY byte of
    the record (including the bound action_digest) breaks the signature.
    """
    payload = _cose_payload(raw, trusted_keys, "decision record")
    try:
        data = cbor_loads(payload)
    except Exception as exc:
        raise PolicyError(f"decision record: payload is not valid CBOR: {exc}") from exc
    try:
        return PolicyDecisionRecord.model_validate(data)
    except Exception as exc:
        raise PolicyError(f"decision record: malformed: {exc}") from exc


def check_decision_binding(record: PolicyDecisionRecord, envelope: ActionEnvelope) -> None:
    """Reject a decision record replayed against a different envelope.

    Raises :class:`PolicyError` unless ``record.action_digest`` equals the
    envelope's digest. The Guardian must call this before minting any
    capability from an ALLOW record.
    """
    if record.action_digest != envelope.action_digest:
        raise PolicyError(
            "decision record action_digest does not match envelope "
            "(replay across envelopes rejected)"
        )
