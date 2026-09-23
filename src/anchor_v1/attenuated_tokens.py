"""Attenuated capability tokens v2 — Biscuit-grade, offline-verifiable.

A token binds a capability grant to:
  * a holder key (proof-of-possession: the holder signs ``nonce || capability_id``),
  * an exact invocation (``parameters_hash`` = sha256 of the canonical
    invocation parameters),
  * a set of Datalog-style caveats (``{"kind": ..., "params": {...}}``),
  * a validity window, a single-use nonce, and an optional parent token
    (delegation chain).

Attenuation is narrowing-only: a child token's authority is provably a subset
of its parent's (the SUBSUMPTION relation). Verification is a fail-closed
pipeline — any failure raises :class:`AuthorizationError`; it never returns a
soft allow.

Caveat vocabulary is intentionally shaped like the IETF attenuating-agent-tokens
(niess/niyikiza) draft constraint vocabulary: small named constraints with
parameters, evaluated against the invocation context at the enforcement point.

This module owns ONLY this file's contents. It uses the package's real
``crypto``/``models`` helpers directly.
"""

from __future__ import annotations

import base64
import hmac
import secrets
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from pydantic import Field

from .crypto import Ed25519Signer, verify_envelope
from .models import SignedEnvelope, StrictModel

from .canonical import sha256_hex

__all__ = [
    "AuthorizationError",
    "Caveat",
    "AttenuatedTokenPayload",
    "CAVEAT_KINDS",
    "issue",
    "attenuate",
    "verify",
    "make_holder_proof",
    "token_hash",
    "MAX_CHAIN_DEPTH",
    "TOKEN_VERSION",
]

TOKEN_VERSION = 2
MAX_CHAIN_DEPTH = 8


class AuthorizationError(Exception):
    """Raised for every denial. Fail-closed: verify() never returns a soft allow."""


class Caveat(StrictModel):
    """One Datalog-style constraint: {"kind": ..., "params": {...}}."""

    kind: str = Field(min_length=1)
    params: dict[str, Any] = Field(default_factory=dict)


class AttenuatedTokenPayload(StrictModel):
    """Canonical payload of an attenuated capability token (v2)."""

    version: int = Field(default=TOKEN_VERSION)
    capability_id: str = Field(min_length=1)
    issuer: str = Field(min_length=1)  # key_id of the issuing key
    subject: str = Field(min_length=1)  # holder binding: b64 Ed25519 pubkey or key_id
    audience: str = Field(min_length=1)  # enforcement point this token is for
    action: str = Field(min_length=1)
    resource: str = Field(min_length=1)
    parameters_hash: str = Field(min_length=1)  # invocation binding
    caveats: list[Caveat] = Field(default_factory=list)
    not_before: datetime
    expires_at: datetime
    nonce: str = Field(min_length=1)
    parent_token_hash: str | None = None  # None for root tokens
    constitution_hash: str = Field(min_length=1)  # which constitution authorized issuance


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------


def _require_aware(value: datetime, name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise AuthorizationError(f"{name} must be a timezone-aware datetime")
    return value.astimezone(timezone.utc)


def _parse_aware_iso(value: str, name: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except (ValueError, TypeError) as exc:
        raise AuthorizationError(f"{name} is not a valid ISO-8601 datetime") from exc
    return _require_aware(parsed, name)


def _is_prefix_at_boundary(prefix: str, value: str) -> bool:
    """Segment-boundary prefix check. Never raw startswith.

    "workspace://scope" matches "workspace://scope/docs" but MUST NOT match
    "workspace://scope-evil".
    """
    if value == prefix:
        return True
    if not value.startswith(prefix):
        return False
    rest = value[len(prefix):]
    return rest.startswith("/") or prefix.endswith("/")


def _url_prefix_ok(allowed: str, url: str) -> bool:
    if url == allowed:
        return True
    if not url.startswith(allowed):
        return False
    rest = url[len(allowed):]
    return rest[:1] in ("", "/", "?", "#")


def token_hash(envelope: SignedEnvelope) -> str:
    """Content hash of a token envelope (sha256 over the canonical payload)."""
    return sha256_hex(envelope.payload)


def _resolve_holder_pubkey(
    subject: str, holder_keys: dict[str, str] | None
) -> bytes:
    """Resolve the token's subject binding to 32 raw Ed25519 public-key bytes.

    ``subject`` is either the base64-encoded raw public key itself, or a
    key_id resolvable through ``holder_keys``. Anything else is a denial.
    """
    try:
        raw = base64.b64decode(subject, validate=True)
    except Exception:
        raw = b""
    if len(raw) == 32:
        return raw
    if holder_keys and subject in holder_keys:
        try:
            raw = base64.b64decode(holder_keys[subject], validate=True)
        except Exception as exc:
            raise AuthorizationError("holder_keys entry is not valid base64") from exc
        if len(raw) != 32:
            raise AuthorizationError("holder_keys entry is not a 32-byte Ed25519 key")
        return raw
    raise AuthorizationError("subject holder key is not resolvable")


def _parse_payload(raw: dict[str, Any]) -> AttenuatedTokenPayload:
    try:
        return AttenuatedTokenPayload.model_validate(raw)
    except Exception as exc:
        raise AuthorizationError(f"malformed token payload: {exc}") from exc


# ---------------------------------------------------------------------------
# caveat registry: validators (mint time) + evaluators (verify time)
# ---------------------------------------------------------------------------

Validator = Callable[[dict[str, Any]], None]
Evaluator = Callable[
    [Caveat, AttenuatedTokenPayload, dict[str, Any], datetime, set[str] | None], None
]


def _v_expiry(params: dict[str, Any]) -> None:
    if not isinstance(params.get("expires_at"), str):
        raise ValueError("expiry caveat requires params.expires_at (ISO-8601 string)")
    _parse_aware_iso(params["expires_at"], "expiry.expires_at")


def _e_expiry(
    caveat: Caveat,
    payload: AttenuatedTokenPayload,
    ctx: dict[str, Any],
    now: datetime,
    used_nonces: set[str] | None,
) -> None:
    if now > _parse_aware_iso(caveat.params["expires_at"], "expiry.expires_at"):
        raise AuthorizationError("caveat violated: expiry")


def _v_uses(params: dict[str, Any]) -> None:
    max_uses = params.get("max_uses")
    if isinstance(max_uses, bool) or not isinstance(max_uses, int) or max_uses < 1:
        raise ValueError("uses caveat requires params.max_uses (int >= 1)")


def _e_uses(
    caveat: Caveat,
    payload: AttenuatedTokenPayload,
    ctx: dict[str, Any],
    now: datetime,
    used_nonces: set[str] | None,
) -> None:
    max_uses = caveat.params["max_uses"]
    if max_uses == 1:
        # Single-use tokens are only safe with caller-side replay tracking.
        if used_nonces is None:
            raise AuthorizationError(
                "caveat violated: single-use token requires a used-nonce set"
            )
        return  # membership itself is enforced by the nonce-freshness step
    consumed = ctx.get("uses_consumed", 0)
    if isinstance(consumed, bool) or not isinstance(consumed, int):
        raise AuthorizationError("caveat violated: uses_consumed must be an int")
    if consumed >= max_uses:
        raise AuthorizationError("caveat violated: uses exhausted")


def _v_http_allowlist(params: dict[str, Any]) -> None:
    hosts = params.get("hosts", [])
    urls = params.get("urls", [])
    if not isinstance(hosts, list) or not isinstance(urls, list):
        raise ValueError("http_allowlist requires params.hosts/params.urls to be lists")
    if not hosts and not urls:
        raise ValueError("http_allowlist requires a non-empty hosts or urls list")
    if any(not isinstance(h, str) or not h for h in hosts + urls):
        raise ValueError("http_allowlist hosts/urls must be non-empty strings")


def _e_http_allowlist(
    caveat: Caveat,
    payload: AttenuatedTokenPayload,
    ctx: dict[str, Any],
    now: datetime,
    used_nonces: set[str] | None,
) -> None:
    # Fail-closed: every allowlisted dimension must be present in the
    # invocation context and must match. Absent context => deny.
    if "hosts" in caveat.params:
        host = ctx.get("http_host")
        if not isinstance(host, str) or host not in caveat.params["hosts"]:
            raise AuthorizationError("caveat violated: http host not allowlisted")
    if "urls" in caveat.params:
        url = ctx.get("http_url")
        if not isinstance(url, str) or not any(
            _url_prefix_ok(a, url) for a in caveat.params["urls"]
        ):
            raise AuthorizationError("caveat violated: http url not allowlisted")


def _v_resource_prefix(params: dict[str, Any]) -> None:
    if not isinstance(params.get("prefix"), str) or not params["prefix"]:
        raise ValueError("resource_prefix caveat requires params.prefix (string)")


def _e_resource_prefix(
    caveat: Caveat,
    payload: AttenuatedTokenPayload,
    ctx: dict[str, Any],
    now: datetime,
    used_nonces: set[str] | None,
) -> None:
    target = ctx.get("resource", payload.resource)
    if not isinstance(target, str) or not _is_prefix_at_boundary(
        caveat.params["prefix"], target
    ):
        raise AuthorizationError("caveat violated: resource outside allowed prefix")


def _v_spend_limit(params: dict[str, Any]) -> None:
    amount = params.get("max_amount")
    if isinstance(amount, bool) or not isinstance(amount, (int, float)):
        raise ValueError("spend_limit caveat requires params.max_amount (number)")
    if amount < 0:
        raise ValueError("spend_limit max_amount must be >= 0")
    if "currency" in params and (
        not isinstance(params["currency"], str) or not params["currency"]
    ):
        raise ValueError("spend_limit currency must be a non-empty string")


def _e_spend_limit(
    caveat: Caveat,
    payload: AttenuatedTokenPayload,
    ctx: dict[str, Any],
    now: datetime,
    used_nonces: set[str] | None,
) -> None:
    # Fail-closed: a spend-limited token presented without spend context => deny.
    if "spend_amount" not in ctx:
        raise AuthorizationError("caveat violated: spend_limit requires spend context")
    amount = ctx["spend_amount"]
    if isinstance(amount, bool) or not isinstance(amount, (int, float)):
        raise AuthorizationError("caveat violated: spend_amount must be a number")
    if amount > caveat.params["max_amount"]:
        raise AuthorizationError("caveat violated: spend limit exceeded")
    if "currency" in caveat.params and ctx.get("spend_currency") != caveat.params[
        "currency"
    ]:
        raise AuthorizationError("caveat violated: spend currency mismatch")


_CAVEATS: dict[str, tuple[Validator, Evaluator]] = {
    "expiry": (_v_expiry, _e_expiry),
    "uses": (_v_uses, _e_uses),
    "http_allowlist": (_v_http_allowlist, _e_http_allowlist),
    "resource_prefix": (_v_resource_prefix, _e_resource_prefix),
    "spend_limit": (_v_spend_limit, _e_spend_limit),
}

#: Public registry of supported caveat kinds (extensible: add a kind here with
#: a mint-time validator and a verify-time evaluator).
CAVEAT_KINDS: tuple[str, ...] = tuple(_CAVEATS)


def _validate_caveat(caveat: Caveat) -> None:
    """Mint-time validation. Raises ValueError (programmer error), not deny."""
    entry = _CAVEATS.get(caveat.kind)
    if entry is None:
        raise ValueError(f"unknown caveat kind: {caveat.kind!r}")
    entry[0](caveat.params)


def _evaluate_caveat(
    caveat: Caveat,
    payload: AttenuatedTokenPayload,
    ctx: dict[str, Any],
    now: datetime,
    used_nonces: set[str] | None,
) -> None:
    entry = _CAVEATS.get(caveat.kind)
    if entry is None:
        # Unknown caveat kinds can never be evaluated => fail closed.
        raise AuthorizationError(f"unevaluable caveat kind: {caveat.kind!r}")
    entry[1](caveat, payload, ctx, now, used_nonces)


# ---------------------------------------------------------------------------
# issuance / attenuation
# ---------------------------------------------------------------------------


def issue(
    issuer: Ed25519Signer,
    *,
    capability_id: str,
    subject: str,
    audience: str,
    action: str,
    resource: str,
    invocation_params: dict[str, Any],
    caveats: list[Caveat] | None = None,
    not_before: datetime,
    expires_at: datetime,
    constitution_hash: str,
) -> SignedEnvelope:
    """Mint a root attenuated capability token, signed by the issuer.

    ``subject`` binds the token to the holder: base64 Ed25519 public key
    (or a key_id resolvable via ``holder_keys`` at verify time).
    ``parameters_hash`` is computed here from the exact invocation parameters —
    the token is only valid for that invocation.
    """
    nb = _require_aware(not_before, "not_before")
    ea = _require_aware(expires_at, "expires_at")
    if nb > ea:
        raise ValueError("not_before must be <= expires_at")
    for caveat in caveats or []:
        _validate_caveat(caveat)
    payload = AttenuatedTokenPayload(
        capability_id=capability_id,
        issuer=issuer.key_id,
        subject=subject,
        audience=audience,
        action=action,
        resource=resource,
        parameters_hash=sha256_hex(invocation_params),
        caveats=list(caveats or []),
        not_before=nb,
        expires_at=ea,
        nonce=secrets.token_hex(16),
        parent_token_hash=None,
        constitution_hash=constitution_hash,
    )
    return issuer.sign_payload(payload.model_dump(mode="json"))


def attenuate(
    parent_envelope: SignedEnvelope,
    issuer: Ed25519Signer,
    new_caveats: list[Caveat],
    child_subject: str,
    *,
    capability_id: str | None = None,
    resource: str | None = None,
    not_before: datetime | None = None,
    expires_at: datetime | None = None,
) -> SignedEnvelope:
    """Mint a child token narrowing ``parent_envelope``. Narrowing only.

    The child carries every parent caveat verbatim (conjunction semantics, so
    authority can only shrink) plus ``new_caveats``. Top-level fields may only
    tighten: ``expires_at`` is clamped to ``min(parent, requested)``,
    ``not_before`` to ``max(parent, requested)``, ``resource`` must stay within
    the parent's resource at a segment boundary. ``parameters_hash``,
    ``action``, ``audience`` and ``constitution_hash`` are inherited unchanged.
    The parent must have been issued by this same issuer key.
    """
    try:
        parent_raw = verify_envelope(parent_envelope, issuer.public_key_bytes())
    except Exception as exc:
        raise AuthorizationError("attenuate: parent signature invalid") from exc
    if parent_envelope.key_id != issuer.key_id:
        raise ValueError("attenuate: parent was not issued by this issuer key")
    parent = _parse_payload(parent_raw)
    for caveat in new_caveats:
        _validate_caveat(caveat)

    child_resource = resource if resource is not None else parent.resource
    if not (
        child_resource == parent.resource
        or _is_prefix_at_boundary(parent.resource, child_resource)
    ):
        raise ValueError("attenuate: resource must narrow the parent's resource")

    child_nb = _require_aware(
        not_before if not_before is not None else parent.not_before, "not_before"
    )
    child_ea = _require_aware(
        expires_at if expires_at is not None else parent.expires_at, "expires_at"
    )
    # Clamp: narrowing only, never widening.
    child_nb = max(child_nb, parent.not_before)
    child_ea = min(child_ea, parent.expires_at)
    if child_nb > child_ea:
        raise ValueError("attenuate: resulting window is empty")

    child = AttenuatedTokenPayload(
        capability_id=capability_id
        or f"{parent.capability_id}#child-{secrets.token_hex(4)}",
        issuer=issuer.key_id,
        subject=child_subject,
        audience=parent.audience,
        action=parent.action,
        resource=child_resource,
        parameters_hash=parent.parameters_hash,
        caveats=[*parent.caveats, *new_caveats],
        not_before=child_nb,
        expires_at=child_ea,
        nonce=secrets.token_hex(16),
        parent_token_hash=token_hash(parent_envelope),
        constitution_hash=parent.constitution_hash,
    )
    _check_subsumption(child, parent)  # sanity: our own construction must satisfy it
    return issuer.sign_payload(child.model_dump(mode="json"))


# ---------------------------------------------------------------------------
# subsumption: child authority ⊆ parent authority (normative)
# ---------------------------------------------------------------------------


def _check_caveat_subsumed(parent_c: Caveat, child_c: Caveat) -> None:
    """Raise AuthorizationError unless child_c is equal-or-tighter than parent_c."""
    kind = parent_c.kind
    if kind == "expiry":
        if _parse_aware_iso(
            child_c.params["expires_at"], "expiry.expires_at"
        ) > _parse_aware_iso(parent_c.params["expires_at"], "expiry.expires_at"):
            raise AuthorizationError("subsumption violated: expiry widened")
    elif kind == "uses":
        if child_c.params["max_uses"] > parent_c.params["max_uses"]:
            raise AuthorizationError("subsumption violated: uses widened")
    elif kind == "http_allowlist":
        for dim in ("hosts", "urls"):
            if dim in parent_c.params:
                if dim not in child_c.params or not set(
                    child_c.params[dim]
                ) <= set(parent_c.params[dim]):
                    raise AuthorizationError(
                        f"subsumption violated: http_allowlist {dim} widened"
                    )
            # parent unconstrained on this dimension: child adding it only narrows
    elif kind == "resource_prefix":
        if not _is_prefix_at_boundary(
            parent_c.params["prefix"], child_c.params["prefix"]
        ):
            raise AuthorizationError("subsumption violated: resource_prefix widened")
    elif kind == "spend_limit":
        if "currency" in parent_c.params and (
            child_c.params.get("currency") != parent_c.params["currency"]
        ):
            raise AuthorizationError("subsumption violated: spend currency changed")
        if child_c.params["max_amount"] > parent_c.params["max_amount"]:
            raise AuthorizationError("subsumption violated: spend_limit widened")
    else:
        # Unknown kinds cannot be proven narrower; exact equality is the only
        # safe relation (verify would deny them anyway).
        if child_c.params != parent_c.params:
            raise AuthorizationError(
                f"subsumption violated: unknown caveat kind {kind!r} changed"
            )


def _check_subsumption(
    child: AttenuatedTokenPayload, parent: AttenuatedTokenPayload
) -> None:
    """Normative SUBSUMPTION: every parent caveat present in the child at
    equal-or-tighter strength, and no top-level field widened."""
    if child.action != parent.action:
        raise AuthorizationError("subsumption violated: action changed")
    if not (
        child.resource == parent.resource
        or _is_prefix_at_boundary(parent.resource, child.resource)
    ):
        raise AuthorizationError("subsumption violated: resource widened")
    if child.audience != parent.audience:
        raise AuthorizationError("subsumption violated: audience changed")
    if child.expires_at > parent.expires_at:
        raise AuthorizationError("subsumption violated: expires_at widened")
    if child.not_before < parent.not_before:
        raise AuthorizationError("subsumption violated: not_before widened")
    if child.parameters_hash != parent.parameters_hash:
        raise AuthorizationError("subsumption violated: parameters_hash changed")
    if child.constitution_hash != parent.constitution_hash:
        raise AuthorizationError("subsumption violated: constitution changed")
    for parent_c in parent.caveats:
        matches = [c for c in child.caveats if c.kind == parent_c.kind]
        if not matches:
            raise AuthorizationError(
                f"subsumption violated: parent caveat {parent_c.kind!r} dropped"
            )
        for child_c in matches:
            _check_caveat_subsumed(parent_c, child_c)


# ---------------------------------------------------------------------------
# verification — fail-closed pipeline
# ---------------------------------------------------------------------------


def make_holder_proof(
    holder: Ed25519Signer, capability_id: str, nonce: str
) -> SignedEnvelope:
    """Proof-of-possession: the bound holder key signs (nonce || capability_id)."""
    return holder.sign_payload({"capability_id": capability_id, "nonce": nonce})


def verify(
    envelope: SignedEnvelope,
    *,
    holder_proof: SignedEnvelope,
    invocation_params: dict[str, Any],
    now: datetime,
    trusted_issuers: dict[str, bytes],
    used_nonces: set[str] | None = None,
    parent_envelope: SignedEnvelope | None = None,
    chain: dict[str, SignedEnvelope] | None = None,
    holder_proofs: dict[str, SignedEnvelope] | None = None,
    holder_keys: dict[str, str] | None = None,
    context: dict[str, Any] | None = None,
    expected_audience: str | None = None,
    _depth: int = 0,
) -> AttenuatedTokenPayload:
    """Verify a token. Returns the payload on success; raises
    :class:`AuthorizationError` on ANY failure. Never returns a soft allow.

    Pipeline: (1) trusted issuer signature over the canonical payload;
    (2) validity window; (3) nonce freshness against ``used_nonces``;
    (4) proof-of-possession by the bound holder key over
    ``(nonce || capability_id)``; (5) invocation binding
    (``sha256(canonical(invocation_params)) == parameters_hash``);
    (6) every caveat evaluates true; (7) if ``parent_token_hash`` is set, the
    parent envelope must be supplied (via ``parent_envelope`` or ``chain``),
    must verify recursively (its own holder proof comes from
    ``holder_proofs[parent_capability_id]``), and subsumption must hold.
    When ``expected_audience`` is given, the token's audience claim must
    equal it at every level of the chain; enforcement points should always
    pass the audience they serve.
    """
    if _depth > MAX_CHAIN_DEPTH:
        raise AuthorizationError("delegation chain too deep")
    now = _require_aware(now, "now")

    # (1) trusted issuer signature over canonical payload
    issuer_key_id = envelope.key_id
    issuer_pub = trusted_issuers.get(issuer_key_id)
    if issuer_pub is None:
        raise AuthorizationError(f"untrusted issuer: {issuer_key_id!r}")
    try:
        raw_payload = verify_envelope(envelope, issuer_pub)
    except Exception as exc:
        raise AuthorizationError("issuer signature verification failed") from exc
    payload = _parse_payload(raw_payload)
    if payload.version != TOKEN_VERSION:
        raise AuthorizationError(
            f"unsupported token version: {payload.version!r}"
        )
    if payload.issuer != issuer_key_id:
        raise AuthorizationError("payload issuer does not match signing key_id")
    # (1b) audience binding: when the enforcement point declares the audience
    # it serves, a token minted for a different audience is denied outright.
    # Enforcement points MUST pass expected_audience; omitting it is only
    # acceptable when the caller performs its own audience check.
    if expected_audience is not None and payload.audience != expected_audience:
        raise AuthorizationError(
            f"audience mismatch: token for {payload.audience!r}, "
            f"enforcement point serves {expected_audience!r}"
        )

    # (2) validity window
    not_before = _require_aware(payload.not_before, "not_before")
    expires_at = _require_aware(payload.expires_at, "expires_at")
    if now < not_before:
        raise AuthorizationError("token not yet valid")
    if now > expires_at:
        raise AuthorizationError("token expired")

    # (3) nonce freshness (single-use / replay protection)
    if used_nonces is not None and payload.nonce in used_nonces:
        raise AuthorizationError("nonce already consumed: replay denied")

    # (4) proof-of-possession: bound holder key signed (nonce || capability_id)
    holder_pub = _resolve_holder_pubkey(payload.subject, holder_keys)
    try:
        proof_payload = verify_envelope(holder_proof, holder_pub)
    except Exception as exc:
        raise AuthorizationError("holder proof-of-possession failed") from exc
    if proof_payload != {"capability_id": payload.capability_id, "nonce": payload.nonce}:
        raise AuthorizationError("holder proof binds the wrong capability/nonce")

    # (5) invocation binding
    if not hmac.compare_digest(
        sha256_hex(invocation_params), payload.parameters_hash
    ):
        raise AuthorizationError("invocation parameters do not match token binding")

    # (6) caveats — every one must hold; unknown kinds deny
    eval_ctx: dict[str, Any] = {**invocation_params, **(context or {})}
    for caveat in payload.caveats:
        _evaluate_caveat(caveat, payload, eval_ctx, now, used_nonces)

    # (7) parent chain: supplied, recursively verified, subsumption holds
    if payload.parent_token_hash is not None:
        parent_env: SignedEnvelope | None = None
        if (
            parent_envelope is not None
            and token_hash(parent_envelope) == payload.parent_token_hash
        ):
            parent_env = parent_envelope
        elif chain is not None and payload.parent_token_hash in chain:
            parent_env = chain[payload.parent_token_hash]
        if parent_env is None:
            raise AuthorizationError("parent token required but not supplied")
        parent_capability_id = parent_env.payload.get("capability_id")
        parent_proof = (holder_proofs or {}).get(parent_capability_id)  # type: ignore[arg-type]
        if parent_proof is None:
            raise AuthorizationError("parent holder proof required but not supplied")
        parent_payload = verify(
            parent_env,
            holder_proof=parent_proof,
            invocation_params=invocation_params,
            now=now,
            trusted_issuers=trusted_issuers,
            used_nonces=used_nonces,
            chain=chain,
            holder_proofs=holder_proofs,
            holder_keys=holder_keys,
            context=context,
            expected_audience=expected_audience,
            _depth=_depth + 1,
        )
        _check_subsumption(payload, parent_payload)

    return payload
