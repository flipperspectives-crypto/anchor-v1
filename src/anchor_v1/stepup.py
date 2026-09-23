"""ANCHOR v1 — quorum step-up approval with WebAuthn assertion verification.

A step-up approval binds a sensitive action (identified by its
``action_digest``) to human/hardware-backed consent: *m-of-n* distinct
authenticators each produce a WebAuthn ``getAssertion``-shaped assertion over
a fresh 32-byte challenge, and the quorum is finalized as a COSE_Sign1
``ApprovalRecord`` that the Guardian/policy layer consumes.

Assertion format accepted (WebAuthn Level 2, section 7.2 "getAssertion"
subset):

* ``Assertion.authenticator_data`` =
  ``rpIdHash(32) || flags(1) || signCount(4, big-endian)`` with optional
  trailing extension bytes (ignored). ``flags`` bit 0 is the User Presence
  (UP) flag.
* ``Assertion.client_data_json`` = UTF-8 JSON object with exactly-checked
  fields: ``type == "webauthn.get"``,
  ``challenge == base64url-nopad(32-byte challenge)`` (compared with a
  constant-time equality check against the expected encoding — no
  canonicalization tricks), ``origin == <pinned origin>``. Extra fields in
  the JSON object are permitted (real browsers add ``crossOrigin`` etc.).
  Authenticators that set ``Authenticator.binds_action_digest`` add an
  ``action_digest`` extension field here — inside the signed material — and
  the quorum requires it to match the approval's digest.
* ``Assertion.signature`` = signature over
  ``authenticatorData || SHA-256(clientDataJSON)`` using the registered
  credential key:
    - ``EdDSA`` credentials: raw 64-byte Ed25519 signature.
    - ``ES256`` credentials: DER-encoded ASN.1 ECDSA signature over
      P-256 with SHA-256 (this is what real hardware security keys emit).
* ``Assertion.key_id`` = credential identifier; it must resolve in the
  registration registry.

Verification checks (all fail-closed, raising :class:`StepUpError`):

1. ``rpIdHash == SHA-256(rp_id)`` — binds the assertion to this relying party.
2. UP flag set — someone (or something) was physically present.
3. ``challenge`` matches the challenge this quorum round issued — binds the
   assertion to this approval and defeats replay of assertions minted for
   other challenges.
4. ``origin`` matches the pinned origin — defeats phishing-site assertions.
5. Signature verifies under the *registered* credential public key —
   defeats assertions minted by unregistered keys.
6. ``signCount`` strictly increases versus the stored counter for the
   credential — clone detection: a cloned authenticator replays a stale
   counter and is rejected on rollback (or on a non-increasing counter).

Documented gaps (out of scope for this module, enforced at higher layers):

* Registration/attestation ceremony — credentials are assumed enrolled via an
  out-of-band trusted ceremony; this module only consumes the registry.
* User Verification (UV) flag — UP is required; a policy demanding UV must
  check the flag itself from the raw assertion bytes.
* Token binding, extension outputs, backup-eligibility / backup-state flags.
* Challenge freshness across actions holds as follows, precisely. Within
  ONE process, challenges are ONE-TIME-USE: every live quorum that has
  recorded an approval registers its challenge in a process-wide in-flight
  registry, and ``approve()`` rejects any approval over a challenge already
  held by another live quorum — so a reused challenge can never satisfy a
  second quorum for a different action, even BEFORE the first quorum
  finalizes. ``finalize()`` moves the challenge from in-flight into a
  burned ledger (``approve()`` also rejects burned challenges), so a reused
  challenge can never silently satisfy a second quorum for a different
  action *in the same process* — even if sign-count state is lost (e.g. a
  per-quorum verifier). A quorum that is discarded without finalizing must
  be ``abandon()``ed to release its in-flight challenge (without burning
  it). Cross-process replay (verifier restarted, ledger empty) is NOT
  defeated by this module: verifier instances holding sign-count/challenge
  state MUST be long-lived across quorums; a fresh verifier per quorum is
  unsafe. The coordinator SHOULD persist burned challenges durably; that
  persistence is out of scope here.
* Assertion-level ``action_digest`` binding exists only for authenticators
  that opt in via ``Authenticator.binds_action_digest`` (the software
  reference does). Real hardware keys cannot emit the extension field, so
  their assertions do NOT bind the digest in signed material — the
  one-time-use challenge ledger and the Guardian's binding check (below)
  cover that path instead.
* The Guardian MUST compare ``record.action_digest`` to the action
  envelope's digest via :func:`check_approval_binding` before authorizing
  anything on the strength of a record. A verified record proves only that
  *some* action with the recorded digest reached quorum — not that it is the
  action being authorized.

Threat model: the authenticator hardware (or the software reference) is
trusted to keep its private key; the channel carrying assertions is not.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import threading
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Literal, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import ValidationError, field_validator, model_validator

from .cbor import CBORError, cbor_dumps, cbor_loads
from .cose import COSEError, cose_sign_bytes, cose_verify
from .crypto import Ed25519Signer
from .models import StrictModel


# ---------------------------------------------------------------------------
# One-time-use challenge ledger (cross-quorum replay containment)
# ---------------------------------------------------------------------------
#
# Every challenge that has been finalized is burned here, process-wide.
# ``QuorumApproval.approve()`` rejects any approval over a burned challenge,
# so assertion bytes minted for action A can never verify into a second
# quorum for action B in the same process — even when the verifier instance
# has lost its sign-count state (e.g. a fresh per-quorum verifier). This
# ledger does NOT survive a process restart: verifier instances holding
# sign-count/challenge state MUST be long-lived across quorums, and the
# coordinator SHOULD persist burned challenges durably (out of scope here).

_burned_challenges: set[bytes] = set()
_burned_challenges_lock = threading.Lock()


def _is_challenge_burned(challenge: bytes) -> bool:
    with _burned_challenges_lock:
        return bytes(challenge) in _burned_challenges


def _burn_challenge(challenge: bytes) -> None:
    with _burned_challenges_lock:
        _burned_challenges.add(bytes(challenge))


# ---------------------------------------------------------------------------
# In-flight challenge registry (pre-finalize cross-quorum window)
# ---------------------------------------------------------------------------
#
# The burned ledger above only burns a challenge at finalize(). That leaves a
# window: with coordinator challenge reuse (a trusted-party misuse case) and
# a non-binding authenticator (real hardware keys carry no action_digest
# extension), assertion bytes minted for digest_A could finalize a quorum for
# digest_B *before* the first quorum finalizes — the ledger never sees the
# challenge twice because nothing has finalized yet.
#
# This registry closes the window: it holds the challenges of all LIVE
# (non-finalized, non-abandoned) quorums that have recorded at least one
# approval, process-wide. ``QuorumApproval.approve()`` atomically claims the
# quorum's challenge here at the moment the first approval binds it, and
# raises ``QuorumError`` if the challenge is already held by a DIFFERENT
# live quorum instance. Two live quorums sharing one challenge is exactly
# the coordinator-reuse misuse case, so rejecting it is correct.
#
# ``finalize()`` moves the challenge from in-flight into the burned ledger;
# ``abandon()`` releases it WITHOUT burning (a never-completed round must
# not poison the challenge for a fresh quorum). A quorum instance holds a
# strong reference here until it finalizes or is abandoned — call
# ``abandon()`` on quorums you discard.

_in_flight_challenges: dict[bytes, "QuorumApproval"] = {}


def _claim_challenge_in_flight(quorum: "QuorumApproval", challenge: bytes) -> None:
    """Atomically bind ``challenge`` to ``quorum`` in the in-flight registry.

    Raises ``QuorumError`` when the challenge is already held by a different
    live quorum instance. Re-claiming by the same quorum is a no-op.
    """
    key = bytes(challenge)
    with _burned_challenges_lock:
        holder = _in_flight_challenges.get(key)
        if holder is not None and holder is not quorum:
            raise QuorumError(
                "challenge is already in-flight in another live quorum "
                "(coordinator challenge reuse across quorums rejected)"
            )
        _in_flight_challenges[key] = quorum


def _release_challenge_in_flight(quorum: "QuorumApproval") -> None:
    """Release whichever in-flight challenge ``quorum`` holds, if any."""
    with _burned_challenges_lock:
        for key, holder in list(_in_flight_challenges.items()):
            if holder is quorum:
                del _in_flight_challenges[key]


# ---------------------------------------------------------------------------
# clientDataJSON action_digest extension field
# ---------------------------------------------------------------------------

_ACTION_DIGEST_FIELD = "action_digest"


def _assertion_action_digest(assertion: Assertion) -> str | None:
    """Return the ``action_digest`` extension field from ``clientDataJSON``.

    Returns ``None`` when the field is absent, not a string, or the JSON is
    unparsable. This reads only the *presented* value; whether it is
    trustworthy is decided by the signature check plus
    ``Authenticator.binds_action_digest`` enforcement in
    :meth:`QuorumApproval.approve`.
    """
    try:
        client_data = json.loads(assertion.client_data_json.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(client_data, dict):
        return None
    bound = client_data.get(_ACTION_DIGEST_FIELD)
    return bound if isinstance(bound, str) else None


# ---------------------------------------------------------------------------
# Errors (fail-closed: everything subclasses ValueError per repo convention)
# ---------------------------------------------------------------------------


class StepUpError(ValueError):
    """Raised when a WebAuthn assertion fails verification."""


class QuorumError(ValueError):
    """Raised when quorum construction, approval collection, finalization, or
    ApprovalRecord verification fails."""


# ---------------------------------------------------------------------------
# Wire models
# ---------------------------------------------------------------------------


class Assertion(StrictModel):
    """A WebAuthn ``getAssertion``-shaped assertion submitted for step-up.

    ``key_id`` identifies the credential whose registered public key must
    verify ``signature``.
    """

    authenticator_data: bytes
    client_data_json: bytes
    signature: bytes
    key_id: str


class StepUpContext(StrictModel):
    """Relying-party expectations an assertion is verified against."""

    rp_id: str
    origin: str


class CredentialRecord(StrictModel):
    """One enrolled credential in the registration registry.

    ``public_key`` encoding by ``key_type``:

    * ``"EdDSA"`` — 32-byte raw Ed25519 public key.
    * ``"ES256"`` — 65-byte uncompressed P-256 point ``0x04 || X || Y``.
    """

    key_type: Literal["ES256", "EdDSA"]
    public_key: bytes


# ---------------------------------------------------------------------------
# Assertion verification core (shared by software and hardware paths)
# ---------------------------------------------------------------------------

_FLAG_UP = 0x01
_AUTH_DATA_MIN_LEN = 32 + 1 + 4  # rpIdHash || flags || signCount


def _b64url_nopad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _credential_public_key(credential: CredentialRecord) -> Any:
    """Build a ``cryptography`` public-key object from a registry record."""
    if credential.key_type == "EdDSA":
        if len(credential.public_key) != 32:
            raise StepUpError("EdDSA credential public key must be 32 bytes")
        try:
            return Ed25519PublicKey.from_public_bytes(credential.public_key)
        except ValueError as exc:
            raise StepUpError(f"invalid EdDSA credential public key: {exc}") from exc
    # ES256
    if len(credential.public_key) != 65 or credential.public_key[0] != 0x04:
        raise StepUpError(
            "ES256 credential public key must be a 65-byte uncompressed point"
        )
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), credential.public_key
        )
    except ValueError as exc:
        raise StepUpError(f"invalid ES256 credential public key: {exc}") from exc


def _verify_signature(
    key_type: str, public_key: Any, signature: bytes, signed_data: bytes
) -> None:
    try:
        if key_type == "EdDSA":
            if len(signature) != 64:
                raise StepUpError("EdDSA assertion signature must be 64 bytes")
            public_key.verify(signature, signed_data)
        else:  # ES256 — hardware keys emit DER-encoded ECDSA signatures
            public_key.verify(signature, signed_data, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise StepUpError("assertion signature verification failed") from exc
    except (ValueError, TypeError) as exc:
        # Malformed DER / wrong curve math still means "not verified".
        raise StepUpError(f"assertion signature invalid: {exc}") from exc


def _verify_assertion_core(
    *,
    challenge: bytes,
    assertion: Assertion,
    rp_id: str,
    origin: str,
    credential: CredentialRecord,
    last_sign_count: int,
) -> int:
    """Run the WebAuthn getAssertion verification subset.

    Returns the assertion's sign count (the caller must persist it for the
    credential). Raises :class:`StepUpError` on any failure — fail closed.
    """
    auth_data = assertion.authenticator_data
    if len(auth_data) < _AUTH_DATA_MIN_LEN:
        raise StepUpError(
            f"authenticator_data too short: {len(auth_data)} < {_AUTH_DATA_MIN_LEN}"
        )
    rp_id_hash, flags, sign_count = (
        auth_data[:32],
        auth_data[32],
        int.from_bytes(auth_data[33:37], "big"),
    )

    # 1. Relying-party binding.
    if not hmac.compare_digest(rp_id_hash, hashlib.sha256(rp_id.encode("utf-8")).digest()):
        raise StepUpError("rpIdHash does not match this relying party")

    # 2. User presence.
    if not flags & _FLAG_UP:
        raise StepUpError("user presence (UP) flag not set")

    # 3/4. clientDataJSON: type, challenge, origin.
    try:
        client_data_text = assertion.client_data_json.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise StepUpError("client_data_json is not valid UTF-8") from exc
    try:
        client_data = json.loads(client_data_text)
    except json.JSONDecodeError as exc:
        raise StepUpError("client_data_json is not valid JSON") from exc
    if not isinstance(client_data, dict):
        raise StepUpError("client_data_json must be a JSON object")
    if client_data.get("type") != "webauthn.get":
        raise StepUpError(
            f"client_data type must be 'webauthn.get', got {client_data.get('type')!r}"
        )
    expected_challenge = _b64url_nopad(challenge)
    presented_challenge = client_data.get("challenge")
    if not isinstance(presented_challenge, str) or not hmac.compare_digest(
        presented_challenge, expected_challenge
    ):
        raise StepUpError("assertion challenge does not match")
    if client_data.get("origin") != origin:
        raise StepUpError(
            f"assertion origin {client_data.get('origin')!r} does not match {origin!r}"
        )

    # 5. Signature over authenticatorData || SHA-256(clientDataJSON).
    signed_data = (
        auth_data + hashlib.sha256(assertion.client_data_json).digest()
    )
    public_key = _credential_public_key(credential)
    _verify_signature(credential.key_type, public_key, assertion.signature, signed_data)

    # 6. Clone detection: the counter must strictly increase.
    if sign_count <= last_sign_count:
        raise StepUpError(
            f"signCount rollback: got {sign_count}, last seen {last_sign_count} "
            "(possible cloned authenticator)"
        )
    return sign_count


# ---------------------------------------------------------------------------
# Authenticator ABC
# ---------------------------------------------------------------------------


class Authenticator(ABC):
    """Something that can issue challenges and verify WebAuthn assertions."""

    #: Capability flag. Authenticators that embed the quorum's
    #: ``action_digest`` in the SIGNED assertion material (as a
    #: ``clientDataJSON`` extension field) set this ``True``; the software
    #: reference does. ``QuorumApproval.approve()`` then REQUIRES the embedded
    #: digest to match the approval's digest, so a stale assertion minted for
    #: action A can never satisfy a quorum for action B. Real hardware keys
    #: cannot emit the extension field and keep this ``False`` — that path is
    #: covered by the one-time-use challenge ledger and the Guardian's
    #: :func:`check_approval_binding` duty instead.
    binds_action_digest: bool = False

    @abstractmethod
    def create_challenge(self) -> bytes:
        """Return 32 fresh random bytes for the authenticator to sign."""

    @abstractmethod
    def verify_assertion(
        self, challenge: bytes, assertion: Assertion, context: StepUpContext
    ) -> str:
        """Verify an assertion against ``challenge`` and ``context``.

        Returns the verified credential ``key_id``. Raises
        :class:`StepUpError` on any failure.
        """


# ---------------------------------------------------------------------------
# SoftwareAuthenticator — test double AND reference implementation
# ---------------------------------------------------------------------------


class SoftwareAuthenticator(Authenticator):
    """Ed25519-backed reference authenticator.

    Emits real WebAuthn-shaped assertions (``rpIdHash || flags || signCount``,
    ``clientDataJSON`` with ``type == "webauthn.get"``) and verifies them with
    the same checks a hardware-key verifier applies. Used in tests and as the
    executable specification of the assertion format.

    When ``action_digest`` is supplied to :meth:`create_assertion`, it is
    embedded as an ``action_digest`` extension field in the clientDataJSON —
    inside the signed material (real WebAuthn permits extra fields) — and any
    quorum collecting the assertion requires it to match the approval's
    digest (see ``binds_action_digest``).
    """

    binds_action_digest = True

    def __init__(
        self, key_id: str, rp_id: str, origin: str, signer: Ed25519Signer
    ) -> None:
        self.key_id = key_id
        self.rp_id = rp_id
        self.origin = origin
        self._signer = signer
        # Device-side counter (increments when minting assertions) and
        # relying-party-side counter (tracks the last verified assertion) are
        # deliberately separate state — exactly as in real WebAuthn, where the
        # counter lives on the key and the last-seen value lives on the
        # server. Conflating them would reject every fresh assertion as a
        # replay.
        self._device_sign_count = 0
        self._rp_last_seen: dict[str, int] = {key_id: 0}

    @classmethod
    def generate(cls, key_id: str, rp_id: str, origin: str) -> "SoftwareAuthenticator":
        return cls(key_id, rp_id, origin, Ed25519Signer.generate(key_id))

    # -- Authenticator interface -------------------------------------------

    def create_challenge(self) -> bytes:
        return secrets.token_bytes(32)

    def verify_assertion(
        self, challenge: bytes, assertion: Assertion, context: StepUpContext
    ) -> str:
        if assertion.key_id != self.key_id:
            raise StepUpError(
                f"unknown credential {assertion.key_id!r} for this authenticator"
            )
        self._check_context(context)
        credential = CredentialRecord(
            key_type="EdDSA", public_key=self._signer.public_key_bytes()
        )
        new_count = _verify_assertion_core(
            challenge=challenge,
            assertion=assertion,
            rp_id=context.rp_id,
            origin=context.origin,
            credential=credential,
            last_sign_count=self._rp_last_seen[self.key_id],
        )
        self._rp_last_seen[self.key_id] = new_count
        return self.key_id

    # -- Assertion creation (the "device" side) -----------------------------

    def create_assertion(
        self, challenge: bytes, *, action_digest: str | None = None
    ) -> Assertion:
        """Mint a WebAuthn-shaped assertion over ``challenge`` (device side).

        When ``action_digest`` is given it is embedded as an
        ``action_digest`` extension field in the clientDataJSON — inside the
        signed material — so the assertion is cryptographically bound to the
        action it was minted for. Quorums require the field (and its match)
        from authenticators with ``binds_action_digest`` set.
        """
        if not isinstance(challenge, (bytes, bytearray)) or len(challenge) != 32:
            raise StepUpError("challenge must be 32 bytes")
        if action_digest is not None and (
            not isinstance(action_digest, str) or not action_digest
        ):
            raise StepUpError("action_digest must be a non-empty string")
        self._device_sign_count += 1
        sign_count = self._device_sign_count
        authenticator_data = (
            hashlib.sha256(self.rp_id.encode("utf-8")).digest()
            + bytes([_FLAG_UP])
            + sign_count.to_bytes(4, "big")
        )
        client_data: dict[str, Any] = {
            "type": "webauthn.get",
            "challenge": _b64url_nopad(bytes(challenge)),
            "origin": self.origin,
        }
        if action_digest is not None:
            client_data[_ACTION_DIGEST_FIELD] = action_digest
        client_data_json = json.dumps(client_data, separators=(",", ":")).encode(
            "utf-8"
        )
        signed_data = (
            authenticator_data + hashlib.sha256(client_data_json).digest()
        )
        signature = self._signer.sign_bytes(signed_data)
        return Assertion(
            authenticator_data=authenticator_data,
            client_data_json=client_data_json,
            signature=signature,
            key_id=self.key_id,
        )

    def _check_context(self, context: StepUpContext) -> None:
        if context.rp_id != self.rp_id or context.origin != self.origin:
            raise StepUpError(
                "verification context does not match this authenticator's "
                f"pinned rp_id/origin ({self.rp_id!r}, {self.origin!r})"
            )


# ---------------------------------------------------------------------------
# WebAuthnVerifier — the real hardware-key path
# ---------------------------------------------------------------------------


class WebAuthnVerifier(Authenticator):
    """Verify assertions from real hardware security keys.

    Credential public keys come from an injected registration registry
    (``cred_id -> CredentialRecord``) supporting ``ES256`` (EC P-256) and
    ``EdDSA`` (Ed25519) credential keys. The accepted assertion format and
    the verification checks are identical to the software path — see the
    module docstring. Sign-count state is tracked per credential inside this
    verifier (clone detection); the registry itself stays immutable.
    """

    def __init__(
        self,
        rp_id: str,
        origin: str,
        registry: Mapping[str, CredentialRecord],
    ) -> None:
        if not rp_id:
            raise StepUpError("rp_id must be non-empty")
        if not origin:
            raise StepUpError("origin must be non-empty")
        if not registry:
            raise StepUpError("registration registry must not be empty")
        self.rp_id = rp_id
        self.origin = origin
        self._registry: dict[str, CredentialRecord] = dict(registry)
        self._sign_counts: dict[str, int] = {
            cred_id: 0 for cred_id in self._registry
        }

    def create_challenge(self) -> bytes:
        return secrets.token_bytes(32)

    def verify_assertion(
        self, challenge: bytes, assertion: Assertion, context: StepUpContext
    ) -> str:
        credential = self._registry.get(assertion.key_id)
        if credential is None:
            raise StepUpError(
                f"credential {assertion.key_id!r} is not registered"
            )
        if context.rp_id != self.rp_id or context.origin != self.origin:
            raise StepUpError(
                "verification context does not match this verifier's "
                f"pinned rp_id/origin ({self.rp_id!r}, {self.origin!r})"
            )
        new_count = _verify_assertion_core(
            challenge=challenge,
            assertion=assertion,
            rp_id=context.rp_id,
            origin=context.origin,
            credential=credential,
            last_sign_count=self._sign_counts[assertion.key_id],
        )
        self._sign_counts[assertion.key_id] = new_count
        return assertion.key_id


# ---------------------------------------------------------------------------
# QuorumApproval — m-of-n collection + finalized ApprovalRecord
# ---------------------------------------------------------------------------


class ApprovalRecord(StrictModel):
    """Finalized quorum decision, signed as COSE_Sign1 by the quorum issuer.

    The Guardian/policy layer consumes this via :func:`verify_approval_record`.
    """

    action_digest: str  # sha256 hex of the ActionEnvelope canonical bytes
    challenge: bytes  # the 32-byte challenge every approval asserted over
    m: int
    n: int
    approver_key_ids: list[str]  # sorted, unique
    decided_at: datetime  # UTC ISO-8601

    @field_validator("decided_at", mode="before")
    @classmethod
    def _coerce_datetime(cls, value: Any) -> Any:
        if isinstance(value, str):
            parsed = datetime.fromisoformat(value)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed
        return value

    @model_validator(mode="after")
    def _check_quorum_shape(self) -> "ApprovalRecord":
        if self.m < 1:
            raise ValueError("m must be >= 1")
        if self.m > self.n:
            raise ValueError("m must be <= n")
        if len(set(self.approver_key_ids)) != len(self.approver_key_ids):
            raise ValueError("approver_key_ids must be unique")
        if self.approver_key_ids != sorted(self.approver_key_ids):
            raise ValueError("approver_key_ids must be sorted")
        if len(self.approver_key_ids) < self.m:
            raise ValueError("fewer approvers than quorum m")
        if not self.action_digest:
            raise ValueError("action_digest must be non-empty")
        if len(self.challenge) != 32:
            raise ValueError("challenge must be 32 bytes")
        return self


class QuorumApproval:
    """Collect *m-of-n* step-up approvals for one action.

    Each approval verifies a WebAuthn assertion over the quorum's challenge
    and is recorded under the verified credential ``key_id`` — one approval
    per ``key_id``; duplicates are rejected, so one authenticator can never
    count twice toward the quorum.

    The first recorded approval binds the quorum to a single
    ``(action_digest, challenge)`` pair; any later approval for a different
    digest or challenge is rejected. ``finalize()`` signs the canonical
    record bytes as COSE_Sign1 with the issuer's Ed25519 key.

    Hardening:

    * One-time-use challenges — every live quorum that has recorded an
      approval registers its challenge in a process-wide in-flight
      registry; ``approve()`` rejects any approval over a challenge already
      held by ANOTHER live quorum, closing the pre-finalize cross-quorum
      window (coordinator challenge reuse). ``finalize()`` moves the
      challenge from in-flight into the burned ledger and ``approve()``
      rejects approvals over an already-burned challenge, so a reused
      challenge can never silently satisfy a second quorum for a different
      action in the same process (even with a fresh, sign-count-less
      verifier). A discarded quorum must be ``abandon()``ed to release its
      in-flight challenge without burning it.
    * Action-digest binding — for authenticators with
      ``binds_action_digest`` set, ``approve()`` requires the assertion's
      signed ``clientDataJSON`` to carry an ``action_digest`` extension field
      matching the approval's digest.
    * Seal — after ``finalize()`` the quorum is sealed: further ``approve()``
      or ``finalize()`` calls raise :class:`QuorumError`.
    """

    def __init__(self, m: int, n: int) -> None:
        if isinstance(m, bool) or not isinstance(m, int):
            raise QuorumError("m must be an integer")
        if isinstance(n, bool) or not isinstance(n, int):
            raise QuorumError("n must be an integer")
        if m < 1:
            raise QuorumError("quorum m must be >= 1")
        if n < 1:
            raise QuorumError("quorum n must be >= 1")
        if m > n:
            raise QuorumError(f"quorum m ({m}) must be <= n ({n})")
        self.m = m
        self.n = n
        self._approvals: dict[str, dict[str, Any]] = {}
        self._action_digest: str | None = None
        self._challenge: bytes | None = None
        self._finalized = False
        self._abandoned = False

    @property
    def is_sealed(self) -> bool:
        """True once :meth:`finalize` has run — the quorum accepts nothing
        further."""
        return self._finalized

    @property
    def is_abandoned(self) -> bool:
        """True once :meth:`abandon` has run — the quorum accepts nothing
        further and its challenge (if any) is no longer in-flight."""
        return self._abandoned

    @property
    def approval_count(self) -> int:
        return len(self._approvals)

    @property
    def bound_action_digest(self) -> str | None:
        return self._action_digest

    def approve(
        self,
        authenticator: Authenticator,
        challenge: bytes,
        assertion: Assertion,
        action_digest: str,
        context: StepUpContext,
    ) -> str:
        """Verify and record one approval. Returns the verified ``key_id``.

        Raises :class:`StepUpError` if the assertion fails verification and
        :class:`QuorumError` on a sealed or abandoned quorum, a burned
        (already-finalized) challenge, a challenge already in-flight in
        another live quorum, a missing/mismatched bound ``action_digest``
        (for authenticators with ``binds_action_digest``), duplicate
        approvers, digest/challenge mismatch, or a full quorum.
        """
        if not isinstance(challenge, (bytes, bytearray)) or len(challenge) != 32:
            raise QuorumError("challenge must be 32 bytes")
        if not isinstance(action_digest, str) or not action_digest:
            raise QuorumError("action_digest must be a non-empty string")
        if self._finalized:
            raise QuorumError("quorum is sealed: already finalized")
        if self._abandoned:
            raise QuorumError("quorum was abandoned")
        if _is_challenge_burned(challenge):
            raise QuorumError(
                "challenge was already finalized by another quorum "
                "(one-time-use: cross-quorum assertion replay rejected)"
            )

        # Raises StepUpError if the assertion does not verify.
        key_id = authenticator.verify_assertion(challenge, assertion, context)

        # Cryptographic action binding for capable authenticators: the digest
        # must be embedded in the SIGNED clientDataJSON, not just claimed in
        # the approve() arguments.
        if getattr(authenticator, "binds_action_digest", False):
            bound = _assertion_action_digest(assertion)
            if bound is None or not hmac.compare_digest(bound, action_digest):
                raise QuorumError(
                    "assertion's signed clientDataJSON does not bind this "
                    "quorum's action_digest "
                    f"(bound={bound!r}; cross-action replay rejected)"
                )

        if key_id in self._approvals:
            raise QuorumError(f"duplicate approval from {key_id!r}: already counted")

        if self._action_digest is None:
            # The first recorded approval binds this quorum to the challenge:
            # claim it in the in-flight registry atomically, so two LIVE
            # quorums can never share one challenge (coordinator challenge
            # reuse). The claim is atomic under the registry lock, so two
            # quorums racing to bind the same challenge cannot both win.
            # A failed approval (StepUpError/QuorumError above) never reaches
            # here, so it never claims.
            _claim_challenge_in_flight(self, challenge)
            self._action_digest = action_digest
            self._challenge = bytes(challenge)
        elif (
            action_digest != self._action_digest
            or bytes(challenge) != self._challenge
        ):
            raise QuorumError(
                "approval binds a different action_digest/challenge than "
                "this quorum (replay across actions rejected)"
            )

        if len(self._approvals) >= self.n:
            raise QuorumError(f"quorum already holds n={self.n} approvals")
        self._approvals[key_id] = {
            "action_digest": action_digest,
            "challenge": bytes(challenge),
        }
        return key_id

    def is_satisfied(self) -> bool:
        """True when >= m distinct approvals share one action_digest and one
        challenge. Fail-closed: mixed or insufficient approvals never
        satisfy; an abandoned quorum never satisfies either."""
        if self._abandoned:
            return False
        if len(self._approvals) < self.m:
            return False
        digests = {a["action_digest"] for a in self._approvals.values()}
        challenges = {a["challenge"] for a in self._approvals.values()}
        return len(digests) == 1 and len(challenges) == 1

    def abandon(self) -> None:
        """Abandon this quorum without finalizing.

        Releases the quorum's in-flight challenge (if any) WITHOUT burning
        it, so a fresh quorum may use the challenge afterwards. The quorum
        accepts nothing further: ``approve()`` raises, ``is_satisfied()``
        returns False, and ``finalize()`` raises. Abandoning an already
        finalized (sealed) quorum raises :class:`QuorumError`; abandoning
        twice is a no-op. Call this on any quorum you discard instead of
        finalizing, or its challenge stays in-flight for the process
        lifetime.
        """
        if self._finalized:
            raise QuorumError("quorum is sealed: already finalized; cannot abandon")
        if self._abandoned:
            return
        self._abandoned = True
        _release_challenge_in_flight(self)

    close = abandon  # alias: QuorumApproval.close() releases like abandon()

    def finalize(
        self, issuer: Ed25519Signer, *, decided_at: datetime | None = None
    ) -> bytes:
        """Sign the quorum decision as COSE_Sign1 bytes (the ApprovalRecord).

        The signed canonical bytes are the deterministic-CBOR encoding of
        ``{action_digest, challenge, m, n, approver_key_ids (sorted),
        decided_at}``. Raises :class:`QuorumError` unless the quorum is
        satisfied and not abandoned. Finalizing seals the quorum (no further
        approvals), releases the challenge from the in-flight registry, and
        burns it process-wide (one-time-use: the challenge can never satisfy
        another quorum).
        """
        if self._finalized:
            raise QuorumError("quorum is sealed: already finalized")
        if self._abandoned:
            raise QuorumError("quorum was abandoned: cannot finalize")
        if not self.is_satisfied():
            raise QuorumError(
                f"cannot finalize: {len(self._approvals)} approvals, need m={self.m}"
            )
        moment = decided_at or datetime.now(timezone.utc)
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        payload = {
            "action_digest": self._action_digest,
            "challenge": self._challenge,
            "m": self.m,
            "n": self.n,
            "approver_key_ids": sorted(self._approvals),
            "decided_at": moment.astimezone(timezone.utc).isoformat(),
        }
        record_bytes = cose_sign_bytes(
            cbor_dumps(payload), issuer.sign_bytes, issuer.key_id.encode("utf-8")
        )
        # Seal and burn only after the record is successfully signed.
        assert self._challenge is not None  # is_satisfied() implies bound
        _burn_challenge(self._challenge)
        _release_challenge_in_flight(self)
        self._finalized = True
        return record_bytes


def verify_approval_record(
    data: bytes, trusted_issuers: Mapping[str, bytes]
) -> ApprovalRecord:
    """Verify a finalized ApprovalRecord (COSE_Sign1, Ed25519) and return it.

    ``trusted_issuers`` maps issuer key-id strings to raw 32-byte Ed25519
    public keys. This is the function the Guardian/policy layer calls: a
    returned record means the quorum's issuer key signed exactly this
    ``(action_digest, challenge, m, n, approvers)`` tuple. Raises
    :class:`QuorumError` on any failure.

    NOTE: the Guardian must still call :func:`check_approval_binding` with
    the action envelope's digest before authorizing — a verified record
    proves *some* action reached quorum, not that it is the action being
    authorized.
    """
    try:
        pubkeys = {
            kid.encode("utf-8"): Ed25519PublicKey.from_public_bytes(raw)
            for kid, raw in trusted_issuers.items()
        }
    except (ValueError, TypeError) as exc:
        raise QuorumError(f"bad trusted issuer key material: {exc}") from exc

    try:
        payload, _kid = cose_verify(data, pubkeys)
    except COSEError as exc:
        raise QuorumError(f"approval record COSE verification failed: {exc}") from exc

    try:
        raw_record = cbor_loads(payload)
    except CBORError as exc:
        raise QuorumError(f"approval record payload is not valid CBOR: {exc}") from exc

    try:
        return ApprovalRecord.model_validate(raw_record)
    except ValidationError as exc:
        raise QuorumError(f"approval record schema invalid: {exc}") from exc


def check_approval_binding(
    record: ApprovalRecord, expected_action_digest: str
) -> None:
    """Reject an approval record replayed against a different action.

    Raises :class:`QuorumError` unless ``record.action_digest`` equals
    ``expected_action_digest`` (compared in constant time). Mirrors
    ``policy_providers.check_decision_binding``.

    THE GUARDIAN MUST call this with the action envelope's digest before
    authorizing anything on the strength of a record: a verified record
    proves only that *some* action with the recorded digest reached quorum —
    not that it is the action being authorized. Without this check, a record
    minted for action A silently authorizes action B.
    """
    if not isinstance(expected_action_digest, str) or not expected_action_digest:
        raise QuorumError("expected_action_digest must be a non-empty string")
    if not hmac.compare_digest(record.action_digest, expected_action_digest):
        raise QuorumError(
            "approval record action_digest does not match the action being "
            "authorized (replay across actions rejected)"
        )
