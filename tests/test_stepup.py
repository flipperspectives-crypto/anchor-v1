"""Tests for anchor_v1 step-up approval: WebAuthn assertions + m-of-n quorum.

Unit tests cover the happy paths. Every attack is labeled ATTACK-### and must
end in rejection — never silent acceptance. Each attack test is written so it
fails if the corresponding check is removed (mutation-checked).
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import secrets
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from pydantic import ValidationError

from anchor_v1.cbor import cbor_dumps, cbor_loads
from anchor_v1.cose import cose_verify
from anchor_v1.crypto import Ed25519Signer
from anchor_v1.stepup import (
    ApprovalRecord,
    Assertion,
    Authenticator,
    CredentialRecord,
    QuorumApproval,
    QuorumError,
    SoftwareAuthenticator,
    StepUpContext,
    StepUpError,
    WebAuthnVerifier,
    check_approval_binding,
    verify_approval_record,
)

RP_ID = "anchor.example"
ORIGIN = "https://anchor.example"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ctx(rp_id: str = RP_ID, origin: str = ORIGIN) -> StepUpContext:
    return StepUpContext(rp_id=rp_id, origin=origin)


def _software(key_id: str, rp_id: str = RP_ID, origin: str = ORIGIN):
    """Return (authenticator, signer) so tests can mint raw assertions too."""
    signer = Ed25519Signer.generate(key_id)
    return SoftwareAuthenticator(key_id, rp_id, origin, signer), signer


def _digest(label: str = "action") -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _b64url_nopad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _es256_credential():
    """Return (private_key, CredentialRecord) for a fresh P-256 credential."""
    priv = ec.generate_private_key(ec.SECP256R1())
    nums = priv.public_key().public_numbers()
    raw = (
        b"\x04"
        + nums.x.to_bytes(32, "big")
        + nums.y.to_bytes(32, "big")
    )
    return priv, CredentialRecord(key_type="ES256", public_key=raw)


def _craft_assertion(
    *,
    key_id: str,
    sign_key,  # Ed25519Signer or ec private key
    key_type: str,  # "EdDSA" | "ES256"
    challenge: bytes,
    rp_id: str = RP_ID,
    origin: str = ORIGIN,
    sign_count: int = 1,
    flags: int = 0x01,
    client_type: str = "webauthn.get",
    extra_client_fields: dict | None = None,
) -> Assertion:
    """Mint a raw assertion the way a hardware key would (for attack tests)."""
    auth_data = (
        hashlib.sha256(rp_id.encode()).digest()
        + bytes([flags])
        + sign_count.to_bytes(4, "big")
    )
    client_data = {"type": client_type, "challenge": _b64url_nopad(challenge),
                   "origin": origin}
    if extra_client_fields:
        client_data.update(extra_client_fields)
    client_data_json = json.dumps(client_data, separators=(",", ":")).encode()
    signed = auth_data + hashlib.sha256(client_data_json).digest()
    if key_type == "EdDSA":
        signature = sign_key.sign_bytes(signed)
    else:
        signature = sign_key.sign(signed, ec.ECDSA(hashes.SHA256()))
    return Assertion(
        authenticator_data=auth_data,
        client_data_json=client_data_json,
        signature=signature,
        key_id=key_id,
    )


def _quorum_with_approvals(m, n, count, digest_label="action") -> tuple[QuorumApproval, list[bytes]]:
    """Build a quorum with `count` distinct software approvers; return it and
    the challenges used (one shared challenge)."""
    q = QuorumApproval(m, n)
    challenge = secrets.token_bytes(32)
    digest = _digest(digest_label)
    for i in range(count):
        auth, _ = _software(f"approver-{i}")
        assertion = auth.create_assertion(challenge, action_digest=digest)
        q.approve(auth, challenge, assertion, digest, _ctx())
    return q, [challenge]


# ---------------------------------------------------------------------------
# Unit: challenges, assertions, verification
# ---------------------------------------------------------------------------


class TestChallenges:
    def test_create_challenge_is_32_random_bytes(self):
        auth, _ = _software("k1")
        c1, c2 = auth.create_challenge(), auth.create_challenge()
        assert len(c1) == 32 and len(c2) == 32 and c1 != c2

    def test_verifier_create_challenge_is_32_random_bytes(self):
        _, cred = _es256_credential()
        v = WebAuthnVerifierShim(cred)
        c = v.create_challenge()
        assert len(c) == 32


class WebAuthnVerifierShim:
    """Tiny helper to build a WebAuthnVerifier in tests."""

    def __init__(self, credential: CredentialRecord, cred_id: str = "cred-1"):
        from anchor_v1.stepup import WebAuthnVerifier

        self.inner = WebAuthnVerifier(RP_ID, ORIGIN, {cred_id: credential})
        self.cred_id = cred_id

    def create_challenge(self) -> bytes:
        return self.inner.create_challenge()

    def verify_assertion(self, challenge, assertion, context):
        return self.inner.verify_assertion(challenge, assertion, context)


class TestSoftwareAuthenticator:
    def test_roundtrip_returns_key_id(self):
        auth, _ = _software("soft-1")
        challenge = auth.create_challenge()
        assertion = auth.create_assertion(challenge)
        assert auth.verify_assertion(challenge, assertion, _ctx()) == "soft-1"

    def test_assertion_is_webauthn_shaped(self):
        auth, _ = _software("soft-1")
        challenge = auth.create_challenge()
        a = auth.create_assertion(challenge)
        assert len(a.authenticator_data) == 37
        assert a.authenticator_data[:32] == hashlib.sha256(RP_ID.encode()).digest()
        assert a.authenticator_data[32] == 0x01  # UP flag
        assert int.from_bytes(a.authenticator_data[33:37], "big") == 1
        cd = json.loads(a.client_data_json.decode())
        assert cd["type"] == "webauthn.get"
        assert cd["challenge"] == _b64url_nopad(challenge)
        assert cd["origin"] == ORIGIN
        assert len(a.signature) == 64

    def test_sign_count_increases_across_assertions(self):
        auth, _ = _software("soft-1")
        c1, c2 = auth.create_challenge(), auth.create_challenge()
        a1 = auth.create_assertion(c1)
        a2 = auth.create_assertion(c2)
        assert int.from_bytes(a1.authenticator_data[33:37], "big") == 1
        assert int.from_bytes(a2.authenticator_data[33:37], "big") == 2
        assert auth.verify_assertion(c1, a1, _ctx()) == "soft-1"
        assert auth.verify_assertion(c2, a2, _ctx()) == "soft-1"

    def test_rejects_unknown_key_id(self):
        auth, _ = _software("soft-1")
        challenge = auth.create_challenge()
        other, _ = _software("soft-2")
        assertion = other.create_assertion(challenge)
        with pytest.raises(StepUpError):
            auth.verify_assertion(challenge, assertion, _ctx())

    def test_create_assertion_rejects_bad_challenge(self):
        auth, _ = _software("soft-1")
        with pytest.raises(StepUpError):
            auth.create_assertion(b"too short")

    def test_authenticator_data_with_extensions_still_verifies(self):
        auth, signer = _software("soft-1")
        challenge = auth.create_challenge()
        # Real keys may append extension outputs after signCount.
        assertion = _craft_assertion(
            key_id="soft-1", sign_key=signer, key_type="EdDSA",
            challenge=challenge, sign_count=1,
        )
        tampered = assertion.model_copy(
            update={"authenticator_data": assertion.authenticator_data + b"\x00" * 8}
        )
        # Extensions are appended AFTER signing here, so re-sign manually:
        signed = tampered.authenticator_data + hashlib.sha256(
            tampered.client_data_json).digest()
        fixed = tampered.model_copy(update={"signature": signer.sign_bytes(signed)})
        assert auth.verify_assertion(challenge, fixed, _ctx()) == "soft-1"

    def test_assertion_forbids_extra_fields(self):
        with pytest.raises(ValidationError):
            Assertion(
                authenticator_data=b"x" * 37,
                client_data_json=b"{}",
                signature=b"y" * 64,
                key_id="k",
                extra_field="nope",
            )


class TestWebAuthnVerifier:
    def test_es256_hardware_key_roundtrip(self):
        priv, cred = _es256_credential()
        shim = WebAuthnVerifierShim(cred)
        challenge = shim.create_challenge()
        assertion = _craft_assertion(
            key_id=shim.cred_id, sign_key=priv, key_type="ES256",
            challenge=challenge,
        )
        assert shim.verify_assertion(challenge, assertion, _ctx()) == shim.cred_id

    def test_eddsa_registry_roundtrip(self):
        signer = Ed25519Signer.generate("hw-eddsa")
        cred = CredentialRecord(key_type="EdDSA", public_key=signer.public_key_bytes())
        shim = WebAuthnVerifierShim(cred)
        challenge = shim.create_challenge()
        assertion = _craft_assertion(
            key_id=shim.cred_id, sign_key=signer, key_type="EdDSA",
            challenge=challenge,
        )
        assert shim.verify_assertion(challenge, assertion, _ctx()) == shim.cred_id

    def test_verifier_is_an_authenticator(self):
        priv, cred = _es256_credential()
        from anchor_v1.stepup import WebAuthnVerifier

        v = WebAuthnVerifier(RP_ID, ORIGIN, {"c": cred})
        assert isinstance(v, Authenticator)

    def test_empty_registry_rejected(self):
        from anchor_v1.stepup import WebAuthnVerifier

        with pytest.raises(StepUpError):
            WebAuthnVerifier(RP_ID, ORIGIN, {})

    def test_malformed_registry_key_rejected_at_verify(self):
        from anchor_v1.stepup import WebAuthnVerifier

        bad = CredentialRecord(key_type="ES256", public_key=b"\x04" + b"\x00" * 10)
        v = WebAuthnVerifier(RP_ID, ORIGIN, {"bad": bad})
        challenge = v.create_challenge()
        assertion = Assertion(
            authenticator_data=hashlib.sha256(RP_ID.encode()).digest()
            + b"\x01" + (1).to_bytes(4, "big"),
            client_data_json=json.dumps(
                {"type": "webauthn.get",
                 "challenge": _b64url_nopad(challenge), "origin": ORIGIN}
            ).encode(),
            signature=b"\x00" * 64,
            key_id="bad",
        )
        with pytest.raises(StepUpError):
            v.verify_assertion(challenge, assertion, _ctx())


# ---------------------------------------------------------------------------
# Unit: quorum collection + finalization
# ---------------------------------------------------------------------------


class TestQuorumConstruction:
    @pytest.mark.parametrize("m,n", [(0, 3), (-1, 3), (4, 3), (2, 0), (1, 0)])
    def test_invalid_parameters_rejected(self, m, n):
        with pytest.raises(QuorumError):
            QuorumApproval(m, n)

    def test_non_integer_parameters_rejected(self):
        with pytest.raises(QuorumError):
            QuorumApproval(True, 3)
        with pytest.raises(QuorumError):
            QuorumApproval(1, "3")

    def test_valid_1of1(self):
        q = QuorumApproval(1, 1)
        assert q.m == 1 and q.n == 1 and q.approval_count == 0
        assert not q.is_satisfied()


class TestQuorumHappyPath:
    def test_2of3_finalize_and_verify_record(self):
        q, _ = _quorum_with_approvals(2, 3, 2)
        assert q.is_satisfied()
        issuer = Ed25519Signer.generate("quorum-issuer")
        record_bytes = q.finalize(issuer)
        record = verify_approval_record(
            record_bytes, {"quorum-issuer": issuer.public_key_bytes()}
        )
        assert isinstance(record, ApprovalRecord)
        assert record.m == 2 and record.n == 3
        assert record.action_digest == _digest("action")
        assert len(record.challenge) == 32
        assert record.approver_key_ids == ["approver-0", "approver-1"]
        assert record.decided_at.tzinfo is not None

    def test_approver_key_ids_sorted_in_record(self):
        q = QuorumApproval(2, 3)
        challenge = secrets.token_bytes(32)
        digest = _digest("action")
        for kid in ("zebra", "apple"):
            auth, _ = _software(kid)
            assertion = auth.create_assertion(challenge, action_digest=digest)
            q.approve(auth, challenge, assertion, digest, _ctx())
        issuer = Ed25519Signer.generate("issuer")
        record = verify_approval_record(
            q.finalize(issuer), {"issuer": issuer.public_key_bytes()}
        )
        assert record.approver_key_ids == ["apple", "zebra"]

    def test_approve_returns_verified_key_id(self):
        q = QuorumApproval(1, 2)
        auth, _ = _software("only")
        challenge = auth.create_challenge()
        digest = _digest("a")
        assertion = auth.create_assertion(challenge, action_digest=digest)
        kid = q.approve(auth, challenge, assertion, digest, _ctx())
        assert kid == "only"
        assert q.is_satisfied()

    def test_rejects_oversized_quorum(self):
        q, _ = _quorum_with_approvals(1, 1, 1)
        auth, _ = _software("extra")
        challenge = secrets.token_bytes(32)
        digest = q.bound_action_digest
        assertion = auth.create_assertion(challenge, action_digest=digest)
        with pytest.raises(QuorumError):
            q.approve(auth, challenge, assertion, digest, _ctx())

    def test_rejects_bad_challenge_shape(self):
        q = QuorumApproval(1, 1)
        auth, _ = _software("k")
        with pytest.raises(QuorumError):
            q.approve(auth, b"short", auth.create_assertion(auth.create_challenge()),
                      _digest("a"), _ctx())

    def test_approval_record_schema_validators(self):
        now = datetime.now(timezone.utc).isoformat()
        base = dict(action_digest="ab" * 32, challenge=secrets.token_bytes(32),
                    m=2, n=3, approver_key_ids=["a", "b"], decided_at=now)
        ApprovalRecord(**base)  # valid
        with pytest.raises(ValidationError):
            ApprovalRecord(**{**base, "approver_key_ids": ["b", "a"]})  # unsorted
        with pytest.raises(ValidationError):
            ApprovalRecord(**{**base, "approver_key_ids": ["a", "a"]})  # dup
        with pytest.raises(ValidationError):
            ApprovalRecord(**{**base, "m": 4})  # m > n
        with pytest.raises(ValidationError):
            ApprovalRecord(**{**base, "m": 3})  # fewer approvers than m
        with pytest.raises(ValidationError):
            ApprovalRecord(**{**base, "challenge": b"short"})
        with pytest.raises(ValidationError):
            ApprovalRecord(**{**base, "action_digest": ""})


# ---------------------------------------------------------------------------
# Adversarial: assertion attacks
# ---------------------------------------------------------------------------


class TestAssertionAttacks:
    def test_ATTACK_001_assertion_for_wrong_challenge_rejected(self):
        auth, _ = _software("victim")
        challenge = auth.create_challenge()
        assertion = auth.create_assertion(challenge)
        wrong_challenge = secrets.token_bytes(32)
        with pytest.raises(StepUpError):
            auth.verify_assertion(wrong_challenge, assertion, _ctx())

    def test_ATTACK_002_wrong_rp_id_rejected(self):
        auth, signer = _software("victim")
        challenge = auth.create_challenge()
        assertion = _craft_assertion(
            key_id="victim", sign_key=signer, key_type="EdDSA",
            challenge=challenge, rp_id="evil.example",  # attacker-controlled rp
        )
        with pytest.raises(StepUpError):
            auth.verify_assertion(challenge, assertion, _ctx())

    def test_ATTACK_003_wrong_origin_rejected(self):
        auth, signer = _software("victim")
        challenge = auth.create_challenge()
        assertion = _craft_assertion(
            key_id="victim", sign_key=signer, key_type="EdDSA",
            challenge=challenge, origin="https://phishing.example",
        )
        with pytest.raises(StepUpError):
            auth.verify_assertion(challenge, assertion, _ctx())

    def test_ATTACK_004_signature_from_unregistered_key_rejected(self):
        priv, cred = _es256_credential()
        shim = WebAuthnVerifierShim(cred)
        challenge = shim.create_challenge()
        # Attacker signs with their OWN P-256 key but claims the victim cred_id.
        attacker_priv = ec.generate_private_key(ec.SECP256R1())
        assertion = _craft_assertion(
            key_id=shim.cred_id, sign_key=attacker_priv, key_type="ES256",
            challenge=challenge,
        )
        with pytest.raises(StepUpError):
            shim.verify_assertion(challenge, assertion, _ctx())

    def test_ATTACK_004b_unknown_credential_id_rejected(self):
        priv, cred = _es256_credential()
        shim = WebAuthnVerifierShim(cred)
        challenge = shim.create_challenge()
        assertion = _craft_assertion(
            key_id="never-registered", sign_key=priv, key_type="ES256",
            challenge=challenge,
        )
        with pytest.raises(StepUpError):
            shim.verify_assertion(challenge, assertion, _ctx())

    def test_ATTACK_005_signcount_rollback_rejected_clone_detection(self):
        auth, signer = _software("victim")
        c1 = auth.create_challenge()
        a1 = auth.create_assertion(c1)  # signCount = 1
        assert auth.verify_assertion(c1, a1, _ctx()) == "victim"
        # Cloned authenticator replays a stale (equal) counter...
        c2 = auth.create_challenge()
        replay = _craft_assertion(
            key_id="victim", sign_key=signer, key_type="EdDSA",
            challenge=c2, sign_count=1,
        )
        with pytest.raises(StepUpError):
            auth.verify_assertion(c2, replay, _ctx())
        # ...and a rolled-back (smaller) counter.
        c3 = auth.create_challenge()
        rollback = _craft_assertion(
            key_id="victim", sign_key=signer, key_type="EdDSA",
            challenge=c3, sign_count=0,
        )
        with pytest.raises(StepUpError):
            auth.verify_assertion(c3, rollback, _ctx())

    def test_ATTACK_005b_user_presence_flag_missing_rejected(self):
        auth, signer = _software("victim")
        challenge = auth.create_challenge()
        assertion = _craft_assertion(
            key_id="victim", sign_key=signer, key_type="EdDSA",
            challenge=challenge, flags=0x00,  # UP bit cleared
        )
        with pytest.raises(StepUpError):
            auth.verify_assertion(challenge, assertion, _ctx())

    def test_ATTACK_005c_truncated_authenticator_data_rejected(self):
        auth, _ = _software("victim")
        challenge = auth.create_challenge()
        assertion = auth.create_assertion(challenge)
        truncated = assertion.model_copy(
            update={"authenticator_data": assertion.authenticator_data[:10]}
        )
        with pytest.raises(StepUpError):
            auth.verify_assertion(challenge, truncated, _ctx())

    def test_wrong_client_data_type_rejected(self):
        auth, signer = _software("victim")
        challenge = auth.create_challenge()
        # "webauthn.create" (registration) must not pass as "webauthn.get".
        assertion = _craft_assertion(
            key_id="victim", sign_key=signer, key_type="EdDSA",
            challenge=challenge, client_type="webauthn.create",
        )
        with pytest.raises(StepUpError):
            auth.verify_assertion(challenge, assertion, _ctx())


# ---------------------------------------------------------------------------
# Adversarial: quorum attacks
# ---------------------------------------------------------------------------


class TestQuorumAttacks:
    def test_ATTACK_006_approval_replayed_against_different_digest_rejected(self):
        q = QuorumApproval(2, 3)
        challenge = secrets.token_bytes(32)
        digest_a = _digest("action-A")
        auth1, _ = _software("approver-1")
        q.approve(auth1, challenge,
                  auth1.create_assertion(challenge, action_digest=digest_a),
                  digest_a, _ctx())
        # Attacker replays an approval minted for the same challenge but tries
        # to bind it to a DIFFERENT action digest. The assertion itself is
        # correctly bound to digest-B (so the failure below exercises the
        # quorum-level pair binding, not the assertion-level check)...
        auth2, _ = _software("approver-2")
        digest_b = _digest("action-B")
        with pytest.raises(QuorumError):
            q.approve(auth2, challenge,
                      auth2.create_assertion(challenge, action_digest=digest_b),
                      digest_b, _ctx())
        assert q.approval_count == 1
        assert not q.is_satisfied()

    def test_ATTACK_006b_assertion_replayed_under_different_challenge_rejected(self):
        q = QuorumApproval(1, 2)
        auth, _ = _software("approver-1")
        challenge_a = auth.create_challenge()
        assertion_for_a = auth.create_assertion(challenge_a)
        challenge_b = secrets.token_bytes(32)  # the quorum's real challenge
        with pytest.raises(StepUpError):
            q.approve(auth, challenge_b, assertion_for_a, _digest("action"), _ctx())
        assert q.approval_count == 0

    def test_ATTACK_007_duplicate_approver_cannot_count_twice(self):
        q = QuorumApproval(2, 2)
        auth, _ = _software("approver-1")
        challenge = secrets.token_bytes(32)
        digest = _digest("action")
        q.approve(auth, challenge,
                  auth.create_assertion(challenge, action_digest=digest),
                  digest, _ctx())
        # Same authenticator tries to approve again with a FRESH assertion
        # (correctly bound, so the failure below exercises the duplicate
        # check, not the binding check).
        with pytest.raises(QuorumError):
            q.approve(auth, challenge,
                      auth.create_assertion(challenge, action_digest=digest),
                      digest, _ctx())
        assert q.approval_count == 1
        assert not q.is_satisfied()

    def test_ATTACK_008_finalize_with_m_minus_1_approvals_rejected(self):
        q, _ = _quorum_with_approvals(2, 3, 1)  # only 1 of required 2
        assert not q.is_satisfied()
        issuer = Ed25519Signer.generate("issuer")
        with pytest.raises(QuorumError):
            q.finalize(issuer)

    def test_ATTACK_009_tampered_approval_record_rejected(self):
        q, _ = _quorum_with_approvals(2, 3, 2)
        issuer = Ed25519Signer.generate("issuer")
        record_bytes = q.finalize(issuer)
        trusted = {"issuer": issuer.public_key_bytes()}

        # (a) Bit-flip anywhere in the message.
        tampered = bytearray(record_bytes)
        tampered[len(tampered) // 2] ^= 0x01
        with pytest.raises(QuorumError):
            verify_approval_record(bytes(tampered), trusted)

        # (b) Surgical payload swap: approver list changed, signature kept.
        outer = cbor_loads(record_bytes)
        payload = cbor_loads(outer[2])
        evil_payload = dict(payload)
        evil_payload["approver_key_ids"] = ["attacker"]
        evil_outer = [outer[0], outer[1], cbor_dumps(evil_payload), outer[3]]
        with pytest.raises(QuorumError):
            verify_approval_record(cbor_dumps(evil_outer), trusted)

        # (c) m downgraded in a re-encoded payload, signature kept.
        evil_payload2 = dict(payload)
        evil_payload2["m"] = 1
        evil_outer2 = [outer[0], outer[1], cbor_dumps(evil_payload2), outer[3]]
        with pytest.raises(QuorumError):
            verify_approval_record(cbor_dumps(evil_outer2), trusted)

        # (d) Unknown issuer key.
        other = Ed25519Signer.generate("other")
        with pytest.raises(QuorumError):
            verify_approval_record(record_bytes, {"other": other.public_key_bytes()})

    def test_ATTACK_010_replayed_assertion_bytes_rejected(self):
        # The real SU-N1 scenario: the SAME challenge is reused for two
        # actions. Assertion bytes minted for action A are replayed into a
        # SECOND quorum targeting action B, through a FRESH verifier instance
        # with no sign-count state (e.g. a restarted process or a per-quorum
        # verifier). The hardware path (WebAuthnVerifier) is used on purpose:
        # hardware assertions carry no action_digest binding, so without the
        # one-time-use challenge ledger this replay would verify, finalize,
        # and produce ApprovalRecord(challenge=C, action_digest=digest_B,
        # approvers=["approver-a"]) — an approval the approver only gave for
        # action A.
        signer = Ed25519Signer.generate("approver-a")
        cred = CredentialRecord(
            key_type="EdDSA", public_key=signer.public_key_bytes()
        )
        challenge = secrets.token_bytes(32)  # reused across both actions
        digest_a, digest_b = _digest("action-A"), _digest("action-B")
        issuer = Ed25519Signer.generate("issuer")
        trusted = {"issuer": issuer.public_key_bytes()}

        # Quorum A: the approver's genuine assertion for action A finalizes.
        verifier_a = WebAuthnVerifier(RP_ID, ORIGIN, {"approver-a": cred})
        qa = QuorumApproval(1, 1)
        assertion_for_a = _craft_assertion(
            key_id="approver-a", sign_key=signer, key_type="EdDSA",
            challenge=challenge, sign_count=1,
        )
        qa.approve(verifier_a, challenge, assertion_for_a, digest_a, _ctx())
        record_a = verify_approval_record(qa.finalize(issuer), trusted)
        assert record_a.action_digest == digest_a
        assert record_a.approver_key_ids == ["approver-a"]

        # The attacker replays the SAME assertion bytes into quorum B for
        # action B, via a FRESH verifier with no sign-count state. The
        # challenge was burned by quorum A's finalize -> QuorumError.
        verifier_b = WebAuthnVerifier(RP_ID, ORIGIN, {"approver-a": cred})
        qb = QuorumApproval(1, 1)
        with pytest.raises(QuorumError):
            qb.approve(verifier_b, challenge, assertion_for_a, digest_b, _ctx())
        assert qb.approval_count == 0
        with pytest.raises(QuorumError):
            qb.finalize(issuer)

        # And even with fresh (unburned) challenges, the Guardian-side binding
        # check stops a record minted for action A from authorizing action B.
        check_approval_binding(record_a, digest_a)  # the honest use: passes
        with pytest.raises(QuorumError):
            check_approval_binding(record_a, digest_b)

    def test_quorum_rejects_second_challenge(self):
        # A quorum is bound to ONE challenge; a different challenge is rejected
        # even from a fresh approver.
        q = QuorumApproval(2, 2)
        challenge = secrets.token_bytes(32)
        digest = _digest("action")
        auth1, _ = _software("a1")
        q.approve(auth1, challenge,
                  auth1.create_assertion(challenge, action_digest=digest),
                  digest, _ctx())
        auth2, _ = _software("a2")
        other_challenge = auth2.create_challenge()
        with pytest.raises(QuorumError):
            q.approve(auth2, other_challenge,
                      auth2.create_assertion(other_challenge,
                                             action_digest=digest),
                      digest, _ctx())
        assert q.approval_count == 1


# ---------------------------------------------------------------------------
# Regression: one-time-use challenges, quorum seal, binding helpers
# ---------------------------------------------------------------------------


class TestOneTimeUseChallenges:
    def test_second_quorum_reusing_finalized_challenge_rejected(self):
        # Finalizing quorum A burns its challenge process-wide; a brand-new
        # quorum can never collect approvals over that challenge again —
        # even from a different approver with a fresh assertion.
        challenge = secrets.token_bytes(32)
        digest = _digest("action")
        issuer = Ed25519Signer.generate("issuer")

        qa = QuorumApproval(1, 1)
        auth_a, _ = _software("approver-a")
        qa.approve(auth_a, challenge,
                   auth_a.create_assertion(challenge, action_digest=digest),
                   digest, _ctx())
        qa.finalize(issuer)

        qb = QuorumApproval(1, 1)
        auth_b, _ = _software("approver-b")
        with pytest.raises(QuorumError):
            qb.approve(auth_b, challenge,
                       auth_b.create_assertion(challenge, action_digest=digest),
                       digest, _ctx())
        assert qb.approval_count == 0
        assert not qb.is_satisfied()

    def test_burned_challenge_rejected_even_with_same_digest(self):
        # One-time-use is per-challenge, not per (challenge, digest) pair:
        # reusing the challenge for the SAME action is still rejected.
        challenge = secrets.token_bytes(32)
        digest = _digest("action")
        issuer = Ed25519Signer.generate("issuer")
        q1 = QuorumApproval(1, 1)
        auth1, _ = _software("a1")
        q1.approve(auth1, challenge,
                   auth1.create_assertion(challenge, action_digest=digest),
                   digest, _ctx())
        q1.finalize(issuer)
        q2 = QuorumApproval(1, 1)
        auth2, _ = _software("a2")
        with pytest.raises(QuorumError):
            q2.approve(auth2, challenge,
                       auth2.create_assertion(challenge, action_digest=digest),
                       digest, _ctx())

    def test_unfinalized_challenge_still_usable_after_abandon(self):
        # Burning happens at finalize(), not at approve(): abandoning a
        # quorum releases its in-flight challenge WITHOUT burning it, so a
        # fresh quorum may use the challenge afterwards. (Two LIVE quorums
        # sharing one challenge is rejected — see TestInFlightChallenges —
        # so an explicit abandon() is the only way to free the challenge.)
        challenge = secrets.token_bytes(32)
        digest = _digest("action")
        q1 = QuorumApproval(1, 2)
        auth1, _ = _software("a1")
        q1.approve(auth1, challenge,
                   auth1.create_assertion(challenge, action_digest=digest),
                   digest, _ctx())
        q1.abandon()
        assert q1.is_abandoned
        q2 = QuorumApproval(1, 1)
        auth2, _ = _software("a2")
        q2.approve(auth2, challenge,
                   auth2.create_assertion(challenge, action_digest=digest),
                   digest, _ctx())
        assert q2.is_satisfied()
        q2.finalize(Ed25519Signer.generate("issuer"))  # then it burns normally


class TestInFlightChallenges:
    """S7: the pre-finalize cross-quorum window. With coordinator challenge
    reuse (trusted-party misuse) and a non-binding authenticator, assertion
    bytes for digest_A could finalize a quorum for digest_B BEFORE the first
    quorum finalizes — the burned ledger alone cannot see this. The
    in-flight registry rejects a second LIVE quorum binding the same
    challenge."""

    def test_two_live_quorums_sharing_challenge_second_approve_raises(self):
        # q1 is live (approved, NOT finalized) over challenge C; q2's first
        # approval over the same challenge must raise — even for the SAME
        # digest, since two live quorums sharing a challenge is the misuse.
        challenge = secrets.token_bytes(32)
        digest = _digest("action")
        q1 = QuorumApproval(1, 2)
        auth1, _ = _software("a1")
        q1.approve(auth1, challenge,
                   auth1.create_assertion(challenge, action_digest=digest),
                   digest, _ctx())

        q2 = QuorumApproval(1, 1)
        auth2, _ = _software("a2")
        with pytest.raises(QuorumError):
            q2.approve(auth2, challenge,
                       auth2.create_assertion(challenge, action_digest=digest),
                       digest, _ctx())
        assert q2.approval_count == 0
        assert not q2.is_satisfied()

    def test_cross_action_replay_before_first_finalize_rejected(self):
        # The exact S7 scenario: the SAME (non-binding hardware) assertion
        # bytes, minted for action A, are replayed into a SECOND quorum for
        # action B through a fresh verifier — before quorum A finalizes.
        # The hardware path is used on purpose: hardware assertions carry no
        # action_digest binding, so only the in-flight registry can reject.
        signer = Ed25519Signer.generate("approver-a")
        cred = CredentialRecord(
            key_type="EdDSA", public_key=signer.public_key_bytes()
        )
        challenge = secrets.token_bytes(32)
        digest_a, digest_b = _digest("action-A"), _digest("action-B")
        verifier_a = WebAuthnVerifier(RP_ID, ORIGIN, {"approver-a": cred})
        qa = QuorumApproval(1, 1)
        assertion_for_a = _craft_assertion(
            key_id="approver-a", sign_key=signer, key_type="EdDSA",
            challenge=challenge, sign_count=1,
        )
        qa.approve(verifier_a, challenge, assertion_for_a, digest_a, _ctx())
        # qa is LIVE — not finalized. The attacker replays into qb for B:
        verifier_b = WebAuthnVerifier(RP_ID, ORIGIN, {"approver-a": cred})
        qb = QuorumApproval(1, 1)
        with pytest.raises(QuorumError):
            qb.approve(verifier_b, challenge, assertion_for_a, digest_b, _ctx())
        assert qb.approval_count == 0
        # The honest quorum is unaffected and can still finalize.
        issuer = Ed25519Signer.generate("issuer")
        record = verify_approval_record(
            qa.finalize(issuer), {"issuer": issuer.public_key_bytes()}
        )
        assert record.action_digest == digest_a

    def test_sequential_quorums_second_still_raises_burned(self):
        # After q1 finalizes, the challenge is burned: a second quorum's
        # approve() raises (the burned-ledger half of one-time-use).
        challenge = secrets.token_bytes(32)
        digest = _digest("action")
        issuer = Ed25519Signer.generate("issuer")
        q1 = QuorumApproval(1, 1)
        auth1, _ = _software("a1")
        q1.approve(auth1, challenge,
                   auth1.create_assertion(challenge, action_digest=digest),
                   digest, _ctx())
        q1.finalize(issuer)
        q2 = QuorumApproval(1, 1)
        auth2, _ = _software("a2")
        with pytest.raises(QuorumError):
            q2.approve(auth2, challenge,
                       auth2.create_assertion(challenge, action_digest=digest),
                       digest, _ctx())

    def test_different_challenges_two_live_quorums_fine(self):
        # Distinct challenges are independent: two live quorums proceed in
        # parallel without interference.
        digest = _digest("action")
        q1, q2 = QuorumApproval(1, 1), QuorumApproval(1, 1)
        for q, name in ((q1, "a1"), (q2, "a2")):
            challenge = secrets.token_bytes(32)
            auth, _ = _software(name)
            q.approve(auth, challenge,
                      auth.create_assertion(challenge, action_digest=digest),
                      digest, _ctx())
            assert q.is_satisfied()

    def test_failed_first_approval_claims_nothing(self):
        # A quorum whose first approval FAILS verification never binds and
        # never claims the challenge: a fresh quorum may use it afterwards.
        challenge = secrets.token_bytes(32)
        digest = _digest("action")
        q1 = QuorumApproval(1, 1)
        auth1, _ = _software("a1")
        wrong_challenge = secrets.token_bytes(32)
        with pytest.raises(StepUpError):  # assertion is for another challenge
            q1.approve(auth1, wrong_challenge,
                       auth1.create_assertion(challenge,
                                              action_digest=digest),
                       digest, _ctx())
        assert q1.approval_count == 0
        q2 = QuorumApproval(1, 1)
        auth2, _ = _software("a2")
        q2.approve(auth2, challenge,
                   auth2.create_assertion(challenge, action_digest=digest),
                   digest, _ctx())
        assert q2.is_satisfied()

    def test_abandon_rejects_further_approvals(self):
        q = QuorumApproval(1, 2)
        challenge = secrets.token_bytes(32)
        digest = _digest("action")
        auth1, _ = _software("a1")
        q.approve(auth1, challenge,
                  auth1.create_assertion(challenge, action_digest=digest),
                  digest, _ctx())
        q.abandon()
        auth2, _ = _software("a2")
        with pytest.raises(QuorumError):
            q.approve(auth2, challenge,
                      auth2.create_assertion(challenge, action_digest=digest),
                      digest, _ctx())
        assert not q.is_satisfied()  # abandoned quorums never satisfy
        with pytest.raises(QuorumError):
            q.finalize(Ed25519Signer.generate("issuer"))

    def test_abandon_twice_is_noop_and_finalized_cannot_abandon(self):
        q = QuorumApproval(1, 1)
        q.abandon()
        q.abandon()  # no-op
        assert q.is_abandoned
        q2 = QuorumApproval(1, 1)
        challenge = secrets.token_bytes(32)
        digest = _digest("action")
        auth, _ = _software("a")
        q2.approve(auth, challenge,
                   auth.create_assertion(challenge, action_digest=digest),
                   digest, _ctx())
        q2.finalize(Ed25519Signer.generate("issuer"))
        with pytest.raises(QuorumError):
            q2.abandon()

    def test_close_alias_releases_like_abandon(self):
        q = QuorumApproval(1, 1)
        challenge = secrets.token_bytes(32)
        digest = _digest("action")
        auth1, _ = _software("a1")
        q.approve(auth1, challenge,
                  auth1.create_assertion(challenge, action_digest=digest),
                  digest, _ctx())
        q.close()
        assert q.is_abandoned
        q2 = QuorumApproval(1, 1)
        auth2, _ = _software("a2")
        q2.approve(auth2, challenge,
                   auth2.create_assertion(challenge, action_digest=digest),
                   digest, _ctx())
        assert q2.is_satisfied()


class TestQuorumSeal:
    def test_post_finalize_approve_rejected(self):
        # The seal fires FIRST in approve(), before any verification work: a
        # sealed quorum never even consults the authenticator. The spy below
        # uses a fresh (unburned) challenge, so only the seal can reject it —
        # neutering the seal makes the spy get called and fails this test.
        calls = []

        class SpyAuthenticator(Authenticator):
            def create_challenge(self):
                return secrets.token_bytes(32)

            def verify_assertion(self, challenge, assertion, context):
                calls.append((challenge, assertion))
                return "spy"

        q = QuorumApproval(1, 2)
        challenge = secrets.token_bytes(32)
        digest = _digest("action")
        auth1, _ = _software("first")
        q.approve(auth1, challenge,
                  auth1.create_assertion(challenge, action_digest=digest),
                  digest, _ctx())
        issuer = Ed25519Signer.generate("issuer")
        q.finalize(issuer)
        assert q.is_sealed

        spy = SpyAuthenticator()
        dummy = Assertion(
            authenticator_data=b"\x00" * 37,
            client_data_json=b"{}",
            signature=b"\x00" * 64,
            key_id="spy",
        )
        with pytest.raises(QuorumError):
            q.approve(spy, secrets.token_bytes(32), dummy, digest, _ctx())
        assert calls == [], "sealed quorum must not consult the authenticator"
        assert q.approval_count == 1

    def test_double_finalize_rejected(self):
        q, _ = _quorum_with_approvals(1, 1, 1)
        issuer = Ed25519Signer.generate("issuer")
        first = q.finalize(issuer)
        assert isinstance(first, bytes)
        with pytest.raises(QuorumError):
            q.finalize(issuer)

    def test_finalize_burns_challenge_for_other_quorums(self):
        # The seal and the burn compose: the finalized quorum's own challenge
        # is dead process-wide afterwards.
        q, (challenge,) = _quorum_with_approvals(1, 1, 1)
        issuer = Ed25519Signer.generate("issuer")
        q.finalize(issuer)
        q2 = QuorumApproval(1, 1)
        auth, _ = _software("other")
        digest = _digest("action")
        with pytest.raises(QuorumError):
            q2.approve(auth, challenge,
                       auth.create_assertion(challenge, action_digest=digest),
                       digest, _ctx())


class TestAssertionDigestBinding:
    def test_create_assertion_embeds_action_digest(self):
        auth, _ = _software("s")
        challenge = auth.create_challenge()
        assertion = auth.create_assertion(challenge, action_digest="abc123")
        client_data = json.loads(assertion.client_data_json.decode())
        assert client_data["action_digest"] == "abc123"
        # The base WebAuthn shape is unchanged.
        assert client_data["type"] == "webauthn.get"
        assert client_data["challenge"] == _b64url_nopad(challenge)

    def test_create_assertion_rejects_empty_action_digest(self):
        auth, _ = _software("s")
        with pytest.raises(StepUpError):
            auth.create_assertion(auth.create_challenge(), action_digest="")

    def test_assertion_without_bound_digest_rejected(self):
        # SoftwareAuthenticator opts into binding, so an assertion minted
        # WITHOUT the extension field cannot satisfy a quorum.
        q = QuorumApproval(1, 1)
        auth, _ = _software("a")
        challenge = auth.create_challenge()
        digest = _digest("action")
        with pytest.raises(QuorumError):
            q.approve(auth, challenge, auth.create_assertion(challenge),
                      digest, _ctx())
        assert q.approval_count == 0

    def test_assertion_bound_to_wrong_digest_rejected(self):
        # Assertion bytes minted for digest-A are replayed into a quorum for
        # digest-B over the SAME (unburned) challenge: the signed
        # clientDataJSON still says digest-A, so the quorum rejects them.
        # This is the assertion-level backstop for the software path.
        auth, _ = _software("a")
        challenge = auth.create_challenge()  # never finalized -> not burned
        assertion_for_a = auth.create_assertion(
            challenge, action_digest=_digest("action-A")
        )
        q = QuorumApproval(1, 1)
        with pytest.raises(QuorumError):
            q.approve(auth, challenge, assertion_for_a, _digest("action-B"),
                      _ctx())
        assert q.approval_count == 0
        assert not q.is_satisfied()

    def test_hardware_path_has_no_assertion_binding(self):
        # WebAuthnVerifier does not opt into binds_action_digest (real
        # hardware keys cannot emit the extension field); document that the
        # hardware path relies on the one-time-use ledger + Guardian check.
        priv, cred = _es256_credential()
        v = WebAuthnVerifier(RP_ID, ORIGIN, {"hw": cred})
        assert v.binds_action_digest is False
        auth_sw, _ = _software("sw")
        assert auth_sw.binds_action_digest is True


class TestCheckApprovalBinding:
    def _record(self, digest_label="action") -> ApprovalRecord:
        q, _ = _quorum_with_approvals(1, 1, 1, digest_label=digest_label)
        issuer = Ed25519Signer.generate("issuer")
        return verify_approval_record(
            q.finalize(issuer), {"issuer": issuer.public_key_bytes()}
        )

    def test_matching_digest_passes(self):
        record = self._record("action")
        check_approval_binding(record, _digest("action"))  # must not raise

    def test_mismatched_digest_raises(self):
        record = self._record("action-A")
        with pytest.raises(QuorumError):
            check_approval_binding(record, _digest("action-B"))

    def test_empty_expected_digest_raises(self):
        record = self._record("action")
        with pytest.raises(QuorumError):
            check_approval_binding(record, "")

    def test_wrong_type_expected_digest_raises(self):
        record = self._record("action")
        with pytest.raises(QuorumError):
            check_approval_binding(record, None)


# ---------------------------------------------------------------------------
# Unit: ApprovalRecord verification (Guardian consumption path)
# ---------------------------------------------------------------------------


class TestApprovalRecordVerification:
    def test_roundtrip_preserves_all_fields(self):
        q, (challenge,) = _quorum_with_approvals(2, 3, 2)
        issuer = Ed25519Signer.generate("issuer")
        decided = datetime(2026, 9, 23, 12, 0, 0, tzinfo=timezone.utc)
        record = verify_approval_record(
            q.finalize(issuer, decided_at=decided),
            {"issuer": issuer.public_key_bytes()},
        )
        assert record.action_digest == _digest("action")
        assert record.challenge == challenge
        assert (record.m, record.n) == (2, 3)
        assert record.decided_at == decided

    def test_garbage_bytes_rejected(self):
        with pytest.raises(QuorumError):
            verify_approval_record(b"not a cose message", {"k": b"\x00" * 32})

    def test_record_with_tampered_kid_rejected(self):
        q, _ = _quorum_with_approvals(1, 1, 1)
        issuer = Ed25519Signer.generate("issuer")
        record_bytes = q.finalize(issuer)
        outer = cbor_loads(record_bytes)
        protected = dict(cbor_loads(outer[0]))
        protected[4] = b"impostor"
        evil_outer = [cbor_dumps(protected), outer[1], outer[2], outer[3]]
        with pytest.raises(QuorumError):
            verify_approval_record(
                cbor_dumps(evil_outer), {"issuer": issuer.public_key_bytes()}
            )

    def test_cose_protected_header_strictness_inherited(self):
        # cose_verify itself enforces alg/kid allowlists; a record signed with
        # a non-empty unprotected header must fail.
        from anchor_v1.cose import cose_sign_bytes

        q, _ = _quorum_with_approvals(1, 1, 1)
        issuer = Ed25519Signer.generate("issuer")
        record = verify_approval_record(
            q.finalize(issuer), {"issuer": issuer.public_key_bytes()}
        )
        payload = cbor_dumps(
            {
                "action_digest": record.action_digest,
                "challenge": record.challenge,
                "m": record.m,
                "n": record.n,
                "approver_key_ids": record.approver_key_ids,
                "decided_at": record.decided_at.isoformat(),
            }
        )
        from anchor_v1.cbor import cbor_loads as _loads

        msg = cose_sign_bytes(payload, issuer.sign_bytes, b"issuer")
        outer = _loads(msg)
        evil = [outer[0], {"evil": 1}, outer[2], outer[3]]
        with pytest.raises(QuorumError):
            verify_approval_record(cbor_dumps(evil), {"issuer": issuer.public_key_bytes()})
