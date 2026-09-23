"""Tests for anchor_v1 Wave 1: canonical CBOR, COSE_Sign1, ActionEnvelope.

Unit tests cover the happy paths and determinism properties. Every attack is
labeled ATTACK-### and must end in rejection — never silent acceptance.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from anchor_v1.cbor import CBORError, Tag, cbor_dumps, cbor_loads
from anchor_v1.cose import COSEError, cose_sign, cose_verify
from anchor_v1.crypto import Ed25519Signer
from anchor_v1.envelope import (
    ActionEnvelope,
    Effect,
    EnvelopeError,
    migrate_from_signed_envelope,
)
from anchor_v1.models import SignedEnvelope


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _signer(key_id: str = "test-key") -> Ed25519Signer:
    return Ed25519Signer.generate(key_id)


def _pubkey(signer: Ed25519Signer) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(signer.public_key_bytes())


def _envelope(**overrides) -> ActionEnvelope:
    now = datetime.now(timezone.utc)
    base = dict(
        action_id=uuid.uuid4(),
        principal="did:example:agent-1",
        effect=Effect(
            plane="shell",
            verb="exec",
            target="sha256:deadbeef",
            args_digest="ab" * 32,
        ),
        policy_ref="constitution:v3:deadbeef",
        issued_at=now,
        not_before=now - timedelta(minutes=5),
        not_after=now + timedelta(hours=1),
        nonce=uuid.uuid4().hex,
    )
    base.update(overrides)
    return ActionEnvelope(**base)


def _trusted(signer: Ed25519Signer) -> dict[str, bytes]:
    return {signer.key_id: signer.public_key_bytes()}


# ---------------------------------------------------------------------------
# CBOR unit tests
# ---------------------------------------------------------------------------

class TestCBORRoundTrip:
    @pytest.mark.parametrize(
        "value",
        [
            0, 1, 23, 24, 255, 256, 65535, 65536,
            2**32 - 1, 2**32, 2**64 - 1,
            -1, -24, -25, -256, -2**64,
            2**64, -(2**64) - 1, 2**100, -(2**100),  # bignum
            b"", b"\x00\xff",
            "", "hello", "héllo wörld ✓",
            [], [1, "two", b"three", None, True],
            {}, {"a": 1, "b": [1, 2]},
            True, False, None,
            0.0, 1.5, -0.0, 100000.0, 3.141592653589793,
            float("inf"), float("-inf"),
            Tag(100, "tagged"),
        ],
    )
    def test_round_trip(self, value):
        assert cbor_loads(cbor_dumps(value)) == value

    def test_nan_round_trip(self):
        import math
        assert math.isnan(cbor_loads(cbor_dumps(float("nan"))))

    def test_shortest_int_forms(self):
        assert cbor_dumps(0) == b"\x00"
        assert cbor_dumps(23) == b"\x17"
        assert cbor_dumps(24) == b"\x18\x18"
        assert cbor_dumps(255) == b"\x18\xff"
        assert cbor_dumps(256) == b"\x19\x01\x00"
        assert cbor_dumps(-1) == b"\x20"
        assert cbor_dumps(-25) == b"\x38\x18"

    def test_shortest_float_forms(self):
        assert cbor_dumps(1.5) == b"\xf9\x3e\x00"          # half
        assert cbor_dumps(100000.0) == b"\xfa\x47\xc3\x50\x00"  # single
        assert len(cbor_dumps(3.141592653589793)) == 9      # double

    def test_canonical_map_ordering(self):
        # length-then-lexicographic over ENCODED keys: "bb" (3B) < "a" (2B)? No:
        # "a" encodes to 2 bytes, "bb" to 3 -> "a" first regardless of value.
        enc = cbor_dumps({"bb": 1, "a": 2, "ccc": 3})
        assert enc == b"\xa3" + b"\x61a\x02" + b"\x62bb\x01" + b"\x63ccc\x03"

    def test_map_order_independent_of_insertion(self):
        d1 = {"z": 1, "a": 2, "m": 3}
        d2 = {"m": 3, "z": 1, "a": 2}
        assert cbor_dumps(d1) == cbor_dumps(d2)

    def test_bignum_encoding(self):
        assert cbor_dumps(2**64) == b"\xc2\x49" + (2**64).to_bytes(9, "big")
        assert cbor_loads(cbor_dumps(-(2**64) - 5)) == -(2**64) - 5


class TestCBORStrictness:
    def test_reject_non_shortest_int(self):
        with pytest.raises(CBORError):
            cbor_loads(b"\x18\x00")  # 0 in 1-byte form
        with pytest.raises(CBORError):
            cbor_loads(b"\x19\x00\x18")  # 24 in 2-byte form

    def test_reject_indefinite_lengths(self):
        with pytest.raises(CBORError):
            cbor_loads(b"\x9f\x01\x02\xff")  # indefinite array
        with pytest.raises(CBORError):
            cbor_loads(b"\x5f\x41\x00\xff")  # indefinite bytes
        with pytest.raises(CBORError):
            cbor_loads(b"\xbf\x61a\x01\xff")  # indefinite map

    def test_reject_misordered_map_keys(self):
        bad = b"\xa2" + b"\x62bb\x01" + b"\x61a\x02"  # "bb" before "a"
        with pytest.raises(CBORError):
            cbor_loads(bad)

    def test_reject_duplicate_map_keys(self):
        bad = b"\xa2" + b"\x61a\x01" + b"\x61a\x02"
        with pytest.raises(CBORError):
            cbor_loads(bad)

    def test_reject_trailing_bytes(self):
        with pytest.raises(CBORError):
            cbor_loads(cbor_dumps(1) + b"\x00")

    def test_reject_truncated(self):
        with pytest.raises(CBORError):
            cbor_loads(b"\x18")

    def test_reject_non_shortest_simple(self):
        with pytest.raises(CBORError):
            cbor_loads(b"\xf8\x00")  # simple(0) must use 1-byte form

    def test_reject_non_shortest_bignum(self):
        with pytest.raises(CBORError):
            cbor_loads(b"\xc2\x42\x00\x01")  # leading zero byte

    def test_reject_wrong_type(self):
        with pytest.raises(CBORError):
            cbor_loads("not bytes")


# ---------------------------------------------------------------------------
# COSE unit tests
# ---------------------------------------------------------------------------

class TestCOSE:
    def test_sign_verify_round_trip(self):
        s = _signer()
        msg = cose_sign(b"payload-bytes", s._private_key, b"test-key")
        payload, kid = cose_verify(msg, {b"test-key": _pubkey(s)})
        assert payload == b"payload-bytes"
        assert kid == b"test-key"

    def test_protected_header_content(self):
        s = _signer()
        msg = cose_sign(b"x", s._private_key, b"test-key")
        outer = cbor_loads(msg)
        protected = cbor_loads(outer[0])
        assert protected == {1: -8, 4: b"test-key"}
        assert outer[1] == {}

    def test_external_aad_binds(self):
        s = _signer()
        msg = cose_sign(b"x", s._private_key, b"test-key", external_aad=b"aad")
        with pytest.raises(COSEError):
            cose_verify(msg, {b"test-key": _pubkey(s)})  # wrong aad
        payload, _ = cose_verify(msg, {b"test-key": _pubkey(s)}, external_aad=b"aad")
        assert payload == b"x"

    def test_reject_empty_kid(self):
        s = _signer()
        with pytest.raises(COSEError):
            cose_sign(b"x", s._private_key, b"")

    def test_reject_non_canonical_cose(self):
        s = _signer()
        msg = cose_sign(b"x", s._private_key, b"k")
        # Re-encode outer array with non-shortest int for array length.
        tampered = b"\x98\x04" + msg[1:]  # 0x98 0x04 = 4 in 1-byte form (non-shortest)
        with pytest.raises(COSEError):
            cose_verify(tampered, {b"k": _pubkey(s)})


# ---------------------------------------------------------------------------
# ActionEnvelope unit tests
# ---------------------------------------------------------------------------

class TestActionEnvelope:
    def test_sign_verify_round_trip(self):
        s = _signer()
        env = _envelope()
        msg = env.sign_envelope(s)
        got = ActionEnvelope.verify_envelope(msg, _trusted(s))
        assert got.action_digest == env.action_digest
        assert got.action_id == env.action_id

    def test_canonical_bytes_stable_across_encodings(self):
        env = _envelope()
        once = env.canonical_bytes()
        twice = env.canonical_bytes()
        assert once == twice
        # Decode -> re-encode is a fixed point (strict decoder + canonical encoder).
        assert cbor_dumps(cbor_loads(once)) == once

    def test_digest_changes_with_any_field(self):
        env = _envelope()
        d0 = env.action_digest
        assert _envelope(nonce="different").action_digest != d0
        assert _envelope(principal="someone-else").action_digest != d0
        assert _envelope(policy_ref="constitution:v9:00").action_digest != d0

    def test_digest_is_sha256_of_canonical_bytes(self):
        env = _envelope()
        assert env.action_digest == hashlib.sha256(env.canonical_bytes()).hexdigest()

    def test_field_insertion_order_does_not_change_digest(self):
        # Build the same logical envelope from a differently-ordered dict.
        env = _envelope()
        raw = env.model_dump(mode="json")
        shuffled = {k: raw[k] for k in reversed(list(raw.keys()))}
        assert cbor_dumps(shuffled) == env.canonical_bytes()

    def test_migrate_from_signed_envelope(self):
        s = _signer("v0-key")
        se = s.sign_payload({"subject": "agent-9", "action": "ls /tmp",
                             "issued_at": "2026-09-23T08:00:00+00:00"})
        migrated = migrate_from_signed_envelope(se)
        assert isinstance(migrated, ActionEnvelope)
        assert migrated.principal == "agent-9"
        assert migrated.policy_ref == "v0:unknown"
        # Deterministic: same v0 envelope -> same migrated envelope.
        assert migrate_from_signed_envelope(se).action_id == migrated.action_id
        assert migrate_from_signed_envelope(se).action_digest == migrated.action_digest

    def test_migrate_preserves_effect_when_present(self):
        se = SignedEnvelope(
            key_id="k",
            payload={"effect": {"plane": "http", "verb": "post",
                                "target": "https://x", "args_digest": "ff" * 32}},
            signature="e30=",
        )
        migrated = migrate_from_signed_envelope(se)
        assert migrated.effect.plane == "http"
        assert migrated.effect.args_digest == "ff" * 32


# ---------------------------------------------------------------------------
# Adversarial attacks — every one must end in REJECTION
# ---------------------------------------------------------------------------

class TestAdversarial:
    def _signed(self, signer=None, **overrides):
        s = signer or _signer()
        env = _envelope(**overrides)
        return s, env, env.sign_envelope(s)

    def test_attack_01_reencoding_non_canonical_cbor_rejected(self):
        """ATTACK-01 (re-encoding): same logical envelope, non-canonical CBOR
        on the wire (non-shortest ints) must be rejected by the strict decoder."""
        s, env, msg = self._signed()
        outer = cbor_loads(msg)
        # Replace payload with a hand-built non-canonical encoding:
        # map header 0xa8 (8 entries) in non-shortest 2-byte form 0xb9 0x00 0x08.
        non_canonical = b"\xb9\x00\x08" + env.canonical_bytes()[1:]
        tampered = cbor_dumps([outer[0], outer[1], non_canonical, outer[3]])
        with pytest.raises(EnvelopeError):
            ActionEnvelope.verify_envelope(tampered, _trusted(s))

    def test_attack_02_canonical_digest_stable_across_reencodes(self):
        """ATTACK-02 (digest stability): an attacker re-encodes the envelope
        through a *different* CBOR library path (misordered keys, long ints);
        the strict decoder must reject it, and the canonical digest must be
        identical no matter which insertion order produced the bytes."""
        s, env, msg = self._signed()
        digest_before = env.action_digest
        # Wire variant with misordered map keys.
        raw = cbor_loads(env.canonical_bytes())
        keys = list(raw.keys())
        misordered = b"\xa8"
        for k in reversed(keys):
            misordered += cbor_dumps(k) + cbor_dumps(raw[k])
        outer = cbor_loads(msg)
        tampered = cbor_dumps([outer[0], outer[1], misordered, outer[3]])
        with pytest.raises(EnvelopeError):
            ActionEnvelope.verify_envelope(tampered, _trusted(s))
        # And the canonical digest is stable: encode twice, compare bytes.
        assert env.canonical_bytes() == env.canonical_bytes()
        assert env.action_digest == digest_before

    def test_attack_03_protected_header_alg_confusion(self):
        """ATTACK-03 (alg confusion): protected header claims alg != EdDSA
        (e.g. -7/ES256). Must be rejected even before signature checking."""
        s, env, msg = self._signed()
        outer = cbor_loads(msg)
        evil_protected = cbor_dumps({1: -7, 4: b"test-key"})  # ES256
        tampered = cbor_dumps([evil_protected, outer[1], outer[2], outer[3]])
        with pytest.raises(EnvelopeError, match="algorithm not allowed"):
            ActionEnvelope.verify_envelope(tampered, _trusted(s))

    def test_attack_04_payload_swap_after_signing(self):
        """ATTACK-04 (payload swap): flip a bit in the signed payload; the
        signature must fail and the envelope must be rejected."""
        s, env, msg = self._signed()
        outer = cbor_loads(msg)
        payload = bytearray(outer[2])
        payload[20] ^= 0x01
        tampered = cbor_dumps([outer[0], outer[1], bytes(payload), outer[3]])
        with pytest.raises(EnvelopeError, match="signature verification failed"):
            ActionEnvelope.verify_envelope(tampered, _trusted(s))

    def test_attack_05_kid_confusion_wrong_key(self):
        """ATTACK-05 (kid confusion): verify against a trust set where the
        claimed kid maps to a DIFFERENT key. Must be rejected."""
        s, env, msg = self._signed()
        other = _signer("test-key")  # same kid string, different keypair
        with pytest.raises(EnvelopeError, match="signature verification failed"):
            ActionEnvelope.verify_envelope(msg, _trusted(other))

    def test_attack_06_kid_confusion_unknown_kid(self):
        """ATTACK-06: kid not present in the trust set. Must be rejected."""
        s, env, msg = self._signed()
        with pytest.raises(EnvelopeError, match="unknown kid"):
            ActionEnvelope.verify_envelope(msg, {"someone-else": s.public_key_bytes()})

    def test_attack_07_expired_envelope(self):
        """ATTACK-07 (replay of expired envelope): not_after in the past."""
        past = datetime.now(timezone.utc) - timedelta(seconds=1)
        s, env, msg = self._signed(not_after=past,
                                   not_before=past - timedelta(hours=1),
                                   issued_at=past - timedelta(hours=1))
        with pytest.raises(EnvelopeError, match="expired"):
            ActionEnvelope.verify_envelope(msg, _trusted(s))

    def test_attack_08_not_yet_valid_envelope(self):
        """ATTACK-08 (pre-play): not_before in the future."""
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        s, env, msg = self._signed(not_before=future,
                                   not_after=future + timedelta(hours=1))
        with pytest.raises(EnvelopeError, match="not yet valid"):
            ActionEnvelope.verify_envelope(msg, _trusted(s))

    def test_attack_09_duplicate_map_keys_on_wire(self):
        """ATTACK-09: envelope payload CBOR with a duplicated map key.
        The second value must not silently win — reject the whole message."""
        s, env, msg = self._signed()
        outer = cbor_loads(msg)
        dup = (b"\xa8"
               + b"\x6aaction_id" + cbor_dumps(str(env.action_id))
               + b"\x6aaction_id" + cbor_dumps(str(uuid.uuid4())))
        # Pad to 8 entries with the remaining real fields (duplicates of nonce too).
        raw = cbor_loads(env.canonical_bytes())
        wire = b"\xa8"
        seen = 0
        for k, v in raw.items():
            if k == "action_id":
                wire += b"\x6aaction_id" + cbor_dumps(str(env.action_id))
                wire += b"\x6aaction_id" + cbor_dumps(str(uuid.uuid4()))
                seen += 2
            else:
                wire += cbor_dumps(k) + cbor_dumps(v)
                seen += 1
        assert seen == 9  # 8 fields + 1 duplicate
        # Fix the map header count to 9.
        wire = b"\xa9" + wire[1:]
        tampered = cbor_dumps([outer[0], outer[1], wire, outer[3]])
        with pytest.raises(EnvelopeError):
            ActionEnvelope.verify_envelope(tampered, _trusted(s))

    def test_attack_10_cross_protocol_v0_json_rejected(self):
        """ATTACK-10 (cross-protocol confusion): a v0 SignedEnvelope JSON blob
        must NOT verify as an ActionEnvelope."""
        s = _signer("v0-key")
        se = s.sign_payload({"subject": "agent-9", "action": "rm -rf /"})
        v0_json_bytes = json.dumps(se.model_dump(mode="json")).encode()
        with pytest.raises(EnvelopeError):
            ActionEnvelope.verify_envelope(v0_json_bytes, _trusted(s))

    def test_attack_11_tampered_signature(self):
        """ATTACK-11: flip a bit in the signature bytes."""
        s, env, msg = self._signed()
        outer = cbor_loads(msg)
        sig = bytearray(outer[3])
        sig[-1] ^= 0x01
        tampered = cbor_dumps([outer[0], outer[1], outer[2], bytes(sig)])
        with pytest.raises(EnvelopeError, match="signature verification failed"):
            ActionEnvelope.verify_envelope(tampered, _trusted(s))

    def test_attack_12_unprotected_header_smuggling(self):
        """ATTACK-12: parameters smuggled in the unprotected header (outside
        the signed protected header) must be rejected, even with a valid sig
        over the original Sig_structure."""
        s = _signer()
        raw_key = s._private_key
        # Sign with a non-empty unprotected header directly at the COSE layer.
        protected = cbor_dumps({1: -8, 4: b"test-key"})
        sig_structure = cbor_dumps(["Signature1", protected, b"", b"payload"])
        sig = raw_key.sign(sig_structure)
        msg = cbor_dumps([protected, {1: -7}, b"payload", sig])  # alg smuggled outside
        with pytest.raises(COSEError, match="unprotected header must be empty"):
            cose_verify(msg, {b"test-key": _pubkey(s)})

    def test_attack_13_indefinite_length_cbor_rejected(self):
        """ATTACK-13: indefinite-length CBOR anywhere in the message."""
        s = _signer()
        msg = cose_sign(b"x", s._private_key, b"k")
        tampered = b"\x9f" + msg[1:]  # indefinite array instead of definite
        with pytest.raises((COSEError, EnvelopeError)):
            ActionEnvelope.verify_envelope(tampered, {"k": s.public_key_bytes()})

    def test_attack_14_truncated_message(self):
        """ATTACK-14: truncated COSE bytes."""
        s, env, msg = self._signed()
        with pytest.raises(EnvelopeError):
            ActionEnvelope.verify_envelope(msg[: len(msg) // 2], _trusted(s))

    def test_attack_15_extra_protected_header_labels(self):
        """ATTACK-15: protected header with extra labels beyond {alg, kid}."""
        s = _signer()
        protected = cbor_dumps({1: -8, 4: b"test-key", 999: "evil"})
        sig_structure = cbor_dumps(["Signature1", protected, b"", b"payload"])
        sig = s._private_key.sign(sig_structure)
        msg = cbor_dumps([protected, {}, b"payload", sig])
        with pytest.raises(COSEError, match="exactly alg and kid"):
            cose_verify(msg, {b"test-key": _pubkey(s)})
