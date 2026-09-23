"""Tests for anchor_v1.anchored_checkpoints: every rule + adversarial attacks.

All attacks must end invalid / rejected — never silent-accept.
"""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone

import pytest

from anchor_v1.anchored_checkpoints import (
    AnchorProof,
    CalendarNotFoundError,
    Checkpoint,
    CheckpointChain,
    CheckpointError,
    EvidenceEvent,
    EvidenceLog,
    HttpOTSCalendarClient,
    InclusionProof,
    LocalEmulatedAnchor,
    NextCheckpointSigner,
    OTSAnchorError,
    OTSCalendarClient,
    OTSCodecError,
    OpenTimestampsAnchor,
    TimestampAnchor,
    TrustedCheckpointSigner,
    _OTS_MAGIC,
    _OTSNode,
    _ots_decode_file,
    _ots_encode_attestation,
    _ots_encode_file,
    _ots_encode_node,
    _ots_varuint_encode,
    build_merkle_root,
    event_hash,
    prove_event,
    seal_checkpoint,
    verify_checkpoint_chain,
    verify_checkpoint_events,
    verify_inclusion,
)
from anchor_v1.crypto import Ed25519Signer
from anchor_v1.models import SignedEnvelope

NOW = datetime(2026, 9, 23, 12, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# fixtures / helpers
# ---------------------------------------------------------------------------


def make_log(n: int, base: datetime = NOW) -> EvidenceLog:
    log = EvidenceLog()
    for i in range(n):
        log.append(
            event_type=f"agent.action.{i % 3}",
            data={"i": i, "detail": f"event-{i}"},
            timestamp=base + timedelta(seconds=i),
        )
    return log


def make_signer(key_id: str = "ckpt-signer-1") -> Ed25519Signer:
    return Ed25519Signer.generate(key_id)


def trusted(signer: Ed25519Signer) -> TrustedCheckpointSigner:
    return TrustedCheckpointSigner(
        key_id=signer.key_id, public_key=signer.public_key_b64()
    )


def make_anchor(key_id: str = "anchor-key-1") -> LocalEmulatedAnchor:
    return LocalEmulatedAnchor(Ed25519Signer.generate(key_id))


def seal_range(
    log: EvidenceLog,
    start: int,
    end: int,
    signer: Ed25519Signer,
    anchor: LocalEmulatedAnchor,
    prev_root: str | None = None,
    next_signer: NextCheckpointSigner | None = None,
) -> SignedEnvelope:
    events = log.events_in_range(start, end)
    return seal_checkpoint(
        events,
        signer,
        anchor,
        prev_root,
        next_signer=next_signer,
        timestamp=NOW + timedelta(minutes=start),
    )


def checkpoint_of(envelope: SignedEnvelope) -> Checkpoint:
    return Checkpoint.model_validate(envelope.payload)


# ---------------------------------------------------------------------------
# unit: evidence log / hash chain
# ---------------------------------------------------------------------------


class TestEvidenceLog:
    def test_append_assigns_sequence_and_links(self):
        log = make_log(3)
        assert [e.sequence for e in log.events] == [0, 1, 2]
        assert log.events[0].previous_hash is None
        assert log.events[1].previous_hash == event_hash(log.events[0])
        assert log.events[2].previous_hash == event_hash(log.events[1])
        assert log.verify_hash_chain()

    def test_hash_changes_when_event_rewritten(self):
        log = make_log(2)
        original = event_hash(log.events[1])
        tampered = log.events[1].model_copy(update={"data": {"i": 1, "evil": True}})
        assert event_hash(tampered) != original

    def test_events_in_range_rejects_bad_ranges(self):
        log = make_log(5)
        with pytest.raises(CheckpointError):
            log.events_in_range(3, 2)
        with pytest.raises(CheckpointError):
            log.events_in_range(0, 9)
        with pytest.raises(CheckpointError):
            log.events_in_range(-1, 2)

    def test_naive_timestamp_rejected(self):
        with pytest.raises(Exception):
            EvidenceEvent(
                sequence=0,
                event_type="x",
                timestamp=datetime(2026, 1, 1),  # naive -> rejected
            )


# ---------------------------------------------------------------------------
# unit: merkle tree
# ---------------------------------------------------------------------------


class TestMerkleTree:
    def test_single_leaf_root_is_leaf(self):
        leaf = "ab" * 32
        assert build_merkle_root([leaf]) == leaf

    def test_two_leaves_root(self):
        a, b = "aa" * 32, "bb" * 32
        from anchor_v1.canonical import sha256_hex

        assert build_merkle_root([a, b]) == sha256_hex({"left": a, "right": b})

    def test_empty_rejected(self):
        with pytest.raises(CheckpointError):
            build_merkle_root([])

    def test_deterministic_and_order_sensitive(self):
        log = make_log(8)
        leaves = [event_hash(e) for e in log.events]
        assert build_merkle_root(leaves) == build_merkle_root(leaves)
        assert build_merkle_root(leaves) != build_merkle_root(leaves[::-1])

    def test_odd_leaf_duplication_documented(self):
        # 3 leaves: level becomes [h01, h22] where h22 = H(leaf2 || leaf2)
        leaves = ["a" * 64, "b" * 64, "c" * 64]
        from anchor_v1.canonical import sha256_hex

        h01 = sha256_hex({"left": leaves[0], "right": leaves[1]})
        h22 = sha256_hex({"left": leaves[2], "right": leaves[2]})
        assert build_merkle_root(leaves) == sha256_hex({"left": h01, "right": h22})


# ---------------------------------------------------------------------------
# unit: inclusion proofs
# ---------------------------------------------------------------------------


class TestInclusionProofs:
    def test_prove_and_verify_every_leaf(self):
        log = make_log(5)
        signer, anchor = make_signer(), make_anchor()
        env = seal_range(log, 0, 4, signer, anchor)
        cp = checkpoint_of(env)
        events = list(log.events_in_range(0, 4))
        for i, event in enumerate(events):
            proof = prove_event(cp, events, i)
            assert verify_inclusion(cp, event, proof) is True
            # minimal: ceil(log2(5)) = 3 steps
            assert len(proof.steps) == 3

    def test_single_event_checkpoint_empty_proof(self):
        log = make_log(1)
        signer, anchor = make_signer(), make_anchor()
        env = seal_range(log, 0, 0, signer, anchor)
        cp = checkpoint_of(env)
        events = list(log.events_in_range(0, 0))
        proof = prove_event(cp, events, 0)
        assert proof.steps == []
        assert cp.merkle_root == event_hash(events[0])
        assert verify_inclusion(cp, events[0], proof) is True

    def test_wrong_event_fails(self):
        log = make_log(5)
        signer, anchor = make_signer(), make_anchor()
        env = seal_range(log, 0, 4, signer, anchor)
        cp = checkpoint_of(env)
        events = list(log.events_in_range(0, 4))
        proof = prove_event(cp, events, 2)
        assert verify_inclusion(cp, events[3], proof) is False

    def test_prove_refuses_mismatched_events(self):
        log = make_log(5)
        signer, anchor = make_signer(), make_anchor()
        env = seal_range(log, 0, 4, signer, anchor)
        cp = checkpoint_of(env)
        other = make_log(5, base=NOW + timedelta(days=1))  # different events
        with pytest.raises(CheckpointError):
            prove_event(cp, list(other.events), 0)

    def test_proof_steps_are_minimal(self):
        log = make_log(16)
        signer, anchor = make_signer(), make_anchor()
        env = seal_range(log, 0, 15, signer, anchor)
        cp = checkpoint_of(env)
        events = list(log.events)
        proof = prove_event(cp, events, 7)
        assert len(proof.steps) == 4  # log2(16)
        assert verify_inclusion(cp, events[7], proof) is True


# ---------------------------------------------------------------------------
# unit: checkpoint sealing + chaining
# ---------------------------------------------------------------------------


class TestCheckpointSealing:
    def test_seal_binds_range_root_and_anchor(self):
        log = make_log(6)
        signer, anchor = make_signer(), make_anchor()
        env = seal_range(log, 0, 5, signer, anchor)
        cp = checkpoint_of(env)
        assert cp.start_seq == 0 and cp.end_seq == 5 and cp.event_count == 6
        assert cp.previous_checkpoint_root is None
        assert cp.merkle_root == build_merkle_root(
            [event_hash(e) for e in log.events_in_range(0, 5)]
        )
        assert cp.anchor_proof.root_hash == cp.merkle_root
        assert cp.anchor_proof.emulated is True
        assert cp.checkpoint_id.startswith("ckpt-")

    def test_seal_rejects_zero_events(self):
        with pytest.raises(CheckpointError):
            seal_checkpoint([], make_signer(), make_anchor(), None)

    def test_seal_rejects_broken_ledger_chain(self):
        log = make_log(3)
        events = list(log.events_in_range(0, 2))
        broken = events[1].model_copy(update={"previous_hash": "00" * 32})
        with pytest.raises(CheckpointError):
            seal_checkpoint(
                [events[0], broken, events[2]], make_signer(), make_anchor(), None
            )

    def test_seal_rejects_noncontiguous_events(self):
        log = make_log(5)
        events = [log.events[0], log.events[2], log.events[3]]
        with pytest.raises(CheckpointError):
            seal_checkpoint(events, make_signer(), make_anchor(), None)


class TestCheckpointChainVerify:
    def _three(self):
        log = make_log(9)
        signer, anchor = make_signer(), make_anchor()
        c1 = seal_range(log, 0, 2, signer, anchor, None)
        c2 = seal_range(
            log, 3, 5, signer, anchor, checkpoint_of(c1).merkle_root
        )
        c3 = seal_range(
            log, 6, 8, signer, anchor, checkpoint_of(c2).merkle_root
        )
        return log, signer, anchor, [c1, c2, c3]

    def test_valid_chain_verifies(self):
        log, signer, anchor, chain = self._three()
        assert verify_checkpoint_chain(chain, trusted(signer), anchor) is True

    def test_empty_chain_fails(self):
        signer, anchor = make_signer(), make_anchor()
        assert verify_checkpoint_chain([], trusted(signer), anchor) is False

    def test_verify_checkpoint_events_full_rebuild(self):
        log, signer, anchor, chain = self._three()
        assert verify_checkpoint_events(chain[1], list(log.events_in_range(3, 5))) is True
        # wrong events -> False
        assert verify_checkpoint_events(chain[1], list(log.events_in_range(0, 2))) is False

    def test_chain_class_seal_and_verify(self):
        log = make_log(6)
        signer, anchor = make_signer(), make_anchor()
        cc = CheckpointChain(trusted(signer), anchor)
        cc.register_signer(signer)
        cc.seal(list(log.events_in_range(0, 2)))
        cc.seal(list(log.events_in_range(3, 5)))
        assert len(cc) == 2
        assert cc.verify() is True

    def test_chain_class_rejects_gap(self):
        log = make_log(6)
        signer, anchor = make_signer(), make_anchor()
        cc = CheckpointChain(trusted(signer), anchor)
        cc.register_signer(signer)
        cc.seal(list(log.events_in_range(0, 2)))
        with pytest.raises(CheckpointError):
            cc.seal(list(log.events_in_range(4, 5)))  # gap at 3


# ---------------------------------------------------------------------------
# unit: anchor interface
# ---------------------------------------------------------------------------


class TestAnchorInterface:
    def test_local_emulated_round_trip(self):
        anchor = make_anchor()
        proof = anchor.anchor("ff" * 32, NOW)
        assert proof.scheme == "local-emulated"
        assert proof.emulated is True
        assert len(anchor.log) == 1
        checkpoint = {
            "merkle_root": "ff" * 32,
            "timestamp": NOW.isoformat(),
        }
        assert anchor.verify_anchor(checkpoint, proof) is True

    def test_local_emulated_rejects_wrong_root(self):
        anchor = make_anchor()
        proof = anchor.anchor("ff" * 32, NOW)
        checkpoint = {"merkle_root": "00" * 32, "timestamp": NOW.isoformat()}
        assert anchor.verify_anchor(checkpoint, proof) is False

    def test_local_emulated_rejects_wrong_timestamp(self):
        anchor = make_anchor()
        proof = anchor.anchor("ff" * 32, NOW)
        checkpoint = {
            "merkle_root": "ff" * 32,
            "timestamp": (NOW + timedelta(hours=1)).isoformat(),
        }
        assert anchor.verify_anchor(checkpoint, proof) is False

    def test_local_emulated_rejects_proof_not_in_log(self):
        # Same anchor key, second instance: signature valid, but the proof was
        # never issued by THIS log -> membership check fails closed.
        key = Ed25519Signer.generate("shared-anchor-key")
        anchor_a = LocalEmulatedAnchor(key)
        anchor_b = LocalEmulatedAnchor(key)
        proof = anchor_b.anchor("ff" * 32, NOW)
        checkpoint = {"merkle_root": "ff" * 32, "timestamp": NOW.isoformat()}
        assert anchor_b.verify_anchor(checkpoint, proof) is True
        assert anchor_a.verify_anchor(checkpoint, proof) is False

    def test_local_emulated_is_labeled(self):
        assert LocalEmulatedAnchor.EMULATED is True

    def test_local_emulated_is_labeled(self):
        assert LocalEmulatedAnchor.EMULATED is True


# ---------------------------------------------------------------------------
# unit: real OpenTimestampsAnchor (network isolated behind a fake calendar)
# ---------------------------------------------------------------------------


class FakeCalendar(OTSCalendarClient):
    """In-memory stand-in for a public OTS calendar. No network."""

    def __init__(self):
        self.submitted: list[bytes] = []
        self._timestamps: dict[bytes, _OTSNode] = {}
        self.fail_submit = False
        self.fail_get = False

    def submit(self, digest: bytes) -> bytes:
        if self.fail_submit:
            raise OTSAnchorError("simulated calendar outage")
        self.submitted.append(bytes(digest))
        node = _OTSNode(bytes(digest))
        node.attestations.append(("pending", "https://fake.calendar/digest"))
        self._timestamps[bytes(digest)] = node
        return _ots_encode_node(node)

    def get_timestamp(self, digest: bytes) -> bytes:
        if self.fail_get:
            raise OTSAnchorError("simulated calendar outage")
        node = self._timestamps.get(bytes(digest))
        if node is None:
            raise CalendarNotFoundError("unknown commitment")
        return _ots_encode_node(node)

    def upgrade_to_bitcoin(self, digest: bytes, height: int) -> None:
        node = _OTSNode(bytes(digest))
        node.attestations.append(("bitcoin", height))
        self._timestamps[bytes(digest)] = node


def make_ots(url: str = "https://fake.calendar") -> tuple[OpenTimestampsAnchor, FakeCalendar]:
    calendar = FakeCalendar()
    return OpenTimestampsAnchor(calendar, calendar_url=url), calendar


class TestOpenTimestampsAnchor:
    # Byte-identity vectors generated with the reference
    # python-opentimestamps implementation (serialize -> parse -> serialize).
    PENDING_HEX = (
        "004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294"
        "01" "08" + "aa" * 32 +
        "00" "83dfe30d2ef90c8e" "22" "21"
        "68747470733a2f2f612e706f6f6c2e6f70656e74696d657374616d70732e6f7267"
    )
    BITCOIN_HEX = (
        "004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294"
        "01" "08" + "aa" * 32 +
        "00" "0588960d73d71901" "03" "81ea30"
    )
    NESTED_HEX = (
        "004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294"
        "01" "08" + "aa" * 32 +
        "f0" "02" "0102"
        "00" "0588960d73d71901" "03" "81ea30"
    )

    def test_codec_matches_reference_vectors(self):
        # Our codec must be byte-identical with the reference implementation
        # on real .ots shapes: pending, bitcoin, and nested (append op).
        for vector in (self.PENDING_HEX, self.BITCOIN_HEX, self.NESTED_HEX):
            raw = bytes.fromhex(vector)
            digest, node = _ots_decode_file(raw)
            assert digest == bytes.fromhex("aa" * 32)
            assert _ots_encode_file(digest, node) == raw

    def test_codec_reference_vectors_attestations(self):
        digest, node = _ots_decode_file(bytes.fromhex(self.PENDING_HEX))
        assert node.attestations == [
            ("pending", "https://a.pool.opentimestamps.org")
        ]
        _, btc_node = _ots_decode_file(bytes.fromhex(self.BITCOIN_HEX))
        assert btc_node.attestations == [("bitcoin", 800001)]
        _, nested = _ots_decode_file(bytes.fromhex(self.NESTED_HEX))
        assert nested.ops[0][0] == "append"
        assert nested.ops[0][1] == b"\x01\x02"
        assert nested.ops[0][2].attestations == [("bitcoin", 800001)]

    def test_codec_rejects_bad_magic(self):
        with pytest.raises(OTSCodecError):
            _ots_decode_file(b"not-an-ots-file" + b"\x00" * 40)

    def test_codec_rejects_truncated(self):
        raw = bytes.fromhex(self.PENDING_HEX)
        with pytest.raises(OTSCodecError):
            _ots_decode_file(raw[:40])

    def test_codec_rejects_trailing_bytes(self):
        raw = bytes.fromhex(self.PENDING_HEX)
        with pytest.raises(OTSCodecError):
            _ots_decode_file(raw + b"\x00")

    def test_codec_rejects_unknown_op(self):
        # 0xF2 (reverse) is a real OTS op we deliberately do not support:
        # its operand format is known, but we fail closed on anything outside
        # the append/prepend/sha256 subset.
        digest = bytes.fromhex("aa" * 32)
        raw = (
            _OTS_MAGIC + _ots_varuint_encode(1) + b"\x08" + digest
            + b"\xf2" + b"\x00" + _ots_encode_attestation(("pending", "https://x"))
        )
        with pytest.raises(OTSCodecError, match="unsupported OTS op"):
            _ots_decode_file(raw)

    def test_codec_rejects_wrong_crypto_op(self):
        digest = bytes.fromhex("aa" * 32)
        raw = _OTS_MAGIC + _ots_varuint_encode(1) + b"\x02" + digest[:20]
        with pytest.raises(OTSCodecError):
            _ots_decode_file(raw)

    def test_anchor_happy_path(self):
        ots, calendar = make_ots()
        root = "bb" * 32
        proof = ots.anchor(root, NOW)
        assert proof.scheme == "opentimestamps"
        assert proof.emulated is False
        assert proof.root_hash == root
        assert proof.key_id == "https://fake.calendar"
        assert proof.signature == ""
        assert calendar.submitted == [bytes.fromhex(root)]
        # The stored receipt is a well-formed .ots file for this root.
        raw = base64.b64decode(proof.ots_receipt_b64)
        digest, node = _ots_decode_file(raw)
        assert digest == bytes.fromhex(root)
        assert node.attestations == [("pending", "https://fake.calendar/digest")]

    def test_anchor_is_a_timestamp_anchor(self):
        ots, _ = make_ots()
        assert isinstance(ots, TimestampAnchor)

    def test_anchor_rejects_bad_root_hash(self):
        ots, _ = make_ots()
        with pytest.raises(OTSAnchorError):
            ots.anchor("not-hex", NOW)
        with pytest.raises(OTSAnchorError):
            ots.anchor("aa" * 16, NOW)  # 16 bytes, not 32

    def test_anchor_network_failure_raises_no_fake_proof(self):
        ots, calendar = make_ots()
        calendar.fail_submit = True
        with pytest.raises(OTSAnchorError):
            ots.anchor("cc" * 32, NOW)

    def test_anchor_rejects_garbage_calendar_response(self):
        class GarbageCalendar(OTSCalendarClient):
            def submit(self, digest: bytes) -> bytes:
                return b"this is not a timestamp"

            def get_timestamp(self, digest: bytes) -> bytes:
                return b"neither is this"

        ots = OpenTimestampsAnchor(GarbageCalendar(), calendar_url="https://x")
        with pytest.raises(OTSAnchorError, match="malformed"):
            ots.anchor("dd" * 32, NOW)

    def test_upgrade_pending_returns_proof_unchanged(self):
        ots, _ = make_ots()
        proof = ots.anchor("ee" * 32, NOW)
        assert ots.bitcoin_height(proof) is None
        upgraded = ots.upgrade(proof)
        assert upgraded.ots_receipt_b64 == proof.ots_receipt_b64
        assert ots.bitcoin_height(upgraded) is None

    def test_upgrade_to_bitcoin(self):
        ots, calendar = make_ots()
        root = "ff" * 32
        proof = ots.anchor(root, NOW)
        calendar.upgrade_to_bitcoin(bytes.fromhex(root), 800002)
        upgraded = ots.upgrade(proof)
        assert upgraded.ots_receipt_b64 != proof.ots_receipt_b64
        assert ots.bitcoin_height(upgraded) == 800002
        # Original proof object is untouched (upgrade returns a new proof).
        assert ots.bitcoin_height(proof) is None

    def test_upgrade_unknown_commitment_raises(self):
        ots, _ = make_ots()
        proof = ots.anchor("11" * 32, NOW)
        ots2, _ = make_ots()  # fresh calendar that never saw the digest
        with pytest.raises(OTSAnchorError):
            ots2.upgrade(proof)

    def test_verify_anchor_happy_path(self):
        ots, _ = make_ots()
        root = "22" * 32
        proof = ots.anchor(root, NOW)
        checkpoint = {"merkle_root": root, "timestamp": NOW.isoformat()}
        assert ots.verify_anchor(checkpoint, proof) is True

    def test_verify_anchor_after_upgrade(self):
        ots, calendar = make_ots()
        root = "33" * 32
        proof = ots.anchor(root, NOW)
        calendar.upgrade_to_bitcoin(bytes.fromhex(root), 800003)
        upgraded = ots.upgrade(proof)
        checkpoint = {"merkle_root": root, "timestamp": NOW.isoformat()}
        assert ots.verify_anchor(checkpoint, upgraded) is True

    def test_verify_anchor_rejects_tampered_receipt(self):
        ots, _ = make_ots()
        proof = ots.anchor("44" * 32, NOW)
        raw = bytearray(base64.b64decode(proof.ots_receipt_b64))
        raw[40] ^= 0x01  # flip a digest byte
        tampered = proof.model_copy(
            update={"ots_receipt_b64": base64.b64encode(bytes(raw)).decode("ascii")}
        )
        checkpoint = {"merkle_root": "44" * 32, "timestamp": NOW.isoformat()}
        assert ots.verify_anchor(checkpoint, tampered) is False

    def test_verify_anchor_rejects_foreign_receipt(self):
        ots, _ = make_ots()
        proof = ots.anchor("55" * 32, NOW)
        # Receipt is genuine, but for a DIFFERENT checkpoint root.
        checkpoint = {"merkle_root": "66" * 32, "timestamp": NOW.isoformat()}
        assert ots.verify_anchor(checkpoint, proof) is False

    def test_verify_anchor_rejects_emulated_proof(self):
        ots, _ = make_ots()
        emulated = make_anchor().anchor("77" * 32, NOW)
        checkpoint = {"merkle_root": "77" * 32, "timestamp": NOW.isoformat()}
        assert ots.verify_anchor(checkpoint, emulated) is False

    def test_verify_anchor_rejects_timestamp_mismatch(self):
        ots, _ = make_ots()
        proof = ots.anchor("88" * 32, NOW)
        checkpoint = {
            "merkle_root": "88" * 32,
            "timestamp": (NOW + timedelta(hours=1)).isoformat(),
        }
        assert ots.verify_anchor(checkpoint, proof) is False

    def test_verify_anchor_rejects_non_proof(self):
        ots, _ = make_ots()
        checkpoint = {"merkle_root": "99" * 32, "timestamp": NOW.isoformat()}
        assert ots.verify_anchor(checkpoint, "not-a-proof") is False  # type: ignore[arg-type]

    def test_seal_and_verify_checkpoint_with_ots_anchor(self):
        # End-to-end: seal a checkpoint through the OTS anchor, then verify
        # the full checkpoint (events + anchor proof) offline.
        ots, _ = make_ots()
        log = make_log(3)
        signer = make_signer()
        envelope = seal_checkpoint(
            list(log.events_in_range(0, 2)), signer, ots, None, timestamp=NOW
        )
        assert verify_checkpoint_events(envelope, list(log.events_in_range(0, 2))) is True
        assert verify_checkpoint_chain(
            [envelope], trusted(signer), ots
        ) is True

    def test_seal_fails_closed_on_calendar_outage(self):
        ots, calendar = make_ots()
        calendar.fail_submit = True
        log = make_log(2)
        with pytest.raises(OTSAnchorError):
            seal_checkpoint(
                list(log.events_in_range(0, 1)), make_signer(), ots, None
            )

    def test_http_client_rejects_non_http_url(self):
        with pytest.raises(ValueError):
            HttpOTSCalendarClient("ftp://example.com")

    def test_http_client_validates_digest_length(self):
        client = HttpOTSCalendarClient("https://a.pool.opentimestamps.org")
        with pytest.raises(OTSAnchorError):
            client.submit(b"too-short")
        with pytest.raises(OTSAnchorError):
            client.get_timestamp(b"too-short")


# ---------------------------------------------------------------------------
# unit: signer rotation
# ---------------------------------------------------------------------------


def _rotation_chain():
    log = make_log(6)
    old, new = make_signer("old-key"), make_signer("new-key")
    anchor = make_anchor()
    rotation = NextCheckpointSigner(
        key_id=new.key_id, public_key=new.public_key_b64()
    )
    c1 = seal_checkpoint(
        list(log.events_in_range(0, 2)),
        old,
        anchor,
        None,
        next_signer=rotation,
        timestamp=NOW,
    )
    c2 = seal_checkpoint(
        list(log.events_in_range(3, 5)),
        new,
        anchor,
        checkpoint_of(c1).merkle_root,
        timestamp=NOW + timedelta(minutes=3),
    )
    return log, old, new, anchor, [c1, c2], rotation


class TestSignerRotation:
    def test_rotation_takes_effect_after_declaring_checkpoint(self):
        log, old, new, anchor, chain, _ = _rotation_chain()
        assert verify_checkpoint_chain(chain, trusted(old), anchor) is True

    def test_old_key_cannot_sign_after_rotation(self):
        log, old, new, anchor, chain, _ = _rotation_chain()
        c1 = chain[0]
        forged_c2 = seal_checkpoint(
            list(log.events_in_range(3, 5)),
            old,  # old key tries to keep signing after rotation
            anchor,
            checkpoint_of(c1).merkle_root,
            timestamp=NOW + timedelta(minutes=3),
        )
        assert verify_checkpoint_chain([c1, forged_c2], trusted(old), anchor) is False

    def test_new_key_cannot_sign_before_rotation(self):
        log, old, new, anchor, chain, rotation = _rotation_chain()
        # new key signs the FIRST checkpoint (rotation is not retroactive)
        early = seal_checkpoint(
            list(log.events_in_range(0, 2)),
            new,
            anchor,
            None,
            timestamp=NOW,
        )
        assert verify_checkpoint_chain([early], trusted(old), anchor) is False

    def test_chain_class_rotation_flow(self):
        log, old, new, anchor, _, rotation = _rotation_chain()
        cc = CheckpointChain(trusted(old), anchor)
        cc.register_signer(old)
        cc.register_signer(new)
        cc.seal(list(log.events_in_range(0, 2)), next_signer=rotation)
        cc.seal(list(log.events_in_range(3, 5)))
        assert cc.verify() is True


# ---------------------------------------------------------------------------
# ADVERSARIAL ATTACKS — every one must fail closed
# ---------------------------------------------------------------------------


class TestAdversarialAttacks:
    def _base(self):
        log = make_log(9)
        signer, anchor = make_signer(), make_anchor()
        c1 = seal_range(log, 0, 2, signer, anchor, None)
        c2 = seal_range(log, 3, 5, signer, anchor, checkpoint_of(c1).merkle_root)
        c3 = seal_range(log, 6, 8, signer, anchor, checkpoint_of(c2).merkle_root)
        return log, signer, anchor, [c1, c2, c3]

    def test_attack_1_rewritten_event_vs_original_checkpoint(self):
        """Operator rewrites an event, re-serves the ORIGINAL checkpoint: the
        inclusion proof for the tampered event must fail against it."""
        log, signer, anchor, chain = self._base()
        cp = checkpoint_of(chain[1])
        events = list(log.events_in_range(3, 5))
        tampered = events[1].model_copy(
            update={"data": {"i": 4, "detail": "REWRITTEN BY OPERATOR"}}
        )
        honest_proof = prove_event(cp, events, 4)
        assert verify_inclusion(cp, tampered, honest_proof) is False
        # and a full event-set revalidation also fails
        assert (
            verify_checkpoint_events(
                chain[1], [events[0], tampered, events[2]]
            )
            is False
        )

    def test_attack_2_forged_checkpoint_signature(self):
        """Attacker re-signs a checkpoint payload with their own key while
        keeping the legitimate key_id: signature verification must fail."""
        log, signer, anchor, chain = self._base()
        attacker = Ed25519Signer.generate(signer.key_id)  # same key_id, wrong key
        forged = attacker.sign_payload(dict(chain[1].payload))
        assert verify_checkpoint_chain(
            [chain[0], forged, chain[2]], trusted(signer), anchor
        ) is False

    def test_attack_3_skipped_chain_link(self):
        """Operator drops the middle checkpoint: the hash link must break."""
        log, signer, anchor, chain = self._base()
        assert verify_checkpoint_chain([chain[0], chain[2]], trusted(signer), anchor) is False

    def test_attack_4_anchor_proof_swapped_between_checkpoints(self):
        """Anchor proof from checkpoint A transplanted onto checkpoint B's
        payload: root binding must fail."""
        log, signer, anchor, chain = self._base()
        cp_b = checkpoint_of(chain[1]).model_copy(
            update={"anchor_proof": checkpoint_of(chain[0]).anchor_proof}
        )
        swapped = signer.sign_payload(cp_b.model_dump(mode="json"))
        assert verify_checkpoint_chain(
            [chain[0], swapped, chain[2]], trusted(signer), anchor
        ) is False

    def test_attack_5_event_inserted_out_of_order(self):
        """Sequence tampering: events reordered inside the sealed range must
        not verify against the checkpoint."""
        log, signer, anchor, chain = self._base()
        cp = checkpoint_of(chain[1])
        events = list(log.events_in_range(3, 5))
        reordered = [events[1], events[0], events[2]]
        assert verify_checkpoint_events(chain[1], reordered) is False
        # a prover cannot build a path for the reordered set: the rebuilt
        # root no longer matches the checkpoint
        with pytest.raises(CheckpointError):
            prove_event(cp, reordered, 4)
        # control: the honest order still proves and verifies
        honest_proof = prove_event(cp, events, 4)
        assert verify_inclusion(cp, events[1], honest_proof) is True

    def test_attack_6_flipped_direction_bits(self):
        """Inclusion proof with every direction bit flipped must not verify."""
        log, signer, anchor, chain = self._base()
        cp = checkpoint_of(chain[1])
        events = list(log.events_in_range(3, 5))
        proof = prove_event(cp, events, 4)
        flipped = proof.model_copy(
            update={
                "steps": [
                    s.model_copy(update={"sibling_is_left": not s.sibling_is_left})
                    for s in proof.steps
                ]
            }
        )
        assert verify_inclusion(cp, events[1], flipped) is False
        assert verify_inclusion(cp, events[1], proof) is True  # control

    def test_attack_7_rewrite_plus_reseal_without_anchor_key(self):
        """Operator rewrites history AND reseals a fresh checkpoint with the
        checkpoint key — but cannot mint an anchor proof (no anchor key), so
        the resealed chain must fail verification."""
        log, signer, anchor, chain = self._base()
        cp = checkpoint_of(chain[1])
        events = list(log.events_in_range(3, 5))
        tampered = events[1].model_copy(update={"data": {"i": 4, "forged": True}})
        # operator reseals WITHOUT a real anchor: forges a proof-looking blob
        fake_proof = AnchorProof(
            scheme="local-emulated",
            root_hash="00" * 32,
            timestamp=cp.timestamp,
            key_id="anchor-key-1",
            signature=base64.b64encode(b"\x00" * 64).decode("ascii"),
            emulated=True,
        )
        forged_cp = cp.model_copy(update={"anchor_proof": fake_proof})
        forged_env = signer.sign_payload(forged_cp.model_dump(mode="json"))
        assert verify_checkpoint_chain(
            [chain[0], forged_env], trusted(signer), anchor
        ) is False

    def test_attack_8_forged_rotation_declaration(self):
        """Attacker without the checkpoint key declares a rotation to their
        own key: the declaring checkpoint's signature must fail."""
        log, old, new, anchor, chain, rotation = _rotation_chain()
        attacker = Ed25519Signer.generate("attacker-key")
        evil_rotation = NextCheckpointSigner(
            key_id=attacker.key_id, public_key=attacker.public_key_b64()
        )
        evil_c1 = seal_checkpoint(
            list(log.events_in_range(0, 2)),
            old,
            anchor,
            None,
            next_signer=evil_rotation,
            timestamp=NOW,
        )
        # attacker re-signs the declaring checkpoint with THEIR key
        forged_decl = attacker.sign_payload(dict(evil_c1.payload))
        assert verify_checkpoint_chain([forged_decl], trusted(old), anchor) is False

    def test_attack_9_tampered_anchor_timestamp_in_payload(self):
        """Backdating the anchor timestamp inside a signed payload breaks the
        checkpoint signature (anchor proof is covered by the signature)."""
        log, signer, anchor, chain = self._base()
        cp = checkpoint_of(chain[1])
        backdated_proof = cp.anchor_proof.model_copy(
            update={"timestamp": cp.timestamp - timedelta(days=30)}
        )
        backdated = cp.model_copy(update={"anchor_proof": backdated_proof})
        # re-signing with the legit key still fails anchor verification,
        # because the proof no longer matches the checkpoint timestamp
        resealed = signer.sign_payload(backdated.model_dump(mode="json"))
        assert verify_checkpoint_chain(
            [chain[0], resealed, chain[2]], trusted(signer), anchor
        ) is False

    def test_attack_10_sibling_hash_substitution(self):
        """Inclusion proof with one sibling hash replaced by attacker data."""
        log, signer, anchor, chain = self._base()
        cp = checkpoint_of(chain[1])
        events = list(log.events_in_range(3, 5))
        proof = prove_event(cp, events, 4)
        poisoned = proof.model_copy(
            update={
                "steps": [
                    proof.steps[0].model_copy(update={"sibling": "de" * 32})
                ]
                + list(proof.steps[1:])
            }
        )
        assert verify_inclusion(cp, events[1], poisoned) is False
