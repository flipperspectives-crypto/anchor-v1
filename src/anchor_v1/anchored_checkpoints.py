"""ANCHOR v1 — Publicly anchored evidence checkpoints (Wave B, capability 5).

Merkle checkpoints over append-only evidence events, timestamped to a
transparency log (OpenTimestamps-style). Compliance proof that survives a
compromised operator: even if the operator rewrites history, the forgery must
break one of (a) the Merkle root bound to the checkpoint, (b) the
checkpoint-to-checkpoint hash link, or (c) the independent anchor proof — all
re-validated offline by :func:`verify_checkpoint_chain`.

Local only, except for :class:`OpenTimestampsAnchor`, whose network I/O is
isolated behind the :class:`OTSCalendarClient` interface (substitute a fake
for offline tests). :class:`LocalEmulatedAnchor` remains the default for
tests and offline deployments — nothing in this module selects a public
calendar on its own.
"""

from __future__ import annotations

import base64
import hashlib
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

from pydantic import Field, field_validator

from anchor_v1.canonical import canonical_bytes, sha256_hex
from anchor_v1.crypto import Ed25519Signer, verify_envelope
from anchor_v1.models import SignedEnvelope, StrictModel

__all__ = [
    "AnchorProof",
    "Checkpoint",
    "CheckpointChain",
    "CheckpointError",
    "EvidenceEvent",
    "EvidenceLog",
    "HttpOTSCalendarClient",
    "InclusionProof",
    "LocalEmulatedAnchor",
    "NextCheckpointSigner",
    "OTSAnchorError",
    "OTSCalendarClient",
    "OpenTimestampsAnchor",
    "ProofStep",
    "TimestampAnchor",
    "TrustedCheckpointSigner",
    "anchor_leaf",
    "build_merkle_root",
    "event_hash",
    "prove_event",
    "seal_checkpoint",
    "verify_checkpoint_chain",
    "verify_checkpoint_events",
    "verify_inclusion",
]

_SCHEME_LOCAL_EMULATED = "local-emulated"
_SCHEME_OPENTIMESTAMPS = "opentimestamps"


class CheckpointError(ValueError):
    """Raised when a checkpoint fails build-time admission. Fail closed."""


def _require_aware_utc(value: datetime, field_name: str) -> datetime:
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value.astimezone(timezone.utc)


def _require_pubkey_b64(value: str, field_name: str) -> str:
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ValueError(f"{field_name} must be valid base64") from exc
    if len(raw) != 32:
        raise ValueError(f"{field_name} must decode to 32 bytes (raw Ed25519)")
    return value


# ---------------------------------------------------------------------------
# Evidence events: append-only, hash-chained
# ---------------------------------------------------------------------------


class EvidenceEvent(StrictModel):
    """One evidence event. ``previous_hash`` links it into the ledger's hash
    chain (None only for the ledger's first event)."""

    sequence: int = Field(ge=0)
    event_type: str = Field(min_length=1)
    data: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    previous_hash: str | None = Field(default=None)

    @field_validator("timestamp")
    @classmethod
    def _tz_aware(cls, v: datetime) -> datetime:
        return _require_aware_utc(v, "timestamp")


def event_hash(event: EvidenceEvent) -> str:
    """Canonical hash of an event. Binds sequence, type, data, timestamp AND the
    previous_hash link, so any rewrite or reorder changes the leaf hash."""
    return sha256_hex(event.model_dump(mode="json"))


class EvidenceLog:
    """Append-only evidence ledger. Each appended event carries the previous
    event's hash, forming a tamper-evident chain (v0-ledger style)."""

    def __init__(self) -> None:
        self._events: list[EvidenceEvent] = []

    def __len__(self) -> int:
        return len(self._events)

    @property
    def events(self) -> tuple[EvidenceEvent, ...]:
        return tuple(self._events)

    def append(
        self,
        event_type: str,
        data: dict[str, Any] | None = None,
        timestamp: datetime | None = None,
    ) -> EvidenceEvent:
        """Append an event. Sequence is assigned (never caller-supplied); the
        hash link is set from the previous event. Returns the stored event."""
        previous_hash = event_hash(self._events[-1]) if self._events else None
        event = EvidenceEvent(
            sequence=len(self._events),
            event_type=event_type,
            data=dict(data or {}),
            timestamp=timestamp or datetime.now(timezone.utc),
            previous_hash=previous_hash,
        )
        self._events.append(event)
        return event

    def events_in_range(self, start_seq: int, end_seq: int) -> list[EvidenceEvent]:
        """The contiguous slice [start_seq, end_seq]. Raises CheckpointError on
        gaps, out-of-order sequences, or out-of-bounds ranges."""
        if start_seq < 0 or end_seq < start_seq:
            raise CheckpointError(f"invalid checkpoint range [{start_seq}, {end_seq}]")
        if end_seq >= len(self._events):
            raise CheckpointError(
                f"range end {end_seq} beyond ledger length {len(self._events)}"
            )
        window = self._events[start_seq : end_seq + 1]
        for expected, event in enumerate(window, start=start_seq):
            if event.sequence != expected:
                raise CheckpointError(
                    f"sequence tampering: position expects {expected}, "
                    f"event carries {event.sequence}"
                )
        return list(window)

    def verify_hash_chain(self) -> bool:
        """Re-validate every previous_hash link from genesis. Fail closed."""
        try:
            for i, event in enumerate(self._events):
                expected = event_hash(self._events[i - 1]) if i else None
                if event.sequence != i or event.previous_hash != expected:
                    return False
            return True
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Merkle tree over canonical event hashes
# ---------------------------------------------------------------------------


def _parent_hash(left: str, right: str) -> str:
    return sha256_hex({"left": left, "right": right})


def build_merkle_root(leaf_hashes: list[str]) -> str:
    """Binary Merkle root. Odd levels duplicate the last node (Bitcoin-style);
    a single leaf's root is the leaf hash itself. Empty input is rejected."""
    if not leaf_hashes:
        raise CheckpointError("cannot build a Merkle tree over zero leaves")
    level = list(leaf_hashes)
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [
            _parent_hash(level[i], level[i + 1]) for i in range(0, len(level), 2)
        ]
    return level[0]


class ProofStep(StrictModel):
    """One step of a Merkle inclusion path: the sibling hash plus a direction
    bit. Minimal: no redundant data."""

    sibling: str = Field(min_length=1)
    sibling_is_left: bool = Field(description="True iff the sibling is the left child")


class InclusionProof(StrictModel):
    """Minimal Merkle inclusion proof for one leaf."""

    leaf_hash: str = Field(min_length=1)
    leaf_index: int = Field(ge=0)
    total_leaves: int = Field(ge=1)
    steps: list[ProofStep] = Field(default_factory=list)

    @field_validator("leaf_index")
    @classmethod
    def _index_in_range(cls, v: int, info) -> int:  # type: ignore[no-untyped-def]
        total = (info.data or {}).get("total_leaves")
        if total is not None and v >= total:
            raise ValueError("leaf_index out of range for total_leaves")
        return v


def _prove(leaf_hashes: list[str], leaf_index: int) -> list[ProofStep]:
    """Walk from the leaf to the root collecting sibling hashes."""
    steps: list[ProofStep] = []
    level = list(leaf_hashes)
    index = leaf_index
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        if index % 2 == 0:
            steps.append(ProofStep(sibling=level[index + 1], sibling_is_left=False))
        else:
            steps.append(ProofStep(sibling=level[index - 1], sibling_is_left=True))
        level = [
            _parent_hash(level[i], level[i + 1]) for i in range(0, len(level), 2)
        ]
        index //= 2
    return steps


def prove_event(
    checkpoint: "Checkpoint",
    events: list[EvidenceEvent],
    sequence: int,
) -> InclusionProof:
    """Build the Merkle inclusion path proving ``sequence`` is committed by
    ``checkpoint``. Rebuilds the tree from ``events`` and refuses if the
    rebuilt root does not match the checkpoint — the prover cannot fake a
    path for a checkpoint the events do not support."""
    leaves = [event_hash(e) for e in events]
    if checkpoint.event_count != len(leaves):
        raise CheckpointError("event count does not match checkpoint")
    if build_merkle_root(leaves) != checkpoint.merkle_root:
        raise CheckpointError("events do not rebuild this checkpoint's Merkle root")
    index = sequence - checkpoint.start_seq
    if not 0 <= index < len(leaves):
        raise CheckpointError(f"sequence {sequence} outside checkpoint range")
    return InclusionProof(
        leaf_hash=leaves[index],
        leaf_index=index,
        total_leaves=len(leaves),
        steps=_prove(leaves, index),
    )


def verify_inclusion(
    checkpoint: "Checkpoint", event: EvidenceEvent, proof: InclusionProof
) -> bool:
    """Fully offline inclusion check: recompute the leaf hash from the event,
    fold the sibling path, compare against the checkpoint's Merkle root."""
    try:
        leaf = event_hash(event)
        if leaf != proof.leaf_hash:
            return False
        if proof.total_leaves != checkpoint.event_count:
            return False
        node = leaf
        for step in proof.steps:
            node = (
                _parent_hash(step.sibling, node)
                if step.sibling_is_left
                else _parent_hash(node, step.sibling)
            )
        return node == checkpoint.merkle_root
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Checkpoint payload + signer rotation
# ---------------------------------------------------------------------------


class TrustedCheckpointSigner(StrictModel):
    """Bootstrap trust: the key id + raw public key that may sign checkpoints."""

    key_id: str = Field(min_length=1)
    public_key: str = Field(description="base64 of the 32-byte raw Ed25519 public key")

    @field_validator("public_key")
    @classmethod
    def _valid_pubkey(cls, v: str) -> str:
        return _require_pubkey_b64(v, "public_key")


class NextCheckpointSigner(StrictModel):
    """Key-rotation declaration carried inside a checkpoint. Takes effect for
    checkpoints AFTER the declaring one — never retroactively."""

    key_id: str = Field(min_length=1)
    public_key: str = Field(description="base64 of the 32-byte raw Ed25519 public key")

    @field_validator("public_key")
    @classmethod
    def _valid_pubkey(cls, v: str) -> str:
        return _require_pubkey_b64(v, "public_key")


class AnchorProof(StrictModel):
    """Timestamp proof binding a Merkle root to a point in time."""

    scheme: str = Field(description="'local-emulated' or 'opentimestamps'")
    root_hash: str = Field(min_length=1)
    timestamp: datetime
    key_id: str = Field(
        min_length=1, description="key id of the anchor (timestamping) key"
    )
    signature: str = Field(description="base64 Ed25519 signature over the proof body")
    emulated: bool = Field(
        default=False,
        description="True ONLY for LocalEmulatedAnchor proofs; "
        "a real transparency-log proof must carry emulated=False",
    )
    ots_receipt_b64: str | None = Field(
        default=None,
        description="base64 OpenTimestamps receipt (.ots) once upgraded to a "
        "Bitcoin attestation; None for emulated proofs",
    )

    @field_validator("timestamp")
    @classmethod
    def _tz_aware(cls, v: datetime) -> datetime:
        return _require_aware_utc(v, "timestamp")


class Checkpoint(StrictModel):
    """One sealed evidence checkpoint over the contiguous event range
    [start_seq, end_seq]. The anchor proof is sealed BEFORE signing, so the
    checkpoint signature covers the Merkle root, the chain link, the anchor
    proof, and any rotation declaration together."""

    checkpoint_id: str = Field(min_length=1)
    start_seq: int = Field(ge=0)
    end_seq: int = Field(ge=0)
    event_count: int = Field(ge=1)
    merkle_root: str = Field(min_length=1)
    previous_checkpoint_root: str | None = Field(
        default=None, description="merkle_root of the previous checkpoint; None only for genesis"
    )
    timestamp: datetime
    anchor_proof: AnchorProof
    next_signer: NextCheckpointSigner | None = Field(
        default=None,
        description="rotation declaration; takes effect for later checkpoints only",
    )

    @field_validator("timestamp")
    @classmethod
    def _tz_aware(cls, v: datetime) -> datetime:
        return _require_aware_utc(v, "timestamp")

    @field_validator("end_seq")
    @classmethod
    def _range_valid(cls, v: int, info) -> int:  # type: ignore[no-untyped-def]
        start = (info.data or {}).get("start_seq")
        if start is not None and v < start:
            raise ValueError("end_seq must be >= start_seq")
        return v

    @field_validator("event_count")
    @classmethod
    def _count_matches(cls, v: int, info) -> int:  # type: ignore[no-untyped-def]
        data = info.data or {}
        start, end = data.get("start_seq"), data.get("end_seq")
        if start is not None and end is not None and v != end - start + 1:
            raise ValueError("event_count must equal end_seq - start_seq + 1")
        return v


def checkpoint_payload_dict(checkpoint: Checkpoint) -> dict[str, Any]:
    """The exact dict that checkpoint signatures cover."""
    return checkpoint.model_dump(mode="json")


# ---------------------------------------------------------------------------
# Timestamp anchors
# ---------------------------------------------------------------------------


class TimestampAnchor(ABC):
    """Pluggable timestamping interface. Implementations bind a Merkle root to
    a timestamp with a key the checkpoint operator does NOT control — that
    separation is what makes the anchor survive a compromised operator."""

    @abstractmethod
    def anchor(self, root_hash: str, timestamp: datetime) -> AnchorProof:
        """Timestamp ``root_hash`` at ``timestamp``. Returns the anchor proof."""
        raise NotImplementedError

    @abstractmethod
    def verify_anchor(self, checkpoint: dict[str, Any], proof: AnchorProof) -> bool:
        """True iff ``proof`` is a genuine anchor of this checkpoint's root at
        this checkpoint's timestamp. Fail closed: any doubt -> False."""
        raise NotImplementedError


def anchor_leaf(scheme: str, root_hash: str, timestamp: datetime) -> bytes:
    """Canonical bytes the anchor key signs: binds scheme, root, and time."""
    return canonical_bytes(
        {"scheme": scheme, "root_hash": root_hash, "timestamp": timestamp.isoformat()}
    )


class LocalEmulatedAnchor(TimestampAnchor):
    """EMULATED transparency log for tests and offline deployments.

    Keeps a local append-only log of anchor proofs, each signed by a DEDICATED
    anchor key (never the checkpoint-signing key). Verification checks the
    signature, the root/timestamp binding, AND membership in the append-only
    log — so an operator who holds the checkpoint key still cannot fabricate
    an anchor proof for rewritten history.

    This is explicitly NOT a public transparency log: proofs carry
    ``emulated=True`` and ``scheme="local-emulated"`` so they can never be
    mistaken for real OpenTimestamps attestations.
    """

    EMULATED = True

    def __init__(self, anchor_signer: Ed25519Signer):
        self._signer = anchor_signer
        self._log: list[AnchorProof] = []

    @property
    def log(self) -> tuple[AnchorProof, ...]:
        """The append-only anchor log (read-only view)."""
        return tuple(self._log)

    def anchor(self, root_hash: str, timestamp: datetime) -> AnchorProof:
        timestamp = _require_aware_utc(timestamp, "timestamp")
        body = anchor_leaf(_SCHEME_LOCAL_EMULATED, root_hash, timestamp)
        signature = self._signer._private_key.sign(body)
        proof = AnchorProof(
            scheme=_SCHEME_LOCAL_EMULATED,
            root_hash=root_hash,
            timestamp=timestamp,
            key_id=self._signer.key_id,
            signature=base64.b64encode(signature).decode("ascii"),
            emulated=True,
        )
        self._log.append(proof)
        return proof

    def verify_anchor(self, checkpoint: dict[str, Any], proof: AnchorProof) -> bool:
        try:
            if proof.scheme != _SCHEME_LOCAL_EMULATED or not proof.emulated:
                return False
            if proof.key_id != self._signer.key_id:
                return False
            if proof.root_hash != checkpoint.get("merkle_root"):
                return False
            cp_ts = checkpoint.get("timestamp")
            # Normalize both sides to datetimes: the payload carries the
            # pydantic JSON form ("...Z") while the proof carries a datetime.
            if isinstance(cp_ts, str):
                cp_ts = datetime.fromisoformat(cp_ts)
            if not isinstance(cp_ts, datetime) or cp_ts != proof.timestamp:
                return False
            key = self._signer._private_key.public_key()
            key.verify(
                base64.b64decode(proof.signature),
                anchor_leaf(proof.scheme, proof.root_hash, proof.timestamp),
            )
            # Membership in the append-only log: the anchor never "issued" a
            # proof that is not in its log. A signature-valid proof minted
            # outside this log (e.g. by a second instance sharing the key)
            # does not verify here.
            return any(
                entry.signature == proof.signature and entry.root_hash == proof.root_hash
                for entry in self._log
            )
        except Exception:
            return False


class OTSAnchorError(ValueError):
    """Fail-closed error for OpenTimestamps anchoring.

    Raised (never a soft allow / fake proof) when the calendar is
    unreachable, returns garbage, or a receipt fails verification.
    """


class OTSCodecError(OTSAnchorError):
    """Malformed OpenTimestamps bytes — not parseable, fail closed."""


class CalendarNotFoundError(OTSAnchorError):
    """The calendar has no timestamp for this commitment (HTTP 404)."""


# ---------------------------------------------------------------------------
# OpenTimestamps wire codec (minimal, byte-compatible subset)
#
# Byte-compatible with the reference python-opentimestamps implementation
# (magic, varuint, Timestamp node framing with 0xFF separators, pending and
# bitcoin attestations). Supports the linear aggregation chains real
# calendars return: append / prepend / sha256 ops and pending + bitcoin
# attestations. Unknown op tags are rejected (fail closed) — their operand
# format cannot be determined safely.
# ---------------------------------------------------------------------------

_OTS_MAGIC = bytes.fromhex(
    "004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294"
)
_OTS_VERSION = 1
_OTS_TAG_SHA256_CRYPTO = 0x08
_OTS_SEP = 0xFF
_OTS_ATTESTATION_TAG = 0x00
_OTS_OP_APPEND = 0xF0
_OTS_OP_PREPEND = 0xF1
_OTS_OP_SHA256 = 0xF7
_OTS_ATTESTATION_PENDING = bytes.fromhex("83dfe30d2ef90c8e")
_OTS_ATTESTATION_BITCOIN = bytes.fromhex("0588960d73d71901")
_OTS_MAX_MSG = 4 * 1024 * 1024
_OTS_MAX_NESTING = 64


def _ots_varuint_encode(n: int) -> bytes:
    if n < 0:
        raise OTSCodecError("negative varuint")
    out = bytearray()
    while True:
        bits = n & 0x7F
        n >>= 7
        if n:
            out.append(bits | 0x80)
        else:
            out.append(bits)
            return bytes(out)


def _ots_varuint_decode(data: bytes, pos: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while True:
        if pos >= len(data):
            raise OTSCodecError("truncated varuint")
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7
        if shift > 63:
            raise OTSCodecError("varuint overflow")


def _ots_varbytes_encode(raw: bytes) -> bytes:
    return _ots_varuint_encode(len(raw)) + raw


def _ots_varbytes_decode(data: bytes, pos: int) -> tuple[bytes, int]:
    length, pos = _ots_varuint_decode(data, pos)
    if length > len(data) - pos:
        raise OTSCodecError("truncated varbytes")
    return data[pos : pos + length], pos + length


class _OTSNode:
    """One Timestamp node: attestations plus (op -> child) edges."""

    __slots__ = ("msg", "attestations", "ops")

    def __init__(self, msg: bytes):
        self.msg = msg
        # attestations: ("pending", uri) | ("bitcoin", height) | ("unknown", tag, payload)
        self.attestations: list[tuple] = []
        # ops: (kind, operand, child) with kind in {"append", "prepend", "sha256"}
        self.ops: list[tuple[str, bytes | None, "_OTSNode"]] = []


def _ots_attestation_sort_key(att: tuple) -> bytes:
    if att[0] == "pending":
        return _OTS_ATTESTATION_PENDING
    if att[0] == "bitcoin":
        return _OTS_ATTESTATION_BITCOIN
    return att[1]


def _ots_encode_attestation(att: tuple) -> bytes:
    if att[0] == "pending":
        inner = _ots_varbytes_encode(att[1].encode("utf-8"))
        return _OTS_ATTESTATION_PENDING + _ots_varbytes_encode(inner)
    if att[0] == "bitcoin":
        inner = _ots_varuint_encode(att[1])
        return _OTS_ATTESTATION_BITCOIN + _ots_varbytes_encode(inner)
    return att[1] + _ots_varbytes_encode(att[2])


def _ots_decode_attestation(data: bytes, pos: int) -> tuple[tuple, int]:
    if pos + 8 > len(data):
        raise OTSCodecError("truncated attestation tag")
    tag = data[pos : pos + 8]
    pos += 8
    payload, pos = _ots_varbytes_decode(data, pos)
    if tag == _OTS_ATTESTATION_PENDING:
        uri_bytes, end = _ots_varbytes_decode(payload, 0)
        if end != len(payload):
            raise OTSCodecError("trailing bytes in pending attestation")
        try:
            uri = uri_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise OTSCodecError(f"pending attestation URI is not UTF-8: {exc}") from exc
        return ("pending", uri), pos
    if tag == _OTS_ATTESTATION_BITCOIN:
        height, end = _ots_varuint_decode(payload, 0)
        if end != len(payload):
            raise OTSCodecError("trailing bytes in bitcoin attestation")
        return ("bitcoin", height), pos
    return ("unknown", tag, payload), pos


_OP_TAG = {"append": _OTS_OP_APPEND, "prepend": _OTS_OP_PREPEND, "sha256": _OTS_OP_SHA256}


def _ots_encode_op(kind: str, operand: bytes | None) -> bytes:
    if kind == "append":
        assert operand is not None
        return bytes([_OTS_OP_APPEND]) + _ots_varbytes_encode(operand)
    if kind == "prepend":
        assert operand is not None
        return bytes([_OTS_OP_PREPEND]) + _ots_varbytes_encode(operand)
    if kind == "sha256":
        return bytes([_OTS_OP_SHA256])
    raise OTSCodecError(f"unsupported OTS op: {kind!r}")


def _ots_apply_op(kind: str, operand: bytes | None, msg: bytes) -> bytes:
    if len(msg) > _OTS_MAX_MSG:
        raise OTSCodecError("OTS message exceeds size limit")
    if kind == "append":
        assert operand is not None
        return msg + operand
    if kind == "prepend":
        assert operand is not None
        return operand + msg
    if kind == "sha256":
        return hashlib.sha256(msg).digest()
    raise OTSCodecError(f"unsupported OTS op: {kind!r}")


def _ots_encode_node(node: _OTSNode) -> bytes:
    if not node.attestations and not node.ops:
        raise OTSCodecError("cannot encode an empty OTS timestamp node")
    out = bytearray()
    attestations = sorted(node.attestations, key=_ots_attestation_sort_key)
    ops = sorted(node.ops, key=lambda item: (_OP_TAG[item[0]], item[1] or b""))
    for att in attestations[:-1]:
        out += bytes([_OTS_SEP, _OTS_ATTESTATION_TAG])
        out += _ots_encode_attestation(att)
    if not ops:
        out += bytes([_OTS_ATTESTATION_TAG])
        out += _ots_encode_attestation(attestations[-1])
    else:
        if attestations:
            out += bytes([_OTS_SEP, _OTS_ATTESTATION_TAG])
            out += _ots_encode_attestation(attestations[-1])
        for kind, operand, child in ops[:-1]:
            out += bytes([_OTS_SEP])
            out += _ots_encode_op(kind, operand)
            out += _ots_encode_node(child)
        kind, operand, child = ops[-1]
        out += _ots_encode_op(kind, operand)
        out += _ots_encode_node(child)
    return bytes(out)


def _ots_decode_node(
    data: bytes, pos: int, msg: bytes, depth: int = 0
) -> tuple[_OTSNode, int]:
    if depth > _OTS_MAX_NESTING:
        raise OTSCodecError("OTS timestamp nesting too deep")
    node = _OTSNode(msg)

    def do_tag(tag: int, pos: int) -> int:
        if tag == _OTS_ATTESTATION_TAG:
            att, pos = _ots_decode_attestation(data, pos)
            node.attestations.append(att)
            return pos
        if tag == _OTS_OP_APPEND:
            operand, pos = _ots_varbytes_decode(data, pos)
            kind: str = "append"
        elif tag == _OTS_OP_PREPEND:
            operand, pos = _ots_varbytes_decode(data, pos)
            kind = "prepend"
        elif tag == _OTS_OP_SHA256:
            operand, kind = None, "sha256"
        else:
            raise OTSCodecError(f"unsupported OTS op tag 0x{tag:02x} — fail closed")
        child_msg = _ots_apply_op(kind, operand, msg)
        child, pos = _ots_decode_node(data, pos, child_msg, depth + 1)
        node.ops.append((kind, operand, child))
        return pos

    if pos >= len(data):
        raise OTSCodecError("truncated OTS timestamp node")
    tag = data[pos]
    pos += 1
    while tag == _OTS_SEP:
        if pos >= len(data):
            raise OTSCodecError("truncated OTS timestamp node after separator")
        tag = data[pos]
        pos += 1
        pos = do_tag(tag, pos)
        if pos >= len(data):
            raise OTSCodecError("truncated OTS timestamp node")
        tag = data[pos]
        pos += 1
    pos = do_tag(tag, pos)
    if not node.attestations and not node.ops:
        raise OTSCodecError("empty OTS timestamp node")
    return node, pos


def _ots_encode_file(digest: bytes, node: _OTSNode) -> bytes:
    if len(digest) != 32:
        raise OTSCodecError("OTS file digest must be 32 bytes (SHA-256)")
    return (
        _OTS_MAGIC
        + _ots_varuint_encode(_OTS_VERSION)
        + bytes([_OTS_TAG_SHA256_CRYPTO])
        + digest
        + _ots_encode_node(node)
    )


def _ots_decode_file(data: bytes) -> tuple[bytes, _OTSNode]:
    if not data.startswith(_OTS_MAGIC):
        raise OTSCodecError("bad OpenTimestamps magic")
    pos = len(_OTS_MAGIC)
    version, pos = _ots_varuint_decode(data, pos)
    if version != _OTS_VERSION:
        raise OTSCodecError(f"unsupported OTS version {version}")
    if pos >= len(data) or data[pos] != _OTS_TAG_SHA256_CRYPTO:
        raise OTSCodecError("OTS file must use the SHA-256 crypto op")
    pos += 1
    if pos + 32 > len(data):
        raise OTSCodecError("truncated OTS file digest")
    digest = data[pos : pos + 32]
    pos += 32
    node, pos = _ots_decode_node(data, pos, digest)
    if pos != len(data):
        raise OTSCodecError("trailing bytes after OTS timestamp")
    return digest, node


def _ots_walk_attestations(node: _OTSNode) -> list[tuple]:
    found = list(node.attestations)
    for _, _, child in node.ops:
        found.extend(_ots_walk_attestations(child))
    return found


# ---------------------------------------------------------------------------
# Calendar network boundary — the ONLY place network I/O happens.
# ---------------------------------------------------------------------------


class OTSCalendarClient(ABC):
    """Network boundary for OpenTimestamps calendar servers.

    ALL network I/O for OTS anchoring goes through this interface, so tests
    (and offline deployments) can substitute a fake. Implementations must
    raise :class:`OTSAnchorError` (or a subclass) on any failure — never
    return a fabricated timestamp.
    """

    @abstractmethod
    def submit(self, digest: bytes) -> bytes:
        """POST ``digest`` (32 bytes) to the calendar's ``/digest`` endpoint.

        Returns the serialized pending Timestamp bytes. Raises
        :class:`OTSAnchorError` on any failure.
        """
        raise NotImplementedError

    @abstractmethod
    def get_timestamp(self, digest: bytes) -> bytes:
        """GET the timestamp for ``digest`` from ``/timestamp/{hex}``.

        Returns serialized Timestamp bytes (possibly upgraded with a
        Bitcoin attestation). Raises :class:`CalendarNotFoundError` if the
        calendar has no such commitment, :class:`OTSAnchorError` otherwise.
        """
        raise NotImplementedError


class HttpOTSCalendarClient(OTSCalendarClient):
    """Real calendar client over HTTPS (urllib, stdlib only)."""

    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = 30.0,
        user_agent: str = "anchor-v1-opentimestamps",
        max_response_bytes: int = 1_000_000,
    ):
        if not base_url.startswith(("https://", "http://")):
            raise ValueError("calendar base_url must be http(s)")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes
        self._headers = {
            "Accept": "application/vnd.opentimestamps.v1",
            "User-Agent": user_agent,
        }

    def _post(self, path: str, body: bytes) -> bytes:
        import urllib.error
        import urllib.request

        url = self.base_url + path
        request = urllib.request.Request(url, data=body, headers=self._headers)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                if response.status != 200:
                    raise OTSAnchorError(
                        f"calendar {url} returned HTTP {response.status}"
                    )
                raw = response.read(self.max_response_bytes + 1)
        except OTSAnchorError:
            raise
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise CalendarNotFoundError(
                    f"calendar has no timestamp for this commitment ({url})"
                ) from exc
            raise OTSAnchorError(
                f"calendar request failed: HTTP {exc.code} ({url})"
            ) from exc
        except Exception as exc:
            raise OTSAnchorError(f"calendar request failed ({url}): {exc}") from exc
        if len(raw) > self.max_response_bytes:
            raise OTSAnchorError("calendar response exceeded size limit")
        return raw

    def _get(self, path: str) -> bytes:
        import urllib.error
        import urllib.request

        url = self.base_url + path
        request = urllib.request.Request(url, headers=self._headers)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                if response.status != 200:
                    raise OTSAnchorError(
                        f"calendar {url} returned HTTP {response.status}"
                    )
                raw = response.read(self.max_response_bytes + 1)
        except OTSAnchorError:
            raise
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise CalendarNotFoundError(
                    f"calendar has no timestamp for this commitment ({url})"
                ) from exc
            raise OTSAnchorError(
                f"calendar request failed: HTTP {exc.code} ({url})"
            ) from exc
        except Exception as exc:
            raise OTSAnchorError(f"calendar request failed ({url}): {exc}") from exc
        if len(raw) > self.max_response_bytes:
            raise OTSAnchorError("calendar response exceeded size limit")
        return raw

    def submit(self, digest: bytes) -> bytes:
        if len(digest) != 32:
            raise OTSAnchorError("submit digest must be 32 bytes")
        return self._post("/digest", digest)

    def get_timestamp(self, digest: bytes) -> bytes:
        if len(digest) != 32:
            raise OTSAnchorError("get_timestamp digest must be 32 bytes")
        return self._get("/timestamp/" + digest.hex())


class OpenTimestampsAnchor(TimestampAnchor):
    """Real OpenTimestamps anchoring against public calendar servers.

    ``anchor()`` submits the Merkle root digest to the calendar (network
    call through the injected :class:`OTSCalendarClient`) and stores the
    returned pending timestamp as a detached ``.ots`` file in
    ``AnchorProof.ots_receipt_b64``. ``upgrade()`` polls the calendar until
    a Bitcoin block attestation appears and replaces the receipt with the
    upgraded bytes. ``verify_anchor()`` replays the timestamp ops locally
    and checks the receipt commits to the checkpoint's Merkle root —
    fully offline, no network.

    Proof semantics: ``AnchorProof.key_id`` is the calendar URL (the
    attesting party); ``signature`` is empty because OTS proofs are
    self-verifying — the receipt bytes ARE the proof, there is no Ed25519
    signature. ``emulated`` is always False so these proofs can never be
    confused with :class:`LocalEmulatedAnchor` proofs.

    Trust note: a *pending* receipt proves submission to the calendar, not
    public anchoring — only a receipt carrying a Bitcoin attestation
    (see :meth:`bitcoin_height`) survives a compromised operator. Batch
    many checkpoints per timestamp (one Bitcoin attestation covers the
    batch) and keep a :class:`LocalEmulatedAnchor` pre-anchor for
    immediacy between batches.
    """

    def __init__(self, calendar: OTSCalendarClient, *, calendar_url: str):
        if not isinstance(calendar, OTSCalendarClient):
            raise TypeError("calendar must be an OTSCalendarClient")
        if not calendar_url:
            raise ValueError("calendar_url is required")
        self._calendar = calendar
        self._calendar_url = calendar_url

    @property
    def calendar_url(self) -> str:
        return self._calendar_url

    @staticmethod
    def _digest_for(root_hash: str) -> bytes:
        try:
            digest = bytes.fromhex(root_hash)
        except ValueError as exc:
            raise OTSAnchorError(f"root_hash is not hex: {exc}") from exc
        if len(digest) != 32:
            raise OTSAnchorError("root_hash must be 32 bytes (64 hex chars)")
        return digest

    def _parse_timestamp(self, raw: bytes, digest: bytes) -> _OTSNode:
        try:
            node, pos = _ots_decode_node(raw, 0, digest)
        except OTSCodecError as exc:
            raise OTSAnchorError(f"calendar returned malformed timestamp: {exc}") from exc
        if pos != len(raw):
            raise OTSAnchorError("calendar returned timestamp with trailing bytes")
        if not _ots_walk_attestations(node):
            raise OTSAnchorError("calendar returned a timestamp with no attestations")
        return node

    def anchor(self, root_hash: str, timestamp: datetime) -> AnchorProof:
        timestamp = _require_aware_utc(timestamp, "timestamp")
        digest = self._digest_for(root_hash)
        raw = self._calendar.submit(digest)
        node = self._parse_timestamp(raw, digest)
        receipt = _ots_encode_file(digest, node)
        return AnchorProof(
            scheme=_SCHEME_OPENTIMESTAMPS,
            root_hash=root_hash,
            timestamp=timestamp,
            key_id=self._calendar_url,
            signature="",
            emulated=False,
            ots_receipt_b64=base64.b64encode(receipt).decode("ascii"),
        )

    def upgrade(self, proof: AnchorProof) -> AnchorProof:
        """Poll the calendar for a Bitcoin attestation.

        Returns a NEW proof with the upgraded ``.ots`` receipt when the
        calendar has one; returns ``proof`` unchanged while the timestamp
        is still pending. Raises :class:`OTSAnchorError` if the calendar
        does not know this commitment or returns garbage.
        """
        if proof.scheme != _SCHEME_OPENTIMESTAMPS or proof.emulated:
            raise OTSAnchorError("upgrade() requires an opentimestamps proof")
        digest = self._digest_for(proof.root_hash)
        raw = self._calendar.get_timestamp(digest)
        node = self._parse_timestamp(raw, digest)
        if not any(att[0] == "bitcoin" for att in _ots_walk_attestations(node)):
            return proof
        receipt = _ots_encode_file(digest, node)
        return proof.model_copy(
            update={"ots_receipt_b64": base64.b64encode(receipt).decode("ascii")}
        )

    def bitcoin_height(self, proof: AnchorProof) -> int | None:
        """Highest Bitcoin block height attested in this proof, or None.

        None means the receipt is still pending (submitted, not yet
        publicly anchored) or malformed.
        """
        if (
            proof.scheme != _SCHEME_OPENTIMESTAMPS
            or proof.emulated
            or not proof.ots_receipt_b64
        ):
            return None
        try:
            raw = base64.b64decode(proof.ots_receipt_b64, validate=True)
            digest, node = _ots_decode_file(raw)
        except (OTSCodecError, ValueError):
            return None
        heights = [
            att[1] for att in _ots_walk_attestations(node) if att[0] == "bitcoin"
        ]
        _ = digest
        return max(heights) if heights else None

    def verify_anchor(self, checkpoint: dict[str, Any], proof: AnchorProof) -> bool:
        """True iff ``proof`` is a genuine OTS anchor of this checkpoint.

        Checks, fail-closed: the proof is a non-emulated opentimestamps
        proof carrying a receipt; the receipt is a well-formed ``.ots``
        file whose digest equals the checkpoint's Merkle root; every
        timestamp op replays consistently; the proof timestamp matches the
        checkpoint timestamp. Fully offline — no network.

        A pending (not-yet-Bitcoin-anchored) receipt verifies as True: it
        is genuine evidence of calendar submission. Relying parties that
        need operator-compromise resistance must additionally require
        :meth:`bitcoin_height` to be non-None.
        """
        try:
            if not isinstance(proof, AnchorProof):
                return False
            if proof.scheme != _SCHEME_OPENTIMESTAMPS or proof.emulated:
                return False
            if not proof.ots_receipt_b64:
                return False
            if proof.root_hash != checkpoint.get("merkle_root"):
                return False
            cp_ts = checkpoint.get("timestamp")
            if isinstance(cp_ts, str):
                cp_ts = datetime.fromisoformat(cp_ts)
            if not isinstance(cp_ts, datetime) or cp_ts != proof.timestamp:
                return False
            raw = base64.b64decode(proof.ots_receipt_b64, validate=True)
            digest, _node = _ots_decode_file(raw)
            # The .ots digest must equal the checkpoint's Merkle root —
            # this is what binds the receipt to THIS checkpoint.
            if digest != self._digest_for(proof.root_hash):
                return False
            return True
        except (OTSCodecError, OTSAnchorError, ValueError):
            return False


# ---------------------------------------------------------------------------
# Sealing
# ---------------------------------------------------------------------------


def _checkpoint_id(start_seq: int, end_seq: int, merkle_root: str) -> str:
    return "ckpt-" + sha256_hex(
        {"start_seq": start_seq, "end_seq": end_seq, "merkle_root": merkle_root}
    )[:32]


def seal_checkpoint(
    events: list[EvidenceEvent],
    signer: Ed25519Signer,
    anchor: TimestampAnchor,
    previous_checkpoint_root: str | None,
    next_signer: NextCheckpointSigner | None = None,
    timestamp: datetime | None = None,
) -> SignedEnvelope:
    """Seal a checkpoint over a contiguous ``events`` slice and sign it.

    Steps (order matters): validate contiguity + ledger hash chain -> build
    Merkle root -> timestamp the root with the anchor -> assemble the payload
    (including the anchor proof) -> sign the whole payload with the checkpoint
    signer. Raises CheckpointError on any admission failure.
    """
    if not events:
        raise CheckpointError("cannot seal a checkpoint over zero events")
    timestamp = _require_aware_utc(
        timestamp or datetime.now(timezone.utc), "timestamp"
    )

    for i, event in enumerate(events):
        if event.sequence != events[0].sequence + i:
            raise CheckpointError(
                f"events not contiguous: expected sequence "
                f"{events[0].sequence + i}, got {event.sequence}"
            )
    # Ledger hash-chain links must be intact across the sealed range.
    for prev, curr in zip(events, events[1:]):
        if curr.previous_hash != event_hash(prev):
            raise CheckpointError(
                f"ledger hash chain broken between sequences "
                f"{prev.sequence} and {curr.sequence}"
            )

    start_seq, end_seq = events[0].sequence, events[-1].sequence
    merkle_root = build_merkle_root([event_hash(e) for e in events])
    proof = anchor.anchor(merkle_root, timestamp)

    checkpoint = Checkpoint(
        checkpoint_id=_checkpoint_id(start_seq, end_seq, merkle_root),
        start_seq=start_seq,
        end_seq=end_seq,
        event_count=len(events),
        merkle_root=merkle_root,
        previous_checkpoint_root=previous_checkpoint_root,
        timestamp=timestamp,
        anchor_proof=proof,
        next_signer=next_signer,
    )
    return signer.sign_payload(checkpoint_payload_dict(checkpoint))


def _parse_checkpoint(envelope: SignedEnvelope) -> Checkpoint:
    """Strictly parse a signed envelope's payload into a Checkpoint."""
    return Checkpoint.model_validate(envelope.payload)


def verify_checkpoint_events(
    envelope: SignedEnvelope, events: list[EvidenceEvent]
) -> bool:
    """Full re-validation of one checkpoint against raw events: parse the
    payload strictly, rebuild the Merkle root from the events, and require an
    exact match on range, count, root, contiguity, and ledger hash links."""
    try:
        checkpoint = _parse_checkpoint(envelope)
        if (
            checkpoint.event_count != len(events)
            or not events
            or events[0].sequence != checkpoint.start_seq
            or events[-1].sequence != checkpoint.end_seq
        ):
            return False
        for i, event in enumerate(events):
            if event.sequence != checkpoint.start_seq + i:
                return False
        for prev, curr in zip(events, events[1:]):
            if curr.previous_hash != event_hash(prev):
                return False
        return build_merkle_root([event_hash(e) for e in events]) == checkpoint.merkle_root
    except Exception:
        return False


def verify_checkpoint_chain(
    signed_checkpoints: list[SignedEnvelope],
    bootstrap_signer: TrustedCheckpointSigner,
    anchor: TimestampAnchor,
) -> bool:
    """Re-validate an entire checkpoint chain from untrusted input.

    For every checkpoint: signature verifies under the key active at its
    position (rotations declared via ``next_signer`` take effect for LATER
    checkpoints only), the previous_checkpoint_root link matches the prior
    checkpoint's root (genesis must be None), timestamps are non-decreasing,
    and the anchor proof verifies. Any failure -> False (fail closed).
    """
    try:
        if not signed_checkpoints:
            return False
        key_registry = {bootstrap_signer.key_id: bootstrap_signer.public_key}
        active_key_id = bootstrap_signer.key_id
        previous: Checkpoint | None = None

        for envelope in signed_checkpoints:
            if envelope.alg != "Ed25519" or envelope.key_id != active_key_id:
                return False
            public_key = key_registry.get(envelope.key_id)
            if public_key is None:
                return False
            try:
                verify_envelope(envelope, base64.b64decode(public_key))
            except Exception:
                return False

            checkpoint = _parse_checkpoint(envelope)

            # Checkpoint-to-checkpoint hash link.
            expected_prev = previous.merkle_root if previous is not None else None
            if checkpoint.previous_checkpoint_root != expected_prev:
                return False
            # Monotonic time: checkpoints cannot travel backwards.
            if previous is not None and checkpoint.timestamp < previous.timestamp:
                return False
            # Range discipline: checkpoints tile the event space with no gaps
            # and no overlaps.
            if previous is not None and (
                checkpoint.start_seq != previous.end_seq + 1
            ):
                return False

            try:
                if not anchor.verify_anchor(envelope.payload, checkpoint.anchor_proof):
                    return False
            except NotImplementedError:
                # A stub anchor (e.g. unapproved OpenTimestamps) can never
                # validate a chain — fail closed, never skip the check.
                return False
            except Exception:
                return False

            # Rotation declared here takes effect for the NEXT checkpoint.
            if checkpoint.next_signer is not None:
                key_registry[checkpoint.next_signer.key_id] = (
                    checkpoint.next_signer.public_key
                )
                active_key_id = checkpoint.next_signer.key_id
            previous = checkpoint
        return True
    except Exception:
        return False


class CheckpointChain:
    """Ordered, validated chain of sealed checkpoints.

    ``seal()`` admits each new checkpoint only if its range tiles exactly onto
    the previous checkpoint (no gaps/overlaps), it is signed by the currently
    active checkpoint key, and its anchor proof verifies. ``verify()``
    re-validates the whole chain from untrusted envelopes.
    """

    def __init__(
        self,
        bootstrap_signer: TrustedCheckpointSigner,
        anchor: TimestampAnchor,
    ):
        self._bootstrap = bootstrap_signer
        self._anchor = anchor
        self._checkpoints: list[SignedEnvelope] = []
        self._signers: dict[str, Ed25519Signer] = {}
        self._active_key_id = bootstrap_signer.key_id

    def register_signer(self, signer: Ed25519Signer) -> None:
        """Make a checkpoint-signing key available to this chain (holds the
        private key, so this is the operator side, not the verifier side)."""
        self._signers[signer.key_id] = signer

    @property
    def checkpoints(self) -> tuple[SignedEnvelope, ...]:
        return tuple(self._checkpoints)

    @property
    def head(self) -> SignedEnvelope | None:
        return self._checkpoints[-1] if self._checkpoints else None

    def __len__(self) -> int:
        return len(self._checkpoints)

    def seal(
        self,
        events: list[EvidenceEvent],
        next_signer: NextCheckpointSigner | None = None,
        timestamp: datetime | None = None,
    ) -> SignedEnvelope:
        """Seal the next checkpoint over ``events`` with the active key."""
        signer = self._signers.get(self._active_key_id)
        if signer is None:
            raise CheckpointError(
                f"no registered signer for active key_id {self._active_key_id!r}"
            )
        head = self.head
        if head is not None:
            head_cp = _parse_checkpoint(head)
            if events and events[0].sequence != head_cp.end_seq + 1:
                raise CheckpointError(
                    f"checkpoint range must tile: expected start_seq "
                    f"{head_cp.end_seq + 1}, got {events[0].sequence}"
                )
            previous_root: str | None = head_cp.merkle_root
        else:
            if events and events[0].sequence != 0:
                raise CheckpointError(
                    "genesis checkpoint must start at sequence 0, "
                    f"got {events[0].sequence}"
                )
            previous_root = None

        envelope = seal_checkpoint(
            events,
            signer,
            self._anchor,
            previous_root,
            next_signer=next_signer,
            timestamp=timestamp,
        )
        # Admission check: the freshly sealed checkpoint must verify as a
        # one-longer chain before it is accepted.
        candidate = self._checkpoints + [envelope]
        if not verify_checkpoint_chain(candidate, self._bootstrap, self._anchor):
            raise CheckpointError("freshly sealed checkpoint failed chain admission")
        self._checkpoints.append(envelope)
        if next_signer is not None:
            self._active_key_id = next_signer.key_id
        return envelope

    def verify(self) -> bool:
        """Re-validate every checkpoint signature, chain link, and anchor
        proof from the stored envelopes."""
        return verify_checkpoint_chain(
            list(self._checkpoints), self._bootstrap, self._anchor
        )
