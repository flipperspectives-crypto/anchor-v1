"""ANCHOR v1 — provenance-bound read capabilities (Wave 4).

Reads are governed too. A read capability (``authority.KIND_READ``) does not
authorize an action — it authorizes READING data, and only data whose
**provenance** satisfies the caveats the issuer signed into the capability:

* ``read_key_prefix`` — scope: the key must start with this prefix.
* ``read_trusted_writers`` — the recorded writer's key id must be in this
  allowlist. This is the injection defense: data written by an untrusted
  key (a compromised agent, a poisoned import) is unreadable even though
  the key itself is in scope.
* ``read_min_version`` — freshness: the record's version must be >= this,
  defeating stale-read TOCTOU (approving a read of "the current config"
  must not serve last month's config).
* ``read_require_statement`` — the write must be backed by a registered
  SCITT statement hash (ties reads to the transparency log).

Every write records its provenance: the writer's key id, an Ed25519
signature over ``(domain || key || version || value_hash)``, a monotonic
version, an optional SCITT statement hash, and a timestamp. Every read
verifies the writer's signature (value integrity is part of provenance),
checks the caveats fail-closed, and appends to an audit log — who read
what, with which capability, when.

Reads are non-mutating, so a read capability is REUSABLE until it expires:
``CapabilityStore.check_capability`` runs every consume check EXCEPT the
ISSUED→CONSUMED flip, and each read still requires a FRESH holder proof
(a stolen read capability without the holder's private key is useless).
Read capabilities can never mint children and can never be consumed for
execution — ``kind`` is enforced at the read path.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import Field

from anchor_v1.authority import KIND_READ, CapabilityPayload
from anchor_v1.crypto import Ed25519Signer
from anchor_v1.models import StrictModel
from anchor_v1.store import AuthorizationDenied, CapabilityStore

__all__ = [
    "ProvenanceError",
    "ProvenanceRecord",
    "ReadResult",
    "ProvenanceStore",
    "provenance_signature_bytes",
]

_PROVENANCE_DOMAIN = b"anchor-v1-provenance\x00"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS documents (
    key                 TEXT PRIMARY KEY,
    value               BLOB NOT NULL,
    value_hash          TEXT NOT NULL,
    writer_key_id       TEXT NOT NULL,
    writer_signature    TEXT NOT NULL,
    version             INTEGER NOT NULL,
    statement_hash      TEXT,
    written_at          TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS read_audit (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    key             TEXT NOT NULL,
    capability_id   TEXT NOT NULL,
    reader_pubkey   TEXT NOT NULL,
    read_at         TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (
    key     TEXT PRIMARY KEY,
    value   TEXT NOT NULL
);
"""


class ProvenanceError(ValueError):
    """Any provenance write/read failure (fail closed)."""


class ProvenanceRecord(StrictModel):
    """The recorded provenance of one stored value."""

    key: str = Field(min_length=1)
    value_hash: str = Field(min_length=64, max_length=64)
    writer_key_id: str = Field(min_length=1)
    writer_signature: str = Field(min_length=128, max_length=128)
    version: int = Field(ge=1)
    statement_hash: str | None = Field(default=None, min_length=64, max_length=64)
    written_at: str = Field(min_length=1)


class ReadResult(StrictModel):
    """A successful provenance-checked read."""

    key: str
    value: bytes
    provenance: ProvenanceRecord
    capability_id: str

    model_config = {"arbitrary_types_allowed": True}


def provenance_signature_bytes(key: str, version: int, value_hash: str) -> bytes:
    """The exact bytes a writer signs for a provenance record."""
    return (
        _PROVENANCE_DOMAIN
        + key.encode("utf-8")
        + b"\x00"
        + version.to_bytes(8, "big")
        + bytes.fromhex(value_hash)
    )


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ProvenanceStore:
    """Provenance-tracking document store with capability-gated reads.

    ``capability_store`` is the ANCHOR ``CapabilityStore`` used to verify
    read capabilities (registration, revocation, holder proofs). The
    documents live in this store's own SQLite database.
    """

    def __init__(
        self,
        capability_store: CapabilityStore,
        db_path: str = ":memory:",
    ) -> None:
        self._caps = capability_store
        self._lock = threading.RLock()
        self._db = sqlite3.connect(db_path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.isolation_level = None
        with self._lock:
            self._db.executescript(_SCHEMA)
            self._db.execute("PRAGMA busy_timeout = 5000")
            cur = self._db.execute("SELECT value FROM meta WHERE key = 'version'")
            if cur.fetchone() is None:
                self._db.execute("INSERT INTO meta (key, value) VALUES ('version', '0')")

    # -- writes -----------------------------------------------------------

    def write(
        self,
        key: str,
        value: bytes,
        writer: Ed25519Signer,
        *,
        statement_hash: bytes | None = None,
        now: datetime | None = None,
    ) -> ProvenanceRecord:
        """Store ``value`` under ``key``, signed by ``writer``.

        ``statement_hash`` (32 bytes) optionally ties the write to a
        registered SCITT statement. The version is monotonic per store.
        """
        if not isinstance(key, str) or not key:
            raise ProvenanceError("key must be a non-empty string")
        if not isinstance(value, (bytes, bytearray)):
            raise ProvenanceError("value must be bytes")
        if statement_hash is not None:
            if not isinstance(statement_hash, (bytes, bytearray)) or len(statement_hash) != 32:
                raise ProvenanceError("statement_hash must be 32 bytes")
            stmt_hex: str | None = bytes(statement_hash).hex()
        else:
            stmt_hex = None
        if not writer.key_id:
            raise ProvenanceError("writer key id must not be empty")
        moment = now if now is not None else datetime.now(timezone.utc)
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)

        value_hash = hashlib.sha256(bytes(value)).hexdigest()
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                cur = self._db.execute("SELECT value FROM meta WHERE key = 'version'")
                version = int(cur.fetchone()["value"]) + 1
                signature = writer.sign_bytes(
                    provenance_signature_bytes(key, version, value_hash)
                ).hex()
                self._db.execute(
                    "INSERT INTO documents (key, value, value_hash, writer_key_id,"
                    " writer_signature, version, statement_hash, written_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
                    " ON CONFLICT(key) DO UPDATE SET"
                    " value = excluded.value,"
                    " value_hash = excluded.value_hash,"
                    " writer_key_id = excluded.writer_key_id,"
                    " writer_signature = excluded.writer_signature,"
                    " version = excluded.version,"
                    " statement_hash = excluded.statement_hash,"
                    " written_at = excluded.written_at",
                    (
                        key,
                        bytes(value),
                        value_hash,
                        writer.key_id,
                        signature,
                        version,
                        stmt_hex,
                        moment.isoformat(),
                    ),
                )
                self._db.execute(
                    "UPDATE meta SET value = ? WHERE key = 'version'",
                    (str(version),),
                )
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise
        return ProvenanceRecord(
            key=key,
            value_hash=value_hash,
            writer_key_id=writer.key_id,
            writer_signature=signature,
            version=version,
            statement_hash=stmt_hex,
            written_at=moment.isoformat(),
        )

    # -- reads ------------------------------------------------------------

    def read(
        self,
        key: str,
        *,
        capability_cose: bytes,
        holder_proof: bytes,
        challenge: bytes,
        trusted_issuers: Mapping[bytes, Ed25519PublicKey],
        trusted_writer_keys: Mapping[str, Ed25519PublicKey] | None = None,
        now: datetime | None = None,
    ) -> ReadResult:
        """Read ``key`` iff the capability and the data's provenance agree.

        Steps (fail-closed, in order): (1) verify the read capability —
        full checks, no consumption, fresh holder proof; (2) ``kind`` must
        be ``"read"``; (3) load the record; (4) verify the WRITER's
        signature over the stored value (integrity is provenance); (5) check
        every provenance caveat from the capability; (6) audit-log the read.

        ``trusted_writer_keys`` maps writer key ids to public keys so the
        writer signature can be checked. When omitted, only writers whose
        key id appears there... — no: when omitted the signature cannot be
        verified, so the read is refused. Pass the deployment's writer
        registry.
        """
        moment = now if now is not None else datetime.now(timezone.utc)
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)

        # (1) capability verification — raises AuthorizationDenied on any failure.
        try:
            payload: CapabilityPayload = self._caps.check_capability(
                capability_cose=capability_cose,
                holder_proof=holder_proof,
                challenge=challenge,
                trusted_issuers=trusted_issuers,
                now=moment,
            )
        except AuthorizationDenied as exc:
            raise ProvenanceError(f"read refused: capability invalid: {exc}") from exc

        # (2) kind enforcement: only read capabilities read.
        if payload.kind != KIND_READ:
            raise ProvenanceError(
                f"read refused: capability kind {payload.kind!r} is not 'read'"
            )

        with self._lock:
            cur = self._db.execute(
                "SELECT key, value, value_hash, writer_key_id, writer_signature,"
                " version, statement_hash, written_at FROM documents WHERE key = ?",
                (key,),
            )
            row = cur.fetchone()
            if row is None:
                raise ProvenanceError(f"read refused: unknown key {key!r}")
            record = ProvenanceRecord(
                key=row["key"],
                value_hash=row["value_hash"],
                writer_key_id=row["writer_key_id"],
                writer_signature=row["writer_signature"],
                version=row["version"],
                statement_hash=row["statement_hash"],
                written_at=row["written_at"],
            )
            value = bytes(row["value"])

            # (3) scope: the key must fall under the capability's prefix.
            prefix = payload.read_key_prefix or ""
            if not key.startswith(prefix):
                raise ProvenanceError(
                    f"read refused: key {key!r} outside capability prefix {prefix!r}"
                )

            # (4) writer signature: integrity is part of provenance. A value
            # whose bytes don't match the writer's signature was tampered
            # with after the write — unreadable, regardless of caveats.
            if trusted_writer_keys is None:
                raise ProvenanceError(
                    "read refused: no trusted writer registry provided"
                )
            writer_key = trusted_writer_keys.get(record.writer_key_id)
            if writer_key is None:
                raise ProvenanceError(
                    f"read refused: writer {record.writer_key_id!r} not in registry"
                )
            if hashlib.sha256(value).hexdigest() != record.value_hash:
                raise ProvenanceError("read refused: stored value hash mismatch")
            try:
                signature_bytes = bytes.fromhex(record.writer_signature)
            except ValueError as exc:
                raise ProvenanceError(
                    "read refused: malformed writer signature"
                ) from exc
            try:
                writer_key.verify(
                    signature_bytes,
                    provenance_signature_bytes(
                        record.key, record.version, record.value_hash
                    ),
                )
            except InvalidSignature as exc:
                raise ProvenanceError(
                    "read refused: writer signature invalid — data tampered"
                ) from exc

            # (5) provenance caveats from the capability.
            if payload.read_trusted_writers is not None:
                if record.writer_key_id not in payload.read_trusted_writers:
                    raise ProvenanceError(
                        f"read refused: writer {record.writer_key_id!r} not in "
                        "capability's trusted-writer allowlist"
                    )
            if (
                payload.read_min_version is not None
                and record.version < payload.read_min_version
            ):
                raise ProvenanceError(
                    f"read refused: record version {record.version} is older than "
                    f"capability minimum {payload.read_min_version}"
                )
            if payload.read_require_statement and not record.statement_hash:
                raise ProvenanceError(
                    "read refused: capability requires a registered SCITT "
                    "statement, but the write has none"
                )

            # (6) audit the read.
            self._db.execute(
                "INSERT INTO read_audit (key, capability_id, reader_pubkey, read_at)"
                " VALUES (?, ?, ?, ?)",
                (
                    key,
                    payload.capability_id,
                    bytes(payload.holder_pubkey).hex(),
                    moment.isoformat(),
                ),
            )
            return ReadResult(
                key=key,
                value=value,
                provenance=record,
                capability_id=payload.capability_id,
            )

    # -- audit ------------------------------------------------------------

    def audit_log(self, key: str | None = None) -> list[dict]:
        """Who read what, with which capability, when."""
        with self._lock:
            if key is None:
                cur = self._db.execute(
                    "SELECT key, capability_id, reader_pubkey, read_at"
                    " FROM read_audit ORDER BY id"
                )
            else:
                cur = self._db.execute(
                    "SELECT key, capability_id, reader_pubkey, read_at"
                    " FROM read_audit WHERE key = ? ORDER BY id",
                    (key,),
                )
            return [dict(r) for r in cur.fetchall()]

    def current_version(self) -> int:
        with self._lock:
            cur = self._db.execute("SELECT value FROM meta WHERE key = 'version'")
            return int(cur.fetchone()["value"])
