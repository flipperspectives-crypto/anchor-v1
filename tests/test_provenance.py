"""Tests for provenance-bound read capabilities (Wave 4):
anchor_v1.provenance + authority.issue_read + CapabilityStore.check_capability.

Threat model: reads are governed too. A reader holding a capability for
``config/*`` must NOT be able to read values injected by an untrusted
writer, stale values from before a rotation, values whose bytes were
tampered with after the write, or values lacking the required
transparency-log backing. Every such path fails closed.

Also covered: read capabilities are reusable (no consumption) but still
need a fresh holder proof per read; every read is audit-logged; a read
capability can never execute; issuance without a provenance anchor is
refused.
"""

from __future__ import annotations

import hashlib
import os
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from anchor_v1 import authority
from anchor_v1.authority import KIND_READ, CapabilityError
from anchor_v1.crypto import Ed25519Signer
from anchor_v1.provenance import (
    ProvenanceError,
    ProvenanceRecord,
    ProvenanceStore,
    provenance_signature_bytes,
)
from anchor_v1.store import AuthorizationDenied, CapabilityStore

NOW = datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# fixtures / helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def authority_signer() -> Ed25519Signer:
    return Ed25519Signer.generate("authority-1")


@pytest.fixture
def writer_signer() -> Ed25519Signer:
    return Ed25519Signer.generate("writer-1")


@pytest.fixture
def attacker_signer() -> Ed25519Signer:
    return Ed25519Signer.generate("attacker-1")


@pytest.fixture
def holder_signer() -> Ed25519Signer:
    return Ed25519Signer.generate("holder-1")


@pytest.fixture
def store() -> CapabilityStore:
    s = CapabilityStore()
    s.sync_revocations()
    return s


@pytest.fixture
def pstore(store: CapabilityStore) -> ProvenanceStore:
    return ProvenanceStore(store)


@pytest.fixture
def trusted_issuers(authority_signer) -> dict:
    return {
        authority_signer.key_id.encode(): Ed25519PublicKey.from_public_bytes(
            authority_signer.public_key_bytes()
        )
    }


@pytest.fixture
def writer_registry(writer_signer, attacker_signer) -> dict:
    return {
        writer_signer.key_id: Ed25519PublicKey.from_public_bytes(
            writer_signer.public_key_bytes()
        ),
        attacker_signer.key_id: Ed25519PublicKey.from_public_bytes(
            attacker_signer.public_key_bytes()
        ),
    }


def issue_read_cap(
    store,
    authority_signer,
    holder_signer,
    trusted_issuers,
    *,
    prefix="config/",
    writers=("writer-1",),
    min_version=None,
    require_statement=False,
    ttl=timedelta(minutes=15),
    now=NOW,
):
    cose = authority.issue_read(
        issuer=authority_signer,
        holder_pubkey=holder_signer.public_key_bytes(),
        read_key_prefix=prefix,
        read_trusted_writers=list(writers) if writers is not None else None,
        read_min_version=min_version,
        read_require_statement=require_statement,
        ttl=ttl,
        now=now,
    )
    payload = authority.verify_capability(cose, trusted_issuers, now=now)
    assert payload.kind == KIND_READ
    store.register_capability(payload)
    return cose, payload


def do_read(pstore, trusted_issuers, writer_registry, key, cose, holder_signer,
            payload, *, now=NOW):
    challenge = os.urandom(32)
    proof = authority.make_holder_proof(holder_signer, payload.capability_id, challenge)
    return pstore.read(
        key,
        capability_cose=cose,
        holder_proof=proof,
        challenge=challenge,
        trusted_issuers=trusted_issuers,
        trusted_writer_keys=writer_registry,
        now=now,
    )


@pytest.fixture
def seeded(pstore, writer_signer):
    """One trusted write: config/db-url v1 by writer-1."""
    record = pstore.write("config/db-url", b"postgres://prod", writer_signer, now=NOW)
    return record


# ---------------------------------------------------------------------------
# A. issuance — provenance binding is mandatory
# ---------------------------------------------------------------------------


class TestIssuance:
    def test_issue_read_happy_path(self, authority_signer, holder_signer):
        cose = authority.issue_read(
            issuer=authority_signer,
            holder_pubkey=holder_signer.public_key_bytes(),
            read_key_prefix="config/",
            read_trusted_writers=["writer-1"],
        )
        assert isinstance(cose, bytes)

    def test_issue_read_without_provenance_anchor_refused(
        self, authority_signer, holder_signer
    ):
        # No trusted writers AND no statement requirement: meaningless.
        with pytest.raises(CapabilityError, match="must bind provenance"):
            authority.issue_read(
                issuer=authority_signer,
                holder_pubkey=holder_signer.public_key_bytes(),
                read_key_prefix="config/",
            )

    def test_issue_read_with_statement_requirement_only(
        self, authority_signer, holder_signer
    ):
        cose = authority.issue_read(
            issuer=authority_signer,
            holder_pubkey=holder_signer.public_key_bytes(),
            read_key_prefix="config/",
            read_trusted_writers=None,
            read_require_statement=True,
        )
        assert isinstance(cose, bytes)

    def test_issue_read_empty_prefix_refused(self, authority_signer, holder_signer):
        with pytest.raises(CapabilityError, match="read_key_prefix"):
            authority.issue_read(
                issuer=authority_signer,
                holder_pubkey=holder_signer.public_key_bytes(),
                read_key_prefix="",
                read_trusted_writers=["w"],
            )

    def test_issue_read_empty_writers_refused(self, authority_signer, holder_signer):
        with pytest.raises(CapabilityError, match="non-empty list"):
            authority.issue_read(
                issuer=authority_signer,
                holder_pubkey=holder_signer.public_key_bytes(),
                read_key_prefix="config/",
                read_trusted_writers=[],
            )

    def test_read_caveats_rejected_for_execution_kind(
        self, authority_signer, holder_signer
    ):
        from anchor_v1.canonical import sha256_hex

        with pytest.raises(CapabilityError, match="only valid for kind 'read'"):
            authority._issue(
                authority_signer,
                kind=authority.KIND_EXECUTION,
                action_digest=sha256_hex({"x": 1}),
                holder_pubkey=holder_signer.public_key_bytes(),
                spend_limit=None,
                spend_asset=None,
                ttl=timedelta(minutes=5),
                parent_capability_id=None,
                max_revocation_staleness=300,
                now=NOW,
                read_key_prefix="config/",
            )


# ---------------------------------------------------------------------------
# B. happy-path reads
# ---------------------------------------------------------------------------


class TestHappyPath:
    def test_read_succeeds_and_returns_provenance(
        self, pstore, store, authority_signer, holder_signer, trusted_issuers,
        writer_registry, writer_signer, seeded,
    ):
        cose, payload = issue_read_cap(
            store, authority_signer, holder_signer, trusted_issuers
        )
        result = do_read(
            pstore, trusted_issuers, writer_registry, "config/db-url",
            cose, holder_signer, payload,
        )
        assert result.value == b"postgres://prod"
        assert result.provenance.writer_key_id == "writer-1"
        assert result.provenance.version == 1
        assert result.capability_id == payload.capability_id

    def test_read_capability_is_reusable(
        self, pstore, store, authority_signer, holder_signer, trusted_issuers,
        writer_registry, seeded,
    ):
        cose, payload = issue_read_cap(
            store, authority_signer, holder_signer, trusted_issuers
        )
        for _ in range(3):
            result = do_read(
                pstore, trusted_issuers, writer_registry, "config/db-url",
                cose, holder_signer, payload,
            )
            assert result.value == b"postgres://prod"
        # Still ISSUED — reads never consume.
        assert store.capability_state(payload.capability_id) == "ISSUED"
        assert len(pstore.audit_log("config/db-url")) == 3

    def test_read_returns_latest_version(
        self, pstore, store, authority_signer, holder_signer, trusted_issuers,
        writer_registry, writer_signer, seeded,
    ):
        pstore.write("config/db-url", b"postgres://prod2", writer_signer, now=NOW)
        cose, payload = issue_read_cap(
            store, authority_signer, holder_signer, trusted_issuers
        )
        result = do_read(
            pstore, trusted_issuers, writer_registry, "config/db-url",
            cose, holder_signer, payload,
        )
        assert result.value == b"postgres://prod2"
        assert result.provenance.version == 2

    def test_audit_log_records_reads(
        self, pstore, store, authority_signer, holder_signer, trusted_issuers,
        writer_registry, seeded,
    ):
        cose, payload = issue_read_cap(
            store, authority_signer, holder_signer, trusted_issuers
        )
        do_read(pstore, trusted_issuers, writer_registry, "config/db-url",
                cose, holder_signer, payload)
        entries = pstore.audit_log("config/db-url")
        assert len(entries) == 1
        assert entries[0]["capability_id"] == payload.capability_id
        assert entries[0]["reader_pubkey"] == holder_signer.public_key_bytes().hex()


# ---------------------------------------------------------------------------
# C. provenance enforcement — the core of the slice
# ---------------------------------------------------------------------------


class TestProvenanceEnforcement:
    def test_untrusted_writer_denied(
        self, pstore, store, authority_signer, holder_signer, trusted_issuers,
        writer_registry, attacker_signer, seeded,
    ):
        # Attacker injects a value under an in-scope key.
        pstore.write("config/db-url", b"postgres://evil", attacker_signer, now=NOW)
        cose, payload = issue_read_cap(
            store, authority_signer, holder_signer, trusted_issuers,
            writers=("writer-1",),  # attacker NOT allowlisted
        )
        with pytest.raises(ProvenanceError, match="not in capability's trusted-writer"):
            do_read(pstore, trusted_issuers, writer_registry, "config/db-url",
                    cose, holder_signer, payload)

    def test_key_outside_prefix_denied(
        self, pstore, store, authority_signer, holder_signer, trusted_issuers,
        writer_registry, writer_signer, seeded,
    ):
        pstore.write("secrets/api-key", b"shh", writer_signer, now=NOW)
        cose, payload = issue_read_cap(
            store, authority_signer, holder_signer, trusted_issuers, prefix="config/"
        )
        with pytest.raises(ProvenanceError, match="outside capability prefix"):
            do_read(pstore, trusted_issuers, writer_registry, "secrets/api-key",
                    cose, holder_signer, payload)

    def test_stale_version_denied(
        self, pstore, store, authority_signer, holder_signer, trusted_issuers,
        writer_registry, writer_signer, seeded,
    ):
        # Record is v1; capability demands v2+ (e.g. post-rotation reads).
        cose, payload = issue_read_cap(
            store, authority_signer, holder_signer, trusted_issuers, min_version=2
        )
        with pytest.raises(ProvenanceError, match="older than capability minimum"):
            do_read(pstore, trusted_issuers, writer_registry, "config/db-url",
                    cose, holder_signer, payload)
        # After a fresh write (v2), the same capability works.
        pstore.write("config/db-url", b"postgres://new", writer_signer, now=NOW)
        result = do_read(pstore, trusted_issuers, writer_registry, "config/db-url",
                         cose, holder_signer, payload)
        assert result.value == b"postgres://new"

    def test_missing_statement_denied(
        self, pstore, store, authority_signer, holder_signer, trusted_issuers,
        writer_registry, seeded,
    ):
        cose, payload = issue_read_cap(
            store, authority_signer, holder_signer, trusted_issuers,
            writers=None, require_statement=True,
        )
        with pytest.raises(ProvenanceError, match="requires a registered SCITT"):
            do_read(pstore, trusted_issuers, writer_registry, "config/db-url",
                    cose, holder_signer, payload)

    def test_statement_backed_write_readable(
        self, pstore, store, authority_signer, holder_signer, trusted_issuers,
        writer_registry, writer_signer,
    ):
        stmt_hash = hashlib.sha256(b"fake-scitt-statement").digest()
        pstore.write("config/key", b"v", writer_signer,
                     statement_hash=stmt_hash, now=NOW)
        cose, payload = issue_read_cap(
            store, authority_signer, holder_signer, trusted_issuers,
            writers=None, require_statement=True,
        )
        result = do_read(pstore, trusted_issuers, writer_registry, "config/key",
                         cose, holder_signer, payload)
        assert result.provenance.statement_hash == stmt_hash.hex()

    def test_tampered_value_denied(
        self, pstore, store, authority_signer, holder_signer, trusted_issuers,
        writer_registry, seeded,
    ):
        # Attacker flips the bytes directly in the DB, bypassing write().
        pstore._db.execute(
            "UPDATE documents SET value = ? WHERE key = ?",
            (b"postgres://tampered", "config/db-url"),
        )
        cose, payload = issue_read_cap(
            store, authority_signer, holder_signer, trusted_issuers
        )
        with pytest.raises(ProvenanceError, match="hash mismatch|signature invalid"):
            do_read(pstore, trusted_issuers, writer_registry, "config/db-url",
                    cose, holder_signer, payload)

    def test_unknown_key_denied(
        self, pstore, store, authority_signer, holder_signer, trusted_issuers,
        writer_registry,
    ):
        cose, payload = issue_read_cap(
            store, authority_signer, holder_signer, trusted_issuers
        )
        with pytest.raises(ProvenanceError, match="unknown key"):
            do_read(pstore, trusted_issuers, writer_registry, "config/nope",
                    cose, holder_signer, payload)

    def test_writer_not_in_registry_denied(
        self, pstore, store, authority_signer, holder_signer, trusted_issuers,
        seeded,
    ):
        cose, payload = issue_read_cap(
            store, authority_signer, holder_signer, trusted_issuers
        )
        # Deployment forgot to register the writer's public key: fail closed.
        with pytest.raises(ProvenanceError, match="writer registry|not in registry"):
            do_read(pstore, trusted_issuers, {}, "config/db-url",
                    cose, holder_signer, payload)

    def test_malformed_writer_signature_denied(
        self, pstore, store, authority_signer, holder_signer, trusted_issuers,
        writer_registry, writer_signer, seeded,
    ):
        # DB tampering: the stored signature is no longer valid hex (128
        # chars so it reaches the decode step). The read path must raise
        # ProvenanceError, not leak a raw ValueError.
        pstore._db.execute(
            "UPDATE documents SET writer_signature = ? WHERE key = ?",
            ("zz" * 64, "config/db-url"),
        )
        cose, payload = issue_read_cap(
            store, authority_signer, holder_signer, trusted_issuers
        )
        with pytest.raises(ProvenanceError, match="malformed writer signature"):
            do_read(pstore, trusted_issuers, writer_registry, "config/db-url",
                    cose, holder_signer, payload)


# ---------------------------------------------------------------------------
# D. capability checks still apply to reads
# ---------------------------------------------------------------------------


class TestCapabilityChecks:
    def test_expired_read_capability_denied(
        self, pstore, store, authority_signer, holder_signer, trusted_issuers,
        writer_registry, seeded,
    ):
        cose, payload = issue_read_cap(
            store, authority_signer, holder_signer, trusted_issuers,
            ttl=timedelta(seconds=1), now=NOW,
        )
        with pytest.raises(ProvenanceError, match="capability invalid"):
            do_read(pstore, trusted_issuers, writer_registry, "config/db-url",
                    cose, holder_signer, payload,
                    now=NOW + timedelta(seconds=2))

    def test_wrong_holder_proof_denied(
        self, pstore, store, authority_signer, holder_signer, trusted_issuers,
        writer_registry, seeded,
    ):
        cose, payload = issue_read_cap(
            store, authority_signer, holder_signer, trusted_issuers
        )
        challenge = os.urandom(32)
        with pytest.raises(ProvenanceError, match="capability invalid"):
            pstore.read(
                "config/db-url",
                capability_cose=cose,
                holder_proof=os.urandom(64),
                challenge=challenge,
                trusted_issuers=trusted_issuers,
                trusted_writer_keys=writer_registry,
                now=NOW,
            )

    def test_revoked_read_capability_denied(
        self, pstore, store, authority_signer, holder_signer, trusted_issuers,
        writer_registry, seeded,
    ):
        cose, payload = issue_read_cap(
            store, authority_signer, holder_signer, trusted_issuers
        )
        store.revoke(payload.capability_id)
        with pytest.raises(ProvenanceError, match="capability invalid"):
            do_read(pstore, trusted_issuers, writer_registry, "config/db-url",
                    cose, holder_signer, payload)

    def test_unregistered_read_capability_denied(
        self, pstore, authority_signer, holder_signer, trusted_issuers,
        writer_registry, seeded,
    ):
        # Minted but never registered with the store.
        cose = authority.issue_read(
            issuer=authority_signer,
            holder_pubkey=holder_signer.public_key_bytes(),
            read_key_prefix="config/",
            read_trusted_writers=["writer-1"],
            now=NOW,
        )
        payload = authority.verify_capability(cose, trusted_issuers, now=NOW)
        with pytest.raises(ProvenanceError, match="capability invalid"):
            do_read(pstore, trusted_issuers, writer_registry, "config/db-url",
                    cose, holder_signer, payload)

    def test_execution_capability_cannot_read(
        self, pstore, store, authority_signer, holder_signer, trusted_issuers,
        writer_registry, seeded,
    ):
        from anchor_v1.canonical import sha256_hex

        cose = authority.issue_execution(
            issuer=authority_signer,
            action_digest=sha256_hex({"x": 1}),
            holder_pubkey=holder_signer.public_key_bytes(),
            now=NOW,
        )
        payload = authority.verify_capability(cose, trusted_issuers, now=NOW)
        store.register_capability(payload)
        with pytest.raises(ProvenanceError, match="not 'read'"):
            do_read(pstore, trusted_issuers, writer_registry, "config/db-url",
                    cose, holder_signer, payload)

    def test_denied_reads_are_not_audit_logged(
        self, pstore, store, authority_signer, holder_signer, trusted_issuers,
        writer_registry, attacker_signer, seeded,
    ):
        pstore.write("config/db-url", b"postgres://evil", attacker_signer, now=NOW)
        cose, payload = issue_read_cap(
            store, authority_signer, holder_signer, trusted_issuers,
            writers=("writer-1",),
        )
        with pytest.raises(ProvenanceError):
            do_read(pstore, trusted_issuers, writer_registry, "config/db-url",
                    cose, holder_signer, payload)
        assert pstore.audit_log("config/db-url") == []


# ---------------------------------------------------------------------------
# E. provenance record integrity
# ---------------------------------------------------------------------------


class TestRecordIntegrity:
    def test_signature_bytes_are_stable(self):
        a = provenance_signature_bytes("k", 3, "ab" * 32)
        b = provenance_signature_bytes("k", 3, "ab" * 32)
        assert a == b
        assert provenance_signature_bytes("k", 4, "ab" * 32) != a

    def test_version_is_monotonic(self, pstore, writer_signer):
        r1 = pstore.write("a", b"1", writer_signer, now=NOW)
        r2 = pstore.write("b", b"2", writer_signer, now=NOW)
        r3 = pstore.write("a", b"3", writer_signer, now=NOW)
        assert (r1.version, r2.version, r3.version) == (1, 2, 3)
        assert pstore.current_version() == 3

    def test_write_rejects_bad_inputs(self, pstore, writer_signer):
        with pytest.raises(ProvenanceError):
            pstore.write("", b"v", writer_signer)
        with pytest.raises(ProvenanceError):
            pstore.write("k", "not-bytes", writer_signer)
        with pytest.raises(ProvenanceError):
            pstore.write("k", b"v", writer_signer, statement_hash=b"short")
