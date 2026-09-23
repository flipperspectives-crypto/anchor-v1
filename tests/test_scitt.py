"""Tests for SCITT evidence mapping (Wave 4): anchor_v1.scitt.

RFC 9943 Signed Statements (COSE_Sign1 with CWT iss/sub in the protected
header), RFC 9942 Receipts (detached payload = derived Merkle root, vds=1,
inclusion proof in unprotected header label 396), Transparent Statements
(receipts embedded at unprotected label 394), the injectable transparency
log with its registration policy, and the ANCHOR event -> statement
mapping (decision/approval/mint/consume/execution/revocation).

Everything is fail-closed: any signature, structural, or inclusion
failure raises SCITTError.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from anchor_v1 import authority
from anchor_v1.canonical import sha256_hex
from anchor_v1.cbor import cbor_dumps, cbor_loads
from anchor_v1.crypto import Ed25519Signer
from anchor_v1.scitt import (
    KNOWN_STATEMENT_TYPES,
    STATEMENT_CONSUME,
    STATEMENT_DECISION,
    STATEMENT_EPOCH,
    STATEMENT_EXECUTION,
    STATEMENT_FREEZE,
    STATEMENT_MINT,
    STATEMENT_POLICY_CHANGE,
    STATEMENT_REVOCATION,
    LocalTransparencyLog,
    SCITTError,
    TransparencyLog,
    _audit_path,
    _leaf,
    _mth,
    _root_from_proof,
    _scitt_parse,
    add_receipt,
    approval_statement,
    consume_statement,
    decision_statement,
    epoch_statement,
    execution_statement,
    freeze_statement,
    issue_statement,
    mint_statement,
    parse_statement,
    policy_change_statement,
    revocation_statement,
    verify_transparent_statement,
)
from anchor_v1.state_binding import PolicyDecision, prepare
from anchor_v1.store import CapabilityStore

NOW = datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# fixtures / helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def issuer() -> Ed25519Signer:
    return Ed25519Signer.generate("issuer-1")


@pytest.fixture
def log_signer() -> Ed25519Signer:
    return Ed25519Signer.generate("scitt-log-1")


@pytest.fixture
def trusted_issuers(issuer) -> dict:
    return {
        issuer.key_id.encode(): Ed25519PublicKey.from_public_bytes(
            issuer.public_key_bytes()
        )
    }


@pytest.fixture
def trusted_logs(log_signer) -> dict:
    return {
        log_signer.key_id.encode(): Ed25519PublicKey.from_public_bytes(
            log_signer.public_key_bytes()
        )
    }


@pytest.fixture
def log(log_signer) -> LocalTransparencyLog:
    return LocalTransparencyLog(log_signer)


def make_statement(issuer, subject="action:abc123", stype=STATEMENT_MINT, claims=None):
    return issue_statement(
        statement_type=stype,
        subject=subject,
        claims=claims or {"k": "v"},
        issuer=issuer,
    )


def transparent_bundle(issuer, log, trusted_issuers, trusted_logs, **kw):
    """Issue, register, embed: returns (transparent_bytes, statement, receipt)."""
    statement = make_statement(issuer, **kw)
    receipt = log.register(statement)
    return add_receipt(statement, receipt), statement, receipt


# ---------------------------------------------------------------------------
# A. statement issuance / parsing
# ---------------------------------------------------------------------------


class TestStatements:
    def test_issue_parse_round_trip(self, issuer, trusted_issuers):
        stmt = make_statement(
            issuer, subject="action:deadbeef", stype=STATEMENT_DECISION,
            claims={"allowed": True},
        )
        view = parse_statement(stmt, trusted_issuers)
        assert view["issuer"] == "issuer-1"
        assert view["subject"] == "action:deadbeef"
        assert view["statement_type"] == STATEMENT_DECISION
        assert view["claims"] == {"allowed": True}
        assert view["issued_at"]

    def test_protected_header_carries_cwt_claims(self, issuer):
        stmt = make_statement(issuer, subject="sub-1")
        protected, _u, _p, _s, _pb = _scitt_parse(stmt)
        assert protected[1] == -8  # EdDSA
        assert protected[4] == b"issuer-1"
        assert protected[15] == {1: "issuer-1", 2: "sub-1"}

    def test_empty_subject_rejected(self, issuer):
        with pytest.raises(SCITTError, match="subject"):
            make_statement(issuer, subject="")

    def test_empty_issuer_rejected(self):
        bad = Ed25519Signer.generate("")
        with pytest.raises(SCITTError, match="key id"):
            make_statement(bad, subject="x")

    def test_unknown_statement_type_rejected(self, issuer):
        with pytest.raises(SCITTError, match="unknown statement type"):
            issue_statement(
                statement_type="evil.type", subject="x",
                claims={}, issuer=issuer,
            )

    def test_tampered_payload_rejected(self, issuer, trusted_issuers):
        stmt = make_statement(issuer, claims={"amount": 100})
        protected_b, unprotected, payload, sig, _pb = _scitt_parse(stmt)
        body = cbor_loads(payload)
        body["claims"] = {"amount": 1_000_000}
        forged = cbor_dumps([_scitt_parse(stmt)[4], unprotected, cbor_dumps(body), sig])
        with pytest.raises(SCITTError, match="signature verification failed"):
            parse_statement(forged, trusted_issuers)

    def test_header_payload_subject_mismatch_rejected(self, issuer, trusted_issuers):
        # Re-sign a payload whose subject disagrees with the protected header.
        stmt = make_statement(issuer, subject="real-subject")
        _p, _u, payload, _s, _pb = _scitt_parse(stmt)
        body = cbor_loads(payload)
        body["subject"] = "fake-subject"
        new_payload = cbor_dumps(body)
        protected = {15: {1: "issuer-1", 2: "real-subject"}, 1: -8, 4: b"issuer-1"}
        protected_b = cbor_dumps(protected)
        sig = issuer.sign_bytes(cbor_dumps(["Signature1", protected_b, b"", new_payload]))
        mismatched = cbor_dumps([protected_b, {}, new_payload, sig])
        with pytest.raises(SCITTError, match="subject mismatch"):
            parse_statement(mismatched, trusted_issuers)

    def test_unknown_kid_rejected(self, issuer):
        stmt = make_statement(issuer)
        with pytest.raises(SCITTError, match="unknown kid"):
            parse_statement(stmt, {})

    def test_all_nine_types_known(self):
        assert KNOWN_STATEMENT_TYPES == frozenset(
            {
                STATEMENT_DECISION,
                "anchor.v1/approval",
                STATEMENT_MINT,
                STATEMENT_CONSUME,
                STATEMENT_EXECUTION,
                STATEMENT_REVOCATION,
                STATEMENT_FREEZE,
                STATEMENT_POLICY_CHANGE,
                STATEMENT_EPOCH,
            }
        )


# ---------------------------------------------------------------------------
# B. RFC 6962 Merkle tree
# ---------------------------------------------------------------------------


class TestMerkle:
    def test_single_leaf(self):
        leaves = [_leaf(b"a")]
        assert _mth(leaves) == leaves[0]
        assert _audit_path(leaves, 0) == []
        assert _root_from_proof(leaves[0], 0, [], 1) == leaves[0]

    def test_two_leaves(self):
        leaves = [_leaf(b"a"), _leaf(b"b")]
        root = _mth(leaves)
        assert root == hashlib.sha256(b"\x01" + leaves[0] + leaves[1]).digest()
        for i in range(2):
            proof = _audit_path(leaves, i)
            assert _root_from_proof(leaves[i], i, proof, 2) == root

    def test_audit_paths_all_sizes(self):
        for n in range(1, 9):
            leaves = [_leaf(f"leaf-{i}".encode()) for i in range(n)]
            root = _mth(leaves)
            for i in range(n):
                proof = _audit_path(leaves, i)
                assert _root_from_proof(leaves[i], i, proof, n) == root, (n, i)

    def test_wrong_leaf_fails(self):
        leaves = [_leaf(b"a"), _leaf(b"b"), _leaf(b"c")]
        root = _mth(leaves)
        proof = _audit_path(leaves, 0)
        assert _root_from_proof(_leaf(b"evil"), 0, proof, 3) != root

    def test_domain_separation(self):
        # A leaf hash can never equal a node hash for the same preimage.
        assert _leaf(b"x") != hashlib.sha256(b"\x01" + _leaf(b"x") + _leaf(b"x")).digest()


# ---------------------------------------------------------------------------
# C. transparency log + receipts
# ---------------------------------------------------------------------------


class TestTransparencyLog:
    def test_register_returns_verifiable_receipt(
        self, issuer, log, trusted_issuers, trusted_logs
    ):
        transparent, statement, receipt = transparent_bundle(
            issuer, log, trusted_issuers, trusted_logs
        )
        assert log.tree_size == 1
        result = verify_transparent_statement(transparent, trusted_issuers, trusted_logs)
        assert result["statement"]["subject"] == "action:abc123"
        assert result["statement"]["issuer"] == "issuer-1"
        assert len(result["receipts"]) == 1
        assert result["receipts"][0]["log_key_id"] == "scitt-log-1"
        assert result["receipts"][0]["leaf_index"] == 0
        assert result["receipts"][0]["tree_size"] == 1

    def test_receipt_wire_shape(self, issuer, log):
        statement = make_statement(issuer)
        receipt = log.register(statement)
        protected, unprotected, payload, _sig, _pb = _scitt_parse(receipt)
        assert payload is None  # detached
        assert protected[1] == -8
        assert protected[395] == 1  # vds = RFC9162_SHA256
        assert protected[15][1] == "scitt-log-1"
        assert protected[15][2] == hashlib.sha256(statement).hexdigest()
        vdp = unprotected[396]
        assert vdp["proof_type"] == -1
        assert vdp["leaf_index"] == 0 and vdp["tree_size"] == 1
        assert vdp["audit_path"] == []

    def test_append_only_earlier_receipts_still_verify(
        self, issuer, log, trusted_issuers, trusted_logs
    ):
        t1, _s1, _r1 = transparent_bundle(issuer, log, trusted_issuers, trusted_logs,
                                          subject="action:one")
        transparent_bundle(issuer, log, trusted_issuers, trusted_logs,
                           subject="action:two")
        transparent_bundle(issuer, log, trusted_issuers, trusted_logs,
                           subject="action:three")
        assert log.tree_size == 3
        # The FIRST statement's receipt still verifies after later appends.
        result = verify_transparent_statement(t1, trusted_issuers, trusted_logs)
        assert result["receipts"][0]["tree_size"] == 1
        assert len(result["receipts"]) == 1

    def test_registration_policy_refuses_type(self, issuer, log_signer):
        strict_log = LocalTransparencyLog(
            log_signer, allowed_types={STATEMENT_MINT}
        )
        with pytest.raises(SCITTError, match="refuses type"):
            strict_log.register(make_statement(issuer, stype=STATEMENT_DECISION))

    def test_custom_registration_policy_hook(self, issuer, log_signer):
        def no_bob(view):
            if view["claims"].get("user") == "bob":
                raise SCITTError("bob is not welcome")

        hooked = LocalTransparencyLog(log_signer, registration_policy=no_bob)
        hooked.register(make_statement(issuer, claims={"user": "alice"}))
        with pytest.raises(SCITTError, match="not welcome"):
            hooked.register(make_statement(issuer, claims={"user": "bob"}))

    def test_log_with_trusted_issuers_rejects_stranger(self, log_signer, trusted_issuers):
        stranger = Ed25519Signer.generate("stranger")
        strict_log = LocalTransparencyLog(log_signer, trusted_issuers=trusted_issuers)
        with pytest.raises(SCITTError, match="unknown kid"):
            strict_log.register(make_statement(stranger))

    def test_receipt_for_other_statement_rejected(
        self, issuer, log, trusted_issuers, trusted_logs
    ):
        s1 = make_statement(issuer, subject="action:one")
        s2 = make_statement(issuer, subject="action:two")
        r1 = log.register(s1)
        log.register(s2)
        # Attach s1's receipt to s2: the receipt's subject won't match.
        bad = add_receipt(s2, r1)
        with pytest.raises(SCITTError, match="not this statement's hash"):
            verify_transparent_statement(bad, trusted_issuers, trusted_logs)

    def test_empty_log_key_rejected(self):
        with pytest.raises(SCITTError, match="key id"):
            LocalTransparencyLog(Ed25519Signer.generate(""))


# ---------------------------------------------------------------------------
# D. transparent statements — adversarial
# ---------------------------------------------------------------------------


class TestTransparentStatements:
    def test_bare_statement_is_not_transparent(self, issuer, trusted_issuers, trusted_logs):
        with pytest.raises(SCITTError, match="no receipts"):
            verify_transparent_statement(
                make_statement(issuer), trusted_issuers, trusted_logs
            )

    def test_tampered_receipt_rejected(self, issuer, log, trusted_issuers, trusted_logs):
        transparent, _s, _r = transparent_bundle(
            issuer, log, trusted_issuers, trusted_logs
        )
        _p, unprotected, payload, sig, pb = _scitt_parse(transparent)
        receipts = list(unprotected[394])
        tampered_receipt = bytearray(receipts[0])
        tampered_receipt[-1] ^= 0xFF  # flip a signature byte
        bad = cbor_dumps([pb, {394: [bytes(tampered_receipt)]}, payload, sig])
        with pytest.raises(SCITTError):
            verify_transparent_statement(bad, trusted_issuers, trusted_logs)

    def test_receipt_with_wrong_vds_rejected(
        self, issuer, log, trusted_issuers, trusted_logs
    ):
        transparent, statement, _r = transparent_bundle(
            issuer, log, trusted_issuers, trusted_logs
        )
        _p, unprotected, _pl, _sg, _pb = _scitt_parse(transparent)
        receipt = unprotected[394][0]
        rprot, runprot, _rpl, _rsg, _rpb = _scitt_parse(receipt)
        rprot = dict(rprot)
        rprot[395] = 999  # unknown verifiable data structure
        # Re-signing with the log key keeps the sig valid so the vds check fires.
        from anchor_v1.scitt import _scitt_sign

        evil_log_signer = log._signer
        bad_receipt = _scitt_sign(
            payload=None, protected=rprot, unprotected=runprot,
            sign_fn=evil_log_signer.sign_bytes,
        )
        bad = add_receipt(statement, bad_receipt)
        with pytest.raises(SCITTError, match="vds must be 1"):
            verify_transparent_statement(bad, trusted_issuers, trusted_logs)

    def test_receipt_from_untrusted_log_rejected(
        self, issuer, log_signer, trusted_issuers, trusted_logs
    ):
        other_log = LocalTransparencyLog(Ed25519Signer.generate("rogue-log"))
        statement = make_statement(issuer)
        receipt = other_log.register(statement)
        transparent = add_receipt(statement, receipt)
        with pytest.raises(SCITTError, match="unknown kid"):
            verify_transparent_statement(transparent, trusted_issuers, trusted_logs)

    def test_tampered_statement_with_valid_receipt_rejected(
        self, issuer, log, trusted_issuers, trusted_logs
    ):
        transparent, _s, _r = transparent_bundle(
            issuer, log, trusted_issuers, trusted_logs
        )
        _p, unprotected, payload, sig, pb = _scitt_parse(transparent)
        body = cbor_loads(payload)
        body["claims"] = {"k": "tampered"}
        bad = cbor_dumps([pb, unprotected, cbor_dumps(body), sig])
        with pytest.raises(SCITTError, match="signature verification failed"):
            verify_transparent_statement(bad, trusted_issuers, trusted_logs)

    def test_multiple_receipts_from_independent_logs(
        self, issuer, log_signer, trusted_issuers
    ):
        log_a = LocalTransparencyLog(log_signer)
        signer_b = Ed25519Signer.generate("scitt-log-2")
        log_b = LocalTransparencyLog(signer_b)
        logs_trusted = {
            log_signer.key_id.encode(): Ed25519PublicKey.from_public_bytes(
                log_signer.public_key_bytes()
            ),
            signer_b.key_id.encode(): Ed25519PublicKey.from_public_bytes(
                signer_b.public_key_bytes()
            ),
        }
        statement = make_statement(issuer)
        t = add_receipt(statement, log_a.register(statement))
        t = add_receipt(t, log_b.register(statement))
        result = verify_transparent_statement(t, trusted_issuers, logs_trusted)
        assert {r["log_key_id"] for r in result["receipts"]} == {
            "scitt-log-1", "scitt-log-2",
        }

    def test_parse_statement_refuses_transparent_by_default(
        self, issuer, log, trusted_issuers, trusted_logs
    ):
        transparent, _s, _r = transparent_bundle(
            issuer, log, trusted_issuers, trusted_logs
        )
        with pytest.raises(SCITTError, match="verify_transparent_statement"):
            parse_statement(transparent, trusted_issuers)


# ---------------------------------------------------------------------------
# E. evidence mapping — ANCHOR events -> statements
# ---------------------------------------------------------------------------


def _lifecycle_setup():
    """Build a real decision->mint->consume chain for mapping tests."""
    auth = Ed25519Signer.generate("authority-1")
    holder = Ed25519Signer.generate("holder-1")
    store = CapabilityStore()
    store.sync_revocations()
    store.write_state({"acct:alice:balance": 500})
    from anchor_v1.envelope import ActionEnvelope, Effect
    import secrets, uuid

    envelope = ActionEnvelope(
        action_id=uuid.uuid4(),
        principal="agent-1",
        effect=Effect(
            plane="ledger", verb="transfer", target="ledger-1",
            args_digest=sha256_hex({"to": "bob", "amount": 100}),
        ),
        policy_ref="constitution-hash-abc",
        issued_at=NOW, not_before=NOW,
        not_after=NOW + timedelta(minutes=5),
        nonce=secrets.token_hex(16),
    )

    def policy(state, env):
        bal = state.get("acct:alice:balance") or 0
        return PolicyDecision(
            allowed=bal >= 100,
            outcome={"balance_after": bal - 100},
            planned_writes={"acct:alice:balance": bal - 100},
        )

    preview = prepare(
        store, envelope=envelope, read_keys=["acct:alice:balance"],
        policy_fn=policy, authority_signer=auth, now=NOW,
    )
    cose = authority.issue_execution(
        issuer=auth, action_digest=envelope.action_digest,
        holder_pubkey=holder.public_key_bytes(),
    )
    trusted = {
        auth.key_id.encode(): Ed25519PublicKey.from_public_bytes(auth.public_key_bytes())
    }
    payload = authority.verify_capability(cose, trusted, now=NOW)
    return auth, store, envelope, preview, payload, trusted


class TestEvidenceMapping:
    def test_decision_statement(self, issuer, trusted_issuers):
        _a, _s, envelope, preview, _p, _t = _lifecycle_setup()
        stmt = decision_statement(preview, issuer)
        view = parse_statement(stmt, trusted_issuers)
        assert view["statement_type"] == STATEMENT_DECISION
        assert view["subject"] == f"action:{envelope.action_digest}"
        assert view["claims"]["allowed"] is True
        assert view["claims"]["state_version"] == preview.state_version
        assert view["claims"]["preview_id"] == preview.preview_id

    def test_mint_and_consume_statements(self, issuer, trusted_issuers):
        _a, _s, envelope, _pv, payload, _t = _lifecycle_setup()
        mint_view = parse_statement(mint_statement(payload, issuer), trusted_issuers)
        assert mint_view["statement_type"] == STATEMENT_MINT
        assert mint_view["subject"] == f"action:{envelope.action_digest}"
        assert mint_view["claims"]["capability_id"] == payload.capability_id
        assert mint_view["claims"]["kind"] == payload.kind

        consume_view = parse_statement(
            consume_statement(payload, issuer, state_version=2), trusted_issuers
        )
        assert consume_view["statement_type"] == STATEMENT_CONSUME
        assert consume_view["claims"]["state_version"] == 2

    def test_execution_statement(self, issuer, trusted_issuers):
        from anchor_v1.mcp_gateway import ExecutionReceipt

        receipt = ExecutionReceipt(
            receipt_id="rcpt-1", tool_name="files.read", server_id="fs",
            args_digest=sha256_hex({"a": 1}),
            result_digest=sha256_hex({"content": "ok"}),
            capability_id="cap-1", executed_at=NOW, gateway_key_id="gw-1",
        )
        view = parse_statement(
            execution_statement(receipt, issuer, action_digest="digest-9"),
            trusted_issuers,
        )
        assert view["statement_type"] == STATEMENT_EXECUTION
        assert view["subject"] == "action:digest-9"
        assert view["claims"]["tool_name"] == "files.read"
        assert view["claims"]["receipt_id"] == "rcpt-1"

    def test_approval_statement(self, issuer, trusted_issuers):
        from anchor_v1.multisig_constitution import ActionReceipt

        ar = ActionReceipt(
            action="transfer", resource="ledger-1", constitution_hash="ch-1"
        )
        view = parse_statement(approval_statement(ar, issuer), trusted_issuers)
        assert view["statement_type"] == "anchor.v1/approval"
        assert view["claims"]["constitution_hash"] == "ch-1"

    def test_revocation_statement(self, issuer, trusted_issuers):
        view = parse_statement(
            revocation_statement(
                capability_id="cap-9", revoked_at=NOW.isoformat(), epoch=3,
                issuer=issuer,
            ),
            trusted_issuers,
        )
        assert view["statement_type"] == STATEMENT_REVOCATION
        assert view["subject"] == "capability:cap-9"
        assert view["claims"]["epoch"] == 3

    def test_full_lifecycle_transparent(
        self, issuer, log, trusted_issuers, trusted_logs
    ):
        """decision -> mint -> consume -> execution: every event becomes a
        transparent statement, all verifiable offline."""
        _a, _s, envelope, preview, payload, _t = _lifecycle_setup()
        from anchor_v1.mcp_gateway import ExecutionReceipt

        events = [
            decision_statement(preview, issuer),
            mint_statement(payload, issuer),
            consume_statement(payload, issuer, state_version=2),
            execution_statement(
                ExecutionReceipt(
                    receipt_id="rcpt-1", tool_name="transfer", server_id="ledger-1",
                    args_digest=envelope.effect.args_digest,
                    result_digest=sha256_hex({"ok": True}),
                    capability_id=payload.capability_id,
                    executed_at=NOW, gateway_key_id="gw-1",
                ),
                issuer,
                action_digest=envelope.action_digest,
            ),
        ]
        for stmt in events:
            transparent = add_receipt(stmt, log.register(stmt))
            result = verify_transparent_statement(
                transparent, trusted_issuers, trusted_logs
            )
            assert len(result["receipts"]) == 1
        assert log.tree_size == 4
        # All four share the action subject: an auditor can pull the full
        # evidence trail for one action_digest.
        subjects = {
            parse_statement(e, trusted_issuers, allow_receipts=True)["subject"]
            for e in events
        }
        assert subjects == {f"action:{envelope.action_digest}"}


# ---------------------------------------------------------------------------
# D. freeze / policy_change / epoch statements (Wave-4 spec gap fill)
# ---------------------------------------------------------------------------


class TestFreezePolicyEpochStatements:
    """Build, verify round-trip, and tamper rejection for the three statement
    types added to complete the 9-type SCITT mapping."""

    def test_freeze_statement_round_trip(self, issuer, trusted_issuers):
        stmt = freeze_statement(
            action_digest="abc123",
            reason="suspected fraud",
            frozen_at=NOW.isoformat(),
            epoch=2,
            issuer=issuer,
        )
        view = parse_statement(stmt, trusted_issuers)
        assert view["statement_type"] == STATEMENT_FREEZE
        assert view["subject"] == "action:abc123"
        assert view["claims"]["reason"] == "suspected fraud"
        assert view["claims"]["epoch"] == 2

    def test_policy_change_statement_round_trip(self, issuer, trusted_issuers):
        stmt = policy_change_statement(
            constitution_hash="ch-2",
            previous_hash="ch-1",
            changed_at=NOW.isoformat(),
            epoch=3,
            issuer=issuer,
        )
        view = parse_statement(stmt, trusted_issuers)
        assert view["statement_type"] == STATEMENT_POLICY_CHANGE
        assert view["subject"] == "policy:constitution"
        assert view["claims"]["constitution_hash"] == "ch-2"
        assert view["claims"]["previous_hash"] == "ch-1"

    def test_epoch_statement_round_trip(self, issuer, trusted_issuers):
        stmt = epoch_statement(epoch=4, started_at=NOW.isoformat(), issuer=issuer)
        view = parse_statement(stmt, trusted_issuers)
        assert view["statement_type"] == STATEMENT_EPOCH
        assert view["subject"] == "epoch:4"
        assert view["claims"]["epoch"] == 4

    def test_tampered_new_statements_rejected(self, issuer, trusted_issuers):
        statements = [
            freeze_statement(
                action_digest="d", reason="r",
                frozen_at=NOW.isoformat(), epoch=1, issuer=issuer,
            ),
            policy_change_statement(
                constitution_hash="c", previous_hash=None,
                changed_at=NOW.isoformat(), epoch=1, issuer=issuer,
            ),
            epoch_statement(epoch=1, started_at=NOW.isoformat(), issuer=issuer),
        ]
        for stmt in statements:
            _protected, unprotected, payload, sig, protected_bytes = _scitt_parse(
                stmt
            )
            body = cbor_loads(payload)
            body["claims"]["epoch"] = 9_999_999
            forged = cbor_dumps(
                [protected_bytes, unprotected, cbor_dumps(body), sig]
            )
            with pytest.raises(SCITTError, match="signature verification failed"):
                parse_statement(forged, trusted_issuers)
