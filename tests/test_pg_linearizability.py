"""Multi-process linearizability tests for PgCapabilityStore (real PostgreSQL).

Each test spawns N worker *processes* (spawn context); every worker opens
its own ``PgCapabilityStore`` connection — simulating N independent nodes.
The database is the ONLY serialization point: there is no shared RLock.

What is verified:
  * double-spend race: N processes race one capability -> exactly 1 winner.
  * budget race: N processes race mandate debits -> budget never oversubscribed.
  * revoke ordering: revoke-before-consume denies; consume-before-revoke is
    stable; a true revoke-vs-consume race never double-spends and never
    consumes after a committed revoke.
  * scale: M capabilities x N workers attempting all -> exactly M wins.

Requires PostgreSQL. Resolution order:
  1. ``ANCHOR_PG_DSN`` env var (e.g. postgresql://user@host/db), or
  2. the ``pgserver`` package (embedded Postgres; used in this environment).

Skipped cleanly when neither is available.
"""

from __future__ import annotations

import hashlib
import multiprocessing as mp
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from anchor_v1 import authority
from anchor_v1.authority import KIND_EXECUTION, issue_execution, make_holder_proof
from anchor_v1.crypto import Ed25519Signer
from anchor_v1.store import (
    AuthorizationDenied,
    BudgetExceededError,
    DoubleSpendError,
    MandateLifecycle,
    RevokedError,
)

# ---------------------------------------------------------------------------
# Postgres availability
# ---------------------------------------------------------------------------


def _resolve_pg():
    """Return (dsn, owns_server, server_handle) or None if unavailable."""
    dsn = os.environ.get("ANCHOR_PG_DSN")
    if dsn:
        return dsn, False, None
    try:
        import pgserver
    except ImportError:
        return None
    try:
        srv = pgserver.get_server("/tmp/pgdata")
        return srv.get_uri(), True, srv
    except Exception:
        return None


_PG = _resolve_pg()
NEEDS_PG = pytest.mark.skipif(
    _PG is None, reason="PostgreSQL not available (set ANCHOR_PG_DSN or install pgserver)"
)

CTX = mp.get_context("spawn")
N_WORKERS = 8


@pytest.fixture(scope="session")
def pg_base_dsn():
    assert _PG is not None
    return _PG[0]


@pytest.fixture()
def pg_dsn(pg_base_dsn):
    """Fresh database per test, with schema created by PgCapabilityStore."""
    import psycopg

    from anchor_v1.pg_store import PgCapabilityStore

    dbname = f"anchor_lin_{uuid.uuid4().hex[:12]}"
    admin = psycopg.connect(pg_base_dsn, autocommit=True)
    try:
        admin.execute(f'CREATE DATABASE "{dbname}"')
    finally:
        admin.close()
    # pgserver DSN: postgresql://postgres:@/postgres?host=/tmp/pgdata
    # -> swap dbname. Generic DSNs: append/replace path naively.
    if "?" in pg_base_dsn:
        base, _, query = pg_base_dsn.partition("?")
        head = base.rsplit("/", 1)[0]
        dsn = f"{head}/{dbname}?{query}"
    else:
        head = pg_base_dsn.rsplit("/", 1)[0]
        dsn = f"{head}/{dbname}"
    store = PgCapabilityStore(dsn)  # creates schema
    store.close()
    yield dsn
    admin = psycopg.connect(pg_base_dsn, autocommit=True)
    try:
        admin.execute(f'DROP DATABASE IF EXISTS "{dbname}" WITH (FORCE)')
    finally:
        admin.close()


# ---------------------------------------------------------------------------
# helpers (parent side)
# ---------------------------------------------------------------------------


def _trusted_of(issuer: Ed25519Signer):
    return (
        issuer.key_id.encode("utf-8"),
        issuer.public_key_bytes(),
    )


def _issue_registered(store, issuer, holder, digest, **kw):
    cose = issue_execution(
        issuer,
        action_digest=digest,
        holder_pubkey=holder.public_key_bytes(),
        max_revocation_staleness=kw.get("staleness", 3600),
    )
    payload = authority.verify_capability(cose, _trusted_dict(issuer))
    store.register_capability(payload)
    return cose, payload


def _trusted_dict(issuer: Ed25519Signer):
    kid, pub = _trusted_of(issuer)
    return {kid: Ed25519PublicKey.from_public_bytes(pub)}


def _new_keys():
    issuer = Ed25519Signer.generate("authority-pg")
    holder = Ed25519Signer.generate("holder-pg")
    return issuer, holder


# ---------------------------------------------------------------------------
# workers (module level: must be picklable for spawn)
# ---------------------------------------------------------------------------


def _worker_consume(dsn, cap_id, cose, proof, challenge, kid, pub, start_evt, q):
    try:
        from anchor_v1.pg_store import PgCapabilityStore
        from anchor_v1.store import DoubleSpendError as DSE
        from anchor_v1.store import RevokedError as RE

        trusted = {kid: Ed25519PublicKey.from_public_bytes(pub)}
        store = PgCapabilityStore(dsn)
        try:
            assert start_evt.wait(timeout=60)
            try:
                store.consume_capability(
                    capability_cose=cose,
                    holder_proof=proof,
                    challenge=challenge,
                    trusted_issuers=trusted,
                )
                q.put(("win", cap_id))
            except DSE:
                q.put(("double_spend", cap_id))
            except RE:
                q.put(("revoked", cap_id))
        finally:
            store.close()
    except Exception as exc:  # noqa: BLE001 - any surprise is a test failure
        q.put(("error", f"{type(exc).__name__}: {exc}"))


def _worker_debit(dsn, mandate_id, reserve, start_evt, q):
    try:
        from anchor_v1.pg_store import PgCapabilityStore
        from anchor_v1.store import BudgetExceededError as BEE

        store = PgCapabilityStore(dsn)
        try:
            assert start_evt.wait(timeout=60)
            try:
                store.debit_mandate_for_child(mandate_id, reserve)
                q.put(("win", reserve))
            except BEE:
                q.put(("budget_denied", reserve))
        finally:
            store.close()
    except Exception as exc:  # noqa: BLE001
        q.put(("error", f"{type(exc).__name__}: {exc}"))


def _worker_revoke(dsn, target_id, start_evt, q):
    try:
        from anchor_v1.pg_store import PgCapabilityStore

        store = PgCapabilityStore(dsn)
        try:
            assert start_evt.wait(timeout=60)
            store.revoke(target_id)
            q.put(("revoked", target_id))
        finally:
            store.close()
    except Exception as exc:  # noqa: BLE001
        q.put(("error", f"{type(exc).__name__}: {exc}"))


def _worker_consume_all(dsn, caps, challenge, kid, pub, start_evt, q):
    """One worker attempts every capability in `caps` sequentially."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        from anchor_v1.pg_store import PgCapabilityStore
        from anchor_v1.store import DoubleSpendError as DSE

        trusted = {kid: Ed25519PublicKey.from_public_bytes(pub)}
        store = PgCapabilityStore(dsn)
        try:
            assert start_evt.wait(timeout=60)
            my_wins = 0
            for cap_id, cose, proof in caps:
                try:
                    store.consume_capability(
                        capability_cose=cose,
                        holder_proof=proof,
                        challenge=challenge,
                        trusted_issuers=trusted,
                    )
                    my_wins += 1
                except DSE:
                    pass
            q.put(("done", my_wins))
        finally:
            store.close()
    except Exception as exc:  # noqa: BLE001
        q.put(("error", f"{type(exc).__name__}: {exc}"))


def _run_workers(target, args_list, timeout=180):
    """Spawn one process per args tuple; return list of queue results."""
    start_evt = CTX.Event()
    q = CTX.Queue()
    procs = [CTX.Process(target=target, args=(a + (start_evt, q))) for a in args_list]
    for p in procs:
        p.start()
    start_evt.set()
    for p in procs:
        p.join(timeout=timeout)
        if p.is_alive():
            p.terminate()
            p.join()
            raise AssertionError(f"worker {p.pid} hung (terminated)")
    results = []
    while not q.empty():
        results.append(q.get())
    assert len(results) == len(args_list), (
        f"lost worker results: got {len(results)}, expected {len(args_list)}"
    )
    errors = [r for r in results if r[0] == "error"]
    assert not errors, f"unexpected worker errors: {errors}"
    return results


# ---------------------------------------------------------------------------
# tests
# ---------------------------------------------------------------------------


@NEEDS_PG
def test_pg_double_spend_race(pg_dsn):
    """8 processes race one capability: exactly one winner, no double-spend."""
    from anchor_v1.pg_store import PgCapabilityStore

    issuer, holder = _new_keys()
    kid, pub = _trusted_of(issuer)
    challenge = secrets.token_bytes(16)
    digest = hashlib.sha256(b"pg-double-spend").hexdigest()

    store = PgCapabilityStore(pg_dsn)
    try:
        cose, payload = _issue_registered(store, issuer, holder, digest)
        proof = make_holder_proof(holder, payload.capability_id, challenge)
    finally:
        store.close()

    args = [
        (pg_dsn, payload.capability_id, cose, proof, challenge, kid, pub)
        for _ in range(N_WORKERS)
    ]
    results = _run_workers(_worker_consume, args)

    wins = [r for r in results if r[0] == "win"]
    denied = [r for r in results if r[0] == "double_spend"]
    assert len(wins) == 1, f"expected exactly 1 winner, got {len(wins)}: {results}"
    assert len(denied) == N_WORKERS - 1

    store = PgCapabilityStore(pg_dsn)
    try:
        assert store.capability_state(payload.capability_id) == "CONSUMED"
    finally:
        store.close()


@NEEDS_PG
def test_pg_budget_race(pg_dsn):
    """8 processes race debits of 30 against spend_limit=100.

    Exactly 3 win (90 reserved); the 4th would oversubscribe (120 > 100).
    spend_used must never exceed the limit.
    """
    from anchor_v1.pg_store import PgCapabilityStore

    store = PgCapabilityStore(pg_dsn)
    try:
        store.create_mandate("m-pg-budget", spend_limit=100, actions_limit=1000)
        store.transition_mandate("m-pg-budget", MandateLifecycle.ACTIVE)
    finally:
        store.close()

    args = [(pg_dsn, "m-pg-budget", 30) for _ in range(N_WORKERS)]
    results = _run_workers(_worker_debit, args)

    wins = [r for r in results if r[0] == "win"]
    denied = [r for r in results if r[0] == "budget_denied"]
    assert len(wins) == 3, f"expected exactly 3 winners, got {len(wins)}: {results}"
    assert len(denied) == N_WORKERS - 3

    store = PgCapabilityStore(pg_dsn)
    try:
        m = store.get_mandate("m-pg-budget")
        assert m["spend_used"] == 90, f"spend_used={m['spend_used']}, expected 90"
        assert m["spend_used"] <= 100, "BUDGET OVERSUBSCRIBED"
    finally:
        store.close()


@NEEDS_PG
def test_pg_revoke_before_consume_denies(pg_dsn):
    """Deterministic ordering: committed revoke -> consume must fail."""
    from anchor_v1.pg_store import PgCapabilityStore

    issuer, holder = _new_keys()
    challenge = secrets.token_bytes(16)
    digest = hashlib.sha256(b"pg-revoke-first").hexdigest()

    store = PgCapabilityStore(pg_dsn)
    try:
        cose, payload = _issue_registered(store, issuer, holder, digest)
        proof = make_holder_proof(holder, payload.capability_id, challenge)
        store.revoke(payload.capability_id)
        with pytest.raises(RevokedError):
            store.consume_capability(
                capability_cose=cose,
                holder_proof=proof,
                challenge=challenge,
                trusted_issuers=_trusted_dict(issuer),
            )
        assert store.capability_state(payload.capability_id) == "ISSUED"
    finally:
        store.close()


@NEEDS_PG
def test_pg_consume_before_revoke_stable(pg_dsn):
    """Deterministic ordering: consume wins -> later revoke is harmless."""
    from anchor_v1.pg_store import PgCapabilityStore

    issuer, holder = _new_keys()
    challenge = secrets.token_bytes(16)
    digest = hashlib.sha256(b"pg-consume-first").hexdigest()

    store = PgCapabilityStore(pg_dsn)
    try:
        cose, payload = _issue_registered(store, issuer, holder, digest)
        proof = make_holder_proof(holder, payload.capability_id, challenge)
        store.consume_capability(
            capability_cose=cose,
            holder_proof=proof,
            challenge=challenge,
            trusted_issuers=_trusted_dict(issuer),
        )
        store.revoke(payload.capability_id)  # revoking a consumed cap: no-op semantically
        assert store.capability_state(payload.capability_id) == "CONSUMED"
        assert store.is_revoked(payload.capability_id)
    finally:
        store.close()


@NEEDS_PG
def test_pg_revoke_vs_consume_race(pg_dsn):
    """True race: 7 consumers + 1 revoker start together.

    Linearizability demands: at most one consume wins; if nobody wins the
    capability is still ISSUED *and* revoked (no consume-after-revoke).
    """
    from anchor_v1.pg_store import PgCapabilityStore

    issuer, holder = _new_keys()
    kid, pub = _trusted_of(issuer)
    challenge = secrets.token_bytes(16)
    digest = hashlib.sha256(b"pg-revoke-race").hexdigest()

    store = PgCapabilityStore(pg_dsn)
    try:
        cose, payload = _issue_registered(store, issuer, holder, digest)
        proof = make_holder_proof(holder, payload.capability_id, challenge)
        cap_id = payload.capability_id
    finally:
        store.close()

    start_evt = CTX.Event()
    q = CTX.Queue()
    procs = [
        CTX.Process(
            target=_worker_consume,
            args=(pg_dsn, cap_id, cose, proof, challenge, kid, pub, start_evt, q),
        )
        for _ in range(7)
    ]
    procs.append(
        CTX.Process(
            target=_worker_revoke, args=(pg_dsn, cap_id, start_evt, q)
        )
    )
    for p in procs:
        p.start()
    start_evt.set()
    for p in procs:
        p.join(timeout=180)
        if p.is_alive():
            p.terminate()
            p.join()
            raise AssertionError("worker hung")
    results = []
    while not q.empty():
        results.append(q.get())
    assert len(results) == 8, f"lost results: {results}"
    assert not [r for r in results if r[0] == "error"], results

    wins = [r for r in results if r[0] == "win"]
    assert len(wins) <= 1, f"DOUBLE SPEND under revoke race: {results}"

    store = PgCapabilityStore(pg_dsn)
    try:
        state = store.capability_state(cap_id)
        revoked = store.is_revoked(cap_id)
        assert revoked, "revoker must have committed"
        if wins:
            assert state == "CONSUMED"  # consume linearized before revoke
        else:
            # revoke linearized first: every consume saw it (or lost the race
            # to a serialization abort and then saw it on retry)
            assert state == "ISSUED", f"consume-after-revoke? state={state}"
    finally:
        store.close()


@NEEDS_PG
def test_pg_many_capabilities_no_double_spend(pg_dsn):
    """40 capabilities, 8 workers each attempting all 40.

    Exactly 40 total wins; every capability ends CONSUMED exactly once.
    Stresses serializable abort/retry rates under contention.
    """
    from anchor_v1.pg_store import PgCapabilityStore

    issuer, holder = _new_keys()
    kid, pub = _trusted_of(issuer)
    challenge = secrets.token_bytes(16)

    store = PgCapabilityStore(pg_dsn)
    caps = []
    try:
        for i in range(40):
            digest = hashlib.sha256(f"pg-scale-{i}".encode()).hexdigest()
            cose, payload = _issue_registered(store, issuer, holder, digest)
            proof = make_holder_proof(holder, payload.capability_id, challenge)
            caps.append((payload.capability_id, cose, proof))
    finally:
        store.close()

    # One worker per (capability) would be 320 procs; instead each of the 8
    # workers attempts every capability sequentially in its own process.
    args = [(pg_dsn, caps, challenge, kid, pub) for _ in range(N_WORKERS)]
    results = _run_workers(_worker_consume_all, args, timeout=300)
    total_wins = sum(r[1] for r in results if r[0] == "done")
    assert total_wins == 40, f"expected 40 total wins, got {total_wins}: {results}"

    store = PgCapabilityStore(pg_dsn)
    try:
        for cap_id, _, _ in caps:
            assert store.capability_state(cap_id) == "CONSUMED", cap_id
    finally:
        store.close()
