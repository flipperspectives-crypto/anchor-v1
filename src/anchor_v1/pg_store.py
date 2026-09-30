"""ANCHOR v1 — PostgreSQL-backed CapabilityStore (multi-node linearizability PoC).

This is a faithful port of :mod:`anchor_v1.store`'s linearizability-critical
paths from SQLite to PostgreSQL. It exists to answer one question:

    *Do the store's linearizability claims hold when the process-wide RLock
    is gone — i.e. with N independent processes ("nodes") hitting one
    Postgres?*

Adaptations from the SQLite design (``store.py``):

* ``BEGIN IMMEDIATE`` (SQLite's single-writer lock) becomes
  ``SERIALIZABLE`` transactions. Every critical section runs at
  ``ISOLATION LEVEL SERIALIZABLE`` and retries on
  ``serialization_failure`` (40001) / ``deadlock_detected`` (40P01) with
  exponential backoff. The guarded ``UPDATE ... WHERE state='ISSUED'``
  predicates are kept verbatim — Postgres re-evaluates ``WHERE`` on the
  latest committed row version after a lock wait (EvalPlanQual), so the
  guards remain the last line of defense even if isolation were weakened.
* The process-wide ``threading.RLock`` is NOT a correctness mechanism here.
  Each ``PgCapabilityStore`` owns one connection; separate processes (the
  actual multi-node case) never share it. A small lock is kept only because
  a psycopg connection must not be used concurrently from two threads.
* Schema: ``BLOB`` -> ``BYTEA``, ``INTEGER PRIMARY KEY AUTOINCREMENT`` ->
  ``SERIAL PRIMARY KEY``, ``?`` placeholders -> ``%s``,
  ``last_insert_rowid()`` -> ``RETURNING id``.
* ``sqlite3.IntegrityError`` -> ``psycopg.errors.UniqueViolation``.
* Retry is implemented as ``_run_serializable(fn)`` taking a callback —
  NOT a ``@contextmanager`` generator: a generator-based context manager
  may only yield once, so a retry loop inside one raises ``RuntimeError:
  generator didn't stop after throw()`` on the first retry.

What this port covers: schema, capability registration, mandate lifecycle,
``sync_revocations``/``revoke``, ``debit_mandate_for_child`` (budget race),
and the full ``consume_capability`` critical section (steps 1-11, including
the revocation predicate read that *requires* SERIALIZABLE — at
READ COMMITTED a concurrent ``revoke()`` could slip between the check and
the commit).

Deliberately out of scope for the PoC: ``read_state``/``write_state``/
``commit_state_bound`` (TOCTOU state binding) and ``check_capability``.
They are mechanical ports of the same pattern; see the report for details.

Do NOT use in production without review — this is a test harness.
"""

from __future__ import annotations

import json
import random
import threading
import time
from datetime import datetime, timezone
from typing import Callable, Mapping, TypeVar

import psycopg
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from psycopg import IsolationLevel, errors
from psycopg.rows import dict_row

from . import authority
from .authority import CapabilityError, CapabilityPayload
from .envelope import ActionEnvelope
from .store import (
    AuthorizationDenied,
    BudgetExceededError,
    DoubleSpendError,
    LifecycleError,
    MandateLifecycle,
    RevokedError,
    StaleRevocationError,
    StoreError,
    UnknownCapabilityError,
    LEGAL_TRANSITIONS,
)

__all__ = ["PgCapabilityStore", "MAX_TXN_ATTEMPTS"]

#: Serialization-retry budget per critical section.
MAX_TXN_ATTEMPTS = 8

#: SQLSTATEs that are safe to retry with a fresh transaction.
_RETRYABLE = (
    errors.SerializationFailure,  # 40001
    errors.DeadlockDetected,  # 40P01
)

# NOTE: mandates is created before capabilities — Postgres (unlike SQLite)
# validates the REFERENCES target at CREATE TABLE time.
_PG_SCHEMA = """
CREATE TABLE IF NOT EXISTS mandates (
    id              TEXT PRIMARY KEY,
    lifecycle       TEXT NOT NULL DEFAULT 'CREATED',
    spend_used      INTEGER NOT NULL DEFAULT 0,
    spend_limit     INTEGER,
    actions_used    INTEGER NOT NULL DEFAULT 0,
    actions_limit   INTEGER,
    recipients_json TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS capabilities (
    id                      TEXT PRIMARY KEY,
    action_digest           TEXT NOT NULL,
    holder_pubkey           BYTEA NOT NULL,
    kind                    TEXT NOT NULL,
    state                   TEXT NOT NULL DEFAULT 'ISSUED',
    spend_limit             INTEGER,
    spend_asset             TEXT,
    issued_at               TEXT NOT NULL,
    expires_at              TEXT NOT NULL,
    consumed_at             TEXT,
    spend_consumed          INTEGER NOT NULL DEFAULT 0,
    mandate_id              TEXT REFERENCES mandates(id),
    max_revocation_staleness_s INTEGER NOT NULL DEFAULT 300
);
CREATE TABLE IF NOT EXISTS revocations (
    id          TEXT PRIMARY KEY,
    revoked_at  TEXT NOT NULL,
    epoch       INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS epochs (
    id          SERIAL PRIMARY KEY,
    started_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (
    key     TEXT PRIMARY KEY,
    value   TEXT NOT NULL
);
"""

T = TypeVar("T")


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class PgCapabilityStore:
    """Postgres-backed capability store. See module docstring."""

    def __init__(self, dsn: str) -> None:
        # One connection per store instance. Separate processes => separate
        # connections => the DB (not a process lock) is the serialization
        # point. That is exactly the multi-node property under test.
        self._conn = psycopg.connect(dsn, row_factory=dict_row, autocommit=False)
        self._conn.isolation_level = IsolationLevel.SERIALIZABLE
        # Connection thread-safety only — NOT a correctness mechanism.
        self._iolock = threading.Lock()

        def _init(cur: psycopg.Cursor) -> None:
            cur.execute(_PG_SCHEMA)
            cur.execute(
                "SELECT value FROM meta WHERE key = 'last_revocation_sync_at'"
            )
            if cur.fetchone() is None:
                cur.execute(
                    "INSERT INTO meta (key, value) VALUES ('last_revocation_sync_at', %s)",
                    (repr(time.time()),),
                )
            cur.execute("SELECT COUNT(*) AS n FROM epochs")
            if cur.fetchone()["n"] == 0:
                cur.execute(
                    "INSERT INTO epochs (started_at) VALUES (%s)", (_utcnow_iso(),)
                )

        self._run_serializable(_init)

    def close(self) -> None:
        with self._iolock:
            self._conn.close()

    # -- transactions -----------------------------------------------------

    def _run_serializable(
        self, fn: Callable[[psycopg.Cursor], T], *, max_attempts: int = MAX_TXN_ATTEMPTS
    ) -> T:
        """Run ``fn(cur)`` as one SERIALIZABLE transaction, retrying the whole
        body on serialization failures / deadlocks with exponential backoff."""
        attempt = 0
        while True:
            attempt += 1
            try:
                with self._iolock, self._conn.transaction():
                    with self._conn.cursor() as cur:
                        return fn(cur)
            except _RETRYABLE as exc:
                # transaction() already rolled back; sleep, then retry.
                if attempt >= max_attempts:
                    raise StoreError(
                        f"transaction aborted after {max_attempts} "
                        f"serialization retries: {exc}"
                    ) from exc
                time.sleep(min(0.01 * (2**attempt), 0.5) * (0.5 + random.random()))

    # -- revocation view ----------------------------------------------------

    def sync_revocations(
        self, revoked_ids: list[str] | None = None, *, now: float | None = None
    ) -> int:
        when = time.time() if now is None else float(now)

        def _go(cur: psycopg.Cursor) -> int:
            cur.execute(
                "INSERT INTO epochs (started_at) VALUES (%s) RETURNING id",
                (_utcnow_iso(),),
            )
            epoch = int(cur.fetchone()["id"])
            for rid in revoked_ids or []:
                cur.execute(
                    "INSERT INTO revocations (id, revoked_at, epoch) VALUES (%s, %s, %s) "
                    "ON CONFLICT(id) DO NOTHING",
                    (rid, _utcnow_iso(), epoch),
                )
            cur.execute(
                "INSERT INTO meta (key, value) VALUES ('last_revocation_sync_at', %s) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (repr(when),),
            )
            return epoch

        return self._run_serializable(_go)

    def revoke(self, capability_or_mandate_id: str) -> int:
        return self.sync_revocations([capability_or_mandate_id])

    def is_revoked(self, capability_or_mandate_id: str) -> bool:
        def _go(cur: psycopg.Cursor) -> bool:
            cur.execute(
                "SELECT 1 FROM revocations WHERE id = %s",
                (capability_or_mandate_id,),
            )
            return cur.fetchone() is not None

        return self._run_serializable(_go)

    @staticmethod
    def _last_sync(cur: psycopg.Cursor) -> float:
        cur.execute("SELECT value FROM meta WHERE key = 'last_revocation_sync_at'")
        row = cur.fetchone()
        return float(row["value"]) if row else 0.0

    # -- mandates ------------------------------------------------------------

    def create_mandate(
        self,
        mandate_id: str,
        *,
        spend_limit: int | None = None,
        actions_limit: int | None = None,
        recipients: list[str] | None = None,
    ) -> None:
        if spend_limit is not None and (
            isinstance(spend_limit, bool) or spend_limit < 0
        ):
            raise StoreError("spend_limit must be a non-negative int or None")
        if actions_limit is not None and (
            isinstance(actions_limit, bool) or actions_limit < 0
        ):
            raise StoreError("actions_limit must be a non-negative int or None")

        def _go(cur: psycopg.Cursor) -> None:
            try:
                cur.execute(
                    "INSERT INTO mandates (id, lifecycle, spend_limit, actions_limit, recipients_json)"
                    " VALUES (%s, 'CREATED', %s, %s, %s)",
                    (
                        mandate_id,
                        spend_limit,
                        actions_limit,
                        json.dumps(recipients or []),
                    ),
                )
            except errors.UniqueViolation as exc:
                raise StoreError(f"mandate {mandate_id!r} already exists") from exc

        self._run_serializable(_go)

    def get_mandate(self, mandate_id: str) -> dict:
        def _go(cur: psycopg.Cursor) -> dict:
            cur.execute("SELECT * FROM mandates WHERE id = %s", (mandate_id,))
            row = cur.fetchone()
            if row is None:
                raise StoreError(f"unknown mandate {mandate_id!r}")
            return dict(row)

        return self._run_serializable(_go)

    def transition_mandate(self, mandate_id: str, new_lifecycle: str) -> None:
        def _go(cur: psycopg.Cursor) -> None:
            cur.execute(
                "SELECT lifecycle FROM mandates WHERE id = %s", (mandate_id,)
            )
            row = cur.fetchone()
            if row is None:
                raise StoreError(f"unknown mandate {mandate_id!r}")
            current = row["lifecycle"]
            if new_lifecycle not in LEGAL_TRANSITIONS.get(current, frozenset()):
                raise LifecycleError(
                    f"illegal mandate transition {current} -> {new_lifecycle}"
                )
            cur.execute(
                "UPDATE mandates SET lifecycle = %s WHERE id = %s",
                (new_lifecycle, mandate_id),
            )

        self._run_serializable(_go)

    # -- capability registration ---------------------------------------------

    def register_capability(
        self, payload: CapabilityPayload, *, mandate_id: str | None = None
    ) -> None:
        def _go(cur: psycopg.Cursor) -> None:
            if mandate_id is not None:
                cur.execute("SELECT 1 FROM mandates WHERE id = %s", (mandate_id,))
                if cur.fetchone() is None:
                    raise StoreError(f"unknown mandate {mandate_id!r}")
            try:
                cur.execute(
                    "INSERT INTO capabilities (id, action_digest, holder_pubkey, kind,"
                    " state, spend_limit, spend_asset, issued_at, expires_at,"
                    " mandate_id, max_revocation_staleness_s)"
                    " VALUES (%s, %s, %s, %s, 'ISSUED', %s, %s, %s, %s, %s, %s)",
                    (
                        payload.capability_id,
                        payload.action_digest,
                        bytes(payload.holder_pubkey),
                        payload.kind,
                        payload.spend_limit,
                        payload.spend_asset,
                        payload.issued_at,
                        payload.expires_at,
                        mandate_id,
                        payload.max_revocation_staleness,
                    ),
                )
            except errors.UniqueViolation as exc:
                raise StoreError(
                    f"capability {payload.capability_id!r} already registered"
                ) from exc

        self._run_serializable(_go)

    def capability_state(self, capability_id: str) -> str:
        def _go(cur: psycopg.Cursor) -> str:
            cur.execute(
                "SELECT state FROM capabilities WHERE id = %s", (capability_id,)
            )
            row = cur.fetchone()
            if row is None:
                raise UnknownCapabilityError(capability_id)
            return row["state"]

        return self._run_serializable(_go)

    # -- mint-child budget debit ----------------------------------------------

    def debit_mandate_for_child(
        self, mandate_id: str, child_spend_limit: int | None
    ) -> None:
        reserve = child_spend_limit or 0
        if isinstance(reserve, bool) or reserve < 0:
            raise BudgetExceededError("child spend_limit must be a non-negative int")

        def _go(cur: psycopg.Cursor) -> None:
            cur.execute(
                "UPDATE mandates SET spend_used = spend_used + %s,"
                " actions_used = actions_used + 1"
                " WHERE id = %s AND lifecycle = 'ACTIVE'"
                " AND (spend_limit IS NULL OR spend_used + %s <= spend_limit)"
                " AND (actions_limit IS NULL OR actions_used + 1 <= actions_limit)",
                (reserve, mandate_id, reserve),
            )
            if cur.rowcount == 0:
                cur.execute(
                    "SELECT lifecycle, spend_used, spend_limit, actions_used, actions_limit"
                    " FROM mandates WHERE id = %s",
                    (mandate_id,),
                )
                row = cur.fetchone()
                if row is None:
                    raise StoreError(f"unknown mandate {mandate_id!r}")
                if row["lifecycle"] != MandateLifecycle.ACTIVE:
                    raise AuthorizationDenied(
                        f"cannot mint child: mandate {mandate_id} is {row['lifecycle']}"
                    )
                raise BudgetExceededError(
                    f"mandate {mandate_id} budget oversubscribed by child mint"
                )

        self._run_serializable(_go)

    # -- consumption: the linearizable critical section -----------------------

    def consume_capability(
        self,
        *,
        capability_cose: bytes,
        holder_proof: bytes,
        challenge: bytes,
        trusted_issuers: Mapping[bytes, Ed25519PublicKey],
        envelope: ActionEnvelope | None = None,
        spend_amount: int = 0,
        now: datetime | None = None,
    ) -> CapabilityPayload:
        if isinstance(spend_amount, bool) or not isinstance(spend_amount, int):
            raise AuthorizationDenied("spend_amount must be an integer")
        if spend_amount < 0:
            raise AuthorizationDenied("spend_amount must be >= 0")
        moment = now if now is not None else datetime.now(timezone.utc)
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)

        def _go(cur: psycopg.Cursor) -> CapabilityPayload:
            return self._consume_inner(
                cur,
                capability_cose=capability_cose,
                holder_proof=holder_proof,
                challenge=challenge,
                trusted_issuers=trusted_issuers,
                envelope=envelope,
                spend_amount=spend_amount,
                moment=moment,
            )

        return self._run_serializable(_go)

    def _consume_inner(
        self,
        cur: psycopg.Cursor,
        *,
        capability_cose: bytes,
        holder_proof: bytes,
        challenge: bytes,
        trusted_issuers: Mapping[bytes, Ed25519PublicKey],
        envelope: ActionEnvelope | None,
        spend_amount: int,
        moment: datetime,
    ) -> CapabilityPayload:
        # (1) Stateless verification: COSE signature + structural checks.
        try:
            payload = authority.verify_capability(
                capability_cose, trusted_issuers, now=moment
            )
        except CapabilityError as exc:
            raise AuthorizationDenied(f"capability verification failed: {exc}") from exc

        # (2) The capability must be registered with this store.
        cur.execute(
            "SELECT * FROM capabilities WHERE id = %s", (payload.capability_id,)
        )
        row = cur.fetchone()
        if row is None:
            raise UnknownCapabilityError(
                f"capability {payload.capability_id!r} not registered"
            )

        # (3) Presented bytes must match the registered record.
        if bytes(row["holder_pubkey"]) != bytes(payload.holder_pubkey):
            raise AuthorizationDenied("holder key does not match registered capability")
        if row["action_digest"] != payload.action_digest:
            raise AuthorizationDenied("action digest does not match registered capability")
        if row["kind"] != payload.kind:
            raise AuthorizationDenied("kind does not match registered capability")

        # (4) Envelope binding.
        if envelope is not None and envelope.action_digest != payload.action_digest:
            raise AuthorizationDenied(
                "envelope action_digest does not match capability binding"
            )

        # (5) Revocation: capability id or its mandate id in the revocation set.
        # NOTE: this predicate read is exactly why the transaction is
        # SERIALIZABLE — a concurrent revoke() committing between this check
        # and our commit must abort us, not slip through.
        mandate_id = row["mandate_id"]
        revoke_targets = [payload.capability_id] + (
            [mandate_id] if mandate_id else []
        )
        for target in revoke_targets:
            cur.execute("SELECT 1 FROM revocations WHERE id = %s", (target,))
            if cur.fetchone() is not None:
                raise RevokedError(f"{target!r} has been revoked")

        # (6) Revocation staleness: fail closed.
        staleness = moment.timestamp() - self._last_sync(cur)
        if staleness > payload.max_revocation_staleness:
            raise StaleRevocationError(
                f"revocation view is {staleness:.1f}s old, exceeding the "
                f"capability's max_revocation_staleness of "
                f"{payload.max_revocation_staleness}s — denying fail-closed"
            )

        # (7) Single-use check (the guarded UPDATE in step 11 is the real
        # enforcement; this early check gives a clean error).
        if row["state"] != "ISSUED":
            raise DoubleSpendError(
                f"capability {payload.capability_id!r} already {row['state']}"
            )

        # (8) Holder-of-key proof.
        try:
            authority.verify_holder_proof(
                bytes(payload.holder_pubkey),
                payload.capability_id,
                challenge,
                holder_proof,
            )
        except CapabilityError as exc:
            raise AuthorizationDenied(f"holder proof failed: {exc}") from exc

        # (9) Mandate must be ACTIVE.
        if mandate_id is not None:
            cur.execute(
                "SELECT lifecycle FROM mandates WHERE id = %s", (mandate_id,)
            )
            mrow = cur.fetchone()
            if mrow is None or mrow["lifecycle"] != MandateLifecycle.ACTIVE:
                raise AuthorizationDenied(
                    f"mandate {mandate_id} is not ACTIVE "
                    f"({mrow['lifecycle'] if mrow else 'missing'})"
                )

        # (10) Capability-level spend envelope.
        if payload.spend_limit is not None and spend_amount > payload.spend_limit:
            raise BudgetExceededError(
                f"spend_amount {spend_amount} exceeds capability spend_limit "
                f"{payload.spend_limit}"
            )

        # (11) The atomic flip. Guarded: only ISSUED rows move. Under
        # concurrency the loser either blocks-then-sees-0-rows (EvalPlanQual)
        # or takes a serialization failure (retried, then sees CONSUMED at
        # step 7). Either way: exactly one winner.
        cur.execute(
            "UPDATE capabilities SET state = 'CONSUMED', consumed_at = %s,"
            " spend_consumed = %s WHERE id = %s AND state = 'ISSUED'",
            (_utcnow_iso(), spend_amount, payload.capability_id),
        )
        if cur.rowcount != 1:
            raise DoubleSpendError(
                f"capability {payload.capability_id!r} consumed concurrently"
            )
        return payload
