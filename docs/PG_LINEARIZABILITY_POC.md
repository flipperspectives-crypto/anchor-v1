# Multi-node PostgreSQL linearizability — PoC report (2026-09-25)

## Question
`src/anchor_v1/store.py` claims linearizability via process-wide RLock +
`BEGIN IMMEDIATE`. README: "Single-process linearizability only...
multi-node deployments untested." Does the design hold with N independent
processes ("nodes") on one Postgres?

## Answer: yes — with the adaptations below, all linearizability properties held.

## What was built (new files, existing code untouched)
- `src/anchor_v1/pg_store.py` — faithful Postgres port of store.py's critical
  paths: schema, mandate lifecycle, revocation sync, `debit_mandate_for_child`,
  full 11-step `consume_capability`.
- `tests/test_pg_linearizability.py` — 6 multi-process tests (spawn context,
  8 workers, each with its own connection = separate nodes).

## SQLite -> Postgres adaptations
1. `BEGIN IMMEDIATE` -> `ISOLATION LEVEL SERIALIZABLE` per critical section.
2. Retry on 40001/40P01 with exponential backoff (max 8 attempts), else
   `StoreError`. Implemented as `_run_serializable(fn)` callback — NOT a
   `@contextmanager` generator (retry-in-generator raises `RuntimeError:
   generator didn't stop after throw()`; this was caught by fault-injection
   testing, see below).
3. Guarded `UPDATE ... WHERE` predicates kept verbatim. Postgres re-evaluates
   WHERE on the latest row version after lock wait (EvalPlanQual), so losers
   cleanly see 0 rows.
4. RLock dropped as a correctness mechanism (kept only for connection
   thread-safety). The DB is the serialization point.
5. Schema: `BLOB`->`BYTEA`, `AUTOINCREMENT`->`SERIAL`, `?`->`%s`,
   `last_insert_rowid()`->`RETURNING id`; `mandates` created before
   `capabilities` (Postgres validates FK targets at CREATE time; SQLite
   tolerates forward references).

## Test results (real PostgreSQL via pgserver, 8 worker processes)
| test | result |
|---|---|
| double-spend race (8 procs, 1 cap) | exactly 1 winner, 7 DoubleSpendError |
| budget race (8 procs x 30, limit 100) | exactly 3 winners, spend_used=90, never oversubscribed |
| revoke-before-consume | RevokedError, stays ISSUED |
| consume-before-revoke | stable CONSUMED |
| revoke-vs-consume true race | <=1 winner; no consume-after-revoke |
| scale (40 caps x 8 workers) | exactly 40 wins, all CONSUMED once |
Stress: race trio re-run 3x, all stable. Serialization retries observed = 0
in these patterns (guarded UPDATE + row locking resolves them without SSI
aborts); retry path verified separately by fault injection (2 forced 40001
-> success; 8 forced 40001 -> StoreError). Deterministic SSI probe confirmed
correct phantom handling: overlapping consume/revoke linearizes in either
order; non-overlapping revoke-then-consume always sees the revocation.

## Bugs found (in the PoC, not in store.py)
1. Retry-in-`@contextmanager` RuntimeError (above) — fixed via callback pattern.
2. `IsolationLevel` must be the enum, not the string "serializable".
3. FK forward reference rejected by Postgres — schema reorder.

No linearizability violations found. No changes to `store.py` needed for the
concepts; the SQLite implementation's guarded-UPDATE design ports cleanly.

## Production recommendations
1. Use SERIALIZABLE + bounded retry (as in pg_store.py) for consume/debit/
   revoke paths; surface retry-exhaustion as a 503-style retryable error,
   not a silent deny.
2. Keep the guarded `UPDATE ... WHERE` predicates — they are the last line of
   defense and make most races resolve without SSI aborts.
3. Add `SELECT ... FOR UPDATE` on the capability row early in consume if
   hot-key contention becomes a problem (reduces SSI abort rate under load).
4. The revocation predicate read (step 5) is what mandates SERIALIZABLE over
   READ COMMITTED; document this invariant next to the isolation setting.
5. Port `commit_state_bound`/TOCTOU state binding with the same pattern
   (out of scope for this PoC).
6. For CI: run these tests against a real Postgres service (they skip cleanly
   without one); consider a nightly multi-node chaos run with more workers.

## Environment notes
PostgreSQL was NOT preinstalled. Installed via `pip install pgserver`
(embedded binaries) + `psycopg[binary]` in a venv at /tmp/pgtest (ephemeral).
For CI, use a real Postgres service container instead.
