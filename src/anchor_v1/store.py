"""ANCHOR v1 — linearizable consumption / budget engine (Wave 2, Revision B pivot 10; blocker 3).

``CapabilityStore`` is a SQLite-backed (stdlib ``sqlite3``) stand-in for the
production serializable-Postgres design. Linearizability is achieved by
serializing every state-changing operation behind a process-wide lock and
executing the critical section as a single ``BEGIN IMMEDIATE`` transaction:

    verify (COSE + structural) + epoch/revocation check + holder-proof check
    + state→CONSUMED + budget reserve  ==  ONE atomic transaction.

Double-consume is impossible: the state flip is a guarded
``UPDATE ... WHERE state='ISSUED'`` and a zero rowcount means someone else
won the race.

Mandate lifecycle: CREATED → ACTIVE → PAUSED → EXHAUSTED → REVOKED → EXPIRED,
with only the legal transitions below accepted. ``mint_child`` debits the
mandate's action/spend budget atomically: minting a child reserves its full
``spend_limit`` against the mandate (worst-case reservation), so the mandate
budget can never be oversubscribed no matter how children are consumed.

THE CAP TRADE-OFF (explicit, per Revision B pivot 10):
------------------------------------------------------
Instant global revocation is impossible for an enforcement point that must
keep working while partitioned from the authority — this is the CAP theorem,
not a bug we can code around. We do NOT pretend otherwise.

Instead, every capability carries ``max_revocation_staleness`` (seconds).
The store tracks ``last_revocation_sync_at``: the wall-clock time its local
revocation view was last refreshed from the authority. At consume time, if

    now - last_revocation_sync_at > capability.max_revocation_staleness

the store FAILS CLOSED and refuses consumption. A stale revocation view is
treated as no revocation view at all.

Consequences, stated plainly:

* A revocation issued at the authority takes effect at an enforcement point
  no later than that point's next revocation sync — and any capability whose
  staleness bound expires before the sync arrives becomes unusable rather
  than usable-but-unrevoked. Availability of *execution* is sacrificed to
  keep the revocation guarantee honest.
* Operators choose the bound per capability: short bounds (tens of seconds)
  approximate instant revocation but require a live sync channel; long
  bounds (hours) survive partitions but leave a window where a revoked
  capability still executes.
* ``sync_revocations()`` is the only way to refresh the view; there is no
  background thread, no implicit network call, and no silent expiry of the
  fail-closed behavior.

Threading model: one shared SQLite connection (``check_same_thread=False``)
guarded by an ``RLock``. All public methods take the lock; the consume path
additionally holds ``BEGIN IMMEDIATE`` so concurrent threads serialize on
the database write lock as well. ``:memory:`` databases are supported and
are per-store (each store gets its own connection).
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from datetime import datetime, timezone
from typing import Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import authority
from .authority import CapabilityError, CapabilityPayload
from .canonical import canonical_bytes, sha256_hex
from .envelope import ActionEnvelope
from .state_binding import EffectPreview, StateChangedError, StateView

__all__ = [
    "StoreError",
    "AuthorizationDenied",
    "DoubleSpendError",
    "BudgetExceededError",
    "RevokedError",
    "StaleRevocationError",
    "LifecycleError",
    "UnknownCapabilityError",
    "CapabilityState",
    "MandateLifecycle",
    "LEGAL_TRANSITIONS",
    "CapabilityStore",
]

# ---------------------------------------------------------------------------
# errors
# ---------------------------------------------------------------------------


class StoreError(Exception):
    """Base class for store failures."""


class AuthorizationDenied(StoreError):
    """Fail-closed denial: bad capability, holder mismatch, digest mismatch,
    unknown capability, or mandate not ACTIVE."""


class DoubleSpendError(AuthorizationDenied):
    """The capability was already consumed. Exactly one consumer wins."""


class BudgetExceededError(AuthorizationDenied):
    """Spend or action budget would be oversubscribed."""


class RevokedError(AuthorizationDenied):
    """The capability or its mandate was revoked."""


class StaleRevocationError(AuthorizationDenied):
    """The store's revocation view is older than the capability's
    ``max_revocation_staleness`` bound. Fail closed: deny."""


class LifecycleError(StoreError):
    """Illegal mandate lifecycle transition."""


class UnknownCapabilityError(AuthorizationDenied):
    """No such capability id in the store."""


# ---------------------------------------------------------------------------
# state model
# ---------------------------------------------------------------------------


class CapabilityState:
    ISSUED = "ISSUED"
    CONSUMED = "CONSUMED"


class MandateLifecycle:
    CREATED = "CREATED"
    ACTIVE = "ACTIVE"
    PAUSED = "PAUSED"
    EXHAUSTED = "EXHAUSTED"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"


#: Legal mandate lifecycle transitions. Everything else raises LifecycleError.
LEGAL_TRANSITIONS: dict[str, frozenset[str]] = {
    MandateLifecycle.CREATED: frozenset(
        {MandateLifecycle.ACTIVE, MandateLifecycle.REVOKED, MandateLifecycle.EXPIRED}
    ),
    MandateLifecycle.ACTIVE: frozenset(
        {
            MandateLifecycle.PAUSED,
            MandateLifecycle.EXHAUSTED,
            MandateLifecycle.REVOKED,
            MandateLifecycle.EXPIRED,
        }
    ),
    MandateLifecycle.PAUSED: frozenset(
        {MandateLifecycle.ACTIVE, MandateLifecycle.REVOKED, MandateLifecycle.EXPIRED}
    ),
    MandateLifecycle.EXHAUSTED: frozenset({MandateLifecycle.REVOKED}),
    MandateLifecycle.REVOKED: frozenset(),
    MandateLifecycle.EXPIRED: frozenset(),
}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS capabilities (
    id                      TEXT PRIMARY KEY,
    action_digest           TEXT NOT NULL,
    holder_pubkey           BLOB NOT NULL,
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
CREATE TABLE IF NOT EXISTS mandates (
    id              TEXT PRIMARY KEY,
    lifecycle       TEXT NOT NULL DEFAULT 'CREATED',
    spend_used      INTEGER NOT NULL DEFAULT 0,
    spend_limit     INTEGER,
    actions_used    INTEGER NOT NULL DEFAULT 0,
    actions_limit   INTEGER,
    recipients_json TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS revocations (
    id          TEXT PRIMARY KEY,
    revoked_at  TEXT NOT NULL,
    epoch       INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS epochs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (
    key     TEXT PRIMARY KEY,
    value   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS agent_state (
    key     TEXT PRIMARY KEY,
    value   TEXT NOT NULL
);
"""


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class CapabilityStore:
    """Linearizable capability consumption + mandate budget engine."""

    def __init__(self, db_path: str = ":memory:") -> None:
        self._lock = threading.RLock()
        self._db = sqlite3.connect(db_path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        # Manual transaction control: every critical section runs its own
        # BEGIN IMMEDIATE ... COMMIT/ROLLBACK.
        self._db.isolation_level = None
        with self._lock:
            self._db.executescript(_SCHEMA)
            self._db.execute("PRAGMA busy_timeout = 5000")
            if db_path != ":memory:":
                try:
                    self._db.execute("PRAGMA journal_mode = WAL")
                except sqlite3.Error:
                    pass
            cur = self._db.execute(
                "SELECT value FROM meta WHERE key = 'last_revocation_sync_at'"
            )
            if cur.fetchone() is None:
                self._db.execute(
                    "INSERT INTO meta (key, value) VALUES ('last_revocation_sync_at', ?)",
                    (repr(time.time()),),
                )
            cur = self._db.execute("SELECT COUNT(*) AS n FROM epochs")
            if cur.fetchone()["n"] == 0:
                self._db.execute(
                    "INSERT INTO epochs (started_at) VALUES (?)", (_utcnow_iso(),)
                )
            cur = self._db.execute(
                "SELECT value FROM meta WHERE key = 'state_version'"
            )
            if cur.fetchone() is None:
                self._db.execute(
                    "INSERT INTO meta (key, value) VALUES ('state_version', '0')"
                )

    # -- low-level ----------------------------------------------------------

    def _last_sync(self) -> float:
        cur = self._db.execute(
            "SELECT value FROM meta WHERE key = 'last_revocation_sync_at'"
        )
        row = cur.fetchone()
        return float(row["value"]) if row else 0.0

    def _set_last_sync(self, when: float) -> None:
        self._db.execute(
            "INSERT INTO meta (key, value) VALUES ('last_revocation_sync_at', ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (repr(when),),
        )

    # -- revocation view ----------------------------------------------------

    def sync_revocations(
        self, revoked_ids: list[str] | None = None, *, now: float | None = None
    ) -> int:
        """Refresh the store's revocation view from the authority.

        Inserts ``revoked_ids`` into the revocation set, bumps the epoch, and
        records the sync time. This is the ONLY thing that refreshes the
        view — there is no background sync and no network call. Returns the
        new epoch number.
        """
        when = time.time() if now is None else float(now)
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                self._db.execute(
                    "INSERT INTO epochs (started_at) VALUES (?)", (_utcnow_iso(),)
                )
                cur = self._db.execute("SELECT last_insert_rowid() AS id")
                epoch = int(cur.fetchone()["id"])
                for rid in revoked_ids or []:
                    self._db.execute(
                        "INSERT INTO revocations (id, revoked_at, epoch) VALUES (?, ?, ?) "
                        "ON CONFLICT(id) DO NOTHING",
                        (rid, _utcnow_iso(), epoch),
                    )
                self._set_last_sync(when)
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise
            return epoch

    def revoke(self, capability_or_mandate_id: str) -> int:
        """Revoke a capability or mandate id. Returns the new epoch number."""
        return self.sync_revocations([capability_or_mandate_id])

    def is_revoked(self, capability_or_mandate_id: str) -> bool:
        with self._lock:
            cur = self._db.execute(
                "SELECT 1 FROM revocations WHERE id = ?",
                (capability_or_mandate_id,),
            )
            return cur.fetchone() is not None

    # -- mandates ------------------------------------------------------------

    def create_mandate(
        self,
        mandate_id: str,
        *,
        spend_limit: int | None = None,
        actions_limit: int | None = None,
        recipients: list[str] | None = None,
    ) -> None:
        """Create a mandate in CREATED lifecycle."""
        if spend_limit is not None and (
            isinstance(spend_limit, bool) or spend_limit < 0
        ):
            raise StoreError("spend_limit must be a non-negative int or None")
        if actions_limit is not None and (
            isinstance(actions_limit, bool) or actions_limit < 0
        ):
            raise StoreError("actions_limit must be a non-negative int or None")
        with self._lock:
            try:
                self._db.execute(
                    "INSERT INTO mandates (id, lifecycle, spend_limit, actions_limit, recipients_json)"
                    " VALUES (?, 'CREATED', ?, ?, ?)",
                    (
                        mandate_id,
                        spend_limit,
                        actions_limit,
                        json.dumps(recipients or []),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise StoreError(f"mandate {mandate_id!r} already exists") from exc

    def get_mandate(self, mandate_id: str) -> dict:
        with self._lock:
            cur = self._db.execute(
                "SELECT * FROM mandates WHERE id = ?", (mandate_id,)
            )
            row = cur.fetchone()
            if row is None:
                raise StoreError(f"unknown mandate {mandate_id!r}")
            return dict(row)

    def transition_mandate(self, mandate_id: str, new_lifecycle: str) -> None:
        """Move a mandate along a legal lifecycle transition only."""
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                cur = self._db.execute(
                    "SELECT lifecycle FROM mandates WHERE id = ?", (mandate_id,)
                )
                row = cur.fetchone()
                if row is None:
                    raise StoreError(f"unknown mandate {mandate_id!r}")
                current = row["lifecycle"]
                if new_lifecycle not in LEGAL_TRANSITIONS.get(current, frozenset()):
                    raise LifecycleError(
                        f"illegal mandate transition {current} -> {new_lifecycle}"
                    )
                self._db.execute(
                    "UPDATE mandates SET lifecycle = ? WHERE id = ?",
                    (new_lifecycle, mandate_id),
                )
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    # -- capability registration ---------------------------------------------

    def register_capability(
        self, payload: CapabilityPayload, *, mandate_id: str | None = None
    ) -> None:
        """Record an issued capability so it can later be consumed.

        Called by the issuing authority at issuance time. A capability that
        was never registered can never be consumed (unknown id => deny).
        """
        with self._lock:
            if mandate_id is not None:
                cur = self._db.execute(
                    "SELECT 1 FROM mandates WHERE id = ?", (mandate_id,)
                )
                if cur.fetchone() is None:
                    raise StoreError(f"unknown mandate {mandate_id!r}")
            try:
                self._db.execute(
                    "INSERT INTO capabilities (id, action_digest, holder_pubkey, kind,"
                    " state, spend_limit, spend_asset, issued_at, expires_at,"
                    " mandate_id, max_revocation_staleness_s)"
                    " VALUES (?, ?, ?, ?, 'ISSUED', ?, ?, ?, ?, ?, ?)",
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
            except sqlite3.IntegrityError as exc:
                raise StoreError(
                    f"capability {payload.capability_id!r} already registered"
                ) from exc

    def capability_state(self, capability_id: str) -> str:
        with self._lock:
            cur = self._db.execute(
                "SELECT state FROM capabilities WHERE id = ?", (capability_id,)
            )
            row = cur.fetchone()
            if row is None:
                raise UnknownCapabilityError(capability_id)
            return row["state"]

    # -- mint-child budget debit ----------------------------------------------

    def debit_mandate_for_child(
        self, mandate_id: str, child_spend_limit: int | None
    ) -> None:
        """Atomically reserve budget for a child minted from a mandate.

        Reserves the child's full ``spend_limit`` against the mandate
        (worst-case reservation) and debits one action. The mandate must be
        ACTIVE; anything else — PAUSED, EXHAUSTED, REVOKED, EXPIRED — denies
        the mint. Oversubscription is impossible: the guarded UPDATE either
        applies the whole debit or applies nothing.
        """
        reserve = child_spend_limit or 0
        if isinstance(reserve, bool) or reserve < 0:
            raise BudgetExceededError("child spend_limit must be a non-negative int")
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                cur = self._db.execute(
                    "UPDATE mandates SET spend_used = spend_used + ?,"
                    " actions_used = actions_used + 1"
                    " WHERE id = ? AND lifecycle = 'ACTIVE'"
                    " AND (spend_limit IS NULL OR spend_used + ? <= spend_limit)"
                    " AND (actions_limit IS NULL OR actions_used + 1 <= actions_limit)",
                    (reserve, mandate_id, reserve),
                )
                if cur.rowcount == 0:
                    # Distinguish the reason for a precise error.
                    cur = self._db.execute(
                        "SELECT lifecycle, spend_used, spend_limit, actions_used, actions_limit"
                        " FROM mandates WHERE id = ?",
                        (mandate_id,),
                    )
                    row = cur.fetchone()
                    self._db.execute("ROLLBACK")
                    if row is None:
                        raise StoreError(f"unknown mandate {mandate_id!r}")
                    if row["lifecycle"] != MandateLifecycle.ACTIVE:
                        raise AuthorizationDenied(
                            f"cannot mint child: mandate {mandate_id} is {row['lifecycle']}"
                        )
                    raise BudgetExceededError(
                        f"mandate {mandate_id} budget oversubscribed by child mint"
                    )
                self._db.execute("COMMIT")
            except Exception:
                try:
                    self._db.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise

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
        """Consume a capability: verify + epoch/revocation + holder proof +
        state→CONSUMED + budget reserve, atomically.

        Returns the verified payload on success. Raises (fail-closed) on ANY
        failure: bad COSE, unknown capability, digest/holder mismatch, revoked
        capability or mandate, stale revocation view, expired capability,
        bad holder proof, budget exceeded, inactive mandate, or double-spend.
        On failure nothing is consumed and no budget is debited.
        """
        if isinstance(spend_amount, bool) or not isinstance(spend_amount, int):
            raise AuthorizationDenied("spend_amount must be an integer")
        if spend_amount < 0:
            raise AuthorizationDenied("spend_amount must be >= 0")
        moment = now if now is not None else datetime.now(timezone.utc)
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)

        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                result = self._consume_inner(
                    capability_cose=capability_cose,
                    holder_proof=holder_proof,
                    challenge=challenge,
                    trusted_issuers=trusted_issuers,
                    envelope=envelope,
                    spend_amount=spend_amount,
                    moment=moment,
                )
                self._db.execute("COMMIT")
                return result
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    def check_capability(
        self,
        *,
        capability_cose: bytes,
        holder_proof: bytes,
        challenge: bytes,
        trusted_issuers: Mapping[bytes, Ed25519PublicKey],
        now: datetime | None = None,
    ) -> CapabilityPayload:
        """Verify a capability WITHOUT consuming it: every ``consume_capability``
        check (COSE, revocation, holder proof, expiry, mandate) except the
        ISSUED→CONSUMED flip. Used for reusable capabilities — reads are
        non-mutating, so a read capability stays valid until it expires, but
        EVERY read still requires a fresh holder proof and runs the full
        verification. Raises (fail-closed) exactly like ``consume_capability``.
        """
        moment = now if now is not None else datetime.now(timezone.utc)
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        with self._lock:
            return self._consume_inner(
                capability_cose=capability_cose,
                holder_proof=holder_proof,
                challenge=challenge,
                trusted_issuers=trusted_issuers,
                envelope=None,
                spend_amount=0,
                moment=moment,
                consume=False,
            )

    def _consume_inner(
        self,
        *,
        capability_cose: bytes,
        holder_proof: bytes,
        challenge: bytes,
        trusted_issuers: Mapping[bytes, Ed25519PublicKey],
        envelope: ActionEnvelope | None,
        spend_amount: int,
        moment: datetime,
        consume: bool = True,
    ) -> CapabilityPayload:
        # (1) Stateless verification: COSE signature + structural checks.
        # A capability presented with a forged or expired token dies here.
        try:
            payload = authority.verify_capability(
                capability_cose, trusted_issuers, now=moment
            )
        except CapabilityError as exc:
            raise AuthorizationDenied(f"capability verification failed: {exc}") from exc

        # (2) The capability must be registered with this store.
        cur = self._db.execute(
            "SELECT * FROM capabilities WHERE id = ?", (payload.capability_id,)
        )
        row = cur.fetchone()
        if row is None:
            raise UnknownCapabilityError(
                f"capability {payload.capability_id!r} not registered"
            )

        # (3) The presented bytes must match the registered record: the COSE
        # signature is valid, but the store only honors the exact issuance it
        # recorded (prevents cross-registration confusion).
        if bytes(row["holder_pubkey"]) != bytes(payload.holder_pubkey):
            raise AuthorizationDenied("holder key does not match registered capability")
        if row["action_digest"] != payload.action_digest:
            raise AuthorizationDenied("action digest does not match registered capability")
        if row["kind"] != payload.kind:
            raise AuthorizationDenied("kind does not match registered capability")

        # (4) Envelope binding: when the PEP supplies the envelope it is about
        # to execute, its digest must equal the capability's bound digest.
        if envelope is not None and envelope.action_digest != payload.action_digest:
            raise AuthorizationDenied(
                "envelope action_digest does not match capability binding"
            )

        # (5) Revocation: capability id or its mandate id in the revocation set.
        mandate_id = row["mandate_id"]
        revoke_targets = [payload.capability_id] + (
            [mandate_id] if mandate_id else []
        )
        for target in revoke_targets:
            cur = self._db.execute(
                "SELECT 1 FROM revocations WHERE id = ?", (target,)
            )
            if cur.fetchone() is not None:
                raise RevokedError(f"{target!r} has been revoked")

        # (6) Revocation staleness: fail closed when the store's revocation
        # view is older than the capability's bound. This is the CAP
        # trade-off made explicit — see module docstring.
        staleness = moment.timestamp() - self._last_sync()
        if staleness > payload.max_revocation_staleness:
            raise StaleRevocationError(
                f"revocation view is {staleness:.1f}s old, exceeding the "
                f"capability's max_revocation_staleness of "
                f"{payload.max_revocation_staleness}s — denying fail-closed"
            )

        # (7) Single-use: exactly one consumer may flip ISSUED -> CONSUMED.
        if row["state"] != CapabilityState.ISSUED:
            raise DoubleSpendError(
                f"capability {payload.capability_id!r} already {row['state']}"
            )

        # (8) Holder-of-key proof: the bound key must have signed
        # (capability_id || challenge). No proof, or a proof from any other
        # key, is a denial. Bearer replay is structurally impossible.
        try:
            authority.verify_holder_proof(
                bytes(payload.holder_pubkey),
                payload.capability_id,
                challenge,
                holder_proof,
            )
        except CapabilityError as exc:
            raise AuthorizationDenied(f"holder proof failed: {exc}") from exc

        # (9) Mandate checks (for children minted from a mandate): the mandate
        # must be ACTIVE — PAUSED/EXHAUSTED/REVOKED/EXPIRED all deny.
        if mandate_id is not None:
            cur = self._db.execute(
                "SELECT lifecycle FROM mandates WHERE id = ?", (mandate_id,)
            )
            mrow = cur.fetchone()
            if mrow is None or mrow["lifecycle"] != MandateLifecycle.ACTIVE:
                raise AuthorizationDenied(
                    f"mandate {mandate_id} is not ACTIVE "
                    f"({mrow['lifecycle'] if mrow else 'missing'})"
                )
            # Note: spend was reserved at mint time (debit_mandate_for_child),
            # so no mandate debit happens here — reservation covers worst case.

        # (10) Capability-level spend envelope: the presented spend must fit
        # inside the capability's own caveat.
        if payload.spend_limit is not None and spend_amount > payload.spend_limit:
            raise BudgetExceededError(
                f"spend_amount {spend_amount} exceeds capability spend_limit "
                f"{payload.spend_limit}"
            )

        # (11) The atomic flip. Guarded: only ISSUED rows move. Skipped for
        # verify-only checks (consume=False): reads don't burn capabilities.
        if consume:
            cur = self._db.execute(
                "UPDATE capabilities SET state = 'CONSUMED', consumed_at = ?,"
                " spend_consumed = ? WHERE id = ? AND state = 'ISSUED'",
                (_utcnow_iso(), spend_amount, payload.capability_id),
            )
            if cur.rowcount != 1:
                # A concurrent consumer won the race between our read and this
                # write — even though the lock makes that impossible here, the
                # guard keeps the invariant true under any future lock change.
                raise DoubleSpendError(
                    f"capability {payload.capability_id!r} consumed concurrently"
                )
        return payload

    # -- state-bound prepare/commit (TOCTOU defense) -------------------------
    # Governance-relevant state lives in the ``agent_state`` table with a
    # single monotonic ``state_version`` in ``meta``. Every write bumps the
    # version. ``commit_state_bound`` re-verifies the preview's
    # (version, digest) binding INSIDE the same BEGIN IMMEDIATE transaction
    # that consumes the capability and applies the planned writes — so there
    # is no window between the state check and the effect.

    def _state_version_locked(self) -> int:
        cur = self._db.execute("SELECT value FROM meta WHERE key = 'state_version'")
        row = cur.fetchone()
        return int(row["value"]) if row else 0

    def _read_state_locked(self, keys: list[str]) -> StateView:
        version = self._state_version_locked()
        values: dict[str, object] = {}
        for key in keys:
            cur = self._db.execute(
                "SELECT value FROM agent_state WHERE key = ?", (key,)
            )
            row = cur.fetchone()
            values[key] = json.loads(row["value"]) if row else None
        digest = sha256_hex({k: values[k] for k in sorted(values)})
        return StateView(version=version, digest=digest, values=values)

    def state_version(self) -> int:
        """Current monotonic state version."""
        with self._lock:
            return self._state_version_locked()

    def read_state(self, keys: list[str]) -> StateView:
        """Snapshot the given state keys: (version, digest, values).

        Missing keys read as ``None`` and are covered by the digest, so a
        key created between prepare and commit breaks the binding.
        """
        if not keys:
            raise StoreError("read_state requires at least one key")
        with self._lock:
            return self._read_state_locked([str(k) for k in keys])

    def write_state(self, writes: dict[str, object]) -> int:
        """Deployment setup helper: apply writes and bump the state version.

        NOT part of the commit path — normal effects go through
        ``commit_state_bound`` with an authority-signed preview.
        """
        if not writes:
            raise StoreError("write_state requires at least one write")
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                for key, value in writes.items():
                    blob = canonical_bytes(value).decode("utf-8")
                    self._db.execute(
                        "INSERT INTO agent_state (key, value) VALUES (?, ?)"
                        " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                        (str(key), blob),
                    )
                new_version = self._state_version_locked() + 1
                self._db.execute(
                    "UPDATE meta SET value = ? WHERE key = 'state_version'",
                    (str(new_version),),
                )
                self._db.execute("COMMIT")
                return new_version
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    def commit_state_bound(
        self,
        *,
        envelope: ActionEnvelope,
        capability_cose: bytes,
        holder_proof: bytes,
        challenge: bytes,
        trusted_issuers: Mapping[bytes, Ed25519PublicKey],
        preview: EffectPreview,
        now: datetime,
    ) -> dict:
        """Atomically consume the capability and apply the preview's planned
        state writes — but ONLY if the live state still matches the preview's
        (version, digest) binding.

        One ``BEGIN IMMEDIATE`` transaction covers: full capability
        consumption (the existing ``_consume_inner`` checks), the state
        re-verification, the planned writes, and the version bump. Any
        failure rolls back everything: the capability stays ISSUED and no
        writes land. A state that moved since prepare raises
        :class:`StateChangedError`.
        """
        if not isinstance(now, datetime):
            raise StoreError("commit_state_bound requires an aware datetime")
        moment = now if now.tzinfo is not None else now.replace(tzinfo=timezone.utc)

        # The preview's planned writes may only touch keys the policy read:
        # otherwise the digest binding would not cover the write.
        extra = set(preview.planned_writes) - set(preview.read_keys)
        if extra:
            raise StateChangedError(
                f"preview writes to keys outside its read set: {sorted(extra)}"
            )

        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                payload = self._consume_inner(
                    capability_cose=capability_cose,
                    holder_proof=holder_proof,
                    challenge=challenge,
                    trusted_issuers=trusted_issuers,
                    envelope=envelope,
                    spend_amount=0,
                    moment=moment,
                )
                view = self._read_state_locked(list(preview.read_keys))
                if (
                    view.version != preview.state_version
                    or view.digest != preview.state_digest
                ):
                    raise StateChangedError(
                        f"state moved since prepare: preview bound to "
                        f"(v{preview.state_version}, {preview.state_digest[:16]}…) "
                        f"but live state is (v{view.version}, {view.digest[:16]}…)"
                    )
                for key, value in preview.planned_writes.items():
                    blob = canonical_bytes(value).decode("utf-8")
                    self._db.execute(
                        "INSERT INTO agent_state (key, value) VALUES (?, ?)"
                        " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                        (str(key), blob),
                    )
                new_version = view.version + 1
                self._db.execute(
                    "UPDATE meta SET value = ? WHERE key = 'state_version'",
                    (str(new_version),),
                )
                self._db.execute("COMMIT")
                return {
                    "preview_id": preview.preview_id,
                    "capability_id": payload.capability_id,
                    "state_version": new_version,
                    "applied_writes": dict(preview.planned_writes),
                }
            except Exception:
                self._db.execute("ROLLBACK")
                raise
