# ANCHOR v1 — Authority Core Formal Specification (summary)

Status: Wave 6 conformance document. Verified against `src/anchor_v1/authority.py`,
`src/anchor_v1/store.py`, and the 1017/1017 green suite on 2026-09-23.

> **TLA+ consistency obligation.** A TLA+ model of the authority core is being
> written in parallel by Builder E at `anchor-v1/tla/authority.tla`. That file did
> NOT exist at the time this document was written. This summary MUST stay consistent
> with it: the state names, the transition set, and invariants I1–I5 below are the
> shared contract. If the TLA+ model refines any of them, THIS document must be
> updated to match (or the TLA+ model must be fixed); a divergence is a defect.

## 1. State machine

### 1.1 Capability lifecycle (execution capabilities)

```
ISSUED --consume--> CONSUMED
```

There are no other states and no other transitions for execution capabilities.
`store.py::CapabilityState` defines exactly `ISSUED` and `CONSUMED`.

* `ISSUED` is set at registration (`store.py::CapabilityStore.register_capability`).
* The transition is performed ONLY by `store.py::_consume_inner` step (11) via a
  guarded `UPDATE capabilities SET state='CONSUMED' ... WHERE id=? AND state='ISSUED'`.
  A `rowcount != 1` raises `DoubleSpendError`.
* `check_capability` runs the same pipeline with `consume=False`: verification only,
  no state transition. Read capabilities are reusable until expiry but every use
  still requires a fresh holder proof (`authority.py::issue_read` docstring).

### 1.2 Mandate lifecycle

`store.py::LEGAL_TRANSITIONS` enumerates the complete legal transition set; any
other transition raises `LifecycleError`:

```
CREATED   -> {ACTIVE, REVOKED, EXPIRED}
ACTIVE    -> {PAUSED, EXHAUSTED, REVOKED, EXPIRED}
PAUSED    -> {ACTIVE, REVOKED, EXPIRED}
EXHAUSTED -> {REVOKED}
REVOKED   -> {}            (terminal)
EXPIRED   -> {}            (terminal)
```

Enforced by `store.py::CapabilityStore.transition_mandate`, which performs the
read-check-write inside one `BEGIN IMMEDIATE` transaction. Mandates are the only
capability kind that can mint children; a child can be minted only while the
mandate is `ACTIVE` (`store.py::debit_mandate_for_child` refuses all other states).

### 1.3 Mandate attenuation as set-subset

`authority.py::mint_child` enforces monotonic attenuation as a structural subset
relation on every caveat dimension — child authority ⊆ parent authority:

| Dimension | Rule (violation raises `CapabilityError`) |
|---|---|
| kind | parent must be `"mandate"` (execution/read cannot delegate) |
| scope | child `action_digest` = parent `action_digest` (pinned; no broadening) |
| spend | child `spend_limit` ≤ parent `spend_limit`; a bounded parent's limit cannot be dropped; `spend_asset` must be preserved when set |
| time | child `expires_at` ≤ parent `expires_at` |
| revocation freshness | child `max_revocation_staleness` ≤ parent `max_revocation_staleness` |

Every minted child is kind `"execution"` and records `parent_capability_id`.

### 1.4 Atomic consume transaction

`store.py::CapabilityStore.consume_capability` wraps `_consume_inner` in
`RLock` + `BEGIN IMMEDIATE` ... `COMMIT`/`ROLLBACK`. Inside ONE transaction, in
order:

1. `authority.verify_capability` — COSE signature + structural checks + expiry.
2. Registration check — unknown id → `UnknownCapabilityError` (deny).
3. Cross-registration confusion check — presented `holder_pubkey`/`action_digest`/
   `kind` must equal the registered record.
4. Envelope binding — supplied envelope digest must equal capability digest.
5. Revocation — capability id or mandate id in the revocation set → `RevokedError`.
6. Revocation staleness — view older than `max_revocation_staleness` →
   `StaleRevocationError` (fail closed; the CAP trade-off).
7. Single-use — state must be `ISSUED`, else `DoubleSpendError`.
8. Holder proof — `verify_holder_proof(holder_pubkey, capability_id, challenge, proof)`.
9. Mandate active — `ACTIVE` only; spend was already reserved at mint time.
10. Spend envelope — `spend_amount` ≤ capability `spend_limit`.
11. Guarded state flip `ISSUED → CONSUMED` (execution) — or skipped for
    `consume=False` (read verification).

Any failure aborts the transaction: nothing is consumed, no budget moves.

## 2. Invariants

| # | Invariant | Enforcement |
|---|---|---|
| I1 | **No double-consume.** A capability id transitions `ISSUED → CONSUMED` at most once. | Guarded `UPDATE ... WHERE state='ISSUED'` + `rowcount` check in `_consume_inner` step (11); serialized by `RLock` + `BEGIN IMMEDIATE` (`store.py`). Pinned by `tests/test_authority.py` (`TestStore`). |
| I2 | **Monotonic attenuation.** Every minted child satisfies child ⊆ parent on all caveat dimensions. | Structural checks in `authority.py::mint_child`; re-verified independently by `verify_chain` (`delegation_chains.py`) and the SUBSUMPTION relation (`attenuated_tokens.py`). Pinned by `tests/test_authority.py`, `tests/test_attenuated_tokens.py`, `tests/test_delegation_chains.py`. |
| I3 | **Revoked-never-consumed (within the staleness bound).** A revoked capability or mandate cannot be consumed once the revocation is visible; before visibility, the staleness bound fails closed. | Revocation-set lookup (step 5) + `StaleRevocationError` (step 6); revocation propagates via `sync_revocations`/`revoke` bumping the epoch (`store.py`). Pinned by `tests/test_authority.py`. |
| I4 | **Budget-never-negative.** `spend_used ≤ spend_limit` and `actions_used ≤ actions_limit` for every mandate; capability `spend_amount ≤ spend_limit`. | `debit_mandate_for_child` guarded `UPDATE` (mint reserves the child's FULL spend limit, worst case); capability-level check (step 10) in `_consume_inner` (`store.py`). `create_mandate` rejects negative limits. Pinned by `tests/test_authority.py`. |
| I5 | **Holder binding.** Consumption requires a signature by the bound `holder_pubkey` over `capability_id \|\| challenge` with a fresh per-request challenge. Bearer presentation is structurally insufficient. | `verify_holder_proof` (step 8); `make_holder_proof` rejects empty challenges; `authority.py` module contract. Pinned by `tests/test_authority.py`. |

## 3. Supporting invariants (same transaction boundary)

* **Registration integrity:** only registered capabilities can be consumed
  (`UnknownCapabilityError`); the presented record must match the registered
  record field-for-field on the security-critical columns (step 3).
* **Validity window:** `verify_capability` enforces `expires_at > issued_at` and
  `now ≤ expires_at` (`authority.py`).
* **Envelope integrity:** `action_digest = SHA-256(canonical_bytes(ActionEnvelope))`,
  deterministic CBOR per RFC 8949 (`envelope.py`, `canonical.py`).
* **State-bound commit atomicity:** `commit_state_bound` re-verifies the preview's
  `(version, digest)` inside the same transaction as consumption and the planned
  writes; any mismatch raises `StateChangedError` and rolls back everything
  (`store.py`).

## 4. What the model does NOT cover

* The store is a SQLite stand-in for the production serializable-Postgres design;
  the `RLock` + `BEGIN IMMEDIATE` linearizability argument holds for one process.
  Multi-process/multi-host linearizability is a deployment property.
* `check_capability` (verify-only path for reads) is NOT part of the state machine;
  it performs no transition.
* Cross-process WebAuthn challenge replay, trust-bundle correctness, and challenge
  freshness are coordinator duties (see `docs/THREAT_MODEL.md` residual risks).
* Cross-plane verb/target mapping (v1.0.0 versioned limitation): the
  Guardian<->shell PEP integration seam is cross-plane by design — the
  presenting plane's `verb`/`target` (e.g. shell `verb="exec"`) are NOT
  equated with the acs-plane `event.action`/`event.resource` (e.g.
  `action="shell.exec"`), because no cross-plane mapping exists in the
  protocol and the guardian has no ground truth to validate against
  (`src/anchor_v1/acs_guardian.py::_validate_presented_envelope` binds
  principal, exact args, policy ref, and validity window only). Each plane
  validates strictly within its own scope. Cross-plane translation is a
  deployment/orchestrator responsibility until v1.1 (see
  `docs/THREAT_MODEL.md` item 12). Tripwire test
  `tests/test_redteam2_fixes.py::test_p5_cross_plane_envelope_allowed_by_design`
  locks this behavior.
