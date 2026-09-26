# ANCHOR v1 — TLA+ conformance model of the authority core

`authority.tla` is a finite-state model of the capability authority
(`src/anchor_v1/authority.py`) and the consumption / budget engine
(`src/anchor_v1/store.py`). It exists so the *protocol-level* safety
properties — no double-consume, monotonic attenuation, revoked-means-denied,
budget soundness, holder binding, expiry — can be checked exhaustively by
the TLC model checker, independently of the Python test suite.

> **Status (2026-09-25):** model-checked with TLC 2026.09.25 (tla2tools
> v1.8.0) on OpenJDK 21. The reduced 2-id model
> (`authority-small.cfg`) was **checked exhaustively: 11.2M states
> generated, 4.3M distinct, all 7 invariants hold** (6.5 min on 2 cores).
> TLC also found and we fixed one over-strong invariant (see run notes).
> The full 3-id `authority.cfg` exceeds this machine (60M+ states, thrashes
> on 8 GB); it needs symmetry reduction or a bigger box.

## 1. Prerequisites

* **Java 11+** (`java -version`)
* **`tla2tools.jar`** — download from the TLA+ releases page:
  <https://github.com/tlaplus/tlaplus/releases>
  (pick the latest `v1.x` release and download the `tla2tools.jar` asset;
  e.g. `https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar`).
  Place it in this directory (`tla/`).

## 2. Model configuration

Save the following as `tla/authority.cfg` (same directory as
`authority.tla`):

```cfg
\* TLC model configuration for authority.tla
\* (Full bounds: 3 capability ids, 2 effects, 2 holders. WARNING: this
\*  generates 60M+ states and needs ~8 GB+ RAM or symmetry reduction;
\*  for a model that exhausts on a laptop use authority-small.cfg.)
INIT Init
NEXT Next

INVARIANT TypeOK
INVARIANT NoDoubleConsume
INVARIANT AttenuationMonotonic
INVARIANT RevokedNeverConsumed
INVARIANT BudgetNeverNegative
INVARIANT HolderBindingPreserved
INVARIANT ExpiryHonored

CONSTANT Ids      = {"c1", "c2", "c3"}
CONSTANT Effects  = {"e1", "e2"}
CONSTANT Holders  = {"h1", "h2"}
CONSTANT Digests  = {"d1", "d2"}
CONSTANT NoId      = "NOID"
CONSTANT NoHolder  = "NOHOLDER"
CONSTANT NoDigest  = "NODIGEST"
CONSTANT MaxBudget = 2
CONSTANT MaxClock  = 3
CONSTANT MaxStale  = 2
CONSTANT MaxNonce  = 2
CONSTANT MaxEpoch  = 4
```

## 3. Running TLC

From the `tla/` directory:

```sh
java -cp tla2tools.jar tlc2.TLC -config authority.cfg authority.tla
```

(If Java complains about heap on larger bounds, add e.g.
`-Xmx4G` before `-cp`.)

## 4. What a passing run looks like

A clean run ends with:

```
Model checking completed. No error has been found.
```

preceded by TLC's summary line reporting distinct states generated.
On the reduced 2-id model (`authority-small.cfg`: 2 ids, MaxBudget=1,
MaxClock=2, MaxStale=1, MaxNonce=1, MaxEpoch=2) expect ~4.3M distinct
states and ~6 minutes on 2 cores; the full 3-id `authority.cfg` is 60M+
states and needs a bigger machine or symmetry reduction.

A **failing** run instead prints:

```
Error: Invariant <Name> is violated.
```

followed by a minimal trace: the sequence of states and the action that
produced the violation. That trace is the payoff of this model — it is a
concrete interleaving (issue → attenuate → revoke → consume …) that breaks
a property the Python suite is supposed to enforce. Treat any violation
as a bug in either the implementation or the model, and reconcile the two
before re-running.

## 5. Extending the model bounds

Edit the `CONSTANT` assignments in `authority.cfg`. Effects on the state
space (rough guidance):

| Constant | Meaning | Cost of raising |
|---|---|---|
| `Ids` | capability-id pool (add `"c4"`, …) | **High** — each new id multiplies issuance/attenuation interleavings |
| `Effects` | effect universe; scopes range over its subsets | **High** — scopes are `SUBSET Effects` (2^n) |
| `Holders` | holder identities | Medium — multiplies proof/Consume branches |
| `Digests` | action digests | Low |
| `MaxBudget` | spend/budget granularity | Medium — widens MintChild/Consume choice |
| `MaxClock` | logical time horizon | Medium — more ExpireTick interleavings |
| `MaxStale` | staleness-bound granularity | Low |
| `MaxNonce` | nonce values | Low |
| `MaxEpoch` | revocation-epoch cap | Low–medium |

Rules of thumb:

* Keep `MaxClock` small (3–4). Time only matters relative to `expires`
  and `maxStale`; a longer horizon adds nothing but interleavings.
* If TLC slows down, cut `Ids` to 2 first — most properties
  (attenuation, double-consume, revocation) already manifest with a
  parent and one child.
* `Ids`, `Effects`, and `Holders` are fully symmetric in the spec. For
  larger bounds, convert the cfg sets to TLC model values (`{c1, c2, c3}`
  instead of `{"c1", "c2", "c3"}`) and add a `SYMMETRY` entry permuting
  those sets; that cuts the state space ~24x (3! x 2! x 2!). Note:
  symmetry requires *model values* — quoted strings are rejected with
  `Symmetry function must have model values as domain and range`.

## 6. Mapping: TLA+ action → Python implementation

Read the model against the code action by action:

| TLA+ action | Python function(s) | Notes |
|---|---|---|
| `IssueMandate` | `authority.issue_mandate` + `store.register_capability` (+ `store.create_mandate` for the ledger row) | `ledger`/`budget0` ← mandate `spend_limit` |
| `IssueExecution` | `authority.issue_execution` + `store.register_capability` | One-use, non-delegable |
| `IssueRead` | `authority.issue_read` + `store.register_capability` | Reusable; provenance caveats folded into `scope` |
| `MintChild` (Attenuate) | `authority.mint_child` + `store.debit_mandate_for_child` | Guards mirror the attenuation checks line-for-line: `scope ⊆`, digest pinned, `spend ≤`, `expires ≤`, `maxStale ≤`, worst-case reservation `ledger[p] ≥ sp` |
| `PresentProof` | `authority.make_holder_proof` / `verify_holder_proof` | Abstracted as an unforgeable token only the bound holder can present; each `Consume`/`CheckRead` consumes it (fresh challenge ⇒ no replay) |
| `Consume` | `store.consume_capability` / `_consume_inner` steps (1)–(11) | One atomic transition = the `BEGIN IMMEDIATE` critical section; the guarded `UPDATE … WHERE state='ISSUED'` is the `state = "ISSUED"` guard + flip |
| `CheckRead` | `store.check_capability` | Full verification, **no** state flip — reads stay usable until expiry |
| `Revoke` | `store.revoke` / `sync_revocations` | Adds to the revocation set, bumps `epoch`, refreshes the view (`syncT := clock`) |
| `EpochTick` | `store.sync_revocations()` with no new ids | Epoch bump + staleness-view refresh only |
| `ExpireTick` | wall-clock advance (implicit in `verify_capability`'s `moment > expires_at` check) | Expired caps fail `MayAuthorize` via `clock < expires` |

## 7. Invariants → test-suite enforcement

Every TLA+ invariant corresponds to a property the Python suite actually
tests (all in `tests/test_authority.py`):

| TLA+ invariant | Enforced by (test file :: test) |
|---|---|
| `NoDoubleConsume` | `test_authority.py::TestConsumption::test_double_consume_denied`; `test_attack_double_spend_race`; `test_shell_pep_second_execute_denied_double_spend` |
| `AttenuationMonotonic` | `test_mint_child_from_mandate_ok`; `test_mint_child_from_execution_refused`; `test_child_expiry_clamped_to_parent`; `test_attack_mandate_amplification`; `test_attack_spend_bound_cannot_be_dropped` |
| `RevokedNeverConsumed` | `test_consume_revoked_capability_denied`; `test_consume_revoked_mandate_denies_child` |
| `BudgetNeverNegative` | `test_mint_child_debits_mandate_budget`; `test_mint_child_beyond_actions_limit_denied`; `test_spend_over_capability_limit_denied`; `test_attack_budget_race` |
| `HolderBindingPreserved` | `test_consume_bad_holder_proof_denied_state_unchanged`; `test_attack_holder_key_mismatch`; `test_attack_bearer_replay_denied`; `test_holder_proof_roundtrip` |
| `ExpiryHonored` | `test_expired_capability_denied` |

## 8. Deliberate abstractions (what the model does NOT check)

* **Cryptography.** COSE_Sign1 / Ed25519 are abstracted away; the model
  assumes signatures verify iff the key is the bound one. Signature
  malleability, canonical-CBOR, and kid-allowlist bugs are the test
  suite's job (`test_tampered_signature_denied`, `test_untrusted_issuer_denied`).
* **Mandate lifecycle.** `CREATED → ACTIVE → PAUSED → …` is collapsed to
  `state = "ISSUED"`; `MintChild` requiring an ISSUED parent mirrors
  `debit_mandate_for_child`'s `lifecycle = 'ACTIVE'` guard.
* **Revoking a consumed capability.** `Revoke` is restricted to ISSUED
  capabilities. This is unobservable in the implementation (a consumed
  capability can never authorize again), so no behavior relevant to the
  invariants is lost.
* **State binding / TOCTOU** (`commit_state_bound`, `state_version`) is
  out of scope — it belongs to a separate model.
* **Liveness/availability.** Only safety invariants are stated; the CAP
  trade-off's availability cost (fail-closed on stale revocation view)
  is modeled (`maxStale` + `syncT`) but not quantified.

## 9. Run notes (2026-09-25)

* **Config comments:** TLC config files use `\*` comments, not `#`. The
  `#` form is rejected (`ConfigFileException`); the committed cfgs use
  `\*`.
* **State space is large.** The 3-id bounds (3 ids, 2 effects, 2 holders,
  MaxBudget=2, MaxClock=3, MaxEpoch=4) generate 60M+ distinct states --
  on a 2-core/8 GB box the run thrashed after 130M generated states
  (disk-queue GC death spiral, ~50k states/min) and was killed. The
  reduced 2-id model (`authority-small.cfg`: 2 ids, MaxBudget=1,
  MaxClock=2, MaxStale=1, MaxNonce=1, MaxEpoch=2) **exhausts cleanly:
  11,173,730 states generated, 4,277,023 distinct, depth 6, 6m27s, all 7
  invariants hold, no errors** (TLC 2026.09.25, OpenJDK 21.0.5,
  `-XX:+UseParallelGC -Xmx4g`). Give TLC 4G heap for the small model.
* **TLC found a real spec bug: `RevokedNeverConsumed` was over-strong.**
  The first small-model run violated it with the trace
  `IssueMandate(c1) -> MintChild(c1,c2) -> PresentProof(c2) ->
  Consume(c2) -> Revoke(c1)`: a child consumed *before* its parent
  mandate was revoked. That history is legitimate incident response --
  the consumption happened when nothing was revoked. The invariant's
  intent ("revocation bites at consume time") is enforced by
  `MayAuthorize` (checked on every `Consume`/`CheckRead`), which blocks
  revoke-*then*-consume. The invariant was restated to its checkable
  core (`i \in revoked => authzCount[i] = 0`; `Revoke` requires ISSUED
  and `MayAuthorize` blocks consume-after-revoke), with the rationale in
  a comment above it. The implementation was never wrong -- only the
  invariant's statement.
* **Symmetry works; the earlier "TLC regression" claim was my error.**
  `SYMMETRY` failed with `must have model values as domain and range`
  because the cfg used quoted strings (`{"c1", ...}`). Retested with
  model values (`{c1, c2, c3}`) on a minimal spec: symmetry applies
  correctly. The spec's cfgs still use strings, so symmetry is not
  currently enabled; converting is future work for the 3-id model.
