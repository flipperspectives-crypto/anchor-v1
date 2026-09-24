# ANCHOR v1

An open, model-agnostic runtime governor for AI agents. One invariant: no consequential autonomous action occurs unless a deterministic authority authorized that exact effect, through an unforgeable tightly-bounded capability; execution happens through an enforcement point the agent cannot bypass; the chain is independently verifiable later. A hardened ACS-compatible Guardian decides, every ALLOW mints a one-use holder-of-key capability bound to the exact action digest, a credential-brokering PEP executes, and SCITT-compatible (RFC 9421/9943) evidence makes the whole trail verifiable offline. Pure Python, stdlib + `cryptography` + `pydantic` only.

Release `v1.0.0` (annotated tag on commit `b1949cc`). This is a research-grade artifact: the limitations below are real and stated, not footnoted.

## Named guarantees

Twelve named guarantees, each with threat / precondition / attack / invariant / test vector / receipt, in `tests/test_conformance.py`. 1017/1017 conformance-wave tests green; 9/9 mutation checks green.

| ID | Threat pinned |
|---|---|
| CAP-REPLAY-001 | Capability replay / double-spend |
| AUTHZ-TOCTOU-007 | Prepare/commit time-of-check-time-of-use race |
| BUDGET-RACE-008 | Concurrent consumes racing a spend limit |
| LEDGER-FORK-009 | SCITT transparency log fork |
| POL-NAN-010 | Non-finite (NaN/Infinity) smuggling in policy context |
| POL-NEQTYPE-011 | `neq` with type-mismatched operands |
| ID-SVIDPATH-012 | X.509 pathlen-violating SPIFFE chain |
| ID-JWTEXP-013 | Non-finite or absurdly-skewed JWT times |
| STEPUP-XQUORUM-014 | Cross-quorum assertion replay |
| AGID-REDOS-015 | ReDoS via pathological glob patterns |
| AGID-SPENDTYPE-016 | Non-finite max_spend in agent assertion |
| DELEG-DEPTH-017 | Delegation chain at depth ≥ 2 with asor-wimse narrowing |

## Trust package (`docs/`, `tla/`)

| File | Contents |
|---|---|
| `docs/THREAT_MODEL.md` | Assets, 45-scenario adversary harness results, residual risks |
| `docs/SPEC.md` | Authority-core formal specification summary |
| `docs/SBOM.md` | Bill of materials; import audit of all `src/` and `tests/` |
| `docs/REPRODUCIBLE_BUILDS.md` | Environment + test determinism recipe |
| `docs/SIGSTORE.md` | Keyless-signing run-book (not yet executed) |
| `tla/authority.tla` + `tla/README.md` | Finite-state model, 7 invariants, exact TLC run-book |

## Test results

1043 passed, 1 xfailed (1044 collected). Per wave: Waves 0–4 (authority core: deterministic policy evaluation, one-use capabilities, credential-brokering PEP, SCITT transparency log with 9 statement types) — 703 green; Wave 5 (enterprise adapters: native + Cedar/Rego-subset policy providers, SPIFFE/OIDC/Entra/Okta consume-only identity adapters, WebAuthn + m-of-n quorum step-up, `did:key` agent identity) — 1005/1005, 100+ adversarial attacks across 5 rounds with 18 bypasses found and closed, zero open; Wave 6 (conformance) — 1017/1017, 9/9 mutation checks; Wave 7 (Guardian↔PEP presented-envelope integration) — 1030 green, independent red team blocked 11/11 attacks; red-team-2 added 13 regression tests. Reality trial: 5/5 real actions governed end-to-end (file write, append, git init/add/commit), 4/4 live bypass probes denied, 15/15 SCITT statements verified offline, tampered evidence rejected.

## Honest limitations

1. **Rust/WASM offline verifier unbuilt.** No Rust toolchain on the build machine. The Python verifier stands in; recorded as a residual risk.
2. **TLC model check not executed.** No Java on the build machine. Spec and run-book exist; nobody has run them.
3. **Cedar/Rego are pure-Python subsets.** Documented subsets, not the real engines. Do not claim full Cedar/OPA compatibility.
4. **Single-process linearizability only.** SQLite stands in for serializable Postgres; multi-node deployments untested.
5. **Double-mint tripwire.** Minting the same presented envelope twice yields two consumable capability_ids (per-id one-use enforcement). Adjudicated not-exploitable (trusted-shim-only seam) and kept as a strict-xfail regression tripwire.
6. **Tag is annotated, not PGP/Sigstore-signed.** The signing run-book (`docs/SIGSTORE.md`) is written; executing it needs the maintainer's identity.
7. **CI is one Ubuntu runner.** `.github/workflows/ci.yml` installs the SBOM pins on Python 3.12 and runs the suite plus a 1044-test collection floor. It does not run mutation checks, the adversary harness, or TLC, and it has no second OS. The v1.0.0 tag itself was verified on one machine, one Python (3.12.3), one day.

## Run the tests

Requires Python ≥ 3.12 and the test dependencies (`pytest`).

```sh
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[test]"
pytest
```

Or, from the repo root with an existing venv:

```sh
.venv/bin/pytest -q
```

Expected result: `1043 passed, 1 xfailed` (the xfail is the double-mint tripwire, limitation 5). The same command is what `.github/workflows/ci.yml` runs. `pytest` config lives in `pyproject.toml` (`pythonpath = ["src"]`, `testpaths = ["tests"]`, `addopts = "-ra"`).
