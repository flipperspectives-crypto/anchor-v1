# ANCHOR v1 — Reproducible Builds

There are **no compiled artifacts** in ANCHOR v1 — it is pure Python
(`src/anchor_v1/`, 25 modules). "Reproducible" therefore means: identical
environment + identical test outcome, i.e. **environment determinism + test
determinism**. This document is the exact recipe.

## 1. Reference environment (verified 2026-09-23)

* Python: **3.12.3** (`/home/hatch/workspace/anchor-v1/.venv/bin/python --version`)
* OS: Linux (repo was built and tested on the Linux VM at
  `/home/hatch/workspace/anchor-v1/anchor-v1/`).
* Frozen dependencies: see `docs/SBOM.md` — notably `cryptography==50.0.1`,
  `pydantic==2.13.5`, `pytest==9.1.1`.

## 2. Exact reproduction recipe

```bash
# 1. Create the virtualenv with the reference interpreter
python3.12 -m venv .venv
source .venv/bin/activate

# 2. Install the package + test extra
#    NOTE: this step requires NETWORK access to PyPI. This build environment
#    has no network; the existing venv at /home/hatch/workspace/anchor-v1/.venv
#    was provisioned with network available. Offline installs are only possible
#    from a local wheel cache or the SBOM-pinned freeze (see step 2b).
pip install -e ".[test]"

# 2b. Pin exact versions (recommended; pyproject.toml only declares floors)
pip install cryptography==50.0.1 pydantic==2.13.5 pytest==9.1.1

# 3. Run the full suite from the package directory
cd anchor-v1
.venv/bin/python -m pytest -q
```

Expected result (verified 2026-09-24, Python 3.12.14): **1043 passed, 1 xfailed**
(collection: `1044 tests collected`). The 2026-09-23 note of 1017 passed predates
Wave 7 and the red-team-2 regression tests. That earlier reference-VM run
completed in ~4s; the current suite took 7.31s on aarch64, most of it the two
guardian timeout tests (`time.sleep(5)` cut off at `decision_timeout_s=0.2`).

Pytest config is in `pyproject.toml` (`[tool.pytest.ini_options]`):
`pythonpath = ["src"]`, `testpaths = ["tests"]`, `addopts = "-ra"`.

## 3. Test-count pinning (regression gate)

`.github/workflows/ci.yml` runs this gate on every push to `anchor-v1` and on
pull requests, on GitHub-hosted Ubuntu with Python 3.12 and the SBOM pins:

```bash
n=$(python -m pytest --collect-only -q 2>/dev/null | tail -1 | grep -oE '^[0-9]+')
test "$n" -ge 1044 || { echo "test count regression: $n < 1044"; exit 1; }
python -m pytest -q
```

The floor is the collected count (1043 passing + 1 strict xfail). A decrease
without an explicit report explaining it fails the workflow. Milestone history
before this workflow existed was recorded in `LOG.md` (for example "Suite
1017/1017, baseline 703/703 intact").

Count-only gates cannot detect weakened tests; the Wave 5 process paired the
count gate with independent verifier re-runs, /tmp-copy mutation spot-checks,
and red-team bypass attempts (see LOG.md). Those checks are not in CI.

## 4. Test determinism notes

* Nonces, capability ids, and key material come from `secrets.token_hex` /
  `cryptography` key generation — random per run, but tests assert on *structure*
  and *verification outcomes*, never on fixed random values. No `random.seed` is
  required and none is used.
* Expiry / revocation-staleness tests inject explicit `now` parameters rather
  than sleeping, so they do not depend on wall-clock speed.
* **Timing-sensitive tests (known):** `tests/test_acs_guardian.py` contains two
  decision-timeout tests (`test_decision_fn_timeout_denied`,
  `test_fail_closed_matrix`) where a `time.sleep(5)` decision function is cut
  off by a `decision_timeout_s=0.2`. They are robust (5s >> 0.2s) but they make
  the suite take ~10s longer and they exercise real thread timeouts — on a
  severely CPU-starved runner the timeout margins still hold (the timeout kills
  the slow function regardless), but these are the tests most likely to behave
  oddly under extreme load.
* `write_state` / `commit_state_bound` ordering is serialized by `RLock` +
  `BEGIN IMMEDIATE`; the store tests exercise thread races under that lock and
  are deterministic by construction (the lock removes the race, it does not just
  narrow it).

## 5. What "reproducible" does NOT mean here

* No sdist/wheel is built by this recipe (the package is installed `-e`, i.e.
  in-place source). Build reproducibility of release artifacts is covered by
  `docs/SIGSTORE.md`.
* No lockfile ships with the repo; exact pins live in `docs/SBOM.md` only.
