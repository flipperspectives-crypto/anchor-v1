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

Expected result (as of 2026-09-23): **1017 passed** (collection alone:
`python -m pytest --collect-only -q` reports `1017 tests collected`).
The run above completed in ~4s on the reference VM.

Pytest config is in `pyproject.toml` (`[tool.pytest.ini_options]`):
`pythonpath = ["src"]`, `testpaths = ["tests"]`, `addopts = "-ra"`.

## 3. Test-count pinning (regression gate)

There is **no CI workflow in the repo** (no `.github/` directory). Count pinning
is procedural today, enforced by the coordinator at every milestone:

1. Run the full suite: `python -m pytest -q`.
2. Record the result in `LOG.md` (milestone lines, e.g. "Suite 1017/1017,
   baseline 703/703 intact").
3. A count that *decreases* or diverges from the previous milestone without an
   explicit builder report explaining it is treated as a regression and blocks
   the gate.

The recommended machine-checkable form (to be wired into CI when it exists):

```bash
n=$(python -m pytest --collect-only -q 2>/dev/null | tail -1 | grep -oE '^[0-9]+')
test "$n" -ge 1017 || { echo "test count regression: $n < 1017"; exit 1; }
```

Count-only gates cannot detect weakened tests; the Wave 5 process paired the
count gate with independent verifier re-runs, /tmp-copy mutation spot-checks,
and red-team bypass attempts (see LOG.md).

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
