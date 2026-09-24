# ANCHOR v1 — Software Bill of Materials (SBOM)

Generated: 2026-09-23, from `/home/hatch/workspace/anchor-v1/.venv/bin/python -m pip freeze`.
Codebase: `anchor-v1/` (pure Python, `src/anchor_v1`, 25 modules).
Declared dependencies: `pyproject.toml` — `cryptography>=42`, `pydantic>=2.6`,
`pytest>=8` (test extra). Requires Python >= 3.12.

Import audit: every `^import` / `^from` in `src/` and `tests/` was checked. The code
imports exactly three third-party packages — `cryptography`, `pydantic`, and
`pytest` (tests only). Everything else in the venv is either a transitive
dependency of those three or an installed-but-unused package (listed below).

## A. Third-party runtime dependencies (imported by src/)

| Package | Frozen version | Declared | Used for |
|---|---|---|---|
| cryptography | 50.0.1 | `cryptography>=42` | Ed25519 sign/verify everywhere (`crypto.py`, `authority.py`, `cose.py`, `scitt.py`...); `Ed25519PublicKey`; X.509 chain verification for SPIFFE SVIDs (`identity_adapters.py`, `from cryptography import x509`) |
| pydantic | 2.13.5 | `pydantic>=2.6` | `StrictModel` (`models.py`), policy/constitution/checkpoint models (`policy_providers.py`, `multisig_constitution.py`, `anchored_checkpoints.py`) |

## B. Third-party test dependencies (imported by tests/ only)

| Package | Frozen version | Declared | Used for |
|---|---|---|---|
| pytest | 9.1.1 | `pytest>=8` (test extra) | The suite: 1044 collected (1043 pass, 1 xfail) |

## C. Transitive dependencies (installed, not directly imported)

| Package | Frozen version | Pulled in by |
|---|---|---|
| annotated-types | 0.8.0 | pydantic |
| cffi | 2.1.1 | cryptography |
| iniconfig | 2.3.0 | pytest |
| packaging | 26.3 | pytest |
| pluggy | 1.6.0 | pytest |
| pycparser | 3.0 | cffi |
| pydantic_core | 2.46.5 | pydantic |
| Pygments | 2.21.0 | pytest |
| typing-inspection | 0.4.4 | pydantic |
| typing_extensions | 4.16.0 | pydantic, cryptography, typing-inspection |

## D. Installed but NOT imported (not runtime dependencies)

Verified by grep over all of `src/`, `tests/`, and `adversarial_harness.py`: no
`import`/`from` of these names. They are venv environment extras, not ANCHOR
dependencies. (Names appear only in comments/strings — e.g. the hand-rolled,
stdlib-only OTS codec in `anchored_checkpoints.py` mentions "python-opentimestamps"
as the reference implementation it is byte-compatible with; it does not import it.)

| Package | Frozen version |
|---|---|
| beautifulsoup4 | 4.15.0 |
| certifi | 2026.7.22 |
| charset-normalizer | 3.5.1 |
| filelock | 4.0.1 |
| gdown | 6.4.0 |
| idna | 3.20 |
| opentimestamps | 0.4.5 |
| pycryptodomex | 3.23.0 |
| PySocks | 1.7.1 |
| python-bitcoinlib | 0.12.2 |
| requests | 2.34.2 |
| soupsieve | 2.9.2 |
| tqdm | 4.70.1 |
| urllib3 | 2.8.0 |

## E. Standard library (no vendoring, no versions to pin)

The security-critical path — `authority.py`, `store.py`, `cose.py`, `cbor.py`,
`canonical.py`, `crypto.py`, `envelope.py` — additionally uses only stdlib:
`sqlite3` (linearizable store), `hashlib`/`hmac` (SHA-256 digests, guardian wire
HMAC), `secrets` (nonces, capability ids), `threading` (process-wide lock),
`json`, `base64`, `struct`, `re` (native-rule regexes; identity uses a
linear-time matcher instead), `math`, `decimal`, `fractions`, `fnmatch`,
`datetime`, `uuid`, `dataclasses`, `collections`, `subprocess` (PEP), `os`,
`pathlib`, `time`, `copy`, `numbers`, `binascii`, `typing`, `abc`, `urllib`
(not used for fetching — adapter parsing only), `concurrent.futures` (guardian
timeout), `hmac`.

## F. Dependency policy for the security-critical path

1. **No new runtime dependencies without a security review.** The authority core
   (Section E) is deliberately stdlib + `cryptography` + `pydantic` only.
2. **Hand-rolled codec policy:** CBOR (RFC 8949 deterministic), COSE_Sign1
   (RFC 9052), and the OpenTimestamps codec are hand-rolled on stdlib rather than
   pulled in as dependencies, to keep the trusted computing base small
   (`src/anchor_v1/cbor.py`, `src/anchor_v1/cose.py`, `src/anchor_v1/anchored_checkpoints.py`
   lines ~514-629). Third-party CBOR/COSE libraries were deliberately avoided.
3. **Residual gaps (honest):** `pyproject.toml` declares *floors*, not pins
   (`cryptography>=42`, `pydantic>=2.6`, `pytest>=8`) — there is no lockfile in
   the repo, so the freeze above is the pin and it lives only in this document.
   The venv contains unused packages (Section D) that should be removed from
   release environments. No dependency vulnerability scan is wired into the repo.
