# ANCHOR v1 — Changelog

Built 2026-09-23 in a single day by an agent swarm (coordinator + per-capability
builders + independent verifier + red team). Every wave gated on: full suite
green, adversarial harness >= 95% pass with 0 fail, baseline never regressing.

## Wave 0 — Hardened ACS Guardian (`acs_guardian.py`)
Full hook coverage (allow/deny/modify/ask/defer), HMAC wire auth with nonce
registry, fail-closed on all error modes, every ALLOW/MODIFY mints a one-use
capability (mint failure -> DENY; bare ALLOW unconstructible). 77 tests
(65 unit + 12 adversarial).

## Wave 1 — Canonical ActionEnvelope + COSE (`envelope.py`, `cbor.py`, `cose.py`)
Deterministic hand-rolled CBOR, COSE_Sign1 over Ed25519, ActionDigest =
SHA-256(canonical(ActionEnvelope)) as the normative protocol object. Zero new
dependencies. 82 tests, 15 adversarial attacks all rejected.

## Wave 2 — Authority engine (`authority.py`, `store.py`, `pep.py`)
Holder-of-key one-shot capabilities (Mandate vs Execution, monotonic
attenuation), linearizable consumption (one SQLite IMMEDIATE transaction =
verify+epoch+revocation+consume+budget-reserve; documented CAP trade-off and
`max_revocation_staleness`), CredentialBroker + ShellPEP + EgressProxy
(non-bypassable deployment invariant). 74 tests (57 unit + 17 adversarial,
incl. a 32-thread double-spend race).

## Guardian integration (Wave 0/2 seam)
Guardian minting rewired to `authority.issue_execution` over a canonical
ActionEnvelope; `holder_keys` registry (unknown subject -> DENY);
`resolve_pending()` for ASK/DEFER. 90 guardian tests. Suite: 450/450.

## Wave 3 — Planes (`mcp_gateway.py`, `a2a.py`, `planes.py` reframe)
Native MCP (2026-07-28 spec) gateway with fail-closed deny ordering and signed
ExecutionReceipts; A2A 1.0 delegation propagation (8 fail-closed gates in
`receive_delegation`, asor-wimse narrowing at every hop). During test-writing
a real envelope-binding defect was found and fixed in source
(`tools_call` must require the exact `ActionEnvelope` the capability was
minted against). Full test files for both gateways added.

## Wave 4 — Trust core (`state_binding.py`, `scitt.py`, `provenance.py`)
- State-bound prepare/commit TOCTOU defense: EffectPreview binds
  state_version/state_digest; commit re-verifies in one atomic transaction
  (state moved -> `StateChangedError`, zero writes). 28 tests.
- SCITT/RFC 9943 evidence mapping: COSE signed statements + RFC 6962
  transparency receipts; 9 statement types (decision, approval, mint,
  consume, execution, freeze, revocation, policy_change, epoch). 35 tests.
- Provenance-bound read capabilities: issuance fails closed without a
  provenance anchor; reads verify writer Ed25519 signatures and every
  caveat. 27 tests.
Suite: 697/697. Three post-wave fixes (missing SCITT statement types,
malformed-provenance-signature normalization, read-invariant re-enforcement
on the verify path) -> 703/703.

## Wave 5 — Enterprise adapters
`policy_providers.py` (native + Cedar/Rego pure-Python subsets, signed
PolicyDecisionRecord), `identity_adapters.py` (SPIFFE SVID X.509 verify,
hand-rolled OIDC JWT, Entra/Okta issuer+tenant pinning — consume-only),
`stepup.py` (WebAuthn-shaped assertions with signCount clone detection,
m-of-n QuorumApproval, one-time-use challenge ledger), `agent_identity.py`
(did:key Ed25519, COSE capability assertions, verified registry with
revocation). 302 new tests. 14 confirmed bypasses found and closed across
4 adversarial rounds (NaN/Infinity smuggling incl. Decimal, type-confusion
neq, X.509 pathlen, JWT exp/Infinity, cross-quorum replay, ReDoS, clock_skew
footgun); every fix mutation-checked. Suite: 1005/1005.

## Wave 6 — Conformance
`tla/authority.tla` (7 invariants) + `tla/README.md` TLC run-book;
`tests/test_conformance.py` (12 named guarantees, each with threat /
precondition / attack / invariant / test-vector / expected-receipt);
`docs/` trust package (THREAT_MODEL.md, SPEC.md, SBOM.md,
REPRODUCIBLE_BUILDS.md, SIGSTORE.md — 514 lines, 11 residual risks
explicit). Suite: 1017/1017.

## Wave 7 — Guardian<->PEP integration seam (`acs_guardian.py`, additive only)
Closed the structural gap the first reality trial exposed (Guardian minted
only acs-plane envelopes; ShellPEP refused them). Guardian now accepts an
optional caller-presented execution-plane envelope, validates
principal/args_digest/policy_ref/validity-window, and mints the one-use
capability against its digest (mirrors the MCP gateway's presented-envelope
pattern). Default path byte-identical; ShellPEP plane check untouched.
13 tests + 1 strict xfail (double-mint digest-level replay tripwire, kept
deliberately). Suite: 1030/1030.

## Reality trial — PASS (2026-09-23)
5/5 real actions governed end-to-end (file write, append, git
init/add/commit `bfccaf5` in `trial-scratch/`), every action
Guardian -> policy -> presented-envelope mint -> ShellPEP. 4/4 live bypass
probes denied (replay -> DoubleSpendError, forgery -> PEPError, ungoverned
execution -> PEPError, post-approval tampering -> PEPError). 15/15 SCITT
evidence statements verified offline, chain intact. GitHub push SKIPPED
(`gh` not logged in; no repos created, nothing faked).

## v1.0.0 — Known limitations (shipped deliberately)

- **P5 cross-plane seam (documented residual).** The Guardian<->shell PEP
  integration seam does not enforce verb/target equality across planes: a
  shell-plane `verb="exec"`/`target="trial-cmd"` is accepted for a guardian
  event `action="shell.exec"`/`resource="sandbox://host"` by design.
  `_validate_presented_envelope` (`src/anchor_v1/acs_guardian.py`) binds
  principal, exact args (`args_digest`), policy ref, and validity window;
  verb/target are the presenting plane's labels and have no protocol-level
  ground truth to equate against. Each plane validates strictly within its
  own scope; cross-plane translation is the deployment/orchestrator's
  responsibility until v1.1 (see `docs/THREAT_MODEL.md` item 12 and
  `docs/SPEC.md` §4). Tripwire test
  `tests/test_redteam2_fixes.py::test_p5_cross_plane_envelope_allowed_by_design`
  locks this behavior. This does not block publication: the enforced
  backstops (`args_digest` -> `action_digest` -> the PEP's digest->command
  registry) bind exactly what runs.
