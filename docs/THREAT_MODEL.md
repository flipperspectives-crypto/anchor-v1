# ANCHOR v1 — Threat Model

Status: Wave 6 conformance document. Every claim cites the module and the test file
that pins it. Last verified against the codebase and the 1017/1017 green suite on
2026-09-23.

## 1. Assets

| Asset | Form | Module |
|---|---|---|
| Holder-of-key capabilities (mandate / execution / read) | COSE_Sign1 over canonical CBOR payload | `src/anchor_v1/authority.py` |
| Policy documents (native rules, Cedar subset, Rego subset) | Data-as-dict, signed `PolicyDecisionRecord` | `src/anchor_v1/policy_providers.py` |
| Identity trust bundles (CA bundle, JWKS, Entra/Okta tenant pins) | Injected at construction, never issued | `src/anchor_v1/identity_adapters.py` |
| Evidence ledger (SCITT statements, receipts, Merkle checkpoints) | COSE_Sign1 statements + transparency receipts | `src/anchor_v1/scitt.py`, `src/anchor_v1/anchored_checkpoints.py` |
| Downstream credentials (secrets the agent must never see) | Held by the PEP broker, not the agent | `src/anchor_v1/pep.py` |

## 2. Trust boundaries

1. **Governor vs agent process.** The governor (authority, store, Guardian, PEP) runs
   OUTSIDE the agent sandbox. An agent with ambient credentials plus a governor
   *library* is UNGOVERNED — a library cannot stop code that does not call it.
   (`src/anchor_v1/pep.py` module docstring; enforced by deployment shape.)
2. **Agent process vs PEP.** The PEP (`CredentialBroker`) holds raw downstream secrets
   and exposes only brokered execution; `broker.secrets` raises `BrokerAccessDenied`.
   The agent never sees ambient credentials.
3. **PEP vs transparency log.** SCITT statements are issued by the governor and
   countersigned by the transparency service as receipts riding in COSE label 394;
   verification is fully offline (`src/anchor_v1/scitt.py`). Even a compromised
   operator cannot rewrite history without breaking the Merkle root, the
   checkpoint-to-checkpoint hash link, or the independent anchor proof
   (`src/anchor_v1/anchored_checkpoints.py::verify_checkpoint_chain`).
4. **Online verifier vs offline verifier.** Verification is designed for offline
   operation (Ed25519, deterministic CBOR, hash chains). Network is required only
   for revocation sync and for OpenTimestamps public anchoring — both isolated
   behind explicit interfaces (see RESIDUAL RISKS).

## 3. Threat actors

* **Malicious agent** — holds stolen capability bytes, replays proofs, races consumes,
  tampers with envelopes, smuggles authority through delegation.
* **Compromised operator** — rewrites logs, rotates constitutions, injects policy,
  rewrites checkpoint history.
* **Network attacker** — forges guardian wire frames, tampers COSE headers, replays
  WebAuthn assertions across quorums.
* **Malicious policy author** — crafts NaN/type-confusion contexts, `neq` bypasses,
  rules outside the documented subsets, fail-open defaults.
* **Confused deputy** — swaps the action digest between approval and execution so a
  capability/approval is applied to the wrong action.

## 4. Threat -> mitigation -> test table

| Threat | Mitigating module / mechanism | Covering test file |
|---|---|---|
| Stolen capability bytes used as bearer token | Holder-of-key proof: capability presented *with* valid `verify_holder_proof` signature over `capability_id \|\| challenge`, else `AuthorizationDenied`; stolen blob alone is useless | `src/anchor_v1/authority.py` `make_holder_proof`/`verify_holder_proof` -> `tests/test_authority.py` |
| Proof replay against a new challenge | Challenge is a fresh server nonce per request (`ShellPEP`/store require it); proof binds `capability_id \|\| challenge` | `src/anchor_v1/authority.py` -> `tests/test_authority.py` |
| Double-consume race | Single atomic transaction: guarded `UPDATE ... WHERE state='ISSUED'`, zero rowcount -> `DoubleSpendError`; `RLock` + `BEGIN IMMEDIATE` | `src/anchor_v1/store.py::_consume_inner` step (11) -> `tests/test_authority.py` (`TestStore`) |
| Budget overspend by children | `debit_mandate_for_child` reserves the child's full `spend_limit` (worst case) atomically; guarded `UPDATE` makes oversubscription impossible | `src/anchor_v1/store.py` -> `tests/test_authority.py` |
| Privilege amplification via delegation | `mint_child` structural attenuation: same `action_digest`, `spend_limit <=` parent, `expires_at <=` parent, staleness `<=` parent; execution caps cannot mint | `src/anchor_v1/authority.py::mint_child` -> `tests/test_authority.py`; SUBSUMPTION in `src/anchor_v1/attenuated_tokens.py` -> `tests/test_attenuated_tokens.py`; `src/anchor_v1/delegation_chains.py::verify_chain` -> `tests/test_delegation_chains.py` |
| Revoked capability still executes | Revocation set + epoch; `max_revocation_staleness` fail-closed (`StaleRevocationError`) when the revocation view is too old — the CAP trade-off made explicit | `src/anchor_v1/store.py` (`sync_revocations`, `_consume_inner` steps 5-6) -> `tests/test_authority.py` |
| Agent reads raw downstream secrets | `CredentialBroker.secrets` raises `BrokerAccessDenied`; only brokered execution | `src/anchor_v1/pep.py` -> `tests/test_authority.py` (`TestPEP`) |
| Guardian wire forgery / replay | Every frame HMAC-signed under pre-shared key with fresh nonce + timestamp window; guardian errors/decisions-timeouts fail closed to DENY | `src/anchor_v1/acs_guardian.py` -> `tests/test_acs_guardian.py` |
| COSE downgrade / header smuggling | Algorithm allowlist (EdDSA -8 only); protected header must be exactly `{1: -8, 4: kid}`; unprotected header must be empty; strict deterministic CBOR | `src/anchor_v1/cose.py` -> `tests/test_envelope.py` (ATTACK-03, ATTACK-12) |
| Envelope tampering / digest swap | `action_digest = SHA-256(canonical CBOR)`; store binds envelope digest to capability digest at consume (step 4); `EffectPreview` binds envelope digest; Guardian must call `check_approval_binding` | `src/anchor_v1/envelope.py`, `src/anchor_v1/store.py`, `src/anchor_v1/stepup.py` -> `tests/test_envelope.py`, `tests/test_authority.py`, `tests/test_stepup.py` |
| Operator rewrites evidence history | Hash-chained shadow log (`verify_log`); Merkle checkpoints with hash-linked chain re-validated offline; SCITT transparent statements with receipts | `src/anchor_v1/shadow_mode.py` -> `tests/test_shadow_mode.py`; `src/anchor_v1/anchored_checkpoints.py` -> `tests/test_anchored_checkpoints.py`; `src/anchor_v1/scitt.py` -> `tests/test_scitt.py` |
| Shadow-mode downgrade / replay | Mode changes only via signed `ModeChangeCommand` from an authorized key, with monotonic sequence number + expiry; `never_shadow` patterns always enforce | `src/anchor_v1/shadow_mode.py` -> `tests/test_shadow_mode.py` |
| Untrusted data injection into reads | Read capabilities MUST bind provenance (`read_trusted_writers` allowlist or `read_require_statement`) at issuance AND at verify; writes record signed provenance | `src/anchor_v1/authority.py::_check_read_caveats`, `src/anchor_v1/provenance.py` -> `tests/test_provenance.py` |
| NaN / type-confusion policy bypass (RT-001) | Non-finite numerics (any numeric type, nested) make every condition FALSE incl. `neq`; type-strict comparisons; default DENY; exceptions -> DENY | `src/anchor_v1/policy_providers.py` -> `tests/test_policy_providers.py` |
| Policy outside documented subset | Anything outside the documented Cedar/Rego subsets raises `PolicyError` at load — never silently ignored | `src/anchor_v1/policy_providers.py` -> `tests/test_policy_providers.py` |
| ReDoS in identity target patterns | Regex engine DELETED, replaced with a linear-time token matcher; `_MAX_TARGET_PATTERN_LEN=2048`, `_MAX_TARGET_LEN=4096` fail closed | `src/anchor_v1/agent_identity.py` -> `tests/test_agent_identity.py` |
| Clock-skew abuse in OIDC | `clock_skew` must be finite >= 0, capped at 86400s at construction (inherited by Entra/Okta); exp/iat/nbf require `math.isfinite` | `src/anchor_v1/identity_adapters.py` -> `tests/test_identity_adapters.py` |
| X.509 path-len spoofing | `pathlen` enforced per RFC 5280 S4.2.1.9, depth-tracked, explicit violation is fatal | `src/anchor_v1/identity_adapters.py` -> `tests/test_identity_adapters.py` |
| WebAuthn cross-quorum replay | One-time-use challenge ledger: in-flight registry + burned ledger (process-wide lock); reused challenge can never satisfy a second quorum in-process; quorum sealed after finalize | `src/anchor_v1/stepup.py` -> `tests/test_stepup.py` (incl. real cross-quorum replay test) |
| Hardware authenticator lacking digest binding | Assertions that cannot emit the action-digest extension are covered by the challenge ledger + the Guardian's `check_approval_binding` | `src/anchor_v1/stepup.py` -> `tests/test_stepup.py` |
| TOCTOU between policy decision and effect | Prepare/Commit: `commit_state_bound` re-verifies `(version, digest)` binding INSIDE the same `BEGIN IMMEDIATE` transaction that consumes the capability and applies writes; mismatch -> `StateChangedError`, everything rolled back | `src/anchor_v1/store.py::commit_state_bound`, `src/anchor_v1/state_binding.py` -> `tests/test_state_binding.py` |
| MCP tool confusion / A2A card spoofing | `NativeMCPGateway` enforces holder-of-key capabilities on every `tools/call`; verifiable agent cards signed by the guardian key | `src/anchor_v1/mcp_gateway.py` -> `tests/test_mcp_gateway.py`; `src/anchor_v1/a2a.py` -> `tests/test_a2a.py` |
| Constitution forgery / retroactive rotation | m-of-n Ed25519 signatures over content hash; supersedes hash chain; trust-set rotation is forward-only (never retroactive) | `src/anchor_v1/multisig_constitution.py` -> `tests/test_multisig_constitution.py` |
| End-to-end hostile paths | 45-scenario adversarial harness attacking Wave A capabilities + cross-module attacks; exit 0 only if 0 FAIL | `adversarial_harness.py` (45 scenarios: 43 PASS, 2 FLAG, 0 FAIL — re-verified 2026-09-23) |

## 5. RESIDUAL RISKS (not covered — stated honestly)

1. **Rust/WASM offline verifier not built.** The offline-verification story rests on the
   Python implementation. A Rust or WASM verifier (for constrained/offline deployments)
   was blocked on toolchain availability ("no Rust toolchain", blocker 11, LOG.md) and
   is not built. The Python verifier stands in.
2. **OpenTimestamps anchoring needs network + overseer approval.** `OpenTimestampsAnchor`
   is a tested stub that raises until overseer-approved network use; real calendar
   I/O lives behind `OTSCalendarClient` (`src/anchor_v1/anchored_checkpoints.py`).
   Public timestamping does not happen in an offline deployment.
3. **Coordinator duties (documented in code, NOT enforced by code).**
   * Fresh server challenge per request — the modules *require* a challenge but the
     *freshness source* is a coordinator duty.
   * `stepup.py` verifier instances MUST be long-lived across quorums; cross-process
     replay is not defeated by the module ("The coordinator SHOULD persist burned
     challenges durably; that persistence is out of scope here").
   * `identity_adapters.py` `clock_skew` choice (bounded to [0, 86400] but the exact
     value is a deployment decision) and trust-bundle provisioning: trust material
     (CA bundle, JWKS) is INJECTED at construction with no network fetch — a wrong
     bundle is a deployment failure, not a code failure.
4. **Cedar/Rego subsets are documented subsets, not full languages.** Policies written
   against full Cedar or full Rego semantics will fail to load; operators must know
   which constructs are rejected (`src/anchor_v1/policy_providers.py` docstring).
5. **No CI workflow ships with the repo** (no `.github/`). Count pinning and gate
   verdicts are procedural today (coordinator full-suite run + LOG.md milestones).
   See `docs/REPRODUCIBLE_BUILDS.md`.
6. **Nothing is signed yet.** This package ships no signatures; the Sigstore run-book
   in `docs/SIGSTORE.md` describes release-day signing, not an existing artifact.
7. **Linearizability holds for one process only.** The `RLock` + `BEGIN IMMEDIATE`
   linearizability argument — the basis for no-double-consume (I1) and the atomic
   consume transaction — holds for ONE process. The store is a SQLite stand-in
   for the production serializable-Postgres design; multi-process/multi-host
   linearizability is a deployment property, not a property the code can
   guarantee (see `docs/SPEC.md` §4).
8. **Wire nonces are single-use PER GUARDIAN, not per PSK (red-team-2 P2).**
   Two `AcsGuardian` instances sharing one PSK each accept the same
   byte-identical frame and mint two distinct one-use capabilities for one
   intended action. HARD REQUIREMENT: one guardian instance per PSK for
   one-use semantics. Do not run "replicas" behind a load balancer on the
   same PSK expecting cross-instance replay protection — that needs a
   shared nonce store, which is not implemented.
9. **Wire subject is self-asserted under the PSK channel (red-team-2 P3).**
   The HMAC-PSK wire protocol authenticates the CHANNEL, not the subject:
   any PSK holder can name any subject in `event.subject`, minting
   capabilities bound to a victim's holder key or poisoning the ASK
   approver queue (holder-of-key proof still stops direct USE by the
   attacker, but audit attribution is poisonable). Mitigations, in order:
   (a) pass `wire_allowed_subjects` to `AcsGuardian` to DENY wire subjects
   outside a known set at the authentication layer (default off);
   (b) production MUST use a mutually-authenticated channel (mTLS or
   DPoP-bound) that binds the subject to the channel identity, per the
   module docstring's production note. Follow-up: per-peer keys or
   channel-bound subjects.
10. **`LocalTransparencyLog` without `trusted_issuers` is permissive
    (red-team-2 P7).** With no `trusted_issuers`, any structurally-valid
    statement — including an attacker-forged one — registers and receives
    a genuine inclusion receipt. Construction now emits a loud
    `UserWarning` in that case. Production deployments MUST pass an
    explicit `trusted_issuers` set; the permissive default exists only for
    tests and local experimentation.
11. **`decision_timeout_s` is not a hard bound against GIL-holding
    decision functions (red-team-2 P8).** The timeout is enforced via
    `ThreadPoolExecutor.result(timeout=...)`, but a CPU-bound decision
    function (e.g. a catastrophic-backtracking regex in a policy rule) can
    starve the GIL and delay the timeout's enforcement itself (measured:
    ~56s against a 2s bound), and pinned worker threads stay burning in
    the pool — subsequent decisions DENY (fail-closed) but availability
    degrades. The decision outcome still fails closed (DENY), never
    fail-open. Production MUST isolate decision logic in a separate
    process (as the `AcsGuardian` docstring already requires); in-process
    timeouts are a backstop, not a guarantee.
12. **Presented-envelope verb/target are not validated against the event
    (red-team-2 P5).** `_validate_presented_envelope` binds principal,
    exact args (`args_digest`), policy ref, and validity window — but NOT
    `verb`/`target` against `event.action`/`event.resource`. This is
    deliberate, not an oversight: the Wave 7 seam is cross-plane by design
    (the shell shim presents `verb="exec"`/`target="trial-cmd"` for a
    guardian event with `action="shell.exec"`/`resource="sandbox://host"`),
    and no cross-plane verb/target mapping exists in the protocol, so the
    guardian has no ground truth to equate against. The what/where binding
    end-to-end is `args_digest` → `action_digest` → the PEP's
    digest→command registry (unregistered digests are refused at consume).
    Residual: a compromised shim (outside the trust boundary — the shim is
    a trusted component) could label a presented envelope misleadingly;
    the minted capability would still be bound to the exact decided args.
    Recommended follow-up: an explicit per-deployment verb/target
    allowlist or plane mapping if deployments need the guardian to
    second-guess shim labels.
