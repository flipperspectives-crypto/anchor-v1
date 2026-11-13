# Solana Foundation Grant Proposal: ANCHOR v1

**Project Name:** ANCHOR v1 Constitutional Policy Enforcement Point for Solana Autonomous AI Agents  
**Category / Track:** Artificial Intelligence (AI) Infrastructure & Security  
**Target Grant:** Solana Foundation AI & Developer Tooling Grant ($10,000 USDG)  
**Primary Applicant / Author:** Lauren Flipo (`fliptrigga13`, Canada)  
**Repository:** [fliptrigga13/anchor-v1](https://github.com/fliptrigga13/anchor-v1)  
**Active Upstream PR:** [#4: feat(integrations): Jupiter Swap V2 & Solana On-Chain PEP](https://github.com/flipperspectives-crypto/anchor-v1/pull/4)  
**License:** Apache-2.0 (100% Free & Open Source Public Good; offline Rust/WASM verifier crate MIT)  

---

## 1. Executive Summary & Problem Statement

Autonomous AI agents executing on Solana (powered by frameworks such as Solana Agent Kit, ElizaOS, Rig, and LangChain) represent the fastest-growing frontier of decentralized automation. However, current agent deployment patterns suffer from a fatal security vulnerability: **Ambient Authority and Key Compromise**.

### The Vulnerability:
1. **Raw Signing Keys in Agent Context:** Agents are provisioned with raw Ed25519 private keys or unrestricted ambient RPC signing capabilities.
2. **Prompt Injection & Model Drift Exploitation:** If an LLM agent experiences prompt injection, tool-call hallucination, or adversarial jailbreaking, the agent can immediately broadcast arbitrary transactions: draining treasuries, transferring assets to attacker-controlled accounts, or calling malicious smart contracts.
3. **Absence of Cryptographic Policy Binding:** Transactions submitted by AI agents carry no tamper-proof cryptographic audit trail proving which governance policy, budget cap, or human quorum authorized the action.

---

## 2. The Solution: ANCHOR v1 Constitutional Runtime

**ANCHOR v1** introduces a formally modeled (`tla/authority.tla` — 4,277,023 distinct TLC states verified across 7 invariants with 0 violations in `tla/TLC_RUN_RESULTS.txt`), fail-closed constitutional runtime with an offline Rust/WASM verifier (`rust/verifier/`), designed specifically to secure autonomous AI agents on Solana.

### Key Architectural Invariants:
1. **Zero Ambient Authority (`SolanaCredentialBroker`):**
   * Private signing keys are strictly isolated in a tamper-resistant broker outside the agent execution boundary.
   * Direct inspection of private keys or secrets by agent code triggers immediate `BrokerAccessDenied` exceptions.
2. **Cryptographic Capability Envelopes (COSE-Sign1):**
   * Agents cannot broadcast transactions at will. They must propose an `ActionEnvelope` and obtain an unforgeable COSE-Sign1 capability token attested by an Ed25519 constitutional quorum.
3. **Fail-Closed Policy Enforcement Point (`SolanaInstructionPEP`):**
   * Intercepts every Solana instruction prior to serialization and signing.
   * Enforces program ID whitelisting (System Program, SPL Token, Token-2022, Compute Budget, etc.).
   * Enforces recipient address whitelisting and transaction lamport spend ceilings.
4. **Linearizable Single-Use Store (`CapabilityStore`):**
   * Every capability is atomically consumed in a linearizable store, guaranteeing mathematical immunity against double-spends, replay attacks, and TOCTOU divergence.
5. **SCITT Immutable Audit Attestation:**
   * Emits deterministic SCITT (Supply Chain Integrity, Transparency, and Trust) audit receipts linking action digests, on-chain transaction signatures, and constitutional policy references.

---

## 3. Scope of Work & Grant Milestones ($10,000 USDG)

| Milestone | Deliverable Description | Status | Grant Allocation |
| :--- | :--- | :--- | :--- |
| **Milestone 1** | **Core Solana Instruction PEP & Credential Broker**<br>Complete implementation of `SolanaInstructionPEP`, `SolanaCredentialBroker`, program ID whitelist, spend envelopes, atomic single-use capability consumption, and 100% passing test suite. | **100% Completed** | **$3,000 USDG** |
| **Milestone 2** | **Solana Agent Kit & ElizaOS Middleware Adapters**<br>Turnkey drop-in middleware package for `@solana/agent-kit` and ElizaOS, enabling agent developers to wrap their wallet adapters with Anchor constitutional enforcement in one line of code. | **Ready for Dev** | **$4,000 USDG** |
| **Milestone 3** | **On-Chain Constitutional Attestation & Devnet Sandbox**<br>Solana on-chain program (written in Anchor/Rust) that anchors constitutional epoch checkpoints and revocation roots on-chain, accompanied by an interactive Devnet test harness. | **Ready for Dev** | **$3,000 USDG** |

---

## 4. Public Good Impact on the Solana Ecosystem

ANCHOR v1 is 100% open-source software built to protect the Solana ecosystem:
* **Securing Autonomous Capital:** Enables DAOs, enterprise treasuries, and DeFi protocols to deploy autonomous agents with mathematical assurance that wallets cannot be drained beyond predefined spend envelopes.
* **Ecosystem Standardization:** Establishes the first formal, RFC-compliant cryptographic capability and policy enforcement standard for Solana AI agent frameworks.
* **Attracting Institutional Liquidity:** Provides institutional risk managers and compliance officers with verifiable audit receipts required to fund autonomous on-chain trading and governance strategies.

---

## 5. Verification & Test Receipts

ANCHOR v1 features a comprehensive, battle-tested test suite:

```bash
# Run the complete Anchor v1 integration test suite
pytest -v tests/test_solana_pep.py tests/test_jupiter_pep.py
```

### Verified Test & Formal Proof Matrix:
* **Formal TLA+ Model (`tla/authority.tla` & `tla/TLC_RUN_RESULTS.txt`):** PASS (11,173,730 states generated / 4,277,023 distinct states verified, 0 violations across all 7 invariants: `TypeOK`, `NoDoubleConsume`, `AttenuationMonotonic`, `RevokedNeverConsumed`, `BudgetNeverNegative`, `HolderBindingPreserved`, `ExpiryHonored`)
* **Core & Adversarial Suite (`tests/` + `rust/verifier/`):** PASS (1,044+ pytest unit/attack tests + offline Rust/WASM verifier + `6/6` `tests/test_jupiter_pep.py`)
* `test_credential_broker_isolation`: PASS (Zero ambient access to private keys)
* `test_successful_solana_transfer_execution`: PASS (500M lamport transfer with SCITT receipt)
* `test_double_spend_replay_rejected`: PASS (Atomic fail-closed replay containment)
* `test_unauthorized_program_id_rejected_before_consumption`: PASS (Rogue program ID rejection)
* `test_unauthorized_recipient_rejected_before_consumption`: PASS (Rogue recipient address rejection)
* `test_budget_exceeded_rejected`: PASS (Transaction ceiling enforcement)
* `test_multi_instruction_transaction_success`: PASS (Atomic multi-instruction batching)
* `test_invalid_plane_rejected`: PASS (Plane isolation enforcement)

---

## 6. Official Solana Foundation Application Field Reference

* **Applicant Name:** Lauren Flipo (`fliptrigga13`)
* **Country of Residence:** Canada
* **Company / Project Name:** ANCHOR v1
* **Track:** Artificial Intelligence
* **Grant Amount Requested:** $10,000 USDG
* **Website / Repo:** `https://github.com/fliptrigga13/anchor-v1`
* **Upstream PR:** `https://github.com/flipperspectives-crypto/anchor-v1/pull/4`
* **Program ID / Target:** `Solana_Runtime_V1` / `SolanaInstructionPEP`
* **Open Source Commitment:** 100% Open Source under Apache-2.0 license (`LICENSE`; `rust/verifier/` crate `MIT`)
