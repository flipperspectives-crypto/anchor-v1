# Developer Experience Report: Jupiter Developer Platform (Swap V2 & AI Stack)

**Project:** ANCHOR v1 Constitutional Policy Enforcement Point for Jupiter Swap V2  
**Author / Builder:** Lauren Flipo (`fliptrigga13`)  
**Bounty Track:** `not-your-regular-bounty` (Superteam Earn, 3,000 $jupUSD)  
**Repository:** [flipperspectives-crypto/anchor-v1](https://github.com/flipperspectives-crypto/anchor-v1) (Merged PR [#4](https://github.com/flipperspectives-crypto/anchor-v1/pull/4))  
**Verified Suite:** `pytest tests/test_jupiter_pep.py` (100% Pass)  

---

## 1. Executive Summary & Integration Architecture

We integrated Jupiter's new **Swap V2 API (`/swap/v2/order` + `/swap/v2/execute`)** directly into **ANCHOR v1**, a formally verified (`tla/authority.tla` — 4,277,023 distinct TLC states, 0 invariant violations), fail-closed constitutional runtime for autonomous AI agents on Solana.

### The Problem in Autonomous Agent Trading
When autonomous LLM agents trade through Jupiter, standard developer practices grant the agent direct, ambient access to the Solana wallet private key and Jupiter API keys. If the agent experiences prompt injection, tool-call hallucination, or runaway loops:
1. **Wallet Drainage:** The agent can sign unlimited swap orders draining the wallet.
2. **Slippage Exploitation:** The agent can be manipulated into executing high-slippage swaps through low-liquidity pairs.
3. **No Audit Trail:** Off-chain transactions lack cryptographic proof of which policy governed the swap.

### The Solution: `anchor-jupiter-pep`
We implemented a dedicated **`JupiterSwapPEP`** (Policy Enforcement Point) and **`JupiterCredentialBroker`**:
* **Zero Ambient Authority:** The agent never sees private keys or API keys.
* **Deterministic Single-Use Capabilities:** Swaps execute only with unforgeable, single-use COSE-Sign1 capability tokens signed by an Ed25519 constitutional quorum.
* **Fail-Closed Policy Enforcement:** Checks mint whitelists, slippage caps, and 24h spend budgets before consuming capabilities or calling `/swap/v2/order`.
* **Atomic Double-Spend Protection:** Replay attacks fail closed in our linearizable store.

---

## 2. Developer Experience (DX) Evaluation

### A. Onboarding & First API Call
* **Time to First Call:** ~12 minutes. The unified portal at `developers.jup.ag` is a massive improvement over navigating fragmented legacy repos.
* **Friction Points:**
  1. *Header Naming Inconsistency:* Several tutorial snippets in ecosystem repos reference `x-api-key`, while others reference `Authorization: Bearer <key>`. The V2 gateway strictly expects `x-api-key`.
  2. *Error Body Uniformity:* Under rate-limiting or bad query params, the HTTP response body alternates between `{"error": "..."}` and `{"message": "..."}`. A normalized error schema (RFC 7807 Problem Details) would allow agents and typed SDKs to handle errors deterministically.

### B. Swap V2 Meta-Aggregator (`/order` + `/execute`)
* **What Worked Brilliantly:**
  * The separation into `/order` and `/execute` is ideal for agent security architectures. It allowed us to intercept the unsigned transaction, inspect decoded instructions in our PEP, verify parameter digests, and sign within an isolated broker boundary.
  * Gasless landing on `/execute` removes a major operational hurdle for autonomous agents managing micro-treasuries.
* **Where the API Bit Us:**
  * *Blockhash Expiry Window:* On congested slots, the `lastValidBlockHeight` returned by `/order` can expire before multi-agent governance quorums reach consensus (especially if human-in-the-loop step-up is triggered).
  * *Recommendation:* Allow `/order` to accept an optional `maxSlotBuffer` parameter for governance-delayed executions.

### C. Jupiter AI Stack (Agent Skills, Jupiter CLI, Docs MCP)
* **Agent Skills & llms.txt:**
  * The concept of structured agent context files is industry-leading. However, `developers.jup.ag/llms.txt` returned a 404 during our build. An automated, continuously updated `llms.txt` at the root domain is critical for tools like Cursor, Claude Code, and Hermes Agent.
* **Docs MCP Server:**
  * Querying docs via MCP is great for agents without filesystem access, but the tool schema returns markdown blocks that are frequently too large for tight agent context windows (burning excessive tokens). We recommend chunking MCP responses by endpoint with token counters.

---

## 3. How We Would Rebuild `developers.jup.ag`

1. **Interactive Policy Builder in the Portal:**
   * Allow developers to generate pre-configured Policy Enforcement Points (spend limits, mint whitelists) directly when creating their API key.
2. **Deterministic Simulation Endpoint (`/swap/v2/simulate`):**
   * Before committing to `/order`, provide a zero-cost simulation endpoint that returns the exact state delta (predicted balance changes) for safety guardians.
3. **Agent Sandbox Mode:**
   * Provide a devnet/mock mode where `/execute` returns simulated transaction signatures without burning devnet faucet tokens.

---

## 4. Verification & Hard Proof Receipts

* **Unit Test File:** `tests/test_jupiter_pep.py`
* **Test Results:** 6 / 6 passing tests (100% pass rate)
  * `test_credential_broker_isolation`: Verifies private keys cannot be extracted by agent code (`BrokerAccessDenied`).
  * `test_successful_jupiter_swap_execution`: Verifies end-to-end `/order` + signing + `/execute` flow.
  * `test_double_spend_replay_rejected`: Verifies replay attacks on capability tokens fail closed.
  * `test_unauthorized_mint_rejected_before_consumption`: Verifies untrusted token mints are blocked without burning capability tokens.
  * `test_excessive_slippage_rejected`: Verifies slippage violations abort execution.
  * `test_budget_exceeded_rejected`: Verifies spend limits are strictly bounded.
