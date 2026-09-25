# anchor-v1-verifier

Offline verifier for [ANCHOR v1](https://github.com/flipperspectives-crypto/anchor-v1)
authority artifacts — in Rust, with WebAssembly bindings.

This closes **residual risk #1** in `docs/THREAT_MODEL.md`: the offline-verification
story no longer rests solely on the Python implementation. A Rust (or WASM) verifier
serves constrained and offline deployments — air-gapped hosts, edge workers,
browser-based auditors — that cannot or should not run the Python stack.

## What it verifies (offline — no network, no signing, no key generation)

| Artifact | Check |
|---|---|
| COSE_Sign1 (RFC 9052) | Strict deterministic-CBOR decode; protected header exactly `{1: -8, 4: kid}`; empty unprotected header; Ed25519 over `Sig_structure` with caller-supplied `external_aad`; kid from an explicit trust set |
| ActionEnvelope | COSE verification + strict schema (extra fields forbidden) + validity window (`not_before ≤ now ≤ not_after`) + `action_digest = SHA-256(canonical CBOR)` |
| Checkpoint chain (v0 `SignedEnvelope`s) | Per-checkpoint Ed25519 over canonical JSON; hash-link `previous_checkpoint_root`; non-decreasing timestamps; gapless/overlap-free sequence tiling; signer rotation (`next_signer` takes effect for *later* checkpoints only); emulated timestamp-anchor proof (scheme, `emulated` flag, key, root, time bindings + signature) |
| Merkle inclusion | Leaf recomputed from the event, sibling path folded, root compared |
| Holder proof | Ed25519 over `capability_id ‖ challenge` (non-empty challenge) |
| Event hash | `SHA-256(canonical JSON)` of the evidence event |

Fail-closed throughout: any malformed input, disallowed algorithm, unknown key,
or bad signature is an error — never a silent pass. The chain API folds all
failures into `false`, matching the Python `verify_checkpoint_chain` contract.

## Layout

- `src/cbor.rs` — strict deterministic CBOR codec (RFC 8949 §4.2.1): shortest-form
  ints, canonical map ordering, definite lengths only, shortest floats, bignum
  tags 2/3. Non-canonical encodings are rejected.
- `src/canonical_json.rs` — canonical JSON, byte-identical to Python's
  `json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=False, allow_nan=False)`,
  including CPython's shortest float `repr` formatting.
- `src/cose.rs` — COSE_Sign1 verification with the hardened header policy.
- `src/envelope.rs` — ActionEnvelope verification.
- `src/checkpoint.rs` — checkpoint chains, Merkle inclusion, anchor proofs.
- `src/holder.rs` — holder proof-of-possession.
- `src/wasm.rs` — `wasm-bindgen` API (feature `wasm`): JSON in/out, base64 for bytes.
- `src/main.rs` — `anchor-verify` CLI (exit 0 = valid, 1 = invalid, 2 = usage error).

## Use

**Library** — see `src/lib.rs` docs; e.g.:

```rust
let ok = checkpoint::verify_checkpoint_chain(&chain, &bootstrap, &anchor_trust);
```

**CLI**:

```sh
anchor-verify chain --chain @chain.json --bootstrap @bootstrap.json \
  --anchor-key-id anchor-key-1 --anchor-key <B64> [--anchor-log @anchor-log.json]
anchor-verify cose --message @msg.b64 --keys @trust.json
anchor-verify envelope --cose @env.b64 --keys @trust.json --now 2026-06-01T12:00:00+00:00
anchor-verify inclusion --checkpoint @cp.json --event @event.json --proof @proof.json
anchor-verify holder --pubkey <B64> --capability-id <ID> --challenge <B64> --proof <B64>
anchor-verify event-hash --event @event.json
```

(`@path` reads the argument from a file.)

**WASM**:

```sh
cargo build --target wasm32-unknown-unknown --features wasm
wasm-bindgen --target web --out-dir pkg target/wasm32-unknown-unknown/debug/anchor_v1_verifier.wasm
```

then in JS:

```js
import { verify_checkpoint_chain } from './pkg/anchor_v1_verifier.js';
const ok = verify_checkpoint_chain(chainJson, bootstrapJson, anchorJson);
```

## Trust inputs

The verifier takes trust roots as explicit arguments — it has no ambient authority:

- `trusted_keys` / `bootstrap`: the key ids and raw Ed25519 public keys you trust
  (compare against your out-of-band trust bundle).
- `AnchorTrust.log`: the operator's append-only anchor log. When supplied, anchor
  proofs must appear in it — the full `LocalEmulatedAnchor` semantics. When omitted,
  the signature/scheme/root/time bindings are still verified; the log-membership
  half is documented as skipped.
- `now` for envelope validity windows is caller-supplied (offline clocks are the
  caller's responsibility).

Out of scope, by design: revocation sync, OpenTimestamps calendar I/O, challenge
freshness, and policy evaluation — all require network or coordinator duties
(see `docs/THREAT_MODEL.md`).

## Parity notes (Python ↔ Rust)

Verified by cross-implementation fixtures (`fixtures/gen.py` generates with the
real Python `anchor_v1`; `tests/cross_verify.rs` asserts agreement):

1. **Anchor-leaf timestamps.** The anchor key signs `timestamp.isoformat()` on the
   datetime object (`…+00:00`), while the JSON proof carries pydantic's `Z`-suffixed
   form. The verifier reconstructs the isoformat form before checking the signature.
2. **Big JSON integers.** Python ints are arbitrary-precision; JSON text preserves
   them, so the verifier parses with `arbitrary_precision` and emits integer syntax
   verbatim instead of coercing through f64.
3. **Floats** use CPython's shortest-`repr` rules (fixed vs. exponential threshold,
   signed zero-padded exponents), tested against CPython outputs.

## Security hardening (P0, 2026-09-25 audit)

- **Ed25519 is strict.** Every signature check uses `verify_strict`, which
  rejects small-order public keys. `tests/p0_hardening.rs` proves the point:
  a forged signature under the identity-point key passes non-strict `verify`
  but fails `verify_strict`, and the COSE pipeline rejects it.
- **Decoder resource limits.** CBOR decoding caps input at 16 MiB
  (`cbor::MAX_INPUT_BYTES`, enforced in `loads()`), nesting at 64 levels
  (`MAX_DEPTH`), uses checked arithmetic and `usize::try_from` for all
  lengths (no truncation or wrap on 32-bit targets), and bounds every
  allocation by remaining input. The canonical-JSON writer caps nesting at
  128. The WASM entry points cap every input at 16 MiB before parsing.
- **No panics on attacker input.** The decoders contain no `unwrap`/`expect`
  on untrusted paths; every `#[wasm_bindgen]` export returns
  `Result<T, JsValue>` and converts failures to structured JS errors.
- **Locked supply chain.** `Cargo.lock` is committed; build and test with
  `--locked`. CI runs `cargo audit --deny warnings` and `cargo deny check`
  (see `deny.toml` and `.github/workflows/verifier-ci.yml`).
- **Pinned floor for `time`.** `time >= 0.3.47` is required
  (RUSTSEC-2026-0009 / stack-exhaustion DoS in older parsers), with only the
  `parsing` + `std` features enabled.

## Supply-chain hardening (P1, 2026-09-25)

- **Pinned toolchain + MSRV.** `rust-toolchain.toml` pins Rust 1.89.0
  (clippy + wasm32 target); `Cargo.toml` declares `rust-version = "1.88"`
  (the floor set by `time 0.3.55`). CI builds on the pinned toolchain.
- **Hardened release profile.** `[profile.release]` sets `lto = true`,
  `panic = "abort"`, `strip = true`, and keeps `overflow-checks = true`:
  a panic is preferable to a silent wraparound in verification code.
- **`sha2` 0.11.** The direct dependency was bumped 0.10 -> 0.11, dropping
  the duplicate 0.10 tree (and `version_check`) from the lockfile.
- **`cargo vet` baseline.** `supply-chain/` carries the vet configuration;
  CI runs `cargo vet --locked` so new dependencies must be audited.
- **Vendored offline build.** CI vendors all dependencies and rebuilds
  `--offline` from the vendor directory, proving the crate builds with no
  network access.
- **Fuzz targets.** `fuzz/` holds `cargo-fuzz` targets for the CBOR decoder
  (`cbor_decode`) and the canonical-JSON roundtrip (`canonical_json`).
  They require nightly (`cargo fuzz run <target>`); the decoders are written
  so any input produces `Ok`/`Err`, never a panic.

## Testing

```sh
# Regenerate fixtures with the Python implementation, then run everything:
python3 fixtures/gen.py
cargo test --locked
```

`tests/cross_verify.rs` covers: valid + tampered COSE messages (bad signature,
re-encoded payload, non-canonical protected header, unknown kid, smuggled header
fields, non-empty unprotected header, wrong alg, truncation); valid/expired/
not-yet-valid/tampered/extra-field envelopes; 11 checkpoint-chain cases (valid,
bad signature, broken hash link, sequence gap, time travel, wrong key after
rotation, bad anchor root, genesis with previous root, empty chain, wrong anchor
key, proof missing from anchor log); Merkle inclusion accept/reject; holder proofs;
byte-exact canonical JSON; CBOR valid vectors + 11 strictness rejections.
