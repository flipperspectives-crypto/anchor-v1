//! ANCHOR v1 offline verifier (Rust).
//!
//! Pure-offline verification of ANCHOR v1 authority artifacts — no network,
//! no key generation, no signing. This crate mirrors the verification halves
//! of the Python implementation:
//!
//! * [`cbor`] — strict deterministic CBOR codec (RFC 8949 §4.2.1),
//! * [`canonical_json`] — byte-exact canonical JSON for digests / v0 signatures,
//! * [`cose`] — COSE_Sign1 (RFC 9052) verification over Ed25519,
//! * [`envelope`] — ActionEnvelope verification (schema + validity window),
//! * [`checkpoint`] — checkpoint-chain + Merkle-inclusion verification,
//! * [`holder`] — holder proof-of-possession verification.
//!
//! Fail-closed throughout: any malformed input, disallowed algorithm,
//! unknown key, or bad signature is an [`Error`], never a silent pass.

pub mod canonical_json;
pub mod cbor;
pub mod checkpoint;
pub mod cose;
pub mod envelope;
pub mod error;
pub mod holder;

#[cfg(feature = "wasm")]
pub mod wasm;

pub use error::{Error, Result};

/// Maximum untrusted-input size accepted anywhere in this crate (16 MiB).
/// Decoders allocate in proportion to their input, so this caps memory on
/// hostile input. Re-exported from [`cbor::MAX_INPUT_BYTES`]; the CBOR
/// decoder enforces it directly, and the WASM/CLI input helpers enforce it
/// before parsing.
pub use cbor::MAX_INPUT_BYTES;
