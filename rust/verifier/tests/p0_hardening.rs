//! P0 security-hardening regression tests (2026-09-25 audit).
//!
//! * Ed25519 verification is strict: a small-order-key signature forgery that
//!   passes non-strict `verify` must fail `verify_strict`, and the COSE
//!   pipeline must reject it.
//! * The CBOR decoder enforces an input-size cap, a nesting-depth limit, and
//!   rejects forged lengths without truncation or arithmetic wrap.
//! * The canonical-JSON writer enforces a nesting-depth limit.

use anchor_v1_verifier::{canonical_json, cbor, cose, MAX_INPUT_BYTES};

// ---------------------------------------------------------------------------
// Ed25519 strict verification
// ---------------------------------------------------------------------------

/// Compressed Ed25519 basepoint: 0x58 followed by 31 0x66 bytes.
const BASEPOINT_COMPRESSED: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];

/// Classic small-order forgery: with the identity point as the public key
/// (order 1), the verification equation `[s]B - [k]A == R` collapses to
/// `[s]B == R`, so `R = [1]B, s = 1` is a "valid" signature for *any* message
/// under non-strict verification. Strict verification rejects the weak key.
#[test]
fn small_order_key_forgery_rejected_by_strict_verify() {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    // Identity point (order 1): compressed Edwards encoding of (x=0, y=1).
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let weak = VerifyingKey::from_bytes(&identity).expect("identity point must decode");
    assert!(weak.is_weak(), "test key must be a small-order point");

    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&BASEPOINT_COMPRESSED); // R = [1]B
    sig_bytes[32] = 1; // s = 1, little-endian
    let forged = Signature::from_slice(&sig_bytes).expect("forged signature must parse");

    // The attack works against non-strict verification ...
    assert!(
        weak.verify(b"any message at all", &forged).is_ok(),
        "non-strict verify must accept the small-order forgery (otherwise this is not a valid attack test)"
    );
    // ... and is stopped by strict verification, which is what the crate uses.
    assert!(weak.verify_strict(b"any message at all", &forged).is_err());
}

/// The same forgery delivered through the real COSE pipeline must fail.
#[test]
fn cose_pipeline_rejects_small_order_key() {
    let kid = b"weak-key".to_vec();
    let protected = cbor::dumps(&cbor::Value::Map(vec![
        (cbor::Value::Int(cbor::Integer::Small(1)), cbor::Value::Int(cbor::Integer::Small(-8))),
        (cbor::Value::Int(cbor::Integer::Small(4)), cbor::Value::Bytes(kid.clone())),
    ]))
    .unwrap();
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&BASEPOINT_COMPRESSED);
    sig_bytes[32] = 1;
    let message = cbor::dumps(&cbor::Value::Array(vec![
        cbor::Value::Bytes(protected),
        cbor::Value::Map(vec![]),
        cbor::Value::Bytes(b"forged payload".to_vec()),
        cbor::Value::Bytes(sig_bytes.to_vec()),
    ]))
    .unwrap();

    let trusted = vec![(kid, {
        let mut identity = [0u8; 32];
        identity[0] = 1; // identity point as the trusted key
        identity
    })];
    let err = cose::verify(&message, &trusted, b"").expect_err("forgery must not verify");
    assert_eq!(err.reason, "bad-signature");
}

// ---------------------------------------------------------------------------
// CBOR decoder resource limits
// ---------------------------------------------------------------------------

#[test]
fn cbor_rejects_oversized_input() {
    let big = vec![0xf6; MAX_INPUT_BYTES + 1]; // 16 MiB + 1 of nulls
    let err = cbor::loads(&big).expect_err("oversized input must be rejected");
    assert_eq!(err.reason, "input-too-large");
}

#[test]
fn cbor_rejects_forged_byte_string_length() {
    // bstr with a u64::MAX length prefix: must error (truncated), never
    // truncate the length or wrap the bounds check.
    let mut evil = vec![0x5b]; // major 2, ai 27
    evil.extend_from_slice(&u64::MAX.to_be_bytes());
    let err = cbor::loads(&evil).expect_err("forged length must be rejected");
    assert!(
        err.reason == "truncated-cbor" || err.reason == "length-overflow",
        "unexpected reason: {}",
        err.reason
    );
}

#[test]
fn cbor_enforces_depth_limit() {
    // 70 nested single-element arrays: decode must stop at MAX_DEPTH (64).
    let mut deep = vec![0x81; 70];
    deep.push(0xf6);
    let err = cbor::loads(&deep).expect_err("over-deep nesting must be rejected");
    assert_eq!(err.reason, "depth-limit");

    // 64-deep nesting is still accepted.
    let mut ok_deep = vec![0x81; 64];
    ok_deep.push(0xf6);
    assert!(cbor::loads(&ok_deep).is_ok());
}

// ---------------------------------------------------------------------------
// Canonical-JSON writer depth limit
// ---------------------------------------------------------------------------

#[test]
fn canonical_json_writer_enforces_depth_limit() {
    // Hand-build a 200-deep array (serde_json's parser would never produce
    // this; the writer must still refuse it).
    let mut v = serde_json::Value::Null;
    for _ in 0..200 {
        v = serde_json::Value::Array(vec![v]);
    }
    let err = canonical_json::canonical_bytes(&v).expect_err("over-deep value must be rejected");
    assert_eq!(err.reason, "depth-limit");

    // A 100-deep value is still accepted.
    let mut ok = serde_json::Value::Null;
    for _ in 0..100 {
        ok = serde_json::Value::Array(vec![ok]);
    }
    assert!(canonical_json::canonical_bytes(&ok).is_ok());
}
