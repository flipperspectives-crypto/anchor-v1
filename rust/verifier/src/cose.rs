//! Hand-rolled COSE_Sign1 (RFC 9052) verification over Ed25519.
//!
//! Mirrors `src/anchor_v1/cose.py`. The signed object is:
//!
//! ```text
//! COSE_Sign1 = [ body_protected : bstr, unprotected : map,
//!                payload : bstr, signature : bstr ]
//! ```
//!
//! with `Sig_structure = ["Signature1", body_protected, external_aad, payload]`.
//!
//! Protocol hardening (fail-closed, matching the Python side):
//! * algorithm allowlist: only EdDSA (-8),
//! * protected header must contain exactly `{1: -8, 4: kid}` — no extra labels,
//! * unprotected header must be empty,
//! * CBOR is decoded with the strict deterministic decoder.

use crate::cbor::{self, Integer, Value};
use crate::error::{Error, Result};
use ed25519_dalek::{Signature, VerifyingKey};

/// COSE algorithm + header label registry values (RFC 9053 / RFC 9052).
pub const ALG_EDDSA: i128 = -8;
const LABEL_ALG: i128 = 1;
const LABEL_KID: i128 = 4;

/// Verify a COSE_Sign1 message. Returns `(payload, kid)`.
///
/// `trusted_keys` maps kid bytes to 32-byte Ed25519 public keys. Fails closed
/// on any malformed input, disallowed algorithm, unknown kid, or bad signature.
pub fn verify(
    message: &[u8],
    trusted_keys: &[(Vec<u8>, [u8; 32])],
    external_aad: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let outer = cbor::loads(message)
        .map_err(|e| Error::new("malformed-cose", format!("malformed COSE_Sign1: {e}")))?;

    let items = outer.as_array().ok_or_else(|| {
        Error::new("malformed-cose", "COSE_Sign1 must be an array of 4 elements")
    })?;
    if items.len() != 4 {
        return Err(Error::new(
            "malformed-cose",
            "COSE_Sign1 must be an array of 4 elements",
        ));
    }
    let body_protected = items[0].as_bytes().ok_or_else(|| {
        Error::new("malformed-cose", "body_protected must be a byte string")
    })?;
    let unprotected = &items[1];
    let payload = items[2].as_bytes().ok_or_else(|| {
        Error::new("malformed-cose", "payload must be a byte string")
    })?;
    let signature = items[3].as_bytes().ok_or_else(|| {
        Error::new("malformed-cose", "signature must be a byte string")
    })?;
    if signature.len() != 64 {
        return Err(Error::new(
            "bad-signature-length",
            "signature must be a 64-byte Ed25519 signature",
        ));
    }

    let protected = cbor::loads(body_protected)
        .map_err(|e| Error::new("malformed-protected", format!("malformed protected header: {e}")))?;
    let (_alg, kid) = validate_headers(&protected, unprotected)?;

    let key_bytes = trusted_keys
        .iter()
        .find(|(k, _)| k.as_slice() == kid)
        .map(|(_, pk)| pk)
        .ok_or_else(|| Error::new("unknown-kid", "unknown kid: no trusted key"))?;
    let key = VerifyingKey::from_bytes(key_bytes)
        .map_err(|_| Error::new("bad-key", "trusted key is not a valid Ed25519 public key"))?;

    let sig_structure = cbor::dumps(&Value::Array(vec![
        Value::Text("Signature1".to_owned()),
        Value::Bytes(body_protected.to_vec()),
        Value::Bytes(external_aad.to_vec()),
        Value::Bytes(payload.to_vec()),
    ]))?;
    let sig = Signature::from_slice(signature)
        .map_err(|_| Error::new("bad-signature", "malformed Ed25519 signature"))?;
    key.verify_strict(&sig_structure, &sig)
        .map_err(|_| Error::new("bad-signature", "signature verification failed"))?;

    Ok((payload.to_vec(), kid.to_vec()))
}

/// Validate protected/unprotected headers (ATTACK-12 / ATTACK-15). Fail-closed.
fn validate_headers(protected: &Value, unprotected: &Value) -> Result<(i128, Vec<u8>)> {
    let up = unprotected.as_map().ok_or_else(|| {
        Error::new("bad-headers", "unprotected header must be a map")
    })?;
    if !up.is_empty() {
        return Err(Error::new("bad-headers", "unprotected header must be empty"));
    }
    let p = protected.as_map().ok_or_else(|| {
        Error::new("bad-headers", "protected header must be a map")
    })?;
    if p.len() != 2 {
        return Err(Error::new(
            "bad-headers",
            "protected header must contain exactly alg and kid",
        ));
    }
    let mut alg: Option<i128> = None;
    let mut kid: Option<Vec<u8>> = None;
    for (k, v) in p {
        match k {
            Value::Int(Integer::Small(n)) if *n == LABEL_ALG => alg = v.as_int(),
            Value::Int(Integer::Small(n)) if *n == LABEL_KID => {
                kid = v.as_bytes().map(|b| b.to_vec())
            }
            _ => {
                return Err(Error::new(
                    "bad-headers",
                    "protected header must contain exactly alg and kid",
                ))
            }
        }
    }
    let alg = alg.ok_or_else(|| {
        Error::new("bad-headers", "protected header must contain exactly alg and kid")
    })?;
    let kid = kid.ok_or_else(|| {
        Error::new("bad-headers", "protected header must contain exactly alg and kid")
    })?;
    if alg != ALG_EDDSA {
        return Err(Error::new(
            "bad-algorithm",
            format!("algorithm not allowed: {alg} (only EdDSA/-8)"),
        ));
    }
    Ok((alg, kid))
}
