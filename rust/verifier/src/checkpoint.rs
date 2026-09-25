//! Offline checkpoint-chain and Merkle-inclusion verification.
//!
//! Mirrors `src/anchor_v1/anchored_checkpoints.py`:
//! * `verify_checkpoint_chain` — re-validates a chain of v0 `SignedEnvelope`
//!   checkpoints (canonical-JSON Ed25519 signatures, hash links, sequence
//!   tiling, monotonic time, signer rotation, anchor proofs),
//! * `verify_inclusion` — Merkle inclusion of an evidence event,
//! * `event_hash` / `parent_hash` — the hash primitives,
//! * `LocalEmulatedAnchor.verify_anchor` — the signature/binding half of the
//!   emulated timestamp-anchor check.
//!
//! Out of scope for a pure offline verifier: the anchor's append-only
//! log-membership check. Pass the operator's anchor log via
//! [`AnchorTrust::log`] to enforce it; otherwise the signature, scheme, and
//! root/timestamp bindings are verified and the log check is documented as
//! skipped.

use crate::canonical_json;
use crate::error::{Error, Result};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

/// Bootstrap trust: the key id + raw Ed25519 public key that may sign
/// checkpoints (`TrustedCheckpointSigner`).
#[derive(Debug, Clone)]
pub struct TrustedSigner {
    pub key_id: String,
    pub public_key: [u8; 32],
}

/// Trust inputs for the timestamp anchor (`LocalEmulatedAnchor` semantics).
#[derive(Debug, Clone)]
pub struct AnchorTrust<'a> {
    pub key_id: &'a str,
    pub public_key: &'a [u8; 32],
    /// Optional operator anchor log (AnchorProof JSON objects). When present,
    /// proofs must appear in it — the append-only membership half of
    /// `LocalEmulatedAnchor.verify_anchor`.
    pub log: Option<&'a [Value]>,
}

fn b64_32(field: &str, s: &str) -> Result<[u8; 32]> {
    use base64::Engine;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|_| Error::new("bad-base64", format!("field {field} is not valid base64")))?;
    if raw.len() != 32 {
        return Err(Error::new(
            "bad-key-length",
            format!("field {field} must decode to 32 bytes"),
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

fn b64_sig(field: &str, s: &str) -> Result<Signature> {
    use base64::Engine;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|_| Error::new("bad-base64", format!("field {field} is not valid base64")))?;
    Signature::from_slice(&raw)
        .map_err(|_| Error::new("bad-signature", format!("field {field} is not a valid Ed25519 signature")))
}

fn req_str(map: &Map<String, Value>, field: &'static str) -> Result<String> {
    map.get(field)
        .and_then(|v| v.as_str())
        .map(|s| s.to_owned())
        .ok_or_else(|| Error::new("bad-schema", format!("field {field} missing or not a string")))
}

fn req_int(map: &Map<String, Value>, field: &'static str) -> Result<i64> {
    map.get(field).and_then(|v| v.as_i64()).ok_or_else(|| {
        Error::new("bad-schema", format!("field {field} missing or not an integer"))
    })
}

fn forbid_extra(map: &Map<String, Value>, allowed: &[&str], what: &str) -> Result<()> {
    for k in map.keys() {
        if !allowed.contains(&k.as_str()) {
            return Err(Error::new(
                "bad-schema",
                format!("{what} has forbidden extra field {k:?}"),
            ));
        }
    }
    Ok(())
}

fn parse_time(field: &str, value: &str) -> Result<OffsetDateTime> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| Error::new("bad-timestamp", format!("field {field} is not valid RFC-3339")))
}

/// Verify a v0 `SignedEnvelope` (Ed25519 over canonical JSON) and return the
/// payload object. Mirrors `crypto.verify_envelope` + the key-id check in
/// `verify_checkpoint_chain`.
pub fn verify_signed_envelope(
    env: &Value,
    expected_key_id: &str,
    public_key: &[u8; 32],
) -> Result<Map<String, Value>> {
    let map = env.as_object().ok_or_else(|| {
        Error::new("bad-schema", "signed envelope must be a JSON object")
    })?;
    forbid_extra(map, &["alg", "key_id", "payload", "signature"], "signed envelope")?;
    let alg = req_str(map, "alg")?;
    if alg != "Ed25519" {
        return Err(Error::new(
            "bad-algorithm",
            format!("unsupported signature algorithm: {alg}"),
        ));
    }
    let key_id = req_str(map, "key_id")?;
    if key_id != expected_key_id {
        return Err(Error::new(
            "wrong-key-id",
            "envelope key_id does not match the active checkpoint key",
        ));
    }
    let payload = map
        .get("payload")
        .and_then(|v| v.as_object())
        .ok_or_else(|| Error::new("bad-schema", "envelope payload must be an object"))?
        .clone();
    let sig_b64 = req_str(map, "signature")?;
    let sig = b64_sig("signature", &sig_b64)?;

    let key = VerifyingKey::from_bytes(public_key)
        .map_err(|_| Error::new("bad-key", "checkpoint key is not a valid Ed25519 public key"))?;
    let msg = canonical_json::canonical_bytes(&Value::Object(payload.clone()))?;
    key.verify_strict(&msg, &sig)
        .map_err(|_| Error::new("bad-signature", "envelope signature verification failed"))?;
    Ok(payload)
}

/// Canonical hash of an evidence event. Binds sequence, type, data, timestamp
/// AND the previous_hash link.
pub fn event_hash(event: &Value) -> Result<String> {
    canonical_json::sha256_hex(event)
}

fn parent_hash(left: &str, right: &str) -> Result<String> {
    canonical_json::sha256_hex(&serde_json::json!({"left": left, "right": right}))
}

/// Fully offline Merkle inclusion check: recompute the leaf hash from the
/// event, fold the sibling path, compare against the checkpoint's root.
/// Mirrors `verify_inclusion` (returns `false` on any failure).
pub fn verify_inclusion(checkpoint: &Value, event: &Value, proof: &Value) -> bool {
    (|| -> Result<bool> {
        let cp = checkpoint.as_object().ok_or_else(|| Error::new("bad-schema", "checkpoint must be an object"))?;
        let merkle_root = req_str(cp, "merkle_root")?;
        let event_count = req_int(cp, "event_count")?;

        let pf = proof.as_object().ok_or_else(|| Error::new("bad-schema", "proof must be an object"))?;
        forbid_extra(pf, &["leaf_hash", "leaf_index", "total_leaves", "steps"], "inclusion proof")?;
        let leaf_hash = req_str(pf, "leaf_hash")?;
        let total_leaves = req_int(pf, "total_leaves")?;
        let steps = pf.get("steps").and_then(|v| v.as_array()).ok_or_else(|| {
            Error::new("bad-schema", "proof steps must be an array")
        })?;

        if event_hash(event)? != leaf_hash {
            return Ok(false);
        }
        if total_leaves != event_count {
            return Ok(false);
        }
        let mut node = leaf_hash;
        for step in steps {
            let s = step.as_object().ok_or_else(|| Error::new("bad-schema", "proof step must be an object"))?;
            forbid_extra(s, &["sibling", "sibling_is_left"], "proof step")?;
            let sibling = req_str(s, "sibling")?;
            let is_left = s.get("sibling_is_left").and_then(|v| v.as_bool()).ok_or_else(|| {
                Error::new("bad-schema", "sibling_is_left must be a boolean")
            })?;
            node = if is_left {
                parent_hash(&sibling, &node)?
            } else {
                parent_hash(&node, &sibling)?
            };
        }
        Ok(node == merkle_root)
    })()
    .unwrap_or(false)
}

/// Format an instant exactly as Python's `datetime.isoformat()` does for a
/// UTC-aware datetime: `YYYY-MM-DDTHH:MM:SS[.ffffff]+00:00`.
///
/// This matters because the anchor key signs `anchor_leaf(...)`, whose
/// `timestamp` field is `datetime.isoformat()` on the datetime object —
/// while the JSON-serialized proof carries pydantic's `Z`-suffixed form.
/// The two strings differ (`+00:00` vs `Z`); the signature only verifies
/// against the isoformat form.
fn python_isoformat_utc(dt: OffsetDateTime) -> String {
    let dt = dt.to_offset(time::UtcOffset::UTC);
    let (y, m, d) = dt.to_calendar_date();
    let (h, min, s) = dt.to_hms();
    let micros = dt.microsecond();
    if micros == 0 {
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}+00:00",
            y, m as u8, d, h, min, s
        )
    } else {
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}+00:00",
            y, m as u8, d, h, min, s, micros
        )
    }
}

/// Canonical bytes the anchor key signs: binds scheme, root, and time.
/// Mirrors `anchor_leaf`. `timestamp_iso` must be the Python-isoformat form
/// (see `python_isoformat_utc`), not the JSON `Z`-suffixed form.
fn anchor_leaf_bytes(scheme: &str, root_hash: &str, timestamp_iso: &str) -> Result<Vec<u8>> {
    canonical_json::canonical_bytes(&serde_json::json!({
        "scheme": scheme,
        "root_hash": root_hash,
        "timestamp": timestamp_iso,
    }))
}

/// Verify an emulated timestamp anchor proof against a checkpoint payload.
/// This is the offline-checkable half of `LocalEmulatedAnchor.verify_anchor`:
/// scheme, `emulated` flag, key binding, root binding, timestamp binding, and
/// the Ed25519 signature. When `trust.log` is present, proof membership in the
/// operator's append-only anchor log is additionally required.
fn verify_anchor_proof(
    checkpoint: &Map<String, Value>,
    proof: &Value,
    trust: &AnchorTrust,
) -> Result<()> {
    let pf = proof.as_object().ok_or_else(|| {
        Error::new("bad-schema", "anchor proof must be an object")
    })?;
    forbid_extra(
        pf,
        &["scheme", "root_hash", "timestamp", "key_id", "signature", "emulated", "ots_receipt_b64"],
        "anchor proof",
    )?;
    let scheme = req_str(pf, "scheme")?;
    if scheme != "local-emulated" {
        return Err(Error::new("bad-anchor", "anchor scheme is not local-emulated"));
    }
    let emulated = pf.get("emulated").and_then(|v| v.as_bool()).ok_or_else(|| {
        Error::new("bad-schema", "anchor proof emulated flag must be a boolean")
    })?;
    if !emulated {
        return Err(Error::new("bad-anchor", "emulated anchor proof must carry emulated=true"));
    }
    let key_id = req_str(pf, "key_id")?;
    if key_id != trust.key_id {
        return Err(Error::new("bad-anchor", "anchor proof key_id mismatch"));
    }
    let root_hash = req_str(pf, "root_hash")?;
    let merkle_root = req_str(checkpoint, "merkle_root")?;
    if root_hash != merkle_root {
        return Err(Error::new("bad-anchor", "anchor proof root does not match checkpoint"));
    }
    // Timestamp binding: the proof's instant must equal the checkpoint's.
    let proof_ts = req_str(pf, "timestamp")?;
    let cp_ts = req_str(checkpoint, "timestamp")?;
    let proof_dt = parse_time("anchor_proof.timestamp", &proof_ts)?;
    if proof_dt != parse_time("checkpoint.timestamp", &cp_ts)? {
        return Err(Error::new("bad-anchor", "anchor proof timestamp mismatch"));
    }

    let key = VerifyingKey::from_bytes(trust.public_key)
        .map_err(|_| Error::new("bad-key", "anchor key is not a valid Ed25519 public key"))?;
    let leaf = anchor_leaf_bytes(&scheme, &root_hash, &python_isoformat_utc(proof_dt))?;
    let sig = b64_sig("anchor_proof.signature", &req_str(pf, "signature")?)?;
    key.verify_strict(&leaf, &sig)
        .map_err(|_| Error::new("bad-signature", "anchor proof signature invalid"))?;

    if let Some(log) = trust.log {
        let sig_b64 = req_str(pf, "signature")?;
        let member = log.iter().any(|entry| {
            let e = match entry.as_object() {
                Some(e) => e,
                None => return false,
            };
            e.get("signature").and_then(|v| v.as_str()) == Some(sig_b64.as_str())
                && e.get("root_hash").and_then(|v| v.as_str()) == Some(root_hash.as_str())
        });
        if !member {
            return Err(Error::new("bad-anchor", "anchor proof not present in the anchor log"));
        }
    }
    Ok(())
}

struct ParsedCheckpoint {
    payload: Map<String, Value>,
    merkle_root: String,
    previous_root: Option<String>,
    timestamp: OffsetDateTime,
    start_seq: i64,
    end_seq: i64,
    anchor_proof: Value,
    next_signer: Option<(String, [u8; 32])>,
}

fn parse_checkpoint(payload: Map<String, Value>) -> Result<ParsedCheckpoint> {
    forbid_extra(
        &payload,
        &[
            "checkpoint_id", "start_seq", "end_seq", "event_count", "merkle_root",
            "previous_checkpoint_root", "timestamp", "anchor_proof", "next_signer",
        ],
        "checkpoint",
    )?;
    let start_seq = req_int(&payload, "start_seq")?;
    let end_seq = req_int(&payload, "end_seq")?;
    if start_seq < 0 || end_seq < start_seq {
        return Err(Error::new("bad-range", "checkpoint range invalid"));
    }
    let event_count = req_int(&payload, "event_count")?;
    if event_count != end_seq - start_seq + 1 {
        return Err(Error::new(
            "bad-range",
            "event_count must equal end_seq - start_seq + 1",
        ));
    }
    let merkle_root = req_str(&payload, "merkle_root")?;
    let previous_root = payload
        .get("previous_checkpoint_root")
        .and_then(|v| v.as_str())
        .map(|s| s.to_owned());
    let timestamp = parse_time("timestamp", &req_str(&payload, "timestamp")?)?;
    let anchor_proof = payload
        .get("anchor_proof")
        .cloned()
        .ok_or_else(|| Error::new("bad-schema", "checkpoint anchor_proof missing"))?;
    let next_signer = match payload.get("next_signer") {
        None | Some(Value::Null) => None,
        Some(v) => {
            let m = v.as_object().ok_or_else(|| {
                Error::new("bad-schema", "next_signer must be an object")
            })?;
            forbid_extra(m, &["key_id", "public_key"], "next_signer")?;
            let key_id = req_str(m, "key_id")?;
            if key_id.is_empty() {
                return Err(Error::new("bad-schema", "next_signer key_id must be non-empty"));
            }
            let public_key = b64_32("next_signer.public_key", &req_str(m, "public_key")?)?;
            Some((key_id, public_key))
        }
    };
    Ok(ParsedCheckpoint {
        payload,
        merkle_root,
        previous_root,
        timestamp,
        start_seq,
        end_seq,
        anchor_proof,
        next_signer,
    })
}

/// Re-validate an entire checkpoint chain from untrusted input.
///
/// For every checkpoint: signature verifies under the key active at its
/// position (rotations declared via `next_signer` take effect for LATER
/// checkpoints only), the previous_checkpoint_root link matches the prior
/// checkpoint's root (genesis must be None), timestamps are non-decreasing,
/// ranges tile with no gaps/overlaps, and the anchor proof verifies.
/// Any failure → `false` (fail closed), mirroring the Python contract.
pub fn verify_checkpoint_chain(
    signed_checkpoints: &[Value],
    bootstrap: &TrustedSigner,
    anchor: &AnchorTrust,
) -> bool {
    (|| -> Result<bool> {
        if signed_checkpoints.is_empty() {
            return Ok(false);
        }
        let mut registry: HashMap<String, [u8; 32]> = HashMap::new();
        registry.insert(bootstrap.key_id.clone(), bootstrap.public_key);
        let mut active_key_id = bootstrap.key_id.clone();
        let mut previous: Option<ParsedCheckpoint> = None;

        for envelope in signed_checkpoints {
            let active_key = registry.get(&active_key_id).ok_or_else(|| {
                Error::new("unknown-kid", "active checkpoint key not in registry")
            })?;
            let payload = verify_signed_envelope(envelope, &active_key_id, active_key)
                .map_err(|_| Error::new("bad-envelope", "checkpoint envelope failed verification"))?;
            let checkpoint = parse_checkpoint(payload)?;

            // Checkpoint-to-checkpoint hash link.
            let expected_prev = previous.as_ref().map(|p| p.merkle_root.clone());
            if checkpoint.previous_root != expected_prev {
                return Ok(false);
            }
            // Monotonic time: checkpoints cannot travel backwards.
            if let Some(prev) = &previous {
                if checkpoint.timestamp < prev.timestamp {
                    return Ok(false);
                }
                // Range discipline: checkpoints tile the event space with no
                // gaps and no overlaps.
                if checkpoint.start_seq != prev.end_seq + 1 {
                    return Ok(false);
                }
            }

            if verify_anchor_proof(&checkpoint.payload, &checkpoint.anchor_proof, anchor).is_err() {
                return Ok(false);
            }

            // Rotation declared here takes effect for the NEXT checkpoint.
            if let Some((key_id, public_key)) = checkpoint.next_signer.clone() {
                registry.insert(key_id.clone(), public_key);
                active_key_id = key_id;
            }
            previous = Some(checkpoint);
        }
        Ok(true)
    })()
    .unwrap_or(false)
}

/// Exported for the WASM layer and CLI: SHA-256 hex of raw bytes.
pub fn sha256_hex_bytes(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}
