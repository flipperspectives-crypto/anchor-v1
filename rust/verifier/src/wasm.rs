//! `wasm-bindgen` API for constrained/offline deployments (browsers,
//! edge workers, mobile webviews). JSON in / JSON out; binary values travel
//! as base64 (standard alphabet).
//!
//! Every function is fail-closed: verification failures return `false` (or
//! throw for malformed *trust inputs* such as undecodable keys), never a
//! silent pass.

use crate::{canonical_json, checkpoint, cose, envelope, holder, MAX_INPUT_BYTES};
use base64::Engine;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use wasm_bindgen::prelude::*;

fn check_input_len(field: &str, s: &str) -> Result<(), JsValue> {
    // Base64 inflates ~4/3; the decoded form is checked again by the core
    // decoders, but reject absurd inputs before decoding.
    if s.len() > MAX_INPUT_BYTES {
        return Err(JsValue::from_str(&format!(
            "{field} exceeds input limit of {MAX_INPUT_BYTES} bytes"
        )));
    }
    Ok(())
}

fn b64decode_b(field: &str, s: &str) -> Result<Vec<u8>, JsValue> {
    check_input_len(field, s)?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|_| JsValue::from_str(&format!("{field} is not valid base64")))?;
    if raw.len() > MAX_INPUT_BYTES {
        return Err(JsValue::from_str(&format!(
            "{field} exceeds input limit of {MAX_INPUT_BYTES} bytes"
        )));
    }
    Ok(raw)
}

fn b64_32(field: &str, s: &str) -> Result<[u8; 32], JsValue> {
    let raw = b64decode_b(field, s)?;
    if raw.len() != 32 {
        return Err(JsValue::from_str(&format!("{field} must decode to 32 bytes")));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

fn parse_json(field: &str, s: &str) -> Result<serde_json::Value, JsValue> {
    check_input_len(field, s)?;
    serde_json::from_str(s).map_err(|e| JsValue::from_str(&format!("{field} is not valid JSON: {e}")))
}

/// Verify a COSE_Sign1 message.
/// `trusted_keys_json`: `{"<kid_b64>": "<pubkey_b64>", ...}`.
/// Returns `{"payload_b64": "...", "kid_b64": "..."}`; throws on failure.
#[wasm_bindgen]
pub fn cose_verify(
    message_b64: &str,
    trusted_keys_json: &str,
    external_aad_b64: &str,
) -> Result<String, JsValue> {
    let message = b64decode_b("message_b64", message_b64)?;
    let aad = if external_aad_b64.is_empty() {
        Vec::new()
    } else {
        b64decode_b("external_aad_b64", external_aad_b64)?
    };
    let keys_value = parse_json("trusted_keys_json", trusted_keys_json)?;
    let keys_obj = keys_value
        .as_object()
        .ok_or_else(|| JsValue::from_str("trusted_keys_json must be an object"))?;
    let mut keys = Vec::with_capacity(keys_obj.len());
    for (kid_b64, pk_b64) in keys_obj {
        let kid = b64decode_b("trusted kid", kid_b64)?;
        let pk_str = pk_b64
            .as_str()
            .ok_or_else(|| JsValue::from_str("trusted public keys must be base64 strings"))?;
        keys.push((kid, b64_32("trusted public key", pk_str)?));
    }
    let (payload, kid) = cose::verify(&message, &keys, &aad)
        .map_err(|e| JsValue::from_str(&format!("COSE verification failed: {e}")))?;
    Ok(serde_json::json!({
        "payload_b64": base64::engine::general_purpose::STANDARD.encode(&payload),
        "kid_b64": base64::engine::general_purpose::STANDARD.encode(&kid),
    })
    .to_string())
}

/// Verify an ActionEnvelope carried as COSE_Sign1 bytes.
/// `trusted_keys_json`: `{"<kid_str>": "<pubkey_b64>", ...}`.
/// `now_rfc3339`: verifier's clock; empty string falls back to `Date.now()`.
/// Returns the verified envelope fields as JSON; throws on failure.
#[wasm_bindgen]
pub fn verify_action_envelope(
    cose_b64: &str,
    trusted_keys_json: &str,
    now_rfc3339: &str,
    external_aad_b64: &str,
) -> Result<String, JsValue> {
    let data = b64decode_b("cose_b64", cose_b64)?;
    let aad = if external_aad_b64.is_empty() {
        Vec::new()
    } else {
        b64decode_b("external_aad_b64", external_aad_b64)?
    };
    let keys_value = parse_json("trusted_keys_json", trusted_keys_json)?;
    let keys_obj = keys_value
        .as_object()
        .ok_or_else(|| JsValue::from_str("trusted_keys_json must be an object"))?;
    let mut keys = Vec::with_capacity(keys_obj.len());
    for (kid, pk_b64) in keys_obj {
        let pk_str = pk_b64
            .as_str()
            .ok_or_else(|| JsValue::from_str("trusted public keys must be base64 strings"))?;
        keys.push((kid.clone(), b64_32("trusted public key", pk_str)?));
    }
    let now = if now_rfc3339.is_empty() {
        let ms = js_sys::Date::now();
        OffsetDateTime::from_unix_timestamp_nanos((ms * 1_000_000.0) as i128)
            .map_err(|_| JsValue::from_str("could not derive time from Date.now()"))?
    } else {
        OffsetDateTime::parse(now_rfc3339, &Rfc3339)
            .map_err(|_| JsValue::from_str("now_rfc3339 is not valid RFC-3339"))?
    };
    let env = envelope::verify_envelope(&data, &keys, now, &aad)
        .map_err(|e| JsValue::from_str(&format!("envelope verification failed: {e}")))?;
    Ok(serde_json::json!({
        "action_id": env.action_id,
        "principal": env.principal,
        "plane": env.plane,
        "verb": env.verb,
        "target": env.target,
        "args_digest": env.args_digest,
        "policy_ref": env.policy_ref,
        "issued_at": env.issued_at,
        "not_before": env.not_before,
        "not_after": env.not_after,
        "nonce": env.nonce,
        "action_digest": env.action_digest,
        "kid_b64": base64::engine::general_purpose::STANDARD.encode(&env.kid),
    })
    .to_string())
}

/// Re-validate a checkpoint chain from untrusted input.
/// `bootstrap_json`: `{"key_id": "...", "public_key_b64": "..."}`.
/// `anchor_json`: `{"key_id": "...", "public_key_b64": "...", "log": [...]}` —
/// `log` (anchor-log membership) is optional.
/// Returns `true` iff the whole chain verifies; malformed trust inputs throw.
#[wasm_bindgen]
pub fn verify_checkpoint_chain(
    chain_json: &str,
    bootstrap_json: &str,
    anchor_json: &str,
) -> Result<bool, JsValue> {
    let chain_value = parse_json("chain_json", chain_json)?;
    let chain = chain_value
        .as_array()
        .ok_or_else(|| JsValue::from_str("chain_json must be an array"))?;
    let bootstrap_value = parse_json("bootstrap_json", bootstrap_json)?;
    let bootstrap_obj = bootstrap_value
        .as_object()
        .ok_or_else(|| JsValue::from_str("bootstrap_json must be an object"))?;
    let bootstrap = checkpoint::TrustedSigner {
        key_id: bootstrap_obj
            .get("key_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| JsValue::from_str("bootstrap key_id missing"))?
            .to_owned(),
        public_key: b64_32(
            "bootstrap public key",
            bootstrap_obj
                .get("public_key_b64")
                .and_then(|v| v.as_str())
                .ok_or_else(|| JsValue::from_str("bootstrap public_key_b64 missing"))?,
        )?,
    };
    let anchor_value = parse_json("anchor_json", anchor_json)?;
    let anchor_obj = anchor_value
        .as_object()
        .ok_or_else(|| JsValue::from_str("anchor_json must be an object"))?;
    let anchor_key_id = anchor_obj
        .get("key_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsValue::from_str("anchor key_id missing"))?;
    let anchor_public_key = b64_32(
        "anchor public key",
        anchor_obj
            .get("public_key_b64")
            .and_then(|v| v.as_str())
            .ok_or_else(|| JsValue::from_str("anchor public_key_b64 missing"))?,
    )?;
    let anchor_log: Option<Vec<serde_json::Value>> = match anchor_obj.get("log") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => Some(
            v.as_array()
                .ok_or_else(|| JsValue::from_str("anchor log must be an array"))?
                .clone(),
        ),
    };
    let trust = checkpoint::AnchorTrust {
        key_id: anchor_key_id,
        public_key: &anchor_public_key,
        log: anchor_log.as_deref(),
    };
    Ok(checkpoint::verify_checkpoint_chain(chain, &bootstrap, &trust))
}

/// Offline Merkle inclusion check. Returns `true` iff the event is committed
/// by the checkpoint via the proof.
#[wasm_bindgen]
pub fn verify_inclusion(
    checkpoint_json: &str,
    event_json: &str,
    proof_json: &str,
) -> Result<bool, JsValue> {
    let cp = parse_json("checkpoint_json", checkpoint_json)?;
    let event = parse_json("event_json", event_json)?;
    let proof = parse_json("proof_json", proof_json)?;
    Ok(checkpoint::verify_inclusion(&cp, &event, &proof))
}

/// Canonical event hash (`SHA-256` of the canonical JSON).
#[wasm_bindgen]
pub fn event_hash(event_json: &str) -> Result<String, JsValue> {
    let event = parse_json("event_json", event_json)?;
    checkpoint::event_hash(&event).map_err(|e| JsValue::from_str(&format!("event_hash failed: {e}")))
}

/// Holder proof-of-possession check. Returns `true` iff the 64-byte proof is a
/// valid Ed25519 signature by the holder key over `capability_id || challenge`.
#[wasm_bindgen]
pub fn holder_proof_verify(
    holder_pubkey_b64: &str,
    capability_id: &str,
    challenge_b64: &str,
    proof_b64: &str,
) -> Result<bool, JsValue> {
    let pubkey = b64decode_b("holder_pubkey_b64", holder_pubkey_b64)?;
    let challenge = b64decode_b("challenge_b64", challenge_b64)?;
    let proof = b64decode_b("proof_b64", proof_b64)?;
    Ok(holder::verify_holder_proof(&pubkey, capability_id, &challenge, &proof).is_ok())
}

/// SHA-256 hex of raw bytes (base64 in).
#[wasm_bindgen]
pub fn sha256_hex_bytes(data_b64: &str) -> Result<String, JsValue> {
    let data = b64decode_b("data_b64", data_b64)?;
    Ok(checkpoint::sha256_hex_bytes(&data))
}

/// SHA-256 hex of the canonical JSON encoding of a JSON document.
#[wasm_bindgen]
pub fn canonical_json_sha256_hex(json_str: &str) -> Result<String, JsValue> {
    let value = parse_json("json_str", json_str)?;
    canonical_json::sha256_hex(&value)
        .map_err(|e| JsValue::from_str(&format!("canonical_json_sha256_hex failed: {e}")))
}
