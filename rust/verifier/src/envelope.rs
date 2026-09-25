//! ActionEnvelope verification: COSE_Sign1 + schema + validity window.
//!
//! Mirrors `ActionEnvelope.verify_envelope` in `src/anchor_v1/envelope.py`.
//! The action digest is `SHA-256` of the canonical CBOR payload bytes —
//! exactly the bytes the COSE signature covers.

use crate::cbor::{self, Value};
use crate::error::{Error, Result};
use sha2::{Digest, Sha256};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

/// A verified action envelope: every field the offline verifier vouches for.
#[derive(Debug, Clone)]
pub struct VerifiedEnvelope {
    pub action_id: String,
    pub principal: String,
    pub plane: String,
    pub verb: String,
    pub target: String,
    pub args_digest: String,
    pub policy_ref: String,
    pub issued_at: String,
    pub not_before: String,
    pub not_after: String,
    pub nonce: String,
    /// SHA-256 hex of the canonical CBOR payload bytes.
    pub action_digest: String,
    /// COSE kid (UTF-8 bytes) that signed the envelope.
    pub kid: Vec<u8>,
}

fn parse_time(field: &str, value: &str) -> Result<OffsetDateTime> {
    OffsetDateTime::parse(value, &Rfc3339).map_err(|_| {
        Error::new(
            "bad-timestamp",
            format!("envelope field {field} is not a valid RFC-3339 timestamp"),
        )
    })
}

fn req_text(map: &Value, field: &'static str) -> Result<String> {
    map.get(field)
        .and_then(|v| v.as_text())
        .map(|s| s.to_owned())
        .ok_or_else(|| {
            Error::new("bad-schema", format!("envelope field {field} missing or not a string"))
        })
}

fn forbid_extra(map: &Value, allowed: &[&str], what: &str) -> Result<()> {
    let entries = map.as_map().ok_or_else(|| {
        Error::new("bad-schema", format!("{what} must be a map"))
    })?;
    for (k, _) in entries {
        let name = k.as_text().ok_or_else(|| {
            Error::new("bad-schema", format!("{what} keys must be text"))
        })?;
        if !allowed.contains(&name) {
            return Err(Error::new(
                "bad-schema",
                format!("{what} has forbidden extra field {name:?}"),
            ));
        }
    }
    Ok(())
}

/// Verify COSE_Sign1 bytes and return the validated ActionEnvelope.
///
/// `trusted_keys` maps key-id strings to raw 32-byte Ed25519 public keys.
/// `now` is the verifier's clock (offline: caller-supplied). Fails closed on
/// any COSE, schema, or validity-window failure.
pub fn verify_envelope(
    data: &[u8],
    trusted_keys: &[(String, [u8; 32])],
    now: OffsetDateTime,
    external_aad: &[u8],
) -> Result<VerifiedEnvelope> {
    let cose_keys: Vec<(Vec<u8>, [u8; 32])> = trusted_keys
        .iter()
        .map(|(kid, pk)| (kid.as_bytes().to_vec(), *pk))
        .collect();
    let (payload, kid) =
        crate::cose::verify(data, &cose_keys, external_aad).map_err(|e| {
            Error::new(e.reason, format!("envelope COSE verification failed: {e}"))
        })?;

    let raw = cbor::loads(&payload).map_err(|e| {
        Error::new("bad-payload", format!("envelope payload is not valid CBOR: {e}"))
    })?;
    const FIELDS: &[&str] = &[
        "action_id",
        "principal",
        "effect",
        "policy_ref",
        "issued_at",
        "not_before",
        "not_after",
        "nonce",
    ];
    forbid_extra(&raw, FIELDS, "envelope")?;
    let action_id = req_text(&raw, "action_id")?;
    let principal = req_text(&raw, "principal")?;
    let policy_ref = req_text(&raw, "policy_ref")?;
    let issued_at = req_text(&raw, "issued_at")?;
    let not_before = req_text(&raw, "not_before")?;
    let not_after = req_text(&raw, "not_after")?;
    let nonce = req_text(&raw, "nonce")?;

    let effect = raw.get("effect").ok_or_else(|| {
        Error::new("bad-schema", "envelope field effect missing")
    })?;
    forbid_extra(effect, &["plane", "verb", "target", "args_digest"], "effect")?;
    let plane = req_text(effect, "plane")?;
    let verb = req_text(effect, "verb")?;
    let target = req_text(effect, "target")?;
    let args_digest = req_text(effect, "args_digest")?;

    let not_before_t = parse_time("not_before", &not_before)?;
    let not_after_t = parse_time("not_after", &not_after)?;
    parse_time("issued_at", &issued_at)?; // must parse; not otherwise constrained
    if now < not_before_t {
        return Err(Error::new(
            "not-yet-valid",
            "envelope not yet valid (not_before in the future)",
        ));
    }
    if now > not_after_t {
        return Err(Error::new(
            "expired",
            "envelope expired (not_after in the past)",
        ));
    }

    let action_digest = hex::encode(Sha256::digest(&payload));

    Ok(VerifiedEnvelope {
        action_id,
        principal,
        plane,
        verb,
        target,
        args_digest,
        policy_ref,
        issued_at,
        not_before,
        not_after,
        nonce,
        action_digest,
        kid,
    })
}
