//! Holder proof-of-possession verification.
//!
//! Mirrors `authority.verify_holder_proof` / `make_holder_proof`: the holder
//! signs `capability_id || server_challenge_nonce` with the bound holder key.
//! The challenge must be non-empty (a captured proof cannot be replayed
//! against a new challenge — freshness itself is a coordinator duty).

use crate::error::{Error, Result};
use ed25519_dalek::{Signature, VerifyingKey};

/// Verify a holder proof. `Ok(())` on success; `Err` on ANY failure
/// (wrong key, wrong challenge, wrong capability, malformed signature).
pub fn verify_holder_proof(
    holder_pubkey: &[u8],
    capability_id: &str,
    challenge: &[u8],
    proof: &[u8],
) -> Result<()> {
    if holder_pubkey.len() != 32 {
        return Err(Error::new(
            "bad-key-length",
            "holder_pubkey must be 32 raw Ed25519 bytes",
        ));
    }
    if !capability_id.is_ascii() {
        return Err(Error::new(
            "bad-capability-id",
            "capability_id must be ASCII (Python signs capability_id.encode(\"ascii\"))",
        ));
    }
    if challenge.is_empty() {
        return Err(Error::new(
            "empty-challenge",
            "challenge must be a non-empty byte string",
        ));
    }
    if proof.len() != 64 {
        return Err(Error::new(
            "bad-proof-length",
            "holder proof must be a 64-byte Ed25519 signature",
        ));
    }
    let mut message = Vec::with_capacity(capability_id.len() + challenge.len());
    message.extend_from_slice(capability_id.as_bytes());
    message.extend_from_slice(challenge);

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(holder_pubkey);
    let key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| Error::new("bad-key", "holder_pubkey is not a valid Ed25519 public key"))?;
    let sig = Signature::from_slice(proof)
        .map_err(|_| Error::new("bad-signature", "holder proof is not a valid Ed25519 signature"))?;
    key.verify_strict(&message, &sig)
        .map_err(|_| Error::new("bad-signature", "holder proof-of-possession failed"))
}
