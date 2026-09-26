//! `anchor-verify` — offline CLI for ANCHOR v1 artifact verification.
//!
//! Exit codes: 0 = valid, 1 = verification failed, 2 = usage/input error.
//! An argument value of `@path` reads the value from the file at `path`.

use anchor_v1_verifier::{canonical_json, checkpoint, cose, envelope, holder};
use base64::Engine;
use std::process::ExitCode;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

fn usage() -> ! {
    eprintln!(
        "anchor-verify — offline ANCHOR v1 artifact verification\n\
         \n\
         Usage:\n  \
         anchor-verify cose --message @file|B64 --keys @file|JSON [--aad @file|B64]\n  \
         anchor-verify envelope --cose @file|B64 --keys @file|JSON [--now RFC3339] [--aad @file|B64]\n  \
         anchor-verify chain --chain @file|JSON --bootstrap @file|JSON \\\n                      \
         --anchor-key-id ID --anchor-key B64 [--anchor-log @file|JSON]\n  \
         anchor-verify inclusion --checkpoint @file|JSON --event @file|JSON --proof @file|JSON\n  \
         anchor-verify holder --pubkey B64 --capability-id ID --challenge B64 --proof B64\n  \
         anchor-verify event-hash --event @file|JSON\n\
         \n\
         @path reads the argument from a file. JSON trust inputs:\n  \
         cose --keys:            {{\"<kid_b64>\": \"<pubkey_b64>\"}}\n  \
         envelope --keys:        {{\"<kid_str>\": \"<pubkey_b64>\"}}\n  \
         chain --bootstrap:      {{\"key_id\": \"...\", \"public_key_b64\": \"...\"}}\n  \
         chain --anchor-log:     [<AnchorProof JSON>, ...] (optional)"
    );
    std::process::exit(2);
}

fn arg_value(args: &[String], name: &str) -> Option<String> {
    args.windows(2).find_map(|w| {
        if w[0] == name {
            Some(w[1].clone())
        } else {
            None
        }
    })
}

fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

/// `@path` → file contents, otherwise the literal.
fn resolve(raw: &str) -> Result<String, String> {
    if let Some(path) = raw.strip_prefix('@') {
        std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))
    } else {
        Ok(raw.to_owned())
    }
}

fn b64(field: &str, s: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|_| format!("{field} is not valid base64"))
}

fn b64_32(field: &str, s: &str) -> Result<[u8; 32], String> {
    let raw = b64(field, s)?;
    if raw.len() != 32 {
        return Err(format!("{field} must decode to 32 bytes"));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || has_flag(&args, "--help") || has_flag(&args, "-h") {
        usage();
    }
    let result = match args[0].as_str() {
        "cose" => cmd_cose(&args[1..]),
        "envelope" => cmd_envelope(&args[1..]),
        "chain" => cmd_chain(&args[1..]),
        "inclusion" => cmd_inclusion(&args[1..]),
        "holder" => cmd_holder(&args[1..]),
        "event-hash" => cmd_event_hash(&args[1..]),
        _ => usage(),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(Fail::Invalid(msg)) => {
            eprintln!("INVALID: {msg}");
            ExitCode::from(1)
        }
        Err(Fail::Input(msg)) => {
            eprintln!("error: {msg}");
            ExitCode::from(2)
        }
    }
}

enum Fail {
    Invalid(String),
    Input(String),
}
type CmdResult = Result<(), Fail>;
fn input<T>(r: Result<T, String>) -> Result<T, Fail> {
    r.map_err(Fail::Input)
}
fn invalid<T>(r: Result<T, anchor_v1_verifier::Error>) -> Result<T, Fail> {
    r.map_err(|e| Fail::Invalid(e.to_string()))
}

fn cmd_cose(args: &[String]) -> CmdResult {
    let message = input(arg_value(args, "--message").ok_or("--message is required".to_owned()).and_then(|v| resolve(&v)).and_then(|v| b64("--message", &v)))?;
    let keys_json = input(arg_value(args, "--keys").ok_or("--keys is required".to_owned()).and_then(|v| resolve(&v)))?;
    let aad = match arg_value(args, "--aad") {
        Some(v) => input(resolve(&v).and_then(|s| b64("--aad", &s)))?,
        None => Vec::new(),
    };
    let keys_value: serde_json::Value =
        input(serde_json::from_str(&keys_json).map_err(|e| format!("--keys is not valid JSON: {e}")))?;
    let mut keys = Vec::new();
    for (kid_b64, pk) in input(keys_value.as_object().ok_or("keys must be a JSON object".to_owned()))?.iter() {
        let kid = input(b64("trusted kid", kid_b64))?;
        let pk_str = input(pk.as_str().ok_or("trusted public keys must be base64 strings".to_owned()))?;
        keys.push((kid, input(b64_32("trusted public key", pk_str))?));
    }
    let (payload, kid) = invalid(cose::verify(&message, &keys, &aad))?;
    println!(
        "{}",
        serde_json::json!({
            "payload_b64": base64::engine::general_purpose::STANDARD.encode(&payload),
            "kid_b64": base64::engine::general_purpose::STANDARD.encode(&kid),
        })
    );
    Ok(())
}

fn cmd_envelope(args: &[String]) -> CmdResult {
    let data = input(arg_value(args, "--cose").ok_or("--cose is required".to_owned()).and_then(|v| resolve(&v)).and_then(|v| b64("--cose", &v)))?;
    let keys_json = input(arg_value(args, "--keys").ok_or("--keys is required".to_owned()).and_then(|v| resolve(&v)))?;
    let aad = match arg_value(args, "--aad") {
        Some(v) => input(resolve(&v).and_then(|s| b64("--aad", &s)))?,
        None => Vec::new(),
    };
    let now = match arg_value(args, "--now") {
        Some(s) => input(OffsetDateTime::parse(&s, &Rfc3339).map_err(|_| "--now is not valid RFC-3339".to_owned()))?,
        None => OffsetDateTime::now_utc(),
    };
    let keys_value: serde_json::Value =
        input(serde_json::from_str(&keys_json).map_err(|e| format!("--keys is not valid JSON: {e}")))?;
    let mut keys = Vec::new();
    for (kid, pk) in input(keys_value.as_object().ok_or("keys must be a JSON object".to_owned()))?.iter() {
        let pk_str = input(pk.as_str().ok_or("trusted public keys must be base64 strings".to_owned()))?;
        keys.push((kid.clone(), input(b64_32("trusted public key", pk_str))?));
    }
    let env = invalid(envelope::verify_envelope(&data, &keys, now, &aad))?;
    println!(
        "{}",
        serde_json::json!({
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
    );
    Ok(())
}

fn cmd_chain(args: &[String]) -> CmdResult {
    let chain_json = input(arg_value(args, "--chain").ok_or("--chain is required".to_owned()).and_then(|v| resolve(&v)))?;
    let bootstrap_json = input(arg_value(args, "--bootstrap").ok_or("--bootstrap is required".to_owned()).and_then(|v| resolve(&v)))?;
    let anchor_key_id = input(arg_value(args, "--anchor-key-id").ok_or("--anchor-key-id is required".to_owned()))?;
    let anchor_key = input(arg_value(args, "--anchor-key").ok_or("--anchor-key is required".to_owned()).and_then(|v| b64_32("--anchor-key", &v)))?;
    let anchor_log: Option<Vec<serde_json::Value>> = match arg_value(args, "--anchor-log") {
        Some(v) => {
            let s = input(resolve(&v))?;
            let parsed: serde_json::Value =
                input(serde_json::from_str(&s).map_err(|e| format!("--anchor-log is not valid JSON: {e}")))?;
            Some(input(parsed.as_array().cloned().ok_or("anchor log must be a JSON array".to_owned()))?)
        }
        None => None,
    };

    let chain_value: serde_json::Value =
        input(serde_json::from_str(&chain_json).map_err(|e| format!("--chain is not valid JSON: {e}")))?;
    let chain = input(chain_value.as_array().cloned().ok_or("--chain must be a JSON array".to_owned()))?;
    let bootstrap_value: serde_json::Value = input(
        serde_json::from_str(&bootstrap_json).map_err(|e| format!("--bootstrap is not valid JSON: {e}")),
    )?;
    let bobj = input(bootstrap_value.as_object().ok_or("--bootstrap must be a JSON object".to_owned()))?;
    let bootstrap = checkpoint::TrustedSigner {
        key_id: input(bobj.get("key_id").and_then(|v| v.as_str()).ok_or_else(|| "bootstrap key_id missing".to_owned()))?.to_owned(),
        public_key: input(b64_32(
            "bootstrap public key",
            input(bobj.get("public_key_b64").and_then(|v| v.as_str()).ok_or("bootstrap public_key_b64 missing".to_owned()))?,
        ))?,
    };
    let trust = checkpoint::AnchorTrust {
        key_id: &anchor_key_id,
        public_key: &anchor_key,
        log: anchor_log.as_deref(),
    };
    if checkpoint::verify_checkpoint_chain(&chain, &bootstrap, &trust) {
        println!("chain valid");
        Ok(())
    } else {
        Err(Fail::Invalid("checkpoint chain verification failed".to_owned()))
    }
}

fn cmd_inclusion(args: &[String]) -> CmdResult {
    let load = |name: &str| -> Result<serde_json::Value, Fail> {
        let s = input(arg_value(args, name).ok_or(format!("{name} is required")).and_then(|v| resolve(&v)))?;
        input(serde_json::from_str(&s).map_err(|e| format!("{name} is not valid JSON: {e}")))
    };
    let cp = load("--checkpoint")?;
    let event = load("--event")?;
    let proof = load("--proof")?;
    if checkpoint::verify_inclusion(&cp, &event, &proof) {
        println!("inclusion valid");
        Ok(())
    } else {
        Err(Fail::Invalid("inclusion proof verification failed".to_owned()))
    }
}

fn cmd_holder(args: &[String]) -> CmdResult {
    let get = |name: &str| -> Result<String, Fail> {
        input(
            arg_value(args, name)
                .ok_or(format!("{name} is required"))
                .and_then(|v| resolve(&v)),
        )
    };
    let pubkey = input(b64("--pubkey", &get("--pubkey")?))?;
    let capability_id = get("--capability-id")?;
    let challenge = input(b64("--challenge", &get("--challenge")?))?;
    let proof = input(b64("--proof", &get("--proof")?))?;
    invalid(holder::verify_holder_proof(&pubkey, &capability_id, &challenge, &proof))?;
    println!("holder proof valid");
    Ok(())
}

fn cmd_event_hash(args: &[String]) -> CmdResult {
    let s = input(arg_value(args, "--event").ok_or("--event is required".to_owned()).and_then(|v| resolve(&v)))?;
    let event: serde_json::Value =
        input(serde_json::from_str(&s).map_err(|e| format!("--event is not valid JSON: {e}")))?;
    let h = invalid(canonical_json::sha256_hex(&event))?;
    println!("{h}");
    Ok(())
}
