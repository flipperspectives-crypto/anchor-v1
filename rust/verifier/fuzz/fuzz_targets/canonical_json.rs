#![no_main]
use anchor_v1_verifier::canonical_json::canonical_bytes;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Parse with serde_json (128-deep limit), then re-emit canonical bytes.
    // Neither stage may panic; the writer enforces its own 128-deep limit
    // for hand-constructed values.
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(data) {
        let _ = canonical_bytes(&v);
    }
});
