#![no_main]
use anchor_v1_verifier::cbor::loads;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The decoder must never panic or hang on adversarial input: it enforces
    // a 16 MiB input cap, 64-deep nesting limit, and checked arithmetic.
    // Any return (Ok or Err) is acceptable; a panic/abort is a bug.
    let _ = loads(data);
});
