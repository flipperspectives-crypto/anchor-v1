//! Canonical JSON serialization, byte-identical to the Python
//! `canonical_bytes` used for all digests and v0 signatures:
//!
//! ```python
//! json.dumps(value, sort_keys=True, separators=(",", ":"),
//!            ensure_ascii=False, allow_nan=False).encode("utf-8")
//! ```
//!
//! Rules mirrored here:
//! * object keys sorted by Unicode code point (UTF-8 byte order),
//! * no whitespace (`separators=(",", ":")`),
//! * non-ASCII emitted raw as UTF-8 (`ensure_ascii=False`),
//! * control characters escaped as `\b \f \n \r \t` or `\u00XX`,
//! * floats use CPython's shortest-repr formatting (fixed vs. exponential
//!   threshold, signed zero-padded exponents),
//! * NaN / infinities are rejected (`allow_nan=False`).

use crate::error::{Error, Result};
use serde_json::Value;

/// Maximum nesting depth accepted by the writer. `serde_json`'s parser
/// already caps depth at 128, so legitimately parsed values can never reach
/// this; it exists so hand-constructed values cannot exhaust the stack.
const MAX_DEPTH: usize = 128;

/// Serialize `value` to canonical JSON bytes.
pub fn canonical_bytes(value: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    write_value(value, &mut out, 0)?;
    Ok(out)
}

/// SHA-256 hex of the canonical JSON bytes (`sha256_hex` in `canonical.py`).
pub fn sha256_hex(value: &Value) -> Result<String> {
    use sha2::{Digest, Sha256};
    let bytes = canonical_bytes(value)?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn write_value(v: &Value, out: &mut Vec<u8>, depth: usize) -> Result<()> {
    if depth > MAX_DEPTH {
        return Err(Error::new(
            "depth-limit",
            format!("JSON nesting depth exceeded limit of {MAX_DEPTH}"),
        ));
    }
    match v {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                out.extend_from_slice(u.to_string().as_bytes());
            } else if let Some(i) = n.as_i64() {
                out.extend_from_slice(i.to_string().as_bytes());
            } else {
                let raw = n.as_str();
                if is_integer_syntax(raw) {
                    // Arbitrary-precision integer (Python ints have no upper
                    // bound): the JSON text is already the canonical digits.
                    out.extend_from_slice(raw.as_bytes());
                } else if let Some(f) = n.as_f64() {
                    write_float(f, out)?;
                } else {
                    return Err(Error::new("bad-number", "unrepresentable JSON number"));
                }
            }
        }
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_value(item, out, depth + 1)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            // sort_keys=True: Python sorts str keys by Unicode code point,
            // which is UTF-8 byte order.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            out.push(b'{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_string(k, out);
                out.push(b':');
                write_value(&map[*k], out, depth + 1)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn write_string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\u{08}' => out.extend_from_slice(b"\\b"),
            '\u{0c}' => out.extend_from_slice(b"\\f"),
            c if (c as u32) < 0x20 => {
                // \u00XX — Python uses lowercase hex.
                out.extend_from_slice(b"\\u00");
                let b = c as u8;
                out.push(hex_digit(b >> 4));
                out.push(hex_digit(b & 0xf));
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

fn hex_digit(n: u8) -> u8 {
    if n < 10 {
        b'0' + n
    } else {
        b'a' + (n - 10)
    }
}

fn is_integer_syntax(s: &str) -> bool {
    let digits = s.strip_prefix('-').unwrap_or(s);
    !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
}

/// CPython `repr(float)` formatting for JSON output.
///
/// Uses the shortest digit string that round-trips (via ryu), then applies
/// CPython's fixed-vs-exponential rule: exponential when the decimal exponent
/// `decpt` (value = 0.digits × 10^decpt) satisfies `decpt <= -4 || decpt > 16`;
/// otherwise fixed notation with a trailing `.0` for integral values.
fn write_float(x: f64, out: &mut Vec<u8>) -> Result<()> {
    if !x.is_finite() {
        return Err(Error::new(
            "non-finite-float",
            "NaN and infinities are not allowed in canonical JSON",
        ));
    }
    if x == 0.0 {
        // Covers -0.0: Python json.dumps(-0.0) -> "-0.0".
        out.extend_from_slice(if x.is_sign_negative() { b"-0.0" } else { b"0.0" });
        return Ok(());
    }
    let neg = x.is_sign_negative();
    // Shortest round-trip digits in scientific form, e.g. "1e16",
    // "1.2345678901234568e16", "1e-5". `{:e}` always emits a mantissa, 'e',
    // and a signed exponent for finite non-zero inputs.
    let sci = format!("{:e}", x.abs());
    let (mant, exp_part) = sci
        .split_once('e')
        .ok_or_else(|| Error::new("bad-float", "float formatting failed"))?;
    let exp: i32 = exp_part.parse().map_err(|_| Error::new("bad-float", "float formatting failed"))?;
    let digits: String = mant.chars().filter(|c| *c != '.').collect();
    // value = 0.digits × 10^decpt
    let decpt: i32 = exp + 1;

    let mut s = String::new();
    if neg {
        s.push('-');
    }
    if decpt <= -4 || decpt > 16 {
        // Exponential: d.dddde±XX, exponent always signed, ≥ 2 digits.
        let mut it = digits.chars();
        s.push(
            it.next()
                .ok_or_else(|| Error::new("bad-float", "float formatting failed"))?,
        );
        let rest: String = it.collect();
        if !rest.is_empty() {
            s.push('.');
            s.push_str(&rest);
        }
        s.push('e');
        if exp < 0 {
            s.push('-');
        } else {
            s.push('+');
        }
        let mag = exp.abs().to_string();
        if mag.len() < 2 {
            s.push('0');
        }
        s.push_str(&mag);
    } else if decpt <= 0 {
        s.push_str("0.");
        for _ in 0..(-decpt) {
            s.push('0');
        }
        s.push_str(&digits);
    } else if decpt as usize >= digits.len() {
        s.push_str(&digits);
        for _ in 0..(decpt as usize - digits.len()) {
            s.push('0');
        }
        s.push_str(".0");
    } else {
        let d = decpt as usize;
        s.push_str(&digits[..d]);
        s.push('.');
        s.push_str(&digits[d..]);
    }
    out.extend_from_slice(s.as_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn float_formatting_matches_cpython() {
        // (value, expected CPython json.dumps output)
        let cases: &[(f64, &str)] = &[
            (1.0, "1.0"),
            (-0.0, "-0.0"),
            (0.1, "0.1"),
            (1e16, "1e+16"),
            (1e15, "1000000000000000.0"),
            (1e-4, "0.0001"),
            (1e-5, "1e-05"),
            (123.456, "123.456"),
            (100.0, "100.0"),
            (1.5e-7, "1.5e-07"),
            (-2.5e-3, "-0.0025"),
            (1.7976931348623157e308, "1.7976931348623157e+308"),
            (5e-324, "5e-324"),
            (0.30000000000000004, "0.30000000000000004"),
        ];
        for (x, want) in cases {
            let got = canonical_bytes(&json!(*x)).unwrap();
            assert_eq!(std::str::from_utf8(&got).unwrap(), *want, "x={x}");
        }
    }

    #[test]
    fn string_escaping_matches_cpython() {
        let v = json!("a\"b\\c\nd\te\u{0001}f\u{007f}g\u{00e9}h");
        let got = String::from_utf8(canonical_bytes(&v).unwrap()).unwrap();
        assert_eq!(got, "\"a\\\"b\\\\c\\nd\\te\\u0001f\u{007f}g\u{00e9}h\"");
    }

    #[test]
    fn key_order_and_separators() {
        let v = json!({"b": 1, "a": [1, 2], "c": {"z": true, "a": null}});
        let got = String::from_utf8(canonical_bytes(&v).unwrap()).unwrap();
        assert_eq!(got, r#"{"a":[1,2],"b":1,"c":{"a":null,"z":true}}"#);
    }

    #[test]
    fn rejects_non_finite() {
        // serde_json cannot represent non-finite floats at all
        // (Number::from_f64 returns None), which upholds allow_nan=False.
        assert!(serde_json::Number::from_f64(f64::NAN).is_none());
        assert!(serde_json::Number::from_f64(f64::INFINITY).is_none());
        assert!(serde_json::Number::from_f64(f64::NEG_INFINITY).is_none());
    }
}
