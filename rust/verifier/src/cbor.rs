//! Strict deterministic CBOR codec (RFC 8949 §4.2.1).
//!
//! Mirrors `src/anchor_v1/cbor.py` exactly:
//! * shortest-form integers (minimal additional-information width),
//! * canonical map key ordering — encoded keys sorted by (length, lexicographic),
//! * definite lengths only (indefinite lengths rejected),
//! * preferred shortest float serialization: half → single → double,
//! * bignum tags 2/3 for integers outside the 64-bit range.
//!
//! The decoder is strict: any non-canonical encoding is rejected. Strictness
//! is a security property — signature verification must never accept two
//! different byte strings for the same logical value.

use crate::error::{Error, Result};

/// Maximum nesting depth accepted by the decoder (matches `cbor.py`).
pub const MAX_DEPTH: usize = 64;

/// Maximum input size accepted by the decoder (16 MiB). Every allocation the
/// decoder performs is a slice or copy of the input (or bounded by remaining
/// input length), so this caps total memory on hostile input. COSE messages,
/// envelopes, and checkpoint artifacts are kilobytes in practice.
pub const MAX_INPUT_BYTES: usize = 16 * 1024 * 1024;

/// A decoded CBOR data item.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Int(Integer),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    /// Canonical order: keys sorted by (len(encoded), encoded).
    Map(Vec<(Value, Value)>),
    Tag(u64, Box<Value>),
    Float(f64),
    Bool(bool),
    Null,
    Undefined,
    Simple(u8),
}

/// A CBOR integer. `Small` covers the full ±2^127 range; `Big` is an
/// out-of-range bignum (tags 2/3) kept as sign + trimmed big-endian magnitude.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Integer {
    Small(i128),
    Big { negative: bool, magnitude: Vec<u8> },
}

impl Integer {
    fn small(v: i128) -> Value {
        Value::Int(Integer::Small(v))
    }
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

fn head(major: u8, n: u64, out: &mut Vec<u8>) -> Result<()> {
    if n < 24 {
        out.push((major << 5) | n as u8);
    } else if n < 0x100 {
        out.push((major << 5) | 24);
        out.push(n as u8);
    } else if n < 0x10000 {
        out.push((major << 5) | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n < 0x100000000 {
        out.push((major << 5) | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push((major << 5) | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
    Ok(())
}

fn encode_uint_arg(major: u8, n: u128, out: &mut Vec<u8>) -> Result<()> {
    if n <= u64::MAX as u128 {
        head(major, n as u64, out)
    } else {
        Err(Error::new("integer-too-large", "integer argument too large for CBOR"))
    }
}

fn encode_integer(v: &Integer, out: &mut Vec<u8>) -> Result<()> {
    // Mirror cbor.py ranges: [0, 2^64) -> major 0, [-2^64, 0) -> major 1,
    // everything else -> bignum tags 2/3 with minimal big-endian content.
    const TWO64: i128 = 1 << 64;
    let (negative, mag): (bool, u128) = match v {
        Integer::Small(n) if (0..TWO64).contains(n) => return encode_uint_arg(0, *n as u128, out),
        Integer::Small(n) if (-TWO64..0).contains(n) => {
            return encode_uint_arg(1, (-1 - *n) as u128, out)
        }
        Integer::Small(n) if *n >= 0 => (false, *n as u128),
        Integer::Small(n) if *n == i128::MIN => (true, i128::MAX as u128),
        Integer::Small(n) => (true, (-1 - *n) as u128),
        Integer::Big { negative, magnitude } => {
            let tag: u64 = if *negative { 3 } else { 2 };
            head(6, tag, out)?;
            head(2, magnitude.len() as u64, out)?;
            out.extend_from_slice(magnitude);
            return Ok(());
        }
    };
    let tag: u64 = if negative { 3 } else { 2 };
    let bytes = mag.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len() - 1);
    head(6, tag, out)?;
    head(2, (bytes.len() - start) as u64, out)?;
    out.extend_from_slice(&bytes[start..]);
    Ok(())
}

/// Shortest float encoding: half → single → double; canonical NaN is f9 7e00.
fn encode_float(x: f64, out: &mut Vec<u8>) {
    if x.is_nan() {
        out.extend_from_slice(&[0xf9, 0x7e, 0x00]);
        return;
    }
    // `struct.pack(">e", x)` raises OverflowError for finite values outside
    // the half range; the half crate saturates instead, so skip half when a
    // finite input overflows to infinity.
    let h = half::f16::from_f64(x);
    if h.to_f64() == x && (x.is_infinite() || !h.is_infinite()) {
        out.push(0xf9);
        out.extend_from_slice(&h.to_be_bytes());
        return;
    }
    let f = x as f32;
    if (f as f64) == x {
        out.push(0xfa);
        out.extend_from_slice(&f.to_be_bytes());
        return;
    }
    out.push(0xfb);
    out.extend_from_slice(&x.to_be_bytes());
}

fn encode_value(v: &Value, out: &mut Vec<u8>) -> Result<()> {
    match v {
        Value::Null => out.push(0xf6),
        Value::Bool(true) => out.push(0xf5),
        Value::Bool(false) => out.push(0xf4),
        Value::Undefined => out.push(0xf7),
        Value::Simple(n) => {
            if *n < 32 {
                return Err(Error::new(
                    "non-canonical-simple",
                    "simple values < 32 must use the 1-byte form",
                ));
            }
            out.push(0xf8);
            out.push(*n);
        }
        Value::Int(n) => encode_integer(n, out)?,
        Value::Float(x) => encode_float(*x, out),
        Value::Bytes(b) => {
            head(2, b.len() as u64, out)?;
            out.extend_from_slice(b);
        }
        Value::Text(s) => {
            let raw = s.as_bytes();
            head(3, raw.len() as u64, out)?;
            out.extend_from_slice(raw);
        }
        Value::Array(items) => {
            head(4, items.len() as u64, out)?;
            for item in items {
                encode_value(item, out)?;
            }
        }
        Value::Map(pairs) => {
            // Canonical ordering: sort by (len(encoded key), encoded key).
            let mut enc: Vec<(Vec<u8>, &Value, &Value)> = Vec::with_capacity(pairs.len());
            for (k, val) in pairs {
                let mut kb = Vec::new();
                encode_value(k, &mut kb)?;
                enc.push((kb, k, val));
            }
            enc.sort_by(|a, b| (a.0.len(), &a.0).cmp(&(b.0.len(), &b.0)));
            head(5, enc.len() as u64, out)?;
            for (kb, _, val) in &enc {
                out.extend_from_slice(kb);
                encode_value(val, out)?;
            }
        }
        Value::Tag(num, inner) => {
            head(6, *num, out)?;
            encode_value(inner, out)?;
        }
    }
    Ok(())
}

/// Deterministically encode a value to CBOR bytes.
pub fn dumps(value: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    encode_value(value, &mut out)?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// Decoding (strict)
// ---------------------------------------------------------------------------

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    depth: usize,
}

impl<'a> Reader<'a> {
    fn read(&mut self, n: usize) -> Result<&'a [u8]> {
        // checked_add: a forged length must not wrap the end offset past the
        // bounds check (on 32-bit targets `pos + n` could otherwise wrap).
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| Error::new("length-overflow", "CBOR length overflows address space"))?;
        if end > self.data.len() {
            return Err(Error::new("truncated-cbor", "truncated CBOR input"));
        }
        let chunk = &self.data[self.pos..end];
        self.pos = end;
        Ok(chunk)
    }

    /// Decode the argument, enforcing shortest form.
    fn arg(&mut self, ai: u8) -> Result<u64> {
        if ai < 24 {
            return Ok(ai as u64);
        }
        match ai {
            24 => {
                let n = self.read(1)?[0] as u64;
                if n < 24 {
                    return Err(Error::new(
                        "non-shortest-int",
                        "non-shortest integer encoding (1-byte)",
                    ));
                }
                Ok(n)
            }
            25 => {
                let b = self.read(2)?;
                let n = u16::from_be_bytes([b[0], b[1]]) as u64;
                if n < 0x100 {
                    return Err(Error::new(
                        "non-shortest-int",
                        "non-shortest integer encoding (2-byte)",
                    ));
                }
                Ok(n)
            }
            26 => {
                let b = self.read(4)?;
                let n = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64;
                if n < 0x10000 {
                    return Err(Error::new(
                        "non-shortest-int",
                        "non-shortest integer encoding (4-byte)",
                    ));
                }
                Ok(n)
            }
            27 => {
                let b = self.read(8)?;
                let n = u64::from_be_bytes([
                    b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                ]);
                if n < 0x100000000 {
                    return Err(Error::new(
                        "non-shortest-int",
                        "non-shortest integer encoding (8-byte)",
                    ));
                }
                Ok(n)
            }
            _ => Err(Error::new(
                "invalid-ai",
                format!("invalid additional information {ai}"),
            )),
        }
    }

    fn decode_simple(&mut self, ai: u8) -> Result<Value> {
        match ai {
            0..=19 => Ok(Value::Simple(ai)),
            20 => Ok(Value::Bool(false)),
            21 => Ok(Value::Bool(true)),
            22 => Ok(Value::Null),
            23 => Ok(Value::Undefined),
            24 => {
                let n = self.read(1)?[0];
                if n < 32 {
                    return Err(Error::new(
                        "non-shortest-simple",
                        "non-shortest simple-value encoding",
                    ));
                }
                Ok(Value::Simple(n))
            }
            25 => {
                let b = self.read(2)?;
                let h = half::f16::from_be_bytes([b[0], b[1]]);
                Ok(Value::Float(h.to_f64()))
            }
            26 => {
                let b = self.read(4)?;
                Ok(Value::Float(f32::from_be_bytes([b[0], b[1], b[2], b[3]]) as f64))
            }
            27 => {
                let b = self.read(8)?;
                Ok(Value::Float(f64::from_be_bytes([
                    b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                ])))
            }
            _ => Err(Error::new(
                "invalid-ai",
                "reserved additional information",
            )),
        }
    }

    fn decode_map(&mut self, n: u64) -> Result<Value> {
        let mut pairs = Vec::with_capacity(n.min(1024) as usize);
        let mut prev_key: Option<Vec<u8>> = None;
        for _ in 0..n {
            let key_start = self.pos;
            let key = self.decode()?;
            let key_bytes = self.data[key_start..self.pos].to_vec();
            // Canonical ordering check doubles as the duplicate-key check:
            // equal keys are never strictly greater than the previous one.
            if let Some(prev) = &prev_key {
                if key_bytes.as_slice() <= prev.as_slice() {
                    return Err(Error::new(
                        "non-canonical-map",
                        "map keys not in canonical order (or duplicate key)",
                    ));
                }
            }
            prev_key = Some(key_bytes);
            let val = self.decode()?;
            pairs.push((key, val));
        }
        Ok(Value::Map(pairs))
    }

    fn decode_tag(&mut self, n: u64) -> Result<Value> {
        let inner = self.decode()?;
        if (n == 2 || n == 3) && matches!(inner, Value::Bytes(_)) {
            if let Value::Bytes(content) = &inner {
                if content.len() > 1 && content[0] == 0 {
                    return Err(Error::new(
                        "non-shortest-bignum",
                        "non-shortest bignum encoding",
                    ));
                }
                // Normalize into Small when it fits in i128.
                if content.len() <= 16 {
                    let mut mag = [0u8; 16];
                    mag[16 - content.len()..].copy_from_slice(content);
                    let m = u128::from_be_bytes(mag);
                    if n == 2 {
                        if let Ok(s) = i128::try_from(m) {
                            return Ok(Integer::small(s));
                        }
                    } else if m <= i128::MAX as u128 + 1 {
                        let s = if m == i128::MAX as u128 + 1 {
                            i128::MIN
                        } else {
                            -1 - m as i128
                        };
                        return Ok(Integer::small(s));
                    }
                }
                return Ok(Value::Int(Integer::Big {
                    negative: n == 3,
                    magnitude: content.clone(),
                }));
            }
        }
        Ok(Value::Tag(n, Box::new(inner)))
    }

    fn decode(&mut self) -> Result<Value> {
        if self.depth > MAX_DEPTH {
            return Err(Error::new(
                "depth-limit",
                format!("CBOR nesting depth exceeded limit of {MAX_DEPTH}"),
            ));
        }
        let initial = self.read(1)?[0];
        let major = initial >> 5;
        let ai = initial & 0x1f;
        if ai == 31 {
            return Err(Error::new(
                "indefinite-length",
                "indefinite lengths are not allowed in deterministic CBOR",
            ));
        }
        if major == 7 {
            return self.decode_simple(ai);
        }
        let n = self.arg(ai)?;
        match major {
            0 => Ok(Integer::small(n as i128)),
            1 => Ok(Integer::small(-1 - n as i128)),
            2 => {
                // try_from, not `as`: on 32-bit targets a forged u64 length
                // must error, not truncate to a small usize and decode as
                // empty (with the input cap above, any legitimate length
                // always fits).
                let len = usize::try_from(n).map_err(|_| {
                    Error::new("length-overflow", "CBOR byte string length exceeds address space")
                })?;
                Ok(Value::Bytes(self.read(len)?.to_vec()))
            }
            3 => {
                let len = usize::try_from(n).map_err(|_| {
                    Error::new("length-overflow", "CBOR text string length exceeds address space")
                })?;
                let raw = self.read(len)?;
                std::str::from_utf8(raw)
                    .map(|s| Value::Text(s.to_owned()))
                    .map_err(|_| Error::new("invalid-utf8", "invalid UTF-8 in text string"))
            }
            4 => {
                self.depth += 1;
                let mut items = Vec::with_capacity(n.min(1024) as usize);
                let mut err: Option<Error> = None;
                for _ in 0..n {
                    match self.decode() {
                        Ok(v) => items.push(v),
                        Err(e) => {
                            err = Some(e);
                            break;
                        }
                    }
                }
                self.depth -= 1;
                if let Some(e) = err {
                    return Err(e);
                }
                Ok(Value::Array(items))
            }
            5 => {
                self.depth += 1;
                let r = self.decode_map(n);
                self.depth -= 1;
                r
            }
            6 => {
                self.depth += 1;
                let r = self.decode_tag(n);
                self.depth -= 1;
                r
            }
            _ => Err(Error::new("unknown-major", format!("unknown major type {major}"))),
        }
    }
}

/// Strictly decode deterministic CBOR. Rejects non-canonical encodings.
///
/// The input size is capped at [`MAX_INPUT_BYTES`]: every allocation below is
/// bounded by the input, so this bounds memory on hostile input.
pub fn loads(data: &[u8]) -> Result<Value> {
    if data.len() > MAX_INPUT_BYTES {
        return Err(Error::new(
            "input-too-large",
            format!("CBOR input exceeds limit of {MAX_INPUT_BYTES} bytes"),
        ));
    }
    let mut reader = Reader { data, pos: 0, depth: 0 };
    let value = reader.decode()?;
    if reader.pos != data.len() {
        return Err(Error::new("trailing-bytes", "trailing bytes after CBOR item"));
    }
    Ok(value)
}

// ---------------------------------------------------------------------------
// Convenience accessors for the verifier layers
// ---------------------------------------------------------------------------

impl Value {
    pub fn as_int(&self) -> Option<i128> {
        match self {
            Value::Int(Integer::Small(n)) => Some(*n),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_map(&self) -> Option<&[(Value, Value)]> {
        match self {
            Value::Map(m) => Some(m),
            _ => None,
        }
    }

    /// Look up a text key in a map value.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.as_map()?.iter().find_map(|(k, v)| {
            if k.as_text() == Some(key) {
                Some(v)
            } else {
                None
            }
        })
    }
}
