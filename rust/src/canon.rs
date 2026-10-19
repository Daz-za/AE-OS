//! Canonical encodings: the DAG-CBOR subset used by records, CIDs, and canonical JSON
//! for digests of tool arguments and results (spec section 5).

use serde_json::{Map, Number, Value as Json};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::fmt;

/// A decoded DAG-CBOR value from the subset AE-OS records use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Null,
    Bool(bool),
    /// CBOR integers span -2^64 to 2^64 - 1, so they are held as i128.
    Int(i128),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    /// Map entries in encoded order (length-first, then bytewise).
    Map(Vec<(String, Value)>),
    /// A tag-42 link; holds the binary CID without the leading 0x00.
    Link(Vec<u8>),
}

impl Value {
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Map(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError(pub String);

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DecodeError {}

fn err<T>(msg: &str) -> Result<T, DecodeError> {
    Err(DecodeError(msg.to_string()))
}

// ---------------------------------------------------------------------------------------
// DAG-CBOR encode
// ---------------------------------------------------------------------------------------

fn head(out: &mut Vec<u8>, major: u8, n: u64) {
    let m = major << 5;
    if n < 24 {
        out.push(m | n as u8);
    } else if n < 0x100 {
        out.extend_from_slice(&[m | 24, n as u8]);
    } else if n < 0x1_0000 {
        out.push(m | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n < 0x1_0000_0000 {
        out.push(m | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

fn key_order(a: &str, b: &str) -> Ordering {
    a.len()
        .cmp(&b.len())
        .then_with(|| a.as_bytes().cmp(b.as_bytes()))
}

fn encode_into(v: &Value, out: &mut Vec<u8>) {
    match v {
        Value::Null => out.push(0xf6),
        Value::Bool(true) => out.push(0xf5),
        Value::Bool(false) => out.push(0xf4),
        Value::Int(i) if *i >= 0 => head(out, 0, *i as u64),
        Value::Int(i) => head(out, 1, (-1 - *i) as u64),
        Value::Bytes(b) => {
            head(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        Value::Text(s) => {
            head(out, 3, s.len() as u64);
            out.extend_from_slice(s.as_bytes());
        }
        Value::Array(items) => {
            head(out, 4, items.len() as u64);
            for x in items {
                encode_into(x, out);
            }
        }
        Value::Map(entries) => {
            let mut sorted: Vec<&(String, Value)> = entries.iter().collect();
            sorted.sort_by(|a, b| key_order(&a.0, &b.0));
            head(out, 5, entries.len() as u64);
            for (k, x) in sorted {
                encode_into(&Value::Text(k.clone()), out);
                encode_into(x, out);
            }
        }
        Value::Link(cid) => {
            out.extend_from_slice(&[0xd8, 0x2a]);
            head(out, 2, cid.len() as u64 + 1);
            out.push(0);
            out.extend_from_slice(cid);
        }
    }
}

/// Encode deterministically: shortest-form lengths, map keys length-first then bytewise.
pub fn dag_cbor(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(v, &mut out);
    out
}

// ---------------------------------------------------------------------------------------
// DAG-CBOR decode (same subset; rejects non-canonical input)
// ---------------------------------------------------------------------------------------

struct Reader<'a> {
    data: &'a [u8],
    i: usize,
}

impl Reader<'_> {
    fn take(&mut self, n: usize, what: &str) -> Result<&[u8], DecodeError> {
        if self.data.len() - self.i < n {
            return err(what);
        }
        let s = &self.data[self.i..self.i + n];
        self.i += n;
        Ok(s)
    }

    fn arg(&mut self, info: u8) -> Result<u64, DecodeError> {
        let size = match info {
            0..=23 => return Ok(info as u64),
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            _ => return err("bad length"),
        };
        let b = self.take(size, "bad length")?;
        Ok(b.iter().fold(0u64, |acc, x| (acc << 8) | *x as u64))
    }

    fn value(&mut self, depth: usize) -> Result<Value, DecodeError> {
        if depth > 256 {
            return err("nesting too deep");
        }
        let ib = *self.take(1, "truncated")?.first().unwrap();
        let (major, info) = (ib >> 5, ib & 31);
        if major == 7 {
            return match info {
                20 => Ok(Value::Bool(false)),
                21 => Ok(Value::Bool(true)),
                22 => Ok(Value::Null),
                _ => err("unsupported simple value or float"),
            };
        }
        let n = self.arg(info)?;
        match major {
            0 => Ok(Value::Int(n as i128)),
            1 => Ok(Value::Int(-1 - n as i128)),
            2 | 3 => {
                let len = usize::try_from(n).map_err(|_| DecodeError("truncated string".into()))?;
                let raw = self.take(len, "truncated string")?.to_vec();
                if major == 2 {
                    Ok(Value::Bytes(raw))
                } else {
                    String::from_utf8(raw)
                        .map(Value::Text)
                        .map_err(|_| DecodeError("text is not valid UTF-8".into()))
                }
            }
            4 => {
                let mut out = Vec::new();
                for _ in 0..n {
                    out.push(self.value(depth + 1)?);
                }
                Ok(Value::Array(out))
            }
            5 => {
                let mut out: Vec<(String, Value)> = Vec::new();
                for _ in 0..n {
                    let k = match self.value(depth + 1)? {
                        Value::Text(k) => k,
                        _ => return err("map key must be text"),
                    };
                    if let Some((prev, _)) = out.last() {
                        if key_order(prev, &k) != Ordering::Less {
                            return err("input is not canonical DAG-CBOR");
                        }
                    }
                    let v = self.value(depth + 1)?;
                    out.push((k, v));
                }
                Ok(Value::Map(out))
            }
            6 if n == 42 => match self.value(depth + 1)? {
                Value::Bytes(b) if b.first() == Some(&0) => Ok(Value::Link(b[1..].to_vec())),
                _ => err("bad CID link"),
            },
            _ => Err(DecodeError(format!("unsupported major type {major}"))),
        }
    }
}

/// Decode and check the input is the canonical encoding of the decoded value.
pub fn decode_dag_cbor(data: &[u8]) -> Result<Value, DecodeError> {
    let mut r = Reader { data, i: 0 };
    let v = r.value(0)?;
    if r.i != data.len() {
        return err("trailing bytes");
    }
    if dag_cbor(&v) != data {
        return err("input is not canonical DAG-CBOR");
    }
    Ok(v)
}

// ---------------------------------------------------------------------------------------
// CIDs
// ---------------------------------------------------------------------------------------

/// CIDv1 = version 0x01, codec dag-cbor 0x71, multihash sha2-256 0x12, length 0x20.
pub const CID_PREFIX: [u8; 4] = [0x01, 0x71, 0x12, 0x20];

const BASE32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub fn cid_of_bytes(encoded: &[u8]) -> Vec<u8> {
    let mut cid = CID_PREFIX.to_vec();
    cid.extend_from_slice(&sha256(encoded));
    cid
}

/// Multibase base32 (RFC 4648 lower case, no padding, prefix 'b').
pub fn cid_str(cid: &[u8]) -> String {
    let (mut acc, mut bits, mut out) = (0u32, 0u32, String::from("b"));
    for &byte in cid {
        acc = (acc << 8) | byte as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(BASE32[((acc >> bits) & 31) as usize] as char);
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(BASE32[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

pub fn cid_parse(s: &str) -> Result<Vec<u8>, DecodeError> {
    let rest = s
        .strip_prefix('b')
        .ok_or_else(|| DecodeError("expected base32 CID starting with 'b'".into()))?;
    let (mut acc, mut bits, mut out) = (0u32, 0u32, Vec::new());
    for ch in rest.bytes() {
        let d = BASE32
            .iter()
            .position(|&c| c == ch)
            .ok_or_else(|| DecodeError("invalid base32 character".into()))?;
        acc = (acc << 5) | d as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
        acc &= (1 << bits) - 1;
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------
// Readable view (the "view" field of records.jsonl)
// ---------------------------------------------------------------------------------------

/// Readable JSON view of a decoded record: bytes as {"hex"}, links as {"/": CID}.
pub fn to_view(v: &Value) -> Result<Json, DecodeError> {
    let one = |k: &str, s: String| {
        let mut m = Map::new();
        m.insert(k.to_string(), Json::String(s));
        Json::Object(m)
    };
    Ok(match v {
        Value::Null => Json::Null,
        Value::Bool(b) => Json::Bool(*b),
        Value::Int(i) => {
            if let Ok(u) = u64::try_from(*i) {
                Json::Number(Number::from(u))
            } else if let Ok(s) = i64::try_from(*i) {
                Json::Number(Number::from(s))
            } else {
                return err("integer outside the 64-bit range has no readable view here");
            }
        }
        Value::Bytes(b) => one("hex", hex(b)),
        Value::Text(s) => Json::String(s.clone()),
        Value::Array(items) => Json::Array(items.iter().map(to_view).collect::<Result<_, _>>()?),
        Value::Map(entries) => {
            let mut m = Map::new();
            for (k, x) in entries {
                m.insert(k.clone(), to_view(x)?);
            }
            Json::Object(m)
        }
        Value::Link(cid) => one("/", cid_str(cid)),
    })
}

// ---------------------------------------------------------------------------------------
// Canonical JSON for digests of tool arguments and results
// ---------------------------------------------------------------------------------------

fn json_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn json_into(v: &Json, out: &mut String) -> Result<(), DecodeError> {
    match v {
        Json::Null => out.push_str("null"),
        Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Json::Number(n) => {
            if let Some(u) = n.as_u64() {
                out.push_str(&u.to_string());
            } else if let Some(i) = n.as_i64() {
                out.push_str(&i.to_string());
            } else {
                let x = n.as_f64().unwrap_or(f64::NAN);
                if x.is_finite() && x.fract() == 0.0 && x.abs() < 1e21 {
                    out.push_str(&format!("{x:.0}"));
                } else {
                    return err("non-integral numbers are not supported for digests");
                }
            }
        }
        Json::String(s) => json_string(s, out),
        Json::Array(items) => {
            out.push('[');
            for (i, x) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                json_into(x, out)?;
            }
            out.push(']');
        }
        Json::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                json_string(k, out);
                out.push(':');
                json_into(&m[k], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// Serialize JSON data as RFC 8785 (JCS): keys sorted by UTF-16 code units, no
/// whitespace, integral numbers without a fraction. Non-integral numbers are refused.
pub fn canonical_json(v: &Json) -> Result<String, DecodeError> {
    let mut out = String::new();
    json_into(v, &mut out)?;
    Ok(out)
}

/// SHA-256 over the canonical JSON form, as stored in `args_sha256` and `result_sha256`.
pub fn json_digest(v: &Json) -> Result<[u8; 32], DecodeError> {
    Ok(sha256(canonical_json(v)?.as_bytes()))
}

// ---------------------------------------------------------------------------------------
// Hex
// ---------------------------------------------------------------------------------------

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn unhex(s: &str) -> Result<Vec<u8>, DecodeError> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        return err("invalid hex");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| DecodeError("invalid hex".into()))
        })
        .collect()
}
