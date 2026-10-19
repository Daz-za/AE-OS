//! Checkpoints, receipts, consistency proofs and full log verification (spec sections 3-4).
//!
//! Every check returns a list of problems in the same words as the Python reference
//! implementation; an empty list means valid.

use crate::canon::{
    cid_of_bytes, cid_str, dag_cbor, decode_dag_cbor, hex, sha256, to_view, unhex, Value,
};
use crate::merkle::{self, Hash};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::Value as Json;
use std::collections::HashSet;

pub const FORMAT: &str = "aeos-receipts/v0";
pub const CHECKPOINT_CONTEXT: &[u8] = b"aeos-receipts/checkpoint/v0\n";

/// Short identifier for a public key: first 16 hex digits of its SHA-256.
pub fn key_id(public_key: &[u8]) -> String {
    hex(&sha256(public_key))[..16].to_string()
}

pub fn verify_signature(public_key: &[u8], signature: &[u8], message: &[u8]) -> bool {
    let Ok(pk) = <[u8; 32]>::try_from(public_key) else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(&pk) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(signature) else {
        return false;
    };
    vk.verify(message, &sig).is_ok()
}

fn unb64(s: &str) -> Result<Vec<u8>, String> {
    STANDARD.decode(s).map_err(|e| e.to_string())
}

fn field<'a>(d: &'a Json, k: &str) -> Result<&'a Json, String> {
    d.get(k).ok_or_else(|| format!("missing field '{k}'"))
}

fn text(d: &Json, k: &str) -> Result<String, String> {
    field(d, k)?
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| format!("field '{k}' must be text"))
}

fn uint(d: &Json, k: &str) -> Result<u64, String> {
    field(d, k)?
        .as_u64()
        .ok_or_else(|| format!("field '{k}' must be a non-negative integer"))
}

fn hex_list(d: &Json, k: &str) -> Result<Vec<Vec<u8>>, String> {
    field(d, k)?
        .as_array()
        .ok_or_else(|| format!("field '{k}' must be a list"))?
        .iter()
        .map(|h| {
            h.as_str()
                .ok_or_else(|| format!("field '{k}' must hold hex strings"))
                .and_then(|s| unhex(s).map_err(|e| e.to_string()))
        })
        .collect()
}

/// A log operator's signed statement of the log's size and Merkle root at a moment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub log_id: String,
    pub size: u64,
    pub root: Vec<u8>,
    pub ts: i64,
    pub key_id: String,
    pub sig: Vec<u8>,
}

impl Checkpoint {
    pub fn from_json(d: &Json) -> Result<Self, String> {
        Ok(Checkpoint {
            log_id: text(d, "log")?,
            size: uint(d, "size")?,
            root: unhex(&text(d, "root")?).map_err(|e| e.to_string())?,
            ts: field(d, "ts")?
                .as_i64()
                .ok_or("field 'ts' must be an integer")?,
            key_id: text(d, "key_id")?,
            sig: unb64(&text(d, "sig")?)?,
        })
    }

    /// The signed message: context string, then DAG-CBOR of {log, size, root, ts}.
    pub fn message(&self) -> Vec<u8> {
        let body = Value::Map(vec![
            ("log".into(), Value::Text(self.log_id.clone())),
            ("size".into(), Value::Int(self.size as i128)),
            ("root".into(), Value::Bytes(self.root.clone())),
            ("ts".into(), Value::Int(self.ts as i128)),
        ]);
        let mut m = CHECKPOINT_CONTEXT.to_vec();
        m.extend(dag_cbor(&body));
        m
    }

    pub fn verify(&self, public_key: &[u8]) -> bool {
        self.key_id == key_id(public_key)
            && verify_signature(public_key, &self.sig, &self.message())
    }
}

/// Check an `aeos-receipt/v0` document offline against a trusted public key.
pub fn verify_receipt(receipt: &Json, public_key: &[u8]) -> Vec<String> {
    if receipt.get("type").and_then(Json::as_str) != Some("aeos-receipt/v0") {
        return vec!["not an aeos-receipt/v0 document".into()];
    }
    let parsed = (|| -> Result<_, String> {
        Ok((
            Checkpoint::from_json(field(receipt, "checkpoint")?)?,
            unb64(&text(receipt, "record")?)?,
            uint(receipt, "index")?,
            hex_list(receipt, "inclusion_proof")?,
        ))
    })();
    let (cp, raw, index, proof) = match parsed {
        Ok(x) => x,
        Err(e) => return vec![format!("malformed receipt: {e}")],
    };
    let mut problems = Vec::new();
    if Some(cp.log_id.as_str()) != receipt.get("log_id").and_then(Json::as_str) {
        problems.push("checkpoint belongs to a different log".into());
    }
    if !cp.verify(public_key) {
        problems.push("checkpoint signature does not verify with the given public key".into());
    }
    if let Err(e) = decode_dag_cbor(&raw) {
        problems.push(format!("record bytes are not canonical: {e}"));
    }
    let cid = cid_of_bytes(&raw);
    if Some(cid_str(&cid).as_str()) != receipt.get("cid").and_then(Json::as_str) {
        problems.push("record CID does not match the record bytes".into());
    }
    if !merkle::verify_inclusion(&merkle::leaf_hash(&cid), index, cp.size, &proof, &cp.root) {
        problems.push("inclusion proof does not lead to the checkpoint root".into());
    }
    problems
}

/// Check that a newer checkpoint extends an older one (nothing rewritten or removed).
pub fn verify_consistency_doc(doc: &Json, public_key: &[u8]) -> Vec<String> {
    let parsed = (|| -> Result<_, String> {
        Ok((
            Checkpoint::from_json(field(doc, "old")?)?,
            Checkpoint::from_json(field(doc, "new")?)?,
            hex_list(doc, "proof")?,
        ))
    })();
    let (old, new, proof) = match parsed {
        Ok(x) => x,
        Err(e) => return vec![format!("malformed consistency proof: {e}")],
    };
    let mut problems = Vec::new();
    if old.log_id != new.log_id {
        problems.push("checkpoints belong to different logs".into());
    }
    for (name, cp) in [("old", &old), ("new", &new)] {
        if !cp.verify(public_key) {
            problems.push(format!("{name} checkpoint signature does not verify"));
        }
    }
    if !merkle::verify_consistency(old.size, new.size, &proof, &old.root, &new.root) {
        problems.push("the newer checkpoint does not extend the older one".into());
    }
    problems
}

/// The text of a log directory's files (spec section 6).
pub struct LogFiles<'a> {
    pub log_json: &'a str,
    pub records: &'a str,
    pub checkpoints: &'a str,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct VerifyReport {
    pub log_id: String,
    pub records: usize,
    pub checkpoints: usize,
    pub problems: Vec<String>,
}

impl VerifyReport {
    pub fn ok(&self) -> bool {
        self.problems.is_empty()
    }
}

fn lines(s: &str) -> impl Iterator<Item = &str> {
    s.split_inclusive('\n')
}

/// Recompute everything from a log's files: record bytes, CIDs, causal links, readable
/// views, and every checkpoint's signature and root.
///
/// `public_key` is the key the verifier trusts. If log.json names a different key, that
/// is reported, and checkpoints are checked against the trusted key.
pub fn verify_log(files: &LogFiles, public_key: &[u8]) -> VerifyReport {
    let mut rep = VerifyReport::default();
    match serde_json::from_str::<Json>(files.log_json) {
        Ok(meta) => {
            if meta.get("format").and_then(Json::as_str) != Some(FORMAT) {
                rep.problems.push(format!(
                    "log.json: unsupported log format {}",
                    meta.get("format").unwrap_or(&Json::Null)
                ));
            }
            rep.log_id = meta
                .get("log_id")
                .and_then(Json::as_str)
                .unwrap_or_default()
                .to_string();
            if meta
                .get("public_key")
                .and_then(Json::as_str)
                .map(|s| s.to_ascii_lowercase())
                != Some(hex(public_key))
            {
                rep.problems
                    .push("log.json names a different public key than the trusted one".into());
            }
        }
        Err(e) => rep.problems.push(format!("log.json: unreadable ({e})")),
    }

    let mut leaves: Vec<Hash> = Vec::new();
    let mut seen: HashSet<Vec<u8>> = HashSet::new();
    for (n, line) in lines(files.records).enumerate() {
        rep.records += 1;
        let parsed = (|| -> Result<_, String> {
            let d: Json = serde_json::from_str(line).map_err(|e| e.to_string())?;
            let raw = unb64(&text(&d, "cbor")?)?;
            let rec = decode_dag_cbor(&raw).map_err(|e| e.to_string())?;
            Ok((d, raw, rec))
        })();
        let (d, raw, rec) = match parsed {
            Ok(x) => x,
            Err(e) => {
                rep.problems
                    .push(format!("line {}: unreadable record ({e})", n + 1));
                leaves.push([0u8; 32]);
                continue;
            }
        };
        let cid = cid_of_bytes(&raw);
        let i = d.get("i").cloned().unwrap_or(Json::Null);
        if i.as_u64() != Some(n as u64) {
            let shown = if i.is_null() {
                "None".to_string()
            } else {
                i.to_string()
            };
            rep.problems
                .push(format!("line {}: index {shown} out of sequence", n + 1));
        }
        if d.get("cid").and_then(Json::as_str) != Some(cid_str(&cid).as_str()) {
            rep.problems
                .push(format!("record {n}: stored CID does not match its bytes"));
        }
        if to_view(&rec).ok().as_ref() != d.get("view") {
            rep.problems.push(format!(
                "record {n}: readable view differs from signed bytes"
            ));
        }
        if let Some(Value::Array(parents)) = rec.get("parents") {
            for p in parents {
                let known = matches!(p, Value::Link(c) if seen.contains(c));
                if !known {
                    rep.problems
                        .push(format!("record {n}: parent is missing or later in the log"));
                }
            }
        }
        seen.insert(cid.clone());
        leaves.push(merkle::leaf_hash(&cid));
    }

    let mut prev: Option<u64> = None;
    for (n, line) in lines(files.checkpoints).enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        rep.checkpoints += 1;
        let cp = match serde_json::from_str::<Json>(line)
            .map_err(|e| e.to_string())
            .and_then(|d| Checkpoint::from_json(&d))
        {
            Ok(cp) => cp,
            Err(e) => {
                rep.problems.push(format!(
                    "checkpoints line {}: unreadable checkpoint ({e})",
                    n + 1
                ));
                continue;
            }
        };
        let label = format!("checkpoint size {}", cp.size);
        if cp.log_id != rep.log_id {
            rep.problems
                .push(format!("{label}: belongs to a different log"));
        }
        if !cp.verify(public_key) {
            rep.problems
                .push(format!("{label}: signature does not verify"));
        }
        if cp.size > leaves.len() as u64 {
            rep.problems
                .push(format!("{label}: covers more records than the log holds"));
        } else if merkle::root(&leaves[..cp.size as usize]).as_slice() != cp.root.as_slice() {
            rep.problems.push(format!(
                "{label}: root does not match the records (records were changed, removed or reordered)"
            ));
        }
        if let Some(p) = prev {
            if cp.size < p {
                rep.problems
                    .push(format!("{label}: smaller than the checkpoint before it"));
            }
        }
        prev = Some(cp.size);
    }
    rep
}
