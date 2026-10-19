//! aeos-verify: check AE-OS Receipts evidence offline.

use aeos_verify::canon::{hex, json_digest, unhex};
use aeos_verify::{verify_consistency_doc, verify_log, verify_receipt, LogFiles};
use serde_json::Value as Json;
use std::path::Path;
use std::process::ExitCode;

const USAGE: &str = "\
aeos-verify: check AE-OS Receipts evidence offline

Usage:
  aeos-verify receipt FILE --public-key KEY        check one receipt
  aeos-verify consistency FILE --public-key KEY    check that a log only grew
  aeos-verify log DIR --public-key KEY             recompute and check a whole log
  aeos-verify digest FILE                          SHA-256 of a JSON file's canonical form

KEY is the log's Ed25519 public key as hex, a file holding the hex, or a log.json file.
Take the key from a source you trust, not from the evidence under review.

Exit status: 0 valid, 1 invalid, 2 usage or input error.";

fn read(path: &str) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))
}

fn read_json(path: &str) -> Result<Json, String> {
    serde_json::from_str(&read(path)?).map_err(|e| format!("{path} is not JSON: {e}"))
}

/// Accept a hex key, a file holding one, or a log.json file.
fn public_key(value: &str) -> Result<Vec<u8>, String> {
    let text = if Path::new(value).is_file() {
        read(value)?
    } else {
        value.to_string()
    };
    let text = text.trim();
    let hex_key = if text.starts_with('{') {
        let d: Json = serde_json::from_str(text).map_err(|e| format!("{value}: {e}"))?;
        d.get("public_key")
            .and_then(Json::as_str)
            .ok_or("log.json has no public_key")?
            .to_string()
    } else {
        text.to_string()
    };
    let key = unhex(&hex_key).map_err(|_| "public key must be hex".to_string())?;
    if key.len() != 32 {
        return Err("an Ed25519 public key is 32 bytes (64 hex digits)".into());
    }
    Ok(key)
}

fn report(problems: &[String], ok_message: String) -> ExitCode {
    if problems.is_empty() {
        println!("VALID: {ok_message}");
        return ExitCode::SUCCESS;
    }
    println!("INVALID");
    for p in problems {
        println!("  - {p}");
    }
    ExitCode::from(1)
}

fn run(args: &[String]) -> Result<ExitCode, String> {
    let mut positional = Vec::new();
    let mut key = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(ExitCode::SUCCESS);
            }
            "--version" => {
                println!("aeos-verify {}", env!("CARGO_PKG_VERSION"));
                return Ok(ExitCode::SUCCESS);
            }
            "--public-key" => key = Some(it.next().ok_or("--public-key needs a value")?.clone()),
            s if s.starts_with("--public-key=") => {
                key = Some(s["--public-key=".len()..].to_string())
            }
            s if s.starts_with('-') => return Err(format!("unknown option {s}")),
            s => positional.push(s.to_string()),
        }
    }
    let [cmd, target] = positional.as_slice() else {
        return Err("expected a command and one file or directory".into());
    };
    if cmd == "digest" {
        let digest = json_digest(&read_json(target)?).map_err(|e| e.to_string())?;
        println!("{}", hex(&digest));
        return Ok(ExitCode::SUCCESS);
    }
    let key = public_key(&key.ok_or("--public-key is required")?)?;
    match cmd.as_str() {
        "receipt" => {
            let doc = read_json(target)?;
            let ok = format!(
                "record {} ({}) is in log {} at checkpoint size {}",
                doc["index"],
                doc["cid"].as_str().unwrap_or("?"),
                doc["log_id"].as_str().unwrap_or("?"),
                doc["checkpoint"]["size"]
            );
            Ok(report(&verify_receipt(&doc, &key), ok))
        }
        "consistency" => {
            let doc = read_json(target)?;
            let ok = format!(
                "checkpoint size {} extends checkpoint size {}",
                doc["new"]["size"], doc["old"]["size"]
            );
            Ok(report(&verify_consistency_doc(&doc, &key), ok))
        }
        "log" => {
            let dir = Path::new(target);
            let file = |name: &str| read(&dir.join(name).to_string_lossy());
            let (log_json, records, checkpoints) = (
                file("log.json")?,
                file("records.jsonl")?,
                file("checkpoints.jsonl")?,
            );
            let rep = verify_log(
                &LogFiles {
                    log_json: &log_json,
                    records: &records,
                    checkpoints: &checkpoints,
                },
                &key,
            );
            let ok = format!(
                "{} records and {} signed checkpoints in {}",
                rep.records, rep.checkpoints, rep.log_id
            );
            Ok(report(&rep.problems, ok))
        }
        other => Err(format!("unknown command {other}")),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    }
    match run(&args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("aeos-verify: {e}\n\nRun aeos-verify --help for usage.");
            ExitCode::from(2)
        }
    }
}
