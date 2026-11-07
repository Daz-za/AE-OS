//! Check this implementation against the shared test vectors in
//! testvectors/action-records-v1.json, which come from the Python reference implementation,
//! and against the frozen version 0 file testvectors/receipts-v0.json.

use aeos_verify::canon::{
    canonical_json, cid_of_bytes, cid_parse, cid_str, dag_cbor, decode_dag_cbor, hex, json_digest,
    to_view, unhex,
};
use aeos_verify::merkle::{self, Hash};
use aeos_verify::verify::key_id;
use aeos_verify::{
    before_pending, verify_action_record, verify_action_record_detail, verify_consistency_doc,
    verify_log, LogFiles,
};
use serde_json::Value as Json;
use std::sync::OnceLock;

fn vectors() -> &'static Json {
    static V: OnceLock<Json> = OnceLock::new();
    V.get_or_init(|| {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../testvectors/action-records-v1.json"
        );
        serde_json::from_str(&std::fs::read_to_string(path).expect("read test vectors")).unwrap()
    })
}

/// The frozen version 0 vectors, whose documents have type `aeos-receipt/v0`.
fn vectors_v0() -> &'static Json {
    static V: OnceLock<Json> = OnceLock::new();
    V.get_or_init(|| {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../testvectors/receipts-v0.json"
        );
        serde_json::from_str(&std::fs::read_to_string(path).expect("read v0 vectors")).unwrap()
    })
}

fn cases(name: &str) -> &'static Vec<Json> {
    vectors()[name].as_array().unwrap()
}

fn s(v: &Json) -> &str {
    v.as_str().unwrap()
}

fn bytes(v: &Json) -> Vec<u8> {
    unhex(s(v)).unwrap()
}

fn hash(v: &Json) -> Hash {
    bytes(v).try_into().unwrap()
}

fn hashes(v: &Json) -> Vec<Vec<u8>> {
    v.as_array().unwrap().iter().map(bytes).collect()
}

fn problems(v: &Json) -> Vec<String> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|p| s(p).to_string())
        .collect()
}

#[test]
fn test_key_id() {
    let k = &vectors()["test_key"];
    assert_eq!(key_id(&bytes(&k["public_key"])), s(&k["key_id"]));
}

#[test]
fn cbor_round_trips_and_cids() {
    for c in cases("cbor") {
        let name = s(&c["name"]);
        let enc = bytes(&c["cbor"]);
        let v = decode_dag_cbor(&enc).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(dag_cbor(&v), enc, "{name}");
        assert_eq!(&to_view(&v).unwrap(), &c["view"], "{name}");
        let cid = cid_of_bytes(&enc);
        assert_eq!(cid_str(&cid), s(&c["cid"]), "{name}");
        assert_eq!(cid_parse(s(&c["cid"])).unwrap(), cid, "{name}");
    }
}

#[test]
fn cbor_rejects_non_canonical_input() {
    for c in cases("cbor_reject") {
        assert!(
            decode_dag_cbor(&bytes(&c["cbor"])).is_err(),
            "accepted {}",
            s(&c["name"])
        );
    }
}

#[test]
fn canonical_json_digests() {
    for c in cases("canonical_json") {
        assert_eq!(canonical_json(&c["value"]).unwrap(), s(&c["canonical"]));
        assert_eq!(hex(&json_digest(&c["value"]).unwrap()), s(&c["sha256"]));
    }
}

#[test]
fn merkle_roots_and_proofs() {
    let m = &vectors()["merkle"];
    let leaves: Vec<Hash> = m["leaves"].as_array().unwrap().iter().map(hash).collect();
    for (i, l) in leaves.iter().enumerate() {
        assert_eq!(*l, merkle::leaf_hash(&[i as u8]));
    }
    let roots: Vec<Hash> = m["roots"].as_array().unwrap().iter().map(hash).collect();
    for (n, r) in roots.iter().enumerate() {
        assert_eq!(merkle::root(&leaves[..n]), *r, "root of size {n}");
    }
    for c in m["inclusion"].as_array().unwrap() {
        let (i, n) = (c["index"].as_u64().unwrap(), c["size"].as_u64().unwrap());
        let proof = hashes(&c["proof"]);
        let leaf = &leaves[i as usize];
        let root = &roots[n as usize];
        assert!(
            merkle::verify_inclusion(leaf, i, n, &proof, root),
            "inclusion {i} of {n}"
        );
        if n > 1 {
            assert!(
                !merkle::verify_inclusion(leaf, (i + 1) % n, n, &proof, root),
                "moved {i} of {n}"
            );
            assert!(!merkle::verify_inclusion(
                &leaves[(i as usize + 1) % n as usize],
                i,
                n,
                &proof,
                root
            ));
            assert!(
                !merkle::verify_inclusion(leaf, i, n, &proof[1..], root),
                "short {i} of {n}"
            );
        }
        let mut long = proof.clone();
        long.push(vec![0; 32]);
        assert!(
            !merkle::verify_inclusion(leaf, i, n, &long, root),
            "long {i} of {n}"
        );
    }
    for c in m["consistency"].as_array().unwrap() {
        let (o, n) = (
            c["old_size"].as_u64().unwrap(),
            c["new_size"].as_u64().unwrap(),
        );
        let proof = hashes(&c["proof"]);
        let (ro, rn) = (&roots[o as usize], &roots[n as usize]);
        assert!(
            merkle::verify_consistency(o, n, &proof, ro, rn),
            "consistency {o} to {n}"
        );
        assert!(
            !merkle::verify_consistency(o, n, &proof, rn, ro) || ro == rn,
            "swapped {o} to {n}"
        );
        for k in 0..proof.len() {
            let mut bad = proof.clone();
            bad[k][0] ^= 1;
            assert!(
                !merkle::verify_consistency(o, n, &bad, ro, rn),
                "altered {o} to {n} at {k}"
            );
        }
    }
}

#[test]
fn action_records_match_reference_problems() {
    for c in cases("action_records") {
        let (got, state) =
            verify_action_record_detail(&c["action_record"], &bytes(&c["public_key"]));
        assert_eq!(got, problems(&c["expect_problems"]), "{}", s(&c["name"]));
        assert_eq!(
            state.as_str(),
            s(&c["expect_signature"]),
            "{}",
            s(&c["name"])
        );
    }
}

#[test]
fn issuer_signature_cases_are_present() {
    let names: Vec<&str> = cases("action_records")
        .iter()
        .map(|c| s(&c["name"]))
        .collect();
    for want in [
        "no issuer signature (log-signed only)",
        "issuer signature altered",
        "issuer signature made by a different key under the right key id",
    ] {
        assert!(names.contains(&want), "{want}");
    }
}

#[test]
fn version_0_receipts_in_the_frozen_vectors_still_verify() {
    const OLD_WRONG_TYPE: &str = "not an aeos-receipt/v0 document";
    const NEW_WRONG_TYPE: &str = "not an aeos-action-record/v1 document (or aeos-receipt/v0)";
    let v0 = vectors_v0();
    let all = v0["receipts"].as_array().unwrap();
    assert_eq!(s(&all[0]["receipt"]["type"]), "aeos-receipt/v0");
    for c in all {
        let expected: Vec<String> = problems(&c["expect_problems"])
            .into_iter()
            .map(|p| {
                if p == OLD_WRONG_TYPE {
                    NEW_WRONG_TYPE.to_string()
                } else {
                    p
                }
            })
            .collect();
        let (got, state) = verify_action_record_detail(&c["receipt"], &bytes(&c["public_key"]));
        assert_eq!(got, expected, "{}", s(&c["name"]));
        assert_eq!(state.as_str(), "log-signed only", "{}", s(&c["name"]));
    }
    let first = &all[0];
    assert!(verify_action_record(&first["receipt"], &bytes(&first["public_key"])).is_empty());
}

#[test]
fn version_0_logs_and_consistency_proofs_in_the_frozen_vectors_still_verify() {
    let v0 = vectors_v0();
    for c in v0["consistency"].as_array().unwrap() {
        let got = verify_consistency_doc(&c["proof"], &bytes(&c["public_key"]));
        assert_eq!(got, problems(&c["expect_problems"]), "{}", s(&c["name"]));
    }
    let logs = &v0["logs"];
    let key = bytes(&logs["public_key"]);
    for c in logs["cases"].as_array().unwrap() {
        let rep = verify_log(
            &LogFiles {
                log_json: s(&logs["log_json"]),
                records: s(&c["records"]),
                checkpoints: s(&c["checkpoints"]),
            },
            &key,
        );
        assert_eq!(
            rep.problems,
            problems(&c["expect"]["problems"]),
            "{}",
            s(&c["name"])
        );
    }
}

#[test]
#[allow(deprecated)]
fn deprecated_verify_receipt_still_works() {
    let c = &cases("action_records")[0];
    let doc = &c["action_record"];
    assert!(aeos_verify::verify_receipt(doc, &bytes(&c["public_key"])).is_empty());
}

#[test]
fn consistency_proofs_match_reference_problems() {
    for c in cases("consistency") {
        let got = verify_consistency_doc(&c["proof"], &bytes(&c["public_key"]));
        assert_eq!(got, problems(&c["expect_problems"]), "{}", s(&c["name"]));
    }
}

#[test]
fn logs_match_reference_report() {
    let logs = &vectors()["logs"];
    let key = bytes(&logs["public_key"]);
    for c in logs["cases"].as_array().unwrap() {
        let name = s(&c["name"]);
        let rep = verify_log(
            &LogFiles {
                log_json: s(&logs["log_json"]),
                records: s(&c["records"]),
                checkpoints: s(&c["checkpoints"]),
            },
            &key,
        );
        assert_eq!(rep.problems, problems(&c["expect"]["problems"]), "{name}");
        assert_eq!(
            rep.records as u64,
            c["expect"]["records"].as_u64().unwrap(),
            "{name}"
        );
        assert_eq!(
            rep.checkpoints as u64,
            c["expect"]["checkpoints"].as_u64().unwrap(),
            "{name}"
        );
        assert_eq!(
            rep.issuer_signed as u64,
            c["expect"]["issuer_signed"].as_u64().unwrap(),
            "{name}"
        );
    }
}

#[test]
fn log_with_untrusted_key_is_reported() {
    let logs = &vectors()["logs"];
    let other = bytes(
        &cases("action_records")
            .iter()
            .find(|c| s(&c["name"]) == "wrong public key")
            .unwrap()["public_key"],
    );
    let untouched = &logs["cases"][0];
    let rep = verify_log(
        &LogFiles {
            log_json: s(&logs["log_json"]),
            records: s(&untouched["records"]),
            checkpoints: s(&untouched["checkpoints"]),
        },
        &other,
    );
    assert_eq!(
        rep.problems[0],
        "log.json names a different public key than the trusted one"
    );
    assert!(rep
        .problems
        .iter()
        .any(|p| p.ends_with("signature does not verify")));
}

/// A verifier must report a tampered trail, never crash on it. Each record's bytes are
/// swapped, one at a time, for something that is not a record: other CBOR values, a map with
/// nothing in it, the record cut short, and pseudo-random bytes. Every swap must come back as
/// problems, and so must lines that are not JSON objects at all.
#[test]
fn a_tampered_trail_is_reported_and_never_crashes_the_verifier() {
    use aeos_verify::canon::Value;
    use base64::{engine::general_purpose::STANDARD, Engine};

    let logs = &vectors()["logs"];
    let key = bytes(&logs["public_key"]);
    let log_json = s(&logs["log_json"]);
    let base = logs["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "untouched log")
        .unwrap();
    let records_text = s(&base["records"]);
    let records: Vec<&str> = records_text.lines().collect();
    let checkpoints = s(&base["checkpoints"]);

    let mut seed = 0x2545_f491_4f6c_dd1du64;
    let mut random = |n: usize| -> Vec<u8> {
        (0..n)
            .map(|_| {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                seed as u8
            })
            .collect()
    };

    let deep = {
        let mut v = vec![0x81u8; 300];
        v.push(0x00);
        v
    };
    for i in 0..records.len() {
        let original = unb64_cbor(records[i]);
        let swaps: Vec<Vec<u8>> = vec![
            dag_cbor(&Value::Array(vec![])),
            dag_cbor(&Value::Int(0)),
            dag_cbor(&Value::Text("x".into())),
            dag_cbor(&Value::Map(vec![])),
            original[..original.len() / 2].to_vec(),
            original[..original.len() - 1].to_vec(),
            Vec::new(),
            deep.clone(),
            random(1),
            random(40),
            random(400),
        ];
        for (n, bytes) in swaps.iter().enumerate() {
            let mut line: Json = serde_json::from_str(records[i]).unwrap();
            line["cbor"] = Json::String(STANDARD.encode(bytes));
            let mut lines: Vec<String> = records.iter().map(|l| l.to_string()).collect();
            lines[i] = line.to_string();
            let rep = verify_log(
                &LogFiles {
                    log_json,
                    records: &(lines.join("\n") + "\n"),
                    checkpoints,
                },
                &key,
            );
            assert!(!rep.problems.is_empty(), "record {i}, swap {n}");
        }
        for text in [
            "[]",
            "0",
            "\"x\"",
            "null",
            "{}",
            "{\"cbor\":5}",
            "\u{0}",
            "{",
        ] {
            let mut lines: Vec<String> = records.iter().map(|l| l.to_string()).collect();
            lines[i] = text.to_string();
            let rep = verify_log(
                &LogFiles {
                    log_json,
                    records: &(lines.join("\n") + "\n"),
                    checkpoints,
                },
                &key,
            );
            assert!(!rep.problems.is_empty(), "record {i}, line {text:?}");
        }
    }

    fn unb64_cbor(line: &str) -> Vec<u8> {
        let d: Json = serde_json::from_str(line).unwrap();
        STANDARD.decode(d["cbor"].as_str().unwrap()).unwrap()
    }
}

/// The passkey approval vectors (spec section 10). This verifier does not check approvals; it
/// does have to read their records, with byte strings and nested batches, as the same
/// canonical DAG-CBOR with the same CIDs the Python implementation wrote.
#[test]
fn passkey_approval_records_decode_canonically_with_the_same_cids() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../testvectors/passkey-approvals-v1.json"
    );
    let doc: Json = serde_json::from_str(&std::fs::read_to_string(path).expect("read")).unwrap();
    let mut records = 0;
    for case in doc["cases"].as_array().unwrap() {
        for r in case["records"].as_array().unwrap() {
            let raw = unhex(s(&r["cbor"])).unwrap();
            let value = decode_dag_cbor(&raw).expect("canonical record");
            assert_eq!(dag_cbor(&value), raw, "{}", s(&case["name"]));
            assert_eq!(
                cid_str(&cid_of_bytes(&raw)),
                s(&r["cid"]),
                "{}",
                s(&case["name"])
            );
            records += 1;
        }
    }
    assert!(records > 400);
}

#[test]
fn an_unfinished_write_is_reported_as_one_not_as_a_damaged_record() {
    let v0 = vectors_v0();
    let logs = &v0["logs"];
    let key = bytes(&logs["public_key"]);
    let clean = logs["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| problems(&c["expect"]["problems"]).is_empty())
        .expect("a clean log case");
    let records = s(&clean["records"]);
    let n = records.matches('\n').count();
    let torn = format!("{records}{{\"i\":{n},\"cid\":\"bafy");
    let files = |records| LogFiles {
        log_json: s(&logs["log_json"]),
        records,
        checkpoints: s(&clean["checkpoints"]),
    };
    let rep = verify_log(&files(&torn), &key);
    assert_eq!(
        rep.problems,
        vec![format!(
            "line {}: an unfinished write, not yet recovered",
            n + 1
        )]
    );
    assert_eq!(rep.records, n);
    // A batch announced in .pending is unfinished even when every byte of it is there.
    let first_line = records.find('\n').unwrap() + 1;
    let pending = format!("{{\"offset\":{first_line},\"length\":1}}");
    let (kept, problem) = before_pending(records, Some(&pending));
    assert_eq!(kept, &records[..first_line]);
    assert_eq!(
        problem.as_deref(),
        Some("line 2 on: an unfinished write, not yet recovered (.pending is present)")
    );
    assert_eq!(before_pending(records, None), (records, None));
    assert_eq!(before_pending(records, Some("not json")), (records, None));
}
