//! Check this implementation against the shared test vectors in testvectors/receipts-v0.json,
//! which come from the Python reference implementation.

use aeos_receipts::canon::{
    canonical_json, cid_of_bytes, cid_parse, cid_str, dag_cbor, decode_dag_cbor, hex, json_digest,
    to_view, unhex,
};
use aeos_receipts::merkle::{self, Hash};
use aeos_receipts::verify::key_id;
use aeos_receipts::{verify_consistency_doc, verify_log, verify_receipt, LogFiles};
use serde_json::Value as Json;
use std::sync::OnceLock;

fn vectors() -> &'static Json {
    static V: OnceLock<Json> = OnceLock::new();
    V.get_or_init(|| {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../testvectors/receipts-v0.json"
        );
        serde_json::from_str(&std::fs::read_to_string(path).expect("read test vectors")).unwrap()
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
fn receipts_match_reference_problems() {
    for c in cases("receipts") {
        let got = verify_receipt(&c["receipt"], &bytes(&c["public_key"]));
        assert_eq!(got, problems(&c["expect_problems"]), "{}", s(&c["name"]));
    }
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
    }
}

#[test]
fn log_with_untrusted_key_is_reported() {
    let logs = &vectors()["logs"];
    let other = bytes(
        &cases("receipts")
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
