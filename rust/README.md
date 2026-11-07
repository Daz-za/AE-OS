# aeos-verify

A verifier for [AE-OS action records](../spec/action-records-v1.md), written in Rust and sharing no code with the Python library, so an auditor gets a second implementation's answer. Part of [AE-OS](https://ae-os.org).

An auditor who receives evidence from an organization's AI agents can check it with this tool alone. It reads action records, consistency proofs and audit trail directories produced by the Python library in [`python/`](../python/) or any other implementation of the format, and reports problems in the same words as the Python verifier.

It only verifies. Creating logs and signing checkpoints stays with the log operator.

## Build

```
cd rust
cargo build --release          # the binary is target/release/aeos-verify
```

Requires Rust 1.88 or later.

## Check evidence

```
aeos-verify action-record record.json --public-key <hex>   # one action record is verified (old name: receipt)
aeos-verify consistency proof.json --public-key <hex>      # the audit trail only grew since a kept checkpoint
aeos-verify log ./ap-log --public-key <hex>                # recompute and check a whole audit trail
aeos-verify digest invoice-args.json                       # SHA-256 to compare with args_sha256
```

`--public-key` takes the log's Ed25519 public key as hex, a file holding the hex, or a `log.json` file. Take the key from a source you trust, such as the organization's published key or your own record of it, rather than from the files under review. When checking a whole log, a `log.json` that names a different key is reported as a problem.

The exit status is 0 when the evidence is valid, 1 when it is invalid, and 2 for a usage or input error, so the tool fits into scripts and CI jobs.

`digest` computes the canonical JSON digest used for tool arguments and results (spec section 5.3). It accepts only whole numbers and rejects JSON that contains fractional numbers.

## Use it as a library

The library crate and the command-line binary are both called `aeos-verify`.

```rust
use aeos_verify::verify_action_record;

let public_key: Vec<u8> = /* the log's 32-byte Ed25519 public key */;
let record: serde_json::Value = serde_json::from_str(&std::fs::read_to_string("record.json")?)?;
let problems = verify_action_record(&record, &public_key);
assert!(problems.is_empty(), "{problems:?}");
```

## Shared test vectors

Both implementations test against the shared vectors in [`testvectors/action-records-v1.json`](../testvectors/), which the Python reference implementation generates. The Rust tests require the same CIDs, Merkle roots and proofs, and the same list of problems for every tampered action record, consistency proof and audit trail in that file. They also verify the frozen version 0 file, `receipts-v0.json`. CI runs both on every pull request.
