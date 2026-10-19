# Test vectors

`receipts-v0.json` holds the shared test vectors for [AE-OS Receipts v0](../spec/receipts-v0.md). Every implementation of the format tests against this file:

| Section | Contents |
|---|---|
| `cbor` | Values with their canonical DAG-CBOR bytes, readable view and CID |
| `cbor_reject` | Inputs a decoder must refuse, such as unsorted map keys, floats and trailing bytes |
| `canonical_json` | JSON values with their canonical form and SHA-256 digest |
| `merkle` | Leaf hashes, roots for each tree size, and every inclusion and consistency proof up to size 12 |
| `receipts` | Valid and tampered receipts, with the problems a verifier must report |
| `consistency` | Valid and tampered consistency proofs, with the expected problems |
| `logs` | A small invoice-approval log and tampered copies, with the expected verification report |

The file is generated from the Python reference implementation:

```
pip install -e python
python testvectors/generate.py            # rewrite receipts-v0.json
python testvectors/generate.py --check    # confirm the file is up to date
```

The Python tests run the check, so a change to the format or to the verifier's messages must come with regenerated vectors. The Rust tests in [`rust/tests/vectors.rs`](../rust/tests/vectors.rs) then show whether the Rust verifier still agrees.

The log is signed with a public test key derived from a fixed phrase in `generate.py`. Never use it for a real log.
