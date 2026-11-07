# Test vectors

`action-records-v1.json` holds the shared test vectors for [AE-OS action records v1](../spec/action-records-v1.md). Every implementation of the format tests against this file:

| Section | Contents |
|---|---|
| `cbor` | Values with their canonical DAG-CBOR bytes, readable view and CID |
| `cbor_reject` | Inputs a decoder must refuse, such as unsorted map keys, floats and trailing bytes |
| `canonical_json` | JSON values with their canonical form and SHA-256 digest |
| `merkle` | Leaf hashes, roots for each tree size, and every inclusion and consistency proof up to size 12 |
| `action_records` | Valid and tampered action records with their Receipts and issuer signatures, with the problems a verifier must report and whether the record is `issuer-signed` or `log-signed only` |
| `consistency` | Valid and tampered consistency proofs, with the expected problems |
| `logs` | A small invoice-approval log and tampered copies, with the expected verification report |

The file is generated from the Python reference implementation:

```
pip install -e python
python testvectors/generate.py            # rewrite action-records-v1.json
python testvectors/generate.py --check    # confirm the file is up to date
```

The Python tests run the check, so a change to the format or to the verifier's messages must come with regenerated vectors. The Rust tests in [`rust/tests/vectors.rs`](../rust/tests/vectors.rs) then show whether the Rust verifier still agrees, and [`verify.test.mjs`](../python/src/aeos/ui/verify.test.mjs) does the same for the browser verifier.

`receipts-v0.json` is the version 0 file (section `receipts` holds `aeos-receipt/v0` documents). It is frozen: nothing regenerates it, and every implementation keeps verifying it, which is how old files are known to still work. Everything except the document type is identical between the two files.

The log is signed with a public test key derived from a fixed phrase in `generate.py`. Never use it for a real log.
