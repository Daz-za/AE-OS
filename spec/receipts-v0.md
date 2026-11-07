# AE-OS Receipts, version 0

This was the first draft of the format now specified in [action-records-v1.md](action-records-v1.md). The bytes it defines (records, CIDs, Merkle tree, checkpoints, audit trail directories) are unchanged. Version 1 renames "receipt" to "action record" and aligns the terms with IETF SCITT (RFC 9943, RFC 9942).

What version 0 documents still look like, so that old files stay readable:

- An export document has `type: "aeos-receipt/v0"` and the same fields and checks as `aeos-action-record/v1`. Verifiers accept both.
- The audit trail directory `format` is `aeos-receipts/v0`, and checkpoints are signed under the context `aeos-receipts/checkpoint/v0\n`. Both are unchanged in version 1.
- `testvectors/receipts-v0.json` holds the version 0 test vectors. It is frozen, and every implementation still verifies it.
