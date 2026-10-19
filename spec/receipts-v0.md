# AE-OS Receipts, version 0 (draft)

Status: draft for comment, 2026-10-14. Author: Darren Lentz. Licensed under Apache 2.0 with the rest of this repository.

## Purpose

An organization that lets AI agents act in its systems needs evidence of what each agent did, on whose authority, and under which policy decision. That evidence must hold up when someone outside the organization checks it, such as an external auditor, a regulator or a counterparty.

AE-OS Receipts defines:

1. a **record** for each agent action, with a content address (CID);
2. an append-only **log** of records, organized as an RFC 9162 Merkle tree;
3. signed **checkpoints** that commit to the whole log at a point in time;
4. a **receipt** that proves one record is in the log, checkable with nothing but the receipt and the log's public key;
5. a **consistency proof** that shows a later checkpoint extends an earlier one, so records cannot be removed or rewritten after the fact without detection.

The design follows Certificate Transparency (RFC 6962 and RFC 9162), which uses the same structure to make certificate issuance publicly auditable.

## 1. Records

A record is a map encoded as deterministic DAG-CBOR (section 5). Version 0 records have these fields:

| Field | Type | Meaning |
|---|---|---|
| `v` | integer | Record format version, `0` |
| `kind` | text | What happened (table below). Custom kinds start with `x-` |
| `agent` | text | Identity of the acting agent as a URI, ideally a SPIFFE ID |
| `obo` | text or null | The person or organization the agent acted for |
| `subject` | text or null | What the action was applied to, for example a tool name |
| `body` | map | Facts about the action: digests, decision, reasons, amounts |
| `parents` | list of links | CIDs of the records that caused this one |
| `ts` | integer | Time the record was made, in milliseconds since the Unix epoch |

Record kinds:

| Kind | Written when | Typical body |
|---|---|---|
| `session.start` | An agent session begins | `allow_list` |
| `tool.call` | An agent asks to use a tool | `args_sha256`, `rpc_id` |
| `tool.result` | The tool answers | `outcome` (`ok`, `error`, `rpc-error`), `result_sha256` |
| `policy.decision` | A policy allows, denies or escalates an action | `decision`, `reasons` |
| `approval` | A person approves or rejects an escalated action | `decision`, `approver` |
| `note` | Anything else worth recording | free form |
| `session.end` | The session ends | `unanswered_calls` |

Numbers in a record are integers. Amounts are stored in minor currency units (cents), which keeps the encoding exact.

**Digests instead of content.** By default a record holds the SHA-256 digest of a tool's arguments and result, computed over their canonical JSON form (section 5.3). Anyone holding the original arguments can recompute the digest and confirm they match the record. The full content can be kept beside the log, but it stays outside the signed structure so it can be deleted under a retention policy without breaking any proof.

Known limitation: a digest of a short, guessable value (such as `{"approve": true}`) can be confirmed by guessing. Version 1 will add salted commitments for operators who need to hide low-entropy arguments.

**CID.** The record's identifier is a CIDv1 with codec `dag-cbor` (0x71) and a SHA-256 multihash: the bytes `01 71 12 20` followed by SHA-256 of the record's canonical encoding. Its text form is multibase base32 lower case (prefix `b`).

**Parents.** A record may only name parents that already appear earlier in the same log. Records therefore form a causal graph inside the log: a `tool.result` points to its `tool.call`, which points to the `session.start`.

## 2. The log

The log is a sequence of records. Leaf *i* of the Merkle tree is the binary CID of record *i*:

```
leaf_hash(i) = SHA-256(0x00 || CID_i)
node_hash    = SHA-256(0x01 || left || right)
```

The tree shape and the root (the Merkle tree hash) are exactly those of RFC 9162 section 2.1.1. The root of an empty log is SHA-256 of the empty string. Appending the same record twice is a no-op, because the same bytes give the same CID.

## 3. Checkpoints

A checkpoint is the log operator's signed statement of the log's size and root at a moment:

```
message = "aeos-receipts/checkpoint/v0\n" || DAG-CBOR({"log": log_id, "size": n, "root": root, "ts": ts})
sig     = Ed25519(signing_key, message)
```

`key_id` is the first 16 hex digits of SHA-256 of the 32-byte Ed25519 public key. Verifiers must obtain the public key through a channel they trust (for example the organization's published key, or an auditor's own record of it). A key embedded in the document being checked is no evidence of anything.

Each checkpoint must be at least as large as the one before it.

## 4. Proofs

### 4.1 Receipt

A receipt (`type: "aeos-receipt/v0"`) is a JSON document holding the record bytes (base64), the record's index and CID, an RFC 9162 inclusion proof (hex list) and a checkpoint that covers the record.

To verify a receipt with a trusted public key:

1. Check the checkpoint signature and that its `log` equals the receipt's `log_id`.
2. Check the record bytes are canonical DAG-CBOR.
3. Recompute the CID from the bytes and compare it with the receipt's `cid`.
4. Verify the inclusion proof from `leaf_hash(CID)` at `index` to the checkpoint root, using RFC 9162 section 2.1.3.2.

A valid receipt proves that this exact record was in the log when the checkpoint was signed. It does not prove the record is true or complete; that depends on the controls around the agent and the log, which is why the log should be written by a component the agent cannot bypass, such as the MCP proxy in this repository.

### 4.2 Consistency proof

A consistency proof (`type: "aeos-consistency/v0"`) holds two checkpoints and an RFC 9162 consistency proof between their sizes. A verifier who kept an earlier checkpoint checks both signatures and then the proof (RFC 9162 section 2.1.4.2). A valid proof shows that the first *m* records are unchanged in the later tree.

Auditors and counterparties should keep the checkpoints they receive. Requesting a consistency proof against a kept checkpoint is what detects a rewritten history.

### 4.3 Full log verification

Anyone with read access to the log directory can recompute every CID, check every causal link points backwards, check each record's readable view matches its signed bytes, and check every checkpoint's signature and root against the records.

## 5. Encodings

### 5.1 DAG-CBOR subset

Records use deterministic CBOR (RFC 8949 section 4.2.1) restricted to: null, booleans, integers, byte strings, text strings, arrays, maps with text keys, and tag 42 links. Map keys are sorted by encoded length, then bytewise. Floating-point values are not allowed. Decoders must reject any input that is not the canonical encoding of the value it decodes to.

### 5.2 Links

A link is CBOR tag 42 over a byte string of `0x00` followed by the binary CID.

### 5.3 Canonical JSON for digests

Tool arguments and results are JSON. Their digest is SHA-256 over the RFC 8785 (JCS) serialization: object keys sorted by UTF-16 code units, no insignificant whitespace, integral numbers written without a fraction. The Python implementation follows JCS for all values except unusual non-integral floats, where it uses the shortest round-trip form.

## 6. Log directory layout (reference implementation)

```
log.json            {"format": "aeos-receipts/v0", "log_id", "public_key", "key_id", "created"}
records.jsonl       {"i", "cid", "cbor" (base64), "view" (readable JSON, not signed)}
checkpoints.jsonl   {"log", "size", "root" (hex), "ts", "key_id", "sig" (base64)}
signing.key         Ed25519 private key, PKCS#8 PEM (keep elsewhere in production)
content/<cid>.json  optional full arguments and results
```

## 7. Test vectors

`testvectors/receipts-v0.json` holds test vectors for every part of this format: canonical encodings, CIDs, Merkle roots and proofs, and valid and tampered receipts, consistency proofs and logs with the problems a verifier reports for each. The Python and Rust implementations in this repository both test against it. A change to this specification needs matching vectors.

## 8. Planned for later versions

- Salted commitments for arguments and results.
- Independent witnesses that co-sign checkpoints, and C2SP signed-note checkpoint format.
- Agent identity bound to a SPIFFE SVID presented at session start, and delegation from a person's digital identity wallet.
- Hardware or cloud KMS keys for checkpoint signing.
