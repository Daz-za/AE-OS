# AE-OS action records, version 1 (draft)

Status: draft for comment. Author: Darren Lentz. Licensed under Apache 2.0 with the rest of this repository.

## Purpose

An organization that lets AI agents act in its systems needs evidence of what each agent did, on whose authority, and under which policy decision. That evidence must hold up when someone outside the organization checks it, such as an external auditor, a regulator or a counterparty.

This document defines:

1. an **action record** for each agent action, with a content address (CID) and an issuer signature over it. Its standard name is the **action-record statement**: AE-OS's profile of a SCITT Signed Statement;
2. an append-only **audit trail** of action records, organized as an RFC 9162 Merkle tree. Its standard name is the Transparency Service's log;
3. signed **checkpoints** that commit to the whole audit trail at a point in time;
4. a **Receipt** that proves one action record is in the audit trail, checkable with nothing but the Receipt and the audit trail's public key;
5. a **consistency proof** that shows a later checkpoint extends an earlier one, so records cannot be removed or rewritten after the fact without detection.

An action record together with its Receipt is a **Transparent Statement**. When the issuer signature (where present), the checkpoint signature and the inclusion proof all check out, the action record is **verified**.

## Terms

AE-OS uses the vocabulary of the IETF SCITT architecture. Documents say "action record" and "audit trail" to people, and the standard terms where precision matters.

| Say | Standard term | Meaning here |
|---|---|---|
| action record | Signed Statement, profiled as the action-record statement | One recorded fact about what an agent did, as bytes with a CID and the issuer's signature over it |
| audit trail | The Transparency Service's log (a Verifiable Data Structure) | The append-only Merkle tree of action records |
| Receipt | Receipt | The proof that one action record is in the audit trail, with the signed checkpoint that covers it |
| action record with its Receipt | Transparent Statement | The document an auditor is handed |
| verified | | The issuer signature (where present), the checkpoint signature and the inclusion proof all check out |

The word "receipt" has one meaning in this specification: the SCITT and COSE Receipt, a proof of inclusion. It never names an action record. In finance and ERP a receipt is a different document.

## Standards used

All were checked at rfc-editor.org and datatracker.ietf.org. Both are IETF Proposed Standards, published June 2026.

| Reference | What AE-OS takes from it |
|---|---|
| RFC 9943, *An Architecture for Trustworthy and Transparent Digital Supply Chains* (SCITT) | The terms Statement, Signed Statement, Receipt, Transparent Statement, Transparency Service and Issuer |
| RFC 9942, *CBOR Object Signing and Encryption (COSE) Receipts* | The Receipt as a COSE Single Signer object; header parameters `receipts` (394), `vds` (395) and `vdp` (396); the RFC 9162 tree as `RFC9162_SHA256` (value 1); inclusion proofs (label -1) and consistency proofs (label -2); an inclusion proof of tree size, leaf index and path |
| RFC 9162, *Certificate Transparency Version 2.0* | The Merkle tree hash, inclusion proof and consistency proof algorithms |
| RFC 8949, RFC 8785 | Deterministic CBOR and canonical JSON |

## Conformance

AE-OS is **SCITT-aligned, not yet SCITT-conformant.** What matches, and what does not:

| SCITT / COSE Receipts requirement | AE-OS today | Status |
|---|---|---|
| The tree is the RFC 9162 Merkle tree (`RFC9162_SHA256`) | Same tree shape, same hashes, same root | Matches (the entry is the CID bytes, see section 2) |
| An inclusion proof is tree size, leaf index and a path of hashes | The same three values, in a JSON object | Same content, different encoding |
| Consistency proofs from RFC 9162 | Same algorithm | Matches |
| A Receipt is a COSE_Sign1 with the root as detached payload | A signed checkpoint: JSON, Ed25519 over DAG-CBOR with a context string | Not COSE |
| The Receipt's protected header carries `vds` (395) and CWT Claims (15) with `iss` and `sub` | A `log` identifier and `key_id` in the checkpoint | Not built |
| A Signed Statement is a COSE_Sign1 signed by its Issuer | The gateway signs each action record's CID with its Ed25519 issuer key (section 1.1), in JSON form beside the record. Records written under version 0 have no issuer signature and are reported as "log-signed only" | Issuer-signed statement built; COSE_Sign1 not |
| A Transparent Statement carries Receipts in the `receipts` (394) unprotected header | One JSON document holding the record, the inclusion proof and the checkpoint | Same pieces, JSON not COSE |
| Registration policy and statement rules (RFC 9943) | The audit trail accepts what the gateway writes | Not built |

An auditor today can recompute everything with the Python, Rust or browser verifier. They cannot yet check it with a generic SCITT or COSE Receipts verifier, and AE-OS does not claim they can. The COSE wire format is on the roadmap (see the README).

## 1. Action records

An action record is a map encoded as deterministic DAG-CBOR (section 5). Its fields, and where each lands in a SCITT Signed Statement once the COSE wire format exists:

| Field | Type | Meaning | Planned SCITT counterpart |
|---|---|---|---|
| `v` | integer | Encoding version. It is `0` for every record: the signed bytes have not changed since the first draft | |
| `kind` | text | What happened (table below). Custom kinds start with `x-` | Payload type (`cty`, label 3) |
| `agent` | text | Identity of the acting agent as a URI, ideally a SPIFFE ID | Part of the payload |
| `obo` | text or null | The person or organization the agent acted for | Part of the payload |
| `subject` | text or null | What the action was applied to, for example a tool name | Subject claim (`sub`, label 2 inside CWT Claims) |
| `body` | map | Facts about the action: digests, decision, reasons, amounts | Payload |
| `parents` | list of links | CIDs of the action records that caused this one | Part of the payload |
| `ts` | integer | Time the record was made, in milliseconds since the Unix epoch | Issued-at claim of the CWT Claims |

The Issuer (`iss`, label 1) of an action-record statement is the gateway that writes the record, identified by its key id (section 1.1).

Record kinds:

| Kind | Written when | Typical body |
|---|---|---|
| `session.start` | An agent session begins | `allow_list`, `session_id` |
| `tool.call` | An agent asks to use a tool | `args_sha256`, `rpc_id` or `call_id`, `session_id` |
| `tool.result` | The tool answers | `outcome` (`ok`, `error`, `rpc-error`), `result_sha256`, `call_id` |
| `policy.decision` | A policy allows, denies or escalates an action | `decision`, `reasons` |
| `approval` | A person approves or rejects an escalated action | `decision`, `approver` |
| `journal.entry` | The books record an entry in the accounts | `document`, `date`, `lines` |
| `period.transition` | A controller opens or closes a posting period | `period`, `state`, `by` |
| `note` | Anything else worth recording | free form |
| `session.end` | The session ends | `unanswered_calls` |

Numbers in a record are integers. Amounts are stored in minor currency units (cents), which keeps the encoding exact.

### 1.1 Issuer signature

The gateway signs each action record with its issuer key, the audit trail's existing Ed25519 signing key. The signature covers the record's binary CID, which commits to every byte of the record, under a context string that is not the checkpoint's:

```
message = "aeos-action-record/statement/v1\n" || CID
sig     = Ed25519(issuer_key, message)
```

The signature and the issuer's `key_id` (the same 16-hex-digit identifier as in section 3, so a verifier can pick the right key) sit beside the record, outside the record bytes: in the audit trail's `records.jsonl` line, and in the export document as `statement_signature: {"key_id", "sig"}` (base64). The record bytes and CID are therefore the same with or without the signature.

A verifier that finds `statement_signature` must check it against the trusted public key: a `key_id` that is not the trusted key's, or a signature that does not verify, is a problem. A verifier that finds none reports the record as **log-signed only**: the audit trail's checkpoint vouches for it, but its issuer did not sign it. That is the state of every record written under version 0 and is not a failure.

**Digests instead of content.** By default a record holds the SHA-256 digest of a tool's arguments and result, computed over their canonical JSON form (section 5.3). Anyone holding the original arguments can recompute the digest and confirm they match the record. The full content can be kept beside the audit trail, but it stays outside the signed structure so it can be deleted under a retention policy without breaking any proof.

Known limitation: a digest of a short, guessable value (such as `{"approve": true}`) can be confirmed by guessing. A later version will add salted commitments for operators who need to hide low-entropy arguments.

**CID.** The record's identifier is a CIDv1 with codec `dag-cbor` (0x71) and a SHA-256 multihash: the bytes `01 71 12 20` followed by SHA-256 of the record's canonical encoding. Its text form is multibase base32 lower case (prefix `b`).

**Records reported by other components.** When a gateway, an agent framework or a trace exporter reports tool calls to the audit trail, the records carry the identifiers that component used:

| Body field | Meaning |
|---|---|
| `session_id` | The reporting component's identifier for the agent session |
| `call_id` | Its identifier for the tool call, which links a result to its call |
| `source` | An object of text values that locate the original report, such as an OpenTelemetry trace and span ID or the reporting service's name |
| `call_seen` | `false` on a `tool.result` whose call was never reported; the result then links to its session, when one was reported |

A digest field is left out when the reporting component did not share the arguments or result. Such a record proves that the component reported the call; it does not let anyone confirm what the arguments were.

**Parents.** A record may only name parents that already appear earlier in the same audit trail. Records therefore form a causal graph inside the audit trail: a `tool.result` points to its `tool.call`, which points to the `session.start`.

## 2. The audit trail

The audit trail is a sequence of action records. Leaf *i* of the Merkle tree is the binary CID of record *i*:

```
leaf_hash(i) = SHA-256(0x00 || CID_i)
node_hash    = SHA-256(0x01 || left || right)
```

The tree shape and the root (the Merkle tree hash) are exactly those of RFC 9162 section 2.1.1, with the CID bytes as the entry. The root of an empty audit trail is SHA-256 of the empty string. Appending the same record twice is a no-op, because the same bytes give the same CID.

A SCITT Transparency Service registers the Signed Statement itself as the entry. AE-OS registers its CID, which commits to the same bytes. The COSE wire format will decide whether to keep that or register the statement bytes.

## 3. Checkpoints

A checkpoint is the audit trail operator's signed statement of its size and root at a moment:

```
message = "aeos-receipts/checkpoint/v0\n" || DAG-CBOR({"log": log_id, "size": n, "root": root, "ts": ts})
sig     = Ed25519(signing_key, message)
```

The context string keeps its original text because it is part of the signed bytes: changing it would invalidate every checkpoint already issued. It is a label, not a choice of vocabulary.

`key_id` is the first 16 hex digits of SHA-256 of the 32-byte Ed25519 public key. Verifiers must obtain the public key through a channel they trust (for example the organization's published key, or an auditor's own record of it). A key embedded in the document being checked is no evidence of anything.

Each checkpoint must be at least as large as the one before it.

## 4. Proofs

### 4.1 Transparent Statement and Receipt

An action record with its Receipt is a JSON document (`type: "aeos-action-record/v1"`) holding:

| Field | Part | Meaning |
|---|---|---|
| `record` | Statement | The record bytes, base64 |
| `cid`, `index`, `log_id` | Statement | The record's CID, its position, and the audit trail it belongs to |
| `statement_signature` | Statement | The issuer signature over the CID (section 1.1); absent on records written under version 0 |
| `inclusion_proof` | Receipt | An RFC 9162 inclusion proof, as a hex list of hashes |
| `checkpoint` | Receipt | A signed checkpoint that covers the record; its `size` is the proof's tree size |

To verify with a trusted public key:

1. Check the checkpoint signature and that its `log` equals `log_id`.
2. Check the record bytes are canonical DAG-CBOR.
3. Recompute the CID from the bytes and compare it with `cid`.
4. Verify the inclusion proof from `leaf_hash(CID)` at `index` to the checkpoint root, using RFC 9162 section 2.1.3.2.
5. If `statement_signature` is present, check its `key_id` and signature against the trusted public key (section 1.1).

If all of these hold, the action record is **verified** (issuer-signed, or log-signed only when step 5 had nothing to check): this exact record was in the audit trail when the checkpoint was signed. That does not prove the record is true or complete. That depends on the controls around the agent and the audit trail, which is why the audit trail should be written by a component the agent cannot bypass, such as the MCP proxy in this repository.

Documents of `type: "aeos-receipt/v0"` have the same fields and the same checks. Verifiers must keep accepting them.

### 4.2 Consistency proof

A consistency proof (`type: "aeos-consistency/v0"`) holds two checkpoints and an RFC 9162 consistency proof between their sizes. A verifier who kept an earlier checkpoint checks both signatures and then the proof (RFC 9162 section 2.1.4.2). A valid proof shows that the first *m* records are unchanged in the later tree.

Auditors and counterparties should keep the checkpoints they receive. Requesting a consistency proof against a kept checkpoint is what detects a rewritten history.

### 4.3 Full audit trail verification

Anyone with read access to the audit trail directory can recompute every CID, check every causal link points backwards, check each record's readable view matches its signed bytes, check each issuer signature that is present, and check every checkpoint's signature and root against the records. Records with no issuer signature are counted as log-signed only, not reported as problems.

## 5. Encodings

### 5.1 DAG-CBOR subset

Records use deterministic CBOR (RFC 8949 section 4.2.1) restricted to: null, booleans, integers, byte strings, text strings, arrays, maps with text keys, and tag 42 links. Map keys are sorted by encoded length, then bytewise. Floating-point values are not allowed. Decoders must reject any input that is not the canonical encoding of the value it decodes to.

### 5.2 Links

A link is CBOR tag 42 over a byte string of `0x00` followed by the binary CID.

### 5.3 Canonical JSON for digests

Tool arguments and results are JSON. Their digest is SHA-256 over the RFC 8785 (JCS) serialization: object keys sorted by UTF-16 code units, no insignificant whitespace, integral numbers written without a fraction. The Python implementation follows JCS for all values except unusual non-integral floats, where it uses the shortest round-trip form.

## 6. Audit trail directory layout (reference implementation)

```
log.json            {"format": "aeos-receipts/v0", "log_id", "public_key", "key_id", "created"}
records.jsonl       {"i", "cid", "cbor" (base64), "key_id" and "sig" (issuer signature, section 1.1; absent in version 0), "view" (readable JSON, not signed)}
checkpoints.jsonl   {"log", "size", "root" (hex), "ts", "key_id", "sig" (base64)}
signing.key         Ed25519 private key, PKCS#8 PEM (keep elsewhere in production)
content/<cid>.json  optional full arguments and results
```

`format` keeps its original text so that older audit trails and older tools keep opening each other's directories.

## 7. Compatibility with version 0

Version 0 of this format was called "AE-OS Receipts" (`spec/receipts-v0.md`). Its bytes are unchanged: every record, checkpoint, signature and audit trail directory written under version 0 is valid under version 1, and verifies as log-signed only because it has no issuer signature. Version 1 changes the names, the export document, and adds the issuer signature beside each new record.

| Version 0 | Version 1 |
|---|---|
| "receipt" for a signed action | "action record" (a Receipt is the inclusion proof only) |
| "receipt log" | "audit trail" |
| export document `aeos-receipt/v0` | `aeos-action-record/v1`; verifiers accept both |
| `aeos receipt`, `aeos verify-receipt` | `aeos action-record`, `aeos verify-action-record`; the old commands keep working |
| `ReceiptLog`, `verify_receipt`, `log.receipt()` | `ActionLog`, `verify_action_record`, `log.action_record()`; the old names remain as deprecated aliases for one release |
| `testvectors/receipts-v0.json` | `testvectors/action-records-v1.json`; the v0 file is kept unchanged and every implementation still verifies it |

## 8. Test vectors

`testvectors/action-records-v1.json` holds test vectors for every part of this format: canonical encodings, CIDs, Merkle roots and proofs, and valid and tampered action records, consistency proofs and audit trails with the problems a verifier reports for each. Action record cases include good, altered, wrong-key, swapped and missing issuer signatures, each with the expected `signature` state (`issuer-signed` or `log-signed only`). `testvectors/receipts-v0.json` is the frozen version 0 file, with version 0 documents. The Python, Rust and browser implementations in this repository test against both. A change to this specification needs matching vectors.

## 9. Planned for later versions

- The COSE wire format: action-record statements as COSE_Sign1 (the issuer signature of section 1.1 in COSE form, with CWT Claims), Receipts as COSE Receipts (RFC 9942), Transparent Statements with the `receipts` header.
- Salted commitments for arguments and results.
- Independent witnesses that co-sign checkpoints, and C2SP signed-note checkpoint format. A preview of witness cosigning is described in [identity-and-witnesses-draft.md](identity-and-witnesses-draft.md).
- Agent identity bound to a SPIFFE SVID presented at session start (preview in the same draft), and delegation from a person's digital identity wallet.
- Hardware or cloud KMS keys for checkpoint signing.
