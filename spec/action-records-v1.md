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

An issuer-signed action record together with its Receipt is a **Transparent Statement**. A record with no issuer signature (written under version 0) has a Receipt but is not a Transparent Statement; it is "log-signed only". When the issuer signature (where present), the checkpoint signature and the inclusion proof all check out, the action record is **verified**.

## Terms

AE-OS uses the vocabulary of the IETF SCITT architecture. Documents say "action record" and "audit trail" to people, and the standard terms where precision matters.

| Say | Standard term | Meaning here |
|---|---|---|
| action record | Signed Statement, profiled as the action-record statement | One recorded fact about what an agent did, as bytes with a CID and the issuer's signature over it |
| audit trail | The Transparency Service's log (a Verifiable Data Structure) | The append-only Merkle tree of action records |
| Receipt | Receipt | The proof that one action record is in the audit trail, with the signed checkpoint that covers it |
| issuer-signed action record with its Receipt | Transparent Statement | The document an auditor is handed |
| verified | | The issuer signature (where present), the checkpoint signature and the inclusion proof all check out |

The word "receipt" has one meaning in this specification: the SCITT and COSE Receipt, a proof of inclusion. It never names an action record. In finance and ERP a receipt is a different document.

## Standards used

All were checked at rfc-editor.org and datatracker.ietf.org. RFC 9943 and RFC 9942 are IETF Proposed Standards, published June 2026. RFC 9162 is Experimental (2021), RFC 8949 is an Internet Standard (STD 94, 2020) and RFC 8785 is Informational (2020).

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
| A Signed Statement is a COSE_Sign1 signed by its Issuer | The audit trail's writer signs each action record's CID with the issuer key (section 1.1), in JSON form beside the record; a writer without the key refuses to append. Records written under version 0 have no issuer signature and are reported as "log-signed only" | Issuer-signed statement built; COSE_Sign1 not |
| A Transparent Statement carries Receipts in the `receipts` (394) unprotected header | One JSON document holding the record, the inclusion proof and the checkpoint | Same pieces, JSON not COSE |
| A Signed Statement's protected header carries `kid` when it has no `x5t` or `x5chain` (RFC 9943 section 6) | The issuer signature names its key by `key_id` in a JSON field | Not built |
| The Issuer and the Transparency Service are separate parties | The gateway's issuer key and the audit trail's checkpoint key are the same Ed25519 key. The issuer signature and the checkpoint are therefore **not** two signing parties: whoever holds that key can sign both | Not built (see section 9) |
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

The Issuer (`iss`, label 1) of an action-record statement is the writer of the record, identified by the key id of its issuer key (section 1.1).

Record kinds:

| Kind | Written when | Typical body |
|---|---|---|
| `session.start` | An agent session begins | `allow_list`, `session_id` |
| `tool.call` | An agent asks to use a tool | `args_sha256`, `rpc_id` or `call_id`, `session_id` |
| `tool.result` | The tool answers | `outcome` (`ok`, `error`, `rpc-error`), `result_sha256`, `call_id` |
| `policy.decision` | A policy allows, denies or escalates an action | `decision`, `reasons`, and on an escalation that needs a hardware security key `requires` (section 10.9) |
| `approval` | A person approves or rejects an escalated action | `decision`, `approver`, `signature` or, for a passkey approver, `evidence` (section 10) |
| `journal.entry` | The books record an entry in the accounts | `document`, `date`, `lines` |
| `period.transition` | A controller opens or closes a posting period | `period`, `state`, `by` |
| `note` | Anything else worth recording | free form |
| `session.end` | The session ends | `unanswered_calls` |
| `x-issuer-signing` | The first signed append to an audit trail (section 1.1) | `key_id` |
| `x-approval-evidence` | A passkey assertion that proves an approval, or confirms a registry change (section 10) | `credential_id`, `authenticator_data`, `client_data_json`, `signature`, `nonce`, `rp_id`, `origin`, `request_digest`, `assertion_sha256`, `batch`, `key_class`, `backup_eligible`, `backup_state` |
| `x-passkey-enrolled`, `x-passkey-revoked`, `x-approver-rebound` | A passkey joins, leaves, or loses its standing with an approver's registry (section 10.4) | `approver`, `identity`, `credential_id`, `public_key`, `rp_id`, `origin`, `registration`, `key_class` |

Numbers in a record are integers. Amounts are stored in minor currency units (cents), which keeps the encoding exact.

### 1.1 Issuer signature

The audit trail's writer (the gateway, the recorder, the CLI) signs each action record with the issuer key, which is the audit trail's existing Ed25519 signing key; a writer without the key refuses to append. The signature covers the record's binary CID, which commits to every byte of the record, under a context string that is not the checkpoint's:

```
message = "aeos-action-record/statement/v1\n" || CID
sig     = Ed25519(issuer_key, message)
```

The signature and the issuer's `key_id` (the same 16-hex-digit identifier as in section 3, so a verifier can pick the right key) sit beside the record, outside the record bytes: in the audit trail's `records.jsonl` line, and in the export document as `statement_signature: {"key_id", "sig"}` (base64). The record bytes and CID are therefore the same with or without the signature.

A verifier that finds `statement_signature` must check it against the trusted public key: a `key_id` that is not the trusted key's, or a signature that does not verify, is a problem. A verifier that finds none reports the record as **log-signed only**: the audit trail's checkpoint vouches for it, but its issuer did not sign it. That is the state of every record written under version 0 and is not a failure.

**The signing marker.** The first signed append to a trail first appends a marker record: kind `x-issuer-signing`, agent the trail's `log_id`, body `{"key_id": <the trail's key id>}`, `ts` the time of the record that triggered it. The marker is itself issuer-signed and sits in the Merkle tree like any record, so a checkpoint that covers it stops matching if it is removed. A writer signs every record it appends and refuses to append without the key.

In a trail check, the marker is the first record of kind `x-issuer-signing`, and:

- from the marker on, inclusive, every record must carry an issuer signature that verifies under the trail's key. A record without one is a problem ("record n: issuer signature missing (the issuer-signing marker is record m)");
- a marker whose `key_id` is not the trail's is a problem;
- a `key_id` with an empty or missing `sig` is a problem, anywhere;
- records before the marker need no signature (a version 0 prefix), and a signature that is present there is still checked;
- a trail with no marker is a version 0 trail: its unsigned records pass.

This makes stripping signatures detectable against a trail with a marker: the marker cannot be removed without breaking the checkpoints that cover it, and everything after it must be signed. It does not detect removal of the marker together with everything after it, shown with an earlier genuine checkpoint: that is an older, genuine prefix of the trail, which only a consistency proof against a checkpoint someone kept can expose. An exported document on its own cannot show stripping, because a stripped record looks like a version 0 one: a log-signed-only record from a trail that has a marker means "check the full trail", not "fine".

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

### 1.2 Order of writing

The gateway writes a call's record and each decision (capability, policy, approval) before it runs the tool, and does not run the tool if they cannot be written: the agent is told the action was not performed and an error is logged. A tool's result can only be written after the tool has run. If that write fails, the tool has run, the trail holds the call and its decisions but no result, the agent is told the action ran but is not fully on record, and an error is logged. If the tool failed and that failure cannot be written, the agent is told the action was attempted and failed, and an error is logged. Either way the gap shows in the trail as a call with no result. An approval that answered an escalation stays usable until the allow decision that follows it is written, and budget reserved for a call is given back unless the tool ran.

Signatures are checked strictly, the same way in every verifier: a public key or signature point of small order, and an S value that is not reduced, make the signature invalid (a small-order key verifies some signatures for every message, so lax checking lets forged checkpoints through). A trusted public key of small order is refused when it is loaded.

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

An action record with its Receipt is a JSON document holding the fields below. Its `type` is `aeos-action-record/v1` or `aeos-receipt/v0`, and readers accept both. In this release writers still emit `aeos-receipt/v0`, with the issuer signature as an extra field, because the verifier deployed at ae-os.org/verify reads only that type and ignores fields it does not know; writers switch to `aeos-action-record/v1` in a later release, once the deployed verifier reads it. The fields:

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

The two types have the same fields and the same checks. Verifiers must keep accepting `aeos-receipt/v0`, including documents with no `statement_signature`.

### 4.2 Consistency proof

A consistency proof (`type: "aeos-consistency/v0"`) holds two checkpoints and an RFC 9162 consistency proof between their sizes. A verifier who kept an earlier checkpoint checks both signatures and then the proof (RFC 9162 section 2.1.4.2). A valid proof shows that the first *m* records are unchanged in the later tree.

Auditors and counterparties should keep the checkpoints they receive. Requesting a consistency proof against a kept checkpoint is what detects a rewritten history.

### 4.3 Full audit trail verification

Anyone with read access to the audit trail directory can recompute every CID, check every causal link points backwards, check each record's readable view matches its signed bytes, check each issuer signature that is present, and check every checkpoint's signature and root against the records. From the signing marker on, an unsigned record is a problem, and a key id without a signature is a problem (section 1.1). A trail with no marker is a version 0 trail, counted as log-signed only and not reported as a problem. A verifier reports a tampered trail and never fails on one: a line that is not a JSON object with a text `cbor` field, bytes that are not canonical DAG-CBOR, a record that is not a map, and a checkpoint line that cannot be read are each a problem naming the line, and checking carries on with the rest. The Python and Rust verifiers check whole trails; the browser verifier checks single documents and consistency proofs only.

## 5. Encodings

### 5.1 DAG-CBOR subset

Records use deterministic CBOR (RFC 8949 section 4.2.1) restricted to: null, booleans, integers, byte strings, text strings, arrays, maps with text keys, and tag 42 links. Map keys are sorted by encoded length, then bytewise. Floating-point values are not allowed. Decoders must reject any input that is not the canonical encoding of the value it decodes to, and any value nested more than 256 levels deep.

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
.lock               the file lock: writers hold it exclusive, readers shared
.pending            {"offset", "length", "first_cid"}: a batch of records being written
torn/               bytes taken out of the trail: <offset>.bin (records), checkpoints-<offset>.bin, pending.json
```

`format` keeps its original text so that older audit trails and older tools keep opening each other's directories.

Writers append whole batches of lines holding `.lock` exclusive; readers hold it shared, so no read sees a write in progress (a reader of a copy without `.lock` reads without it). A batch is written as a unit: the writer writes `.pending` and flushes it to the disk, writes the batch's lines and flushes them, then removes `.pending`. In `.pending`, `offset` is the byte offset in records.jsonl where the batch starts, `length` the number of bytes it adds, and `first_cid` the `cid` of its first line.

While `.pending` is present the batch is unfinished, even if every byte of it is there: a reader ignores records.jsonl from `offset` on, and the next writer cuts the file back to `offset` (keeping the cut bytes under `torn/`) before writing. It does so only if `.pending` still describes the batch at its offset: `offset` is the start of a line no further than the end of the file, the file is no longer than `offset + length`, the line at `offset` (if one is whole) has `first_cid` as its `cid`, and no checkpoint that verifies covers a record from `offset` on. A `.pending` that fails any of these is stale (a copy of a trail taken mid-write, restored beside later records, say): it cuts nothing, a reader and a verifier ignore it and report it as stale, and the next writer moves it under `torn/` and refuses that one write. A `.pending` that cannot be read was cut short before any record was written; it holds nothing back, and the next writer moves it aside.

The next writer also cuts a last line of records.jsonl with no newline, and moves a last line of checkpoints.jsonl with no newline under `torn/` before signing a checkpoint. A verifier reports each of these as an unfinished write rather than as damage. Where the platform has no file locks (one writer process), nothing is cut: a writer ends an unfinished last line with a newline, and the verifier reports that line as unreadable.

## 7. Compatibility with version 0

Version 0 of this format was called "AE-OS Receipts" (`spec/receipts-v0.md`). Its bytes are unchanged: every record, checkpoint, signature and audit trail directory written under version 0 is valid under version 1, and verifies as log-signed only because it has no issuer signature. Version 1 changes the names, the export document, and adds the issuer signature beside each new record.

| Version 0 | Version 1 |
|---|---|
| "receipt" for a signed action | "action record" (a Receipt is the inclusion proof only) |
| "receipt log" | "audit trail" |
| export document `aeos-receipt/v0` | `aeos-action-record/v1`; verifiers accept both. Writers still emit `aeos-receipt/v0` (with `statement_signature`) in this release |
| `aeos receipt`, `aeos verify-receipt` | `aeos action-record`, `aeos verify-action-record`; the old commands keep working |
| `ReceiptLog`, `verify_receipt`, `log.receipt()` | `ActionLog`, `verify_action_record`, `log.action_record()`; the old names remain as deprecated aliases for one release |
| `testvectors/receipts-v0.json` | `testvectors/action-records-v1.json`; the v0 file is kept unchanged and every implementation still verifies it |

## 8. Test vectors

`testvectors/action-records-v1.json` holds test vectors for every part of this format: canonical encodings, CIDs, Merkle roots and proofs, and valid and tampered action records, consistency proofs and audit trails with the problems a verifier reports for each. Action record cases include good, altered, wrong-key, swapped and missing issuer signatures, each with the expected `signature` state (`issuer-signed` or `log-signed only`). Audit trail cases include signatures stripped from a prefix, from one record and from every record, a removed marker, and a version 0 trail with no marker. `testvectors/receipts-v0.json` is the frozen version 0 file, with version 0 documents. The Python, Rust and browser implementations in this repository test against both. `testvectors/passkey-approvals-v1.json` holds the vectors for section 10: the constructions with worked values, COSE keys, assertions, single registration responses with the error or the key class a verifier must give (`attestations`, against `authenticator_trust`), and whole trails with the problems a verifier must report. Only Python verifies approvals (section 10.8); Rust and the browser check that those trails decode to the same bytes and CIDs. A change to this specification needs matching vectors.

## 9. Planned for later versions

- The COSE wire format: action-record statements as COSE_Sign1 (the issuer signature of section 1.1 in COSE form, with CWT Claims), Receipts as COSE Receipts (RFC 9942), Transparent Statements with the `receipts` header.
- A separate issuer key for the gateway, distinct from the audit trail's checkpoint key, so the issuer and the Transparency Service are different signing parties.
- Writers emit `aeos-action-record/v1` instead of `aeos-receipt/v0` once the verifier deployed at ae-os.org/verify reads it.
- A `kid` in the issuer signature's protected header (with the COSE form).
- Salted commitments for arguments and results.
- Passkey approvals, attestations and key classes checked by the Rust and browser verifiers (sections 10.8 and 10.9), and RS256 passkeys (Windows Hello on some hardware), which the Python verifier refuses today.
- Approvals signed with a PIV or other smart card, beside passkeys.
- Independent witnesses that co-sign checkpoints, and C2SP signed-note checkpoint format. A preview of witness cosigning is described in [identity-and-witnesses-draft.md](identity-and-witnesses-draft.md).
- Agent identity bound to a SPIFFE SVID presented at session start (preview in the same draft), and delegation from a person's digital identity wallet.
- Hardware or cloud KMS keys for checkpoint signing.

## 10. Passkey approvals

An approval (section 1) is a person's answer to an escalated call. `aeos audit` checks an approval against one Ed25519 key per person. A person who approves with a passkey holds no such key, so a gateway that verified the passkey would sign the approval with its own key, and an auditor would have to trust that key. This section puts the person's own proof in the audit trail, so `aeos audit` checks it with nothing but the trail and the principals file the auditor trusts. A gateway signature, where present, is a convenience and never the proof.

The terms are those of W3C Web Authentication Level 3 (WebAuthn), a W3C Recommendation of 25 August 2026 (w3.org/TR/webauthn-3/, checked there): relying party, RP ID, origin, authenticator data (`rpIdHash`, `flags`, `signCount`), the UP, UV, BE, BS, AT and ED flags (section 6.1), client data (section 5.8.1), the authentication ceremony and the steps of section 7.2 "Verifying an Authentication Assertion", the signature counter (section 6.1.1), the credential public key as a COSE_Key in the CTAP2 canonical CBOR encoding form (section 6.5.1), and the DER `Ecdsa-Sig-Value` of ES256 (section 6.5.5).

### 10.1 The approval and its evidence

For an approver whose principals entry is of type `webauthn` (section 10.3), the `approval` record body is `{escalation, approver, decision, tool, args_sha256, time, evidence, signature?}`. For a yes, `evidence` is the summary `{kind: "passkey-assertion", assertion_sha256}`. `signature` is optional: the assertion is the signature, and any `signature` is the gateway's own.

The assertion sits in a child record of kind `x-approval-evidence`, whose `parents` is `[the approval]` and whose body is:

| Field | Type | Meaning |
|---|---|---|
| `kind` | text | `passkey-assertion` |
| `credential_id` | bytes | The credential that signed |
| `authenticator_data`, `client_data_json`, `signature` | bytes | The three values of the AuthenticatorAssertionResponse, verbatim |
| `nonce` | bytes | At least 16 bytes the server chose for this ceremony |
| `rp_id`, `origin` | text | What the evidence claims. They are compared with the values enrolled for the credential and never used in their place |
| `request_digest` | bytes (32) | The digest the challenge was built from (section 10.2) |
| `assertion_sha256` | bytes (32) | SHA-256(`authenticator_data` ‖ SHA-256(`client_data_json`) ‖ `signature`) |
| `batch` | map, optional | `{context: "aeos/approval-batch/v2", items: [{tool, args_sha256, escalation}, ...]}` (section 10.2); the document item has no `escalation` |
| `key_class` | text | `hardware`, `synced` or `unknown`: the class of key the writer found made the assertion (section 10.9) |
| `backup_eligible`, `backup_state` | boolean | The BE and BS flags of `authenticator_data`, as the writer read them |

Each approval of a batch has its own child record, and every one of them carries the same assertion. In JSON exports bytes are unpadded base64url. `key_class`, `backup_eligible` and `backup_state` are written together; a record without them (written before they existed) states no class, and the audit decides the class itself.

An assertion means one thing: **approve this request**. There is no assertion for declining. A `reject` by a passkey approver authorises nothing and rests on the sign-in that identified the person: its `evidence` is the summary `{kind, ref, sha256}` of that sign-in (a kind other than `passkey-assertion`, a reference, and the SHA-256 of the evidence), which the audit reports and cannot check. A rejection with no such evidence is refused, so no rejection is made anonymously under an approver's name. A rejection that carries an assertion is contradictory and fails.

### 10.2 What the passkey signs

```
request_digest = SHA-256("aeos/request/v2\n" || tool || "\n" || args_sha256 || escalation)
batch_digest   = SHA-256("aeos/approval-batch/v2\n" || item_1 || "\n" || item_2 || ... || item_n)
                 where item = tool || 0x00 || args_sha256 || escalation, in the order shown to the person
challenge      = SHA-256("aeos/approval-challenge/v1\n" || nonce || digest)
```

`tool` is UTF-8, `args_sha256` is the 32-byte digest of the call's arguments (section 5.3), and `escalation` is the 36-byte binary CID of the escalating `policy.decision`, all as the approval record names them. The escalation is in the digest so that a yes binds to one escalation and cannot answer another one for the same call. `digest` is `request_digest`, or `batch_digest` when `batch` is present. The authenticator is asked to sign `challenge`, so `client_data_json.challenge` is its unpadded base64url. A batch holds 1 to 256 items, a tool name in a batch has no NUL byte, and no item repeats. A batch of one still uses `batch_digest`; the two constructions are separate so one can never stand for the other. A batch that signs a document starts with the single item `(aeos/document, SHA-256 of the document)` with no escalation, and each approval citing it must be for a call whose recorded arguments hold `document_sha256`, the same digest in hex.

Names that start with `aeos/` are reserved: an approval is refused for such a tool, and so is a batch item, except the leading `aeos/document`. This keeps a person's yes to a payment from standing for a registry change.

A registry change (section 10.4) is confirmed by an assertion over a request that answers no escalation, so one single request and never a batch: `request_digest = SHA-256("aeos/request/v1\n" || tool || "\n" || args_sha256)`, where `tool` is `aeos/passkey-enrol`, `aeos/passkey-revoke` or `aeos/approver-rebind`, and `args_sha256` is the digest (section 5.3) of `{approver, identity, credential_id, public_key, rp_id, origin}` for an enrolment (`credential_id` and `public_key` as unpadded base64url), of `{approver, credential_id}` for a revocation, or of `{approver, identity, identity_evidence}` for a rebinding (`identity_evidence` as `{kind, ref, sha256}` with `sha256` in unpadded base64url).

A root passkey's registration response (section 10.4) is made for the challenge `SHA-256("aeos/enrol-challenge/v1\n" || approver || "\n" || SHA-256 of the identity evidence)`. The registration response of a passkey added by a registered one is made for `SHA-256("aeos/add-challenge/v1\n" || approver || "\n" || identity)`, with the identity the enrolment names.

### 10.3 Principals

`trust/principals.json` maps a principal to an Ed25519 public key (hex), as before, or to `{"type": "webauthn", "credentials": [...], "witness_key": hex?}`. `credentials` pins the approver's root passkeys: entries of `{credential_id, public_key, rp_id, origin, identity}` (the bytes as unpadded base64url), all five required, so that a pin names the person it was made for. Other fields an exporter adds, such as `created_at_ms` and `revoked_at_ms`, are a cache that the audit ignores. `witness_key` is the gateway key that may have signed the approval, so a verifier can say whether that signature holds. The auditor takes this file from a source they trust.

### 10.4 The registry, kept in the audit trail

Each passkey's life is a record in the trail, so no window of validity rests on the writer's word:

- `x-passkey-enrolled`: `{approver, identity, credential_id, public_key (COSE_Key bytes), rp_id, origin, key_class}` and, for a root passkey, `identity_evidence` and `registration`; for any other, `evidence`, and `registration` when the writer has it.
- `x-passkey-revoked`: `{approver, credential_id, evidence}`.
- `x-approver-rebound`: `{approver, identity, identity_evidence}` and, while a passkey stands, `evidence`.

A registry record or an approval and its `x-approval-evidence` child are written in one batch (section 6), so neither is in the trail without the other. A writer judges the change, or the approval's assertion, at the position the trail will give it, after every earlier record whichever process wrote it. In the reference implementation only `Recorder` with a passkey directory writes these records; the general `append` (and `aeos log append`) refuses them.

`identity_evidence` is `{kind, ref, sha256}`: what identified the person (a sign-in, say). The audit cannot check it: it reports it, and the auditor decides whether to accept it. `registration` is `{client_data_json, attestation_object}`, the response of the registration ceremony, verbatim, with its attestation statement and certificate chain, so the attestation can be checked again offline (section 10.9). `key_class` is the class the writer found for the passkey (section 10.9). `evidence` is a summary as in section 10.1, with an `x-approval-evidence` child that confirms the change (section 10.2).

Each approver has an **epoch**, a count that every root passkey and every rebinding raises by one. The audit rebuilds the registry by walking the trail once, in order, applying each registry record and checking each approval at its own position, with the principals the auditor trusts:

1. A change for a principal that is not of type `webauthn` is a problem.
2. An enrolment made when the approver has no valid passkey is a **root**. It starts a new epoch, binds the approver to its `identity`, and must carry `identity_evidence` and a `registration` whose client data is `webauthn.create` for the enrol challenge of section 10.2, at the enrolled origin, with an attestation object whose authenticator data has the UP, UV and AT flags, the enrolled RP ID hash, credential id and public key, and whose attestation statement verifies (section 10.9). If the principals pin credentials for the approver it must be one of them (same id, key, RP ID, origin and identity); otherwise the audit reports that the root rests on the trail's identity evidence alone.
3. Any other enrolment must name the approver's current identity and carry a confirmation: an assertion from a passkey valid for that approver at that position. So must every revocation (a passkey may revoke itself). Its `registration`, when present, is checked as a root's is, for the add challenge of section 10.2.
4. A rebinding needs `identity_evidence`, starts a new epoch and binds the approver to its `identity`. While the approver has a valid passkey, one of them must confirm it, so the writer alone cannot rebind. A rebinding that is not confirmed is a problem and does not take effect.
5. A credential id enrols once. Its COSE_Key, RP ID and origin must pass section 10.5.

A passkey is **valid for an approver at a position** (a record's index in the trail) when it was enrolled at an earlier position, was not revoked at an earlier position, and was enrolled in the epoch the approver is in at that position and under its identity. A rebinding therefore ends every earlier passkey for good: binding back to an earlier identity does not revive them, because the epoch has moved on. Position, not time, decides: the trail's checkpoints commit to the order of records, while a timestamp is whatever the writer wrote. Approvals before a revocation or rebinding still verify; approvals after it fail.

### 10.5 Keys and the assertion

A credential public key is a COSE_Key in the CTAP2 canonical CBOR encoding form with exactly the fields of an ES256 key (`kty` 2, `alg` -7, `crv` 1, `x`, `y`) or an EdDSA key (`kty` 1, `alg` -8, `crv` 6, `x`), nothing else. CBOR is canonical when its integers are in shortest form, its lengths are definite, and map keys are in order by encoded length then bytewise with none repeated; floats and tags are refused. A key is refused when it is not canonical, is on another curve or algorithm, has coordinates that are not 32 bytes or not reduced, is not a point on P-256, or is an Ed25519 point that is not canonical or is of small order.

A relying party id is a lower-case domain of two or more labels of `a-z`, `0-9` and `-`, not an IP address and not a public suffix. The public suffixes are exactly the list in `public_suffixes` in `testvectors/passkey-approvals-v1.json`, a short list of suffixes under which anyone registers names (such as `co.za`, `github.io`, `herokuapp.com`); it is not the Public Suffix List, and a verifier must refuse these and may refuse more. A declared origin is in its browser serialisation: `https`, lower case, `scheme://host[:port]`, no path and no default port, with a host that is the RP ID or a subdomain of it. `localhost` over `http` is refused, unless the audit runs with the explicit `--demo` option (`aeos audit --demo`): then it is accepted and the audit reports a note that it was.

The attestation object of a registration is decoded as CTAP2 canonical CBOR, except that its map keys may come in any order (a browser encodes it); a key is never repeated.

The assertion is verified as in WebAuthn section 7.2 with the values enrolled for the credential:
- `client_data_json` is UTF-8, decoded with one leading byte order mark stripped as section 7.2 requires, and parsed as JSON with no repeated key;
- `type` is `webauthn.get`; `challenge` is the section 10.2 challenge; `origin` equals the enrolled origin; `crossOrigin` is absent or false and `topOrigin` is absent;
- `rpIdHash` is SHA-256 of the enrolled RP ID; the UP flag and the UV flag are set (AE-OS always requires user verification); BS is not set without BE;
- the AT flag is not set (an AE-OS rule: an assertion carries no attested credential data);
- the bytes after the first 37 of the authenticator data are empty unless the ED flag is set, and then they are exactly one canonical CBOR map with nothing after it;
- the signature is valid over `authenticator_data` ‖ SHA-256(`client_data_json`) with the enrolled key, for ES256 as an ASN.1 DER `Ecdsa-Sig-Value` and for EdDSA as Ed25519 under the strict rules of section 1.2.

`signCount` is advisory: synced passkeys report 0, and a counter that does not rise is not a problem. As section 7.2 describes, when it or the stored counter is non-zero and it is not greater than the stored counter, the audit reports a note that the passkey may have been cloned, and it carries on.

The BE flag of a credential never changes (WebAuthn section 6.1.3). An assertion whose BE differs from the credential's registration, or, for a credential enrolled without one, from its first assertion, fails; for a credential registered as `hardware` the problem says it may have been copied.

### 10.6 Verifying an approval

For each `approval` by a passkey approver, a verifier reports a problem unless every check holds:

1. The record is by the approver, and answers an escalation of the same call (as for any approval).
2. `decision` is `approve`, or `reject` with sign-in evidence (section 10.1); another value fails. A rejection verifies nothing and is counted as no approval.
3. `evidence` names an `x-approval-evidence` child whose `assertion_sha256` matches, whose digest matches its bytes, and which parses.
4. The credential is valid for the approver at the approval's position (section 10.4).
5. The evidence's `rp_id` and `origin` equal those enrolled for the credential.
6. The request the passkey signed is the approval's own: `request_digest` is the digest of the approval's `tool`, `args_sha256` and escalation, or the approval's own item is one of the batch's items and `request_digest` is the batch's digest. If not, the passkey signed a different request.
7. The assertion verifies (section 10.5) over the challenge of section 10.2.
8. If a document is signed, it is the one the call's arguments name.
9. Single use (section 10.7).
10. What the evidence states holds: `backup_eligible` and `backup_state` are the flags of `authenticator_data`, `key_class` is `synced` exactly when `backup_eligible` is true, and a `key_class` of `hardware` is the audit's own class for the assertion (section 10.9).
11. The escalation's step-up requirement, if it has one, is met (section 10.9).

A gateway signature, if present and a `witness_key` is given, must verify or the approval fails; if it verifies the audit says so. Without a `witness_key` the audit says that a gateway signature was not checked. Nothing else depends on it.

**A decision rests on its approval.** For every `policy.decision` whose input carries `approval`, the trail holds an earlier `approval` record with parents `[escalation, the decision's call]`, by the same approver with the same answer, that passed these checks (for an Ed25519 approver, its signature check), and whose tool and arguments are the call's. One approval of one escalation allows at most one call: a second allowed decision on the same escalation is a problem, so one tap never authorises two payments. This holds for Ed25519 approvals too.

### 10.7 Single use

The audit walks the trail once, in order, and checks registry changes and approvals in the same pass. Each nonce and each assertion is used once, except an assertion shared by the approvals of its own batch (each for a different item), and an answer recorded again for the same escalation. Any other later use of an assertion, or of a nonce with another assertion, is a problem naming the first use; a confirmation that reuses an approval's nonce, or the reverse, is such a use. That the server issued the nonce, and issued it only once across trails, cannot be checked from a trail: the audit says that the nonce was bound to the request and checked for reuse inside this trail only.

### 10.8 What is and is not proven

Proven, from the trail and the trusted principals alone: a credential that was registered for the approver at that point in the trail, in the epoch the approver was then in, signed, with user verification, a challenge bound to this exact call and escalation (or to a batch that includes it), at the enrolled RP ID and origin, and no assertion was used twice. With the authenticator trust file as well (section 10.9): which approvals were made with a hardware security key, and that every escalation that required one was answered by one.

Not proven: a passkey proves possession of the credential, not who holds it. Identity comes from the evidence at enrolment: the audit shows each `identity_evidence` and which credential it made the root of the registry, and the auditor accepts or rejects it, or pins the root in the principals file. Without a pin, the root passkey rests on the trail writer's word: the writer could have made a passkey of its own, recorded it as the root, and approved with it, and nothing in the trail rules that out. The registration response only shows that the recorded parts agree. Pin each approver's root in the principals file wherever the writer is not trusted. The audit splits its finding into approvals that rest on a pinned root and approvals that rest on a first passkey that is not pinned. A registration response with the `none` attestation format, or self attestation, carries no maker's signature: it ties the credential id, public key, origin, user verification and the identity evidence together in one recorded response, so a mismatch is caught, but a writer who holds the public key could fabricate it. An attestation that chains to a trusted root proves that a key of that maker's model holds the credential; it says nothing about whose it is. Not proven either: that a person saw what the call does (only that the digest of it was signed), that the device was not shared, that the server issued the nonce, and who the principal is outside the records.

Only the Python verifier (`aeos audit`) checks approvals, attestations and key classes today. The Rust verifier and the browser verifier check whole trails and documents (sections 4.1 and 4.3), which include these records as ordinary action records whose extra fields they read and ignore, but do not check approvals of either kind. They are on the roadmap.

### 10.9 Key classes and the hardware-key step-up

Every passkey has a **key class**, decided by code from its registration response and the authenticator trust file the auditor gives, never by the writer's word:

| Class | When |
|---|---|
| `hardware` | The attestation statement verifies, its certificate chain leads to a root the trust file lists for the authenticator's model, the certificate is bound to that model (below), that model is listed as device-bound, the format is not `android-key`, and the registration's BE flag is 0 |
| `synced` | The registration's BE flag is 1: the credential can be copied to other devices (a multi-device credential, WebAuthn section 6.1.3) |
| `unknown` | Anything else: no registration response, format `none`, self attestation, a model or root the trust file does not list, a chain that does not stand, a certificate not bound to its model, a model not listed as device-bound, or an `android-key` attestation |

An assertion's class is `synced` when its own BE flag is 1, `hardware` when its credential is of class `hardware` (and, by section 10.5, its BE flag is then 0), and `unknown` otherwise.

`hardware` is the trail's evidence that the key cannot leave the authenticator, which NIST SP 800-63B asks of an authenticator at AAL3; a synced passkey cannot give it. AAL3 asks more than a trail can show (of the sign-in, the device and the organization), so the class is evidence for an assessor, not a claim of AAL3.

**Attestation statements.** A registration's statement is verified offline as WebAuthn Level 3 section 8 defines each format: `none` (an empty statement), `packed` (full, with `x5c`, or self, signed by the credential key with its algorithm), `tpm` (version 2.0; `pubArea` holds the credential public key, `certInfo` is `TPM_ST_ATTEST_CERTIFY` with `extraData` the digest of authenticator data ‖ client data hash and `attested.name` naming `pubArea`, signed by the attestation key; the certificate has an empty subject, a subject alternative name with the TPM manufacturer, model and version, and the `tcg-kp-AIKCertificate` key usage), `android-key` (the certificate's key is the credential key; the key description's challenge is the client data hash, `allApplications` is absent, the key was generated (`origin` GENERATED) for signing (`purpose` SIGN) as its hardware-enforced list says, and `attestationSecurityLevel` and `keymasterSecurityLevel` agree and are TrustedEnvironment (1) or StrongBox (2); Software (0) is refused), `apple` (the certificate's nonce extension is SHA-256 of authenticator data ‖ client data hash, and its key is the credential key) and `fido-u2f` (one P-256 certificate, an ES256 credential, and the U2F signature over `0x00 ‖ rpIdHash ‖ clientDataHash ‖ credentialId ‖ public key point`). A `packed` attestation certificate is version 3 with a subject of C, O, OU `Authenticator Attestation` and CN, and is not a CA. An AAGUID extension (OID 1.3.6.1.4.1.45724.1.1.4), where present, is not critical and names the authenticator data's AAGUID. Statement signatures may be ES256, ES384, ES512, EdDSA, RS256, RS384, RS512, PS256, PS384 or PS512, with RSA keys of at least 2048 bits. Other formats, `compound` and `android-safetynet` among them, are refused, and so is a statement with a field its format does not define. A statement that does not verify makes the registration, and so the enrolment, fail.

**The chain.** `x5c` is leaf first, at most five certificates, and may end with the root. Each certificate is valid at the enrolment record's `ts` (a time the writer states, so an auditor who doubts it compares it with the checkpoints around the record); each issuer is a CA certificate (basic constraints CA, and key usage `keyCertSign` when key usage is present) within its path length, and signs the one below it; the last is signed by, or is, a root the trust file lists for that model. Every certificate on the path, the root included, has only critical extensions this verifier checks (basic constraints, key usage, extended key usage, subject alternative name), and a key that is RSA of at least 2048 bits, P-256, P-384, P-521, Ed25519 or Ed448; every signature on the path uses SHA-256, SHA-384 or SHA-512, or an Edwards key. A chain that does not stand does not fail the registration: it makes the class `unknown`, and the audit says why. Revocation lists are not consulted.

**Binding to the model.** A trust file may list one root for several models, as the FIDO Metadata Service does for a maker's range. A `packed` or `tpm` certificate that names the AAGUID in its extension is bound to that model; a `fido-u2f` certificate is bound by its key identifier. Any other certificate (`apple`, or `packed` and `tpm` without the extension) counts as `hardware` only when no other model in the trust file lists the root its chain leads to; otherwise the class is `unknown`, because nothing shows which of those models made it. An `android-key` attestation is never `hardware`: a key in a phone's trusted execution environment is not a security key, and a StrongBox one cannot be told apart from one made with a leaked Android attestation key without Google's attestation revocation list, which this offline verifier does not read.

**The trust file** is JSON the auditor supplies (`aeos audit --authenticators FILE`); the `authenticators` entry of `evidence.json` is read only with `--accept-folder-authenticators`, and the audit then says that a hardware key rests on the word of whoever wrote it. Nothing is fetched at audit time:

```
{"format": "aeos-authenticator-trust/v1", "source": text,
 "mds_blob_no": integer,                                       (when made from an MDS BLOB)
 "authenticators": [{"description": text, "device_bound": bool,
                     "aaguid": lower-case UUID text,                          (FIDO2 models)
                     "attestation_certificate_key_identifiers": [40 hex],     (U2F models)
                     "attestation_root_certificates": [standard base64 DER, ...]}]}
```

A model is found by the authenticator data's AAGUID, or, for `fido-u2f`, by the SHA-1 key identifier of the attestation certificate's subjectPublicKey, as the FIDO Metadata Service lists U2F models (a subject key identifier extension in the certificate is not used). No two entries name the same model, and the all-zero AAGUID names none.

`aeos authenticator-trust` makes this file from a FIDO Metadata Service (MDS3) BLOB the deployer downloads. It checks the BLOB's signature (an ECDSA signature must be exactly the curve's `r ‖ s` length) and chain against the FIDO root certificate the deployer gives, and refuses a BLOB whose `nextUpdate` has passed or is missing unless the deployer passes `--allow-stale`. It records the BLOB's serial number as `mds_blob_no` and refuses to replace a trust file made from a BLOB with a higher number. It leaves out entries with any status report that withdraws trust (`USER_VERIFICATION_BYPASS`, `ATTESTATION_KEY_COMPROMISE`, `USER_KEY_REMOTE_COMPROMISE`, `USER_KEY_PHYSICAL_COMPROMISE`, `REVOKED`). It marks a model device-bound only when its `keyProtection` includes `secure_element` and not `software` (`remote_handle`, which U2F keys list, is allowed), and its latest status report is `FIDO_CERTIFIED` or `FIDO_CERTIFIED_L1` and above (`L1plus`, `L2`, `L2plus`, `L3`, `L3plus`). A model protected only by `hardware` and `tee`, as Windows Hello's TPM and phones list themselves, is never device-bound: it is a platform authenticator, not a hardware security key.

**What the records state.** A writer states the class it finds: `key_class` on each enrolment, and `key_class` with `backup_eligible` and `backup_state` on each `x-approval-evidence`. The audit compares them with its own: a statement of `hardware` the audit does not find, or a statement that contradicts the BE flag, is a problem; a statement of `unknown` for what the audit finds to be `hardware` (a writer with older trust) is a note.

**The step-up.** An escalating `policy.decision` may carry `requires: "hardware-key"`, which the policy's answer gives (`{"decision": "escalate", "reasons": [...], "requires": "hardware-key"}`; `requires` on any other decision is a policy error). An approval of that escalation stands only when it is a passkey approval whose assertion is of class `hardware`; an Ed25519 approval never meets it. A `requires` value the verifier does not know is a requirement no approval meets. A writer keeps the requirement with the escalation when it records it, and refuses an approval of an escalation whose requirement it cannot read. The gateway refuses an approval that does not meet the requirement before anything is written, and warns when it starts if its policy data sets `hardware_key_above_minor` but it has no authenticator trust file; the audit runs the policy again on the recorded input and reports a recorded `requires` that differs from the policy's, so a writer cannot drop the requirement.
