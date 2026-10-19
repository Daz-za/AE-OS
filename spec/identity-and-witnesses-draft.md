# AE-OS identity, gateway and witnesses (draft)

Status: draft, implemented in the Python package as a preview (`identity.py`, `gateway.py`, `witness.py`, `audit.py`). The receipt log format in [receipts-v0.md](receipts-v0.md) is unchanged; everything here sits beside it. Formats may change before they are frozen with test vectors.

## 1. Workload identity

Agents, gateways and tools are identified by [SPIFFE IDs](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md) such as `spiffe://acme.example/agent/accounts-payable`. Each proves its ID with an [X.509-SVID](https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md):

| Property | Value |
|---|---|
| Leaf key | ECDSA P-256, for the workload alone (the preview's issuer generates it; under SPIRE it never leaves the workload) |
| Lifetime | 15 minutes; SPIRE renews at half the lifetime (the preview issues new SVIDs on request) |
| Leaf extensions | CA=false; key usage digitalSignature, keyEncipherment, keyAgreement; extended key usage clientAuth and serverAuth; exactly one URI SAN, the SPIFFE ID |
| Issuer | an intermediate CA (P-256) under the trust domain's root CA (P-384) |
| Trust bundle | the root certificate, given to every relying party |

In production SPIRE issues SVIDs after attesting the node and the workload. The preview's `TrustDomain` issues them directly and does no attestation.

## 2. Gateway

Agents reach tools through a gateway over mutual TLS, both sides presenting SVIDs from the trust domain. Requests are MCP JSON-RPC messages (`initialize`, `tools/list`, `tools/call`) sent as HTTP POSTs to `/mcp`, as in MCP's Streamable HTTP transport; the session is carried in the `Mcp-Session-Id` header and belongs to the identity that opened it.

The gateway:

1. ends any connection whose certificate is missing, expired or not issued under the bundle's root during the TLS handshake, and answers 403 to a peer whose SPIFFE ID is outside the trust domain;
2. takes the agent's SPIFFE ID from its verified certificate, never from the request;
3. allows each identity only the tools configured for it, and records a refusal as a `policy.decision` with decision `deny`;
4. records `session.start`, `tool.call`, `tool.result` and `session.end` under the agent's SPIFFE ID.

The `session.start` body adds:

| Field | Meaning |
|---|---|
| `svid_sha256` | SHA-256 of the DER encoding of the agent's leaf certificate, as bytes |
| `authenticated_by` | `x509-svid-mtls` |
| `trust_domain` | the trust domain whose bundle the gateway used |

## 3. Witness cosignatures

A witness keeps, for each log, the size and root of the last checkpoint it cosigned. It cosigns a newer checkpoint only if the log's signature verifies and an RFC 9162 consistency proof shows the newer tree extends the one it cosigned. Otherwise it refuses, which exposes a log that shows different histories to different parties.

A cosignature is an Ed25519 signature over:

```
"aeos-receipts/cosignature/v0\n" || DAG-CBOR({"checkpoint": <checkpoint message>, "time": <ms>})
```

where `<checkpoint message>` is the exact byte string the log signed (receipts-v0 section 3). The design follows [C2SP tlog-cosignature](https://github.com/C2SP/C2SP/blob/main/tlog-cosignature.md), adapted to v0 checkpoints. Cosignatures are stored one per line in `cosignatures.jsonl` in the log folder:

```json
{"witness":"external-auditor","key_id":"<16 hex>","log":"<log id>","size":14,"time":1792405000000,"sig":"<base64>"}
```

A checkpoint is final for an auditor when at least k of the n witnesses the auditor trusts have valid cosignatures on it.

## 4. Evidence folder

`aeos-receipts audit` checks a folder described by `evidence.json`:

```json
{"format": "aeos-evidence/v0", "trust_domain": "acme.example", "bundle": "trust/bundle.pem",
 "svids": "svids", "log": "log", "witnesses": "witnesses.json"}
```

`svids/` holds the certificate chains (no keys) the agents presented. `key-hierarchy.json`, when present, lists each key and certificate (role, algorithm, holder, what it signs, issuer, validity and fingerprint); it is informational and the audit does not rely on it. `witnesses.json` holds `{"required": k, "keys": {name: hex public key}}`. The audit:

- recomputes the log (receipts-v0 section 6);
- for each `session.start` with `svid_sha256`, checks the matching chain against the trust bundle at the record's time, and checks that its SPIFFE ID is the record's `agent`;
- checks that the latest checkpoint has at least k valid cosignatures.

An auditor should pass the trust bundle, the log's public key and the witness keys from sources they trust (`--bundle`, `--public-key`, `--witnesses`).

## 5. Not yet covered

- Delegated authority: the person's signed mandate and an attenuable token whose subject must equal the mTLS peer.
- Policy as code: Rego compiled to WebAssembly, with decisions that can be replayed.
- Audience-bound JWT-SVIDs on MCP calls.
- Recording the signer's SVID chain CID in every record (the preview records the leaf's fingerprint in `session.start` only).
- Each record signed with the actor's SVID key, as the research paper describes.
- Machine and workload attestation (SPIRE), and kernel-level enforcement.
