# AE-OS identity, delegation, gateway and witnesses (draft)

Status: draft, implemented in the Python package as a preview (`identity.py`, `delegation.py`, `gateway.py`, `witness.py`, `audit.py`). The receipt log format in [receipts-v0.md](receipts-v0.md) is unchanged; everything here sits beside it. Formats may change before they are frozen with test vectors.

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

## 2. Delegated authority

When the gateway holds an authorization service's key, an agent can call tools only under an intent a person has signed. The intent is an **intent envelope**, the DAG-CBOR map

| Field | Meaning |
|---|---|
| `principal` | the person's SPIFFE ID |
| `audience` | the agent's SPIFFE ID |
| `purpose` | what the authority is for, in words |
| `actions` | the tool names the agent may call, sorted |
| `per_action_max_minor` | the largest amount one call may move, in minor units |
| `budget_minor` | the total all calls may move, in minor units |
| `currency` | ISO 4217 code |
| `not_after` | expiry, milliseconds since the Unix epoch |

The person signs it with Ed25519 over `"aeos/intent-envelope/v0\n" || DAG-CBOR(envelope)`. The envelope is named by its CIDv1 (dag-cbor, sha2-256). The preview signs with an Ed25519 key file. Signing with a passkey or smart card after step-up authentication will need a WebAuthn assertion format, which this draft does not yet define.

An authorization service checks the signature and mints a [Biscuit](https://doc.biscuitsec.org/reference/specifications) (v3, Ed25519 root key) whose authority block is:

```
intent("<envelope CID>");
principal("<person's SPIFFE ID>");
check if subject($s), $s == "<audience>" || $s.starts_with("<audience>/");
check if tool($t), {<actions>}.contains($t);
check if amount($a), $a <= <per_action_max_minor>;
check if time($t), $t <= <not_after as an RFC 3339 date>;
```

Biscuit dates are whole seconds.

The token covers the audience and its sub-agents, whose SPIFFE ID paths extend the audience's. Any holder may append a block of further checks (`subject`, `tool`, `amount`, `time`) without contacting the service, for example to give a helper a token for reading only. Appending can only remove authority, because every check in every block must pass.

To authorize a call, the gateway supplies the facts `subject` (the SPIFFE ID from the mTLS connection), `tool`, `amount` (the call's `amount_minor` argument, 0 when absent) and `time` (rounded up to the whole second, since Biscuit times are seconds), with the policy `allow if intent($i)`. It then checks that it holds the envelope the token names and that the envelope's signature verifies against the principal's key. It meters `budget_minor` itself, reserving each allowed call's amount and releasing it if the call fails.

## 3. Gateway

Agents reach tools through a gateway over mutual TLS, both sides presenting SVIDs from the trust domain. Requests are MCP JSON-RPC messages (`initialize`, `tools/list`, `tools/call`) sent as HTTP POSTs to `/mcp`, as in MCP's Streamable HTTP transport; the session is carried in the `Mcp-Session-Id` header and belongs to the identity that opened it.

The gateway:

1. ends any connection whose certificate is missing, expired or not issued under the bundle's root during the TLS handshake, and answers 403 to a peer whose SPIFFE ID is outside the trust domain;
2. takes the agent's SPIFFE ID from its verified certificate, never from the request;
3. allows each identity only the tools configured for it, and records a refusal as a `policy.decision` with decision `deny`;
4. when it holds an authority key, requires a capability token in the `AEOS-Capability` header (base64url) on every `tools/call`, authorizes it as in section 2, and records the outcome as a `policy.decision` linked to the call, under the agent's SPIFFE ID; an allowed call, its decision and its result also name the envelope's principal as `obo`;
5. records `session.start`, `tool.call`, `tool.result` and `session.end` under the agent's SPIFFE ID.

The `session.start` body adds:

| Field | Meaning |
|---|---|
| `svid_sha256` | SHA-256 of the DER encoding of the agent's leaf certificate, as bytes |
| `authenticated_by` | `x509-svid-mtls` |
| `trust_domain` | the trust domain whose bundle the gateway used |
| `authorization` | `aeos-capability/v0` when every call in the session needs a token |

A capability decision's body is `decision` (`allow` or `deny`), `policy` (`aeos-capability/v0`), `amount`, `reasons` (empty when allowed), `token_sha256` (SHA-256 of the token's bytes) when the token decoded and the amount was valid, and `intent` (the envelope CID the token names) when the token's signature verified.

## 4. Witness cosignatures

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

## 5. Evidence folder

`aeos audit` checks a folder described by `evidence.json`:

```json
{"format": "aeos-evidence/v0", "trust_domain": "acme.example", "bundle": "trust/bundle.pem",
 "svids": "svids", "log": "log", "witnesses": "witnesses.json",
 "authority": "trust/authority-public-key.txt", "principals": "trust/principals.json",
 "intents": "intents", "tokens": "tokens"}
```

`svids/` holds the certificate chains (no keys) the agents presented. `key-hierarchy.json`, when present, lists each key and certificate (role, algorithm, holder, what it signs, issuer, validity and fingerprint); it is informational and the audit does not rely on it. `witnesses.json` holds `{"required": k, "keys": {name: hex public key}}`. The last four entries are present when the gateway required tokens: the authorization service's public key (hex), `principals.json` as `{SPIFFE ID: hex Ed25519 public key}`, `intents/<CID>.json` as `{"cid", "envelope", "signature"}`, and `tokens/<sha256 hex>.biscuit` holding each token presented. The audit:

- recomputes the log (receipts-v0 section 6);
- for each `session.start` with `svid_sha256`, checks the matching chain against the trust bundle at the record's time, and checks that its SPIFFE ID is the record's `agent`;
- replays each `aeos-capability/v0` decision from the token, the record's `agent`, `subject`, `ts` and `amount`, the envelope and the principal's key, with the budget spent by earlier allowed calls that ran, and checks it gives the recorded decision and, for an allowed call, that the record's `obo` is the envelope's principal;
- checks that, in sessions with `authorization`, every call with a successful `tool.result` has an allow decision;
- checks that the latest checkpoint has at least k valid cosignatures.

An auditor should pass the trust bundle, the log's public key, the witness keys, the authorization service's key and the people's keys from sources they trust (`--bundle`, `--public-key`, `--witnesses`, `--authority-key`, `--principals`).

## 6. Not yet covered

- A shared, durable budget: the preview keeps it in one gateway's memory, so a restart resets it and gateways do not share it.
- Revocation of tokens before they expire (Biscuit revocation IDs are not yet checked).
- Agent manifests (APOs) that pin each tool's definition digest.
- Policy as code: Rego compiled to WebAssembly, with decisions that can be replayed.
- Audience-bound JWT-SVIDs on MCP calls.
- Recording the signer's SVID chain CID in every record (the preview records the leaf's fingerprint in `session.start` only).
- Each record signed with the actor's SVID key, as the research paper describes.
- Machine and workload attestation (SPIRE), and kernel-level enforcement.
