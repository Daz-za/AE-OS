// Runs the browser verifier against the shared test vectors: node verify.test.mjs
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  actionRecordContent, cidOfBytes, cidStr, decodeDagCbor, leafHash, parsePublicKey, receiptRecord,
  toView, unhex, verifyActionRecord, verifyConsistency, verifyConsistencyProof, verifyInclusion,
  verifyReceipt,
} from "./verify.js";

// JSON.parse rounds integers beyond 2^53; keep their exact text, as toView does.
const load = (name) => JSON.parse(
  readFileSync(new URL(`../../../../testvectors/${name}`, import.meta.url), "utf8"),
  (_, v, ctx) => (typeof v === "number" && !Number.isSafeInteger(v) ? ctx.source : v));
const V = load("action-records-v1.json");
// The frozen version 0 file: its documents are `aeos-receipt/v0` and must keep verifying.
const V0 = load("receipts-v0.json");
const OLD_WRONG_TYPE = "not an aeos-receipt/v0 document";
const NEW_WRONG_TYPE = "not an aeos-action-record/v1 document (or aeos-receipt/v0)";
const big = (x) => BigInt(x);

test("DAG-CBOR values decode to the expected views and CIDs", async () => {
  for (const c of V.cbor) {
    const raw = unhex(c.cbor);
    assert.deepEqual(toView(decodeDagCbor(raw)), c.view, c.name);
    assert.equal(cidStr(await cidOfBytes(raw)), c.cid, c.name);
  }
});

test("non-canonical DAG-CBOR is rejected", () => {
  for (const c of V.cbor_reject) assert.throws(() => decodeDagCbor(unhex(c.cbor)), Error, c.name);
});

test("Merkle inclusion and consistency proofs verify", async () => {
  const M = V.merkle;
  const leaves = M.leaves.map(unhex);
  for (const c of M.inclusion) {
    const root = unhex(M.roots[c.size]);
    assert.ok(await verifyInclusion(leaves[c.index], big(c.index), big(c.size),
      c.proof.map(unhex), root), `inclusion ${c.index}/${c.size}`);
  }
  for (const c of M.consistency) {
    assert.ok(await verifyConsistencyProof(big(c.old_size), big(c.new_size), c.proof.map(unhex),
      unhex(M.roots[c.old_size]), unhex(M.roots[c.new_size])),
    `consistency ${c.old_size}->${c.new_size}`);
  }
  assert.deepEqual(await leafHash(Uint8Array.of(0)), leaves[0]);
});

test("action records report the same problems as the reference implementation", async () => {
  for (const c of V.action_records) {
    assert.deepEqual(await verifyActionRecord(c.action_record, parsePublicKey(c.public_key)),
      c.expect_problems, c.name);
  }
  assert.equal(actionRecordContent(V.action_records[0].action_record).v, 0);
});

test("version 0 receipts in the frozen vectors still verify, and the old names still work", async () => {
  assert.equal(V0.receipts[0].receipt.type, "aeos-receipt/v0");
  for (const c of V0.receipts) {
    const expected = c.expect_problems.map((p) => (p === OLD_WRONG_TYPE ? NEW_WRONG_TYPE : p));
    assert.deepEqual(await verifyActionRecord(c.receipt, parsePublicKey(c.public_key)),
      expected, c.name);
  }
  const first = V0.receipts[0];
  assert.deepEqual(await verifyReceipt(first.receipt, parsePublicKey(first.public_key)), []);
  assert.equal(receiptRecord(first.receipt).v, 0);
});

test("consistency proofs report the same problems as the reference implementation", async () => {
  for (const c of V.consistency) {
    assert.deepEqual(await verifyConsistency(c.proof, parsePublicKey(c.public_key)),
      c.expect_problems, c.name);
  }
});

test("a public key can be given as hex or as log.json", () => {
  const k = parsePublicKey(V.logs.log_json);
  assert.equal(k.length, 32);
  assert.deepEqual(parsePublicKey(` ${V.logs.public_key}\n`), k);
  assert.throws(() => parsePublicKey("abcd"));
});
