// Runs the browser verifier against the shared test vectors: node verify.test.mjs
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  cidOfBytes, cidStr, decodeDagCbor, leafHash, parsePublicKey, receiptRecord, toView, unhex,
  verifyConsistency, verifyConsistencyProof, verifyInclusion, verifyReceipt,
} from "./verify.js";

const url = new URL("../../../../testvectors/receipts-v0.json", import.meta.url);
// JSON.parse rounds integers beyond 2^53; keep their exact text, as toView does.
const V = JSON.parse(readFileSync(url, "utf8"),
  (_, v, ctx) => (typeof v === "number" && !Number.isSafeInteger(v) ? ctx.source : v));
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

test("receipts report the same problems as the reference implementation", async () => {
  for (const c of V.receipts) {
    assert.deepEqual(await verifyReceipt(c.receipt, parsePublicKey(c.public_key)),
      c.expect_problems, c.name);
  }
  assert.equal(receiptRecord(V.receipts[0].receipt).v, 0);
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
