// AE-OS Receipts v0 verifier for web browsers and Node.js 20+ (spec/receipts-v0.md).
//
// Checks receipts and consistency proofs offline with the Web Crypto API (SHA-256 and
// Ed25519); nothing is sent anywhere. Problems are reported in the same words as the
// Python reference implementation and the Rust verifier; an empty list means valid.
// Tested against testvectors/receipts-v0.json by verify.test.mjs.

const subtle = globalThis.crypto.subtle;
const CHECKPOINT_CONTEXT = new TextEncoder().encode("aeos-receipts/checkpoint/v0\n");
const CID_PREFIX = [0x01, 0x71, 0x12, 0x20];
const BASE32 = "abcdefghijklmnopqrstuvwxyz234567";

// ---------------------------------------------------------------------------------------
// Bytes
// ---------------------------------------------------------------------------------------

export function hex(b) {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

export function unhex(s) {
  s = s.trim();
  if (s.length % 2 || !/^[0-9a-fA-F]*$/.test(s)) throw new Error("invalid hex");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out;
}

function unb64(s) {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s) || s.length % 4) throw new Error("invalid base64");
  const bin = atob(s);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let i = 0;
  for (const p of parts) {
    out.set(p, i);
    i += p.length;
  }
  return out;
}

function equal(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

export async function sha256(data) {
  return new Uint8Array(await subtle.digest("SHA-256", data));
}

// ---------------------------------------------------------------------------------------
// DAG-CBOR: the subset records use (spec section 5)
// ---------------------------------------------------------------------------------------

const utf8 = new TextEncoder();
const utf8Strict = new TextDecoder("utf-8", { fatal: true });

function keyOrder(a, b) {
  const x = utf8.encode(a), y = utf8.encode(b);
  if (x.length !== y.length) return x.length - y.length;
  for (let i = 0; i < x.length; i++) if (x[i] !== y[i]) return x[i] - y[i];
  return 0;
}

function head(out, major, n) {
  n = BigInt(n);
  const m = major << 5;
  const push = (bytes, v) => {
    for (let i = bytes - 1; i >= 0; i--) out.push(Number((v >> BigInt(8 * i)) & 0xffn));
  };
  if (n < 24n) out.push(m | Number(n));
  else if (n < 0x100n) { out.push(m | 24); push(1, n); }
  else if (n < 0x10000n) { out.push(m | 25); push(2, n); }
  else if (n < 0x100000000n) { out.push(m | 26); push(4, n); }
  else { out.push(m | 27); push(8, n); }
}

// Values: null, booleans, BigInt integers, Uint8Array bytes, strings, arrays,
// {map: [[key, value], ...]} and {link: Uint8Array} (a CID without its leading 0x00).
function encodeInto(v, out) {
  if (v === null) out.push(0xf6);
  else if (v === true) out.push(0xf5);
  else if (v === false) out.push(0xf4);
  else if (typeof v === "bigint") v >= 0n ? head(out, 0, v) : head(out, 1, -1n - v);
  else if (v instanceof Uint8Array) { head(out, 2, v.length); out.push(...v); }
  else if (typeof v === "string") {
    const b = utf8.encode(v);
    head(out, 3, b.length);
    out.push(...b);
  } else if (Array.isArray(v)) {
    head(out, 4, v.length);
    for (const x of v) encodeInto(x, out);
  } else if (v.link) {
    out.push(0xd8, 0x2a);
    head(out, 2, v.link.length + 1);
    out.push(0, ...v.link);
  } else {
    const entries = [...v.map].sort((a, b) => keyOrder(a[0], b[0]));
    head(out, 5, entries.length);
    for (const [k, x] of entries) { encodeInto(k, out); encodeInto(x, out); }
  }
}

export function dagCbor(v) {
  const out = [];
  encodeInto(v, out);
  return Uint8Array.from(out);
}

function decodeValue(r, depth) {
  if (depth > 256) throw new Error("nesting too deep");
  const take = (n, what) => {
    if (r.data.length - r.i < n) throw new Error(what);
    const s = r.data.subarray(r.i, r.i + n);
    r.i += n;
    return s;
  };
  const ib = take(1, "truncated")[0];
  const major = ib >> 5, info = ib & 31;
  if (major === 7) {
    if (info === 20) return false;
    if (info === 21) return true;
    if (info === 22) return null;
    throw new Error("unsupported simple value or float");
  }
  let n;
  if (info < 24) n = BigInt(info);
  else if (info <= 27) {
    n = 0n;
    for (const x of take(1 << (info - 24), "bad length")) n = (n << 8n) | BigInt(x);
  } else throw new Error("bad length");
  switch (major) {
    case 0: return n;
    case 1: return -1n - n;
    case 2:
    case 3: {
      if (n > BigInt(r.data.length - r.i)) throw new Error("truncated string");
      const raw = take(Number(n), "truncated string").slice();
      if (major === 2) return raw;
      try { return utf8Strict.decode(raw); } catch { throw new Error("text is not valid UTF-8"); }
    }
    case 4: {
      const out = [];
      for (let k = 0n; k < n; k++) out.push(decodeValue(r, depth + 1));
      return out;
    }
    case 5: {
      const map = [];
      for (let k = 0n; k < n; k++) {
        const key = decodeValue(r, depth + 1);
        if (typeof key !== "string") throw new Error("map key must be text");
        if (map.length && keyOrder(map[map.length - 1][0], key) >= 0) {
          throw new Error("input is not canonical DAG-CBOR");
        }
        map.push([key, decodeValue(r, depth + 1)]);
      }
      return { map };
    }
    case 6:
      if (n === 42n) {
        const b = decodeValue(r, depth + 1);
        if (b instanceof Uint8Array && b[0] === 0) return { link: b.slice(1) };
        throw new Error("bad CID link");
      }
  }
  throw new Error(`unsupported major type ${major}`);
}

/** Decode and check the input is the canonical encoding of the decoded value. */
export function decodeDagCbor(data) {
  const r = { data, i: 0 };
  const v = decodeValue(r, 0);
  if (r.i !== data.length) throw new Error("trailing bytes");
  if (!equal(dagCbor(v), data)) throw new Error("input is not canonical DAG-CBOR");
  return v;
}

// ---------------------------------------------------------------------------------------
// CIDs and the readable view
// ---------------------------------------------------------------------------------------

export async function cidOfBytes(encoded) {
  return concat(Uint8Array.from(CID_PREFIX), await sha256(encoded));
}

export function cidStr(cid) {
  let acc = 0, bits = 0, out = "b";
  for (const byte of cid) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += BASE32[(acc >> bits) & 31];
    }
    acc &= (1 << bits) - 1;
  }
  if (bits > 0) out += BASE32[(acc << (5 - bits)) & 31];
  return out;
}

/** Readable JSON view of a decoded record: bytes as {hex}, links as {"/": CID}. */
export function toView(v) {
  if (v === null || typeof v === "boolean" || typeof v === "string") return v;
  if (typeof v === "bigint") return Number.isSafeInteger(Number(v)) ? Number(v) : v.toString();
  if (v instanceof Uint8Array) return { hex: hex(v) };
  if (Array.isArray(v)) return v.map(toView);
  if (v.link) return { "/": cidStr(v.link) };
  return Object.fromEntries(v.map.map(([k, x]) => [k, toView(x)]));
}

// ---------------------------------------------------------------------------------------
// Merkle proofs (RFC 9162)
// ---------------------------------------------------------------------------------------

export async function leafHash(data) {
  return sha256(concat(Uint8Array.of(0), data));
}

async function nodeHash(left, right) {
  return sha256(concat(Uint8Array.of(1), left, right));
}

/** RFC 9162 section 2.1.3.2. Sizes and indexes are BigInt. */
export async function verifyInclusion(leaf, index, size, proof, root) {
  if (index >= size) return false;
  let fn = index, sn = size - 1n, r = leaf;
  for (const p of proof) {
    if (sn === 0n) return false;
    if ((fn & 1n) === 1n || fn === sn) {
      r = await nodeHash(p, r);
      if ((fn & 1n) === 0n) {
        while (fn !== 0n && (fn & 1n) === 0n) { fn >>= 1n; sn >>= 1n; }
      }
    } else {
      r = await nodeHash(r, p);
    }
    fn >>= 1n;
    sn >>= 1n;
  }
  return sn === 0n && equal(r, root);
}

/** RFC 9162 section 2.1.4.2. Sizes are BigInt. */
export async function verifyConsistencyProof(oldSize, newSize, proof, oldRoot, newRoot) {
  if (oldSize === newSize) return proof.length === 0 && equal(oldRoot, newRoot);
  if (!(0n < oldSize && oldSize < newSize) || proof.length === 0) return false;
  const path = (oldSize & (oldSize - 1n)) === 0n ? [oldRoot, ...proof] : [...proof];
  let fn = oldSize - 1n, sn = newSize - 1n;
  while ((fn & 1n) === 1n) { fn >>= 1n; sn >>= 1n; }
  let fr = path[0], sr = path[0];
  for (const c of path.slice(1)) {
    if (sn === 0n) return false;
    if ((fn & 1n) === 1n || fn === sn) {
      fr = await nodeHash(c, fr);
      sr = await nodeHash(c, sr);
      if ((fn & 1n) === 0n) {
        while (fn !== 0n && (fn & 1n) === 0n) { fn >>= 1n; sn >>= 1n; }
      }
    } else {
      sr = await nodeHash(sr, c);
    }
    fn >>= 1n;
    sn >>= 1n;
  }
  return sn === 0n && equal(fr, oldRoot) && equal(sr, newRoot);
}

// ---------------------------------------------------------------------------------------
// Checkpoints, receipts and consistency proofs (spec sections 3-4)
// ---------------------------------------------------------------------------------------

function field(d, k) {
  if (d === null || typeof d !== "object" || !(k in d)) throw new Error(`missing field '${k}'`);
  return d[k];
}

function text(d, k) {
  const v = field(d, k);
  if (typeof v !== "string") throw new Error(`field '${k}' must be text`);
  return v;
}

function uint(d, k) {
  const v = field(d, k);
  if (!Number.isInteger(v) || v < 0) throw new Error(`field '${k}' must be a non-negative integer`);
  return BigInt(v);
}

function hexList(d, k) {
  const v = field(d, k);
  if (!Array.isArray(v)) throw new Error(`field '${k}' must be a list`);
  return v.map((h) => {
    if (typeof h !== "string") throw new Error(`field '${k}' must hold hex strings`);
    return unhex(h);
  });
}

function checkpointFromJson(d) {
  const ts = field(d, "ts");
  const cp = { log: text(d, "log"), size: uint(d, "size"), root: unhex(text(d, "root")) };
  if (!Number.isInteger(ts)) throw new Error("field 'ts' must be an integer");
  return { ...cp, ts: BigInt(ts), keyId: text(d, "key_id"), sig: unb64(text(d, "sig")) };
}

/** Short identifier for a public key: first 16 hex digits of its SHA-256. */
export async function keyId(publicKey) {
  return hex(await sha256(publicKey)).slice(0, 16);
}

export async function verifySignature(publicKey, signature, message) {
  try {
    const key = await subtle.importKey("raw", publicKey, { name: "Ed25519" }, false, ["verify"]);
    return await subtle.verify("Ed25519", key, signature, message);
  } catch (e) {
    if (e && e.name === "NotSupportedError") throw new Error("this browser cannot check Ed25519 signatures; please use a current version");
    return false;
  }
}

async function checkpointVerifies(cp, publicKey) {
  if (cp.keyId !== (await keyId(publicKey))) return false;
  const body = { map: [["log", cp.log], ["size", cp.size], ["root", cp.root], ["ts", cp.ts]] };
  return verifySignature(publicKey, cp.sig, concat(CHECKPOINT_CONTEXT, dagCbor(body)));
}

/** Check an aeos-receipt/v0 document offline against a trusted public key (bytes). */
export async function verifyReceipt(receipt, publicKey) {
  if (receipt === null || typeof receipt !== "object" || receipt.type !== "aeos-receipt/v0") {
    return ["not an aeos-receipt/v0 document"];
  }
  let cp, raw, index, proof;
  try {
    cp = checkpointFromJson(field(receipt, "checkpoint"));
    raw = unb64(text(receipt, "record"));
    index = uint(receipt, "index");
    proof = hexList(receipt, "inclusion_proof");
  } catch (e) {
    return [`malformed receipt: ${e.message}`];
  }
  const problems = [];
  if (cp.log !== receipt.log_id) problems.push("checkpoint belongs to a different log");
  if (!(await checkpointVerifies(cp, publicKey))) {
    problems.push("checkpoint signature does not verify with the given public key");
  }
  try {
    decodeDagCbor(raw);
  } catch (e) {
    problems.push(`record bytes are not canonical: ${e.message}`);
  }
  const cid = await cidOfBytes(raw);
  if (cidStr(cid) !== receipt.cid) problems.push("record CID does not match the record bytes");
  if (!(await verifyInclusion(await leafHash(cid), index, cp.size, proof, cp.root))) {
    problems.push("inclusion proof does not lead to the checkpoint root");
  }
  return problems;
}

/** Check that a newer checkpoint extends an older one (nothing rewritten or removed). */
export async function verifyConsistency(doc, publicKey) {
  let oldCp, newCp, proof;
  try {
    oldCp = checkpointFromJson(field(doc, "old"));
    newCp = checkpointFromJson(field(doc, "new"));
    proof = hexList(doc, "proof");
  } catch (e) {
    return [`malformed consistency proof: ${e.message}`];
  }
  const problems = [];
  if (oldCp.log !== newCp.log) problems.push("checkpoints belong to different logs");
  for (const [name, cp] of [["old", oldCp], ["new", newCp]]) {
    if (!(await checkpointVerifies(cp, publicKey))) {
      problems.push(`${name} checkpoint signature does not verify`);
    }
  }
  if (!(await verifyConsistencyProof(oldCp.size, newCp.size, proof, oldCp.root, newCp.root))) {
    problems.push("the newer checkpoint does not extend the older one");
  }
  return problems;
}

/** The readable record inside a receipt, or null if its bytes do not decode. */
export function receiptRecord(receipt) {
  try {
    return toView(decodeDagCbor(unb64(receipt.record)));
  } catch {
    return null;
  }
}

/** A public key given as hex, or as the text of a log.json file. */
export function parsePublicKey(input) {
  const s = String(input).trim();
  let h = s;
  if (s.startsWith("{")) {
    try {
      h = String(JSON.parse(s).public_key || "");
    } catch {
      throw new Error("the public key file is not valid JSON");
    }
  }
  const key = unhex(h);
  if (key.length !== 32) throw new Error("a public key is 64 hexadecimal characters");
  return key;
}
