// "Check a receipt": a self-contained panel that checks receipts and growth proofs in
// the browser with verify.js. Used by `aeos-receipts ui` and by ae-os.org/verify.
//
//   import { mountCheck } from "./check.js";
//   const panel = mountCheck(document.getElementById("check"), { publicKey: "hex, optional" });
//   panel.load(receiptJsonText, publicKeyText, "file name shown");   // e.g. an example

import { parsePublicKey, receiptRecord, verifyConsistency, verifyReceipt } from "./verify.js";

const MEANING = {
  receipt: [
    "This record is in the log exactly as shown, and the log's owner signed a checkpoint that includes it.",
    "Do not rely on this receipt. Ask the log's owner for a fresh receipt, and check that you used their public key from a source you trust.",
  ],
  consistency: [
    "The newer checkpoint contains every record of the older one, unchanged. Nothing was removed or rewritten in between.",
    "The log's history differs from what you were shown before. Keep both checkpoints as evidence and raise it with the log's owner.",
  ],
};

export const KINDS = {
  "session.start": "Session started",
  "session.end": "Session ended",
  "tool.call": "Tool call requested",
  "tool.result": "Tool call finished",
  "policy.decision": "Policy decision",
  approval: "Approval",
};

export function when(ms) {
  if (typeof ms !== "number") return "";
  return new Date(ms).toISOString().replace("T", " ").slice(0, 19) + " UTC";
}

function el(tag, attrs = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "text") e.textContent = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v);
  }
  for (const c of children) if (c != null) e.append(c);
  return e;
}

/** A definition list describing one record, for people rather than machines. */
export function recordDetails(rec) {
  const rows = [
    ["What happened", KINDS[rec.kind] || rec.kind],
    ["When", when(rec.ts)],
    ["Who", rec.agent],
    ["On behalf of", rec.obo],
    ["Tool or system", rec.subject],
  ];
  const body = rec.body || {};
  if (body.decision) rows.push(["Decision", body.decision + (body.reasons ? ` (${body.reasons.join(", ")})` : "")]);
  if (body.policy) rows.push(["Policy", body.policy]);
  if (body.outcome) rows.push(["Outcome", body.outcome]);
  if (body.args_sha256) rows.push(["Fingerprint of the request", body.args_sha256.hex]);
  if (body.result_sha256) rows.push(["Fingerprint of the result", body.result_sha256.hex]);
  const dl = el("dl", { class: "chk-dl" });
  for (const [k, v] of rows) {
    if (v == null || v === "") continue;
    dl.append(el("dt", { text: k }), el("dd", { text: String(v) }));
  }
  return dl;
}

function readFile(file) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(String(r.result));
    r.onerror = () => reject(r.error);
    r.readAsText(file);
  });
}

function dropZone(label, hint, onText) {
  const input = el("input", { type: "file", accept: ".json,.txt,application/json,text/plain", class: "chk-file" });
  const name = el("span", { class: "chk-name", text: "No file chosen" });
  const zone = el("label", { class: "chk-drop" },
    el("strong", { text: label }), el("span", { class: "chk-hint", text: hint }), name, input);
  const take = async (file) => {
    name.textContent = file.name;
    onText(await readFile(file));
  };
  input.addEventListener("change", () => input.files[0] && take(input.files[0]));
  zone.addEventListener("dragover", (e) => { e.preventDefault(); zone.classList.add("chk-over"); });
  zone.addEventListener("dragleave", () => zone.classList.remove("chk-over"));
  zone.addEventListener("drop", (e) => {
    e.preventDefault();
    zone.classList.remove("chk-over");
    if (e.dataTransfer.files[0]) take(e.dataTransfer.files[0]);
  });
  return { zone, name };
}

export function mountCheck(root, opts = {}) {
  let docText = "";
  const keyBox = el("textarea", {
    class: "chk-key", rows: "2", spellcheck: "false",
    placeholder: "Paste the public key (64 letters and digits), or drop public-key.txt or log.json here",
    "aria-label": "Public key",
  });
  if (opts.publicKey) keyBox.value = opts.publicKey;
  const doc = dropZone("Receipt or growth proof",
    "Drop the .json file here, or click to choose it", (t) => { docText = t; run(); });
  const keyFile = el("input", { type: "file", accept: ".json,.txt", class: "chk-file", "aria-label": "Public key file" });
  keyFile.addEventListener("change", async () => {
    if (keyFile.files[0]) { keyBox.value = (await readFile(keyFile.files[0])).trim(); run(); }
  });
  keyBox.addEventListener("dragover", (e) => e.preventDefault());
  keyBox.addEventListener("drop", async (e) => {
    e.preventDefault();
    if (e.dataTransfer.files[0]) { keyBox.value = (await readFile(e.dataTransfer.files[0])).trim(); run(); }
  });
  keyBox.addEventListener("change", run);
  const result = el("div", { class: "chk-result", "aria-live": "polite" });

  async function run() {
    result.replaceChildren();
    result.className = "chk-result";
    if (!docText) return;
    let d, key;
    try {
      d = JSON.parse(docText);
    } catch {
      return show(false, "This file is not a receipt or growth proof (it is not valid JSON).");
    }
    if (!keyBox.value.trim()) return show(null, "Now add the log's public key to check the file against.");
    try {
      key = parsePublicKey(keyBox.value);
    } catch (e) {
      return show(null, `The public key could not be read: ${e.message}.`);
    }
    const kind = d && d.type === "aeos-receipt/v0" ? "receipt" : d && d.old && d.new ? "consistency" : null;
    if (!kind) return show(false, "This file is neither a receipt nor a growth proof from AE-OS Receipts.");
    let problems;
    try {
      problems = kind === "receipt" ? await verifyReceipt(d, key) : await verifyConsistency(d, key);
    } catch (e) {
      return show(null, e.message);
    }
    const [good, bad] = MEANING[kind];
    const ok = problems.length === 0;
    const title = ok
      ? (kind === "receipt"
        ? `Valid. Record ${d.index} is in log ${d.log_id}, covered by a checkpoint of ${d.checkpoint.size} records signed ${when(d.checkpoint.ts)}.`
        : `Valid. The checkpoint of ${d.new.size} records extends the earlier one of ${d.old.size}.`)
      : "Not valid.";
    show(ok, title, ok ? good : bad, problems);
    if (kind === "receipt") {
      const rec = receiptRecord(d);
      if (rec) {
        result.append(el("h4", { text: ok ? "The record" : "The record, as the file shows it (not proven)" }), recordDetails(rec));
      }
    }
  }

  function show(ok, title, meaning, problems = []) {
    result.className = "chk-result " + (ok === true ? "chk-ok" : ok === false ? "chk-bad" : "chk-wait");
    result.append(el("p", { class: "chk-title", text: title }));
    if (problems.length) {
      result.append(el("ul", {}, ...problems.map((p) => el("li", { text: p }))));
    }
    if (meaning) result.append(el("p", { text: (ok ? "What this means: " : "What to do: ") + meaning }));
  }

  root.replaceChildren(
    doc.zone,
    el("div", { class: "chk-keyrow" },
      el("label", { class: "chk-label", text: "The log's public key" }),
      keyBox,
      el("label", { class: "chk-keyfile" }, "Or choose the key file: ", keyFile)),
    el("p", { class: "chk-note", text: "Get the public key from the log's owner through a channel you trust, such as their website or a known email address. The check runs on this device, and the files stay here." }),
    result,
  );
  return {
    check: run,
    load(text, key, name) {
      docText = text;
      doc.name.textContent = name || "Loaded file";
      if (key != null) keyBox.value = key.trim();
      return run();
    },
  };
}
