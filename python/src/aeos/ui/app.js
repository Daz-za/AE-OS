// The local page for `aeos ui`. Talks to the server in ui/__init__.py.
import { KINDS, mountCheck, recordDetails, when } from "./check.js";
import { workspaceViews } from "./workspace.js";

const code = new URLSearchParams(location.hash.slice(1)).get("code") || sessionStorage.getItem("aeos-code") || "";
try { sessionStorage.setItem("aeos-code", code); } catch { /* private window */ }
history.replaceState(null, "", "/");

const $ = (id) => document.getElementById(id);
let state = null, start = 0, checkMounted = false, wsv = null;

async function api(path, body) {
  const res = await fetch(path, {
    method: body === undefined ? "GET" : "POST",
    headers: { "X-AEOS-Code": code, "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const doc = await res.json().catch(() => ({ error: `The page got an unexpected answer (${res.status}).` }));
  if (!res.ok) throw new Error(doc.error || `Request failed (${res.status}).`);
  return doc;
}

function showError(e) {
  $("error").textContent = e ? e.message || String(e) : "";
  $("error").hidden = !e;
}

async function act(button, fn) {
  showError(null);
  if (button) button.disabled = true;
  try {
    await fn();
  } catch (e) {
    showError(e);
  } finally {
    if (button) button.disabled = false;
  }
}

function show(view) {
  for (const s of document.querySelectorAll(".view")) s.hidden = s.id !== `view-${view}`;
  for (const t of document.querySelectorAll(".tab")) t.classList.toggle("active", t.dataset.view === view);
  if (view === "records") loadRecords();
  if (view === "agents") loadAgents();
  if (view === "decisions") loadDecisions();
  if (view === "books") loadBooks();
  if (view === "arch") wsv.loadArch();
  if (view === "setup") wsv.loadSetup();
  if (view === "close") wsv.loadClose();
  if (view === "try") wsv.loadTry();
  if (view === "modules") wsv.loadModules();
  if (view === "edit") wsv.loadEdit();
  if (view === "check" && !checkMounted && state && state.status) {
    mountCheck($("check"), { publicKey: state.status.public_key });
    checkMounted = true;
  }
}

function download(name, doc) {
  const blob = new Blob([JSON.stringify(doc, null, 2) + "\n"], { type: "application/json" });
  const a = Object.assign(document.createElement("a"), { href: URL.createObjectURL(blob), download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;

function render(s) {
  state = s;
  for (const n of document.querySelectorAll(".ws-only")) n.hidden = !s.workspace;
  // The evidence views need a log; a workspace has one once its log step has run.
  for (const t of document.querySelectorAll("#tabs .tab")) t.hidden = !s.status && t.dataset.view !== "start";
  $("tabs").hidden = !s.folder;
  $("tab-audit").hidden = !s.evidence || !s.status;
  $("seal").hidden = !s.workspace;
  document.querySelectorAll(".cwd").forEach((n) => { n.textContent = s.cwd; });
  drawContinue(s);
  if (!s.folder) return show("start");
  const st = s.status;
  if (!st) return;
  $("log-id").textContent = s.workspace ? `${s.organization}: the log` : `Log ${st.log_id}`;
  $("log-folder").textContent = s.folder;
  const unsealed = st.records - st.last_checkpoint_size;
  const rows = [
    ["Records", `${plural(st.records, "record", "records")} from ${plural(st.agents, "identity", "identities")} (people and agents), across ${plural(st.sessions, "session", "sessions")}`],
    ["Tool calls", `${st.tool_calls} recorded, ${st.refused_calls} refused by policy, ${st.failed_calls} ended in an error`],
    ["Latest record", st.last_record ? when(st.last_record) : "None yet"],
    ["Signed checkpoints", st.checkpoints
      ? `${st.checkpoints}; the latest covers ${plural(st.last_checkpoint_size, "record", "records")} (${when(st.last_checkpoint_ts)})`
      : "None yet"],
    ["Not yet covered", unsealed > 0 ? `${plural(unsealed, "newer record", "newer records")}; sign a checkpoint to cover them` : "Every record is covered by a signed checkpoint"],
    ["Signing key", s.key ? s.key : "Not available. This page can show and check the log, but cannot sign."],
  ];
  $("summary").replaceChildren(...rows.flatMap(([k, v]) => {
    const dt = document.createElement("dt"), dd = document.createElement("dd");
    dt.textContent = k;
    dd.textContent = v;
    return [dt, dd];
  }));
  $("sign").disabled = !st.can_sign || unsealed <= 0;
  $("growth").disabled = st.checkpoints < 2;
  $("public-key").textContent = st.public_key;
  if (s.story) { renderStory(s.story, s.story_kind); $("story").hidden = false; }
  if (s.next_steps) { $("next-steps-text").textContent = s.next_steps; $("next-steps").hidden = false; }
  if (checkMounted) { mountCheck($("check"), { publicKey: st.public_key }); }
}

// Workspaces already in this folder, so someone who closed the page can go back to theirs.
function drawContinue(s) {
  const list = s.workspaces || [];
  $("continue").hidden = !list.length || !!s.folder;
  $("continue-list").replaceChildren(...list.map((f) => {
    const b = el("button", { textContent: `Continue ${f.split(/[\\/]/).pop()}` });
    b.addEventListener("click", () => act(b, async () => fresh(await api("/api/open", { folder: f }))));
    return b;
  }));
}

// The demo's narration, written for a terminal, as numbered steps with paragraphs.
function renderStory(text, kind) {
  const steps = [];
  for (const line of text.split("\n")) {
    const m = line.match(/^(\d+)\. (.*)$/);
    if (m) steps.push({ title: m[2], body: [] });
    else if (steps.length && line.startsWith("   ")) steps[steps.length - 1].body.push(line.trim());
  }
  const ol = document.createElement("ol");
  for (const st of steps) {
    const li = document.createElement("li");
    const strong = Object.assign(document.createElement("strong"), { textContent: st.title });
    li.append(strong, Object.assign(document.createElement("p"), { textContent: st.body.join(" ") }));
    ol.append(li);
  }
  const intro = Object.assign(document.createElement("p"), {
    textContent: kind === "full"
      ? "Acme, a fictional company, lets an AI agent pay supplier invoices and book them, and an auditor checks the evidence. See who acted under Agents, what was refused and why under Decisions, the journal under Books, and run the auditor's check under Audit."
      : "An AI agent pays a supplier invoice at Acme, a fictional company, and an auditor checks the evidence. Look through the records, or try checking payment-receipt.json under Check a receipt. It is in the aeos-demo folder, one level up from the log folder.",
  });
  $("story-text").replaceChildren(intro, ol);
}

function fresh(s) {
  $("story").hidden = true;
  $("next-steps").hidden = true;
  $("verify-result").replaceChildren();
  $("verify-result").className = "chk-result";
  $("audit-result").replaceChildren();
  $("audit-result").className = "chk-result";
  $("decisions-all").checked = false;
  $("decision-trace").hidden = true;
  start = 0;
  render(s);
  show(s.workspace ? "setup" : "overview");
}

async function showChecks(ref, box, button) {
  await act(button, async () => {
    wsv.renderTrace(box, await api(`/api/trace?ref=${ref}`));
    box.scrollIntoView({ behavior: "smooth", block: "nearest" });
  });
}

async function loadRecords() {
  await act(null, async () => {
    const r = await api(`/api/records?start=${start}`);
    const body = $("record-rows");
    body.replaceChildren();
    for (const item of r.records) {
      const rec = item.record, b = rec.body || {};
      const result = b.decision || b.outcome || "";
      const tr = document.createElement("tr");
      tr.className = "row";
      tr.tabIndex = 0;
      const cells = [String(item.index), when(rec.ts), KINDS[rec.kind] || rec.kind, rec.agent || "", rec.subject || "", result];
      const labels = ["#", "When", "What happened", "Who", "Tool or system", "Result"];
      cells.forEach((text, i) => {
        const td = document.createElement("td");
        td.textContent = text;
        td.dataset.label = labels[i];
        if (i === 3) td.className = "who";
        if (i === 5 && ["deny", "escalate", "error"].includes(text)) td.className = `tag-${text}`;
        tr.append(td);
      });
      const toggle = () => {
        const next = tr.nextElementSibling;
        if (next && next.classList.contains("detail")) return next.remove();
        const d = document.createElement("tr"), td = document.createElement("td");
        d.className = "detail";
        td.colSpan = 6;
        const btn = document.createElement("button");
        btn.className = "primary";
        btn.textContent = "Download a receipt for this record";
        const hint = Object.assign(document.createElement("p"), { className: "muted", textContent: "If no signed checkpoint covers this record yet, one is signed first." });
        btn.addEventListener("click", () => act(btn, async () => {
          download(`receipt-${item.index}.json`, await api(`/api/receipt?index=${item.index}`));
          render(await api("/api/state"));
        }));
        const cid = document.createElement("p");
        cid.className = "path";
        cid.textContent = `Fingerprint, a code computed from the record's exact content: ${item.cid}`;
        td.append(recordDetails(rec), cid, btn, hint);
        if (rec.kind === "tool.call" || rec.kind === "policy.decision") {
          const box = el("div", { className: "trace" });
          const checks = el("button", { textContent: "Show each check this call passed" });
          checks.addEventListener("click", () => showChecks(item.index, box, checks));
          td.append(checks, box);
        }
        d.append(td);
        tr.after(d);
      };
      tr.addEventListener("click", toggle);
      tr.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); } });
      body.append(tr);
    }
    const last = r.start + r.records.length;
    $("page-info").textContent = r.total ? `Showing records ${r.start} to ${last - 1} (${r.total} in total; numbering starts at 0)` : "No records yet";
    $("prev").disabled = r.start === 0;
    $("next").disabled = last >= r.total;
  });
}

const el = (tag, props = {}, ...kids) => {
  const n = Object.assign(document.createElement(tag), props);
  n.append(...kids.filter((k) => k !== null && k !== undefined && k !== ""));
  return n;
};
const WORDS = { allow: "Allowed", deny: "Refused", escalate: "Sent to a person" };

async function loadAgents() {
  await act(null, async () => {
    const r = await api("/api/agents");
    const list = $("agents-list");
    if (!r.identities.length) return list.replaceChildren(el("p", { className: "muted", textContent: "No one has acted in this log yet." }));
    list.replaceChildren(...r.identities.map((a) => {
      const facts = [];
      const how = a.connected.filter((c) => c !== "not stated").map((c) => (c === "x509-svid-mtls" ? "a certificate over mutual TLS" : c));
      if (a.sessions) facts.push(`Connected ${plural(a.sessions, "time", "times")}${how.length ? `, authenticated by ${how.join(", ")}` : ""}`);
      if (a.on_behalf_of.length) facts.push(`Acted for ${a.on_behalf_of.join(", ")}`);
      if (a.calls) facts.push(`Tool calls (${a.calls}): ${Object.entries(a.tools).map(([t, n]) => `${t} (${n})`).join(", ")}`);
      if (a.refused) facts.push(`Calls refused: ${a.refused}`);
      if (a.escalated) facts.push(`Calls sent to a person for approval: ${a.escalated}`);
      if (a.approvals) facts.push(`Approvals given: ${a.approvals}`);
      if (a.period_changes) facts.push(`Signed ${plural(a.period_changes, "period change", "period changes")}`);
      if (a.entries) facts.push(`Wrote ${plural(a.entries, "journal entry", "journal entries")}`);
      facts.push(`Active ${when(a.first)} to ${when(a.last)}`);
      return el("article", { className: "item" },
        el("div", { className: "item-head" }, el("span", { className: `badge role-${a.role}`, textContent: a.role }), el("strong", { className: "id", textContent: a.id })),
        el("ul", {}, ...facts.map((f) => el("li", { textContent: f }))));
    }));
  });
}

async function loadDecisions() {
  await act(null, async () => {
    const r = await api(`/api/decisions?all=${$("decisions-all").checked ? 1 : 0}`);
    $("decision-counts").replaceChildren(...Object.entries(r.counts).flatMap(([check, c]) => [
      el("dt", { textContent: check }),
      el("dd", { textContent: Object.entries(c).map(([d, n]) => `${n} ${(WORDS[d] || d).toLowerCase()}`).join(", ") }),
    ]));
    const list = $("decisions-list");
    if (!r.decisions.length) return list.replaceChildren(el("p", { className: "muted", textContent: Object.keys(r.counts).length ? "Nothing was refused or sent to a person." : "No decisions in this log yet." }));
    list.replaceChildren(...r.decisions.map((d) => {
      const who = `${d.agent} called ${d.tool}${d.on_behalf_of ? ` for ${d.on_behalf_of}` : ""}${d.amount ? `, ${d.amount}` : ""}`;
      const approvals = d.approvals.map((x) => el("p", { className: "approval", textContent: `${x.answer === "approve" ? "Approved" : "Rejected"} by ${x.by} (record ${x.index})` }));
      return el("article", { className: "item" },
        el("div", { className: "item-head" },
          el("span", { className: `badge tag-${d.decision}`, textContent: WORDS[d.decision] || d.decision }),
          el("strong", { textContent: d.check }),
          el("span", { className: "muted", textContent: `Record ${d.index} · ${when(d.time)}` })),
        el("p", { className: "id", textContent: who }),
        d.reasons.length ? el("ul", {}, ...d.reasons.map((x) => el("li", { textContent: x }))) : null,
        ...approvals,
        d.call != null ? (() => {
          const b = el("button", { className: "quiet", textContent: "Show each check" });
          b.addEventListener("click", () => showChecks(d.call, $("decision-trace"), b));
          return b;
        })() : null);
    }));
  });
}

function table(head, rows) {
  const cell = (c, i) => el("td", { textContent: c, className: i > 0 ? "num" : "" });
  return el("div", { className: "table-wrap" }, el("table", { className: "ledger" },
    el("thead", {}, el("tr", {}, ...head.map((h, i) => el("th", { textContent: h, className: i > 0 ? "num" : "" })))),
    el("tbody", {}, ...rows.map((r) => el("tr", { className: r.cls || "" },
      ...(r.span ? [el("td", { textContent: r.span, colSpan: head.length })] : r.cells.map(cell)))))));
}

async function loadBooks() {
  await act(null, async () => {
    if (state && state.workspace) await wsv.drawPeriods();
    const r = await api("/api/books");
    const body = $("books-body");
    if (!r.ledgers.length && !r.refused.length) return body.replaceChildren(el("p", { className: "muted", textContent: "This log holds no books of account. The guided tour and the narrated example both keep books." }));
    const parts = [];
    for (const led of r.ledgers) {
      parts.push(el("h2", { textContent: `${led.entity} · ${led.ledger}${led.currency ? ` · ${led.currency}` : ""}` }));
      if (led.periods.length) {
        parts.push(el("div", { className: "periods" }, ...led.periods.map((p) =>
          el("span", { className: `badge period-${p.state}`, textContent: `${p.name}: ${p.state}`, title: `Signed by ${p.by}` }))));
      }
      parts.push(el("h3", { textContent: "Journal" }));
      const rows = [];
      for (const e of led.entries) {
        rows.push({ cls: "entry", span: `${e.document} · ${e.date} · ${e.text}${e.reverses ? ` (reverses ${e.reverses})` : ""}` });
        for (const ln of e.lines) rows.push({ cells: [`${ln.account} ${ln.name}`, ln.debit, ln.credit] });
      }
      parts.push(table(["Entry and account", "Debit", "Credit"], rows));
      parts.push(el("h3", { textContent: "Trial balance" }));
      const tb = led.trial_balance.map((x) => ({ cells: [`${x.account} ${x.name}`, x.debit, x.credit] }));
      tb.push({ cls: "total", cells: ["Total", led.totals.debit, led.totals.credit] });
      parts.push(table(["Account", "Debit", "Credit"], tb));
      if (!led.totals.balanced) parts.push(el("p", { className: "error", textContent: "The trial balance does not balance." }));
    }
    if (r.refused.length) {
      parts.push(el("h3", { textContent: "Entries the books refused" }));
      parts.push(el("ul", {}, ...r.refused.map((x) => el("li", { textContent: `Record ${x.index}, ${when(x.time)}: ${x.reasons.join("; ")}` }))));
    }
    body.replaceChildren(...parts);
  });
}

function formData(form) {
  return Object.fromEntries([...new FormData(form)].map(([k, v]) => [k, String(v).trim()]).filter(([, v]) => v));
}

document.addEventListener("DOMContentLoaded", async () => {
  wsv = workspaceViews({ api, act, el, show, refresh: async () => render(await api("/api/state")) });
  for (const id of ["new-ws-form", "new-acme-form"]) $(id).addEventListener("submit", (e) => {
    e.preventDefault();
    act(e.submitter, async () => fresh(await api("/api/new-workspace", formData(e.target))));
  });
  $("seal").addEventListener("click", (e) => act(e.target, async () => {
    await api("/api/ws/seal", {});
    render(await api("/api/state"));
  }));
  for (const t of document.querySelectorAll(".tab, .jump")) t.addEventListener("click", () => show(t.dataset.view));
  $("run-demo").addEventListener("click", (e) => act(e.target, async () => fresh(await api("/api/demo", {}))));
  $("run-full").addEventListener("click", (e) => act(e.target, async () => {
    e.target.textContent = "Running the example…";
    try { fresh(await api("/api/full-demo", {})); } finally { e.target.textContent = "Run the narrated example"; }
  }));
  $("decisions-all").addEventListener("change", loadDecisions);
  $("run-audit").addEventListener("click", (e) => act(e.target, async () => {
    const r = await api("/api/audit", {});
    const box = $("audit-result");
    box.className = "chk-result " + (r.ok ? "chk-ok" : "chk-bad");
    box.replaceChildren(
      el("p", { className: "chk-title", textContent: r.ok ? "Valid. Every audit check passed." : "Not valid." }),
      ...(r.problems.length ? [el("ul", {}, ...r.problems.map((x) => el("li", { textContent: x })))] : []),
      el("ul", {}, ...r.findings.map((x) => el("li", { textContent: x }))),
      el("p", { textContent: (r.ok ? "What this means: " : "What to do: ") + r.meaning }),
    );
  }));
  $("open-form").addEventListener("submit", (e) => {
    e.preventDefault();
    act(e.submitter, async () => fresh(await api("/api/open", formData(e.target))));
  });
  $("create-form").addEventListener("submit", (e) => {
    e.preventDefault();
    act(e.submitter, async () => fresh(await api("/api/create", formData(e.target))));
  });
  $("verify").addEventListener("click", (e) => act(e.target, async () => {
    const r = await api("/api/verify", {});
    const box = $("verify-result");
    box.className = "chk-result " + (r.ok ? "chk-ok" : "chk-bad");
    const p = (cls, text) => Object.assign(document.createElement("p"), { className: cls, textContent: text });
    const list = document.createElement("ul");
    list.append(...r.problems.map((x) => Object.assign(document.createElement("li"), { textContent: x })));
    box.replaceChildren(
      p("chk-title", r.ok ? `Valid. ${plural(r.records, "record", "records")} and ${plural(r.checkpoints, "signed checkpoint", "signed checkpoints")} checked.` : "Not valid."),
      ...(r.problems.length ? [list] : []),
      p("", (r.ok ? "What this means: " : "What to do: ") + r.meaning),
    );
  }));
  $("sign").addEventListener("click", (e) => act(e.target, async () => render(await api("/api/checkpoint", {}))));
  $("growth").addEventListener("click", (e) => act(e.target, async () => {
    download("growth-proof.json", await api("/api/growth"));
  }));
  $("copy-key").addEventListener("click", (e) => act(e.target, async () => {
    await navigator.clipboard.writeText($("public-key").textContent);
    e.target.textContent = "Copied";
    setTimeout(() => { e.target.textContent = "Copy"; }, 1500);
  }));
  $("prev").addEventListener("click", () => { start = Math.max(0, start - 50); loadRecords(); });
  $("next").addEventListener("click", () => { start += 50; loadRecords(); });

  const select = $("mode");
  await act(null, async () => {
    const s = await api("/api/state");
    for (const [k, v] of Object.entries(s.modes)) {
      select.append(Object.assign(document.createElement("option"), { value: k, textContent: v, selected: k === "later" }));
    }
    render(s);
    if (s.folder) show(s.workspace ? "setup" : "overview");
  });
});
