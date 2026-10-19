// The local page for `aeos ui`. Talks to the server in ui/__init__.py.
import { KINDS, mountCheck, recordDetails, when } from "./check.js";

const code = new URLSearchParams(location.hash.slice(1)).get("code") || sessionStorage.getItem("aeos-code") || "";
try { sessionStorage.setItem("aeos-code", code); } catch { /* private window */ }
history.replaceState(null, "", "/");

const $ = (id) => document.getElementById(id);
let state = null, start = 0, checkMounted = false;

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
  $("tabs").hidden = !s.folder;
  $("cwd").textContent = s.cwd;
  if (!s.folder) return show("start");
  const st = s.status;
  $("log-id").textContent = `Log ${st.log_id}`;
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
  if (s.story) { renderStory(s.story); $("story").hidden = false; }
  if (s.next_steps) { $("next-steps-text").textContent = s.next_steps; $("next-steps").hidden = false; }
  if (checkMounted) { mountCheck($("check"), { publicKey: st.public_key }); }
}

// The demo's narration, written for a terminal, as numbered steps with paragraphs.
function renderStory(text) {
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
    textContent: "An AI agent pays a supplier invoice at Acme, a fictional company, and an auditor checks the evidence. Look through the records, or try checking payment-receipt.json under Check a receipt. It is in the aeos-demo folder, one level up from the log folder.",
  });
  $("story-text").replaceChildren(intro, ol);
}

function fresh(s) {
  $("story").hidden = true;
  $("next-steps").hidden = true;
  $("verify-result").replaceChildren();
  $("verify-result").className = "chk-result";
  start = 0;
  render(s);
  show("overview");
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

function formData(form) {
  return Object.fromEntries([...new FormData(form)].map(([k, v]) => [k, String(v).trim()]).filter(([, v]) => v));
}

document.addEventListener("DOMContentLoaded", async () => {
  for (const t of document.querySelectorAll(".tab")) t.addEventListener("click", () => show(t.dataset.view));
  $("run-demo").addEventListener("click", (e) => act(e.target, async () => fresh(await api("/api/demo", {}))));
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
    if (s.folder) show("overview");
  });
});
