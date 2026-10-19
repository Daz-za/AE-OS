// The workspace views of `aeos ui`: the architecture, setting the company up step by
// step, the film's close as real calls, a single call, the modules, and the file itself.
// app.js passes in its helpers; this module owns these views and the trace display.
import { createDiagram } from "./diagram.js";
import { KINDS } from "./check.js";

const SITE = "https://ae-os.org";
const SOURCE = "https://github.com/Daz-za/ae-os/blob/main/python/src/aeos";
const STEP_ICON = { pass: "✓", fail: "✕", wait: "…", skip: "–" };
const OUTCOME = {
  done: ["Done", "tag-allow", "Every check passed and the tool ran."],
  waiting: ["Waiting for approval", "tag-escalate", "The rules sent this call to a person. It has not run."],
  answered: ["Answered by a person", "tag-escalate", "This call waited for a person, who answered it. The agent then repeated the call with the answer."],
  refused: ["Refused", "tag-deny", "A check refused the call. Nothing ran past that point."],
};
const STATE_WORD = { done: "Done", changed: "Changed", todo: "To do" };
const MORE_KINDS = { "journal.entry": "Journal entry", "period.transition": "Period change", "policy.decision": "Decision" };

export function workspaceViews({ api, act, el, show, refresh }) {
  let ws = null;                  // what /api/ws returned
  let draft = null;               // the workspace as edited under Set up
  let dirty = false;
  let current = "organization";   // the setup step on screen
  const diagrams = {};
  const played = new Set();       // calls already shown travelling through the diagram
  const results = {};             // chapter id -> lines shown under it
  let feedAt = null, feedTimer = null;
  const $ = (id) => document.getElementById(id);

  // ---- helpers ----------------------------------------------------------------------
  const button = (text, fn, cls = "") => {
    const b = el("button", { type: "button", textContent: text, className: cls });
    b.addEventListener("click", fn);
    return b;
  };
  const out = (href, text) => el("a", { href, textContent: text, target: "_blank", rel: "noopener" });
  const howLink = (section) => out(`${SITE}/how-it-works`, `How it works: ${section} ↗`);
  const filmLink = (n) => out(`${SITE}/#film-${n}`, `In the film: chapter ${n} ↗`);
  const currency = () => ((ws && ws.running.books) || {}).currency || "USD";
  const money = (minor) => `${currency()} ${(minor / 100).toLocaleString("en-US", { minimumFractionDigits: 2 })}`;
  const shortHex = (h, n = 16) => (h ? `${String(h).slice(0, n)}…` : "");
  const time = (ms) => new Date(ms).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
  const personName = (id) => ((ws.running.people || []).find((p) => p.id === id) || {}).name || id;
  const kv = (rows) => el("dl", { className: "summary" }, ...rows.filter(Boolean).flatMap(([k, v]) => [el("dt", { textContent: k }), el("dd", {}, v)]));
  const code = (text) => el("pre", { className: "code", textContent: text });
  const mono = (text) => el("span", { className: "mono", textContent: text });
  const chip = (text, cls = "") => el("span", { className: `pill ${cls}`, textContent: text });

  async function load() {
    ws = await api("/api/ws");
    if (!dirty) draft = structuredClone(ws.doc);
    for (const d of Object.values(diagrams)) d.draw(ws);
    return ws;
  }

  function diagram(name, host, opts = {}) {
    if (!diagrams[name]) diagrams[name] = createDiagram($(host), opts);
    if (ws) diagrams[name].draw(ws);
    return diagrams[name];
  }

  function play(answer, ctx) {
    if (!answer || !answer.trace) return;
    played.add(answer.trace.call);
    for (const d of Object.values(diagrams)) d.play(answer.trace, ctx);
  }

  const notReady = () => (ws.serving ? null : el("div", { className: "notice" },
    el("p", { textContent: "The gateway is not running yet. Set the workspace up first; it takes a few seconds." }),
    el("div", { className: "actions tight" }, button("Set up everything", (e) => setupAll(e.target), "primary"),
      button("Go to Set up", () => show("setup")))));

  async function setupAll(btn) {
    await act(btn, async () => {
      if (btn) btn.textContent = "Setting up…";
      try {
        await api("/api/ws/step", { step: "gateway" });
      } finally {
        if (btn) btn.textContent = "Set up everything";
      }
      await load();
      await refresh();
      const view = document.querySelector("main > .view:not([hidden])");
      if (view) show(view.id.replace("view-", ""));
    });
  }

  // ---- the architecture -------------------------------------------------------------
  async function loadArch() {
    await act(null, async () => {
      await load();
      const d = diagram("arch", "arch-diagram", { onPick: pickNode });
      d.setSteps(ws.steps);
      const done = ws.steps.filter((s) => s.state === "done").length;
      $("arch-title").textContent = `${ws.running.organization.name} architecture`;
      $("arch-status").textContent = ws.serving
        ? `Running. The gateway listens on 127.0.0.1:${ws.port}.`
        : `${done} of ${ws.steps.length} setup steps done.`;
      startFeed();
    });
  }

  function pickNode({ step, layer }) {
    const s = ws.steps.find((x) => x.id === step);
    if (!s) return;
    diagrams.arch.highlight(step);
    const box = $("arch-detail");
    box.replaceChildren(
      el("div", { className: "item-head" }, chip(layer[0].toUpperCase() + layer.slice(1), `lay-${layer}`), el("strong", { textContent: s.title }),
        el("span", { className: `badge state-${s.state}`, textContent: STATE_WORD[s.state] })),
      el("p", { textContent: s.text }),
      el("p", { className: "links" }, s.section ? howLink(s.section) : null, s.film ? filmLink(s.film) : null),
      button(`Open step ${ws.steps.indexOf(s) + 1} under Set up`, () => { current = step; show("setup"); }));
    box.hidden = false;
  }

  function startFeed() {
    clearInterval(feedTimer);
    feedAt = null;
    $("arch-feed").replaceChildren();
    const tick = async () => {
      if ($("view-arch").hidden && $("view-close").hidden && $("view-try").hidden) return;
      if (!ws || !ws.steps.some((s) => s.id === "log" && s.state !== "todo")) return;
      try {
        const r = await api(`/api/feed?after=${feedAt == null ? Math.max(0, ws.records - 30) : feedAt}`);
        const fresh = feedAt != null;
        feedAt = r.total;
        const list = $("arch-feed");
        for (const x of r.records) {
          const what = MORE_KINDS[x.kind] || KINDS[x.kind] || x.kind;
          list.prepend(el("li", { className: `feed-${x.result || ""}` },
            el("span", { className: "muted", textContent: `#${x.index}` }), " ", el("strong", { textContent: what }),
            ` · ${x.who || ""}${x.subject ? ` · ${x.subject}` : ""}${x.result ? ` · ${x.result}` : ""}`));
          if (fresh && x.kind === "tool.call" && !played.has(x.index)) {
            played.add(x.index);
            setTimeout(async () => {
              try { play({ trace: await api(`/api/trace?ref=${x.index}`) }, {}); } catch { /* not finished yet */ }
            }, 700);
          }
        }
        while (list.children.length > 60) list.lastChild.remove();
      } catch { /* the page shows errors from actions only */ }
    };
    tick();
    feedTimer = setInterval(tick, 2000);
  }

  // ---- set up, step by step -----------------------------------------------------------
  async function loadSetup() {
    await act(null, async () => {
      await load();
      const d = diagram("setup", "setup-diagram", { compact: true, onPick: ({ step }) => { current = step; drawSetup(); } });
      d.setSteps(ws.steps);
      if (!ws.steps.some((s) => s.id === current)) current = "organization";
      await drawSetup();
    });
  }

  async function drawSetup() {
    const steps = ws.steps;
    const done = steps.filter((s) => s.state === "done").length;
    $("setup-progress").textContent = `${done} of ${steps.length} done`;
    $("setup-all").hidden = ws.serving && done === steps.length;
    $("setup-steps").replaceChildren(...steps.map((s, i) => {
      const li = el("li", { className: `stp state-${s.state}${s.id === current ? " on" : ""}` },
        el("span", { className: "num", textContent: s.state === "done" ? "✓" : String(i + 1) }),
        el("span", {}, el("strong", { textContent: s.title }), el("span", { className: "muted block", textContent: STATE_WORD[s.state] })));
      li.tabIndex = 0;
      const go = () => { current = s.id; drawSetup(); };
      li.addEventListener("click", go);
      li.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); go(); } });
      return li;
    }));
    diagrams.setup.highlight(current);
    const s = steps.find((x) => x.id === current);
    const i = steps.indexOf(s);
    const panel = $("setup-panel");
    const runLabel = s.id === "gateway" ? (ws.serving ? "Restart the gateway" : "Start the gateway")
      : s.state === "todo" ? "Run this step" : s.state === "changed" ? "Run again with the changes" : "Run again";
    const run = button(runLabel, (e) => runStep(e.target, s.id), "primary");
    const next = i < steps.length - 1 ? button("Next step →", () => { current = steps[i + 1].id; drawSetup(); }) : null;
    const settings = settingsFor(s.id);
    panel.replaceChildren(...[
      el("p", { className: "kicker", textContent: `Step ${i + 1} of ${steps.length}` }),
      el("h2", { textContent: s.title }),
      el("p", { textContent: s.text }),
      el("p", { className: "links" }, s.section ? howLink(s.section) : null, s.film ? filmLink(s.film) : null,
        out(`${SOURCE}/${s.module}.py`, `Module: aeos.${s.module} ↗`)),
      settings ? el("details", { className: "settings", open: s.state !== "done" },
        el("summary", { textContent: "Settings" }), settings,
        el("div", { className: "actions tight" }, button("Save changes", (e) => saveDraft(e.target)), el("span", { id: "setup-dirty", className: "muted", textContent: dirty ? "Unsaved changes" : "" })),
        el("div", { id: "setup-problems", className: "error", hidden: true })) : null,
      el("div", { className: "actions" }, run, next),
      el("h3", { textContent: "What this step made" }),
      el("div", { id: "setup-made", className: "made" }, el("p", { className: "muted", textContent: s.state === "todo" && s.id !== "organization" ? "Nothing yet. Run the step to see what it makes." : "Loading…" }))].filter(Boolean));
    if (s.state !== "todo" || s.id === "organization") {
      try { drawMade(s.id, await api(`/api/ws/step?step=${s.id}`)); } catch (e) { $("setup-made").replaceChildren(el("p", { className: "error", textContent: e.message })); }
    }
  }

  async function runStep(btn, step) {
    await act(btn, async () => {
      if (dirty) {
        await saveDraft(null);
        if (dirty) return;
      }
      await api("/api/ws/step", { step });
      await load();
      await refresh();
      diagrams.setup.setSteps(ws.steps);
      await drawSetup();
      diagrams.setup.flash([...document.querySelectorAll(`#setup-diagram [data-step="${step}"]`)].map((g) => g.dataset.id));
    });
  }

  async function saveDraft(btn) {
    await act(btn, async () => {
      const r = await api("/api/ws/save", { doc: draft });
      const box = $("setup-problems");
      if (!r.saved) {
        if (box) { box.replaceChildren(el("p", { textContent: "Not saved. Fix these first:" }), el("ul", {}, ...r.problems.map((p) => el("li", { textContent: p })))); box.hidden = false; }
        return;
      }
      dirty = false;
      await load();
      await refresh();
      await drawSetup();
    });
  }

  const touch = () => { dirty = true; const n = $("setup-dirty"); if (n) n.textContent = "Unsaved changes"; };
  function input(label, value, set, opts = {}) {
    const i = el(opts.rows ? "textarea" : "input", { value: value ?? "", spellcheck: false, placeholder: opts.placeholder || "" });
    if (opts.rows) i.rows = opts.rows; else i.type = opts.type || "text";
    i.addEventListener("input", () => { set(opts.type === "number" ? Number(i.value) : i.value); touch(); });
    return el("label", { className: opts.wide ? "wide" : "" }, label, i);
  }
  function tick(label, value, set) {
    const i = el("input", { type: "checkbox", checked: !!value });
    i.addEventListener("change", () => { set(i.checked); touch(); });
    return el("label", { className: "inline" }, i, label);
  }
  function choose(label, value, options, set, redraw = false) {
    const s = el("select", {}, ...options.map(([v, t]) => el("option", { value: v, textContent: t, selected: v === value })));
    s.addEventListener("change", () => { set(s.value); touch(); if (redraw) drawSetup(); });
    return el("label", {}, label, s);
  }
  function jsonInput(label, value, set, rows = 6) {
    const t = el("textarea", { value: JSON.stringify(value ?? {}, null, 2), rows, spellcheck: false });
    t.addEventListener("input", () => { try { set(JSON.parse(t.value)); t.classList.remove("bad"); touch(); } catch { t.classList.add("bad"); } });
    return el("label", { className: "wide" }, label, t);
  }
  const listText = (v) => String(v).split(",").map((x) => x.trim()).filter(Boolean);
  const remove = (arr, i) => button("Remove", () => { arr.splice(i, 1); touch(); drawSetup(); }, "quiet");
  const add = (text, fn) => button(text, () => { fn(); touch(); drawSetup(); }, "quiet");

  function allTools() {
    const tools = new Set(Object.keys(ws.tools));
    for (const s of draft.systems || []) {
      if (s.type === "example-erp") ["erp.invoice.list", "erp.invoice.get", "erp.invoice.pay"].forEach((t) => tools.add(t));
      for (const t of Array.isArray(s.tools) ? s.tools : Object.keys(s.tools || {})) tools.add(t);
    }
    if (draft.books) tools.add("ledger.post");
    return [...tools].sort();
  }
  const bookEntities = () => (draft.books ? (draft.books.entities || (draft.books.entity ? [draft.books.entity] : [])) : []);

  function settingsFor(step) {
    const d = draft;
    const box = (...kids) => el("div", { className: "form" }, ...kids);
    if (step === "organization") {
      const org = d.organization;
      org.entities = org.entities || [];
      return box(
        el("div", { className: "grid2" }, input("Company name", org.name, (v) => { org.name = v; }),
          input("Trust domain, a domain name you control", org.trust_domain, (v) => { org.trust_domain = v; })),
        el("p", { className: "muted", textContent: "Legal entities. Each keeps its own books." }),
        ...org.entities.map((e, i) => el("div", { className: "row4" },
          input("Id", e.id, (v) => { e.id = v; }), input("Name", e.name, (v) => { e.name = v; }),
          input("Country", e.country, (v) => { e.country = v; }), remove(org.entities, i))),
        add("Add an entity", () => org.entities.push({ id: "NEW-CO", name: "New company", country: "" })));
    }
    if (step === "people") {
      return box(...d.people.map((p, i) => el("div", { className: "sub" },
        el("div", { className: "grid3" }, input("Id", p.id, (v) => { p.id = v; }), input("Name", p.name, (v) => { p.name = v; }), input("Role", p.role, (v) => { p.role = v; })),
        el("div", { className: "checks" }, tick("Approver: answers calls the rules send to a person", p.approver, (v) => { p.approver = v; }),
          tick("Controller: opens and closes months", p.controller, (v) => { p.controller = v; }), remove(d.people, i)))),
      add("Add a person", () => d.people.push({ id: `person-${d.people.length + 1}`, name: "New person" })));
    }
    if (step === "agents") {
      const under = [...(d.instructions || []).map((x) => [`i:${x.id}`, `Instruction ${x.id}, signed by ${personName(x.signed_by)}`]),
        ...d.people.map((p) => [`p:${p.id}`, `Authorized directly by ${p.name || p.id}`])];
      const tools = allTools(), ents = bookEntities();
      return box(...d.agents.map((a, i) => el("fieldset", {},
        el("legend", { textContent: a.id }),
        el("div", { className: "grid3" }, input("Id", a.id, (v) => { a.id = v; }, { placeholder: "stock/02" }), input("Name", a.name, (v) => { a.name = v; }), input("Team", a.team, (v) => { a.team = v; })),
        input("Task", a.purpose, (v) => { a.purpose = v; }, { wide: true }),
        choose("Works under", a.instruction ? `i:${a.instruction}` : `p:${a.authorized_by}`, under, (v) => {
          delete a.instruction; delete a.authorized_by;
          if (v.startsWith("i:")) a.instruction = v.slice(2);
          else Object.assign(a, { authorized_by: v.slice(2), budget: a.budget || "0.00", valid_hours: a.valid_hours || 8 });
        }, true),
        a.authorized_by ? el("div", { className: "grid3" }, input("Payment limit per call", a.per_call_limit || "0.00", (v) => { a.per_call_limit = v; }),
          input("Payment budget in total", a.budget || "0.00", (v) => { a.budget = v; }), input("Hours valid", a.valid_hours || 8, (v) => { a.valid_hours = v; }, { type: "number" })) : null,
        el("p", { className: "muted", textContent: "Tools it may call" }),
        el("div", { className: "checks" }, ...tools.map((t) => tick(t, (a.tools || []).includes(t), (on) => {
          a.tools = on ? [...new Set([...(a.tools || []), t])] : (a.tools || []).filter((x) => x !== t);
        }))),
        ents.length ? el("p", { className: "muted", textContent: "Books it may post to (the rules check this)" }) : null,
        ents.length ? el("div", { className: "checks" }, ...ents.map((e) => tick(e, (a.entities || []).includes(e), (on) => {
          a.entities = on ? [...new Set([...(a.entities || []), e])] : (a.entities || []).filter((x) => x !== e);
          if (!a.entities.length) delete a.entities;
        }))) : null,
        remove(d.agents, i))),
      add("Add an agent", () => d.agents.push({ id: `agent-${d.agents.length + 1}`, name: "New agent", ...(d.instructions && d.instructions[0] ? { instruction: d.instructions[0].id } : { authorized_by: d.people[0].id, budget: "0.00", valid_hours: 8 }), purpose: "", tools: [] })));
    }
    if (step === "log") {
      const w = d.witnesses;
      return box(el("div", { className: "grid2" },
        input("Witnesses, separated by commas", (w.names || []).join(", "), (v) => { w.names = listText(v); }),
        input("How many must cosign", w.required, (v) => { w.required = v; }, { type: "number" })));
    }
    if (step === "books") {
      if (!d.books) return box(el("p", { textContent: "This workspace keeps no books." }), add("Add books", () => { d.books = { ledger: "GL", currency: "USD", entities: (d.organization.entities || []).map((e) => e.id).slice(0, 1), accounts: { 1000: "Bank" } }; }));
      const b = d.books;
      const accounts = Object.entries(b.accounts || {});
      const setAccounts = (rows) => { b.accounts = Object.fromEntries(rows.filter(([k]) => k)); };
      b.periods = b.periods || {};
      const periods = Object.entries(b.periods);
      return box(
        el("div", { className: "grid3" }, input("Ledger", b.ledger, (v) => { b.ledger = v; }), input("Currency", b.currency, (v) => { b.currency = v; }),
          input("Entities, separated by commas", bookEntities().join(", "), (v) => { delete b.entity; b.entities = listText(v); })),
        el("p", { className: "muted", textContent: "Chart of accounts, shared by every entity" }),
        ...accounts.map(([k, v], i) => el("div", { className: "row3" },
          input("Account", k, (nv) => { accounts[i][0] = nv; setAccounts(accounts); }), input("Name", v, (nv) => { accounts[i][1] = nv; setAccounts(accounts); }),
          button("Remove", () => { accounts.splice(i, 1); setAccounts(accounts); touch(); drawSetup(); }, "quiet"))),
        add("Add an account", () => { b.accounts[String(9000 + accounts.length)] = "New account"; }),
        el("p", { className: "muted", textContent: "Months open or closed when the books are set up. The first controller signs each one." }),
        ...periods.map(([k, v], i) => el("div", { className: "row3" },
          input("Month (YYYY-MM)", k, (nv) => { periods[i][0] = nv; b.periods = Object.fromEntries(periods); }),
          choose("State", v, [["open", "Open"], ["closed", "Closed"]], (nv) => { periods[i][1] = nv; b.periods = Object.fromEntries(periods); }),
          button("Remove", () => { periods.splice(i, 1); b.periods = Object.fromEntries(periods); touch(); drawSetup(); }, "quiet"))),
        add("Add a month", () => { b.periods[new Date().toISOString().slice(0, 7)] = "open"; }));
    }
    if (step === "rules") {
      const r = d.rules || (d.rules = { type: "none" });
      const kinds = [["close", "Close rules (built in)"], ["payments", "Payment rules (built in)"], ["wasm", "Your own compiled rules"], ["none", "No rules"]];
      const parts = [choose("Rules", r.type, kinds, (v) => { d.rules = { type: v }; if (v === "close" || v === "payments") d.rules.approval_above = "5000.00"; }, true)];
      if (r.type === "close" || r.type === "payments") parts.push(input("Send calls above this amount to an approver", r.approval_above, (v) => { r.approval_above = v; }));
      if (r.type === "close") {
        r.blocked_tools = r.blocked_tools || {};
        const rows = Object.entries(r.blocked_tools);
        parts.push(el("p", { className: "muted", textContent: "Tools the rules always refuse, with the reason recorded" }),
          ...rows.map(([t, why], i) => el("div", { className: "row3" },
            input("Tool", t, (v) => { rows[i][0] = v; r.blocked_tools = Object.fromEntries(rows); }), input("Reason", why, (v) => { rows[i][1] = v; r.blocked_tools = Object.fromEntries(rows); }),
            button("Remove", () => { rows.splice(i, 1); r.blocked_tools = Object.fromEntries(rows); touch(); drawSetup(); }, "quiet"))),
          add("Add a blocked tool", () => { r.blocked_tools["tool.name"] = "the reason"; }));
      }
      if (r.type === "payments") parts.push(input("Sanctioned suppliers, separated by commas", (r.sanctioned_suppliers || []).join(", "), (v) => { r.sanctioned_suppliers = listText(v); }));
      if (r.type === "wasm") parts.push(el("div", { className: "grid2" }, input("File (.wasm) in the workspace folder", r.file, (v) => { r.file = v; }), input("Entrypoint", r.entrypoint, (v) => { r.entrypoint = v; })),
        jsonInput("Data the rules read", r.data || {}, (v) => { r.data = v; }));
      return box(...parts);
    }
    if (step === "systems") {
      return box(...d.systems.map((s, i) => el("fieldset", {}, el("legend", { textContent: `${s.name || s.id} (${s.type})` }),
        el("div", { className: "grid2" }, input("Id", s.id, (v) => { s.id = v; }), input("Name", s.name, (v) => { s.name = v; })),
        ...(s.type === "records" ? Object.entries(s.tools || {}).map(([t, spec]) => el("div", { className: "sub" },
          el("div", { className: "grid2" }, el("label", {}, "Tool", mono(t)), input("Argument that names the record, such as the account", spec.key, (v) => { spec.key = v; })),
          jsonInput(`Records ${t} returns`, spec.records, (v) => { spec.records = v; }, 5))) : []),
        s.type === "example-erp" ? jsonInput("Invoices", s.invoices, (v) => { s.invoices = v; }, 8) : null,
        s.type === "python" ? input("Python file in the workspace folder", s.file, (v) => { s.file = v; }) : null,
        s.type === "mcp-stdio" ? el("div", { className: "grid3" }, input("Command, as JSON", JSON.stringify(s.command || []), (v) => { try { s.command = JSON.parse(v); } catch { /* keep */ } }),
          input("Prefix", s.prefix, (v) => { s.prefix = v; }), input("Tools, separated by commas", (s.tools || []).join(", "), (v) => { s.tools = listText(v); })) : null,
        remove(d.systems, i))),
      el("div", { className: "actions tight" },
        add("Add records", () => d.systems.push({ id: `system-${d.systems.length + 1}`, type: "records", name: "New system", tools: { "new.tool.get": { key: "id", records: { "A-1": { value: "example" } } } } })),
        add("Add a Python file", () => d.systems.push({ id: `system-${d.systems.length + 1}`, type: "python", file: "tools.py" })),
        add("Add an MCP server", () => d.systems.push({ id: `system-${d.systems.length + 1}`, type: "mcp-stdio", command: ["python", "server.py"], prefix: "", tools: [] }))));
    }
    if (step === "instruction") {
      d.instructions = d.instructions || [];
      return box(...d.instructions.map((x, i) => el("fieldset", {}, el("legend", { textContent: x.id }),
        el("div", { className: "grid2" }, input("Id", x.id, (v) => { x.id = v; }),
          choose("Signed by", x.signed_by, d.people.map((p) => [p.id, p.name || p.id]), (v) => { x.signed_by = v; })),
        input("The instruction", x.purpose, (v) => { x.purpose = v; }, { rows: 3, wide: true }),
        el("div", { className: "grid3" }, input("Payment limit per call", x.per_call_limit, (v) => { x.per_call_limit = v; }),
          input("Payment budget in total", x.budget, (v) => { x.budget = v; }), input("Hours valid", x.valid_hours, (v) => { x.valid_hours = v; }, { type: "number" })),
        remove(d.instructions, i))),
      el("p", { className: "muted", textContent: "Agents choose the instruction they work under in the Agents step. An agent can also be authorized directly by one person." }),
      add("Add an instruction", () => d.instructions.push({ id: `instruction-${d.instructions.length + 1}`, signed_by: d.people[0].id, purpose: "", per_call_limit: "0.00", budget: "0.00", valid_hours: 8 })));
    }
    return null;
  }

  // ---- what each step made ------------------------------------------------------------
  function drawMade(step, v) {
    const box = $("setup-made");
    if (!box) return;
    if (v.problem) return box.replaceChildren(el("p", { className: "error", textContent: v.problem }));
    if (v.step && v.step.state === "todo" && step !== "organization") return box.replaceChildren(el("p", { className: "muted", textContent: "Nothing yet. Run the step to see what it makes." }));
    const f = MADE[step];
    box.replaceChildren(...(f ? f(v) : [code(JSON.stringify(v, null, 2))]));
  }

  const certBox = (title, c, note) => el("div", { className: "cert" },
    el("strong", { textContent: title }), el("span", { className: "muted block", textContent: note }),
    kv([["Key", c.key], ["Subject", mono(c.subject)], c.spiffe ? ["SPIFFE ID", mono(c.spiffe)] : null,
      ["Valid", `${time(c.not_before)} to ${time(c.not_after)}`], ["Fingerprint", mono(shortHex(c.fingerprint, 24))]]));

  const MADE = {
    organization: (v) => [kv([["Company", v.name], ["Trust domain", mono(v.trust_domain)], ["Folder", mono(v.folder)]]),
      el("h4", { textContent: "Legal entities" }), el("ul", {}, ...v.entities.map((e) => el("li", {}, mono(e.id), ` ${e.name}`))),
      el("h4", { textContent: "How identities are named" }),
      kv([["A person", mono(v.ids.person)], ["An agent", mono(v.ids.agent)], ["The gateway", mono(v.ids.gateway)], ["The books service", mono(v.ids.books)]])],
    pki: (v) => [el("div", { className: "tree" },
      certBox("Root certificate authority", v.root, "Signs only the intermediate certificate authority. Kept offline in production."),
      el("div", { className: "tree-arrow", textContent: "signs ↓" }),
      certBox("Intermediate certificate authority", v.intermediate, "Signs the 15-minute certificates. Replaced every day."),
      el("div", { className: "tree-arrow", textContent: "signs ↓" }),
      el("div", { className: "cert faint" }, el("strong", { textContent: "SPIFFE certificates" }), el("span", { className: "muted block", textContent: "One for each agent and the gateway, made in the SPIFFE identities step." }))),
    kv([["Trust bundle", mono(v.bundle)], ["Private keys", mono(v.keys)]])],
    people: (v) => [table(["Person", "SPIFFE ID", "Public key", "Signs"], v.people.map((p) => [
      el("span", {}, el("strong", { textContent: p.name }), p.role ? el("span", { className: "muted block", textContent: p.role }) : null),
      mono(p.spiffe_id), mono(shortHex(p.public_key)),
      ["instructions", p.approver ? "approvals" : "", p.controller ? "period changes" : ""].filter(Boolean).join(", ")])),
    el("p", { className: "muted" }, "Public keys are in ", mono(v.file), ". Private keys stay in private/people/.")],
    agents: (v) => [el("div", { className: "agent-grid" }, ...v.agents.map((a) => el("article", { className: "item" },
      el("div", { className: "item-head" }, el("strong", { className: "mono", textContent: a.id }), a.team ? chip(a.team, "lay-agents") : null),
      el("p", { textContent: a.purpose }),
      el("div", { className: "pills" }, ...a.tools.map((t) => chip(t))),
      a.entities.length ? el("p", { className: "muted", textContent: `May post to the books of ${a.entities.join(", ")}` }) : null,
      el("p", { className: "muted" }, "Fingerprint ", mono(shortHex(a.cid, 22)))))),
    el("p", { className: "muted" }, "Each bundle is saved in agents/ under its fingerprint. Change anything about an agent and it gets a new fingerprint.")],
    identities: (v) => [table(["SPIFFE ID", "Expires in", "Fingerprint"], v.svids.map((c) => [
      mono(c.spiffe), el("span", { className: "countdown", dataset: { until: c.not_after } }), mono(shortHex(c.fingerprint))])),
    el("p", { className: "muted", textContent: `Each certificate lasts ${v.ttl_minutes} minutes. While the gateway runs, the platform issues new ones every ${v.renew_minutes} minutes.` })],
    log: (v) => [kv([["Log", mono(v.log_id)], ["Records", String(v.records)], ["Signed checkpoints", String(v.checkpoints)],
      v.root ? ["Latest Merkle root", mono(shortHex(v.root, 32))] : null, ["Log's public key", mono(shortHex(v.public_key, 32))]]),
    el("h4", { textContent: `Witnesses: ${v.required} must cosign each checkpoint` }),
    el("ul", {}, ...v.witnesses.map((w) => el("li", {}, el("strong", { textContent: w.name }), " ", mono(shortHex(w.public_key)))))],
    books: (v) => [...v.entities.map((e) => el("div", { className: "item" },
      el("div", { className: "item-head" }, el("strong", { textContent: `${e.id} · ${v.ledger} · ${v.currency}` }), el("span", { className: "muted", textContent: e.name })),
      el("div", { className: "periods" }, ...e.periods.map((p) => el("span", { className: `badge period-${p.state}`, textContent: `${p.name}: ${p.state}`, title: `Signed by ${p.by}` }))),
      el("p", { className: "muted", textContent: `${e.entries} journal entr${e.entries === 1 ? "y" : "ies"}` }))),
    el("details", {}, el("summary", { textContent: "Chart of accounts" }), table(["Account", "Name"], Object.entries(v.accounts || {}).map(([k, n]) => [mono(k), n])))],
    rules: (v) => (v.type === "none" ? [el("p", { textContent: "No rules: the gateway allows every call that passes the other checks." })] : [
      kv([["Entrypoint", mono(v.entrypoint)], ["Compiled module", `${v.wasm_bytes.toLocaleString()} bytes of WebAssembly`], ["SHA-256", mono(shortHex(v.wasm_sha256, 32))], ["Saved as", mono(v.file)]]),
      el("details", { open: true }, el("summary", { textContent: "The data the rules read" }), code(JSON.stringify(v.data, null, 2))),
      v.source ? el("details", {}, el("summary", { textContent: "The rules, in Rego" }), code(v.source)) : null]),
    systems: (v) => [table(["System", "Tools"], v.systems.map((s) => [el("strong", { textContent: s.name }), el("div", { className: "pills" }, ...s.tools.map((t) => chip(t)))])),
      el("p", { className: "muted" }, "Agents reach every tool through the gateway, ", mono(v.gateway), ".")],
    instruction: (v) => [...v.intents.map((x) => el("div", { className: "instruction" },
      el("div", { className: "signed" }, el("span", { className: "muted", textContent: "Signed by" }), " ", el("strong", { textContent: (ws.names || {})[x.signed_by] || x.signed_by })),
      el("ul", { className: "lines" }, ...x.purpose.split(/(?<=\.)\s+/).filter(Boolean).map((l) => el("li", { textContent: l }))),
      kv([["Valid until", time(x.not_after)], ["Payments", x.per_action_max_minor ? `up to ${money(x.per_action_max_minor)} a call, ${money(x.budget_minor)} in total` : "none allowed"],
        ["For", x.audience.endsWith("/agent") ? `every agent under ${x.audience}` : x.audience], ["Fingerprint", mono(shortHex(x.cid, 28))], ["Signature", mono(shortHex(x.signature, 28))]]),
      el("h4", { textContent: "Each agent's credential" }),
      el("p", { className: "muted", textContent: "The first block comes from the authorization service and carries the instruction's limits. The second narrows it to one agent. A block can only remove authority." }),
      ...x.tokens.map((t) => el("details", {}, el("summary", {}, mono(t.agent), ` · ${t.bytes} bytes`),
        ...t.blocks.map((b, i) => el("div", {}, el("p", { className: "muted", textContent: i === 0 ? "Block 1, from the authorization service" : `Block ${i + 1}, narrowed to this agent` }), code(b))))))),
    el("p", { className: "muted" }, "The authorization service's public key: ", mono(shortHex(v.authority_public_key, 32)))],
    gateway: (v) => [kv([["Gateway", mono(v.gateway)], ["Listens on", v.port ? `127.0.0.1:${v.port}` : "not running"], ["Agents connect with", mono(v.connect)]]),
      el("h4", { textContent: "Every call passes these checks, in order" }), el("ol", { className: "checks-list" }, ...v.checks.map((c) => el("li", { textContent: c }))),
      el("div", { className: "actions" }, button("Run the close →", () => show("close"), "primary"), button("Try a call", () => show("try")))],
  };

  function table(head, rows) {
    const cell = (c) => (c instanceof Node ? el("td", {}, c) : el("td", { textContent: c }));
    return el("div", { className: "table-wrap" }, el("table", { className: "ledger" },
      el("thead", {}, el("tr", {}, ...head.map((h) => el("th", { textContent: h })))),
      el("tbody", {}, ...rows.map((r) => el("tr", {}, ...r.map(cell))))));
  }

  setInterval(() => {
    for (const n of document.querySelectorAll(".countdown")) {
      const left = Math.round((Number(n.dataset.until) - Date.now()) / 1000);
      n.textContent = left > 0 ? `${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")}` : "expired; renewed while running";
    }
  }, 1000);

  // ---- the close, chapter by chapter --------------------------------------------------
  async function loadClose() {
    await act(null, async () => {
      await load();
      diagram("close", "close-diagram", { compact: true }).setSteps(ws.steps);
      const pin = $("close-pin");
      if (!pin.dataset.wired) {
        pin.dataset.wired = "1";
        try { pin.checked = localStorage.getItem("aeos-pin") !== "0"; } catch { /* private window */ }
        const apply = () => {
          $("close-diagram").classList.toggle("sticky", pin.checked);
          try { localStorage.setItem("aeos-pin", pin.checked ? "1" : "0"); } catch { /* private window */ }
        };
        pin.addEventListener("change", apply);
        apply();
      }
      startFeed();
      drawChapters();
    });
  }

  function drawChapters() {
    const wait = notReady();
    const box = $("close-chapters");
    const cards = ws.chapters.map((ch) => {
      const body = el("div", { className: "chapter-results", id: `ch-${ch.id}` }, ...(results[ch.id] || []));
      const head = el("div", { className: "chapter-head" },
        el("span", { className: "chapter-n", textContent: String(ch.film).padStart(2, "0") }),
        el("div", {}, el("h2", { textContent: ch.title }), el("p", { textContent: ch.text }), el("p", { className: "links" }, filmLink(ch.film))));
      const parts = [head];
      if (ch.missing.length) parts.push(el("p", { className: "muted", textContent: `This chapter uses ${ch.missing.join(", ")}, which this workspace does not have.` }));
      else if (ch.id === "instruction") parts.push(button("Show the instruction", (e) => playInstruction(e.target, ch), "primary"));
      else if (ch.decision) parts.push(el("div", { className: "actions tight" }, ...ch.decision.options.map((o, i) => button(o.label, (e) => decide(e.target, ch, o), i === 0 ? "primary" : ""))));
      else parts.push(button("Play this chapter", (e) => playChapter(e.target, ch), "primary"));
      parts.push(body);
      return el("article", { className: "card chapter" }, ...parts);
    });
    box.replaceChildren(...(wait ? [wait] : []), ...cards);
    if (wait) box.querySelectorAll(".chapter button").forEach((b) => { b.disabled = true; });
  }

  function say(ch, node) {
    (results[ch.id] = results[ch.id] || []).push(node);
    $(`ch-${ch.id}`).append(node);
  }

  function resultLine(step, answer) {
    const t = answer.trace;
    const [title, cls] = t ? OUTCOME[t.outcome] : [answer.ok ? "Done" : "Refused", answer.ok ? "tag-allow" : "tag-deny"];
    const box = el("div", { className: "trace", hidden: true });
    const why = t ? t.steps.find((s) => s.state === "fail" || s.state === "wait") : null;
    return el("div", { className: "result" },
      el("div", { className: "item-head" }, el("span", { className: `badge ${cls}`, textContent: title }), el("strong", { className: "mono", textContent: step.agent }),
        el("span", { textContent: step.says })),
      why ? el("p", { className: "muted", textContent: `${why.label}: ${why.text}` }) : el("p", { className: "muted", textContent: brief(answer) }),
      t ? button("Show each check", () => { if (box.hidden) renderTrace(box, answer); else box.hidden = true; }, "quiet") : null, box);
  }

  function brief(answer) {
    const r = answer.result;
    if (!r) return answer.text;
    if (r.document) return `Booked as ${r.document}`;
    return Object.entries(r).filter(([, v]) => typeof v !== "object").slice(0, 5).map(([k, v]) => `${k.replaceAll("_", " ")}: ${v}`).join(" · ");
  }

  const pause = (ms) => new Promise((r) => setTimeout(r, ms));

  async function call(step) {
    const r = await api("/api/ws/call", { agent: step.agent, tool: step.tool, args: step.args });
    play(r, step);
    return r;
  }

  // One chapter plays at a time, so the diagram shows one story.
  const lock = (on) => document.querySelectorAll("#close-chapters .chapter > button, #close-chapters .chapter .actions button")
    .forEach((b) => { b.disabled = on; });

  async function playChapter(btn, ch) {
    lock(true);
    try { await playChapterNow(btn, ch); } finally { lock(false); }
  }

  async function playChapterNow(btn, ch) {
    await act(btn, async () => {
      results[ch.id] = [];
      $(`ch-${ch.id}`).replaceChildren();
      for (const st of ch.steps) {
        if (st.agent) {
          say(ch, resultLine(st, await call(st)));
          await pause(3600);
        } else if (st.period) {
          const r = await api("/api/ws/period", { period: st.period, state: st.state, person: st.by, entity: st.entity });
          diagrams.close.flash([`person:${st.by}`, `books:${st.entity}`, "log"]);
          say(ch, el("div", { className: "result" }, el("div", { className: "item-head" }, el("span", { className: "badge period-closed", textContent: "Signed" }), el("span", { textContent: st.says })),
            el("p", { className: "muted", textContent: `${st.entity}, ${st.period}: ${((r.periods || {})[st.entity] || {})[st.period] || st.state}` })));
          await pause(900);
        } else if (st.seal) {
          const r = await api("/api/ws/seal", {});
          diagrams.close.flash(["log", "witnesses"]);
          say(ch, el("div", { className: "result" }, el("div", { className: "item-head" }, el("span", { className: "badge tag-allow", textContent: "Sealed" }), el("span", { textContent: st.says })),
            el("p", { className: "muted", textContent: `${r.size} records, cosigned by ${r.witnesses.join(" and ")}` })));
          await pause(900);
        } else if (st.audit) {
          const r = await api("/api/audit", {});
          say(ch, el("div", { className: `result chk-result ${r.ok ? "chk-ok" : "chk-bad"}` },
            el("div", { className: "item-head" }, el("span", { className: `badge ${r.ok ? "tag-allow" : "tag-deny"}`, textContent: r.ok ? "Valid" : "Not valid" }), el("span", { textContent: st.says })),
            el("ul", {}, ...[...r.problems, ...r.findings].map((x) => el("li", { textContent: x })))));
        }
      }
      await refresh();
    });
  }

  async function playInstruction(btn, ch) {
    await act(btn, async () => {
      const v = await api("/api/ws/step?step=instruction");
      results[ch.id] = MADE.instruction(v);
      $(`ch-${ch.id}`).replaceChildren(...results[ch.id]);
      diagrams.close.flash([...Object.keys(diagrams.close.nodes())].filter((id) => id.startsWith("agent:") || id === "authz" || id === `person:${(ws.running.instructions || [{}])[0].signed_by}`));
    });
  }

  async function decide(btn, ch, option) {
    lock(true);
    try { await decideNow(btn, ch, option); } finally { lock(false); }
  }

  async function decideNow(btn, ch, option) {
    await act(btn, async () => {
      await load();
      const esc = ws.escalations.find((x) => x.agent === ch.decision.agent);
      if (!esc) {
        say(ch, el("p", { className: "muted", textContent: "Nothing is waiting for a decision. Play The controls first: the write-down proposed there waits for the CFO." }));
        return;
      }
      const person = ch.decision.person;
      let r = await api("/api/ws/approve", { escalation: esc.escalation, person, verdict: option.verdict });
      play(r, { agent: ch.decision.agent, tool: esc.tool });
      say(ch, resultLine({ agent: ch.decision.agent, says: option.verdict === "approve" ? `${personName(person)} approves the $612,000 write-down` : `${personName(person)} rejects $612,000` }, r));
      if (option.then) {
        await pause(3600);
        r = await call(option.then);
        say(ch, resultLine(option.then, r));
        if (r.trace && r.trace.outcome === "waiting") {
          await pause(3600);
          r = await api("/api/ws/approve", { escalation: r.trace.escalation, person, verdict: "approve" });
          play(r, option.then);
          say(ch, resultLine({ agent: option.then.agent, says: `${personName(person)} approves $410,000` }, r));
        }
      }
      await refresh();
    });
  }

  // ---- one call -----------------------------------------------------------------------
  let form = null;
  async function loadTry() {
    await act(null, async () => {
      await load();
      diagram("try", "try-diagram", { compact: true }).setSteps(ws.steps);
      startFeed();
      const wait = notReady();
      $("try-form").hidden = !!wait;
      $("try-scenarios").replaceChildren(...(wait ? [wait] : []));
      if (wait) return;
      const d = ws.running;
      if (!form || !d.agents.some((a) => a.id === form.agent)) form = { agent: d.agents[0].id, tool: (d.agents[0].tools || [])[0], args: {} };
      drawScenarios();
      drawForm();
      drawConnect();
    });
  }

  function scenarios() {
    const list = [];
    for (const ch of ws.chapters) for (const st of ch.steps) {
      if (st.agent && !ch.missing.length && list.length < 7) list.push([st.says, { agent: st.agent, tool: st.tool, args: structuredClone(st.args) }]);
    }
    const d = ws.running;
    const lacking = d.agents.find((a) => !(a.tools || []).includes("ledger.post"));
    if (lacking && d.books) list.push([`${lacking.id} tries a tool it was not given`, { agent: lacking.id, tool: "ledger.post", args: { date: "2026-09-30", text: "Not allowed", lines: [] } }]);
    if (list.length < 2) for (const a of d.agents.slice(0, 4)) if ((a.tools || [])[0]) list.push([`${a.name || a.id}: ${a.tools[0]}`, { agent: a.id, tool: a.tools[0], args: {} }]);
    return list;
  }

  function drawScenarios() {
    $("try-scenarios").replaceChildren(el("span", { className: "muted", textContent: "Try:" }), ...scenarios().map(([label, f]) =>
      button(label, (ev) => { form = structuredClone(f); drawForm(); send(ev); }, "chip")));
  }

  function recordsSpec(tool) {
    for (const s of ws.running.systems) if (s.type === "records" && s.tools && s.tools[tool]) return s.tools[tool];
    return null;
  }

  function argFields() {
    const a = form.args, t = form.tool;
    const spec = recordsSpec(t);
    if (spec && spec.key) {
      const keys = Object.keys(spec.records || {});
      if (a[spec.key] == null && keys[0]) a[spec.key] = keys[0];
      const s = el("select", {}, ...keys.map((k) => el("option", { value: k, textContent: k, selected: k === a[spec.key] })));
      s.addEventListener("change", () => { a[spec.key] = s.value; drawJson(); });
      return [el("label", {}, spec.key, s)];
    }
    if (t === "erp.invoice.get" || t === "erp.invoice.pay") {
      const inv = ws.invoices;
      if (!a.invoice && inv[0]) { a.invoice = inv[0].invoice; if (t.endsWith("pay")) a.amount_minor = inv[0].amount_minor; }
      const s = el("select", {}, ...inv.map((i) => el("option", { value: i.invoice, textContent: `${i.invoice} · ${i.supplier} · ${money(i.amount_minor)} · ${i.status}`, selected: i.invoice === a.invoice })));
      s.addEventListener("change", () => { a.invoice = s.value; if (t.endsWith("pay")) a.amount_minor = inv.find((i) => i.invoice === s.value).amount_minor; drawJson(); });
      return [el("label", {}, "Invoice", s)];
    }
    if (t === "ledger.post") {
      const accounts = Object.entries((ws.running.books || {}).accounts || {});
      const ents = Object.keys(ws.entities || {});
      a.entity = a.entity || ents[0];
      a.date = a.date || "2026-09-30";
      a.text = a.text ?? "";
      a.lines = a.lines && a.lines.length ? a.lines : [{ account: accounts[0]?.[0], debit_minor: 0 }, { account: accounts[1]?.[0], credit_minor: 0 }];
      const simple = (label, key, type = "text") => {
        const i = el("input", { value: a[key], type });
        i.addEventListener("input", () => { a[key] = i.value; drawJson(); });
        return el("label", {}, label, i);
      };
      const amount = (label, ln, key) => {
        const i = el("input", { value: ln[key] ? (ln[key] / 100).toFixed(2) : "", inputMode: "decimal", placeholder: "0.00" });
        i.addEventListener("input", () => { ln[key] = Math.round(Number(i.value || 0) * 100); drawJson(); });
        return el("label", {}, label, i);
      };
      const entSel = el("select", {}, ...ents.map((e) => el("option", { value: e, textContent: ws.entities[e] !== e ? `${e} ${ws.entities[e]}` : e, selected: e === a.entity })));
      entSel.addEventListener("change", () => { a.entity = entSel.value; drawJson(); });
      return [el("div", { className: "grid3" }, el("label", {}, "Books of", entSel), simple("Date", "date", "date"), simple("Description", "text")),
        ...a.lines.map((ln) => {
          const s = el("select", {}, ...accounts.map(([c, n]) => el("option", { value: c, textContent: `${c} ${n}`, selected: c === ln.account })));
          s.addEventListener("change", () => { ln.account = s.value; drawJson(); });
          return el("div", { className: "row3" }, el("label", {}, "Account", s), amount("Debit", ln, "debit_minor"), amount("Credit", ln, "credit_minor"));
        }),
        button("Add a line", () => { a.lines.push({ account: accounts[0]?.[0] }); drawForm(); }, "quiet")];
    }
    return [];
  }

  const cleanArgs = () => {
    const a = structuredClone(form.args);
    if (Array.isArray(a.lines)) a.lines = a.lines.map((ln) => Object.fromEntries(Object.entries(ln).filter(([, v]) => v !== 0 && v != null)));
    return a;
  };
  function drawJson() {
    const area = $("try-json");
    if (area && document.activeElement !== area) area.value = JSON.stringify(cleanArgs(), null, 2);
  }

  function drawForm() {
    const d = ws.running;
    const agent = d.agents.find((x) => x.id === form.agent) || d.agents[0];
    const given = agent.tools || [];
    const others = Object.keys(ws.tools).filter((t) => !given.includes(t)).sort();
    const teams = [...new Set(d.agents.map((a) => a.team || ""))];
    const agentSel = el("select", {}, ...teams.map((tm) => el("optgroup", { label: tm || "Agents" },
      ...d.agents.filter((a) => (a.team || "") === tm).map((x) => el("option", { value: x.id, textContent: `${x.id} · ${x.name || ""}`, selected: x.id === agent.id })))));
    agentSel.addEventListener("change", () => { form.agent = agentSel.value; form.tool = (d.agents.find((a) => a.id === form.agent).tools || [])[0]; form.args = {}; drawForm(); drawConnect(); });
    const toolSel = el("select", {},
      el("optgroup", { label: "Given to this agent" }, ...given.map((t) => el("option", { value: t, textContent: t, selected: t === form.tool }))),
      ...(others.length ? [el("optgroup", { label: "Not given (the gateway refuses these)" }, ...others.map((t) => el("option", { value: t, textContent: t, selected: t === form.tool })))] : []));
    toolSel.addEventListener("change", () => { form.tool = toolSel.value; form.args = {}; drawForm(); });
    const json = el("textarea", { id: "try-json", rows: 6, spellcheck: false });
    json.addEventListener("input", () => { try { form.args = JSON.parse(json.value); json.classList.remove("bad"); } catch { json.classList.add("bad"); } });
    const fields = argFields();
    const ins = (d.instructions || []).find((x) => x.id === agent.instruction);
    const acts = ins ? `Works under ${personName(ins.signed_by)}'s instruction ${ins.id}` : `Acts for ${personName(agent.authorized_by)}`;
    $("try-form").replaceChildren(
      el("div", { className: "grid2" }, el("label", {}, "Agent", agentSel), el("label", {}, "Tool", toolSel)),
      el("p", { className: "muted", textContent: `${acts}. ${agent.purpose || ""}` }),
      ...fields,
      el("details", { open: !fields.length }, el("summary", { textContent: "Arguments as JSON" }), json),
      el("button", { className: "primary", textContent: `Send as ${agent.id}` }));
    drawJson();
  }

  async function send(e) {
    if (e && e.preventDefault) e.preventDefault();
    await act(e && e.target && e.target.tagName === "BUTTON" ? e.target : null, async () => {
      const args = cleanArgs();
      const r = await api("/api/ws/call", { agent: form.agent, tool: form.tool, args });
      play(r, { agent: form.agent, tool: form.tool, args });
      renderTrace($("try-trace"), r, { approve: true, args });
      ws = await api("/api/ws");
    });
  }

  function drawConnect() {
    const d = ws.running;
    const aid = form.agent;
    const first = (d.agents.find((a) => a.id === aid).tools || [""])[0];
    $("connect-body").replaceChildren(
      el("p", { textContent: ws.port ? `The gateway listens on 127.0.0.1:${ws.port}. Each agent's files are in ${ws.connect}: its certificate and key, the trust bundle, its capability token and gateway.json. The certificates last 15 minutes and are renewed every 5 minutes while the platform runs.` : "Start the gateway under Set up to connect an agent." }),
      code(`from aeos import workspace\n\nagent = workspace.remote_client(r"${ws.folder}", "${aid}")\nagent.initialize()\nprint(agent.call("${first}", {}))\nagent.close()`),
      el("p", { className: "muted" }, "Files for this agent: ", mono(`${ws.connect}/${aid.replaceAll("/", "_")}`)));
  }

  // ---- the trace ----------------------------------------------------------------------
  function renderTrace(box, answer, opts = {}) {
    const t = answer.trace || answer;
    const [title, cls, meaning] = OUTCOME[t.outcome] || OUTCOME.refused;
    const steps = el("ol", { className: "steps" }, ...t.steps.map((s) => el("li", { className: `step step-${s.state}` },
      el("span", { className: "icon", textContent: STEP_ICON[s.state] }),
      el("div", {}, el("strong", { textContent: s.label }), el("p", { textContent: s.text }),
        s.record != null ? el("span", { className: "muted", textContent: `Record ${s.record}` }) : null))));
    const parts = [
      el("div", { className: "item-head" }, el("span", { className: `badge ${cls}`, textContent: title }),
        el("strong", { textContent: `${t.agent_name || t.agent} → ${t.tool}` })),
      el("p", { className: "muted", textContent: meaning }), steps];
    if (opts.approve && t.outcome === "waiting" && ws) {
      const first = (ws.running.people.find((p) => p.approver) || {}).id;
      const who = el("select", {}, ...ws.running.people.map((p) => el("option", { value: p.id, textContent: p.name || p.id, selected: p.id === first })));
      const answerAs = (verdict) => async (ev) => act(ev.target, async () => {
        const r = await api("/api/ws/approve", { escalation: t.escalation, person: who.value, verdict });
        play(r, { agent: form && form.agent, tool: t.tool, args: opts.args });
        renderTrace(box, r, opts);
      });
      parts.push(el("div", { className: "approve" }, el("strong", { textContent: "Answer as a person" }),
        el("label", {}, "Signed by", who),
        el("div", { className: "actions tight" }, button("Approve", answerAs("approve"), "primary"), button("Reject", answerAs("reject")))));
    }
    if (answer.trace) {
      parts.push(el("h3", { textContent: "What the agent got back" }),
        el("pre", { className: "code", textContent: answer.result != null ? JSON.stringify(answer.result, null, 2) : answer.text }));
      if (opts.args && form) {
        const args = Object.entries(opts.args).map(([k, v]) => `${k}=${typeof v === "string" ? (/\s/.test(v) ? `"${v}"` : v) : `'${JSON.stringify(v)}'`}`).join(" ");
        parts.push(el("details", {}, el("summary", { textContent: "The same call from the command line" }),
          code(`aeos call "${ws.folder}" --as ${form.agent} ${form.tool} ${args}`)));
      }
    }
    box.replaceChildren(...parts);
    box.hidden = false;
    [...steps.children].forEach((li, i) => setTimeout(() => li.classList.add("shown"), 120 + i * 180));
  }

  // ---- books: open and close months -------------------------------------------------
  async function drawPeriods() {
    const box = $("period-form");
    if (!ws) ws = await api("/api/ws");
    const controllers = ws.running.people.filter((p) => p.controller);
    if (!ws.running.books || !controllers.length || !ws.serving) { box.hidden = true; return; }
    const ents = Object.keys(ws.entities || {});
    const entity = el("select", {}, ...ents.map((e) => el("option", { value: e, textContent: e })));
    const month = el("input", { type: "month", value: "2026-09", required: true });
    const state = el("select", {}, el("option", { value: "open", textContent: "Open" }), el("option", { value: "closed", textContent: "Close" }));
    const who = el("select", {}, ...controllers.map((p) => el("option", { value: p.id, textContent: p.name || p.id })));
    const go = el("button", { className: "primary", textContent: "Sign the change" });
    box.replaceChildren(el("label", {}, "Books of", entity), el("label", {}, "Month", month), el("label", {}, "Change", state), el("label", {}, "Signed by", who), go);
    box.hidden = false;
    box.onsubmit = (e) => {
      e.preventDefault();
      act(go, async () => {
        ws = await api("/api/ws/period", { period: month.value, state: state.value, person: who.value, entity: entity.value });
        show("books");
      });
    };
  }

  // ---- build with it ------------------------------------------------------------------
  function loadModules() {
    const folder = ws ? ws.folder : "kestrel-foods";
    const rows = MODULES.map((m) => el("article", { className: "card module" },
      el("div", { className: "item-head" }, chip(m.layer, `lay-${m.layer}`), el("h2", { textContent: m.title })),
      el("p", { textContent: m.what }),
      el("p", { className: "links" }, out(`${SOURCE}/${m.module}.py`, `aeos.${m.module} ↗`), m.section ? howLink(m.section) : null),
      code(m.code),
      m.cli ? el("p", { className: "muted" }, "From the command line: ", mono(m.cli.replace("FOLDER", `"${folder}"`))) : null));
    $("modules-body").replaceChildren(
      el("article", { className: "card module whole" },
        el("h2", { textContent: "The whole system" }),
        el("p", { textContent: "One file describes the company. These commands create it, set it up step by step, run it and check the evidence. The Python class behind them, workspace.Platform, does the same from code." }),
        code(`pip install "git+https://github.com/Daz-za/ae-os#subdirectory=python"\naeos new kestrel-foods          # the workspace from the film\naeos build kestrel-foods        # set it up, step by step\naeos up kestrel-foods           # run the gateway for agents to connect to\naeos call kestrel-foods --as stock/02 erp.stock.ageing site=OHIO\naeos audit kestrel-foods        # check all the evidence`),
        code(`from aeos import workspace\n\nwith workspace.Platform("kestrel-foods") as platform:\n    answer = platform.call("stock/02", "erp.stock.ageing", {"site": "OHIO"})\n    for check in answer["trace"]["steps"]:\n        print(check["label"], check["state"], check["text"])`)),
      el("h2", { textContent: "One module at a time" }),
      el("p", { textContent: "Each part below works on its own. Replace any of them with your own, such as SPIRE for the certificate authority or your own rules, and keep the rest." }),
      ...rows);
  }

  // ---- the file -----------------------------------------------------------------------
  async function loadEdit() {
    await act(null, async () => {
      await load();
      $("edit-file").textContent = ws.file;
      $("edit-json").value = JSON.stringify(ws.doc, null, 2);
      $("edit-problems").hidden = !ws.problems.length;
      if (ws.problems.length) $("edit-problems").replaceChildren(el("ul", {}, ...ws.problems.map((p) => el("li", { textContent: p }))));
      $("edit-status").textContent = "";
    });
  }

  async function saveEdit(btn) {
    await act(btn, async () => {
      let doc;
      try { doc = JSON.parse($("edit-json").value); } catch (e) { throw new Error(`The file is not valid JSON: ${e.message}`); }
      const r = await api("/api/ws/save", { doc });
      const box = $("edit-problems");
      if (!r.saved) {
        box.replaceChildren(el("p", { textContent: "Not saved. Fix these first:" }), el("ul", {}, ...r.problems.map((p) => el("li", { textContent: p }))));
        box.hidden = false;
        return;
      }
      box.hidden = true;
      dirty = false;
      await load();
      await refresh();
      $("edit-status").textContent = r.applied ? "Saved, and the platform restarted with it." : "Saved. Steps that depend on the changes show Changed under Set up.";
    });
  }

  $("try-form").addEventListener("submit", send);
  $("setup-all").addEventListener("click", (e) => setupAll(e.target));
  $("edit-save").addEventListener("click", (e) => saveEdit(e.target));
  window.addEventListener("beforeunload", (e) => { if (dirty) e.preventDefault(); });

  return { loadArch, loadSetup, loadClose, loadTry, loadModules, loadEdit, renderTrace, drawPeriods };
}

const MODULES = [
  { title: "Certificate authority and SPIFFE identities", layer: "controls", module: "identity", section: "02 Identity",
    what: "A root and intermediate certificate authority that issue 15-minute SPIFFE certificates, and the mutual TLS checks that use them. SPIRE takes this role in production.",
    code: `from aeos import identity\n\ntd = identity.TrustDomain("kestrel.example")       # root and intermediate\nsvid = td.issue("spiffe://kestrel.example/agent/stock/02")\nprint(identity.spiffe_id_of(svid.leaf), svid.leaf.not_valid_after_utc)`,
    cli: "aeos build FOLDER identities" },
  { title: "Delegated authority", layer: "people", module: "delegation", section: "01 Authority",
    what: "A person signs an instruction, and the authorization service turns it into a Biscuit capability token. Anyone holding a token can narrow it for one agent, and nobody can widen it.",
    code: `import time\nfrom pathlib import Path\nfrom aeos import delegation, keys\n\ncfo = keys.generate_key(Path("cfo.key"))\nintent = delegation.IntentEnvelope(\n    principal="spiffe://kestrel.example/human/cfo", audience="spiffe://kestrel.example/agent",\n    purpose="Close Q3", actions=["ledger.post"], per_action_max_minor=0, budget_minor=0,\n    currency="USD", not_after=int(time.time() * 1000) + 3_600_000).sign(cfo)\nauthority = delegation.Authority()\ntoken = authority.mint(intent, keys.public_bytes(cfo))\nmine = delegation.attenuate(token, subject="spiffe://kestrel.example/agent/stock/02",\n                            actions=["ledger.post"])\nprint(delegation.authorize(mine.to_bytes(), authority.public_key, tool="ledger.post",\n      subject="spiffe://kestrel.example/agent/stock/02", amount=0,\n      at=int(time.time() * 1000)).allowed)`,
    cli: "aeos build FOLDER instruction" },
  { title: "Rules in WebAssembly", layer: "controls", module: "policy", section: "05 Rules",
    what: "Rules written in Rego, the policy language of Open Policy Agent, compiled to WebAssembly and run in a sandbox. The same module gives the same answer when an auditor runs it again.",
    code: `from aeos import policy, workspace\n\nrules = policy.Policy.load(workspace.CLOSE_WASM, {\n    "escalate_above_minor": 25_000_000, "escalate_reason": "above the CFO's limit",\n    "approvers": [], "blocked_tools": {}, "agent_entities": {}, "default_entity": "KF-US"},\n    "aeos/close/decision")\nprint(rules.evaluate({"tool": "ledger.post", "arguments": {"lines": [\n    {"account": "5300", "debit_minor": 61_200_000},\n    {"account": "1300", "credit_minor": 61_200_000}]}}))`,
    cli: "aeos build FOLDER rules" },
  { title: "MCP gateway", layer: "controls", module: "gateway", section: "04 Connections",
    what: "One gateway for every tool call. It checks the agent's certificate, its allow list, its capability token and the rules, then runs the tool and records each step.",
    code: `from aeos.gateway import Gateway\n\n# log, tools and the files come from the modules above; see workspace.Platform\ngateway = Gateway(log, tools, permissions=allowed, trust_domain="kestrel.example",\n                  svid_files=gateway_svid, bundle_file=bundle, authority_key=key,\n                  intents=intents, principal_keys=people, policy=rules)\nport = gateway.start()`,
    cli: "aeos up FOLDER" },
  { title: "Books of account", layer: "ledger", module: "books", section: "06 Books",
    what: "A ledger for each entity, kept as events in the log. Entries must balance and fall in an open month, and only a controller's signature opens or closes a month.",
    code: `from pathlib import Path\nfrom aeos import books, keys\nfrom aeos.log import ReceiptLog, now_ms\n\nlog = ReceiptLog.create(Path("log"), log_id="urn:aeos:kestrel.example", key_path=Path("log.key"))\ncontroller = "spiffe://kestrel.example/human/controller"\ncontroller_key = keys.generate_key(Path("controller.key"))\nkf_us = books.Books(log, agent="spiffe://kestrel.example/service/books", entity="KF-US",\n                    ledger="GL", currency="USD", accounts={"6200": "Utilities",\n                    "2100": "Accrued expenses"},\n                    controllers={controller: keys.public_bytes(controller_key)})\nkf_us.transition(books.PeriodTransition("KF-US", "GL", "2026-09", "open", controller,\n                 now_ms()).sign(controller_key))`,
    cli: "aeos period FOLDER 2026-09 close --as controller --entity KF-US" },
  { title: "Receipt log", layer: "ledger", module: "log", section: "07 Records",
    what: "A log that only adds records, kept as a Merkle tree, a structure of hashes that shows any change. It signs checkpoints and gives a receipt that proves any record is in it.",
    code: `from pathlib import Path\nfrom aeos.log import ReceiptLog, make_record\n\nlog = ReceiptLog.create(Path("log"), log_id="urn:aeos:kestrel.example",\n                        key_path=Path("log.key"))\nentry = log.append(make_record("tool.call", "spiffe://kestrel.example/agent/stock/02",\n                               subject="erp.stock.ageing", body={"site": "OHIO"}))\nlog.checkpoint()\nreceipt = log.receipt(entry)`,
    cli: "aeos verify FOLDER/log" },
  { title: "Witnesses", layer: "ledger", module: "witness", section: "07 Records",
    what: "Independent services that cosign each checkpoint after checking that the log only grew, so everyone sees the same history.",
    code: `from pathlib import Path\nfrom aeos import keys, witness\nfrom aeos.log import ReceiptLog, make_record\n\nlog = ReceiptLog.create(Path("log"), log_id="urn:aeos:kestrel.example", key_path=Path("log.key"))\nlog.append(make_record("tool.call", "spiffe://kestrel.example/agent/stock/02", subject="erp.stock.ageing"))\nauditor = witness.Witness("external-auditor", keys.generate_key(Path("auditor.key")),\n                          Path("auditor.json"))\nprint(witness.request_cosignatures(log, log.checkpoint(), [auditor]))`,
    cli: "aeos seal FOLDER" },
  { title: "Audit", layer: "ledger", module: "audit", section: "07 Records",
    what: "Checks a whole evidence folder from the outside: the log, every certificate, every token and decision, the books and the witnesses' cosignatures.",
    code: `from aeos import audit\n\nfindings, problems = audit.run("kestrel-foods")\nprint("valid" if not problems else problems)`,
    cli: "aeos audit FOLDER" },
];
