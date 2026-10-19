// The builder ("Build") and the playground ("Try it") for a workspace in `aeos ui`.
// app.js passes in its helpers; this module owns the two views and the trace display.

const STEP_ICON = { pass: "✓", fail: "✕", wait: "…", skip: "–" };
const OUTCOME = {
  done: ["Done", "tag-allow", "Every check passed and the tool ran."],
  waiting: ["Waiting for approval", "tag-escalate", "The rules sent this call to a person. It has not run."],
  answered: ["Answered by a person", "tag-escalate", "This call waited for a person, who answered it. The agent then repeated the call with the answer."],
  refused: ["Refused", "tag-deny", "A check refused the call. Nothing ran past that point."],
};
const STATUSES = ["approved for payment", "awaiting approval"];

export function workspaceViews({ api, act, el, show, refresh }) {
  let ws = null;        // what /api/ws returned
  let doc = null;       // the workspace being edited
  let dirty = false;
  const $ = (id) => document.getElementById(id);

  // ---- small form helpers ---------------------------------------------------------
  const markDirty = () => { dirty = true; $("build-status").textContent = "Unsaved changes"; drawMap(); };
  function field(label, value, set, opts = {}) {
    const input = el(opts.multiline ? "textarea" : "input", {
      value: value ?? "", type: opts.type || "text", placeholder: opts.placeholder || "", spellcheck: false,
    });
    if (opts.multiline) input.rows = opts.rows || 4;
    input.addEventListener("input", () => { set(opts.type === "number" ? Number(input.value) : input.value); markDirty(); });
    return el("label", { className: opts.wide ? "wide" : "" }, label, input);
  }
  function check(label, value, set) {
    const input = el("input", { type: "checkbox", checked: !!value });
    input.addEventListener("change", () => { set(input.checked); markDirty(); rebuild(); });
    return el("label", { className: "inline" }, input, label);
  }
  function select(label, value, options, set) {
    const s = el("select", {}, ...options.map(([v, t]) => el("option", { value: v, textContent: t, selected: v === value })));
    s.addEventListener("change", () => { set(s.value); markDirty(); rebuild(); });
    return el("label", {}, label, s);
  }
  const button = (text, fn, cls = "") => {
    const b = el("button", { type: "button", textContent: text, className: cls });
    b.addEventListener("click", fn);
    return b;
  };
  const list = (v) => String(v).split(",").map((x) => x.trim()).filter(Boolean);
  const people = () => doc.people || [];
  const nameOf = (id) => (people().find((p) => p.id === id) || {}).name || id;
  const money = (minor) => `${(doc.books || {}).currency || "USD"} ${(minor / 100).toLocaleString("en-US", { minimumFractionDigits: 2 })}`;

  function allTools() {
    const tools = new Set(Object.keys(ws.tools));
    for (const s of doc.systems || []) {
      if (s.type === "example-erp") ["erp.invoice.list", "erp.invoice.get", "erp.invoice.pay"].forEach((t) => tools.add(t));
      for (const t of s.tools || []) tools.add(t);
    }
    if (doc.books) tools.add("ledger.post"); else tools.delete("ledger.post");
    return [...tools].sort();
  }

  // ---- the map: how a call travels ------------------------------------------------
  function drawMap() {
    const rules = doc.rules || { type: "none" };
    const ruleText = rules.type === "payments"
      ? `Approval above ${(doc.books || {}).currency || "USD"} ${rules.approval_above}; ${list(rules.sanctioned_suppliers || []).length} sanctioned suppliers`
      : rules.type === "wasm" ? `Your rules: ${rules.file}` : "No rules";
    const nodes = [
      ["sec-people", "People", "Sign each agent's authority, approve, close months", people().map((p) => p.name || p.id)],
      ["sec-agents", "Agents", "Act only within what a person signed", (doc.agents || []).map((a) => a.name || a.id)],
      ["sec-rules", "Gateway", "Identity · Allow list · Delegated authority · Rules", [ruleText]],
      ["sec-systems", "Systems and books", "Where the tools are", [...(doc.systems || []).map((s) => s.id), ...(doc.books ? [`Books ${doc.books.entity}`] : [])]],
      ["sec-witnesses", "Log and witnesses", "Every step recorded and sealed", [`${(doc.witnesses || {}).required || 0} of ${((doc.witnesses || {}).names || []).length} witnesses cosign`]],
    ];
    $("build-map").replaceChildren(...nodes.map(([target, title, what, items]) => {
      const b = el("button", { type: "button", className: "node" },
        el("strong", { textContent: title }), el("span", { className: "muted", textContent: what }),
        el("ul", {}, ...items.slice(0, 4).map((x) => el("li", { textContent: x }))));
      b.addEventListener("click", () => $(target).scrollIntoView({ behavior: "smooth", block: "start" }));
      return b;
    }));
  }

  // ---- the builder ----------------------------------------------------------------
  function section(id, title, help, ...body) {
    return el("section", { className: "card build-sec", id }, el("h2", { textContent: title }),
      el("p", { className: "muted", textContent: help }), ...body);
  }

  function rebuild() {
    const tools = allTools();
    const org = doc.organization;
    const parts = [];
    parts.push(section("sec-org", "Organization", "A domain name your organization controls. Every person, agent and service gets an identity under it, such as spiffe://acme.example/agent/accounts-payable.",
      el("div", { className: "grid2" },
        field("Name", org.name, (v) => { org.name = v; }),
        field("Trust domain", org.trust_domain, (v) => { org.trust_domain = v; }, { placeholder: "acme.example" }))));

    parts.push(section("sec-people", "People", "A controller opens and closes months in the books. An approver can release payments the rules hold back.",
      el("div", { className: "rows" }, ...people().map((p, i) => el("div", { className: "row4" },
        field("Name", p.name, (v) => { p.name = v; }),
        field("Id", p.id, (v) => { p.id = v; }),
        el("div", { className: "checks" },
          check("Controller", p.controller, (v) => { p.controller = v; }),
          check("Approver", p.approver, (v) => { p.approver = v; })),
        button("Remove", () => { people().splice(i, 1); markDirty(); rebuild(); }, "quiet")))),
      button("Add a person", () => { people().push({ id: `person-${people().length + 1}`, name: "New person" }); markDirty(); rebuild(); })));

    parts.push(section("sec-agents", "Agents", "Each agent gets an identity and the tools, limits and time a person signs for it.",
      ...(doc.agents || []).map((a, i) => el("div", { className: "sub" },
        el("div", { className: "grid3" },
          field("Name", a.name, (v) => { a.name = v; }),
          field("Id", a.id, (v) => { a.id = v; }),
          select("Authorized by", a.authorized_by, people().map((p) => [p.id, p.name || p.id]), (v) => { a.authorized_by = v; }),
          field("Limit per call", a.per_call_limit, (v) => { a.per_call_limit = v; }, { placeholder: "10000.00" }),
          field("Budget in total", a.budget, (v) => { a.budget = v; }, { placeholder: "20000.00" }),
          field("Hours valid", a.valid_hours, (v) => { a.valid_hours = v; }, { type: "number" })),
        field("Purpose", a.purpose, (v) => { a.purpose = v; }, { wide: true }),
        el("fieldset", {}, el("legend", { textContent: "Tools" }), el("div", { className: "checks" },
          ...tools.map((t) => check(t, (a.tools || []).includes(t), (on) => {
            a.tools = on ? [...new Set([...(a.tools || []), t])] : (a.tools || []).filter((x) => x !== t);
          })))),
        button("Remove this agent", () => { doc.agents.splice(i, 1); markDirty(); rebuild(); }, "quiet"))),
      button("Add an agent", () => {
        doc.agents.push({ id: `agent-${doc.agents.length + 1}`, name: "New agent", authorized_by: (people()[0] || {}).id,
          purpose: "", tools: [], per_call_limit: "0.00", budget: "0.00", valid_hours: 8 });
        markDirty(); rebuild();
      })));

    parts.push(section("sec-systems", "Systems", "Where the tools come from: the example ERP, a Python file of your own, or an MCP server.",
      ...(doc.systems || []).map((s, i) => el("div", { className: "sub" },
        el("div", { className: "item-head" }, el("span", { className: "badge", textContent: s.type }), el("strong", { textContent: s.id })),
        ...systemFields(s),
        button("Remove this system", () => { doc.systems.splice(i, 1); markDirty(); rebuild(); }, "quiet"))),
      el("div", { className: "actions" },
        button("Add a Python file", () => { doc.systems.push({ id: `tools-${doc.systems.length + 1}`, type: "python", file: "my_tools.py" }); markDirty(); rebuild(); }),
        button("Add an MCP server", () => { doc.systems.push({ id: `mcp-${doc.systems.length + 1}`, type: "mcp-stdio", command: ["python3", "server.py"], prefix: "", tools: [] }); markDirty(); rebuild(); }),
        button("Add an example ERP", () => { doc.systems.push({ id: `erp-${doc.systems.length + 1}`, type: "example-erp", invoices: [] }); markDirty(); rebuild(); }))));

    const rules = doc.rules || (doc.rules = { type: "none" });
    const approvers = people().filter((p) => p.approver).map((p) => p.name || p.id);
    parts.push(section("sec-rules", "Rules", "Checked by the gateway on every call, after identity and authority. Written in Rego and run as WebAssembly.",
      select("Rules", rules.type, [["payments", "Payment rules (built in)"], ["wasm", "Your own compiled rules"], ["none", "No rules"]], (v) => {
        doc.rules = v === "payments" ? { type: v, approval_above: "5000.00", sanctioned_suppliers: [] }
          : v === "wasm" ? { type: v, file: "rules/policy.wasm", entrypoint: "acme/payments/decision", data: {} } : { type: v };
      }),
      ...(rules.type === "payments" ? [el("div", { className: "grid2" },
        field("Payments above this amount need approval", rules.approval_above, (v) => { rules.approval_above = v; }),
        field("Sanctioned supplier IDs (comma separated)", (rules.sanctioned_suppliers || []).join(", "), (v) => { rules.sanctioned_suppliers = list(v); })),
      el("p", { className: "muted", textContent: approvers.length ? `Approvers: ${approvers.join(", ")}. The person who authorized an agent cannot approve its payments.` : "Mark at least one person as an approver." })] : []),
      ...(rules.type === "wasm" ? [el("div", { className: "grid2" },
        field("Compiled rules file (.wasm)", rules.file, (v) => { rules.file = v; }),
        field("Entrypoint", rules.entrypoint, (v) => { rules.entrypoint = v; })),
      jsonField("Data for the rules (JSON)", rules.data || {}, (v) => { rules.data = v; })] : [])));

    const b = doc.books;
    parts.push(section("sec-books", "Books of account", "Agents post journal entries with the ledger.post tool. Entries must balance and fall in an open month.",
      check("Keep books", !!b, (on) => {
        doc.books = on ? (doc._books || { entity: "ENTITY", ledger: "GL", currency: "USD", accounts: { 1000: "Bank" } }) : undefined;
        if (!on) doc._books = b;
      }),
      ...(b ? [el("div", { className: "grid3" },
        field("Entity", b.entity, (v) => { b.entity = v; }),
        field("Ledger", b.ledger, (v) => { b.ledger = v; }),
        field("Currency", b.currency, (v) => { b.currency = v; })),
      el("fieldset", {}, el("legend", { textContent: "Chart of accounts" }),
        el("div", { className: "rows" }, ...Object.entries(b.accounts || {}).map(([code, name]) => el("div", { className: "row3" },
          field("Account", code, (v) => { const n = b.accounts[code]; delete b.accounts[code]; b.accounts[v] = n; code = v; }),
          field("Name", name, (v) => { b.accounts[code] = v; }),
          button("Remove", () => { delete b.accounts[code]; markDirty(); rebuild(); }, "quiet")))),
        button("Add an account", () => { b.accounts[String(9000 + Object.keys(b.accounts).length)] = "New account"; markDirty(); rebuild(); }))] : [])));

    const w = doc.witnesses || (doc.witnesses = { names: [], required: 1 });
    parts.push(section("sec-witnesses", "Log and witnesses", "Witnesses are independent services that countersign each checkpoint, a signed summary of the log so far. They refuse a log that shows them two different histories.",
      el("div", { className: "grid2" },
        field("Witnesses (comma separated)", w.names.join(", "), (v) => { w.names = list(v); }),
        field("How many must cosign", w.required, (v) => { w.required = v; }, { type: "number" }))));
    $("build-form").replaceChildren(...parts);
    drawMap();
  }

  function jsonField(label, value, set) {
    const area = el("textarea", { value: JSON.stringify(value, null, 2), rows: 5, spellcheck: false });
    const note = el("span", { className: "muted" });
    area.addEventListener("input", () => {
      try { set(JSON.parse(area.value)); note.textContent = ""; markDirty(); } catch { note.textContent = "Not valid JSON yet"; }
    });
    return el("label", { className: "wide" }, label, area, note);
  }

  function systemFields(s) {
    if (s.type === "example-erp") {
      s.invoices = s.invoices || [];
      return [el("div", { className: "rows" }, ...s.invoices.map((inv, i) => el("div", { className: "row5" },
        field("Invoice", inv.invoice, (v) => { inv.invoice = v; }),
        field("Supplier", inv.supplier, (v) => { inv.supplier = v; }),
        field("Amount", inv.amount, (v) => { inv.amount = v; }),
        select("Status", inv.status || STATUSES[0], STATUSES.map((x) => [x, x]), (v) => { inv.status = v; }),
        button("Remove", () => { s.invoices.splice(i, 1); markDirty(); rebuild(); }, "quiet")))),
      button("Add an invoice", () => { s.invoices.push({ invoice: `INV-${1001 + s.invoices.length}`, supplier: "V-1000", amount: "100.00", status: STATUSES[0] }); markDirty(); rebuild(); })];
    }
    if (s.type === "python") {
      return [el("div", { className: "grid2" }, field("Id", s.id, (v) => { s.id = v; }),
        field("Python file in the workspace folder", s.file, (v) => { s.file = v; })),
      el("p", { className: "muted", textContent: "The file defines TOOLS = {\"name\": function}. Each function takes the call's arguments and returns a result." })];
    }
    return [el("div", { className: "grid2" }, field("Id", s.id, (v) => { s.id = v; }),
      field("Command", (s.command || []).join(" "), (v) => { s.command = v.split(" ").filter(Boolean); }),
      field("Prefix for its tool names", s.prefix || "", (v) => { s.prefix = v; }),
      field("Its tools, with the prefix (comma separated)", (s.tools || []).join(", "), (v) => { s.tools = list(v); }))];
  }

  async function loadBuild() {
    await act(null, async () => {
      ws = await api("/api/ws");
      doc = structuredClone(ws.doc);
      dirty = false;
      $("build-title").textContent = `Build ${doc.organization.name}`;
      $("build-file").textContent = `Saved to ${ws.file}. You can also edit the file directly.`;
      $("build-status").textContent = ws.changed ? "Saved, not yet applied" : "";
      showProblems(ws.problems);
      rebuild();
    });
  }

  function showProblems(problems) {
    const box = $("build-problems");
    box.hidden = !problems.length;
    box.replaceChildren(el("strong", { textContent: "Fix these before the workspace can run:" }),
      el("ul", {}, ...problems.map((p) => el("li", { textContent: p }))));
  }

  async function save(e) {
    await act(e.target, async () => {
      const out = structuredClone(doc);
      delete out._books;
      if (!out.books) delete out.books;
      const r = await api("/api/ws/save", { doc: out });
      if (!r.saved) { showProblems(r.problems); $("build-status").textContent = "Not saved"; return; }
      ws = r;
      dirty = false;
      showProblems([]);
      $("build-status").textContent = r.applied ? "Saved and running" : "Saved. Restart aeos up to apply it.";
      await refresh();
    });
  }

  // ---- the playground -------------------------------------------------------------
  let form = { agent: "", tool: "", args: {} };

  function scenarios() {
    const d = ws.running, out = [];
    const rules = d.rules || {};
    const limit = rules.type === "payments" ? Math.round(Number(rules.approval_above) * 100) : Infinity;
    const sanctioned = rules.sanctioned_suppliers || [];
    const payer = d.agents.find((a) => (a.tools || []).includes("erp.invoice.pay"));
    const other = d.agents.find((a) => !(a.tools || []).includes("erp.invoice.pay"));
    const open = ws.invoices.filter((i) => i.status === "approved for payment");
    const pay = (inv, who = payer) => ({ agent: who.id, tool: "erp.invoice.pay", args: { invoice: inv.invoice, amount_minor: inv.amount_minor } });
    const add = (label, f) => { if (f) out.push([label, f]); };
    const reader = d.agents.find((a) => (a.tools || []).includes("erp.invoice.get"));
    if (reader && ws.invoices[0]) add("Read an invoice", { agent: reader.id, tool: "erp.invoice.get", args: { invoice: ws.invoices[0].invoice } });
    if (payer) {
      const small = open.find((i) => i.amount_minor <= limit && !sanctioned.includes(i.supplier));
      const big = open.find((i) => i.amount_minor > limit && !sanctioned.includes(i.supplier));
      const banned = ws.invoices.find((i) => sanctioned.includes(i.supplier) && i.status !== "paid");
      const waiting = ws.invoices.find((i) => !["approved for payment", "paid"].includes(i.status));
      if (small) add("Pay a small invoice", pay(small));
      if (big) add("Pay a large invoice", pay(big));
      if (banned) add("Pay a sanctioned supplier", pay(banned));
      if (waiting) add("Pay an unapproved invoice", pay(waiting));
      if (other && ws.invoices[0]) add(`${other.name || other.id} tries to pay`, pay(ws.invoices[0], other));
    }
    const booker = d.agents.find((a) => (a.tools || []).includes("ledger.post"));
    const accts = Object.keys((d.books || {}).accounts || {});
    if (booker && accts.length > 1) {
      const today = new Date().toISOString().slice(0, 10);
      const amount = (ws.invoices[0] || {}).amount_minor || 10000;
      add("Book a journal entry", { agent: booker.id, tool: "ledger.post", args: { date: today, text: "Supplier invoice", lines: [{ account: accts[accts.length - 1], debit_minor: amount }, { account: accts[1] || accts[0], credit_minor: amount }] } });
      add("Book an entry that does not balance", { agent: booker.id, tool: "ledger.post", args: { date: today, text: "Typing error", lines: [{ account: accts[accts.length - 1], debit_minor: amount }, { account: accts[1] || accts[0], credit_minor: amount - 450 }] } });
    }
    return out;
  }

  function drawTry() {
    const d = ws.running;
    if (!d.agents.length) {
      $("try-form").replaceChildren(el("p", { textContent: "Add an agent under Build first." }));
      return;
    }
    $("try-scenarios").replaceChildren(el("span", { className: "muted", textContent: "Try:" }), ...scenarios().map(([label, f]) =>
      button(label, (e) => { form = structuredClone(f); drawForm(); send(e); }, "chip")));
    if (!form.agent || !d.agents.find((a) => a.id === form.agent)) {
      const first = d.agents[0];
      form = { agent: first.id, tool: (first.tools || [])[0] || "", args: {} };
    }
    drawForm();
    const sample = ws.invoices[0] ? `{"invoice": "${ws.invoices[0].invoice}"}` : "{}";
    const agent = d.agents[0].id;
    $("connect-body").replaceChildren(
      el("p", { textContent: `While this page or aeos up runs, your own agent connects to the gateway${ws.port ? ` on port ${ws.port}` : ""} with its certificate and token from ${ws.connect}.` }),
      el("pre", { className: "code", textContent: `from aeos import workspace\n\nagent = workspace.remote_client("${ws.folder}", "${agent}")\nagent.initialize()\nprint(agent.call("erp.invoice.get", ${sample}))\nagent.close()` }),
      el("p", { className: "muted", textContent: "The certificates are renewed every few minutes; create the client again to pick up new ones. For more, see docs/building.md in the repository." }));
  }

  function argFields() {
    const t = form.tool, a = form.args;
    const invoices = ws.invoices.map((i) => [i.invoice, `${i.invoice} · ${i.supplier} · ${money(i.amount_minor)} · ${i.status}`]);
    const pick = (label, key) => {
      if (!a[key] && invoices[0]) a[key] = invoices[0][0];
      const s = el("select", {}, ...invoices.map(([v, txt]) => el("option", { value: v, textContent: txt, selected: v === a[key] })));
      s.addEventListener("change", () => {
        a[key] = s.value;
        if (t === "erp.invoice.pay") { a.amount_minor = ws.invoices.find((i) => i.invoice === s.value).amount_minor; drawForm(); }
        drawJson();
      });
      return el("label", {}, label, s);
    };
    const amount = (label, obj, key) => {
      const input = el("input", { value: obj[key] != null ? (obj[key] / 100).toFixed(2) : "", inputMode: "decimal" });
      input.addEventListener("input", () => { const v = Math.round(Number(input.value) * 100); if (Number.isFinite(v)) obj[key] = v; else delete obj[key]; drawJson(); });
      return el("label", {}, label, input);
    };
    if (t === "erp.invoice.get") return [pick("Invoice", "invoice")];
    if (t === "erp.invoice.pay") {
      if (!a.invoice && ws.invoices[0]) { a.invoice = ws.invoices[0].invoice; a.amount_minor = ws.invoices[0].amount_minor; }
      return [pick("Invoice", "invoice"), amount("Amount to pay", a, "amount_minor")];
    }
    if (t === "erp.invoice.list") return [el("p", { className: "muted", textContent: "This tool takes no arguments." })];
    if (t === "ledger.post") {
      const accounts = Object.entries((ws.running.books || {}).accounts || {});
      a.date = a.date || new Date().toISOString().slice(0, 10);
      a.text = a.text ?? "";
      a.lines = a.lines || [{ account: accounts[0]?.[0], debit_minor: 0 }, { account: accounts[1]?.[0], credit_minor: 0 }];
      const simple = (label, key, type = "text") => {
        const input = el("input", { value: a[key], type });
        input.addEventListener("input", () => { a[key] = input.value; drawJson(); });
        return el("label", {}, label, input);
      };
      return [el("div", { className: "grid2" }, simple("Date", "date", "date"), simple("Description", "text")),
        ...a.lines.map((ln, i) => {
          const s = el("select", {}, ...accounts.map(([c, n]) => el("option", { value: c, textContent: `${c} ${n}`, selected: c === ln.account })));
          s.addEventListener("change", () => { ln.account = s.value; drawJson(); });
          return el("div", { className: "row3" }, el("label", {}, `Line ${i + 1}`, s), amount("Debit", ln, "debit_minor"), amount("Credit", ln, "credit_minor"));
        }),
        button("Add a line", () => { a.lines.push({ account: accounts[0]?.[0] }); drawForm(); }, "quiet")];
    }
    return [];
  }

  function drawJson() {
    const area = $("try-json");
    if (area && document.activeElement !== area) area.value = JSON.stringify(cleanArgs(), null, 2);
  }
  const cleanArgs = () => {
    const a = structuredClone(form.args);
    if (Array.isArray(a.lines)) a.lines = a.lines.map((ln) => Object.fromEntries(Object.entries(ln).filter(([, v]) => v !== 0 && v != null)));
    return a;
  };

  function drawForm() {
    const d = ws.running;
    const agent = d.agents.find((x) => x.id === form.agent) || d.agents[0];
    const given = agent.tools || [];
    const others = Object.keys(ws.tools).filter((t) => !given.includes(t)).sort();
    const agentSel = el("select", {}, ...d.agents.map((x) => el("option", { value: x.id, textContent: x.name || x.id, selected: x.id === agent.id })));
    agentSel.addEventListener("change", () => { form.agent = agentSel.value; drawForm(); });
    const toolSel = el("select", {},
      el("optgroup", { label: "Given to this agent" }, ...given.map((t) => el("option", { value: t, textContent: t, selected: t === form.tool }))),
      ...(others.length ? [el("optgroup", { label: "Not given (the gateway refuses these)" }, ...others.map((t) => el("option", { value: t, textContent: t, selected: t === form.tool })))] : []));
    toolSel.addEventListener("change", () => { form.tool = toolSel.value; form.args = {}; drawForm(); });
    const json = el("textarea", { id: "try-json", rows: 6, spellcheck: false });
    json.addEventListener("input", () => { try { form.args = JSON.parse(json.value); json.classList.remove("bad"); } catch { json.classList.add("bad"); } });
    const fields = argFields();
    const sendBtn = el("button", { className: "primary", textContent: `Send as ${agent.name || agent.id}` });
    $("try-form").replaceChildren(
      el("div", { className: "grid2" }, el("label", {}, "Agent", agentSel), el("label", {}, "Tool", toolSel)),
      el("p", { className: "muted", textContent: `Acts for ${nameOfRunning(agent.authorized_by)}: up to ${money(Math.round(Number(agent.per_call_limit) * 100))} a call, ${money(Math.round(Number(agent.budget) * 100))} in total.` }),
      ...fields,
      el("details", { open: !fields.length }, el("summary", { textContent: "Arguments as JSON" }), json),
      sendBtn);
    drawJson();
  }
  const nameOfRunning = (id) => (ws.running.people.find((p) => p.id === id) || {}).name || id;

  async function send(e) {
    if (e && e.preventDefault) e.preventDefault();
    await act(e && e.target && e.target.tagName === "BUTTON" ? e.target : null, async () => {
      const r = await api("/api/ws/call", { agent: form.agent, tool: form.tool, args: cleanArgs() });
      renderTrace($("try-trace"), r, { approve: true });
      ws = await api("/api/ws");
      $("try-scenarios").replaceChildren(el("span", { className: "muted", textContent: "Try:" }), ...scenarios().map(([label, f]) =>
        button(label, (ev) => { form = structuredClone(f); drawForm(); send(ev); }, "chip")));
    });
  }

  // ---- the trace ------------------------------------------------------------------
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
        renderTrace(box, r, opts);
      });
      parts.push(el("div", { className: "approve" }, el("strong", { textContent: "Answer as a person" }),
        el("label", {}, "Signed by", who),
        el("div", { className: "actions tight" }, button("Approve", answerAs("approve"), "primary"), button("Reject", answerAs("reject")))));
    }
    if (answer.trace) {
      parts.push(el("h3", { textContent: "What the agent got back" }),
        el("pre", { className: "code", textContent: answer.result != null ? JSON.stringify(answer.result, null, 2) : answer.text }));
      const args = Object.entries(cleanArgs()).map(([k, v]) => `${k}=${typeof v === "string" ? v : `'${JSON.stringify(v)}'`}`).join(" ");
      parts.push(el("details", {}, el("summary", { textContent: "The same call from the command line" }),
        el("pre", { className: "code", textContent: `aeos call ${ws.folder} --as ${form.agent} ${form.tool} ${args}` })));
    }
    box.replaceChildren(...parts);
    box.hidden = false;
    // Reveal the checks one after another, in the order the gateway ran them.
    [...steps.children].forEach((li, i) => setTimeout(() => li.classList.add("shown"), 120 + i * 180));
  }

  // ---- books: open and close months ------------------------------------------------
  async function drawPeriods() {
    const box = $("period-form");
    if (!ws) ws = await api("/api/ws");
    const controllers = ws.running.people.filter((p) => p.controller);
    if (!ws.running.books || !controllers.length) { box.hidden = true; return; }
    const month = el("input", { type: "month", value: new Date().toISOString().slice(0, 7), required: true });
    const state = el("select", {}, el("option", { value: "open", textContent: "Open" }), el("option", { value: "closed", textContent: "Close" }));
    const who = el("select", {}, ...controllers.map((p) => el("option", { value: p.id, textContent: p.name || p.id })));
    const go = el("button", { className: "primary", textContent: "Sign the change" });
    box.replaceChildren(el("label", {}, "Month", month), el("label", {}, "Change", state), el("label", {}, "Signed by", who), go);
    box.hidden = false;
    box.onsubmit = (e) => {
      e.preventDefault();
      act(go, async () => {
        ws = await api("/api/ws/period", { period: month.value, state: state.value, person: who.value });
        show("books");
      });
    };
  }

  $("build-save").addEventListener("click", save);
  $("try-form").addEventListener("submit", send);
  window.addEventListener("beforeunload", (e) => { if (dirty) e.preventDefault(); });

  return {
    loadBuild,
    async loadTry() { await act(null, async () => { ws = await api("/api/ws"); drawTry(); }); },
    renderTrace,
    drawPeriods,
  };
}
