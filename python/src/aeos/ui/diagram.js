// The architecture as a live diagram: the layers of ae-os.org/how-it-works, filled in from
// the workspace. Parts that a setup step has not made yet are drawn faint, and each call
// travels through the parts it touches, lighting each check as it passes or fails.

const NS = "http://www.w3.org/2000/svg";
const W = 1000;
const LEFT = 150;
export const LAYERS = [
  { id: "people", label: "People", note: "Sign instructions, approvals and period locks", y: 34, h: 62 },
  { id: "agents", label: "Agents", note: "Do the work their credentials allow", y: 126, h: 62 },
  { id: "controls", label: "Controls", note: "Check identity and rules before every call", y: 218, h: 92 },
  { id: "systems", label: "Systems", note: "Provide the tools agents call", y: 340, h: 56 },
  { id: "ledger", label: "Ledger", note: "Keeps the books and a receipt for every step", y: 426, h: 62 },
];
const H = 510;
// Which gateway check each step of a call's trace lights, in order.
const CHECKS = [["identity", "Identity", "identities"], ["allow", "Allow list", "agents"],
  ["authority", "Authority", "instruction"], ["rules", "Rules", "rules"]];

function svg(tag, attrs = {}, ...kids) {
  const n = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) if (v != null) n.setAttribute(k, v);
  for (const k of kids) n.append(k);
  return n;
}
const text = (x, y, s, cls, anchor = "middle") => svg("text", { x, y, class: cls, "text-anchor": anchor }, s);
const short = (s, n) => (s.length > n ? s.slice(0, n - 1) + "…" : s);

// Place `items` evenly in [x0, x1], each up to `max` wide.
function row(items, x0, x1, max, gap = 12) {
  const n = Math.max(items.length, 1);
  const w = Math.min(max, (x1 - x0 - gap * (n - 1)) / n);
  const total = n * w + gap * (n - 1);
  let x = x0 + (x1 - x0 - total) / 2;
  return items.map((it) => { const at = { ...it, x, w }; x += w + gap; return at; });
}

export function createDiagram(host, { compact = false, onPick = null } = {}) {
  let nodes = {}, ws = null;
  const root = svg("svg", { viewBox: `0 0 ${W} ${H}`, class: `arch${compact ? " compact" : ""}`, role: "img" });
  const caption = Object.assign(document.createElement("p"), { className: "arch-caption" });
  caption.setAttribute("aria-live", "polite");
  host.replaceChildren(root, caption);

  function node(id, layer, step, x, y, w, h, title, sub) {
    const g = svg("g", { class: `node lay-${layer}`, "data-id": id, "data-step": step, tabindex: onPick ? 0 : null });
    g.append(svg("rect", { x, y, width: w, height: h, rx: 9 }));
    const max = Math.max(6, Math.floor(w / 7.4));
    g.append(text(x + w / 2, y + (sub ? h / 2 - 3 : h / 2 + 5), short(title, max), "n-title"));
    if (sub) g.append(text(x + w / 2, y + h / 2 + 14, short(sub, Math.floor(w / 6.4)), "n-sub"));
    g.append(svg("title", {}, `${title}${sub ? `: ${sub}` : ""}`));
    if (onPick) {
      g.addEventListener("click", () => onPick({ id, layer, step }));
      g.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onPick({ id, layer, step }); } });
    }
    nodes[id] = { g, cx: x + w / 2, cy: y + h / 2, x, y, w, h };
    return g;
  }

  function draw(data) {
    ws = data;
    nodes = {};
    const d = ws.running, g = svg("g");
    root.replaceChildren(g);
    const org = d.organization;
    g.append(text(LEFT, 18, `${org.name} · trust domain ${org.trust_domain}`, "org", "start"));
    for (const L of LAYERS) {
      g.append(svg("rect", { x: 0, y: L.y - 8, width: W, height: L.h + 16, class: `band lay-${L.id}` }));
      g.append(text(12, L.y + 22, L.label, `band-label lay-${L.id}`, "start"));
      if (!compact) g.append(svg("foreignObject", { x: 10, y: L.y + 28, width: LEFT - 20, height: L.h - 22 },
        Object.assign(document.createElement("div"), { className: "band-note", textContent: L.note })));
    }
    const P = LAYERS[0], A = LAYERS[1], C = LAYERS[2], S = LAYERS[3], Lg = LAYERS[4];
    for (const p of row(d.people, LEFT, W - 10, 170)) {
      const role = p.approver ? "approver" : p.controller ? "controller" : (p.role || "");
      g.append(node(`person:${p.id}`, "people", "people", p.x, P.y, p.w, P.h, p.name || p.id, role));
    }
    for (const a of row(d.agents, LEFT, W - 10, 140, 8)) {
      g.append(node(`agent:${a.id}`, "agents", "agents", a.x, A.y, a.w, A.h, a.id, a.team || a.name || ""));
    }
    g.append(node("ca", "controls", "pki", LEFT, C.y + 8, 140, C.h - 16, "Certificate authority", "SPIFFE IDs"));
    g.append(node("authz", "controls", "instruction", W - 150, C.y + 8, 140, C.h - 16, "Authorization", "capability tokens"));
    const gx = LEFT + 160, gw = W - 170 - gx;
    const gate = node("gateway", "controls", "gateway", gx, C.y, gw, C.h, "", "");
    gate.querySelectorAll("text").forEach((t) => t.remove());
    gate.append(text(gx + 14, C.y + 20, "MCP gateway", "n-title", "start"));
    gate.append(text(gx + gw - 14, C.y + 20, `spiffe://${org.trust_domain}/gateway/mcp`, "n-sub", "end"));
    g.append(gate);
    for (const [i, [id, label, step]] of CHECKS.entries()) {
      const cw = (gw - 28 - 3 * 10) / 4;
      g.append(node(`check:${id}`, "controls", step, gx + 14 + i * (cw + 10), C.y + 32, cw, C.h - 44, label, ""));
    }
    const systems = d.systems.map((s) => ({ id: s.id, name: s.name || s.id }));
    if (d.books) systems.push({ id: "books", name: "Books service" });
    for (const s of row(systems, LEFT, W - 10, 200)) {
      g.append(node(`system:${s.id}`, "systems", s.id === "books" ? "books" : "systems", s.x, S.y, s.w, S.h, s.name, s.id === "books" ? "ledger.post" : ""));
    }
    const names = ws.entities || {};
    const ledger = Object.keys(names).map((e) => ({ id: `books:${e}`, title: `Books ${e}`, sub: names[e] !== e ? names[e] : "", step: "books" }));
    ledger.push({ id: "log", title: "Receipt log", sub: "Merkle tree, signed checkpoints", step: "log" });
    ledger.push({ id: "witnesses", title: "Witnesses", sub: (d.witnesses.names || []).join(", "), step: "log" });
    for (const l of row(ledger, LEFT, W - 10, 220)) g.append(node(l.id, "ledger", l.step, l.x, Lg.y, l.w, Lg.h, l.title, l.sub));
    root.append(svg("g", { class: "trail" }));
    root.append(svg("circle", { class: "packet", r: 7, cx: -20, cy: -20 }));
    setSteps(ws.steps);
  }

  function setSteps(steps) {
    const done = new Set((steps || []).filter((s) => s.state === "done").map((s) => s.id));
    for (const n of Object.values(nodes)) n.g.classList.toggle("pending", !done.has(n.g.dataset.step));
  }

  function highlight(step) {
    for (const n of Object.values(nodes)) n.g.classList.toggle("focus", !!step && n.g.dataset.step === step);
  }

  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
  let running = Promise.resolve(), latest = 0;

  async function hop(from, to) {
    const p = root.querySelector(".packet"), trail = root.querySelector(".trail");
    if (!from || !to) return;
    trail.append(svg("line", { x1: from.cx, y1: from.cy, x2: to.cx, y2: to.cy }));
    if (reduce) { p.setAttribute("cx", to.cx); p.setAttribute("cy", to.cy); return; }
    const t0 = performance.now(), ms = 220;
    await new Promise((done) => {
      const tick = (t) => {
        const k = Math.min(1, (t - t0) / ms), e = k < 0.5 ? 2 * k * k : 1 - (-2 * k + 2) ** 2 / 2;
        p.setAttribute("cx", from.cx + (to.cx - from.cx) * e);
        p.setAttribute("cy", from.cy + (to.cy - from.cy) * e);
        if (k < 1) requestAnimationFrame(tick); else done();
      };
      requestAnimationFrame(tick);
    });
  }

  function mark(id, state) {
    const n = nodes[id];
    if (n) n.g.classList.add(`hit-${state}`);
  }

  // Play one call's journey: the person it acts for, the agent, each gateway check, the
  // person who approved it, the system that ran it, the books, and the log.
  // A newer call replaces one still playing, so the diagram never lags behind the log.
  // A diagram on a hidden view does not play at all.
  function play(trace, { agent, tool, args = {} } = {}) {
    if (!root.isConnected || !root.getClientRects().length) return running;
    const gen = ++latest;
    running = running.then(() => (gen === latest ? playNow(trace, { agent, tool, args }, gen) : null)).catch(() => {});
    return running;
  }

  async function playNow(trace, { agent, tool, args }, gen) {
    if (!ws) return;
    for (const n of Object.values(nodes)) n.g.classList.remove("hit-pass", "hit-fail", "hit-wait", "hit-skip");
    root.querySelector(".trail").replaceChildren();
    const steps = Object.fromEntries(trace.steps.map((s) => [s.step, s]));
    const d = ws.running;
    const agentId = agent || (trace.agent || "").split("/agent/")[1];
    const a = d.agents.find((x) => x.id === agentId) || {};
    const obo = a.authorized_by || ((d.instructions || []).find((i) => i.id === a.instruction) || {}).signed_by;
    const path = [];
    if (obo) path.push([`person:${obo}`, "pass", `${trace.on_behalf_of_name || obo} signed the authority this agent acts under`]);
    path.push([`agent:${agentId}`, "pass", `${trace.agent_name || agentId} calls ${trace.tool}`]);
    for (const [id] of CHECKS) {
      const s = steps[id];
      if (!s) continue;
      path.push([`check:${id}`, s.state, `${s.label}: ${s.text}`]);
      if (s.state === "fail") break;
    }
    const failed = path.some((p) => p[1] === "fail");
    if (!failed && steps.approval && steps.approval.state !== "skip") {
      const who = (d.people.find((p) => steps.approval.text.includes(p.name || p.id)) || d.people.find((p) => p.approver) || {}).id;
      if (who) path.push([`person:${who}`, steps.approval.state, `Approval: ${steps.approval.text}`]);
      if (steps.approval.state !== "pass") path.push(null);
    }
    if (!failed && path[path.length - 1] !== null && steps.tool) {
      const sys = (ws.tools || {})[tool || trace.tool];
      if (sys) path.push([`system:${sys}`, steps.tool.state === "fail" && steps.books && steps.books.state === "fail" ? "pass" : steps.tool.state, `${trace.tool}: ${steps.tool.text}`]);
      if (steps.books && steps.books.state !== "skip") {
        const entity = args.entity || Object.keys(ws.entities || {})[0];
        path.push([`books:${entity}`, steps.books.state, `Books: ${steps.books.text}`]);
      }
    }
    const tail = path.filter(Boolean);
    tail.push(["log", "pass", steps.receipt ? steps.receipt.text : "Recorded"]);
    let prev = null;
    for (const [id, state, say] of tail) {
      if (gen !== latest) return;
      const n = nodes[id];
      if (!n) continue;
      await hop(prev, n);
      mark(id, state);
      caption.textContent = say;
      caption.className = `arch-caption say-${state}`;
      prev = n;
      await sleep(reduce ? 60 : 240);
    }
  }

  function flash(ids, state = "pass") {
    for (const id of ids) mark(id, state);
  }

  return { draw, setSteps, highlight, play, flash, nodes: () => nodes, caption };
}
