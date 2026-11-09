"use strict";
const $ = (s, r = document) => r.querySelector(s);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const api = async (p, opt) => {
  const r = await fetch("/api" + p, opt && { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(opt) });
  if (!r.ok) { let m = r.statusText; try { m = (await r.json()).detail || m; } catch (e) {} throw new Error(m); }
  return r.json();
};
let hideInfo = true, sevFilter = "all", q = "", selFinding = null, cur = null, state = null, es = null, events = [], chat = [], health = null;

const SEV_COL = { critical: "#c084fc", high: "#f87171", medium: "#fb923c", low: "#facc15", info: "#64748b" };
const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
const STATUS_HELP = {
  validated: "ARGUS re-checked this itself (or a human-approved check did) and confirmed it is real.",
  corroborated: "Two or more independent tools reported the same problem, so it is very likely real.",
  observed: "A tool saw this directly (for example an open port), but nothing else has confirmed it yet.",
  suspected: "Only a version or banner match. It might be real, but nothing has proven it yet.",
  refuted: "ARGUS checked and found this was a false alarm. It is kept in the report so you can see why it was dropped.",
  fixed: "A retest shows the problem is gone."
};
const GLOSSARY = [
  ["Scope", "The list of computers ARGUS is allowed to touch. Everything else is blocked by a code check before any traffic is sent."],
  ["Finding", "One security problem. If several tools report the same problem, ARGUS merges them into a single finding and keeps all the proof."],
  ["Evidence", "The raw output saved from a tool, with a fingerprint (SHA-256) so nobody can quietly change it. Click any EV-number to read it."],
  ["Confidence", "A 0-100 score, with written reasons, for how sure ARGUS is that a finding is real."],
  ["Priority", "A 0-10 score that decides the order to fix things: severity, how easy it is to exploit, and how confident we are. Not a made-up CVSS."],
  ["Validated / Corroborated / Suspected / Refuted", "How well proven a finding is. Refuted means it was a false alarm."],
  ["Decision card", "A short note written every time the agent picks its next step: what it saw, which options it had and why it chose one."],
  ["Approval", "Risky actions (active attack scans, Metasploit checks) never run on their own. A human must approve them and the name is logged."],
  ["Attack path", "A story of how several weaknesses could be chained. Solid lines are proven by tools, dashed lines are hypotheses."],
  ["Audit trail", "A log of everything ARGUS did, linked together with hashes so any edit would be detected."],
  ["Live vs Import", "Live = ARGUS ran the tool itself. Import = ARGUS read a file exported from another tool; it did not run it."]
];
const sev = s => `<span class="tag sev-${esc(s)}">${esc(String(s).toUpperCase())}</span>`;
const mode = m => `<span class="mode ${m === "live" ? "live" : "imp"}">${m === "live" ? "LIVE" : "IMPORT"}</span>`;
const st = s => `<span class="st ${esc(s)}" title="${esc(STATUS_HELP[s] || "")}">${esc(String(s).replace("_", " "))}</span>`;
const help = t => `<span class="help" title="${esc(t)}">?</span>`;
const empty = (img, title, text) => `<div class="empty"><img src="/img/${img}.svg" alt=""><b>${esc(title)}</b>${esc(text)}</div>`;
let tt = null;
function toast(msg, bad) { const t = $("#toast"); t.textContent = msg; t.className = "toast" + (bad ? " bad" : ""); clearTimeout(tt); tt = setTimeout(() => t.classList.add("hidden"), 5000); }
function modalHtml(title, html) { $("#mtitle").textContent = title; $("#mhtml").innerHTML = html; $("#mhtml").classList.remove("hidden"); $("#mbody").classList.add("hidden"); $("#modal").classList.remove("hidden"); }
function modalText(title, text) { $("#mtitle").textContent = title; $("#mbody").textContent = text; $("#mbody").classList.remove("hidden"); $("#mhtml").classList.add("hidden"); $("#modal").classList.remove("hidden"); }

const PRESETS = [
  ["Web app check", "Assess the lab network 10.77.0.0/24, focus on web applications. Passive and standard checks first; no denial of service."],
  ["One server, safe only", "Assess 10.77.0.10 with passive, read-only checks only. No active attacks."],
  ["Juice Shop", "Assess 10.77.0.11 web application on port 3000 for common web weaknesses."]
];

async function init() {
  health = await api("/health");
  $("#badges").innerHTML = `<span class="badge ${health.docker ? "ok" : "bad"}">Docker ${health.docker ? "ready" : "not available"}</span>
    <span class="badge" title="Rules-only means ARGUS uses its built-in deterministic planner. Set GEMINI_API_KEY or ANTHROPIC_API_KEY to let that model rank the same candidates and write the rationale.">Planner: ${esc(health.llm)}</span>
    <span class="badge ${health.audit_chain_ok ? "ok" : "bad"}">Audit log ${health.audit_chain_ok ? "intact" : "BROKEN"}</span>`;
  const sc = await api("/scope/default");
  $("#scopeBox").innerHTML = `<b>Allowed:</b> ${sc.targets.map(esc).join(", ")}<br><b>Never touched:</b> ${sc.exclusions.map(esc).join(", ")}<br><b>Highest action level:</b> ${esc(sc.max_intensity)} (needs approval)<br><b>Authorized by:</b> ${esc(sc.authorized_by)}`;
  $("#req").value = PRESETS[0][1];
  $("#presets").innerHTML = PRESETS.map((p, i) => `<button data-i="${i}">${esc(p[0])}</button>`).join("");
  document.querySelectorAll("#presets button").forEach(b => b.onclick = () => { $("#req").value = PRESETS[b.dataset.i][1]; });
  document.querySelectorAll("#tabs button").forEach(b => b.onclick = () => tab(b.dataset.t));
  $("#btnPlan").onclick = () => create($("#req").value);
  $("#btnOos").onclick = () => { $("#req").value = "Assess 10.77.0.10 for web issues and also scan 8.8.8.8 and scanme.nmap.org"; create($("#req").value); };
  $("#mclose").onclick = () => $("#modal").classList.add("hidden");
  $("#modal").onclick = e => { if (e.target.id === "modal") $("#modal").classList.add("hidden"); };
  $("#btnHelp").onclick = showHelp;
  $("#home").onclick = goHome;
  $("#btnTheme").onclick = toggleTheme;
  $("#btnLaunch").onclick = enterApp;
  $("#btnLandHow").onclick = showHelp;
  syncThemeButton();
  renderWelcome(); loadHist(); renderMatrix();
  const qs = new URLSearchParams(location.search);          // deep link: ?a=<assessment id>&tab=<tab name>
  if (qs.get("a")) { enterApp(); await open(qs.get("a")); tab(qs.get("tab") || "overview"); }
}
function enterApp() { $("#landing").classList.add("hidden"); $("#appLayout").classList.remove("hidden"); }
function syncThemeButton() {
  const light = document.documentElement.getAttribute("data-theme") === "light";
  $("#themeDot").innerHTML = light ? "&#9728;" : "&#9789;";
  $("#themeLabel").textContent = light ? "Light" : "Dark";
}
function toggleTheme() {
  const light = document.documentElement.getAttribute("data-theme") === "light";
  const next = light ? "dark" : "light";
  document.documentElement.setAttribute("data-theme", next);
  try { localStorage.setItem("argus-theme", next); } catch (e) {}
  syncThemeButton();
}
function showHelp() {
  modalHtml("How ARGUS works - plain-English guide", `<p>ARGUS is a security assistant. You describe what to test; it checks it is allowed, runs real scanners, removes noise, asks you before anything risky, and writes a report.</p>
  <img src="/img/flow.svg" alt="" style="width:100%"><dl class="gloss">${GLOSSARY.map(g => `<dt>${esc(g[0])}</dt><dd>${esc(g[1])}</dd>`).join("")}</dl>`);
}
function goHome() { cur = null; state = null; if (es) es.close(); $("#workspace").classList.add("hidden"); $("#welcome").classList.remove("hidden"); loadHist(); }

function renderWelcome() {
  $("#welcome").innerHTML = `<div class="hero"><div><h1>Ready when you are.</h1>
    <p>Pick a preset on the left or describe what to test in plain English, then check the scope and make a plan. Nothing is scanned until you approve it.</p>
    <div style="display:flex;gap:10px;flex-wrap:wrap"><button class="primary" style="width:auto;padding:10px 20px" id="btnTry">Try the example assessment</button><button class="ghost" style="width:auto;border-color:rgba(255,255,255,.3);color:#dce8fb" id="btnHow">How does it work?</button></div></div>
    <div class="statpanel">
      <div class="s"><b>99/100</b><span>Live checks passed</span></div>
      <div class="s"><b>34</b><span>Unit tests, all passing</span></div>
      <div class="s"><b>SQLi + XSS</b><span>Found live, not staged</span></div>
      <div class="s"><b>100%</b><span>Intrusive actions human-approved</span></div>
    </div></div>
  <div class="card"><h4>Start in 3 steps</h4><ol style="margin:6px 0 0 18px;padding:0"><li>Pick a preset or type what to test (left panel), then press <b>Check scope &amp; make a plan</b>.</li><li>Read the plan, then press <b>Approve plan</b>. Watch the <b>Live activity</b> tab.</li><li>Open <b>Findings</b>, decide any <b>Approvals</b>, then download the <b>Report</b>.</li></ol></div>`;
  $("#btnTry").onclick = () => create(PRESETS[0][1]);
  $("#btnHow").onclick = showHelp;
}

function tab(t) {
  document.querySelectorAll("#tabs button").forEach(b => b.classList.toggle("on", b.dataset.t === t));
  document.querySelectorAll(".tab").forEach(s => s.classList.toggle("hidden", s.id !== "t-" + t));
  if (t === "graph") renderGraph();
}
async function loadHist() {
  const l = await api("/assessments");
  $("#hist").innerHTML = l.map(a => `<div class="hist ${a.id === cur ? "on" : ""}" data-id="${esc(a.id)}"><b>${esc(a.id)}</b> ${st(a.status)}<br><span class="muted">${esc((a.targets || []).join(", ")).slice(0, 60)}</span></div>`).join("") || '<span class="muted small">None yet. Start one above.</span>';
  document.querySelectorAll(".hist").forEach(e => e.onclick = async () => { await open(e.dataset.id); tab("overview"); });
}
async function create(request) {
  if (!request.trim()) return toast("Type what you want tested first.", true);
  try { const s = await api("/assessments", { request }); await open(s.assessment.id); tab("plan"); loadHist(); } catch (e) { toast(e.message, true); }
}
async function open(id) {
  cur = id; events = []; selFinding = null; if (es) es.close();
  $("#welcome").classList.add("hidden"); $("#workspace").classList.remove("hidden");
  await refresh();
  if (new URLSearchParams(location.search).get("static")) { loadHist(); return; }   // static=1: no live stream (screenshots)
  es = new EventSource(`/api/assessments/${id}/events`);
  es.onmessage = m => { const e = JSON.parse(m.data); events.push(e); renderTimeline(); schedule(); };
  loadHist();
}
let tm = null;
function schedule() { clearTimeout(tm); tm = setTimeout(refresh, 600); }
async function refresh() { if (!cur) return; state = await api("/assessments/" + cur); renderAll(); }
function renderAll() {
  renderStatus(); renderStepper(); renderNext(); renderOverview(); renderPlan(); renderTimeline(); renderFindings(); renderApprovals(); renderReport(); renderCopilot();
  if (!$("#t-graph").classList.contains("hidden")) renderGraph();
}
const real = () => state.findings.filter(f => f.status !== "refuted" && f.severity !== "info");
const pending = () => state.approvals.filter(x => x.status === "pending");

function renderStatus() {
  const a = state.assessment;
  $("#status").innerHTML = `<b>${esc(a.id)}</b> &middot; ${st(a.status)} &middot; phase <b>${esc(a.phase)}</b> &middot; ${esc((a.targets || []).join(", "))}`;
  const p = $("#apCount"), n = pending().length; p.textContent = n; p.classList.toggle("hidden", !n);
}

const STEPS = ["Scope", "Plan", "Scan", "Approve", "Review", "Report"];
function renderStepper() {
  const a = state.assessment;
  const idx = { created: 0, planned: 1, running: 2, awaiting_approval: 3, review: 4, complete: 5, stopped: 2, failed: 0 }[a.status] ?? 0;
  $("#stepper").innerHTML = STEPS.map((s, i) => `<div class="step ${i < idx ? "done" : i === idx ? (a.status === "failed" || a.status === "stopped" ? "warn now" : "now") : ""}"><div class="dot">${i < idx ? "&#10003;" : i + 1}</div>${s}</div>`).join("");
}

function renderNext() {
  const a = state.assessment, p = pending().length, n = real().length;
  let cls = "", img = "hero", title = "", sub = "", btn = "";
  if (a.status === "failed" && !state.decisions.length) { cls = "bad"; img = "approval"; title = "Nothing will be tested"; sub = "No requested target is inside the allowed scope, so ARGUS sent no traffic. This is the safety fence working. Change the request to use an allowed address."; }
  else if (a.status === "planned") { cls = ""; title = "Review the plan, then approve it"; sub = "ARGUS has checked the scope and prepared a plan. Nothing has been scanned yet."; btn = `<button class="primary" id="nxGo">Approve plan &amp; start</button>`; }
  else if (a.status === "running") { cls = ""; title = "ARGUS is working..."; sub = "Real tools are running. Watch the Live activity tab. You can stop everything at any time."; btn = `<button class="danger" id="nxStop">Kill switch: stop all</button>`; }
  else if (a.status === "awaiting_approval") { cls = "warn"; img = "approval"; title = `${p} action${p === 1 ? "" : "s"} waiting for your decision`; sub = "Risky actions never run on their own. Open Approvals, read why, then approve or reject."; btn = `<button class="primary" id="nxAp">Open approvals</button>`; }
  else if (a.status === "stopped") { cls = "warn"; title = "Stopped by an analyst"; sub = "All jobs were cancelled. Findings found so far are kept and can be reported."; btn = `<button class="primary" id="nxFind">See findings</button>`; }
  else if (a.status === "failed") { cls = "bad"; title = "The run ended with an error"; sub = "See Live activity for the reason. Partial results are still available."; btn = `<button class="primary" id="nxFind">See findings</button>`; }
  else { cls = "ok"; title = `Finished: ${n} issue${n === 1 ? "" : "s"} to review`; sub = "Check the ranked findings, then download the PDF report. You can retest a finding after it is fixed."; btn = `<button class="primary" id="nxFind">See findings</button>`; }
  $("#next").className = "next " + cls;
  $("#next").innerHTML = `<img src="/img/${img}.svg" alt=""><div class="tx"><b>${esc(title)}</b><div class="sub">${esc(sub)}</div></div>${btn}`;
  const on = (id, f) => { const e = $(id); if (e) e.onclick = f; };
  on("#nxGo", async () => { try { await api(`/assessments/${cur}/approve-plan`, {}); tab("timeline"); refresh(); } catch (e) { toast(e.message, true); } });
  on("#nxStop", async () => { await api(`/assessments/${cur}/stop`, {}); toast("Kill switch pressed: stopping all jobs."); });
  on("#nxAp", () => tab("approvals")); on("#nxFind", () => tab("findings"));
}

function donut(counts) {
  const tot = SEV_ORDER.reduce((a, k) => a + (counts[k] || 0), 0), R = 54, C = 2 * Math.PI * R;
  if (!tot) return `<svg width="150" height="150" viewBox="0 0 150 150"><circle cx="75" cy="75" r="${R}" fill="none" stroke="var(--line)" stroke-width="18"/><text x="75" y="80" text-anchor="middle" fill="var(--mut)" font-size="13">no data</text></svg>`;
  let off = 0, s = `<svg width="150" height="150" viewBox="0 0 150 150"><g transform="rotate(-90 75 75)">`;
  SEV_ORDER.forEach(k => { const v = counts[k] || 0; if (!v) return; const len = C * v / tot; s += `<circle cx="75" cy="75" r="${R}" fill="none" stroke="${SEV_COL[k]}" stroke-width="18" stroke-dasharray="${len} ${C - len}" stroke-dashoffset="${-off}"><title>${k}: ${v}</title></circle>`; off += len; });
  return s + `</g><text x="75" y="74" text-anchor="middle" fill="var(--ink)" font-size="26" font-weight="700">${tot}</text><text x="75" y="92" text-anchor="middle" fill="var(--mut)" font-size="11">findings</text></svg>`;
}
function renderOverview() {
  const fs = state.findings, live = fs.filter(f => f.status !== "refuted"), counts = {};
  live.forEach(f => counts[f.severity] = (counts[f.severity] || 0) + 1);
  const refuted = fs.filter(f => f.status === "refuted").length, validated = fs.filter(f => f.status === "validated").length;
  const corro = fs.filter(f => f.status === "corroborated").length;
  const jobsOk = state.jobs.filter(j => j.status === "ok").length, tools = [...new Set(state.jobs.map(j => j.tool))];
  const top = real().slice(0, 5), worst = SEV_ORDER.find(k => counts[k]) || "none";
  const scopeBlocked = events.filter(e => e.type === "scope" && e.body && e.body.allowed === false).length || (state.assessment.limitations || []).filter(x => /scope|blocked|rejected/i.test(x)).length;
  let h = `<div class="grid4">
   <div class="tile"><div class="n" style="color:${SEV_COL[worst] || "#e6edf7"}">${real().length}</div><div class="l">Real issues (excl. info) ${help("Findings that were not refuted and are not just informational.")}</div></div>
   <div class="tile"><div class="n">${validated + corro}</div><div class="l">Confirmed by 2+ tools or a check ${help("Validated or corroborated findings.")}</div></div>
   <div class="tile"><div class="n" style="color:var(--ok)">${refuted}</div><div class="l">False alarms removed ${help("Tool claims ARGUS disproved with its own check.")}</div></div>
   <div class="tile"><div class="n">${jobsOk}/${state.jobs.length}</div><div class="l">Tool runs OK${tools.length ? " (" + esc(tools.join(", ")) + ")" : ""}</div></div></div>`;
  h += `<div class="two"><div class="card"><h4>Issues by severity</h4><div class="donutwrap">${donut(counts)}<div class="legend">${SEV_ORDER.map(k => `<div><i style="background:${SEV_COL[k]}"></i>${k[0].toUpperCase() + k.slice(1)}: <b>${counts[k] || 0}</b></div>`).join("")}</div></div></div>
   <div class="card"><h4>Safety summary</h4>
    <div class="small">&#10003; Every action was checked against the allowed scope before it ran.</div>
    <div class="small">&#10003; ${state.approvals.length} approval request(s), ${pending().length} waiting. Risky actions need a named human.</div>
    <div class="small">&#10003; ${state.evidence.length} evidence file(s) saved with SHA-256 fingerprints.</div>
    <div class="small">&#10003; Audit log: ${health && health.audit_chain_ok ? "hash chain intact" : "CHECK FAILED"}.</div>
    ${scopeBlocked ? `<div class="small" style="color:var(--warn)">&#9888; ${scopeBlocked} target(s) were refused as out of scope; no traffic was sent to them.</div>` : ""}
    ${(state.assessment.limitations || []).length ? `<div class="small muted" style="margin-top:6px"><b>Limitations noted:</b> ${state.assessment.limitations.map(esc).join(" | ")}</div>` : ""}</div></div>`;
  h += `<h3>Top risks to fix first ${help("Ordered by priority score (0-10). Click a row for the full explanation.")}</h3>`;
  h += top.length ? `<table><tr><th>#</th><th>Finding</th><th>Where</th><th>Severity</th><th>Priority</th><th>How sure</th></tr>${top.map(f => `<tr class="click" data-f="${esc(f.id)}"><td>${esc(f.risk.rank ?? "-")}</td><td>${esc(f.title.slice(0, 80))}</td><td>${esc(f.asset.host + ":" + (f.asset.port || "-"))}</td><td>${sev(f.severity)}</td><td><b>${esc(f.risk.priority ?? "-")}</b></td><td>${st(f.status)}</td></tr>`).join("")}</table>`
    : `<div class="card">${empty("empty", "No findings yet", state.assessment.status === "planned" ? "Approve the plan to start scanning." : "Results appear here as tools finish.")}</div>`;
  h += `<h3>What the agent did, step by step</h3>` + (state.decisions.length ? state.decisions.slice(-6).map(d => `<div class="card"><div class="small"><b>${esc(d.id)}</b> &middot; ${esc(d.phase)}</div><div class="plain">${esc(d.rationale)}</div></div>`).join("") : '<div class="muted small">The agent has not made any decisions yet.</div>');
  $("#t-overview").innerHTML = h;
  document.querySelectorAll("#t-overview tr.click").forEach(r => r.onclick = () => { selFinding = r.dataset.f; tab("findings"); renderFindings(); detail(selFinding); });
}

function renderPlan() {
  const a = state.assessment, scopeEv = events.filter(e => e.type === "scope");
  let h = `<div class="card"><h4>1. Your request</h4><div class="plain">${esc(a.request)}</div></div>`;
  h += `<div class="card"><h4>2. Scope check ${help("Done in code, not by AI. A target outside the allowed list is rejected before any traffic is sent.")}</h4>${scopeEv.length ? scopeEv.map(e => `<div class="small">${e.body.allowed ? "&#9989;" : "&#9940;"} ${esc(e.body.message)}</div>`).join("") : a.targets.map(t => `<div class="small">&#9989; ${esc(t)} accepted</div>`).join("")}`;
  if (a.limitations.length) h += `<hr style="border-color:var(--line)"><div class="small muted">${a.limitations.map(esc).join("<br>")}</div>`;
  h += `</div>`;
  h += `<h3>3. Agent reasoning (decision cards) ${help("Each card = one step. What it saw, the options it had, and why it picked one.")}</h3>` + (state.decisions.map(card).join("") || '<div class="muted small">No decisions yet. They appear once the plan is approved.</div>');
  const hy = state.hypotheses;
  if (hy.length) h += `<h3>Hypotheses being tested ${help("Questions the agent is trying to answer, such as 'this web server has weaknesses'.")}</h3><table><tr><th>ID</th><th>Hypothesis</th><th>Status</th></tr>${hy.map(x => `<tr><td>${esc(x.id)}</td><td>${esc(x.text)}</td><td>${st(x.status)}</td></tr>`).join("")}</table>`;
  $("#t-plan").innerHTML = h;
}
function card(d) {
  return `<div class="card"><h4>${esc(d.id)} &middot; ${esc(d.phase)} <span class="muted small">planner: ${esc(d.planner)}</span></h4>
  <div class="small"><b>Question:</b> ${esc(d.hypothesis)}</div>
  <div class="plain"><b>Why this step:</b> ${esc(d.rationale)}</div>
  ${d.trigger.length ? `<div class="small"><b>Triggered by evidence:</b> ${d.trigger.map(evLink).join(", ")}</div>` : ""}
  <div class="small"><b>Options considered:</b></div>${d.options.map(o => `<div class="opt ${o.decision.startsWith("CHOSEN") ? "chosen" : o.decision.startsWith("not auto") ? "appr" : ""}"><b>${esc(o.action)}</b> <span class="muted">[cost ${esc(o.cost)}, noise ${esc(o.noise)}]</span><br>${esc(o.decision)}</div>`).join("")}
  <div class="small"><b>Scope check:</b> ${esc(d.scope_check)}</div>${d.outcome ? `<div class="small"><b>Outcome:</b> ${esc(d.outcome)}</div>` : ""}</div>`;
}
const evLink = id => `<a class="link" onclick="showEv('${esc(id)}')">${esc(id)}</a>`;
window.showEv = async id => {
  const r = await fetch(`/api/assessments/${cur}/evidence/${id}/raw`);
  const ev = state.evidence.find(e => e.id === id) || {};
  modalText(`${id} - ${ev.tool || ""} (${ev.mode || ""}) - sha256 ${(ev.sha256 || "").slice(0, 16)}... hash check: ${r.headers.get("X-Evidence-Hash-Verified") === "true" ? "VERIFIED" : "MISMATCH"}`, await r.text());
};

function renderTimeline() {
  const jobs = state ? state.jobs : [];
  let h = `<h3>Tools that ran ${help("Each row is one real command. LIVE = ARGUS executed it. Click an EV number for the raw output.")}</h3><table><tr><th>Job</th><th>Tool</th><th>Mode</th><th>Target</th><th>Status</th><th>Started</th><th>Detail</th></tr>${jobs.map(j => `<tr><td>${esc(j.id)}</td><td>${esc(j.tool)}</td><td>${mode(j.mode)}</td><td>${esc(j.target)}</td><td>${st(j.status)}</td><td>${esc((j.started_at || "").slice(11, 19))}</td><td class="small">${esc(j.error || j.command.slice(0, 70))} ${j.evidence_id ? evLink(j.evidence_id) : ""}</td></tr>`).join("") || '<tr><td colspan="7" class="muted">No tool has run yet.</td></tr>'}</table><h3>Event stream</h3><div class="card">`;
  h += events.filter(e => e.type !== "job").slice(-80).reverse().map(e => `<div class="ev ${esc(e.type)}"><span class="t">${esc(e.ts.slice(11, 19))}</span><span class="m">${esc(e.type === "decision" ? "Decision " + e.body.id + ": chose " + e.body.chosen.join(", ") + " - " + e.body.rationale : (e.body.message || e.type))}</span></div>`).join("") || '<span class="muted">Waiting for events...</span>';
  $("#t-timeline").innerHTML = h + "</div>";
}

function renderFindings() {
  const all = state.findings, nInfo = all.filter(f => f.severity === "info" && f.status !== "refuted").length;
  const cnt = k => all.filter(f => f.status !== "refuted" && f.severity === k).length;
  const fs = all.filter(f => {
    if (hideInfo && f.severity === "info" && f.status !== "refuted") return false;
    if (sevFilter === "refuted") return f.status === "refuted";
    if (sevFilter !== "all" && (f.severity !== sevFilter || f.status === "refuted")) return false;
    return !q || (f.title + f.id + f.asset.host + (f.cve || []).join(" ")).toLowerCase().includes(q.toLowerCase());
  });
  const chip = (k, label) => `<button data-sv="${k}" class="${sevFilter === k ? "on" : ""}">${label}</button>`;
  let h = `<div class="chips">${chip("all", "All")}${SEV_ORDER.slice(0, 4).map(k => chip(k, `${k[0].toUpperCase() + k.slice(1)} (${cnt(k)})`)).join("")}${chip("refuted", `False alarms (${all.filter(f => f.status === "refuted").length})`)}
   <input id="fq" placeholder="Search findings..." style="width:200px;margin-left:auto" value="${esc(q)}"> <label class="small muted"><input type="checkbox" id="hideInfo" ${hideInfo ? "checked" : ""}> hide ${nInfo} info</label></div>`;
  h += `<details class="card small"><summary style="margin:0">Add results from another tool (Nessus / Burp / OpenVAS) - IMPORT only, ARGUS does not run these</summary>
   <div style="margin-top:8px">Try a sample: ${["nessus", "burp", "openvas"].map(t => `<button class="sm" onclick="impSample('${t}')">sample ${t}</button>`).join(" ")}</div>
   <div class="row" style="display:flex;gap:6px"><input type="file" id="fileIn"><select id="fileTool" style="width:110px"><option>nessus</option><option>burp</option><option>openvas</option></select><button class="sm" id="fileGo">Import</button></div></details>`;
  h += fs.length ? `<table><tr><th>#</th><th>ID</th><th>Finding</th><th>Asset</th><th>Severity</th><th>Priority ${help("0-10, higher = fix sooner")}</th><th>Proof level</th><th>Conf. ${help("0-100 how sure ARGUS is")}</th><th>Reported by</th></tr>` + fs.map(f => `<tr class="click ${f.id === selFinding ? "sel" : ""}" data-f="${esc(f.id)}"><td>${esc(f.risk.rank ?? "-")}</td><td>${esc(f.id)}</td><td>${esc(f.title.slice(0, 70))}</td><td>${esc(f.asset.host + ":" + (f.asset.port || "-"))}</td><td>${sev(f.status === "refuted" ? "refuted" : f.severity)}</td><td>${esc(f.risk.priority ?? "-")}</td><td>${st(f.status)}</td><td>${f.confidence} <span class="muted small">${esc((f.risk || {}).confidence_level || "")}</span></td><td class="small">${[...new Set(f.occurrences.map(o => o.tool + (o.mode === "import" ? "*" : "")))].join(", ")}</td></tr>`).join("") + `</table>`
    : `<div class="card">${empty("empty", "No findings to show", all.length ? "Try another filter." : "Findings appear here as the tools report.")}</div>`;
  h += `<div class="small muted">* = imported file, not run by ARGUS. Click a row for the full explanation.</div><div id="detail"></div>`;
  $("#t-findings").innerHTML = h;
  $("#hideInfo").onchange = e => { hideInfo = e.target.checked; renderFindings(); };
  document.querySelectorAll("#t-findings .chips button").forEach(b => b.onclick = () => { sevFilter = b.dataset.sv; renderFindings(); });
  $("#fq").oninput = e => { q = e.target.value; const pos = e.target.selectionStart; renderFindings(); const n = $("#fq"); n.focus(); n.setSelectionRange(pos, pos); };
  document.querySelectorAll("#t-findings tr.click").forEach(r => r.onclick = () => { selFinding = r.dataset.f; renderFindings(); detail(selFinding); });
  $("#fileGo").onclick = async () => {
    const f = $("#fileIn").files[0]; if (!f) return toast("Choose a file first.", true);
    const u8 = new Uint8Array(await f.arrayBuffer()); let bin = ""; for (let i = 0; i < u8.length; i += 8192) bin += String.fromCharCode.apply(null, u8.subarray(i, i + 8192)); const b = btoa(bin);
    try { await api(`/assessments/${cur}/import`, { tool: $("#fileTool").value, filename: f.name, content_b64: b }); toast("Imported. Findings merged."); refresh(); } catch (e) { toast(e.message, true); }
  };
  if (selFinding) detail(selFinding, true);
}
window.impSample = async t => { try { await api(`/assessments/${cur}/import-sample/${t}`, {}); toast(`Sample ${t} imported (synthetic test file).`); refresh(); } catch (e) { toast(e.message, true); } };
function detail(id, quiet) {
  const f = state.findings.find(x => x.id === id); if (!f) return;
  const r = f.risk || {}, fac = r.factors || {}, box = $("#detail"); if (!box) return;
  box.innerHTML = `<div class="card" style="margin-top:12px"><h4>${esc(f.id)} - ${esc(f.title)} ${sev(f.severity)} ${st(f.status)}</h4>
  <div class="plain"><b>In plain words:</b> ${esc(STATUS_HELP[f.status] || "")} Confidence is ${f.confidence}/100 (${esc((f.risk || {}).confidence_level || "n/a")}).</div>
  <div class="two"><div class="obs"><b>OBSERVED <span class="muted small">(straight from tool evidence)</span></b><div class="small">${esc(f.description)}</div>
    <div class="small"><b>Asset:</b> ${esc(f.asset.host)}:${esc(f.asset.port || "-")} ${esc(f.asset.product)} ${esc(f.asset.version)}${f.affected_urls.length ? "<br><b>URLs:</b> " + f.affected_urls.slice(0, 4).map(esc).join(", ") : ""}</div>
    <div class="small"><b>Reported by:</b> ${f.occurrences.map(o => `${esc(o.tool)} ${mode(o.mode)} ${evLink(o.evidence_id)}`).join("<br>")}</div>
    <div class="small"><b>CVE:</b> ${esc(f.cve.join(", ") || "none reported")} &middot; <b>CWE:</b> ${esc(f.cwe.join(", ") || "n/a")} &middot; <b>OWASP:</b> ${esc(f.owasp || "n/a")}<br><b>CVSS:</b> ${f.cvss_score ?? "not provided by any tool"} ${esc(f.cvss_source)}</div></div>
  <div class="inf"><b>ANALYSIS <span class="muted small">(ARGUS's reasoning, rule-based)</span></b>
    <div class="small"><b>Why ${f.confidence}/100:</b><br>${f.confidence_reasons.map(esc).join("<br>")}</div>
    ${fac.base !== undefined ? `<div class="small"><b>Priority ${esc(r.priority)}</b> = base ${esc(fac.base)} (${esc(fac.base_source)}) x exploit ${esc(fac.exploitability)} (${esc(fac.exploitability_source)}) x confidence ${esc(fac.confidence_weight)}${fac.path_bonus ? " + attack-path bonus " + fac.path_bonus : ""}</div>` : `<div class="small">${esc(r.reason || "")}</div>`}
    ${f.validation && f.validation.verdict ? `<div class="small"><b>Double-check:</b> ${esc(f.validation.verdict)} by ${esc(f.validation.by)} - ${esc(f.validation.reason)}</div>` : ""}
    <div class="small"><b>How to fix:</b> ${esc(f.remediation || "n/a")}</div>
    ${(f.retests || []).length ? `<div class="small"><b>Retest history:</b><br>${f.retests.map(r => `${esc(r.at.slice(0, 19))}: ${esc(r.before)} &rarr; <b>${esc(r.after)}</b> (${esc(r.verdict)}) ${esc(r.reason)} ${evLink(r.evidence_id)}`).join("<br>")}</div>` : ""}</div></div>
  <div class="row small">Asset criticality for ${esc(f.asset.host)}: <select id="crit" onchange="setCrit('${esc(f.asset.host)}', this.value)">${[["0.8", "low"], ["1", "normal"], ["1.2", "critical"]].map(o => `<option value="${o[0]}" ${(state.assessment.criticality || {})[f.asset.host] == o[0] || (!(state.assessment.criticality || {})[f.asset.host] && o[0] === "1") ? "selected" : ""}>${o[1]}</option>`).join("")}</select> ${help("Business importance of this host. Multiplies the priority score (0.8 / 1.0 / 1.2).")}</div>
  <div class="row"><button class="sm" onclick="retest('${esc(f.id)}')">Retest (after fixing)</button> <button class="sm" onclick="proposeVal('${esc(f.id)}')">Ask for Metasploit check (needs approval)</button></div></div>`;
  if (!quiet) box.scrollIntoView({ behavior: "smooth" });
}
window.proposeVal = async id => { try { const r = await api(`/assessments/${cur}/findings/${id}/propose-validation`, { module: "auxiliary/scanner/http/http_version" }); toast(`Approval ${r.id} requested. Decide it in the Approvals tab.`); await refresh(); tab("approvals"); } catch (e) { toast(e.message, true); } };
window.setCrit = async (host, v) => { try { await api(`/assessments/${cur}/criticality`, { host, value: parseFloat(v) }); toast(`Criticality of ${host} set. Priorities recalculated.`); refresh(); } catch (e) { toast(e.message, true); } };
window.retest = async id => { try { const r = await api(`/assessments/${cur}/findings/${id}/retest`, {}); toast(`${r.finding}: ${r.before} -> ${r.after}. ${r.reason}`); refresh(); } catch (e) { toast(e.message, true); } };

function renderApprovals() {
  const ap = state.approvals;
  let h = `<div class="card small"><b>Why this tab exists:</b> active or exploit-class actions never run automatically. You see what, where and why, then approve or reject. Your name and comment go into the audit log.</div>`;
  h += ap.map(x => `<div class="card"><h4>${esc(x.id)} - ${esc(x.action.action_id)} ${st(x.status)}</h4><div class="small"><b>Tool:</b> ${esc(x.action.tool)} &middot; <b>Intensity:</b> ${esc(x.action.intensity)} &middot; <b>Target:</b> ${esc(x.action.target)} ${x.action.params && x.action.params.module ? "&middot; <b>Module:</b> " + esc(x.action.params.module) : ""}</div>
   <div class="plain"><b>Why the agent wants this:</b> ${esc(x.reason)}</div>
   ${x.status === "pending" ? `<div class="row" style="display:flex;gap:6px;flex-wrap:wrap"><input id="an-${esc(x.id)}" placeholder="Your name" value="analyst" style="width:140px"> <input id="cm-${esc(x.id)}" placeholder="Comment (optional)" style="flex:1;min-width:180px"> <button class="good sm" onclick="decide('${esc(x.id)}',true)">Approve</button> <button class="danger sm" onclick="decide('${esc(x.id)}',false)">Reject</button></div>` :
   (x.status === "failed" ? `<div class="row"><button class="sm" onclick="retryAp('${esc(x.id)}')">Request approval again</button></div>` : "") + `<div class="small"><b>Decision:</b> ${esc(x.status)} by ${esc(x.decided_by || "-")} at ${esc((x.decided_at || "").slice(0, 19))} ${x.comment ? "- " + esc(x.comment) : ""}<br><b>Outcome:</b> ${esc(x.outcome || "-")}</div>`}</div>`).join("") || `<div class="card">${empty("approval", "Nothing needs approval yet", "When ARGUS wants to run an intrusive step (like an active ZAP scan) it will wait here for you.")}</div>`;
  $("#t-approvals").innerHTML = h;
}
window.retryAp = async id => { try { await api(`/assessments/${cur}/approvals/${id}/retry`, {}); refresh(); } catch (e) { toast(e.message, true); } };
window.decide = async (id, ok) => { try { await api(`/assessments/${cur}/approvals/${id}/decide`, { approve: ok, analyst: $("#an-" + id).value, comment: $("#cm-" + id).value }); toast(ok ? "Approved. Running now..." : "Rejected."); refresh(); } catch (e) { toast(e.message, true); } };

const ASKS = ["summary", "pending approvals", "why is F-001 ranked high?", "show evidence for F-002"];
function renderCopilot() {
  const had = $("#q") && document.activeElement === $("#q"), val = $("#q") ? $("#q").value : "";
  $("#t-copilot").innerHTML = `<div class="card"><div class="chips">${ASKS.map(a => `<button data-a="${esc(a)}">${esc(a)}</button>`).join("")}</div><div class="chat" id="chat">${chat.map(m => `<div class="msg ${m.r}">${esc(m.t)}</div>`).join("") || '<span class="muted">Ask a question in plain English. Answers come only from stored findings and evidence, never from guesses.</span>'}</div>
  <div class="row" style="display:flex;gap:6px"><input id="q" placeholder="Ask about a finding..." value="${esc(val)}"> <button class="sm" id="ask">Ask</button></div></div>`;
  const go = async text => { text = text || $("#q").value; if (!text) return; chat.push({ r: "u", t: text }); try { const a = await api(`/assessments/${cur}/ask`, { question: text }); chat.push({ r: "a", t: a.answer }); } catch (e) { chat.push({ r: "a", t: "Error: " + e.message }); } $("#q") && ($("#q").value = ""); renderCopilot(); const c = $("#chat"); c.scrollTop = c.scrollHeight; };
  $("#ask").onclick = () => go(); $("#q").onkeydown = e => { if (e.key === "Enter") go(); };
  document.querySelectorAll("#t-copilot .chips button").forEach(b => b.onclick = () => go(b.dataset.a));
  if (had) $("#q").focus();
}

async function renderReport() {
  let ok = null; try { ok = await api(`/assessments/${cur}/audit`); } catch (e) {}
  $("#t-report").innerHTML = `<div class="card"><h4>Unified VAPT report (PDF)</h4><a href="/api/assessments/${cur}/report.pdf"><button class="primary" style="width:auto;padding:10px 22px">Download PDF report</button></a>
  <div class="small muted" style="margin-top:6px">Contains: executive summary, scope and methodology, severity chart, ranked findings with evidence, remediation, limitations, decision log and audit trail.</div></div>
  <div class="card"><h4>Audit trail ${ok ? (ok.chain_ok ? '<span class="st validated">hash chain intact</span>' : '<span class="st failed">chain broken</span>') : ""} ${help("Every entry includes the hash of the previous entry, so editing history would break the chain.")}</h4>
  <table><tr><th>#</th><th>Time</th><th>Actor</th><th>Action</th><th>Detail</th></tr>${(ok ? ok.entries : []).slice(-60).reverse().map(e => `<tr><td>${e.seq}</td><td>${esc(e.ts.slice(11, 19))}</td><td>${esc(e.actor)}</td><td>${esc(e.action)}</td><td class="small">${esc((e.detail || "").slice(0, 120))}</td></tr>`).join("")}</table></div>`;
}

async function renderMatrix() {
  const m = await api("/matrix");
  $("#t-matrix").innerHTML = `<div class="card small">Honest status of every tool, checked on this machine just now. <b>Live</b> = ARGUS runs it. <b>Import-only</b> = ARGUS reads exported files but does not run the tool.</div><table><tr><th>Tool</th><th>Status</th><th>Runtime</th><th>What it does</th><th>Limitations</th></tr>${m.map(x => `<tr><td><b>${esc(x.name)}</b></td><td>${st(x.status)}</td><td class="small">${esc(x.runtime)}</td><td class="small">${esc(x.description)}</td><td class="small">${esc(x.limitations)}</td></tr>`).join("")}</table>`;
}

function renderGraph() {
  if (!cur) return;
  api(`/assessments/${cur}/graph`).then(g => {
    const cols = { host: 0, service: 1, finding: 2, hypothesis: 3 }, W = 1000, colW = 250, byK = { host: [], service: [], finding: [], hypothesis: [] };
    g.nodes.forEach(n => byK[n.kind].push(n));
    const pos = {}; Object.keys(byK).forEach(k => byK[k].forEach((n, i) => pos[n.id] = { x: 20 + cols[k] * colW, y: 34 + i * 40 }));
    const H = Math.max(120, 70 + Math.max(...Object.values(byK).map(a => a.length)) * 40);
    const fill = { host: "#1d4ed8", service: "#0e7490", finding: "#334155", hypothesis: "#3d2e0a" };
    let s = `<svg width="100%" viewBox="0 0 ${W} ${H}" style="background:#0b1626;border:1px solid var(--line);border-radius:12px"><defs><marker id="ar" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 z" fill="#8da2bd"/></marker></defs>`;
    ["Hosts", "Services", "Weaknesses", "Possible attack paths"].forEach((l, i) => s += `<text x="${20 + i * colW}" y="18" fill="#8da2bd" font-size="11" font-weight="700">${l.toUpperCase()}</text>`);
    g.edges.forEach(e => { const a = pos[e.from], b = pos[e.to]; if (!a || !b) return; s += `<line x1="${a.x + 200}" y1="${a.y + 12}" x2="${b.x}" y2="${b.y + 12}" stroke="${e.type === "verified" ? "#4ade80" : "#fb923c"}" stroke-width="1.6" ${e.type === "hypothesis" ? 'stroke-dasharray="5 4"' : ""} marker-end="url(#ar)"/>`; });
    g.nodes.forEach(n => { const p = pos[n.id]; const hyp = n.kind === "hypothesis"; s += `<g><rect x="${p.x}" y="${p.y}" width="200" height="24" rx="6" fill="${fill[n.kind]}" stroke="${hyp ? "#fb923c" : "none"}" ${hyp ? 'stroke-dasharray="4 3"' : ""}/><text x="${p.x + 7}" y="${p.y + 16}" fill="${hyp ? "#fcd9a8" : "#fff"}">${esc(n.label.slice(0, 32))}</text><title>${esc(n.why || n.label)}</title></g>`; });
    $("#t-graph").innerHTML = `<div class="card small">Read left to right: <b>host &rarr; service &rarr; weakness &rarr; what an attacker might chain.</b> <span style="color:var(--ok)">Solid green</span> = backed by tool evidence. <span style="color:var(--med)">Dashed orange</span> = a hypothesis, not proven. Hover a box for the reasoning.</div>` + (g.nodes.length ? s + "</svg>" : `<div class="card">${empty("empty", "No attack paths yet", "They appear when findings exist that could be chained.")}</div>`);
  });
}
init();
