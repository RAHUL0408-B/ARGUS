"use strict";
const $ = (s, r = document) => r.querySelector(s);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const api = async (p, opt) => {
  const r = await fetch("/api" + p, opt && { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(opt) });
  if (!r.ok) { let m = r.statusText; try { m = (await r.json()).detail || m; } catch (e) {} throw new Error(m); }
  return r.json();
};
let hideInfo = true, cur = null, state = null, es = null, lastSeq = 0, events = [], chat = [];
const sev = s => `<span class="tag sev-${esc(s)}">${esc(String(s).toUpperCase())}</span>`;
const mode = m => `<span class="mode ${m === "live" ? "live" : "imp"}">${m === "live" ? "LIVE" : "IMPORT"}</span>`;
const st = s => `<span class="st ${esc(s)}">${esc(s)}</span>`;

async function init() {
  const h = await api("/health");
  $("#badges").innerHTML = `<span class="badge ${h.docker ? "ok" : "bad"}">Docker ${h.docker ? "ready" : "not available"}</span>
    <span class="badge">Planner: ${esc(h.llm)}</span><span class="badge ${h.audit_chain_ok ? "ok" : "bad"}">Audit chain ${h.audit_chain_ok ? "intact" : "BROKEN"}</span>`;
  const sc = await api("/scope/default");
  $("#scopeBox").textContent = JSON.stringify({ targets: sc.targets, exclusions: sc.exclusions, max_intensity: sc.max_intensity, authorized_by: sc.authorized_by }, null, 1);
  loadHist(); renderMatrix();
  document.querySelectorAll("#tabs button").forEach(b => b.onclick = () => tab(b.dataset.t));
  $("#btnPlan").onclick = () => create($("#req").value);
  $("#btnOos").onclick = () => { $("#req").value = "Assess 10.77.0.10 for web issues and also scan 8.8.8.8 and scanme.nmap.org"; create($("#req").value); };
  $("#mclose").onclick = () => $("#modal").classList.add("hidden");
}
function tab(t) {
  document.querySelectorAll("#tabs button").forEach(b => b.classList.toggle("on", b.dataset.t === t));
  document.querySelectorAll(".tab").forEach(s => s.classList.toggle("hidden", s.id !== "t-" + t));
  if (t === "graph") renderGraph();
}
async function loadHist() {
  const l = await api("/assessments");
  $("#hist").innerHTML = l.map(a => `<div class="hist ${a.id === cur ? "on" : ""}" data-id="${esc(a.id)}"><b>${esc(a.id)}</b> ${st(a.status)}<br><span class="muted">${esc((a.targets || []).join(", ")).slice(0, 60)}</span></div>`).join("") || '<span class="muted small">None yet.</span>';
  document.querySelectorAll(".hist").forEach(e => e.onclick = () => open(e.dataset.id));
}
async function create(request) {
  try { const s = await api("/assessments", { request }); await open(s.assessment.id); tab("plan"); loadHist(); } catch (e) { alert(e.message); }
}
async function open(id) {
  cur = id; lastSeq = 0; events = []; if (es) es.close();
  await refresh();
  es = new EventSource(`/api/assessments/${id}/events`);
  es.onmessage = m => { const e = JSON.parse(m.data); lastSeq = e.seq; events.push(e); renderTimeline(); schedule(); };
  loadHist();
}
let tm = null;
function schedule() { clearTimeout(tm); tm = setTimeout(refresh, 600); }
async function refresh() { if (!cur) return; state = await api("/assessments/" + cur); renderAll(); }
function renderAll() { renderStatus(); renderPlan(); renderTimeline(); renderFindings(); renderApprovals(); renderReport(); renderCopilot(); if (!$("#t-graph").classList.contains("hidden")) renderGraph(); }

function renderStatus() {
  const a = state.assessment, pend = state.approvals.filter(x => x.status === "pending").length;
  $("#status").innerHTML = `<b>${esc(a.id)}</b> &middot; ${st(a.status)} &middot; phase <b>${esc(a.phase)}</b> &middot; planner ${esc(a.planner)} &middot; ${state.findings.filter(f => f.status !== "refuted").length} findings`;
  const p = $("#apCount"); p.textContent = pend; p.classList.toggle("hidden", !pend);
}

function renderPlan() {
  const a = state.assessment;
  const scopeEv = events.filter(e => e.type === "scope");
  let h = `<div class="card"><h4>Analyst request</h4><div>${esc(a.request)}</div></div>`;
  h += `<div class="card"><h4>Scope validation</h4>${scopeEv.length ? scopeEv.map(e => `<div class="small">${e.body.allowed ? "✅" : "⛔"} ${esc(e.body.message)}</div>`).join("") : a.targets.map(t => `<div class="small">✅ ${esc(t)} accepted</div>`).join("")}`;
  if (a.limitations.length) h += `<hr><div class="small muted">${a.limitations.map(esc).join("<br>")}</div>`;
  h += `</div>`;
  if (a.status === "planned") h += `<div class="card"><b>The agent has proposed a plan. No scan has run.</b><div class="row"><button class="primary" id="btnGo">Approve plan &amp; start assessment</button></div></div>`;
  if (a.status === "running") h += `<div class="card"><button class="danger" id="btnStop">KILL SWITCH: stop all jobs</button></div>`;
  if (a.status === "failed" && !state.decisions.length) h += `<div class="card" style="border-color:var(--bad)"><b>Nothing will be tested.</b> No requested target is inside the authorized scope.</div>`;
  h += `<h3>Decision cards (agent reasoning)</h3>` + state.decisions.map(card).join("");
  const hy = state.hypotheses;
  if (hy.length) h += `<h3>Hypotheses</h3><table><tr><th>ID</th><th>Hypothesis</th><th>Status</th></tr>${hy.map(x => `<tr><td>${esc(x.id)}</td><td>${esc(x.text)}</td><td>${st(x.status)}</td></tr>`).join("")}</table>`;
  $("#t-plan").innerHTML = h;
  const go = $("#btnGo"); if (go) go.onclick = async () => { await api(`/assessments/${cur}/approve-plan`, {}); tab("timeline"); refresh(); };
  const sp = $("#btnStop"); if (sp) sp.onclick = async () => { await api(`/assessments/${cur}/stop`, {}); };
}
function card(d) {
  return `<div class="card"><h4>${esc(d.id)} &middot; ${esc(d.phase)} <span class="muted small">planner: ${esc(d.planner)}</span></h4>
  <div class="small"><b>Hypothesis:</b> ${esc(d.hypothesis)}</div>
  <div class="small"><b>Why:</b> ${esc(d.rationale)}</div>
  ${d.trigger.length ? `<div class="small"><b>Triggered by evidence:</b> ${d.trigger.map(evLink).join(", ")}</div>` : ""}
  <div class="small"><b>Options considered:</b></div>${d.options.map(o => `<div class="opt ${o.decision.startsWith("CHOSEN") ? "chosen" : o.decision.startsWith("not auto") ? "appr" : ""}"><b>${esc(o.action)}</b> <span class="muted">[cost ${esc(o.cost)}, noise ${esc(o.noise)}]</span><br>${esc(o.decision)}</div>`).join("")}
  <div class="small"><b>Scope check:</b> ${esc(d.scope_check)}</div>${d.outcome ? `<div class="small"><b>Outcome:</b> ${esc(d.outcome)}</div>` : ""}</div>`;
}
const evLink = id => `<a class="link" onclick="showEv('${esc(id)}')">${esc(id)}</a>`;
window.showEv = async id => {
  const r = await fetch(`/api/assessments/${cur}/evidence/${id}/raw`);
  const ev = state.evidence.find(e => e.id === id) || {};
  $("#mtitle").textContent = `${id} - ${ev.tool || ""} (${ev.mode || ""}) - sha256 ${(ev.sha256 || "").slice(0, 16)}... hash check: ${r.headers.get("X-Evidence-Hash-Verified") === "true" ? "VERIFIED" : "MISMATCH"}`;
  $("#mbody").textContent = await r.text(); $("#modal").classList.remove("hidden");
};

function renderTimeline() {
  const jobs = state ? state.jobs : [];
  let h = `<h3>Tool execution</h3><table><tr><th>Job</th><th>Tool</th><th>Mode</th><th>Target</th><th>Status</th><th>Started</th><th>Detail</th></tr>${jobs.map(j => `<tr><td>${esc(j.id)}</td><td>${esc(j.tool)}</td><td>${mode(j.mode)}</td><td>${esc(j.target)}</td><td>${st(j.status)}</td><td>${esc((j.started_at || "").slice(11, 19))}</td><td class="small">${esc(j.error || j.command.slice(0, 70))} ${j.evidence_id ? evLink(j.evidence_id) : ""}</td></tr>`).join("") || '<tr><td colspan="7" class="muted">No jobs yet.</td></tr>'}</table><h3>Event stream</h3><div class="card">`;
  h += events.filter(e => e.type !== "job").slice(-80).reverse().map(e => `<div class="ev ${esc(e.type)}"><span class="t">${esc(e.ts.slice(11, 19))}</span><span class="m">${esc(e.type === "decision" ? "Decision " + e.body.id + ": chose " + e.body.chosen.join(", ") + " - " + e.body.rationale : (e.body.message || e.type))}</span></div>`).join("") || '<span class="muted">Waiting for events...</span>';
  $("#t-timeline").innerHTML = h + "</div>";
}

function renderFindings() {
  const fs = state.findings.filter(f => !(hideInfo && f.severity === "info" && f.status !== "refuted"));
  const nInfo = state.findings.filter(f => f.severity === "info" && f.status !== "refuted").length;
  let h = `<div class="card small"><label><input type="checkbox" id="hideInfo" ${hideInfo ? "checked" : ""}> Hide ${nInfo} informational observation(s)</label></div><div class="card small">Import results from other tools (IMPORT only, not executed by ARGUS): ${["nessus", "burp", "openvas"].map(t => `<button class="sm" onclick="impSample('${t}')">sample ${t}</button>`).join(" ")}
  <input type="file" id="fileIn"> <select id="fileTool"><option>nessus</option><option>burp</option><option>openvas</option></select> <button class="sm" id="fileGo">Import file</button></div>`;
  h += `<table><tr><th>#</th><th>ID</th><th>Finding</th><th>Asset</th><th>Sev</th><th>Priority</th><th>Status</th><th>Conf</th><th>Sources</th></tr>`;
  h += fs.map(f => `<tr class="click" data-f="${esc(f.id)}"><td>${esc(f.risk.rank ?? "-")}</td><td>${esc(f.id)}</td><td>${esc(f.title.slice(0, 70))}</td><td>${esc(f.asset.host + ":" + (f.asset.port || "-"))}</td><td>${sev(f.status === "refuted" ? "refuted" : f.severity)}</td><td>${esc(f.risk.priority ?? "-")}</td><td>${st(f.status)}</td><td>${f.confidence}</td><td class="small">${[...new Set(f.occurrences.map(o => o.tool + (o.mode === "import" ? "*" : "")))].join(", ")}</td></tr>`).join("") || '<tr><td colspan="9" class="muted">No findings yet.</td></tr>';
  h += `</table><div class="small muted">* = imported file, not executed by ARGUS. Refuted rows are false positives kept for transparency.</div><div id="detail"></div>`;
  $("#t-findings").innerHTML = h;
  $("#hideInfo").onchange = e => { hideInfo = e.target.checked; renderFindings(); };
  document.querySelectorAll("#t-findings tr.click").forEach(r => r.onclick = () => detail(r.dataset.f));
  $("#fileGo").onclick = async () => {
    const f = $("#fileIn").files[0]; if (!f) return alert("choose a file");
    const b = btoa(String.fromCharCode(...new Uint8Array(await f.arrayBuffer())));
    try { await api(`/assessments/${cur}/import`, { tool: $("#fileTool").value, filename: f.name, content_b64: b }); refresh(); } catch (e) { alert(e.message); }
  };
}
window.impSample = async t => { try { await api(`/assessments/${cur}/import-sample/${t}`, {}); refresh(); } catch (e) { alert(e.message); } };
function detail(id) {
  const f = state.findings.find(x => x.id === id), r = f.risk || {}, fac = r.factors || {};
  $("#detail").innerHTML = `<div class="card"><h4>${esc(f.id)} - ${esc(f.title)} ${sev(f.severity)} ${st(f.status)}</h4>
  <div class="two"><div class="obs"><b>OBSERVED (tool evidence)</b><div class="small">${esc(f.description)}</div>
    <div class="small"><b>Asset:</b> ${esc(f.asset.host)}:${esc(f.asset.port || "-")} ${esc(f.asset.product)} ${esc(f.asset.version)}${f.affected_urls.length ? "<br><b>URLs:</b> " + f.affected_urls.slice(0, 4).map(esc).join(", ") : ""}</div>
    <div class="small"><b>Sources:</b> ${f.occurrences.map(o => `${esc(o.tool)} ${mode(o.mode)} ${evLink(o.evidence_id)}`).join("<br>")}</div>
    <div class="small"><b>CVE:</b> ${esc(f.cve.join(", ") || "none reported")} &middot; <b>CWE:</b> ${esc(f.cwe.join(", ") || "n/a")} &middot; <b>OWASP:</b> ${esc(f.owasp || "n/a")}<br><b>CVSS:</b> ${f.cvss_score ?? "not provided by any tool"} ${esc(f.cvss_source)}</div></div>
  <div class="inf"><b>ANALYSIS (rule-based inference)</b>
    <div class="small"><b>Confidence ${f.confidence}/100:</b><br>${f.confidence_reasons.map(esc).join("<br>")}</div>
    ${fac.base !== undefined ? `<div class="small"><b>Priority ${esc(r.priority)}</b> = base ${esc(fac.base)} (${esc(fac.base_source)}) x exploit ${esc(fac.exploitability)} (${esc(fac.exploitability_source)}) x conf ${esc(fac.confidence_weight)}${fac.path_bonus ? " + path bonus " + fac.path_bonus : ""}</div>` : `<div class="small">${esc(r.reason || "")}</div>`}
    ${f.validation && f.validation.verdict ? `<div class="small"><b>Validation:</b> ${esc(f.validation.verdict)} by ${esc(f.validation.by)} - ${esc(f.validation.reason)}</div>` : ""}
    <div class="small"><b>Remediation:</b> ${esc(f.remediation || "n/a")}</div></div></div>
  <div class="row"><button class="sm" onclick="retest('${esc(f.id)}')">Retest this finding</button> <button class="sm" onclick="proposeVal('${esc(f.id)}')">Request Metasploit validation (needs approval)</button></div></div>`;
  $("#detail").scrollIntoView({ behavior: "smooth" });
}
window.proposeVal = async id => { try { const r = await api(`/assessments/${cur}/findings/${id}/propose-validation`, { module: 'auxiliary/scanner/http/http_version' }); alert('Approval ' + r.id + ' requested. Open the Approvals tab to decide.'); refresh(); tab('approvals'); } catch (e) { alert(e.message); } };
window.retest = async id => { try { const r = await api(`/assessments/${cur}/findings/${id}/retest`, {}); alert(`${r.finding}: ${r.before} -> ${r.after}\n${r.reason}`); refresh(); } catch (e) { alert(e.message); } };

function renderApprovals() {
  const ap = state.approvals;
  let h = `<div class="card small">Active or exploit-class validation never runs automatically. Every decision, comment and outcome below is written to the audit log.</div>`;
  h += ap.map(x => `<div class="card"><h4>${esc(x.id)} - ${esc(x.action.action_id)} ${st(x.status)}</h4><div class="small"><b>Tool:</b> ${esc(x.action.tool)} &middot; <b>Intensity:</b> ${esc(x.action.intensity)} &middot; <b>Target:</b> ${esc(x.action.target)} ${x.action.params && x.action.params.module ? "&middot; <b>Module:</b> " + esc(x.action.params.module) : ""}</div>
   <div class="small"><b>Why the agent wants this:</b> ${esc(x.reason)}</div>
   ${x.status === "pending" ? `<div class="row"><input id="an-${esc(x.id)}" placeholder="Your name" value="analyst"> <input id="cm-${esc(x.id)}" placeholder="Comment" size="30"> <button class="good sm" onclick="decide('${esc(x.id)}',true)">Approve</button> <button class="danger sm" onclick="decide('${esc(x.id)}',false)">Reject</button></div>` :
   (x.status === "failed" ? `<div class="row"><button class="sm" onclick="retryAp('${esc(x.id)}')">Request approval again</button></div>` : "") + `<div class="small"><b>Decision:</b> ${esc(x.status)} by ${esc(x.decided_by || "-")} at ${esc((x.decided_at || "").slice(0, 19))} ${x.comment ? "- " + esc(x.comment) : ""}<br><b>Outcome:</b> ${esc(x.outcome || "-")}</div>`}</div>`).join("") || '<div class="muted">No approvals requested yet.</div>';
  $("#t-approvals").innerHTML = h;
}
window.retryAp = async id => { try { await api(`/assessments/${cur}/approvals/${id}/retry`, {}); refresh(); } catch (e) { alert(e.message); } };
window.decide = async (id, ok) => { try { await api(`/assessments/${cur}/approvals/${id}/decide`, { approve: ok, analyst: $("#an-" + id).value, comment: $("#cm-" + id).value }); refresh(); } catch (e) { alert(e.message); } };

function renderCopilot() {
  $("#t-copilot").innerHTML = `<div class="card"><div class="chat" id="chat">${chat.map(m => `<div class="msg ${m.r}">${esc(m.t)}</div>`).join("") || '<span class="muted">Ask: "why is F-001 ranked high?", "show evidence for F-002", "summary", "pending approvals".</span>'}</div>
  <div class="row"><input id="q" style="width:75%" placeholder="Ask about a finding..."> <button class="sm" id="ask">Ask</button></div><div class="small muted">Answers come only from stored findings and evidence.</div></div>`;
  const go = async () => { const q = $("#q").value; if (!q) return; chat.push({ r: "u", t: q }); const a = await api(`/assessments/${cur}/ask`, { question: q }); chat.push({ r: "a", t: a.answer }); renderCopilot(); };
  $("#ask").onclick = go; $("#q").onkeydown = e => { if (e.key === "Enter") go(); };
}

async function renderReport() {
  let ok = null; try { ok = await api(`/assessments/${cur}/audit`); } catch (e) {}
  $("#t-report").innerHTML = `<div class="card"><h4>Unified VAPT report</h4><a href="/api/assessments/${cur}/report.pdf"><button class="primary" style="width:auto">Download PDF report</button></a>
  <div class="small muted">Executive summary, methodology, severity distribution, detailed findings with evidence, remediation, limitations, evidence index, decision log and audit trail.</div></div>
  <div class="card"><h4>Audit trail ${ok ? (ok.chain_ok ? '<span class="st validated">hash chain intact</span>' : '<span class="st failed">chain broken</span>') : ""}</h4>
  <table><tr><th>#</th><th>Time</th><th>Actor</th><th>Action</th><th>Detail</th></tr>${(ok ? ok.entries : []).slice(-60).reverse().map(e => `<tr><td>${e.seq}</td><td>${esc(e.ts.slice(11, 19))}</td><td>${esc(e.actor)}</td><td>${esc(e.action)}</td><td class="small">${esc((e.detail || "").slice(0, 120))}</td></tr>`).join("")}</table></div>`;
}

async function renderMatrix() {
  const m = await api("/matrix");
  $("#t-matrix").innerHTML = `<div class="card small">This matrix is probed at runtime: it reports what this machine can actually do right now.</div><table><tr><th>Tool</th><th>Status</th><th>Runtime</th><th>What it does</th><th>Limitations</th></tr>${m.map(x => `<tr><td><b>${esc(x.name)}</b></td><td>${st(x.status)}</td><td class="small">${esc(x.runtime)}</td><td class="small">${esc(x.description)}</td><td class="small">${esc(x.limitations)}</td></tr>`).join("")}</table>`;
}

function renderGraph() {
  if (!cur) return;
  api(`/assessments/${cur}/graph`).then(g => {
    const cols = { host: 0, service: 1, finding: 2, hypothesis: 3 }, W = 1000, colW = 250, byK = { host: [], service: [], finding: [], hypothesis: [] };
    g.nodes.forEach(n => byK[n.kind].push(n));
    const pos = {}; Object.keys(byK).forEach(k => byK[k].forEach((n, i) => pos[n.id] = { x: 20 + cols[k] * colW, y: 24 + i * 40 }));
    const H = Math.max(120, 60 + Math.max(...Object.values(byK).map(a => a.length)) * 40);
    const fill = { host: "#0f2742", service: "#1f6fb2", finding: "#546e7a", hypothesis: "#fff3e0" };
    let s = `<svg width="100%" viewBox="0 0 ${W} ${H}" style="background:#fff;border:1px solid var(--line);border-radius:10px"><defs><marker id="ar" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 z" fill="#78909c"/></marker></defs>`;
    g.edges.forEach(e => { const a = pos[e.from], b = pos[e.to]; if (!a || !b) return; s += `<line x1="${a.x + 200}" y1="${a.y + 12}" x2="${b.x}" y2="${b.y + 12}" stroke="${e.type === "verified" ? "#2e7d32" : "#ef6c00"}" stroke-width="1.5" ${e.type === "hypothesis" ? 'stroke-dasharray="5 4"' : ""} marker-end="url(#ar)"/>`; });
    g.nodes.forEach(n => { const p = pos[n.id]; const hyp = n.kind === "hypothesis"; s += `<g><rect x="${p.x}" y="${p.y}" width="200" height="24" rx="5" fill="${fill[n.kind]}" stroke="${hyp ? "#ef6c00" : "none"}" ${hyp ? 'stroke-dasharray="4 3"' : ""}/><text x="${p.x + 6}" y="${p.y + 16}" fill="${hyp ? "#7a4a00" : "#fff"}">${esc(n.label.slice(0, 32))}</text><title>${esc(n.why || n.label)}</title></g>`; });
    $("#t-graph").innerHTML = `<div class="card small"><b>Solid green</b> = backed by tool evidence. <b>Dashed orange</b> = AI/rule hypothesis (not verified). Hover a hypothesis for the reasoning.</div>` + (g.nodes.length ? s + "</svg>" : '<div class="muted">No graph yet.</div>');
  });
}
init();
