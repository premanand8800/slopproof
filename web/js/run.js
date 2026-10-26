"use strict";
// One triage run: a timeline of stages fed by events, for live runs and for recorded ones.

const STAGES = [
  { id: "report", title: "Fetch the report", tech: "HackerOne · GitHub" },
  { id: "claims", title: "Extract every checkable claim", tech: "Nemotron 3.5 Lightning" },
  { id: "code", title: "Check claims against the real code", tech: "git · fuzzy match · line diff" },
  { id: "search", title: "Find the code the report is about", tech: "tree-sitter · BM25" },
  { id: "web", title: "Check references and prior art", tech: "Tavily · Nemotron 3 Super" },
  { id: "screen", title: "Text screen (a vote, never evidence)", tech: "Nemotron 3 Ultra" },
  { id: "analysis", title: "Static analysis of the real code", tech: "Nemotron 3 Ultra" },
  { id: "policy", title: "Project security policy", tech: "quote-checked" },
  { id: "reproduce", title: "Reproduce in a sandbox", tech: "Nemotron agent · Docker · ASan" },
  { id: "verdict", title: "Verdict and reply", tech: "Nemotron 3 Ultra · hard rules" },
];
const ACTIONS = {
  CONFIRMED: "Reproduced, and the proof re-ran from scratch. Treat it as a real vulnerability.",
  PLAUSIBLE: "Not disproved. A maintainer should look.",
  NOT_REPRODUCED: "Safe to close with the evidence below.",
  FABRICATED: "Safe to close: the report relies on things that do not exist.",
};
const ICON = { pending: "", running: "", done: "✓", warn: "!", failed: "✗", skipped: "–" };

class Run {
  constructor(root, opts = {}) {
    this.root = root;
    this.recorded = !!opts.recorded;
    this.sandbox = opts.sandbox !== false;
    this.s = {};
    for (const st of STAGES) this.s[st.id] = { state: "pending", sum: "", html: "", start: null, end: null, open: false };
    this.status = this.recorded ? "recorded" : "queued";
    this.t0 = null;
    this.tEnd = null;
    this.activeSince = null;
    this.now = "Waiting to start…";
    this.steps = 0;
    this.term = "";
    this.layout(opts);
    if (!this.sandbox) this.set("reproduce", "skipped", "sandbox off", `<p class="muted">The sandbox was not requested for this run.</p>`);
    this.render();
  }

  layout(opts) {
    this.root.innerHTML = `
      <div class="run-head">
        <div>
          <div class="kicker">${this.recorded ? "Recorded benchmark run" : "Triage run"}</div>
          <h1 id="r-title" style="margin-top:6px">${esc(opts.title || "Loading report…")}</h1>
          <div class="run-meta"><span class="status" id="r-status"></span><span id="r-meta"></span></div>
        </div>
        <div class="row">
          <button class="btn small" id="r-copy" title="Copy a link to this run">Copy link</button>
          <a class="btn small primary" href="#/">New report</a>
        </div>
      </div>
      <div class="progress"><div id="r-bar" style="width:0"></div></div>
      <div class="run-grid">
        <div>
          <ol class="timeline" id="r-timeline"></ol>
          <div id="r-verdict"></div>
        </div>
        <aside class="side">
          <div class="card">
            <div class="kicker">${this.recorded ? "Original run took" : "Elapsed"}</div>
            <div class="clock" id="r-clock">${this.recorded ? "–" : "0:00"}</div>
            <div class="now" id="r-now"></div>
            <dl id="r-facts"></dl>
          </div>
          <div class="card report-card"><div class="kicker">Report</div>
            <div id="r-repo" class="muted" style="font-size:13px;margin-top:6px;word-break:break-all"></div>
            <details><summary>Show the report text</summary><pre id="r-body"></pre></details></div>
        </aside>
      </div>`;
    $("#r-copy", this.root).onclick = () => {
      navigator.clipboard.writeText(location.href).then(() => toast("Link copied: it reopens this run, even after a reload."));
    };
    $("#r-timeline", this.root).addEventListener("click", (e) => {
      const hd = e.target.closest(".hd");
      if (!hd) return;
      const id = hd.parentElement.parentElement.dataset.id;
      this.s[id].open = !this.s[id].open;
      this.renderStage(id);
    });
  }

  set(id, state, sum, html, ts) {
    const st = this.s[id];
    st.state = state;
    if (sum !== undefined) st.sum = sum;
    if (html !== undefined) st.html = html;
    if (["done", "warn", "failed", "skipped"].includes(state) && st.end == null) st.end = ts ?? null;
    if (state === "warn" || state === "failed") st.open = true;
  }

  // The first stage not finished yet is the one running.
  advance(ts) {
    if (!["queued", "running"].includes(this.status)) return;
    for (const st of STAGES) {
      const x = this.s[st.id];
      if (x.state === "pending") {
        x.state = "running";
        x.start = this.lastTs ?? ts;
        if (st.id === "reproduce") x.open = true;
        break;
      }
      if (x.state === "running") break;
    }
  }

  apply(ev) {
    const ts = ev.ts;
    if (ts && this.t0 == null) this.t0 = ts;
    if (["queued", "report"].includes(ev.stage) && this.status === "queued") this.status = "running";
    switch (ev.stage) {
      case "report":
        $("#r-title", this.root).textContent = ev.title || "Report";
        $("#r-meta", this.root).textContent = ev.created_at ? `filed ${ev.created_at.slice(0, 10)}` : "";
        $("#r-repo", this.root).innerHTML = `<a href="${esc(ev.repo)}" target="_blank" rel="noopener">${esc(ev.repo)}</a>`;
        $("#r-body", this.root).textContent = ev.body || "";
        this.set("report", "done", ev.repo.replace("https://github.com/", ""), "", ts);
        this.now = "Reading the report…";
        break;
      case "claims": renderClaims(this, ev.claims, ts); break;
      case "ref": this.ref = ev.ref; this.now = `Exported the source tree at ${ev.ref.sha.slice(0, 12)}`; break;
      case "code": renderCode(this, ev.code, ts); break;
      case "web": renderWeb(this, ev.web, ts); break;
      case "screen": renderScreen(this, ev.screen, ts); break;
      case "search": renderSearch(this, ev.found, ts); break;
      case "analysis": renderAnalysis(this, ev.analysis, ts); break;
      case "scope": renderPolicy(this, ev.scope, ts); break;
      case "reproduce": renderRepro(this, ev, ts); break;
      case "verdict": renderVerdict(this, ev, ts); break;
      case "done":
        this.status = "done";
        this.tEnd = ts ?? this.tEnd;
        this.now = "Finished.";
        break;
      case "error":
        this.status = ev.interrupted ? "interrupted" : "error";
        this.tEnd = ts ?? Date.now() / 1000;
        for (const st of STAGES) if (this.s[st.id].state === "running") this.set(st.id, "failed", "stopped", undefined, ts);
        this.now = ev.message;
        break;
    }
    if (ts) this.lastTs = ts;
    this.advance(ts);
  }

  render() {
    const tl = $("#r-timeline", this.root);
    if (!tl.children.length) tl.innerHTML = STAGES.map((st) => `<li class="st" data-id="${st.id}"></li>`).join("");
    for (const st of STAGES) this.renderStage(st.id);
    const done = STAGES.filter((st) => ["done", "warn", "failed", "skipped"].includes(this.s[st.id].state)).length;
    $("#r-bar", this.root).style.width = `${Math.round((done / STAGES.length) * 100)}%`;
    const label = { queued: "Queued", running: "Running", done: "Finished", error: "Failed", interrupted: "Interrupted", recorded: "Recorded" }[this.status];
    const el = $("#r-status", this.root);
    el.className = `status ${this.status}`;
    el.innerHTML = `${this.status === "running" || this.status === "queued" ? '<span class="pulse"></span>' : ""}${label}`;
    $("#r-now", this.root).textContent = this.now;
    this.tick();
  }

  renderStage(id) {
    const def = STAGES.find((s) => s.id === id), x = this.s[id];
    const li = $(`.st[data-id="${id}"]`, this.root);
    if (!li) return;
    li.className = `st ${x.state}${x.open ? " open" : ""}`;
    li.innerHTML = `<span class="icon">${ICON[x.state]}</span><div class="box">
      <div class="hd"><div class="title">${esc(def.title)}${x.sum ? `<small>${x.sum}</small>` : ""}</div>
        <span class="chip">${esc(def.tech)}</span><span class="when" data-when="${id}">${this.whenText(id)}</span>
        <span class="chev">${x.html ? "›" : ""}</span></div>
      <div class="bd">${x.html}</div></div>`;
    const term = $(".term", li);
    if (term) term.scrollTop = term.scrollHeight;
  }

  whenText(id) {
    const x = this.s[id];
    if (this.recorded) return "";
    if (x.state === "running" && x.start) return fmtDur(Date.now() / 1000 - x.start);
    if (x.start && x.end) return fmtDur(x.end - x.start);
    return "";
  }

  tick() {
    if (this.recorded || this.t0 == null) return;
    const end = this.tEnd ?? Date.now() / 1000;
    $("#r-clock", this.root).textContent = fmtClock(end - this.t0);
    for (const st of STAGES) {
      if (this.s[st.id].state === "running") {
        const w = $(`[data-when="${st.id}"]`, this.root);
        if (w) w.textContent = this.whenText(st.id);
      }
    }
  }
}

// ---- Stage renderers
function renderClaims(run, c, ts) {
  const n = (a) => (a ? a.length : 0);
  const counts = `${n(c.files)} files · ${n(c.functions)} functions · ${n(c.code_quotes)} code quotes · ${n(c.cves)} CVEs · ${n(c.urls)} URLs`;
  run.set("claims", c.extraction_failed ? "warn" : "done", esc(counts), `<div class="facts">
    ${fact("meh", `<b>Claim:</b> ${esc(c.summary)}`, `${esc(c.vuln_class || "")}${c.attack_surface ? ` · attack surface: ${esc(c.attack_surface)}` : ""}`)}
    ${fact(c.has_poc ? "good" : "meh", c.has_poc ? "The report includes a proof of concept" : "No runnable proof of concept in the report")}
    ${c.extraction_failed ? fact("bad", "Structured extraction failed; later steps read the full report instead") : ""}</div>`, ts);
  run.now = "Checking each claim against the source tree…";
}

function renderCode(run, code, ts) {
  const out = [];
  let bad = 0, good = 0;
  const add = (k, h, s) => { out.push(fact(k, h, s)); if (k === "bad") bad++; if (k === "good") good++; };
  for (const f of code.files) {
    if (f.exists) add("good", `File <code>${esc(f.path)}</code> exists`);
    else if (f.found_elsewhere) add("meh", `File <code>${esc(f.path)}</code> is not at that path`, `Closest: ${f.found_elsewhere.map(esc).join(", ")}`);
    else add("bad", `File <code>${esc(f.path)}</code> does not exist in the project`);
  }
  for (const f of code.functions) {
    if (!f.exists) add("bad", `Function <code>${esc(f.name)}</code> does not exist in the project`);
    else if (f.test_code_only) add("meh", `Function <code>${esc(f.name)}</code> exists only in test code`, f.definitions.map(esc).join(", "));
    else add("good", `Function <code>${esc(f.name)}</code> exists`, f.definitions.length ? `defined at ${f.definitions.map(esc).join(", ")}` : `used in ${f.files_using} files`);
  }
  for (const r of code.line_refs) {
    if (r.actual != null) add("meh", `<code>${esc(r.file)}:${r.line}</code> is <code>${esc(r.actual)}</code>`);
    else add("bad", `Cited line <code>${esc(r.file)}:${r.line}</code> does not exist`);
  }
  for (const q of code.code_quotes) {
    const where = q.match.file ? `best match ${esc(q.match.file)}:${q.match.line}, similarity ${q.match.score}%` : "";
    const sub = `<code>${esc(q.quote.slice(0, 160))}</code><br>${where}${lineDiff(q.line_diff)}`;
    if (q.verdict === "verbatim") add("good", "Quoted code is real", sub);
    else if (q.verdict === "paraphrased") add("meh", "Quoted code is paraphrased, not verbatim", sub);
    else if (q.verdict === "older_version") {
      const h = q.history;
      add("meh", "Quoted code is from an older version of the project", `${sub}<br>Last changed in <code>${esc(h.last_changed.commit)}</code> (${esc(h.last_changed.date)}): ${esc(h.last_changed.subject)}`);
    } else add("bad", "Quoted code is NOT in the codebase", sub);
  }
  const tree = run.ref ? `<p class="muted" style="font-size:13px;margin:12px 0 0">Source tree <code>${esc(run.ref.sha.slice(0, 12))}</code>: ${esc(run.ref.why)}</p>` : "";
  const sum = out.length ? `${good} confirmed · ${bad} contradicted` : "the report cites no code";
  run.set("code", bad ? "warn" : "done", sum, tree + (out.length ? `<div class="facts">${out.join("")}</div>` : `<p class="muted">The report cites no code to check.</p>`), ts);
  run.now = "Searching the code and the web…";
}

function lineDiff(d) {
  if (!d) return "";
  const parts = [`${d.exact} of ${d.lines} lines exact`];
  if (d.changed.length) parts.push(`${d.changed.length} changed`);
  if (d.not_found_count) parts.push(`${d.not_found_count} not found near the match`);
  const body = esc(d.diff).split("\n").map((l) =>
    l.startsWith("+") && !l.startsWith("+++") ? `<span class="add">${l}</span>` :
      l.startsWith("-") && !l.startsWith("---") ? `<span class="del">${l}</span>` : l).join("\n");
  return `<br>${parts.join(" · ")}<details class="ldiff"><summary>Line diff: − real code, + report</summary><pre>${body}</pre></details>`;
}

function renderWeb(run, web, ts) {
  const out = [];
  for (const c of web.cves) out.push(fact(c.supported ? "good" : "bad", `<b>${esc(c.cve)}</b> ${c.supported ? "matches the report" : "does not support this report"}`, `${esc(c.explanation)}${srcLink(c.evidence_url)}`));
  for (const u of web.urls) {
    const k = !u.reachable || u.supports_claim === false ? "bad" : u.supports_claim ? "good" : "meh";
    out.push(fact(k, `<code>${esc(u.url)}</code>`, esc(u.explanation)));
  }
  const p = web.prior_art || {};
  const flags = [p.known_issue && "known issue", p.already_fixed && "already fixed", p.documented_behaviour && "documented behaviour"].filter(Boolean);
  out.push(fact(flags.length ? "meh" : "good", `Prior art: ${flags.length ? flags.join(", ") : "nothing matching found"}`, `${esc(p.explanation)}${srcLink(p.evidence_url)}`));
  const bad = web.cves.filter((c) => !c.supported).length + web.urls.filter((u) => !u.reachable || u.supports_claim === false).length;
  run.set("web", bad ? "warn" : "done", flags.length ? esc(flags.join(", ")) : `${web.cves.length} CVEs · ${web.urls.length} links checked`, `<div class="facts">${out.join("")}</div>`, ts);
}

function renderScreen(run, sc, ts) {
  run.set("screen", "done", sc.close ? "votes to close" : "votes to keep", `<div class="facts">${fact(sc.close ? "bad" : "good",
    sc.close ? "<b>Votes to close as slop</b>" : "<b>Votes to keep</b>",
    `Judged from the wording alone, so its reason is never shown as evidence and can itself be wrong: ${esc(sc.reason)}`)}</div>`, ts);
}

function renderSearch(run, found, ts) {
  if (!found || !found.length) { run.set("search", "done", "no functions indexed", `<p class="muted">No C functions indexed for this project.</p>`, ts); return; }
  const note = found[0].backfilled ? "Computed after this recorded run: its analysis did not see these." : "These functions go to the static analysis along with any code the report cites.";
  run.set("search", "done", `top match <code>${esc(found[0].name)}</code>`, `<div class="facts">${found.slice(0, 6).map((h) =>
    fact("meh", `<code>${esc(h.name)}</code> in <code>${esc(h.file)}:${h.start}</code>`, esc(h.why))).join("")}</div><p class="muted" style="font-size:13px">${note}</p>`, ts);
}

function renderAnalysis(run, a, ts) {
  const kind = a.claim_holds === "yes" ? "bad" : a.claim_holds === "no" ? "good" : "meh";
  const label = { yes: "The claimed condition CAN happen", no: "The claimed condition CANNOT happen", unclear: "Unclear from the code alone" }[a.claim_holds] || a.claim_holds;
  run.set("analysis", a.claim_holds === "unclear" ? "warn" : "done", esc(label), `<div class="facts">${fact(kind, `<b>${label}</b>`, esc(a.reasoning))}
    ${(a.key_lines || []).map((k) => fact("meh", `<code>${esc(k)}</code>`)).join("")}</div>`, ts);
  run.now = run.sandbox ? "Starting the sandbox…" : "Writing the verdict…";
}

function renderPolicy(run, sc, ts) {
  if (!sc) return;
  const label = { out_of_scope: "Policy lists this kind of issue as not a security issue", in_scope: "In scope under the project's policy", unclear: "The policy does not clearly decide" }[sc.scope] || "Project policy";
  run.set("policy", sc.scope === "out_of_scope" ? "warn" : "done", esc(label), `<div class="facts">${fact(sc.scope === "out_of_scope" ? "meh" : "good",
    `<b>${label}</b>${sc.section ? ` (${esc(sc.section)})` : ""}`,
    `${sc.quote ? `“${esc(sc.quote)}” · ${esc(sc.policy_file || "")}<br>` : ""}${esc(sc.reason || "")}<br>Shown for the maintainer; it never decides the verdict.`)}</div>`, ts);
}

function renderRepro(run, ev, ts) {
  const x = run.s.reproduce;
  if (ev.type === "begin") {
    run.term = `<span class="dim">Sandbox started: no network, all capabilities dropped, read-only root. Building with AddressSanitizer…</span>\n`;
    run.now = "Building the project in the sandbox…";
  }
  if (ev.type === "run") {
    run.steps += 1;
    run.term += `\n<span class="cmd">$ ${esc(ev.cmd)}</span>\n`;
    run.now = `Step ${run.steps}: ${ev.cmd.slice(0, 120)}`;
  }
  if (ev.type === "output") {
    const lines = (ev.output || "").trim().split("\n").slice(-14).join("\n");
    run.term += `<span class="${ev.exit_code === 0 ? "" : "fail"}">${esc(lines)}</span>\n<span class="${ev.exit_code === 0 ? "ok" : "fail"}">[exit ${ev.exit_code}]</span>\n`;
  }
  if (ev.type === "write") run.term += `\n<span class="file">✎ ${esc(ev.path)}</span>\n${esc((ev.content || "").slice(0, 1500))}\n`;
  let state = "running", sum = run.steps ? `${run.steps} commands so far` : "starting";
  if (ev.type === "finish") {
    state = ev.outcome === "reproduced" ? "done" : ev.outcome === "not_reproduced" ? "done" : "warn";
    sum = `${esc(ev.outcome.replace("_", " "))}${ev.bundle ? ` · proof ${esc(ev.bundle)}` : ""} · ${run.steps} commands`;
    run.term += `\n<b>Outcome: ${esc(ev.outcome)}</b>${ev.bundle ? `\nProof bundle re-run in a fresh sandbox: ${esc(ev.bundle)}` : ""}\n`;
    run.now = "Writing the verdict…";
  }
  if (x.state === "pending") x.start = run.lastTs ?? ts;
  run.set("reproduce", state, sum, `<div class="term">${run.term}</div>`, ts);
  x.open = true;
}

function renderVerdict(run, ev, ts) {
  const v = ev.verdict, cost = ev.cost || { total_usd: 0, by_model: {} };
  for (const id of ["policy", "reproduce", "screen", "search"]) {
    if (run.s[id].state === "pending" || run.s[id].state === "running") {
      run.set(id, "skipped", id === "reproduce" ? "not run for this report" : "not recorded for this run", "", ts);
    }
  }
  run.set("verdict", "done", `<span class="vt ${esc(v.verdict)}">${esc(v.verdict)}</span>`, "", ts);
  const rows = Object.entries(cost.by_model || {}).map(([m, c]) =>
    `<tr><td class="mono">${esc(m)}</td><td>${c.calls}</td><td>${c.in.toLocaleString()} / ${c.out.toLocaleString()}</td><td>$${c.usd.toFixed(4)}</td></tr>`).join("");
  const action = v.priority === "low" ? "Not disproved, but low priority: handle after the rest of the queue." : ACTIONS[v.verdict] || "";
  $("#r-verdict", run.root).innerHTML = `<div class="card verdict v-${esc(v.verdict)}">
    <div class="vhead"><span class="vbadge">${esc(v.verdict)}</span><span class="muted">confidence ${Math.round((v.confidence || 0) * 100)}%</span></div>
    <h2>${esc(v.headline)}</h2>
    <div class="action">${esc(action)}</div>
    <div class="facts">${(v.findings || []).map((f) => fact(f.kind === "confirmation" ? "good" : f.kind === "contradiction" ? "bad" : "meh", esc(f.text))).join("")}</div>
    <div class="kicker" style="margin-top:18px">Suggested reply to the reporter</div>
    <div class="reply"><pre id="r-reply">${esc(v.maintainer_comment)}</pre><button class="btn small" id="r-copy-reply">Copy</button></div>
    <div id="r-bundle"></div>
    <details style="margin-top:14px"><summary class="muted">Cost $${(cost.total_usd || 0).toFixed(4)}${ev.seconds ? ` · ${fmtDur(ev.seconds)}` : ""} · per model</summary>
      <table class="ledger"><tr><th>Model</th><th>Calls</th><th>Tokens in / out</th><th>USD</th></tr>${rows}</table></details></div>`;
  $("#r-copy-reply", run.root).onclick = () => navigator.clipboard.writeText($("#r-reply", run.root).textContent).then(() => toast("Reply copied"));
  const dl = $("#r-facts", run.root);
  dl.innerHTML = `<dt>Verdict</dt><dd class="vt ${esc(v.verdict)}">${esc(v.verdict)}</dd><dt>Cost</dt><dd>$${(cost.total_usd || 0).toFixed(3)}</dd>
    ${run.ref ? `<dt>Tree</dt><dd>${esc(run.ref.sha.slice(0, 12))}</dd>` : ""}<dt>Commands</dt><dd>${run.steps}</dd>`;
  if (!run.recorded) rememberRun({ id: run.id, verdict: v.verdict, title: $("#r-title", run.root).textContent });
}

function showBundle(run, rep) {
  const b = rep && rep.bundle;
  if (!b) return;
  const bv = rep.bundle_verification || {};
  $("#r-bundle", run.root).innerHTML = `<div class="kicker" style="margin-top:18px">Proof bundle</div><div class="facts">${fact(
    (bv.verdict || "").startsWith("VERIFIED") ? "good" : "meh",
    `<b>${esc(bv.verdict || "not verified")}</b> · <code>sha256:${esc(b.sha256.slice(0, 16))}</code>`,
    `Anyone can re-run it: <code>slopproof verify bundle.json</code> · <a href="#" id="r-dl">download the bundle</a>`)}</div>`;
  $("#r-dl", run.root).onclick = (e) => { e.preventDefault(); download(`slopproof-bundle-${b.sha256.slice(0, 12)}.json`, b); };
}

// ---- Pages
// A live run: the server replays every saved event first, so a reload picks up where the run is.
ROUTES.run = async ([id]) => {
  if (STATIC) { location.hash = "#/"; return; }
  let meta = {};
  try { meta = await getJSON(`/api/jobs/${encodeURIComponent(id)}`); } catch (e) {
    app.innerHTML = `<div class="card"><h2>Run not found</h2><p class="muted">This run is not on this server any more. Start a new one.</p><a class="btn primary" href="#/">New report</a></div>`;
    return;
  }
  const run = new Run(app, { title: (meta.meta && meta.meta.title) || "Report", sandbox: meta.meta ? meta.meta.sandbox !== false : true });
  run.id = id;
  rememberRun({ id, title: (meta.meta && meta.meta.title) || "Report", ts: (meta.meta && meta.meta.ts) || Date.now() / 1000 });
  const es = new EventSource(`/api/jobs/${encodeURIComponent(id)}/events`);
  let finished = false, queued = [], frame = null;
  const flush = () => { frame = null; for (const ev of queued.splice(0)) run.apply(ev); run.render(); };
  es.onmessage = (m) => {
    const ev = JSON.parse(m.data);
    queued.push(ev);
    if (ev.stage === "done" || ev.stage === "error") { finished = true; es.close(); if (ev.stage === "done") loadResult(); }
    if (!frame) frame = requestAnimationFrame(flush);
  };
  es.onerror = () => {
    if (finished) return;
    es.close();
    run.apply({ stage: "error", interrupted: true, message: "Lost the connection to the server. Reload the page to reconnect: the run keeps going on the server." });
    run.render();
  };
  async function loadResult() {
    try { const res = await getJSON(`/api/jobs/${encodeURIComponent(id)}/result`); showBundle(run, res.reproduction); } catch (e) { /* no result kept: older run */ }
  }
  const timer = setInterval(() => run.tick(), 1000);
  return () => { clearInterval(timer); es.close(); };
};

// A recorded benchmark run, rebuilt into the same timeline.
ROUTES.report = async ([mode, id]) => {
  const run = new Run(app, { recorded: true, title: "Loading…", sandbox: true });
  const res = await getJSON(runUrl(mode, id));
  const evs = [{ stage: "report", title: res.title, body: res.report_body || "", repo: `https://github.com/${res.project}`, created_at: res.created_at },
    { stage: "claims", claims: res.claims }, { stage: "ref", ref: res.ref }, { stage: "code", code: res.code }];
  if (res.search) evs.push({ stage: "search", found: res.search });
  evs.push({ stage: "web", web: res.web });
  if (res.screen) evs.push({ stage: "screen", screen: res.screen });
  if (res.analysis) evs.push({ stage: "analysis", analysis: res.analysis });
  if (res.scope) evs.push({ stage: "scope", scope: res.scope });
  const rep = res.reproduction;
  if (rep) {
    evs.push({ stage: "reproduce", type: "begin" });
    for (const t of rep.transcript || []) {
      if (t.tool === "run") evs.push({ stage: "reproduce", type: "run", cmd: t.cmd }, { stage: "reproduce", type: "output", output: t.output, exit_code: t.exit_code });
      else evs.push({ stage: "reproduce", type: "write", path: t.path, content: t.content });
    }
    evs.push({ stage: "reproduce", type: "finish", outcome: rep.outcome, bundle: (rep.bundle_verification || {}).verdict });
  }
  evs.push({ stage: "verdict", verdict: res.verdict, cost: res.cost, seconds: res.seconds });
  for (const ev of evs) run.apply(ev);
  run.status = "recorded";
  if (res.seconds) $("#r-clock", app).textContent = fmtClock(res.seconds);
  run.now = `Recorded run of HackerOne #${id}, replayed as of ${res.created_at ? res.created_at.slice(0, 10) : "its filing date"}.`;
  run.render();
  showBundle(run, rep);
};
