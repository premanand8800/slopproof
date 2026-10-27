"use strict";
// One triage run: a timeline of stages fed by events, for live runs and for recorded ones.

const STAGES = [
  { id: "report", title: "Fetch the report", tech: "HackerOne · GitHub" },
  { id: "claims", title: "Extract every checkable claim", tech: "Nemotron 3.5 Lightning" },
  { id: "memory", title: "Recall from earlier runs", tech: "memory · pinned to code" },
  { id: "code", title: "Check claims against the real code", tech: "git · fuzzy match · line diff" },
  { id: "search", title: "Find the code the report is about", tech: "tree-sitter · BM25" },
  { id: "web", title: "Check references and prior art", tech: "Tavily · Nemotron 3 Super" },
  { id: "screen", title: "Text screen (a vote, never evidence)", tech: "Nemotron 3 Ultra" },
  { id: "analysis", title: "Static analysis of the real code", tech: "Nemotron 3 Ultra" },
  { id: "policy", title: "Project security policy", tech: "quote-checked" },
  { id: "reproduce", title: "Reproduce in a sandbox", tech: "Nemotron agent · Docker · ASan" },
  { id: "verdict", title: "Verdict and reply", tech: "Nemotron 3 Ultra · hard rules" },
];
// What backs a close, in plain words, from the signals the run actually recorded. Only shown for a closing verdict.
function closeBasis(run, v) {
  if (!["NOT_REPRODUCED", "FABRICATED"].includes(v.verdict)) return "";
  const reasons = [];
  const repro = run.s.reproduce;
  if ((run.repro && run.repro.outcome) === "not_reproduced") reasons.push("the sandbox ran the claim and the bug did not occur");
  const prior = (run.web && run.web.prior_art) || {};
  if (prior.already_fixed) reasons.push("web evidence shows this was already fixed in an earlier release");
  else if (prior.known_issue) reasons.push("web evidence ties it to a known, handled issue");
  if (run.screen && run.screen.close) reasons.push(`an independent text-only screen agrees (${Math.round((run.screen.confidence || 0) * 100)}%)`);
  if ((run.analysis && run.analysis.claim_holds) === "no") reasons.push("reading the real code rules the claim out");
  if (!reasons.length) return "";
  return `<div class="basis"><b>Why this can close:</b> ${reasons.join("; ")}.</div>`;
}
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
      <div id="r-summary"></div>
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
            <div id="r-actions"></div>
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
      case "web": this.web = ev.web; renderWeb(this, ev.web, ts); break;
      case "screen": this.screen = ev.screen; renderScreen(this, ev.screen, ts); break;
      case "search": renderSearch(this, ev.found, ts); break;
      case "analysis": this.analysis = ev.analysis; renderAnalysis(this, ev.analysis, ts); break;
      case "scope": renderPolicy(this, ev.scope, ts); break;
      case "reproduce": if (ev.type === "finish") this.repro = { outcome: ev.outcome }; renderRepro(this, ev, ts); break;
      case "verdict": renderVerdict(this, ev, ts); break;
      case "memory": renderMemory(this, ev, ts); break;
      case "cost":
        this.cost = ev.usd;
        $("#r-facts", this.root).innerHTML = `<dt>Cost so far</dt><dd>$${(ev.usd || 0).toFixed(3)}</dd>${this.steps ? `<dt>Commands</dt><dd>${this.steps}</dd>` : ""}`;
        break;
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
    const restoredStage = { claims: "claims", code: "code", web: "web", screen: "screen", search: "search", analysis: "analysis", scope: "policy", reproduce: "reproduce" }[ev.stage];
    if (ev.restored && restoredStage) {
      const x = this.s[restoredStage];
      x.sum = `${x.sum ? `${x.sum} · ` : ""}reused from the earlier run`;
      x.start = x.end = null;
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
    if (this.status !== this.shownActions) this.renderActions();
    this.tick();
  }

  // Resume or re-run, for runs on this server (not recorded benchmark runs).
  async renderActions() {
    this.shownActions = this.status;
    const box = $("#r-actions", this.root);
    if (!box || this.recorded || !this.id || STATIC) return;
    if (!["error", "interrupted", "done"].includes(this.status)) { box.innerHTML = ""; return; }
    const health = await loadHealth();
    const stopped = this.status !== "done";
    const needPass = this.sandbox && health.sandbox_passcode;
    const stoppedAt = STAGES.find((st) => this.s[st.id].state === "failed");
    box.innerHTML = `<div style="margin-top:16px;padding-top:14px;border-top:1px solid var(--line)">
      ${stopped ? `<p style="margin:0 0 10px;font-size:13px">Stopped${stoppedAt ? ` at <b>${esc(stoppedAt.title)}</b>` : ""}. Finished steps are kept, so resuming only runs what is left.</p>` : ""}
      ${needPass ? `<input id="r-pass" type="password" placeholder="sandbox passcode" style="height:38px;margin-bottom:8px">` : ""}
      <div class="row wrap">
        ${stopped ? `<button class="btn small primary" id="r-resume">Resume from where it stopped</button>` : ""}
        <button class="btn small" id="r-fresh">${stopped ? "Start over" : "Run again"}</button></div>
      <div class="form-msg err" id="r-retry-msg"></div></div>`;
    const go = async (fresh) => {
      const msg = $("#r-retry-msg", box);
      msg.textContent = "";
      $$("button", box).forEach((b) => (b.disabled = true));
      try {
        const r = await fetch(`/api/jobs/${encodeURIComponent(this.id)}/retry`, { method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ fresh, passcode: needPass ? $("#r-pass", box).value : null }) });
        const j = await r.json();
        if (!r.ok) throw new Error(j.detail || "Could not start the run.");
        rememberRun({ id: j.job, title: $("#r-title", this.root).textContent, ts: Date.now() / 1000 });
        location.hash = `#/run/${j.job}`;
      } catch (e) {
        msg.textContent = e.message;
        $$("button", box).forEach((b) => (b.disabled = false));
      }
    };
    if ($("#r-resume", box)) $("#r-resume", box).onclick = () => go(false);
    $("#r-fresh", box).onclick = () => go(true);
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
    const rows = refRows(r);
    if (rows.length) add("meh", `<code>${esc(r.file)}:${r.line}</code> in the real source tree`, codeBlock(r.file, rows, r.line));
    else if (r.actual != null) add("meh", `<code>${esc(r.file)}:${r.line}</code> is <code>${esc(r.actual)}</code>`);
    else add("bad", `Cited line <code>${esc(r.file)}:${r.line}</code> does not exist`);
    if (r.actual != null && !run.citedRef) run.citedRef = `${r.file}:${r.line}`;
  }
  if (!run.citedRef) {
    const q = code.code_quotes.find((x) => x.verdict === "verbatim" && x.match && x.match.file);
    if (q) run.citedRef = `${q.match.file}:${q.match.line}`;
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

// Source lines recorded for a cited line, as [{n, text}]. Only text the code check actually read from the tree:
// a context window if the event carries one, else the single line it found at that number. Never invented.
function refRows(r) {
  const start = r.context_start ?? r.snippet_start ?? r.start;
  if (Array.isArray(r.lines) && r.lines.length && typeof r.lines[0] === "object") return r.lines.map((l) => ({ n: l.line ?? l.n, text: l.text ?? "" }));
  const ctx = Array.isArray(r.context) ? r.context : typeof r.snippet === "string" ? r.snippet.split("\n") : null;
  if (ctx && ctx.length && Number.isInteger(start)) return ctx.map((text, i) => ({ n: start + i, text: String(text) }));
  if (r.actual != null) return [{ n: r.line, text: r.actual }];
  return [];
}

function codeBlock(file, rows, hl) {
  return `<div class="codeblk"><div class="cb-file">${esc(file)}</div><pre>${rows.map((r) =>
    `<span class="cb-row${r.n === hl ? " hl" : ""}"><span class="cb-n">${esc(r.n)}</span><span class="cb-t">${esc(r.text)}</span></span>`).join("")}</pre></div>`;
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
  // Icons say whether the evidence supports the report (✓) or contradicts it (✗), as in the verdict's findings.
  const kind = a.claim_holds === "yes" ? "good" : a.claim_holds === "no" ? "bad" : "meh";
  const label = { yes: "The code allows what the report claims", no: "The code rules out what the report claims", unclear: "Unclear from the code alone" }[a.claim_holds] || a.claim_holds;
  const second = a.second_look ? fact("meh", `Second look after fetching ${a.second_look.asked_for.map((n) => `<code>${esc(n)}</code>`).join(", ")}`,
    `First conclusion: ${esc(a.second_look.first_conclusion)}`) : "";
  run.set("analysis", a.claim_holds === "unclear" ? "warn" : "done", esc(label), `<div class="facts">${fact(kind, `<b>${label}</b>`, esc(a.reasoning))}
    ${second}${(a.key_lines || []).map((k) => fact("meh", `<code>${esc(k)}</code>`)).join("")}
    ${(a.callers || []).length ? `<div class="kicker" style="margin-top:6px">Callers: can real input reach the bug?</div>` : ""}
    ${(a.callers || []).map((c) => fact(c.allows === "yes" ? "good" : c.allows === "no" ? "bad" : "meh",
      `<code>${esc(c.caller)}</code>: ${c.allows === "yes" ? "allows it" : c.allows === "no" ? "blocks it" : "unclear"}`, esc(c.why))).join("")}</div>`, ts);
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
    if (/ERROR: AddressSanitizer/.test(ev.output || "")) run.asan = true;
    const lines = (ev.output || "").trim().split("\n").slice(-14).join("\n");
    run.term += `<span class="${ev.exit_code === 0 ? "" : "fail"}">${esc(lines)}</span>\n<span class="${ev.exit_code === 0 ? "ok" : "fail"}">[exit ${ev.exit_code}]</span>\n`;
  }
  if (ev.type === "write") run.term += `\n<span class="file">✎ ${esc(ev.path)}</span>\n${esc((ev.content || "").slice(0, 1500))}\n`;
  let state = "running", sum = run.steps ? `${run.steps} commands so far` : "starting";
  if (ev.type === "finish") {
    run.reproOutcome = ev.outcome;
    if (ev.bundle_sha) run.bundleSha = ev.bundle_sha;
    state = ev.outcome === "reproduced" ? "done" : ev.outcome === "not_reproduced" ? "done" : "warn";
    sum = `${ev.reason ? `stopped without a result: ${esc(ev.reason)}` : esc(ev.outcome.replace("_", " "))}${ev.bundle ? ` · proof ${esc(ev.bundle)}` : ""} · ${run.steps} commands`;
    run.term += `\n<b>Outcome: ${esc(ev.outcome)}</b>${ev.bundle ? `\nProof bundle re-run in a fresh sandbox: ${esc(ev.bundle)}` : ""}\n`;
    run.now = "Writing the verdict…";
  }
  if (x.state === "pending") x.start = run.lastTs ?? ts;
  run.set("reproduce", state, sum, `<div class="term">${run.term}</div>`, ts);
  x.open = true;
}

function renderVerdict(run, ev, ts) {
  const v = ev.verdict, cost = ev.cost || { total_usd: 0, by_model: {} };
  for (const id of ["memory", "policy", "reproduce", "screen", "search"]) {
    if (id === "memory" && run.s.memory.state === "pending") {
      run.set("memory", "skipped", run.recorded ? "not used in benchmark runs" : "nothing remembered for this project yet", "", ts);
      continue;
    }
    if (run.s[id].state === "pending" || run.s[id].state === "running") {
      if (id === "reproduce" && run.steps) run.set(id, "warn", `stopped without a result · ${run.steps} commands`, undefined, ts);
      else run.set(id, "skipped", id === "reproduce" ? "not run for this report" : "not recorded for this run", "", ts);
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
    ${closeBasis(run, v)}
    <div class="facts">${(v.findings || []).map((f) => fact(f.kind === "confirmation" ? "good" : f.kind === "contradiction" ? "bad" : "meh", esc(f.text))).join("")}</div>
    <div class="kicker" style="margin-top:18px">Suggested reply to the reporter</div>
    <p class="reply-note">AI-generated from the evidence above. Read it against the findings before you post.</p>
    <div class="reply"><pre id="r-reply">${esc(v.maintainer_comment)}</pre><button class="btn small" id="r-copy-reply">Copy</button></div>
    <div id="r-bundle"></div>
    <details style="margin-top:14px"><summary class="muted">Cost $${(cost.total_usd || 0).toFixed(4)}${ev.seconds ? ` · ${fmtDur(ev.seconds)}` : ""} · per model</summary>
      <table class="ledger"><tr><th>Model</th><th>Calls</th><th>Tokens in / out</th><th>USD</th></tr>${rows}</table></details></div>`;
  // The answer first: a one-line verdict above the timeline, linking down to the evidence.
  const pct = Math.round((v.confidence || 0) * 100);
  $("#r-summary", run.root).innerHTML = `<div class="vsum v-${esc(v.verdict)}">
    <span class="vstamp-wrap"><span class="vbadge vstamp">${esc(String(v.verdict).replace(/_/g, " "))}</span></span>
    ${v.confidence != null ? `<span class="vring" style="--p:${pct}" title="Model confidence ${pct}%" aria-label="confidence ${pct}%"><b>${pct}<i>%</i></b></span>` : ""}
    <div class="vtext">${esc(v.headline)}<small>${esc(action)}</small><div class="vchips">${verdictChips(run, v)}</div></div>
    <button class="btn small" id="r-jump" type="button">Evidence and reply ↓</button></div>`;
  $("#r-jump", run.root).onclick = () => $("#r-verdict", run.root).scrollIntoView({ behavior: "smooth", block: "start" });
  const refChip = $(".vchip.ref", run.root);
  if (refChip) refChip.onclick = () => {
    run.s.code.open = true;
    run.renderStage("code");
    $('.st[data-id="code"]', run.root).scrollIntoView({ behavior: "smooth", block: "start" });
  };
  $("#r-copy-reply", run.root).onclick = () => navigator.clipboard.writeText($("#r-reply", run.root).textContent).then(() => toast("Reply copied"));
  const dl = $("#r-facts", run.root);
  dl.innerHTML = `<dt>Verdict</dt><dd class="vt ${esc(v.verdict)}">${esc(v.verdict)}</dd><dt>Cost</dt><dd>$${(cost.total_usd || 0).toFixed(3)}</dd>
    ${run.ref ? `<dt>Tree</dt><dd>${esc(run.ref.sha.slice(0, 12))}</dd>` : ""}<dt>Commands</dt><dd>${run.steps}</dd>`;
  if (!run.recorded) rememberRun({ id: run.id, verdict: v.verdict, title: $("#r-title", run.root).textContent });
}

// Up to three evidence chips for the verdict strip, each taken from data this run actually has.
const REF_RE = /\b((?:[\w.-]+\/)*[\w.-]+\.(?:c|h|cc|cpp|hpp|py|js|ts|go|rs|java|rb|php)):(\d+)/;
function verdictChips(run, v) {
  const chips = [];
  let ref = run.citedRef;
  if (!ref) for (const f of v.findings || []) { const m = REF_RE.exec(f.text || ""); if (m) { ref = `${m[1]}:${m[2]}`; break; } }
  if (ref) chips.push(`<button type="button" class="vchip ref" title="Show the code checks">${esc(ref)}</button>`);
  if (run.reproOutcome === "reproduced") chips.push(`<span class="vchip hit">reproduced${run.asan ? " · ASan" : ""}</span>`);
  else if (run.asan) chips.push(`<span class="vchip">ASan report</span>`);
  else if (run.reproOutcome === "not_reproduced") chips.push(`<span class="vchip">not reproduced in sandbox</span>`);
  if (run.bundleSha) chips.push(proofChip(run.bundleSha));
  return chips.slice(0, 3).join("");
}
const proofChip = (sha) => `<span class="vchip proof" title="sha256:${esc(sha)}">proof sha256:${esc(sha.slice(0, 8))}</span>`;

function renderMemory(run, ev, ts) {
  if (ev.learned) {
    const l = ev.learned, parts = [];
    if ((l.skills || []).length) parts.push(`${l.skills.join(" and ")} skill`);
    if ((l.facts || []).length) parts.push(`${l.facts.length} caller facts`);
    const x = run.s.memory;
    x.sum = `${x.sum ? `${x.sum} · ` : ""}learned: ${parts.join(", ") || "nothing new (no hard check confirmed anything)"}`;
    return;
  }
  const r = ev.recalled || {};
  const items = [
    ...(r.skills || []).map((s) => fact("good", `<b>${esc(s.kind)} skill</b>: ${esc(s.title)}`, `worked ${s.successes} time(s) before`)),
    ...(r.facts || []).map((f) => fact(f.stale ? "meh" : "good", `<code>${esc(f.subject)}</code>`,
      `${esc(f.text)}<br>${f.stale ? "<b>Stale:</b> the file changed since this was seen; re-checked, not trusted" : "file unchanged since it was seen"} · source: ${esc(f.source)}`)),
    ...(r.lessons || []).map((x) => fact("meh", `<b>Lesson</b>: ${esc(x.text)}`, `from ${esc(x.source)}`)),
  ];
  run.set("memory", "done", `${(r.skills || []).length} skills · ${(r.facts || []).length} facts · ${(r.lessons || []).length} lessons recalled`,
    `<p class="muted" style="font-size:13px">Leads from earlier runs. They steer where to look and how to build; they never count as evidence.</p><div class="facts">${items.join("")}</div>`, ts);
}

function showBundle(run, rep) {
  const b = rep && rep.bundle;
  if (!b) return;
  const bv = rep.bundle_verification || {};
  const chips = $(".vchips", run.root);
  if (chips && b.sha256 && !$(".vchip.proof", chips) && chips.children.length < 3) chips.insertAdjacentHTML("beforeend", proofChip(b.sha256));
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
  if (meta.meta && meta.meta.retry_of) {
    $("#r-meta", app).insertAdjacentHTML("afterend", `<span>· continues <a href="#/run/${esc(meta.meta.retry_of)}">an earlier run</a>${meta.meta.resumed_steps && meta.meta.resumed_steps.length ? `, reusing ${meta.meta.resumed_steps.length} finished steps` : ""}</span>`);
  }
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
  const here = location.hash;
  const res = await getJSON(runUrl(mode, id));
  if (location.hash !== here) return; // navigated away while loading
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
    evs.push({ stage: "reproduce", type: "finish", outcome: rep.outcome, bundle: (rep.bundle_verification || {}).verdict,
      bundle_sha: rep.bundle && rep.bundle.sha256 });
  }
  evs.push({ stage: "verdict", verdict: res.verdict, cost: res.cost, seconds: res.seconds });

  let i = 0, timer = null, over = false;
  const finish = () => {
    over = true;
    clearTimeout(timer);
    while (i < evs.length) run.apply(evs[i++]);
    run.status = "recorded";
    if (res.seconds) $("#r-clock", app).textContent = fmtClock(res.seconds);
    run.now = `Recorded run of HackerOne #${id}, replayed as of ${res.created_at ? res.created_at.slice(0, 10) : "its filing date"}.`;
    run.root.classList.remove("replaying");
    run.render();
    showBundle(run, rep);
    const skip = $("#r-skip", app);
    if (skip) skip.remove();
  };
  const instant = matchMedia("(prefers-reduced-motion: reduce)").matches || tourStep() != null;
  if (instant) {
    finish();
    // On the tour, go straight to the verdict: the timeline above it is there for anyone who wants the detail.
    if (tourStep() != null) setTimeout(() => $("#r-verdict", app).scrollIntoView({ behavior: "smooth", block: "start" }), 400);
    return;
  }

  // Replay: events one by one, so the stages light up in order. Sandbox steps are minor and go quicker;
  // the whole replay stays under about 12 seconds.
  const STAGE_OF = { report: "report", claims: "claims", ref: "code", code: "code", search: "search", web: "web", screen: "screen",
    analysis: "analysis", scope: "policy", reproduce: "reproduce", verdict: "verdict" };
  const minor = (ev) => ev.stage === "ref" || (ev.stage === "reproduce" && !["begin", "finish"].includes(ev.type));
  const majors = evs.filter((ev) => !minor(ev)).length, minors = evs.length - majors;
  const big = 420, small = Math.max(40, Math.min(250, minors ? (11000 - majors * big) / minors : 0));
  const delays = evs.map((ev) => (minor(ev) ? small : ev.stage === "verdict" ? 600 : big));
  const total = delays.reduce((a, b) => a + b, 0);
  let elapsed = 0;
  run.root.classList.add("replaying");
  $(".run-head .row", app).insertAdjacentHTML("afterbegin", `<button class="btn small" id="r-skip" type="button" title="Show the whole run at once">Skip to verdict ⏭</button>`);
  $("#r-skip", app).onclick = finish;
  run.now = "Replaying the recorded run…";
  run.s.report.state = "running";
  run.render();
  $("#r-status", app).innerHTML = `<span class="pulse"></span>Replaying`;
  const step = () => {
    if (over || !$("#r-skip", app)) return; // finished, or the page was replaced
    const ev = evs[i++];
    run.apply(ev);
    elapsed += delays[i - 1];
    // The next stage shows as running while it waits for its event.
    const next = evs[i] && run.s[STAGE_OF[evs[i].stage]];
    if (next && next.state === "pending") next.state = "running";
    if (i >= evs.length) { finish(); return; }
    run.render();
    if (res.seconds) $("#r-clock", app).textContent = fmtClock((res.seconds * elapsed) / total);
    $("#r-status", app).innerHTML = `<span class="pulse"></span>Replaying`;
    timer = setTimeout(step, delays[i]);
  };
  timer = setTimeout(step, 250);
  return () => { over = true; clearTimeout(timer); };
};
