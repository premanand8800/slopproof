const $ = (s, el = document) => el.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);

const STAGES = [
  ["claims", "Extract claims", "Nemotron 3.5 Lightning"],
  ["code", "Check claims against the real code", "git · fuzzy match"],
  ["web", "Check references and prior art", "Tavily · Nemotron 3 Super"],
  ["analysis", "Static analysis of the real code", "Nemotron 3 Ultra"],
  ["reproduce", "Reproduce in sandbox", "Nemotron 3 Ultra agent · Docker"],
  ["verdict", "Verdict", "Nemotron 3 Ultra"],
];
const ACTIONS = {
  CONFIRMED: "Reproduced. Treat as a real vulnerability.",
  PLAUSIBLE: "Not disproved. A maintainer should look.",
  NOT_REPRODUCED: "Safe to close with the evidence below.",
  FABRICATED: "Safe to close: the report relies on things that do not exist.",
};

// Tabs
document.querySelectorAll(".tab").forEach((b) => b.addEventListener("click", () => showTab(b.dataset.tab)));
function showTab(name) {
  document.querySelectorAll(".tab").forEach((x) => x.classList.toggle("active", x.dataset.tab === name));
  document.querySelectorAll(".panel").forEach((x) => x.classList.toggle("active", x.id === `tab-${name}`));
  if (name === "bench") loadBench();
}

document.querySelectorAll(".examples a").forEach((a) => a.addEventListener("click", () => { $("#url").value = a.dataset.url; }));

// Live triage
$("#form").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("#formerr").textContent = "";
  const body = { sandbox: $("#sandbox").checked };
  if ($("#url").value.trim()) body.url = $("#url").value.trim();
  else Object.assign(body, { text: $("#text").value, repo: $("#repo").value.trim(), title: $("#ptitle").value });
  $("#go").disabled = true;
  try {
    const r = await fetch("/api/triage", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const j = await r.json();
    if (!r.ok) throw new Error(j.detail || "request failed");
    resetLive();
    const es = new EventSource(`/api/jobs/${j.job}/events`);
    es.onmessage = (m) => {
      const ev = JSON.parse(m.data);
      handle(ev);
      if (ev.stage === "done" || ev.stage === "error") { es.close(); $("#go").disabled = false; }
    };
    es.onerror = () => { es.close(); $("#go").disabled = false; };
  } catch (err) {
    $("#formerr").textContent = err.message;
    $("#go").disabled = false;
  }
});

function resetLive() {
  $("#live").hidden = false;
  $("#verdict").hidden = true;
  $("#stages").innerHTML = STAGES.map(([id, name, model]) => `
    <li class="stage" id="st-${id}">
      <div class="head"><div class="name"><span class="dot"></span>${name}</div><span class="model">${model}</span></div>
      <div class="body"></div>
    </li>`).join("");
  $("#st-claims").classList.add("running");
}

function setStage(id, state, html) {
  const el = $(`#st-${id}`);
  if (!el) return;
  el.classList.remove("running", "done");
  if (state) el.classList.add(state);
  if (html !== undefined) $(".body", el).innerHTML = html;
}

function fact(kind, html, sub) {
  const ic = { good: "✓", bad: "✗", meh: "?" }[kind];
  return `<div class="fact ${kind}"><span class="ic">${ic}</span><div>${html}${sub ? `<div class="sub">${sub}</div>` : ""}</div></div>`;
}

function handle(ev) {
  switch (ev.stage) {
    case "report":
      $("#r-title").textContent = ev.title;
      $("#r-meta").textContent = `${ev.repo}${ev.created_at ? " · filed " + ev.created_at.slice(0, 10) : ""}`;
      $("#r-body").textContent = ev.body;
      break;
    case "claims": {
      const c = ev.claims;
      setStage("claims", "done", `<div class="facts">
        ${fact("meh", `<b>Claim:</b> ${esc(c.summary)}`, `${esc(c.vuln_class || "")} · attack surface: ${esc(c.attack_surface || "not stated")}`)}
        ${fact("meh", `${c.files.length} files, ${c.functions.length} functions, ${c.code_quotes.length} code quotes, ${c.cves.length} CVEs, ${c.urls.length} URLs cited`,
          c.has_poc ? "Report includes a PoC" : "No runnable PoC in the report")}
      </div>`);
      setStage("code", "running");
      break;
    }
    case "ref":
      $(`#st-code .body`).innerHTML = `<div class="sub muted">Source tree: <code>${esc(ev.ref.sha.slice(0, 12))}</code>, ${esc(ev.ref.why)}</div>`;
      break;
    case "code":
      setStage("code", "done", ($(`#st-code .body`).innerHTML || "") + renderCode(ev.code));
      setStage("web", "running");
      break;
    case "web":
      setStage("web", "done", renderWeb(ev.web));
      setStage("analysis", "running");
      break;
    case "analysis": {
      const a = ev.analysis;
      const kind = a.claim_holds === "yes" ? "bad" : a.claim_holds === "no" ? "good" : "meh";
      const label = { yes: "The claimed condition CAN happen", no: "The claimed condition CANNOT happen", unclear: "Unclear from the code alone" }[a.claim_holds] || a.claim_holds;
      setStage("analysis", "done", `<div class="facts">${fact(kind, `<b>${label}</b>`, esc(a.reasoning))}
        ${(a.key_lines || []).map((k) => fact("meh", `<code>${esc(k)}</code>`)).join("")}</div>`);
      setStage("reproduce", "running", `<div class="term" id="term"></div>`);
      break;
    }
    case "reproduce":
      renderRepro(ev);
      break;
    case "verdict":
      if (!$("#st-reproduce").classList.contains("done")) setStage("reproduce", "done", $("#term") ? undefined : `<div class="muted">Skipped.</div>`);
      setStage("verdict", "done", "");
      renderVerdict(ev.verdict, ev.cost, ev.seconds);
      break;
    case "error":
      $("#formerr").textContent = ev.message;
      document.querySelectorAll(".stage.running").forEach((x) => x.classList.remove("running"));
      break;
  }
}

function renderCode(code) {
  const out = [];
  for (const f of code.files) {
    if (f.exists) out.push(fact("good", `File <code>${esc(f.path)}</code> exists`));
    else if (f.found_elsewhere) out.push(fact("meh", `File <code>${esc(f.path)}</code> is not at that path`, `Closest: ${f.found_elsewhere.map(esc).join(", ")}`));
    else out.push(fact("bad", `File <code>${esc(f.path)}</code> does not exist in the project`));
  }
  for (const f of code.functions) {
    if (!f.exists) out.push(fact("bad", `Function <code>${esc(f.name)}</code> does not exist in the project`));
    else if (f.test_code_only) out.push(fact("meh", `Function <code>${esc(f.name)}</code> exists only in test code`, f.definitions.map(esc).join(", ")));
    else out.push(fact("good", `Function <code>${esc(f.name)}</code> exists`, f.definitions.length ? `defined at ${f.definitions.map(esc).join(", ")}` : `used in ${f.files_using} files`));
  }
  for (const r of code.line_refs) {
    out.push(r.actual != null ? fact("meh", `<code>${esc(r.file)}:${r.line}</code> is <code>${esc(r.actual)}</code>`)
      : fact("bad", `Cited line <code>${esc(r.file)}:${r.line}</code> does not exist`));
  }
  for (const q of code.code_quotes) {
    const where = q.match.file ? `best match ${esc(q.match.file)}:${q.match.line}, similarity ${q.match.score}%` : "";
    if (q.verdict === "verbatim") out.push(fact("good", "Quoted code is real", `<code>${esc(q.quote.slice(0, 160))}</code><br>${where}`));
    else if (q.verdict === "paraphrased") out.push(fact("meh", "Quoted code is paraphrased, not verbatim", `<code>${esc(q.quote.slice(0, 160))}</code><br>${where}`));
    else out.push(fact("bad", "Quoted code is NOT in the codebase", `<code>${esc(q.quote.slice(0, 160))}</code><br>${where}`));
  }
  return `<div class="facts" style="margin-top:8px">${out.join("") || '<div class="muted">The report cites no code to check.</div>'}</div>`;
}

function renderWeb(web) {
  const out = [];
  for (const c of web.cves) out.push(fact(c.supported ? "good" : "bad", `<b>${esc(c.cve)}</b> ${c.supported ? "matches" : "does not support this report"}`, `${esc(c.explanation)} ${link(c.evidence_url)}`));
  for (const u of web.urls) {
    const k = !u.reachable ? "bad" : u.supports_claim === false ? "bad" : u.supports_claim ? "good" : "meh";
    out.push(fact(k, `<code>${esc(u.url)}</code>`, esc(u.explanation)));
  }
  const p = web.prior_art;
  if (p) {
    const flags = [p.known_issue && "known issue", p.already_fixed && "already fixed", p.documented_behaviour && "documented behaviour"].filter(Boolean);
    out.push(fact(flags.length ? "meh" : "good", `Prior art: ${flags.length ? flags.join(", ") : "nothing matching found"}`, `${esc(p.explanation)} ${link(p.evidence_url)}`));
  }
  return `<div class="facts">${out.join("")}</div>`;
}

const link = (u) => (u ? `<a href="${esc(u)}" target="_blank" rel="noopener">source</a>` : "");

function renderRepro(ev) {
  const term = $("#term");
  if (!term) return;
  if (ev.type === "begin") term.innerHTML = `<span class="muted">Starting sandbox (no network) and background ASan build…</span>\n`;
  if (ev.type === "run") term.innerHTML += `\n<span class="cmd">$ ${esc(ev.cmd)}</span>\n`;
  if (ev.type === "output") {
    const lines = ev.output.trim().split("\n").slice(-12).join("\n");
    term.innerHTML += `<span class="${ev.exit_code === 0 ? "" : "fail"}">${esc(lines)}</span>\n<span class="${ev.exit_code === 0 ? "ok" : "fail"}">[exit ${ev.exit_code}]</span>\n`;
  }
  if (ev.type === "write") term.innerHTML += `\n<span class="file">✎ ${esc(ev.path)}</span>\n${esc(ev.content.slice(0, 1200))}\n`;
  if (ev.type === "finish") {
    term.innerHTML += `\n<b>Outcome: ${esc(ev.outcome)}</b>\n`;
    setStage("reproduce", "done");
  }
  term.scrollTop = term.scrollHeight;
}

function renderVerdict(v, cost, seconds) {
  const el = $("#verdict");
  el.hidden = false;
  el.className = `card verdict v-${v.verdict}`;
  const rows = Object.entries(cost.by_model || {}).map(([m, c]) =>
    `<tr><td class="mono">${esc(m)}</td><td>${c.calls}</td><td>${c.in.toLocaleString()} / ${c.out.toLocaleString()}</td><td>$${c.usd.toFixed(4)}</td></tr>`).join("");
  el.innerHTML = `
    <span class="badge">${esc(v.verdict)}</span> <span class="muted">confidence ${Math.round((v.confidence || 0) * 100)}%</span>
    <h2>${esc(v.headline)}</h2>
    <div class="action">${ACTIONS[v.verdict] || ""}</div>
    <div class="facts">${(v.findings || []).map((f) => fact(f.kind === "confirmation" ? "good" : f.kind === "contradiction" ? "bad" : "meh", esc(f.text))).join("")}</div>
    <div class="kicker" style="margin-top:14px">Suggested reply to the reporter</div>
    <div class="comment"><pre id="mcomment">${esc(v.maintainer_comment)}</pre><button id="copy">Copy</button></div>
    <details><summary>Cost: $${cost.total_usd.toFixed(4)} · ${seconds}s</summary>
      <table class="ledger"><tr><th>Model</th><th>Calls</th><th>Tokens in / out</th><th>USD</th></tr>${rows}</table></details>`;
  $("#copy").onclick = () => navigator.clipboard.writeText($("#mcomment").textContent);
}

// Replay a stored result through the same renderer.
function replay(res) {
  resetLive();
  handle({ stage: "report", title: res.title, body: res.report_body || "", repo: `https://github.com/${res.project}`, created_at: res.created_at });
  handle({ stage: "claims", claims: res.claims });
  handle({ stage: "ref", ref: res.ref });
  handle({ stage: "code", code: res.code });
  handle({ stage: "web", web: res.web });
  if (res.analysis) handle({ stage: "analysis", analysis: res.analysis });
  if (res.reproduction) {
    handle({ stage: "reproduce", type: "begin" });
    for (const t of res.reproduction.transcript || []) {
      if (t.tool === "run") {
        handle({ stage: "reproduce", type: "run", cmd: t.cmd });
        handle({ stage: "reproduce", type: "output", output: t.output, exit_code: t.exit_code });
      } else handle({ stage: "reproduce", type: "write", path: t.path, content: t.content });
    }
    handle({ stage: "reproduce", type: "finish", outcome: res.reproduction.outcome });
  } else {
    setStage("reproduce", "done", `<div class="muted">Not run for this report (static checks only).</div>`);
  }
  handle({ stage: "verdict", verdict: res.verdict, cost: res.cost, seconds: res.seconds });
}

// Benchmark
let bench = null, filter = "all";
async function loadBench() {
  if (!bench) bench = await (await fetch("/api/bench")).json();
  const mode = bench.sandbox.rows.length ? "sandbox" : "static";
  const s = bench.static.score;
  if (s) {
    $("#bench-head").innerHTML = `
      <div class="stat good"><div class="n">${s.slop_auto_closed_pct}%</div><div class="l">of AI-slop reports closed with evidence (${s.slop_auto_closed})</div></div>
      <div class="stat good"><div class="n">${s.real_kept_pct}%</div><div class="l">of real CVE reports kept open (${s.real_wrongly_closed} wrongly closed)</div></div>
      <div class="stat"><div class="n">$${s.avg_usd.toFixed(3)}</div><div class="l">average cost per report, ${s.avg_seconds}s, static checks</div></div>
      <div class="stat"><div class="n">${s.reports}</div><div class="l">public curl HackerOne reports replayed</div></div>`;
  }
  drawRows();
  document.querySelectorAll(".chip").forEach((c) => (c.onclick = () => {
    filter = c.dataset.f;
    document.querySelectorAll(".chip").forEach((x) => x.classList.toggle("active", x === c));
    drawRows();
  }));
}

function drawRows() {
  const sandboxIds = new Set(bench.sandbox.rows.map((r) => r.id));
  const rows = bench.static.rows.filter((r) => filter === "all" || r.label === filter)
    .sort((a, b) => b.created_at.localeCompare(a.created_at));
  $("#bench-count").textContent = `${rows.length} reports · click a row to replay it`;
  $("#bench-rows").innerHTML = rows.map((r) => `
    <tr data-id="${r.id}" data-mode="${sandboxIds.has(r.id) ? "sandbox" : "static"}">
      <td><div>${esc(r.title)}</div><div class="muted mono" style="font-size:12px">#${r.id} · ${r.created_at.slice(0, 10)}${sandboxIds.has(r.id) ? " · sandbox run" : ""}</div></td>
      <td><span class="pill ${r.label}">${r.label === "slop" ? "AI slop" : "real CVE"}</span></td>
      <td><span class="vt ${r.verdict}">${r.verdict}</span></td>
      <td class="mono">$${r.usd.toFixed(3)}</td>
    </tr>`).join("");
  document.querySelectorAll("#bench-rows tr").forEach((tr) => (tr.onclick = async () => {
    const res = await (await fetch(`/api/bench/${tr.dataset.mode}/${tr.dataset.id}`)).json();
    showTab("triage");
    replay(res);
    window.scrollTo({ top: 0, behavior: "smooth" });
  }));
}
