const $ = (s, el = document) => el.querySelector(s);
// The static build (no server) sets SLOPPROOF_STATIC: the benchmark and recorded runs come from JSON files.
const STATIC = window.SLOPPROOF_STATIC === true;
const runUrl = (mode, id) => (STATIC ? `data/runs/${mode}/${id}.json` : `/api/bench/${mode}/${id}`);
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);

const STAGES = [
  ["claims", "Extract claims", "Nemotron 3.5 Lightning"],
  ["code", "Check claims against the real code", "git · fuzzy match"],
  ["search", "Find the code the report is about", "tree-sitter · BM25"],
  ["web", "Check references and prior art", "Tavily · Nemotron 3 Super"],
  ["screen", "Text screen (a vote, never evidence)", "Nemotron 3 Ultra"],
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
  if (name === "proof") loadProof();
}

document.querySelectorAll(".examples a").forEach((a) => a.addEventListener("click", async () => {
  if (!STATIC) { $("#url").value = a.dataset.url; return; }
  // Without a server, the examples replay recorded runs.
  replay(await (await fetch(runUrl(a.dataset.mode, a.dataset.url.split("/").pop()))).json());
}));
if (!STATIC) {
  // A public host may protect the sandbox with a passcode; show the field only then.
  fetch("/api/health").then((r) => r.json()).then((h) => {
    if (!h.sandbox) { $("#sandbox").checked = false; $("#sandbox").disabled = true; }
    $("#passcode").hidden = !(h.sandbox && h.sandbox_passcode);
  }).catch(() => {});
}
if (STATIC) {
  $("#form").querySelectorAll("input, textarea, button").forEach((x) => (x.disabled = true));
  $("#formerr").className = "muted";
  $("#formerr").innerHTML = 'This hosted demo replays recorded runs: pick an example above or open the Benchmark tab. ' +
    'To triage a new report, run SlopProof from <a href="https://github.com/premanand8800/slopproof">GitHub</a> with your own keys.';
}

// Live triage
$("#form").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("#formerr").textContent = "";
  const body = { sandbox: $("#sandbox").checked, passcode: $("#passcode").value || null };
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
      setStage("screen", "running");
      break;
    case "search":
      setStage("search", "done", ev.found.length ? `<div class="facts">${ev.found.slice(0, 6).map((h) =>
        fact("meh", `<code>${esc(h.name)}</code> in <code>${esc(h.file)}:${h.start}</code>`, esc(h.why))).join("")}</div>
        <div class="sub muted">${ev.found[0].backfilled ? "Computed after this stored run: its static analysis did not see these." : "These functions go to the static analysis along with any code the report cites."}</div>`
        : `<div class="muted">No C functions indexed for this project.</div>`);
      break;
    case "screen": {
      const sc = ev.screen;
      setStage("screen", "done", `<div class="facts">${fact(sc.close ? "bad" : "good",
        sc.close ? "<b>Votes to close as slop</b>" : "<b>Votes to keep</b>",
        `Judged from the wording alone, so its reason is not shown as evidence and can itself be wrong: ${esc(sc.reason)}`)}</div>`);
      setStage("analysis", "running");
      break;
    }
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
    const sub = `<code>${esc(q.quote.slice(0, 160))}</code><br>${where}${renderLineDiff(q.line_diff)}`;
    if (q.verdict === "verbatim") out.push(fact("good", "Quoted code is real", sub));
    else if (q.verdict === "paraphrased") out.push(fact("meh", "Quoted code is paraphrased, not verbatim", sub));
    else if (q.verdict === "older_version") {
      const h = q.history;
      out.push(fact("meh", "Quoted code is from an older version of the project",
        `${sub}<br>Added in <code>${esc(h.added.commit)}</code> (${esc(h.added.date)}), last changed in <code>${esc(h.last_changed.commit)}</code> (${esc(h.last_changed.date)}): ${esc(h.last_changed.subject)}`));
    } else out.push(fact("bad", "Quoted code is NOT in the codebase", sub));
  }
  return `<div class="facts" style="margin-top:8px">${out.join("") || '<div class="muted">The report cites no code to check.</div>'}</div>`;
}

function renderLineDiff(d) {
  if (!d) return "";
  const parts = [`${d.exact} of ${d.lines} quoted lines exact`];
  if (d.changed.length) parts.push(`${d.changed.length} changed`);
  if (d.not_found_count) parts.push(`${d.not_found_count} not found near the match`);
  const body = esc(d.diff).split("\n").map((l) =>
    l.startsWith("+") && !l.startsWith("+++") ? `<span class="add">${l}</span>` :
    l.startsWith("-") && !l.startsWith("---") ? `<span class="del">${l}</span>` : l).join("\n");
  return `<br>${parts.join(" · ")}<details class="ldiff"><summary>Line diff: − real code, + report</summary><pre>${body}</pre></details>`;
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
    <div class="action">${v.priority === "low" ? "Not disproved, but low priority: handle after the rest of the queue." : ACTIONS[v.verdict] || ""}</div>
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
  if (res.search) handle({ stage: "search", found: res.search });
  else setStage("search", "done", `<div class="muted">Not run for this stored result (added after the benchmark run).</div>`);
  if (res.screen) handle({ stage: "screen", screen: res.screen });
  else setStage("screen", "done", `<div class="muted">Not stored for this run.</div>`);
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
  const b = res.reproduction && res.reproduction.bundle;
  if (b) {
    const bv = res.reproduction.bundle_verification || {};
    $("#verdict").insertAdjacentHTML("beforeend", `<div class="kicker" style="margin-top:14px">Proof bundle</div>
      <div class="facts">${fact(bv.verdict && bv.verdict.startsWith("VERIFIED") ? "good" : "meh",
        `<b>${esc(bv.verdict || "not verified")}</b> · <code>sha256:${esc(b.sha256.slice(0, 16))}</code>`,
        `Re-run it yourself: <code>slopproof verify bundle.json</code> · <a href="#" id="dl-bundle">download bundle</a>`)}</div>`);
    $("#dl-bundle").onclick = (e) => { e.preventDefault(); download(`slopproof-bundle-${b.sha256.slice(0, 12)}.json`, b); };
  }
}

// Benchmark
let bench = null, filter = "all";
async function loadBench() {
  if (!bench) bench = await (await fetch(STATIC ? "data/bench.json" : "/api/bench")).json();
  const mode = bench.sandbox.rows.length ? "sandbox" : "static";
  const s = bench.static.score, b = bench.baseline.score, fc = bench.baseline.factcheck, sb = bench.sandbox.score;
  if (s) {
    $("#bench-head").innerHTML = `
      <div class="stat good"><div class="n">${s.real_kept_pct}%</div><div class="l">of real CVE reports kept open (${s.real_wrongly_closed} wrongly closed)</div></div>
      <div class="stat good"><div class="n">${s.slop_auto_closed_pct}%</div><div class="l">of AI-slop reports closed, each with checked evidence (${s.slop_auto_closed})</div></div>
      <div class="stat"><div class="n">${s.slop_closed_or_low}</div><div class="l">slop closed or sent to the bottom of the queue, vs ${s.real_closed_or_low} real reports</div></div>
      <div class="stat"><div class="n">$${s.avg_usd.toFixed(3)}</div><div class="l">average cost per report, ${s.avg_seconds}s, static checks</div></div>`;
  }
  if (b && fc) {
    $("#bench-compare").innerHTML = `
      <h3>Why not just ask a model "is this slop?"</h3>
      <p class="muted">We ran that baseline: the same Nemotron 3 Ultra, the same reports, text only. It closes more slop,
      but <b>${fc.closes_with_false_reason} of its ${fc.baseline_closes} closing reasons state something false</b>, checked
      against curl's git tree on the report's date. A maintainer who posts those replies is answering slop with slop.
      SlopProof uses the same call only as a vote and cites only checked facts.</p>
      <table class="ledger">
        <tr><th></th><th>Slop closed</th><th>Real CVEs closed</th><th>Closes with a false reason</th><th>Cost per report</th></tr>
        <tr><td>Text-only baseline</td><td>${b.slop_auto_closed}</td><td>${b.real_wrongly_closed}</td><td>${fc.closes_with_false_reason} of ${fc.baseline_closes}</td><td>$${b.avg_usd.toFixed(4)}</td></tr>
        <tr><td><b>SlopProof, static</b></td><td>${s.slop_auto_closed}</td><td>${s.real_wrongly_closed}</td><td>reasons cite file:line or a source</td><td>$${s.avg_usd.toFixed(3)}</td></tr>
        ${sb ? `<tr><td><b>SlopProof + sandbox</b> (sample)</td><td>${sb.slop_auto_closed}</td><td>${sb.real_wrongly_closed}</td><td>reproduced ${sb.verdicts.real?.CONFIRMED || 0} real CVE</td><td>$${sb.avg_usd.toFixed(2)}</td></tr>` : ""}
      </table>
      <details><summary>The baseline's false statements</summary><div class="facts">
        ${fc.claims.map((c) => fact("bad", `#${esc(c.id)}: baseline said “${esc(c.baseline_said)}”`, `Fact: ${esc(c.fact)}`)).join("")}
      </div></details>`;
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
  const base = Object.fromEntries(bench.baseline.rows.map((r) => [r.id, r.verdict === "FABRICATED" ? "close" : "keep"]));
  const rows = bench.static.rows.filter((r) => filter === "all" || r.label === filter)
    .sort((a, b) => b.created_at.localeCompare(a.created_at));
  $("#bench-count").textContent = `${rows.length} reports · click a row to replay it`;
  $("#bench-rows").innerHTML = rows.map((r) => `
    <tr data-id="${r.id}" data-mode="${sandboxIds.has(r.id) ? "sandbox" : "static"}">
      <td><div>${esc(r.title)}</div><div class="muted mono" style="font-size:12px">#${r.id} · ${r.created_at.slice(0, 10)}${sandboxIds.has(r.id) ? " · sandbox run" : ""}</div></td>
      <td><span class="pill ${r.label}">${r.label === "slop" ? "AI slop" : "real CVE"}</span></td>
      <td><span class="vt ${r.verdict}">${r.verdict}</span>${r.priority === "low" ? ' <span class="muted">low priority</span>' : ""}</td>
      <td class="muted">${base[r.id] || "-"}</td>
      <td class="mono">$${r.usd.toFixed(3)}</td>
    </tr>`).join("");
  document.querySelectorAll("#bench-rows tr").forEach((tr) => (tr.onclick = async () => {
    const res = await (await fetch(runUrl(tr.dataset.mode, tr.dataset.id))).json();
    showTab("triage");
    replay(res);
    window.scrollTo({ top: 0, behavior: "smooth" });
  }));
}

// Proof bundles
function download(name, obj) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([JSON.stringify(obj, null, 1)], { type: "application/json" }));
  a.download = name;
  a.click();
}

const EXAMPLE = "curl-3735184-netrc";
const exampleUrl = (name) => (STATIC ? `data/examples/${name}.json` : `/api/examples/${name}`);

async function loadProof() {
  const el = $("#proof-example");
  if (el.dataset.loaded) return;
  el.dataset.loaded = "1";
  const [b, v] = await Promise.all([fetch(exampleUrl(EXAMPLE)), fetch(exampleUrl(EXAMPLE + ".verification"))]
    .map((p) => p.then((r) => r.json())));
  const files = Object.entries(b.files).map(([p, c]) => `<details><summary><code>${esc(p)}</code> (${c.length} bytes)</summary><pre>${esc(c)}</pre></details>`).join("");
  el.innerHTML = `
    <div class="kicker">Example: real CVE-2026-8926, HackerOne #3735184</div>
    <h2>${esc(b.claim)}</h2>
    <div class="facts">
      ${fact("meh", `Commit <code>${esc(b.commit.slice(0, 12))}</code> of ${esc(b.repo)}`, `bundle <code>sha256:${esc(b.sha256.slice(0, 16))}</code>`)}
      ${fact("meh", "Check command (exits 0 only while the bug is present)", `<code>${esc(b.check)}</code>`)}
    </div>
    ${files}
    <div class="kicker" style="margin-top:14px">Recorded verification</div>
    <div class="facts">${verifyFacts(v)}</div>
    <div class="row between" style="margin-top:12px">
      <span class="muted">Run it yourself: <code>slopproof verify bundle.json --against ${esc(v.at_against.commit.slice(0, 12))}</code></span>
      <span><a href="#" id="dl-example">Download bundle</a></span>
    </div>
    ${STATIC ? "" : `<div class="row" style="margin-top:12px;gap:8px">
      <input id="proof-pass" type="password" placeholder="demo passcode" autocomplete="off" style="max-width:180px">
      <button id="proof-run">Re-run live (about 4 min)</button></div>
      <div class="term" id="proof-term" hidden></div>`}`;
  $("#dl-example").onclick = (e) => { e.preventDefault(); download(`${EXAMPLE}.json`, b); };
  if (!STATIC) $("#proof-run").onclick = () => runProof();
}

function verifyFacts(v) {
  const row = (r, label) => r ? fact(r.bug_present ? "bad" : "good",
    `${label} <code>${esc(r.commit.slice(0, 12))}</code>: <b>${r.bug_present ? "bug present" : r.built ? "bug absent" : "build failed"}</b>`,
    `built and checked in a fresh sandbox in ${r.seconds}s`) : "";
  return fact(v.verdict.startsWith("VERIFIED") ? "good" : "bad", `<b>${esc(v.verdict)}</b>`) +
    row(v.at_commit, "Reported commit") + row(v.at_against, "Fix commit");
}

async function runProof() {
  const term = $("#proof-term");
  term.hidden = false;
  term.textContent = "Starting a fresh sandbox...\n";
  $("#proof-run").disabled = true;
  const r = await fetch(`/api/examples/${EXAMPLE}/verify?passcode=${encodeURIComponent($("#proof-pass").value)}`, { method: "POST" });
  const j = await r.json();
  if (!r.ok) { term.textContent += (j.detail || "failed") + "\n"; $("#proof-run").disabled = false; return; }
  const es = new EventSource(`/api/jobs/${j.job}/events`);
  es.onmessage = (m) => {
    const ev = JSON.parse(m.data);
    if (ev.stage === "verify") term.textContent += ev.message + "\n";
    if (ev.stage === "verified") term.insertAdjacentHTML("afterend", `<div class="facts" style="margin-top:10px">${verifyFacts(ev.result)}</div>`);
    if (ev.stage === "error") term.textContent += "error: " + ev.message + "\n";
    if (ev.stage === "done" || ev.stage === "error") { es.close(); $("#proof-run").disabled = false; }
  };
}
