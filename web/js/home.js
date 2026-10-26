"use strict";
// Home: what SlopProof does, the headline numbers, the report form and this browser's recent runs.

const EXAMPLES = [
  { id: "2298307", mode: "sandbox", label: "WebSocket “strcpy overflow”", kind: "slop" },
  { id: "3117697", mode: "sandbox", label: "cookie “double free”", kind: "slop" },
  { id: "3735184", mode: "sandbox", label: ".netrc password leak, reproduced", kind: "real" },
];

ROUTES.home = async () => {
  app.innerHTML = `
    <section class="hero">
      <div class="retro">
        <div class="term-line" aria-hidden="true"><span class="prompt">C:\\&gt;</span><span id="h-kicker"></span></div>
        <h1 class="typed" style="margin-top:10px" aria-label="Slop is cheap to write. Proof is cheap to check.">
          <span id="h-l1" aria-hidden="true"></span><br><span id="h-l2" aria-hidden="true"></span></h1>
        <p class="lead">SlopProof checks every claim in a security report against the project's real code on the day it was
        filed, checks every reference on the web, and tries to reproduce the bug in a locked-down sandbox. Every verdict
        comes with evidence and a reply you can post.</p>
      </div>
      <div class="kpis" id="kpis">${[1, 2, 3].map(() => `<div class="kpi"><div class="skeleton" style="width:100%"></div></div>`).join("")}</div>
    </section>

    <div class="marquee" aria-hidden="true"><div class="track" id="h-marquee"></div></div>

    <form class="card triage-form" id="form" autocomplete="off">
      <label class="kicker" for="url">Report to check</label>
      <div class="url-row" style="margin-top:10px">
        <input id="url" type="url" placeholder="Paste a HackerOne report or GitHub issue URL">
        <button class="btn primary" id="go" type="submit">Check report</button>
      </div>
      <details class="paste"><summary>…or paste the report text</summary>
        <div class="grid2"><input id="repo" type="url" placeholder="GitHub repo, e.g. https://github.com/curl/curl">
          <input id="ptitle" type="text" placeholder="Report title"></div>
        <textarea id="text" placeholder="Report body"></textarea>
      </details>
      <div class="options">
        <label class="switch"><input id="sandbox" type="checkbox" checked> Reproduce in sandbox</label>
        <span class="muted" style="font-size:13px">Docker, no network, AddressSanitizer · about 5 to 15 minutes</span>
        <input id="passcode" type="password" placeholder="sandbox passcode" class="hidden">
      </div>
      <div class="examples"><span class="muted" style="font-size:13px">Recorded runs:</span>
        ${EXAMPLES.map((e) => `<a class="ex" href="#/report/${e.mode}/${e.id}"><span class="tag ${e.kind}">${e.kind === "slop" ? "AI slop" : "real CVE"}</span>${esc(e.label)}</a>`).join("")}
      </div>
      <div class="form-msg" id="formmsg"></div>
    </form>

    <div id="recent-wrap"></div>

    <div class="section-title"><h2>What happens to a report</h2><a href="#/how">How it works →</a></div>
    <div class="steps3">
      <div class="card"><span class="kicker">1 · Check</span><b>Every claim against the real code</b>
        <p>Files, functions, lines and quoted code are checked against the git tree from the report's date, line by line and through history.</p></div>
      <div class="card"><span class="kicker">2 · Reproduce</span><b>A Nemotron agent tries to trigger it</b>
        <p>It builds the project with AddressSanitizer in a sandbox with no network and runs a test through the real attack surface.</p></div>
      <div class="card"><span class="kicker">3 · Prove</span><b>A proof anyone can re-run</b>
        <p>A confirmed bug becomes a proof bundle: one command re-runs it from scratch, and no AI is involved in verifying it.</p></div>
    </div>`;

  typeHero();
  loadBench().then((b) => {
    const s = b.static.score, fc = b.baseline.factcheck, sb = b.sandbox.score;
    const confirmed = (sb && sb.verdicts.real && sb.verdicts.real.CONFIRMED) || 0;
    const el = $("#kpis");
    if (!el) return;
    el.innerHTML = `
      <div class="kpi"><div class="n ok">${esc(s.real_wrongly_closed)}</div><div class="l">real CVE reports wrongly closed, out of ${s.reports} public curl reports replayed as of their filing date</div></div>
      <div class="kpi"><div class="n accent">${confirmed}</div><div class="l">real CVE reproduced in the sandbox, with a proof that re-runs from scratch</div></div>
      <div class="kpi"><div class="n bad">${fc ? `${fc.closes_with_false_reason}/${fc.baseline_closes}` : "–"}</div><div class="l">closes by a plain “is this slop?” model that cite something false. SlopProof cites checked facts.</div></div>`;
    const items = [`<b>${esc(s.real_wrongly_closed)}</b> real CVE reports wrongly closed`, `<b>${s.reports}</b> curl reports replayed as of their filing date`,
      `<b>${confirmed}</b> real CVE reproduced and proved`, `<b>${fc ? fc.closes_with_false_reason : "–"}</b> false reasons from a text-only model`,
      `<b>$${s.avg_usd.toFixed(2)}</b> per report for the static checks`, "<b>0</b> AI involved in verifying a proof bundle", "NVIDIA Nemotron · Nebius Token Factory · Tavily"];
    const m = $("#h-marquee");
    if (m) m.innerHTML = [...items, ...items].map((x) => `<span>★ ${x}</span>`).join("");
  }).catch(() => { if ($("#kpis")) $("#kpis").innerHTML = ""; });

  const recent = recentRuns();
  if (recent.length && !STATIC) {
    $("#recent-wrap").innerHTML = `<div class="section-title"><h2>Your recent runs</h2><span class="muted" style="font-size:13px">kept in this browser</span></div>
      <div class="recent">${recent.map((r) => `<a href="#/run/${esc(r.id)}"><div class="t">${esc(r.title || "Report")}</div>
        <div class="m">${r.verdict ? `<span class="vt ${esc(r.verdict)}">${esc(r.verdict)}</span>` : `<span>in progress or unfinished</span>`}<span>· ${ago(r.ts || Date.now() / 1000)}</span></div></a>`).join("")}</div>`;
  }

  if (STATIC) {
    $$("#form input, #form textarea, #form button").forEach((x) => (x.disabled = true));
    $("#formmsg").innerHTML = `This hosted copy replays recorded runs: open one above or browse the <a href="#/bench">benchmark</a>.
      To check a new report, run SlopProof from <a href="${GITHUB}">GitHub</a> with your own keys.`;
    return;
  }
  const health = await loadHealth();
  if (!$("#form")) return;
  if (!health.sandbox) { $("#sandbox").checked = false; $("#sandbox").disabled = true; }
  const syncPass = () => $("#passcode").classList.toggle("hidden", !(health.sandbox_passcode && $("#sandbox").checked));
  $("#sandbox").onchange = syncPass;
  syncPass();

  $("#form").onsubmit = async (e) => {
    e.preventDefault();
    const msg = $("#formmsg"), go = $("#go");
    msg.className = "form-msg";
    msg.textContent = "";
    const body = { sandbox: $("#sandbox").checked, passcode: $("#passcode").value || null };
    if ($("#url").value.trim()) body.url = $("#url").value.trim();
    else Object.assign(body, { text: $("#text").value, repo: $("#repo").value.trim(), title: $("#ptitle").value });
    if (!body.url && !body.text) {
      msg.className = "form-msg err";
      msg.textContent = "Paste a report URL, or the report text and its GitHub repo.";
      return;
    }
    go.disabled = true;
    go.textContent = "Starting…";
    try {
      const r = await fetch("/api/triage", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      const j = await r.json();
      if (!r.ok) throw new Error(j.detail || "The request failed.");
      rememberRun({ id: j.job, title: body.url || body.title || "Pasted report", ts: Date.now() / 1000 });
      location.hash = `#/run/${j.job}`;
    } catch (err) {
      msg.className = "form-msg err";
      msg.textContent = err.message;
      go.disabled = false;
      go.textContent = "Check report";
    }
  };
};

// Type the hero out like a 90s terminal. Skipped (shown at once) for people who prefer reduced motion.
async function typeHero() {
  const kicker = "Vulnerability report triage for open source maintainers";
  const lines = [[["Slop is cheap to write."]], [["Proof", "glitch"], [" is cheap to check."]]];
  const k = $("#h-kicker"), l1 = $("#h-l1"), l2 = $("#h-l2");
  if (!k) return;
  const still = () => document.body.contains(k);
  if (matchMedia("(prefers-reduced-motion: reduce)").matches) {
    k.textContent = kicker;
    l1.textContent = lines[0][0][0];
    l2.innerHTML = `<span class="glitch">Proof</span> is cheap to check.<span class="cursor"></span>`;
    return;
  }
  const cursor = document.createElement("span");
  cursor.className = "cursor";
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  k.after(cursor);
  for (const ch of kicker) { if (!still()) return; k.textContent += ch; await sleep(22); }
  await sleep(250);
  for (const [i, target] of [l1, l2].entries()) {
    for (const [text, cls] of lines[i]) {
      const span = document.createElement("span");
      if (cls) span.className = cls;
      target.append(span);
      target.append(cursor);
      for (const ch of text) { if (!still()) return; span.textContent += ch; await sleep(55); }
    }
    await sleep(220);
  }
}
