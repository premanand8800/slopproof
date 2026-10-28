"use strict";
// Home: what SlopProof does, the headline numbers, the report form and this browser's recent runs.

const EXAMPLES = [
  { id: "2298307", mode: "sandbox", label: "WebSocket “strcpy overflow”", kind: "slop" },
  { id: "3117697", mode: "sandbox", label: "cookie “double free”", kind: "slop" },
  { id: "3735184", mode: "sandbox", label: ".netrc password leak, reproduced", kind: "real" },
];

// A report to run live with one click: no passcode, static checks only, about a minute. Invented by us, AI-slop style.
const LIVE_SAMPLE = {
  repo: "https://github.com/gin-gonic/gin",
  title: "Critical: heap buffer overflow in Context.Query() leads to remote code execution",
  text: `A critical heap-based buffer overflow exists in gin's query parsing. In context.go, Context.Query() calls
parseQueryBuffer(), which copies the raw query string into a fixed 1024-byte buffer with memcpy and no length check:

    func (c *Context) parseQueryBuffer(raw string) {
        var buf [1024]byte
        memcpy(&buf[0], raw, len(raw)) // VULNERABLE LINE 412
    }

A query string longer than 1024 bytes overwrites adjacent heap memory, including function pointers in the Context
struct, for remote code execution on any gin server. Reproduce: curl "http://localhost:8080/?q=$(python3 -c 'print("A"*5000)')"`,
};

ROUTES.home = async () => {
  app.innerHTML = `
    <section class="hero">
      <div class="retro">
        <div class="titlebar" aria-hidden="true"><i></i><i></i><i></i><span>SLOPPROOF.EXE</span></div>
        <div class="term-line" aria-hidden="true"><span class="prompt">C:\\&gt;</span><span id="h-kicker"></span></div>
        <h1 class="typed" style="margin-top:10px" aria-label="Slop is cheap to write. Proof is cheap to check.">
          <span id="h-l1" aria-hidden="true"></span><br><span id="h-l2" aria-hidden="true"></span></h1>
        <p class="lead"><b>Proof, not vibes.</b> SlopProof checks every claim against the project's real code as of the filing
        date, the web and a sandbox, so each verdict ships with evidence, a reply to post and, for real bugs, a re-runnable proof bundle.</p>
        <div class="term-open">
          <div class="term-line"><span class="prompt">C:\\&gt;</span>open sample_report<span class="hint">click one</span></div>
          <ul class="term-list">${EXAMPLES.map((e) => `<li><a href="#/report/${e.mode}/${e.id}"><span class="gt" aria-hidden="true">&gt;</span>
            <span class="tt ${e.kind}">[${e.kind === "slop" ? "AI slop" : "real CVE"}]</span> <span class="tl">${esc(e.label)}</span><span class="go" aria-hidden="true">↵</span></a></li>`).join("")}</ul>
        </div>
        <div class="row wrap hero-actions"><button class="btn primary" id="tour-start" type="button">Take the 60-second tour</button>
          <a class="btn" href="#/report/sandbox/3735184">See a real CVE proved</a></div>
      </div>
      <div class="kpis" id="kpis">${[1, 2, 3].map(() => `<div class="kpi"><div class="skeleton" style="width:100%"></div></div>`).join("")}</div>
    </section>
    <div class="runs-on" aria-label="Runs on"><span class="kicker">Runs on</span>
      ${["NVIDIA Nemotron", "Nebius Token Factory", "Tavily", "Docker + AddressSanitizer"].map((x) => `<span class="pill">${x}</span>`).join("")}</div>

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
        <label class="switch"><input id="sandbox" type="checkbox"> Also reproduce in the sandbox</label>
        <span class="muted" style="font-size:13px" id="sandbox-note">Static checks take about 2 minutes. The sandbox (Docker, no network, AddressSanitizer) adds 5 to 15 minutes.</span>
        <input id="passcode" type="password" placeholder="demo passcode (in the Devpost text)" class="hidden">
      </div>
      <div class="examples"><span class="muted" style="font-size:13px">Recorded runs:</span>
        ${EXAMPLES.map((e) => `<a class="ex" href="#/report/${e.mode}/${e.id}"><span class="tag ${e.kind}">${e.kind === "slop" ? "AI slop" : "real CVE"}</span>${esc(e.label)}</a>`).join("")}
      </div>
      ${STATIC ? "" : `<div class="examples"><span class="muted" style="font-size:13px">Or run one live:</span>
        <button class="ex" id="try-live" type="button"><span class="tag slop">Go</span>invented gin “memcpy overflow”, about a minute, no passcode</button></div>`}
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
  $("#tour-start").onclick = startTour;
  loadBench().then((b) => {
    const s = b.static.score, fc = b.baseline.factcheck, sb = b.sandbox.score;
    const confirmed = (sb && sb.verdicts.real && sb.verdicts.real.CONFIRMED) || 0;
    const el = $("#kpis");
    if (!el) return;
    el.innerHTML = `
      <div class="kpi"><div class="n ok" data-count="${esc(s.real_wrongly_closed)}">${esc(s.real_wrongly_closed)}</div><div class="l">real CVE reports wrongly closed, out of ${s.reports} public curl reports replayed as of their filing date</div></div>
      <div class="kpi"><div class="n accent" data-count="${confirmed}">${confirmed}</div><div class="l">real CVE${confirmed === 1 ? "" : "s"} reproduced in the sandbox, each with a proof that re-runs from scratch</div></div>
      <div class="kpi"><div class="n bad" data-count="${fc ? `${fc.closes_with_false_reason}/${fc.baseline_closes}` : "–"}">${fc ? `${fc.closes_with_false_reason}/${fc.baseline_closes}` : "–"}</div><div class="l">closes by a plain “is this slop?” model that cite something false. SlopProof cites checked facts.</div></div>`;
    countUp(el);
    const items = [`<b>${esc(s.real_wrongly_closed)}</b> real CVE reports wrongly closed`, `<b>${s.reports}</b> curl reports replayed as of their filing date`,
      `<b>${confirmed}</b> real CVE${confirmed === 1 ? "" : "s"} reproduced and proved`, `<b>${fc ? fc.closes_with_false_reason : "–"}</b> false reasons from a text-only model`,
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

  if ($("#try-live")) $("#try-live").onclick = () => {
    $("#url").value = "";
    $("#sandbox").checked = false;
    syncPass();
    $(".paste").open = true;
    $("#repo").value = LIVE_SAMPLE.repo;
    $("#ptitle").value = LIVE_SAMPLE.title;
    $("#text").value = LIVE_SAMPLE.text;
    $("#form").requestSubmit();
  };

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
      if (/passcode/.test(err.message) && health.sandbox_passcode) $("#passcode").classList.remove("hidden");
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

// Count the first number in each [data-count] element up from zero the first time it scrolls into view.
// data-count holds the final text ("0/148", "$0.065", "100%"); only its first number moves. Reduced motion: shown at once.
function countUp(root = document) {
  const els = $$("[data-count]", root);
  if (!els.length || matchMedia("(prefers-reduced-motion: reduce)").matches || !("IntersectionObserver" in window)) return;
  const parts = (t) => t.match(/^(\D*)(\d+(?:\.\d+)?)(.*)$/s);
  const run = (el) => {
    const m = parts(el.dataset.count), t0 = performance.now(), dur = 900;
    const dec = (m[2].split(".")[1] || "").length, to = Number(m[2]);
    const step = (now) => {
      if (!el.isConnected) return;
      const p = Math.min(1, (now - t0) / dur), e = 1 - (1 - p) ** 3;
      el.textContent = p < 1 ? m[1] + (to * e).toFixed(dec) + m[3] : el.dataset.count;
      if (p < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  };
  const io = new IntersectionObserver((entries) => entries.forEach((x) => {
    if (x.isIntersecting) { io.unobserve(x.target); run(x.target); }
  }), { threshold: 0.4 });
  for (const el of els) {
    const m = parts(el.dataset.count);
    if (!m || Number(m[2]) === 0) continue;
    el.textContent = m[1] + (0).toFixed((m[2].split(".")[1] || "").length) + m[3];
    io.observe(el);
  }
}
