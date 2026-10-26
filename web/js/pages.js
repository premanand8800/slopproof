"use strict";
// Proof bundles and How it works. Loaded last: it starts the router.

const EXAMPLE_BUNDLE = "curl-3735184-netrc";

function verifyFacts(v) {
  const row = (r, label) => r ? fact(r.bug_present ? "bad" : "good",
    `${label} <code>${esc(r.commit.slice(0, 12))}</code>: <b>${r.bug_present ? "bug present" : r.built ? "bug absent" : "build failed"}</b>`,
    `built and checked in a fresh sandbox in ${r.seconds}s`) : "";
  return fact((v.verdict || "").startsWith("VERIFIED") ? "good" : "bad", `<b>${esc(v.verdict)}</b>`) +
    row(v.at_commit, "Reported commit") + row(v.at_against, "Fix commit");
}

ROUTES.proof = async () => {
  app.innerHTML = `<div class="page-head"><h1>Proof bundles</h1>
    <p>Slop costs nothing to write and hours to disprove. A <b>proof bundle</b> flips that: it pins the project commit,
    the test files and one check command that exits 0 only while the bug is present. Anyone can re-run it in a fresh
    sandbox in about two minutes, and <b>no AI is involved in verifying it</b>. SlopProof writes one for every bug it
    reproduces, and a report only counts as CONFIRMED if its bundle passes again from scratch.</p></div>
    <div class="proof-grid" id="p-grid"><div class="card"><div class="skeleton"></div></div><div class="card"><div class="skeleton"></div></div></div>`;
  const [b, v] = await Promise.all([getJSON(exampleUrl(EXAMPLE_BUNDLE)), getJSON(exampleUrl(EXAMPLE_BUNDLE + ".verification"))]);
  const files = Object.entries(b.files).map(([p, c]) => `<details style="margin-top:8px"><summary><code>${esc(p)}</code>
    <span class="muted">${c.length} bytes</span></summary><pre class="file">${esc(c)}</pre></details>`).join("");
  $("#p-grid").innerHTML = `
    <div class="card"><div class="kicker">Example: real CVE-2026-8926 · HackerOne #3735184</div>
      <h2 style="font-size:20px;margin-top:8px">${esc(b.claim)}</h2>
      <div class="facts">
        ${fact("meh", `Commit <code>${esc(b.commit.slice(0, 12))}</code> of <a href="${esc(b.repo)}" target="_blank" rel="noopener">${esc(b.repo)}</a>`, `bundle <code>sha256:${esc(b.sha256.slice(0, 16))}</code>`)}
        ${fact("meh", "Check command, exits 0 only while the bug is present", `<code>${esc(b.check)}</code>`)}
      </div>${files}
      <div class="row wrap" style="margin-top:16px"><button class="btn" id="p-dl">Download bundle</button>
        <span class="muted" style="font-size:13px">Re-run locally: <code>slopproof verify bundle.json --against ${esc(v.at_against.commit.slice(0, 12))}</code></span></div>
    </div>
    <div class="card"><div class="kicker">Recorded verification</div><div class="facts">${verifyFacts(v)}</div>
      ${STATIC ? "" : `<div class="kicker" style="margin-top:22px">Re-run it live</div>
        <p class="muted" style="font-size:13px;margin:6px 0 10px">Builds curl twice in fresh sandboxes (the reported commit and the fix), about 4 minutes.
        It runs code on this host, so it needs the demo passcode.</p>
        <div class="row"><input id="p-pass" type="password" placeholder="demo passcode" style="max-width:200px;height:40px">
          <button class="btn primary" id="p-run">Re-run live</button></div>
        <div class="term hidden" id="p-term"></div><div id="p-result"></div>`}
    </div>`;
  $("#p-dl").onclick = () => download(`${EXAMPLE_BUNDLE}.json`, b);
  if (STATIC) return;
  let es = null;
  $("#p-run").onclick = async () => {
    const term = $("#p-term"), btn = $("#p-run");
    term.classList.remove("hidden");
    term.textContent = "Starting a fresh sandbox…\n";
    $("#p-result").innerHTML = "";
    btn.disabled = true;
    const r = await fetch(`/api/examples/${EXAMPLE_BUNDLE}/verify?passcode=${encodeURIComponent($("#p-pass").value)}`, { method: "POST" });
    const j = await r.json();
    if (!r.ok) { term.textContent += `${j.detail || "Failed."}\n`; btn.disabled = false; return; }
    const t0 = Date.now();
    es = new EventSource(`/api/jobs/${j.job}/events`);
    es.onmessage = (m) => {
      const ev = JSON.parse(m.data);
      const at = fmtClock((Date.now() - t0) / 1000);
      if (ev.stage === "verify") term.textContent += `[${at}] ${ev.message}\n`;
      if (ev.stage === "verified") $("#p-result").innerHTML = `<div class="facts" style="margin-top:12px">${verifyFacts(ev.result)}</div>`;
      if (ev.stage === "error") term.textContent += `error: ${ev.message}\n`;
      if (ev.stage === "done" || ev.stage === "error") { es.close(); btn.disabled = false; }
    };
  };
  return () => es && es.close();
};

ROUTES.memory = async () => {
  app.innerHTML = `<div class="page-head"><h1>Memory</h1>
    <p>What SlopProof remembers across runs, modelled on how people remember, with the safeguards triage needs.
    Every item says where it came from. Nothing a reporter wrote is stored; items are kept only after a hard check
    (a build that worked, a code line that exists, a proof that re-ran); facts are pinned to the exact file version
    and turn <b>stale</b> when the code changes. Memory steers where to look and how to build. It never decides a
    verdict, and benchmark runs do not use it.</p></div><div id="m-body"><div class="card"><div class="skeleton"></div></div></div>`;
  if (STATIC) { $("#m-body").innerHTML = `<div class="card muted">Memory lives on the server that runs triage; this static copy has none.</div>`; return; }
  const m = await getJSON("/api/memory");
  const section = (title, rows, render, empty) => `<div class="section-title"><h2>${title}</h2><span class="muted" style="font-size:13px">${rows.length}</span></div>
    <div class="card" style="padding:16px">${rows.length ? `<div class="facts" style="margin-top:0">${rows.map(render).join("")}</div>` : `<p class="muted" style="margin:0">${empty}</p>`}</div>`;
  $("#m-body").innerHTML = `<p class="muted">Mode: <b>${esc(m.mode)}</b></p>` +
    section("Skills (procedures that worked)", m.skills, (s) => fact("good", `<b>${esc(s.project)}</b> · ${esc(s.kind)}: ${esc(s.title)}`,
      `<pre style="font-size:12px;margin-top:4px">${esc(s.body)}</pre>worked ${s.successes}× · failed ${s.failures}× · source: ${esc(s.source)}`), "No skills yet: a build or proof has to succeed first.") +
    section("Facts (pinned to code)", m.facts, (f) => fact("meh", `<b>${esc(f.project)}</b> · <code>${esc(f.subject)}</code>`,
      `${esc(f.text)}<br>file ${esc(f.file)} @ blob ${esc((f.blob || "").slice(0, 10))} · used ${f.uses}× · source: ${esc(f.source)}`), "No facts yet.") +
    section("Lessons (from reviews and maintainers)", m.lessons, (x) => fact("meh", esc(x.text),
      `${esc(x.project)} · triggers: ${esc(x.trigger)} · from ${esc(x.source)} · used ${x.uses}×<br>${esc(x.evidence)}`), "No lessons yet.") +
    section("Episodes (runs remembered)", m.episodes, (e) => fact("meh", `<b>${esc(e.project)}</b> · ${esc(e.title)}`,
      `${esc(e.verdict)} · sandbox: ${esc(e.repro || "not run")} · ${e.steps} commands · $${(e.cost || 0).toFixed(3)} · ${ago(e.ts)}`), "No runs remembered yet.");
};

ROUTES.how = () => {
  app.innerHTML = `<div class="page-head"><h1>How it works</h1>
    <p>Writing style is never evidence: many real curl CVEs in 2026 were found with AI tools. SlopProof asks whether a
    report is <b>true</b>, and answers with facts a maintainer can check.</p></div>
    <ol class="pipeline">
      <li><div><b>Extract every checkable claim</b><span>Files, functions, line numbers, quoted code, CVEs, URLs and the attack surface. Nemotron 3.5 Lightning.</span></div></li>
      <li><div><b>Check claims against the real code</b><span>The git tree as of the report's date. Quoted code is matched line by line, with a diff and git history, so code from an older version is not called invented.</span></div></li>
      <li><div><b>Find the code the report is about</b><span>tree-sitter splits the project into functions and BM25 ranks them, even when a report names no file. Measured on 139 real CVEs: a fixed function is in the top 5 for 104.</span></div></li>
      <li><div><b>Check references and prior art</b><span>Tavily search and extract, judged by Nemotron 3 Super. Web search stops at the report's date when replaying the benchmark.</span></div></li>
      <li><div><b>Text screen</b><span>One Nemotron 3 Ultra call reads only the wording. It can vote, never decide, and its reasons are never shown as evidence.</span></div></li>
      <li><div><b>Static analysis and project policy</b><span>Nemotron 3 Ultra reads the real code and traces sizes, bounds and ownership. The project's own security policy is quoted for the maintainer.</span></div></li>
      <li><div><b>Reproduce in a sandbox</b><span>A Nemotron 3 Ultra agent builds the project with AddressSanitizer in Docker (no network, read-only root, all capabilities dropped) and triggers the bug through the real attack surface.</span></div></li>
      <li><div><b>Prove it</b><span>A reproduction becomes a proof bundle and is re-run from scratch in a fresh sandbox. Only then can a report be CONFIRMED.</span></div></li>
      <li><div><b>Verdict and reply</b><span>CONFIRMED, PLAUSIBLE, NOT_REPRODUCED or FABRICATED, with findings that cite file:line or a source, and a reply ready to post.</span></div></li>
    </ol>
    <div class="section-title"><h2>Rules the code enforces</h2></div>
    <div class="rules">
      <div class="card"><b>Doubt never closes a report</b><p>Closing needs the verdict model plus a second, independent signal. Anything else stays PLAUSIBLE.</p></div>
      <div class="card"><b>CONFIRMED needs a proof that re-runs</b><p>The test must run the project's own code, show an impact over intended use, and pass again in a fresh sandbox.</p></div>
      <div class="card"><b>A buggy test proves nothing</b><p>A test that overflows its own buffer, or copies the project's logic into its own program, does not count.</p></div>
      <div class="card"><b>Every number is reproducible</b><p>The benchmark, the baseline and its fact-check, and code search are scripts in the repository.</p></div>
    </div>
    <p style="margin-top:22px"><a class="btn" href="${GITHUB}" target="_blank" rel="noopener">Read the source on GitHub</a></p>`;
};

route();
