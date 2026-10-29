"use strict";
// Proof bundles and How it works. Loaded last: it starts the router.

// Shipped proof bundles of real bugs the sandbox agent reproduced (two curl CVEs, one mxml bug). Each has a
// recorded verification at the reported commit and at the project's fix.
const BUNDLES = [
  { name: "curl-3735184-netrc", report: "3735184", cve: "CVE-2026-8926", short: ".netrc password leak", fix: true,
    title: "curl sends the .netrc password of user alice when the URL names user bob" },
  { name: "curl-4041053-effective-url", report: "4041053", cve: "CVE-2026-94266", short: "password in effective URL",
    title: "curl returns the URL with the password still in it from CURLINFO_EFFECTIVE_URL" },
  { name: "mxml-362-sax-double-free", project: "mxml", cve: "mxml #362", short: "SAX double free (not curl)",
    source: "GitHub issue michaelrsweet/mxml#362", run: "#/run/9ea2afb293b9",
    title: "mxml frees the root node twice when a SAX callback stops at its closing tag" },
];

// The recorded (or live) verification as a seal plus one result card per commit.
function verifySeal(v) {
  const card = (r, label, want) => {
    if (!r) return "";
    const state = !r.built ? "build failed" : r.bug_present ? "bug present" : "bug gone";
    const ok = r.built && r.bug_present === want;
    const exit = r.exit_code == null ? "" : `check exit ${esc(r.exit_code)}${r.exit_code !== 0 ? " (non-zero)" : ""}`;
    return `<div class="vres ${!r.built ? "fail" : r.bug_present ? "present" : "gone"}">
      <div class="vres-head"><span>${label}</span><code>${esc((r.commit || "").slice(0, 12))}</code></div>
      <div class="vres-state">${r.bug_present ? "✗" : r.built ? "✓" : "!"} ${state}</div>
      <div class="vres-sub">${exit}${exit && r.seconds != null ? " · " : ""}${r.seconds != null ? `${esc(r.seconds)}s in a fresh sandbox` : ""}</div>
      <div class="vres-exp">${ok ? "as expected" : "not as expected"}</div></div>`;
  };
  const sealed = v.verdict === "VERIFIED_AND_FIXED";
  return (sealed ? `<div class="seal" title="Re-verified from scratch by a check command, with no model involved">
      <svg viewBox="0 0 24 24" width="22" height="22" aria-hidden="true"><path d="M12 2 3 6v6c0 5 3.8 9.3 9 10 5.2-.7 9-5 9-10V6l-9-4Z" fill="currentColor" opacity=".18"/><path d="M12 2 3 6v6c0 5 3.8 9.3 9 10 5.2-.7 9-5 9-10V6l-9-4Z" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="m8.5 12.2 2.4 2.4 4.6-5" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
      <span><b>VERIFIED_AND_FIXED</b><small>no AI in the loop</small></span></div>`
    : `<div class="facts">${fact((v.verdict || "").startsWith("VERIFIED") ? "good" : "bad", `<b>${esc(v.verdict || "no verdict")}</b>`)}</div>`) +
    `<div class="vres-pair">${card(v.at_commit, "Reported commit", true)}${card(v.at_against, "Fix commit", false)}</div>` +
    (v.problems && v.problems.length ? `<div class="facts">${v.problems.map((p) => fact("bad", esc(p))).join("")}</div>` : "");
}

// The fix agent's recorded result for a bundle: its patch, the check re-run with it in a fresh sandbox, curl's own
// related tests before and after, and the comparison with curl's fix (made only after the agent finished).
function diffHtml(patch) {
  return patch.split("\n").filter((l) => !/^(diff --git|index )/.test(l)).map((l) => {
    const cls = l.startsWith("+++") || l.startsWith("---") ? "dh" : l.startsWith("@@") ? "dh" : l[0] === "+" ? "da" : l[0] === "-" ? "dd" : "";
    return cls ? `<span class="${cls}">${esc(l)}</span>` : esc(l);
  }).join("\n");
}

function fixCard(f) {
  const t = f.tests || {}, after = t.after || {}, before = t.before || {};
  const gone = f.verification && f.verification.built && !f.verification.bug_present;
  const testsOk = t.ids && t.ids.length && !(t.new_failures || []).length && after.ok === after.total;
  const proven = f.verdict === "FIX_VERIFIED" && gone && testsOk;
  const c = f.comparison || {};
  const added = (f.patch.match(/^\+(?!\+\+)/gm) || []).length, removed = (f.patch.match(/^-(?!--)/gm) || []).length;
  const yn = (b) => (b ? "yes" : "no");
  const head = proven
    ? `<div class="seal" title="Checked from scratch with no model involved: the bundle's check and curl's own tests">
      <svg viewBox="0 0 24 24" width="22" height="22" aria-hidden="true"><path d="M12 2 3 6v6c0 5 3.8 9.3 9 10 5.2-.7 9-5 9-10V6l-9-4Z" fill="currentColor" opacity=".18"/><path d="M12 2 3 6v6c0 5 3.8 9.3 9 10 5.2-.7 9-5 9-10V6l-9-4Z" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="m8.5 12.2 2.4 2.4 4.6-5" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
      <span><b>FIX_VERIFIED</b><small>bug gone · curl tests pass</small></span></div>`
    : `<div class="facts">${fact("bad", `<b>${esc(f.verdict)}</b>`, (t.new_failures || []).length ? `breaks curl tests ${esc(t.new_failures.join(", "))} that passed before` : "")}</div>`;
  return `<div class="card fix-card"><div class="kicker">Agent-written fix · checked end to end</div>
    <h2 style="font-size:20px;margin-top:8px">${proven ? "Bug proved, patch written, bug gone, curl's own tests still pass" : "The agent's patch did not pass every check"}</h2>
    <p class="muted" style="font-size:13px;margin:6px 0 0">A Nemotron 3 Ultra agent wrote this patch (+${added} −${removed} lines) in the sandbox where the bug reproduces,
    running the bug check and curl's related tests inside its own loop. Its word is not taken: the patch is applied in a fresh sandbox,
    the bundle's check is re-run, and curl's tests run before and after, each in a fresh build. curl's own fix was never shown to it.</p>
    ${head}
    <div class="vres-pair">
      <div class="vres ${gone ? "gone" : "present"}"><div class="vres-head"><span>Check with the patch</span><code>${esc((f.verification?.commit || "").slice(0, 12))}</code></div>
        <div class="vres-state">${gone ? "✓ bug gone with patch" : "✗ bug still present"}</div>
        <div class="vres-sub">check exit ${esc(f.verification?.exit_code)} · ${esc(f.verification?.seconds)}s in a fresh sandbox</div></div>
      <div class="vres ${testsOk ? "gone" : "present"}"><div class="vres-head"><span>curl's related tests</span><code>${esc((t.ids || []).length)} tests</code></div>
        <div class="vres-state">${testsOk ? "✓" : "✗"} ${esc(after.ok)}/${esc(after.total)} pass</div>
        <div class="vres-sub">${esc(before.ok)}/${esc(before.total)} before the patch · fresh build each</div></div>
    </div>
    <details style="margin-top:12px" open><summary><b>The patch</b> <span class="muted">${esc(f.steps)} agent steps · ${esc(f.agent_seconds ?? f.seconds)}s${f.cost ? ` · $${esc(f.cost.total_usd.toFixed(2))}` : ""}</span></summary>
      <pre class="file diff">${diffHtml(f.patch)}</pre></details>
    ${f.comparison ? `<div class="kicker" style="margin-top:16px">Compared with curl's fix <code>${esc((f.upstream_fix || "").slice(0, 12))}</code>, after the agent finished</div>
    <div class="facts">
      ${fact(c.same_root_cause ? "good" : "meh", `Same root cause: <b>${yn(c.same_root_cause)}</b> · same location: <b>${yn(c.same_location)}</b>${c.same_behaviour_for_reported_bug != null ? ` · same behaviour for the reported bug: <b>${yn(c.same_behaviour_for_reported_bug)}</b>` : ""}`, esc(c.summary))}
      ${c.upstream_extra ? fact("meh", "curl's fix also changes", esc(c.upstream_extra)) : ""}
      ${fact(/^none/i.test(c.agent_patch_risks || "") ? "good" : "bad", "Gaps in the agent's patch for this bug", esc(c.agent_patch_risks))}
    </div>` : ""}
    <details style="margin-top:8px"><summary class="muted">Related tests run</summary><p class="muted" style="font-size:13px">${esc((t.ids || []).join(" "))}</p></details>
  </div>`;
}

ROUTES.proof = async (parts) => {
  const ex = BUNDLES.find((x) => x.name === parts[0]) || BUNDLES[0];
  app.innerHTML = `<div class="page-head"><h1>Proof bundles</h1>
    <p>Slop costs nothing to write and hours to disprove. A <b>proof bundle</b> flips that: it pins the project commit,
    the test files and one check command that exits 0 only while the bug is present. Anyone can re-run it in a fresh
    sandbox in about two minutes, and <b>no AI is involved in verifying it</b>. SlopProof writes one for every bug it
    reproduces, and a report only counts as CONFIRMED if its bundle passes again from scratch.</p></div>
    <div class="seg" role="tablist" style="margin-top:18px">${BUNDLES.map((x) => `<button role="tab" class="${x === ex ? "active" : ""}" data-n="${x.name}">${esc(x.cve)} · ${esc(x.short)}</button>`).join("")}</div>
    <div class="proof-grid" id="p-grid"><div class="card"><div class="skeleton"></div></div><div class="card"><div class="skeleton"></div></div></div>
    <div id="p-fix"></div>`;
  $$(".seg button", app).forEach((btn) => { btn.onclick = () => { location.hash = `#/proof/${btn.dataset.n}`; }; });
  const [b, v, fx] = await Promise.all([getJSON(exampleUrl(ex.name)), getJSON(exampleUrl(ex.name + ".verification")),
    ex.fix ? getJSON(exampleUrl(ex.name + ".fix")).catch(() => null) : null]);
  const cmd = v.command || `slopproof verify ${ex.name}.json --against ${v.at_against ? v.at_against.commit : ""}`;
  const files = Object.entries(b.files).map(([p, c]) => `<details style="margin-top:8px"><summary><code>${esc(p)}</code>
    <span class="muted">${c.length} bytes</span></summary><pre class="file">${esc(c)}</pre></details>`).join("");
  $("#p-grid").innerHTML = `
    <div class="card"><div class="kicker">Real ${esc(ex.cve)} · ${esc(ex.source || `HackerOne #${ex.report}`)}</div>
      <h2 style="font-size:20px;margin-top:8px">${esc(ex.title)}</h2>
      <div class="row wrap" style="margin-top:6px;font-size:13px"><a href="${esc(ex.run || `#/report/sandbox/${ex.report}`)}">See the triage run that wrote it →</a></div>
      <div class="facts">
        ${fact("meh", `Commit <code>${esc(b.commit.slice(0, 12))}</code> of <a href="${esc(b.repo)}" target="_blank" rel="noopener">${esc(b.repo)}</a>`, `bundle <code>sha256:${esc(b.sha256.slice(0, 16))}</code>`)}
        ${fact("meh", "Check command, exits 0 only while the bug is present", `<code>${esc(b.check)}</code>`)}
      </div>${files}
      <details style="margin-top:8px"><summary class="muted">The agent's claim, as sealed in the bundle</summary><pre class="file">${esc(b.claim)}</pre></details>
      <div class="row wrap" style="margin-top:16px"><button class="btn" id="p-dl">Download bundle</button></div>
    </div>
    <div class="card"><div class="kicker">Recorded verification</div>${verifySeal(v)}
      <div class="kicker" style="margin-top:20px">Re-run it yourself</div>
      <div class="cmd"><code id="p-cmd">${esc(cmd)}</code><button class="btn small" id="p-copy" aria-label="Copy the re-run command">Copy</button></div>
      ${STATIC ? "" : `<div class="kicker" style="margin-top:22px">Re-run it live</div>
        <p class="muted" style="font-size:13px;margin:6px 0 10px">Builds ${esc(ex.project || "curl")} twice in fresh sandboxes (the reported commit and the fix), ${ex.project === "mxml" ? "under a minute" : "about 4 minutes"}.
        No passcode: the commands are the ones in the bundle above. If someone just ran it, you see that run.</p>
        <div class="row"><button class="btn primary" id="p-run">Re-run live</button></div>
        <div class="term hidden" id="p-term"></div><div id="p-result"></div>`}
    </div>`;
  if (fx && fx.patch) $("#p-fix").innerHTML = fixCard(fx);
  $("#p-dl").onclick = () => download(`${ex.name}.json`, b);
  $("#p-copy").onclick = () => copyText(cmd);
  if (STATIC) return;
  let es = null;
  $("#p-run").onclick = async () => {
    const term = $("#p-term"), btn = $("#p-run");
    term.classList.remove("hidden");
    term.textContent = "Starting a fresh sandbox…\n";
    $("#p-result").innerHTML = "";
    btn.disabled = true;
    const r = await fetch(`/api/examples/${ex.name}/verify`, { method: "POST" });
    const j = await r.json();
    if (!r.ok) { term.textContent += `${j.detail || "Failed."}\n`; btn.disabled = false; return; }
    if (j.joined) term.textContent = "Showing the re-run started in the last few minutes.\n";
    const t0 = Date.now();
    es = new EventSource(`/api/jobs/${j.job}/events`);
    es.onmessage = (m) => {
      const ev = JSON.parse(m.data);
      const at = fmtClock((Date.now() - t0) / 1000);
      if (ev.stage === "verify") term.textContent += `[${at}] ${ev.message}\n`;
      if (ev.stage === "verified") $("#p-result").innerHTML = `<div style="margin-top:12px">${verifySeal(ev.result)}</div>`;
      if (ev.stage === "error") term.textContent += `error: ${ev.message}\n`;
      if (ev.stage === "done" || ev.stage === "error") { es.close(); btn.disabled = false; }
    };
  };
  return () => es && es.close();
};


// ---- Memory page graphs (inline SVG, theme tokens only) ----
// Animated memory tree: real projects/facts/skills/lessons from the API, with a scripted (replay) story over them.
function memTree(host, m) {
  const short = (t, n) => ((t = String(t || "")).length > n ? t.slice(0, n - 1) + "…" : t);
  const reduce = window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches;
  const pj = {};
  const P = (k) => (pj[k] = pj[k] || { name: k, items: [], verdict: null });
  m.skills.forEach((x) => P(x.project).items.push({ type: "skill", label: `skill: ${x.kind} recipe`, src: x.source }));
  m.facts.forEach((x) => P(x.project).items.push({ type: "fact", label: `fact: ${x.file || x.subject}`, src: x.source, f: x }));
  m.lessons.forEach((x) => P(x.project === "*" ? "all projects" : x.project).items.push({ type: "lesson", label: `lesson: ${(x.trigger || "review").split(",")[0]}`, src: x.source }));
  m.episodes.forEach((e) => { const o = P(e.project); if (!o.verdict) o.verdict = e.verdict; });
  const names = Object.keys(pj);
  if (!names.length) { host.innerHTML = `<p class="muted" style="margin:0">Nothing stored yet: memory starts empty and grows after the first hard check passes.</p>`; return; }
  const score = (p) => (p.items.some((i) => i.type === "skill") ? 2 : 0) + (p.items.some((i) => i.type === "fact") ? 2 : 0) + (p.verdict ? 1 : 0);
  const story = pj[names.slice().sort((a, b) => score(pj[b]) - score(pj[a]))[0]];
  // the story's newest fact is held back and "created" at step 3
  const fi = story.items.map((i) => i.type).lastIndexOf("fact");
  const made = fi >= 0 ? story.items.splice(fi, 1)[0]
    : { type: "fact", label: "fact: parser.c", src: "code (model reading)", f: { file: "parser.c", blob: "a1b2c3d4e5f6" } };
  const blob7 = (made.f.blob || "").slice(0, 7), mfile = made.f.file || "file";
  const others = names.filter((n) => pj[n] !== story).sort((a, b) => pj[b].items.length - pj[a].items.length).slice(0, 4).map((n) => pj[n]);
  const hidden = names.length - 1 - others.length;
  const order = [...others, story];
  let y = 22;
  order.forEach((p) => {
    const uniq = []; const t = new Set();
    p.items.forEach((i) => { if (!t.has(i.type)) { t.add(i.type); uniq.push(i); } });
    p.shown = [...uniq, ...p.items.filter((i) => !uniq.includes(i))].slice(0, 2);
    p.more = p.items.length - p.shown.length;
    const rows = p.shown.length + (p.more ? 1 : 0) + (p === story ? 1 : 0);
    const h = Math.max(rows * 28, 36);
    p.top = y + (h - rows * 28) / 2; p.cy = y + h / 2; y += h + 12;
  });
  const H = Math.round(y + 44), W = 760, rootY = order.reduce((a, p) => a + p.cy, 0) / order.length;
  const curve = (x1, y1, x2, y2) => `M${x1} ${y1} C${(x1 + x2) / 2} ${y1} ${(x1 + x2) / 2} ${y2} ${x2} ${y2}`;
  const leafY = (p, i) => p.top + i * 28 + 14;
  let g = "";
  order.forEach((p) => {
    g += `<path class="edge f1" pathLength="1" d="${curve(80, rootY, 150, p.cy)}"><title>${esc(p.name)} branch</title></path>`;
    p.shown.forEach((it, i) => {
      const ly = leafY(p, i);
      g += `<path class="edge f1${p === story ? " rec" : ""}" pathLength="1" d="${curve(300, p.cy, 353, ly)}"/>
        <g transform="translate(360 ${ly})"><g class="nd f1"><circle r="7" class="t-${it.type}"><title>${esc(it.label)} (source: ${esc(it.src)})</title></circle>
        <text x="14" y="4" font-size="12">${esc(short(it.label, 26))}</text></g></g>`;
    });
    if (p.more) g += `<text class="mu fd f1" x="374" y="${leafY(p, p.shown.length + (p === story ? 1 : 0)) + 4}" font-size="11">+${p.more} more</text>`;
    g += `<g transform="translate(150 ${p.cy - 14})"><g class="nd f1">${p === story ? `<rect class="ring" width="150" height="28" rx="14"/>` : ""}
      <rect class="pill${p === story ? " sp" : ""}" width="150" height="28" rx="14"><title>${esc(p.name)}</title></rect><text x="75" y="18" text-anchor="middle" font-size="12" font-weight="600">${esc(short(p.name, 20))}</text></g></g>`;
  });
  const my = leafY(story, story.shown.length);
  g += `<g transform="translate(50 ${rootY})"><circle r="30" class="root"/><text text-anchor="middle" y="4" class="rt" font-size="12" font-weight="700">Memory</text></g>`;
  // step 2: report + recall
  const ry = story.cy + 28;
  g += `<path class="edge f2 rep" pathLength="1" d="${curve(98, ry, 150, story.cy + 6)}"/>
    <g transform="translate(8 ${ry - 13})"><g class="nd f2"><rect class="rpt" width="90" height="26" rx="8"/><text x="45" y="17" text-anchor="middle" font-size="12" font-weight="600">Report</text></g></g>
    <text class="mu fd f2" x="8" y="${ry + 26}" font-size="10.5">replay, then recall</text>`;
  // step 3: new leaf, with its source and pin
  g += `<path class="edge f3 newe" pathLength="1" d="${curve(300, story.cy, 353, my)}"/>
    <g transform="translate(360 ${my})" class="storyleaf"><g class="nd f3"><circle r="9" class="t-fact"><title>new ${esc(made.label)} (source: ${esc(made.src)})</title></circle><circle r="13" class="halo"/></g>
    <text class="fd f3" x="18" y="-2" font-size="12" font-weight="600">${esc(short(made.label, 24))}</text>
    <text class="mu fd f3 pin" x="18" y="12" font-size="10.5">from ${esc(short(made.src, 16))} · pin @${esc(blob7)}</text>
    <text class="fd f4 stl" x="18" y="12" font-size="10.5">STALE: ${esc(short(mfile, 14))} changed</text></g>`;
  // step 5: barrier + verdict
  g += `<line class="fd f5 bar" x1="592" y1="8" x2="592" y2="${H - 8}"/>
    <text class="fd f5 mu" x="604" y="16" font-size="10.5">memory never decides</text>
    <path class="xs fd f5" d="M562 ${my} H586 M586 ${my - 6} L598 ${my + 6} M598 ${my - 6} L586 ${my + 6}"/>
    <g transform="translate(612 ${my - 22})"><g class="nd f5"><rect class="vd" width="140" height="44" rx="10"/><text x="70" y="19" text-anchor="middle" font-size="12" font-weight="700">Verdict</text>
    <text x="70" y="34" text-anchor="middle" font-size="10.5" class="mu">${esc(short(story.verdict ? story.verdict.toLowerCase().replace("_", " ") + ", from evidence" : "decided from evidence", 24))}</text></g></g>`;
  const recalled = story.shown.map((i) => i.label).join(", ") || "nothing yet";
  const cnt = (a) => a.length;
  const caps = [
    `Memory grows one branch per project: ${names.length} projects, ${cnt(m.skills)} skills, ${cnt(m.facts)} facts, ${cnt(m.lessons)} lessons (real data).`,
    `Replay: a report about ${story.name} arrives. Memory recalls what it has: ${recalled}.`,
    `A hard check passes (build worked, code line exists, proof re-ran), so a new fact is stored with its source: ${made.src}.`,
    `The pinned file ${mfile} changes (pin @${blob7} no longer matches). The fact turns stale until a run sees it again.`,
    `The verdict comes from evidence, outside memory. Memory edges stop at the barrier: it never decides.`];
  const desc = "Animated tree. " + caps.join(" ");
  host.innerHTML = `<div class="mt-cap" id="mt-cap" aria-live="polite"></div>
    <div class="mt-scroll"><svg class="tr" viewBox="0 0 ${W} ${H}" role="img" aria-labelledby="mt-t mt-d" data-cur="0"><title id="mt-t">How memory grows and stops short of the verdict</title><desc id="mt-d">${esc(desc)}</desc>${g}</svg></div>
    <div class="mt-ctl"><button class="btn" id="mt-pause" type="button">Pause</button><button class="btn" id="mt-replay" type="button">Replay</button><span class="muted" id="mt-ind"></span>
    <span class="mlegend" style="margin:0 0 0 auto"><span><i class="sw c-fresh"></i>fact</span><span><i class="sw c-skill"></i>skill</span><span><i class="sw c-lesson"></i>lesson</span><span><i class="sw c-stale"></i>stale</span></span></div>
    ${hidden > 0 ? `<p class="muted" style="margin:8px 0 0;font-size:12px">${hidden} more project${hidden > 1 ? "s" : ""} not drawn.</p>` : ""}`;
  const svg = host.querySelector("svg"), cap = $("#mt-cap"), ind = $("#mt-ind"), sc = host.querySelector(".mt-scroll"), pb = $("#mt-pause");
  const D = [900, 4200, 4800, 4800, 4200, 5600];
  let step = 0, timer = null, paused = false;
  const set = (n) => {
    step = n; svg.dataset.cur = n;
    for (let k = 1; k <= 5; k++) svg.classList.toggle("on-" + k, k <= n);
    cap.textContent = n ? caps[n - 1] : "Memory, replayed on real data.";
    ind.textContent = n ? `step ${n} of 5 · replay` : "replay";
    if (!reduce && sc.scrollWidth > sc.clientWidth + 4) sc.scrollTo({ left: n >= 5 ? 9999 : n >= 3 ? 100 : 0, behavior: "smooth" });
  };
  const sched = () => { clearTimeout(timer); timer = setTimeout(() => { if (!svg.isConnected) return; set((step + 1) % 6); sched(); }, D[step]); };
  if (reduce) { set(5); host.querySelector(".mt-ctl button").style.display = "none"; $("#mt-replay").style.display = "none"; ind.textContent = "final state (reduced motion)"; return; }
  pb.onclick = () => { paused = !paused; pb.textContent = paused ? "Play" : "Pause"; paused ? clearTimeout(timer) : sched(); };
  $("#mt-replay").onclick = () => { paused = false; pb.textContent = "Pause"; set(0); sched(); };
  set(0); sched();
}

function memBar(parts, label, max) {
  // parts: [{v, cls, name}] drawn as percentage rects inside one responsive SVG
  const total = max || parts.reduce((a, p) => a + p.v, 0) || 1;
  let x = 0, rects = "";
  for (const p of parts) { if (!p.v) continue; const w = (p.v / total) * 100; rects += `<rect x="${x}%" y="0" width="${w}%" height="100%" class="${p.cls}"><title>${esc(p.name)}: ${p.v}</title></rect>`; x += w; }
  return `<svg class="mbar" role="img" aria-label="${esc(label)}" preserveAspectRatio="none"><title>${esc(label)}</title><rect width="100%" height="100%" class="bg"/>${rects}</svg>`;
}
function memLegend(items) { return `<div class="mlegend">${items.map(([c, n]) => `<span><i class="sw ${c}"></i>${n}</span>`).join("")}</div>`; }

function memCharts(m) {
  const isStale = (f) => f.stale === true || (f.status && f.status !== "active");
  const proj = {};
  const get = (k) => (proj[k] = proj[k] || { skills: 0, fresh: 0, stale: 0, lessons: 0 });
  m.skills.forEach((s) => get(s.project).skills++);
  m.facts.forEach((f) => (isStale(f) ? get(f.project).stale++ : get(f.project).fresh++));
  m.lessons.forEach((l) => get(l.project === "*" ? "all projects" : l.project).lessons++);
  const names = Object.keys(proj).sort((a, b) => (proj[b].skills + proj[b].fresh + proj[b].stale + proj[b].lessons) - (proj[a].skills + proj[a].fresh + proj[a].stale + proj[a].lessons));
  const tot = (p) => p.skills + p.fresh + p.stale + p.lessons;
  const max = Math.max(1, ...names.map((n) => tot(proj[n])));
  const stored = names.length ? `<div class="mchart">${names.map((n) => { const p = proj[n];
    return `<div class="mrw"><div class="ml" title="${esc(n)}">${esc(n)}</div>${memBar([
      { v: p.skills, cls: "c-skill", name: "skills" }, { v: p.fresh, cls: "c-fresh", name: "fresh facts" },
      { v: p.stale, cls: "c-stale", name: "stale facts" }, { v: p.lessons, cls: "c-lesson", name: "lessons" }],
      `${n}: ${p.skills} skills, ${p.fresh} fresh facts, ${p.stale} stale facts, ${p.lessons} lessons`, max)}<div class="mv">${tot(p)}</div></div>`; }).join("")}</div>
    ${memLegend([["c-skill", "skills"], ["c-fresh", "fresh facts"], ["c-stale", "stale facts (file changed)"], ["c-lesson", "lessons"]])}`
    : `<p class="muted" style="margin:0">Nothing stored yet.</p>`;

  const sk = m.skills.slice().sort((a, b) => (b.successes - b.failures) - (a.successes - a.failures));
  const smax = Math.max(1, ...sk.map((s) => Math.max(s.successes, s.failures)));
  const skills = sk.length ? `<div class="mchart">${sk.map((s) => { const lab = `${s.project} · ${s.kind}`;
    const fw = (s.failures / smax) * 50, sw = (s.successes / smax) * 50;
    return `<div class="mrw"><div class="ml" title="${esc(s.title)}">${esc(lab)}</div>
      <svg class="mbar" role="img" aria-label="${esc(`${lab}: worked ${s.successes} times, failed ${s.failures} times`)}" preserveAspectRatio="none"><title>${esc(`${lab}: worked ${s.successes}, failed ${s.failures}`)}</title>
      <rect width="100%" height="100%" class="bg"/><rect x="${50 - fw}%" width="${fw}%" height="100%" class="c-bad"/><rect x="50%" width="${sw}%" height="100%" class="c-fresh"/><rect x="50%" width="1.5" height="100%" class="ax" transform="translate(-.75 0)"/></svg>
      <div class="mv"><span class="bd">${s.failures}</span> / <span class="gd">${s.successes}</span></div></div>`; }).join("")}</div>
    ${memLegend([["c-bad", "failed (left)"], ["c-fresh", "worked (right)"]])}`
    : `<p class="muted" style="margin:0">No skills yet: a build or proof has to succeed first.</p>`;

  const vc = { CONFIRMED: "c-fresh", PLAUSIBLE: "c-stale", NOT_REPRODUCED: "c-skill", FABRICATED: "c-lesson" };
  const ep = {}; m.episodes.forEach((e) => { const o = (ep[e.project] = ep[e.project] || {}); o[e.verdict] = (o[e.verdict] || 0) + 1; });
  const en = Object.keys(ep).sort((a, b) => Object.values(ep[b]).reduce((x, y) => x + y, 0) - Object.values(ep[a]).reduce((x, y) => x + y, 0));
  const emax = Math.max(1, ...en.map((n) => Object.values(ep[n]).reduce((x, y) => x + y, 0)));
  const eps = en.length ? `<div class="mchart">${en.map((n) => { const parts = Object.keys(vc).map((v) => ({ v: ep[n][v] || 0, cls: vc[v], name: v }));
    const t = parts.reduce((a, p) => a + p.v, 0);
    return `<div class="mrw"><div class="ml" title="${esc(n)}">${esc(n)}</div>${memBar(parts, `${n}: ` + parts.filter((p) => p.v).map((p) => `${p.v} ${p.name}`).join(", "), emax)}<div class="mv">${t}</div></div>`; }).join("")}</div>
    ${memLegend(Object.keys(vc).map((v) => [vc[v], v.toLowerCase().replace("_", " ")]))}` : `<p class="muted" style="margin:0">No runs remembered yet.</p>`;

  const card = (t, sub, body) => `<div class="card mcard"><h3>${t}</h3><p class="muted msub">${sub}</p>${body}</div>`;
  return `<div class="section-title"><h2>How memory works</h2></div><div class="card mtcard" id="mtree"></div>
    <div class="section-title"><h2>What is stored</h2></div>
    <div class="mgrid">${card("Stored per project", "Count of items by type. Facts are fresh until the pinned file changes.", stored)}
    ${card("Skills: worked vs failed", "Procedures that worked, ranked by net wins.", skills)}
    ${card("Runs remembered, by verdict", "Each run is kept as an episode, labelled with its verdict.", eps)}</div>`;
}

ROUTES.memory = async () => {
  app.innerHTML = `<div class="page-head"><h1>Memory</h1>
    <p>What SlopProof remembers across runs, modelled on how people remember, with the safeguards triage needs.
    Every item says where it came from. Nothing a reporter wrote is stored; items are kept only after a hard check
    (a build that worked, a code line that exists, a proof that re-ran); facts are pinned to the exact file version
    and turn <b>stale</b> when the code changes. Memory steers where to look and how to build. It never decides a
    verdict, and benchmark runs do not use it.</p></div><div id="m-body"><div class="card"><div class="skeleton"></div></div></div>`;
  if (STATIC) { $("#m-body").innerHTML = `<div class="card muted">Memory lives on the server that runs triage; this static copy has none.</div>`; return; }
  const m = await getJSON("/api/memory");
  const section = (title, rows, render, empty) => `<details class="mdet"><summary><h2>${title}</h2><span class="muted" style="font-size:13px">${rows.length}</span></summary>
    <div class="card" style="padding:16px">${rows.length ? `<div class="facts" style="margin-top:0">${rows.map(render).join("")}</div>` : `<p class="muted" style="margin:0">${empty}</p>`}</div></details>`;
  $("#m-body").innerHTML = `<p class="muted">Mode: <b>${esc(m.mode)}</b></p>` + memCharts(m) + `<div class="section-title"><h2>Details</h2></div>` +
    section("Skills (procedures that worked)", m.skills, (s) => fact("good", `<b>${esc(s.project)}</b> · ${esc(s.kind)}: ${esc(s.title)}`,
      `<pre style="font-size:12px;margin-top:4px">${esc(s.body)}</pre>worked ${s.successes}× · failed ${s.failures}× · source: ${esc(s.source)}`), "No skills yet: a build or proof has to succeed first.") +
    section("Facts (pinned to code)", m.facts, (f) => fact("meh", `<b>${esc(f.project)}</b> · <code>${esc(f.subject)}</code>`,
      `${esc(f.text)}<br>file ${esc(f.file)} @ blob ${esc((f.blob || "").slice(0, 10))} · used ${f.uses}× · source: ${esc(f.source)}`), "No facts yet.") +
    section("Lessons (from reviews and maintainers)", m.lessons, (x) => fact("meh", esc(x.text),
      `${esc(x.project)} · triggers: ${esc(x.trigger)} · from ${esc(x.source)} · used ${x.uses}×<br>${esc(x.evidence)}`), "No lessons yet.") +
    section("Episodes (runs remembered)", m.episodes, (e) => fact("meh", `<b>${esc(e.project)}</b> · ${esc(e.title)}`,
      `${esc(e.verdict)} · sandbox: ${esc(e.repro || "not run")} · ${e.steps} commands · $${(e.cost || 0).toFixed(3)} · ${ago(e.ts)}`), "No runs remembered yet.");
  memTree($("#mtree"), m);
};

ROUTES.how = () => {
  app.innerHTML = `<div class="page-head"><h1>How it works</h1>
    <p>Writing style is never evidence: many real curl CVEs in 2026 were found with AI tools. SlopProof asks whether a
    report is <b>true</b>, and answers with facts a maintainer can check.</p></div>
    <ol class="pipeline">
      <li><div><b>Extract every checkable claim</b><span>Files, functions, line numbers, quoted code, CVEs, URLs and the attack surface. Nemotron 3.5 Lightning.</span></div></li>
      <li><div><b>Check claims against the real code</b><span>The git tree as of the report's date. Quoted code is matched line by line, with a diff and git history, so code from an older version is not called invented.</span></div></li>
      <li><div><b>Find the code the report is about</b><span>tree-sitter splits the project into functions and BM25 ranks them, even when a report names no file. Measured on 139 real CVEs: a fixed function is in the top 5 for 103. It also parses Python, Go, JavaScript and Rust.</span></div></li>
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
