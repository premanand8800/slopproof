"use strict";

// Live runs outside the curl benchmark (kept on the demo server). Reports written by us; see README "Beyond curl".
const BEYOND = [
  { job: "5d238c7e8c3c", project: "psf/requests (Python)", what: "real CVE-2024-35195, written from the public advisory", verdict: "PLAUSIBLE", ok: true,
    note: "Kept open: the code at v2.31.0 (the release the report names) shows the pool reuse it describes." },
  { job: "b31796d9edea", project: "gin-gonic/gin (Go)", what: "invented “heap overflow in Context.Query()”", verdict: "FABRICATED", ok: true,
    note: "parseQueryBuffer() and its memcpy do not exist in gin; Go has no memcpy." },
  { job: "ce0af4d0ca30", project: "expressjs/express (JavaScript)", what: "invented “prototype pollution in res.json()”", verdict: "PLAUSIBLE",
    note: "deepMergeJson() does not exist and res.json() (lib/response.js:236) calls JSON.stringify directly. Still kept open at low priority: a related fix exists, so code reading alone may not close it." },
  { job: "cdc10e0ef32e", project: "fluent/fluent-bit (C, with sandbox)", what: "chunked-parser read past the end", verdict: "PLAUSIBLE",
    note: "Two HTTP/1 callers pass the length without a NUL terminator; the sandbox did not reproduce it." },
];
// Benchmark: headline numbers, SlopProof against the text-only baseline, and every recorded run.

function bar(label, value, max, cls) {
  const pct = max ? Math.round((value / max) * 100) : 0;
  return `<div class="bar"><div class="lbl"><span>${label}</span><b>${value}/${max}</b></div>
    <div class="track"><div class="fill ${cls || ""}" style="width:${pct}%"></div></div></div>`;
}
const frac = (s) => s.split("/").map(Number);
const provedCount = (sb) => (sb && sb.verdicts.real && sb.verdicts.real.CONFIRMED) || 0;

// Head-to-head: SlopProof against the same model asked only "is this slop?". Every number comes from loadBench().
function scoreboard(s, base, fc, sb) {
  const num = (v, cls, sub) => `<div class="sb-cell"><div class="n ${cls || ""}" data-count="${esc(v)}">${esc(v)}</div>${sub ? `<div class="sub">${sub}</div>` : ""}</div>`;
  const txt = (v, sub) => `<div class="sb-cell"><div class="n none">${v}</div>${sub ? `<div class="sub">${sub}</div>` : ""}</div>`;
  const row = (label, hint, ours, theirs) => `<div class="sb-row"><div class="sb-label"><b>${label}</b><span>${hint}</span></div>${ours}${theirs}</div>`;
  const proved = provedCount(sb);
  const sbReal = sb ? frac(sb.real_wrongly_closed)[1] : 0;
  return `<section class="card scoreboard" aria-labelledby="sb-h">
    <div class="kicker">Head to head · same reports, same Nemotron model</div>
    <h2 id="sb-h">SlopProof vs a plain “is this slop?” model</h2>
    <div class="sb-grid">
      <div class="sb-row sb-head"><div></div><div class="us">SlopProof</div><div>Plain model</div></div>
      ${row("Real CVEs wrongly closed", "lower is better", num(s.real_wrongly_closed, "ok"), num(base.real_wrongly_closed))}
      ${row("AI slop closed", "out of the slop reports", num(s.slop_auto_closed, "accent", "each with checked evidence"),
        num(base.slop_auto_closed, "", `${esc(fc.closes_with_false_reason)} of its ${esc(fc.baseline_closes)} closes cite something false`))}
      ${row("Closes citing something false", "checked against the git tree on the report's date", txt("checked", "every close cites evidence checked against the code"),
        num(`${fc.closes_with_false_reason}/${fc.baseline_closes}`, "bad"))}
      ${sb ? row("Real CVEs proved in the sandbox", "reproduced under AddressSanitizer", num(proved, "accent", `of ${sbReal} real CVEs in the sandbox sample`),
        txt("none", "text only, it cannot run anything")) : ""}
    </div></section>`;
}

ROUTES.bench = async () => {
  app.innerHTML = `<div class="page-head"><h1>Benchmark</h1>
    <p>Every public curl HackerOne report we could collect: the reports curl's maintainer lists as AI slop, and the
    reports that became real CVEs. Each one is judged <b>as of the day it was filed</b>: the source tree from that day,
    and web evidence published before it, so later write-ups cannot leak the answer. Scores below are the final run
    (NVIDIA Nemotron on Nebius Token Factory); earlier runs stay in the repository for transparency.</p></div>
    <div class="stats" id="b-stats">${[1, 2, 3, 4].map(() => `<div class="stat"><div class="skeleton"></div></div>`).join("")}</div>
    <div id="b-score"></div>
    <div class="compare" id="b-compare"></div>
    ${STATIC ? "" : `<div class="section-title"><h2>Beyond curl</h2><span class="muted" style="font-size:13px">live runs on other projects and languages</span></div>
    <div class="card" style="padding:16px"><p class="muted" style="margin:0 0 10px;font-size:14px">The benchmark is curl (C). These runs show the same
      pipeline on Python, Go and JavaScript projects. The reports are test reports we wrote: one from a public advisory, two invented
      the way AI slop is. A handful of runs, not a benchmark.</p><div class="facts">${BEYOND.map((r) =>
      fact(r.ok ? "good" : "meh", `<a href="#/run/${r.job}">${esc(r.project)}</a> · ${esc(r.what)} → <span class="vt ${r.verdict}">${r.verdict}</span>`, esc(r.note))).join("")}</div></div>`}
    <div class="section-title"><h2>All reports</h2><span class="muted" id="b-count" style="font-size:13px"></span></div>
    <div class="card" style="padding:16px">
      <div class="table-tools">
        <input type="search" id="b-q" placeholder="Search titles or report numbers">
        <div class="seg" id="b-seg">
          <button data-f="all" class="active">All</button><button data-f="slop">AI slop</button>
          <button data-f="real">Real CVEs</button><button data-f="sandbox">Sandbox runs</button></div>
      </div>
      <div style="overflow-x:auto"><table class="bench"><thead><tr><th>Report</th><th>Ground truth</th><th>SlopProof</th>
        <th class="hide-sm">Text-only baseline</th><th class="hide-sm">Cost</th></tr></thead><tbody id="b-rows"></tbody></table></div>
      <div class="more hidden" id="b-more"><button class="btn small" type="button"></button></div>
    </div>`;

  const b = await loadBench();
  const s = b.static.score, base = b.baseline.score, fc = b.baseline.factcheck, sb = b.sandbox.score;
  $("#b-stats").innerHTML = `
    <div class="stat"><div class="n ok" data-count="${s.real_kept_pct}%">${s.real_kept_pct}%</div><div class="l">of real CVE reports kept open (${esc(s.real_wrongly_closed)} wrongly closed)</div></div>
    <div class="stat"><div class="n accent" data-count="${s.slop_auto_closed_pct}%">${s.slop_auto_closed_pct}%</div><div class="l">of AI-slop reports closed, each with checked evidence (${esc(s.slop_auto_closed)})</div></div>
    <div class="stat"><div class="n" data-count="${esc(s.slop_closed_or_low)}">${esc(s.slop_closed_or_low)}</div><div class="l">slop closed or sent to the bottom of the queue, against ${esc(s.real_closed_or_low)} real reports</div></div>
    <div class="stat"><div class="n" data-count="$${s.avg_usd.toFixed(3)}">$${s.avg_usd.toFixed(3)}</div><div class="l">average cost per report for the static checks, ${s.avg_seconds}s</div></div>`;

  if (base && fc) $("#b-score").innerHTML = scoreboard(s, base, fc, sb);
  countUp(app);

  if (base && fc) {
    const [sc, st] = frac(s.slop_auto_closed), [bc, bt] = frac(base.slop_auto_closed);
    const [sr, srt] = frac(s.real_wrongly_closed), [br, brt] = frac(base.real_wrongly_closed);
    $("#b-compare").innerHTML = `
      <div class="card"><div class="kicker">Why not just ask a model “is this slop?”</div>
        <h2 style="font-size:19px;margin-top:6px">It closes more, for the wrong reasons</h2>
        <p class="muted" style="font-size:14px">Same Nemotron 3 Ultra, same reports, text only. ${fc.closes_with_false_reason} of its
        ${fc.baseline_closes} closing reasons state something false, checked against curl's git tree on the report's date.
        Posting those replies answers slop with slop.</p>
        <div class="bars">
          ${bar("Slop closed: SlopProof", sc, st)}${bar("Slop closed: text-only baseline", bc, bt, "base")}
          ${bar("Baseline closes with a false reason", fc.closes_with_false_reason, fc.baseline_closes, "bad")}
          ${bar("Real CVEs wrongly closed: SlopProof", sr, srt)}${bar("Real CVEs wrongly closed: baseline", br, brt, "base")}
        </div>
        <div class="legend"><span><i style="background:var(--accent)"></i>SlopProof</span><span><i style="background:var(--muted)"></i>Text-only baseline</span><span><i style="background:var(--bad)"></i>False reasons</span></div>
      </div>
      <div class="card"><div class="kicker">The baseline's false statements</div>
        <div class="facts" style="max-height:360px;overflow:auto">${fc.claims.map((c) => fact("bad",
          `#${esc(c.id)}: “${esc(c.baseline_said)}”`, `Fact: ${esc(c.fact)}`)).join("")}</div>
        ${sb ? `<p class="muted" style="font-size:13px;margin-top:14px">Sandbox sample: ${esc(sb.slop_auto_closed)} slop closed with a run,
          ${esc(sb.real_wrongly_closed)} real wrongly closed, ${provedCount(sb)} real CVE${provedCount(sb) === 1 ? "" : "s"} reproduced.</p>` : ""}
      </div>`;
  }

  const sandboxIds = new Set(b.sandbox.rows.map((r) => r.id));
  const baseOf = Object.fromEntries(b.baseline.rows.map((r) => [r.id, r.verdict === "FABRICATED" ? "close" : "keep"]));
  const sandboxRow = Object.fromEntries(b.sandbox.rows.map((r) => [r.id, r]));
  let filter = "all", limit = 25;
  const draw = () => {
    const q = $("#b-q").value.trim().toLowerCase();
    const rows = b.static.rows.filter((r) => (filter === "all" || (filter === "sandbox" ? sandboxIds.has(r.id) : r.label === filter))
      && (!q || r.title.toLowerCase().includes(q) || r.id.includes(q))).sort((x, y) => y.created_at.localeCompare(x.created_at));
    $("#b-count").textContent = `${rows.length} reports · open one to see every step`;
    const more = $("#b-more");
    more.classList.toggle("hidden", rows.length <= limit);
    $("button", more).textContent = `Show all ${rows.length} reports`;
    $("#b-rows").innerHTML = rows.slice(0, limit).map((r) => {
      const sbr = sandboxRow[r.id];
      const v = sbr ? sbr.verdict : r.verdict;
      return `<tr data-href="#/report/${sbr ? "sandbox" : "static"}/${esc(r.id)}">
        <td><div>${esc(r.title)}</div><div class="muted mono" style="font-size:12px">#${esc(r.id)} · ${esc(r.created_at.slice(0, 10))}${sbr ? " · sandbox run" : ""}</div></td>
        <td><span class="tag ${esc(r.label)}">${r.label === "slop" ? "AI slop" : "real CVE"}</span></td>
        <td><span class="vt ${esc(v)}">${esc(v)}</span>${(sbr || r).priority === "low" ? '<div class="muted" style="font-size:12px">low priority</div>' : ""}</td>
        <td class="hide-sm muted">${baseOf[r.id] || "–"}</td><td class="hide-sm mono">$${(sbr || r).usd.toFixed(3)}</td></tr>`;
    }).join("");
  };
  $("#b-q").oninput = () => { limit = 25; draw(); };
  $("#b-more").onclick = () => { limit = Infinity; draw(); };
  $("#b-seg").onclick = (e) => {
    const btn = e.target.closest("button");
    if (!btn) return;
    filter = btn.dataset.f;
    limit = 25;
    $$("#b-seg button").forEach((x) => x.classList.toggle("active", x === btn));
    draw();
  };
  $("#b-rows").onclick = (e) => { const tr = e.target.closest("tr"); if (tr) location.hash = tr.dataset.href; };
  draw();
};
