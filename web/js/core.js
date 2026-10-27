"use strict";
// Shared helpers and the hash router. Pages register themselves in ROUTES (see the other files).
// The static build (no server) sets window.SLOPPROOF_STATIC and reads JSON files instead of the API.

const STATIC = window.SLOPPROOF_STATIC === true;
const GITHUB = "https://github.com/premanand8800/slopproof";
const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const app = $("#app");
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);

function fmtClock(s) {
  s = Math.max(0, Math.round(s));
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), x = s % 60;
  const mm = String(m).padStart(h ? 2 : 1, "0"), ss = String(x).padStart(2, "0");
  return h ? `${h}:${mm}:${ss}` : `${mm}:${ss}`;
}
const fmtDur = (s) => (s == null ? "" : s < 60 ? `${Math.max(0, s).toFixed(s < 10 ? 1 : 0)}s` : fmtClock(s));
function ago(ts) {
  const d = Date.now() / 1000 - ts;
  if (d < 60) return "just now";
  if (d < 3600) return `${Math.round(d / 60)} min ago`;
  if (d < 86400) return `${Math.round(d / 3600)} h ago`;
  return `${Math.round(d / 86400)} d ago`;
}

function toast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => t.classList.remove("show"), 2600);
}

async function getJSON(url) {
  const r = await fetch(url);
  if (!r.ok) {
    const j = await r.json().catch(() => ({}));
    throw new Error(j.detail || `${r.status} ${r.statusText}`);
  }
  return r.json();
}

function download(name, obj) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([JSON.stringify(obj, null, 1)], { type: "application/json" }));
  a.download = name;
  a.click();
}

function fact(kind, html, sub) {
  const ic = { good: "✓", bad: "✗", meh: "•" }[kind];
  return `<div class="fact ${kind}"><span class="ic">${ic}</span><div>${html}${sub ? `<div class="sub">${sub}</div>` : ""}</div></div>`;
}
const srcLink = (u) => (u ? ` <a href="${esc(u)}" target="_blank" rel="noopener">source</a>` : "");

// Data sources (API, or JSON files in the static build)
const runUrl = (mode, id) => (STATIC ? `data/runs/${mode}/${id}.json` : `/api/bench/${mode}/${id}`);
const exampleUrl = (name) => (STATIC ? `data/examples/${name}.json` : `/api/examples/${name}`);
let benchCache = null;
const loadBench = async () => (benchCache ||= await getJSON(STATIC ? "data/bench.json" : "/api/bench"));
let healthCache = null;
async function loadHealth() {
  if (STATIC) return { sandbox: false };
  return (healthCache ||= await getJSON("/api/health").catch(() => ({})));
}

// Runs started from this browser, so they can be reopened after a reload
const RECENT_KEY = "slopproof.recent";
function recentRuns() {
  try { return JSON.parse(localStorage.getItem(RECENT_KEY) || "[]"); } catch (e) { return []; }
}
function rememberRun(entry) {
  try {
    const old = recentRuns();
    const prev = old.find((r) => r.id === entry.id) || {};
    const list = [{ ...prev, ...entry }, ...old.filter((r) => r.id !== entry.id)];
    localStorage.setItem(RECENT_KEY, JSON.stringify(list.slice(0, 12)));
  } catch (e) { /* storage unavailable: recent runs are a convenience only */ }
}

// Theme
function toggleTheme() {
  const root = document.documentElement;
  const dark = root.dataset.theme ? root.dataset.theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
  root.dataset.theme = dark ? "light" : "dark";
  try { localStorage.setItem("theme", root.dataset.theme); } catch (e) { /* not persisted */ }
}
$("#theme").onclick = toggleTheme;

// Copy text to the clipboard, with a fallback for browsers that refuse the async API.
async function copyText(text) {
  try { await navigator.clipboard.writeText(text); }
  catch (e) {
    const ta = document.createElement("textarea");
    ta.value = text; ta.setAttribute("readonly", ""); ta.style.cssText = "position:fixed;opacity:0;top:0;left:0";
    document.body.appendChild(ta); ta.select();
    try { document.execCommand("copy"); } catch (e2) { /* nothing more to try */ }
    ta.remove();
  }
  toast("Copied to clipboard");
}

// Command palette: Ctrl/Cmd+K anywhere, "/" when not typing, or the header button.
const palette = { el: null, items: [], shown: [], sel: 0, prev: null, runsLoaded: false };
function paletteBase() {
  const page = (label, hash, hint) => ({ label, hint, kind: "Page", run: () => { location.hash = hash; } });
  return [
    page("Triage", "#/", "check a report"), page("Benchmark", "#/bench", "196 curl reports"),
    page("Proofs", "#/proof", "re-runnable proof bundles"), page("Memory", "#/memory", "what runs remember"),
    page("How it works", "#/how", "the pipeline"),
    { label: "Start the 60-second tour", kind: "Action", hint: "five stops", run: startTour },
    { label: "Toggle dark mode", kind: "Action", hint: "light / dark", run: toggleTheme },
    { label: "Open GitHub repo", kind: "Link", hint: "source, MIT", run: () => window.open(GITHUB, "_blank", "noopener") },
  ];
}
function paletteRender() {
  const q = $("#pal-q").value.trim().toLowerCase();
  palette.shown = palette.items.filter((it) => !q || `${it.label} ${it.hint || ""} ${it.kind}`.toLowerCase().includes(q)).slice(0, 60);
  palette.sel = Math.min(palette.sel, Math.max(0, palette.shown.length - 1));
  const list = $("#pal-list");
  list.innerHTML = palette.shown.length ? palette.shown.map((it, i) => `<li role="option" id="pal-o${i}" data-i="${i}" aria-selected="${i === palette.sel}"
      class="${i === palette.sel ? "sel" : ""}"><span class="pal-kind">${esc(it.kind)}</span><span class="pal-label">${esc(it.label)}</span>
      ${it.hint ? `<span class="pal-hint">${esc(it.hint)}</span>` : ""}</li>`).join("")
    : `<li class="pal-empty">${palette.runsLoaded ? "Nothing matches." : "Nothing matches yet. Loading recorded runs…"}</li>`;
  $("#pal-q").setAttribute("aria-activedescendant", palette.shown.length ? `pal-o${palette.sel}` : "");
  const cur = $(`#pal-o${palette.sel}`);
  if (cur) cur.scrollIntoView({ block: "nearest" });
}
function paletteChoose(i) {
  const it = palette.shown[i];
  if (!it) return;
  closePalette(false);
  it.run();
}
function paletteBuild() {
  const el = document.createElement("div");
  el.className = "pal-back hidden";
  el.innerHTML = `<div class="pal" role="dialog" aria-modal="true" aria-label="Command palette">
    <div class="pal-search"><svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true"><path fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" d="m20 20-4.2-4.2M11 18a7 7 0 1 1 0-14 7 7 0 0 1 0 14Z"/></svg>
      <input id="pal-q" type="text" placeholder="Search pages, actions, runs…" autocomplete="off" spellcheck="false"
        role="combobox" aria-expanded="true" aria-controls="pal-list" aria-label="Search commands">
      <kbd>Esc</kbd></div>
    <ul id="pal-list" role="listbox" aria-label="Results"></ul>
    <div class="pal-foot"><span><kbd>↑</kbd><kbd>↓</kbd> move</span><span><kbd>Enter</kbd> open</span><span><kbd>Esc</kbd> close</span></div></div>`;
  document.body.appendChild(el);
  palette.el = el;
  el.addEventListener("mousedown", (e) => { if (e.target === el) closePalette(); });
  $("#pal-q").addEventListener("input", () => { palette.sel = 0; paletteRender(); });
  $("#pal-list").addEventListener("click", (e) => { const li = e.target.closest("li[data-i]"); if (li) paletteChoose(+li.dataset.i); });
  $("#pal-list").addEventListener("mousemove", (e) => {
    const li = e.target.closest("li[data-i]");
    if (li && +li.dataset.i !== palette.sel) { palette.sel = +li.dataset.i; paletteRender(); }
  });
  el.addEventListener("keydown", (e) => {
    const n = palette.shown.length;
    if (e.key === "Escape") { e.preventDefault(); closePalette(); }
    else if (e.key === "ArrowDown" && n) { e.preventDefault(); palette.sel = (palette.sel + 1) % n; paletteRender(); }
    else if (e.key === "ArrowUp" && n) { e.preventDefault(); palette.sel = (palette.sel - 1 + n) % n; paletteRender(); }
    else if (e.key === "Enter") { e.preventDefault(); paletteChoose(palette.sel); }
    else if (e.key === "Tab") { e.preventDefault(); $("#pal-q").focus(); } // the input is the only focus stop
  });
}
function openPalette() {
  if (!palette.el) paletteBuild();
  if (!palette.el.classList.contains("hidden")) return;
  palette.prev = document.activeElement;
  if (!palette.items.length) palette.items = paletteBase();
  palette.sel = 0;
  $("#pal-q").value = "";
  palette.el.classList.remove("hidden");
  document.documentElement.classList.add("pal-open");
  paletteRender();
  $("#pal-q").focus();
  if (!palette.runsLoaded) {
    loadBench().then((b) => {
      const sandbox = new Set((b.sandbox?.rows || []).map((r) => r.id));
      const runs = (b.static?.rows || []).map((r) => {
        const mode = sandbox.has(r.id) ? "sandbox" : "static";
        return { label: r.title, hint: `#${r.id}${mode === "sandbox" ? " · sandbox" : ""}`, kind: "Run",
          run: () => { location.hash = `#/report/${mode}/${encodeURIComponent(r.id)}`; } };
      });
      palette.items = [...paletteBase(), ...runs];
      palette.runsLoaded = true;
      if (!palette.el.classList.contains("hidden")) paletteRender();
    }).catch(() => { palette.runsLoaded = true; });
  }
}
function closePalette(restore = true) {
  if (!palette.el || palette.el.classList.contains("hidden")) return;
  palette.el.classList.add("hidden");
  document.documentElement.classList.remove("pal-open");
  if (restore && palette.prev && document.contains(palette.prev)) palette.prev.focus();
  palette.prev = null;
}
addEventListener("keydown", (e) => {
  if ((e.ctrlKey || e.metaKey) && !e.altKey && e.key.toLowerCase() === "k") {
    e.preventDefault();
    palette.el && !palette.el.classList.contains("hidden") ? closePalette() : openPalette();
    return;
  }
  if (e.key === "/" && !e.ctrlKey && !e.metaKey && !e.altKey) {
    const t = e.target;
    const typing = t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName));
    if (!typing) { e.preventDefault(); openPalette(); }
  }
});
if ($("#pal-btn")) $("#pal-btn").onclick = openPalette;

// Guided tour: five stops a judge can click through in about a minute. Kept per tab in sessionStorage.
const TOUR = [
  { hash: "#/report/sandbox/2298307", text: "A fake report: its “buffer overflow” is ruled out by a bounds check two lines earlier (lib/ws.c:578). Closed with evidence, and a reply to post." },
  { hash: "#/report/sandbox/3735184", text: "A real CVE: the agent reproduced the .netrc password leak in the sandbox, and the run became a proof bundle." },
  { hash: "#/proof", text: "The proof bundles (two so far): one command re-runs each from scratch. Bug present at the reported commit, gone at curl's fix. No AI involved in verifying." },
  { hash: "#/bench", text: "196 curl reports replayed as of their filing date: 0 real CVEs wrongly closed. A plain “is this slop?” model gives false reasons in 13 of 31 closes." },
  { hash: "#/memory", text: "Memory across runs, built so attackers can't teach it: facts pinned to the code version, nothing a reporter wrote is stored, and it never decides a verdict." },
];
function tourStep() { try { return JSON.parse(sessionStorage.getItem("tour") ?? "null"); } catch (e) { return null; } }
function setTour(i) { try { i == null ? sessionStorage.removeItem("tour") : sessionStorage.setItem("tour", String(i)); } catch (e) { /* no tour persistence */ } }
function startTour() { setTour(0); location.hash = TOUR[0].hash; }
function renderTour() {
  const i = tourStep(), el = $("#tour");
  if (i == null || !TOUR[i]) { el.classList.add("hidden"); return; }
  el.classList.remove("hidden");
  el.innerHTML = `<span class="tour-n">Tour ${i + 1}/${TOUR.length}</span><span class="tour-t">${esc(TOUR[i].text)}</span>
    <span class="row">${i > 0 ? `<button class="btn small" id="tour-prev">Back</button>` : ""}
    ${i < TOUR.length - 1 ? `<button class="btn small primary" id="tour-next">Next</button>` : `<button class="btn small primary" id="tour-end">Finish</button>`}
    <button class="btn small" id="tour-x" title="Close the tour">✕</button></span>`;
  const go = (j) => { setTour(j); location.hash = TOUR[j].hash; };
  if ($("#tour-prev")) $("#tour-prev").onclick = () => go(i - 1);
  if ($("#tour-next")) $("#tour-next").onclick = () => go(i + 1);
  if ($("#tour-end")) $("#tour-end").onclick = () => { setTour(null); location.hash = "#/"; };
  $("#tour-x").onclick = () => { setTour(null); renderTour(); };
}
const TITLES = { home: "SlopProof", bench: "Benchmark · SlopProof", proof: "Proof bundles · SlopProof", memory: "Memory · SlopProof",
  how: "How it works · SlopProof", run: "Triage run · SlopProof", report: "Recorded run · SlopProof" };

// Router. A page function gets the path parts and may return a cleanup function.
const ROUTES = {};
let cleanup = null, routeSeq = 0;
function route() {
  if (cleanup) cleanup();
  cleanup = null;
  const seq = ++routeSeq;
  const parts = location.hash.replace(/^#\/?/, "").split("/").filter(Boolean).map(decodeURIComponent);
  const name = parts[0] || "home";
  const nav = ["run", "report", "home"].includes(name) ? "home" : name;
  $$("nav a").forEach((a) => a.classList.toggle("active", a.dataset.nav === nav));
  window.scrollTo(0, 0);
  document.title = TITLES[name] || TITLES.home;
  renderTour();
  const page = ROUTES[name] || ROUTES.home;
  Promise.resolve(page(parts.slice(1))).then((fn) => {
    const fnc = typeof fn === "function" ? fn : null;
    if (seq !== routeSeq) { if (fnc) fnc(); return; } // a newer page owns the screen now: stop this one's timers
    cleanup = fnc;
  })
    .catch((e) => { app.innerHTML = `<div class="card"><h2>Something went wrong</h2><p class="muted">${esc(e.message)}</p><a href="#/">Back to start</a></div>`; });
}
addEventListener("hashchange", route);
