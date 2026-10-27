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
$("#theme").onclick = () => {
  const root = document.documentElement;
  const dark = root.dataset.theme ? root.dataset.theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
  root.dataset.theme = dark ? "light" : "dark";
  try { localStorage.setItem("theme", root.dataset.theme); } catch (e) { /* not persisted */ }
};

// Guided tour: five stops a judge can click through in about a minute. Kept per tab in sessionStorage.
const TOUR = [
  { hash: "#/report/sandbox/2298307", text: "A fake report: its “buffer overflow” is ruled out by a bounds check two lines earlier (lib/ws.c:578). Closed with evidence, and a reply to post." },
  { hash: "#/report/sandbox/3735184", text: "A real CVE: the agent reproduced the .netrc password leak in the sandbox, and the run became a proof bundle." },
  { hash: "#/proof", text: "The proof bundle: one command re-runs it from scratch. Bug present at the reported commit, gone at curl's fix. No AI involved in verifying." },
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
let cleanup = null;
function route() {
  if (cleanup) cleanup();
  cleanup = null;
  const parts = location.hash.replace(/^#\/?/, "").split("/").filter(Boolean).map(decodeURIComponent);
  const name = parts[0] || "home";
  const nav = ["run", "report", "home"].includes(name) ? "home" : name;
  $$("nav a").forEach((a) => a.classList.toggle("active", a.dataset.nav === nav));
  window.scrollTo(0, 0);
  document.title = TITLES[name] || TITLES.home;
  renderTour();
  const page = ROUTES[name] || ROUTES.home;
  Promise.resolve(page(parts.slice(1))).then((fn) => { cleanup = typeof fn === "function" ? fn : null; })
    .catch((e) => { app.innerHTML = `<div class="card"><h2>Something went wrong</h2><p class="muted">${esc(e.message)}</p><a href="#/">Back to start</a></div>`; });
}
addEventListener("hashchange", route);
