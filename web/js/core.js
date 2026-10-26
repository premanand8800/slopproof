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
  const page = ROUTES[name] || ROUTES.home;
  Promise.resolve(page(parts.slice(1))).then((fn) => { cleanup = typeof fn === "function" ? fn : null; })
    .catch((e) => { app.innerHTML = `<div class="card"><h2>Something went wrong</h2><p class="muted">${esc(e.message)}</p><a href="#/">Back to start</a></div>`; });
}
addEventListener("hashchange", route);
