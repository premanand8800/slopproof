"""Web app: submit a report, stream the triage live, browse the benchmark."""

import hashlib
import json
import os
import queue
import re
import secrets
import threading
import time
import uuid
from collections.abc import Callable
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .benchscore import score
from .pipeline import fetch_report, resume_from_events, triage

ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / "web"
BENCH = ROOT / "bench"

# The public demo can turn the sandbox off and cap spend; locally both default to on and unlimited.
SANDBOX_ENABLED = os.environ.get("SLOPPROOF_SANDBOX", "1") == "1"
DAILY_RUNS = int(os.environ.get("SLOPPROOF_DAILY_RUNS", "0"))
# On a public host, sandbox runs (model-written code on the host) need this passcode; static checks do not.
SANDBOX_KEY = os.environ.get("SLOPPROOF_SANDBOX_KEY", "")

app = FastAPI(title="SlopProof")
jobs: dict[str, dict] = {}
JOBS_DIR = ROOT / ".cache" / "jobs"


def new_job(kind: str, meta: dict) -> tuple[str, Callable[[dict], None]]:
    """A job whose events are kept in memory for streaming and appended to disk, so a page reload or a server
    restart can show the run again (a run cut off by a restart is reported as interrupted)."""
    JOBS_DIR.mkdir(parents=True, exist_ok=True)
    job_id = uuid.uuid4().hex[:12]
    q: queue.Queue = queue.Queue()
    jobs[job_id] = {"queue": q, "events": [], "result": None}
    path = JOBS_DIR / f"{job_id}.jsonl"
    path.write_text(json.dumps({"stage": "meta", "kind": kind, "ts": time.time(), **meta}, default=str) + "\n")
    lock = threading.Lock()

    def emit(ev: dict) -> None:
        ev = {**ev, "ts": round(time.time(), 2)}
        with lock:
            jobs[job_id]["events"].append(ev)
            with path.open("a") as f:
                f.write(json.dumps(ev, default=str) + "\n")
        q.put(ev)

    emit({"stage": "queued"})
    return job_id, emit


def stored_events(job_id: str) -> list[dict] | None:
    if not re.fullmatch(r"[0-9a-f]{12}", job_id):
        return None
    path = JOBS_DIR / f"{job_id}.jsonl"
    if not path.exists():
        return None
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
_runs_today = {"day": "", "n": 0}
_lock = threading.Lock()


class TriageRequest(BaseModel):
    url: str | None = None
    title: str | None = None
    text: str | None = None
    repo: str | None = None
    sandbox: bool = True
    passcode: str | None = None


@app.get("/api/health")
def health():
    active = sum(1 for j in jobs.values() if j["result"] is None and not any(
        e["stage"] in ("done", "error") for e in j["events"]))
    return {"ok": True, "active_jobs": active, "sandbox": SANDBOX_ENABLED, "sandbox_passcode": bool(SANDBOX_KEY), "daily_runs": DAILY_RUNS or None,
            "nebius_key": bool(os.environ.get("NEBIUS_API_KEY")), "tavily_key": bool(os.environ.get("TAVILY_API_KEY"))}


@app.post("/api/triage")
def start(req: TriageRequest):
    if req.sandbox and SANDBOX_ENABLED and SANDBOX_KEY and not secrets.compare_digest(req.passcode or "", SANDBOX_KEY):
        raise HTTPException(403, "The sandbox needs the demo passcode. Untick it to run the static checks.")
    if req.url:
        try:
            rep = fetch_report(req.url)
        except Exception as e:
            raise HTTPException(400, str(e))
        repo = req.repo or rep["repo"]
    else:
        if not (req.text and req.repo):
            raise HTTPException(400, "Give a report URL, or the report text plus the GitHub repo URL.")
        rep = {"title": req.title or "Untitled report", "body": req.text, "created_at": None}
        repo = req.repo
    if not repo:
        raise HTTPException(400, "Could not infer the repository. Add the GitHub repo URL.")
    return {"job": launch(rep, repo, bool(req.sandbox and SANDBOX_ENABLED), req.url)}


def _count_run() -> None:
    with _lock:
        day = time.strftime("%Y-%m-%d")
        if _runs_today["day"] != day:
            _runs_today.update(day=day, n=0)
        if DAILY_RUNS and _runs_today["n"] >= DAILY_RUNS:
            raise HTTPException(429, "The public demo hit today's budget. Browse the recorded runs, or run SlopProof locally.")
        _runs_today["n"] += 1


def launch(rep: dict, repo: str, sandbox: bool, url: str | None, resume: dict | None = None,
           retry_of: str | None = None) -> str:
    _count_run()
    job_id, emit = new_job("triage", {"title": rep["title"], "url": url, "repo": repo, "sandbox": sandbox,
                                      "created_at": rep.get("created_at"), "retry_of": retry_of,
                                      "resumed_steps": sorted(resume or {})})

    def work() -> None:
        try:
            emit({"stage": "report", "title": rep["title"], "body": rep["body"][:20000], "repo": repo,
                  "created_at": rep.get("created_at")})
            res = triage(rep["title"], rep["body"], repo, rep.get("created_at"), run_sandbox=sandbox, emit=emit,
                         resume=resume, run_id=job_id)
            jobs[job_id]["result"] = res
            emit({"stage": "done"})
        except Exception as e:
            emit({"stage": "error", "message": friendly_error(e)})

    threading.Thread(target=work, daemon=True).start()
    return job_id


class RetryRequest(BaseModel):
    passcode: str | None = None
    fresh: bool = False


@app.post("/api/jobs/{job_id}/retry")
def retry(job_id: str, req: RetryRequest):
    """Run a stopped or finished report again. By default the steps that already finished are reused, so a run
    cut off by a rate limit or a restart continues where it stopped; fresh=true starts over."""
    saved = list(jobs[job_id]["events"]) if job_id in jobs else []
    disk = stored_events(job_id) or []
    if not saved and not disk:
        raise HTTPException(404, "unknown run")
    meta = next((e for e in disk if e["stage"] == "meta"), {})
    events = saved or [e for e in disk if e["stage"] != "meta"]
    if job_id in jobs and not any(e["stage"] in ("done", "error") for e in events):
        raise HTTPException(409, "This run is still going.")
    report = next((e for e in events if e["stage"] == "report"), None)
    if report:
        rep, repo = {"title": report["title"], "body": report["body"], "created_at": report.get("created_at")}, report["repo"]
    elif meta.get("url"):
        rep = fetch_report(meta["url"])
        repo = meta.get("repo") or rep["repo"]
    else:
        raise HTTPException(400, "This run has no saved report to retry.")
    sandbox = bool(meta.get("sandbox")) and SANDBOX_ENABLED
    if sandbox and SANDBOX_KEY and not secrets.compare_digest(req.passcode or "", SANDBOX_KEY):
        raise HTTPException(403, "This run uses the sandbox: enter the demo passcode to run it again.")
    resume = {} if req.fresh else resume_from_events(events)
    return {"job": launch(rep, repo, sandbox, meta.get("url"), resume, retry_of=job_id), "resumed": sorted(resume)}


def friendly_error(e: Exception) -> str:
    """Say what went wrong in words a visitor can act on; keep the raw text in the server log."""
    text = str(e)
    print(f"run failed: {text[:2000]}", flush=True)
    if "per-day" in text:
        return "The free model quota for today is used up. It resets at 00:00 UTC; try again then."
    if "429" in text or "Rate limit" in text:
        return "The model provider is rate limiting us right now. Wait a minute and try again."
    if "402" in text or "credits" in text.lower() or "limit" in text.lower() and "key" in text.lower():
        return "The model provider's spending limit for this demo was reached. Try again later."
    return f"The run failed: {text[:300]}"


EXAMPLES = ROOT / "examples" / "bundles"


def _example(name: str) -> dict:
    if not re.fullmatch(r"[\w.-]+", name) or not (EXAMPLES / f"{name}.json").exists():
        raise HTTPException(404, "no such example")
    return json.loads((EXAMPLES / f"{name}.json").read_text())


@app.get("/api/memory")
def memory_overview():
    """What SlopProof remembers across runs, with each item's source. Read-only here; maintainers edit it with
    `slopproof memory` on the host."""
    from . import memory
    return {"mode": memory.mode(), **memory.overview()}


@app.get("/api/examples/{name}")
def example(name: str):
    """A shipped example proof bundle, or its recorded verification ({name}.verification)."""
    return _example(name)


# Re-running a shipped bundle needs no passcode: its commands are fixed in the repository, not typed by a visitor.
# One re-run at a time; a click while one runs, or within VERIFY_REUSE seconds of the last, joins that job.
VERIFY_REUSE = 15 * 60
_verify: dict = {"job": None, "name": None, "at": 0.0}
_verify_lock = threading.Lock()


@app.post("/api/examples/{name}/verify")
def verify_example(name: str):
    """Re-run one of the shipped example bundles live. Only bundles in the repository can run here;
    anyone can verify their own bundle locally with `slopproof verify`."""
    bundle = _example(name)
    if not SANDBOX_ENABLED:
        raise HTTPException(403, "This host has no sandbox. Run: slopproof verify " + f"examples/bundles/{name}.json")
    recorded = (EXAMPLES / f"{name}.verification.json")
    against = json.loads(recorded.read_text()).get("at_against", {}).get("commit") if recorded.exists() else None
    from .bundle import verify

    with _verify_lock:
        last = _verify["job"]
        ended = {e.get("stage") for e in jobs[last]["events"]} if last in jobs else {"error"}
        running = not ended & {"done", "error"}
        if running and _verify["name"] != name:
            raise HTTPException(429, "Another proof is re-running right now. Try again in a few minutes.")
        recent_ok = "done" in ended and time.time() - _verify["at"] < VERIFY_REUSE
        if _verify["name"] == name and (running or recent_ok):
            return {"job": last, "joined": True}
        job_id, emit = new_job("verify", {"title": bundle.get("claim", name)})
        _verify.update(job=job_id, name=name, at=time.time())

    def work() -> None:
        try:
            res = verify(bundle, against, emit=lambda m: emit({"stage": "verify", "message": m}))
            jobs[job_id]["result"] = res
            emit({"stage": "verified", "result": res})
            emit({"stage": "done"})
        except Exception as e:
            emit({"stage": "error", "message": str(e)[:500]})

    threading.Thread(target=work, daemon=True).start()
    return {"job": job_id}


@app.get("/api/jobs/{job_id}")
def job_summary(job_id: str):
    evs = jobs[job_id]["events"] if job_id in jobs else (stored_events(job_id) or [])
    if not evs:
        raise HTTPException(404, "unknown run")
    disk = stored_events(job_id) or []
    meta = next((e for e in disk if e["stage"] == "meta"), {})
    last = evs[-1]["stage"]
    status = "done" if last == "done" else "error" if last == "error" else \
        "running" if job_id in jobs else "interrupted"
    verdict = next((e.get("verdict") for e in reversed(evs) if e["stage"] == "verdict"), None)
    return {"id": job_id, "status": status, "meta": meta, "verdict": verdict}


@app.get("/api/jobs/{job_id}/events")
def events(job_id: str):
    job = jobs.get(job_id)
    if not job:
        # Not running in this process: replay what was saved. If it never finished, the server restarted.
        saved = stored_events(job_id)
        if saved is None:
            raise HTTPException(404, "unknown run")

        def replay_saved():
            for ev in saved:
                if ev["stage"] != "meta":
                    yield f"data: {json.dumps(ev, default=str)}\n\n"
            if saved[-1]["stage"] not in ("done", "error"):
                gone = {"stage": "error", "interrupted": True,
                        "message": "This run was cut off when the server restarted. Start it again to finish it."}
                yield f"data: {json.dumps(gone)}\n\n"

        return StreamingResponse(replay_saved(), media_type="text/event-stream")

    def stream():
        sent = 0
        while True:
            evs = job["events"]
            while sent < len(evs):
                yield f"data: {json.dumps(evs[sent], default=str)}\n\n"
                if evs[sent]["stage"] in ("done", "error"):
                    return
                sent += 1
            try:
                job["queue"].get(timeout=15)
            except queue.Empty:
                yield ": keepalive\n\n"

    return StreamingResponse(stream(), media_type="text/event-stream")


@app.get("/api/jobs/{job_id}/result")
def result(job_id: str):
    job = jobs.get(job_id)
    if not job or job["result"] is None:
        raise HTTPException(404, "not finished")
    return job["result"]


# The headline file for each mode first, then older runs kept for transparency. A recorded run is looked up in
# that order, so a link to a report scored only in an older run still opens.
BENCH_FILES = {
    "static": ("results_static_final.jsonl", "results_static.jsonl"),
    "sandbox": ("results_sandbox.jsonl",),
    "baseline": ("results_baseline.jsonl",),
}


def load_rows(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def bench_rows(mode: str, bench_dir: Path = BENCH, headline_only: bool = True) -> list[dict]:
    """The rows of a benchmark mode: the headline run, or (headline_only=False) every run, newest first and
    each report id once."""
    rows, seen = [], set()
    for name in BENCH_FILES.get(mode, ()):
        for r in load_rows(bench_dir / name):
            if r["id"] not in seen:
                seen.add(r["id"])
                rows.append(r)
        if headline_only:
            break
    return rows


@app.get("/api/bench")
def bench():
    out = {}
    for mode in ("static", "sandbox", "baseline"):
        rows = [{k: v for k, v in r.items() if k != "full"} for r in bench_rows(mode)]
        out[mode] = {"score": score(rows) if rows else None, "rows": rows}
    factcheck = BENCH / "baseline_factcheck.json"
    out["baseline"]["factcheck"] = json.loads(factcheck.read_text()) if factcheck.exists() else None
    return out


def stored_run(r: dict, bodies: dict[str, str]) -> dict:
    """A stored benchmark run with the report text and date, so a replay shows what was triaged."""
    return {**r["full"], "report_body": bodies.get(r["id"], ""), "created_at": r.get("created_at")}


def report_bodies(bench_dir: Path = BENCH) -> dict[str, str]:
    path = bench_dir / "dataset.jsonl"
    if not path.exists():
        return {}
    return {d["id"]: d["body"] for d in map(json.loads, path.read_text().splitlines()) if d}


@app.get("/api/bench/{mode}/{report_id}")
def bench_run(mode: str, report_id: str):
    for r in bench_rows(mode, headline_only=False):
        if r["id"] == report_id:
            return stored_run(r, report_bodies())
    raise HTTPException(404, "no such run")


app.mount("/static", StaticFiles(directory=WEB), name="static")


def _asset_version() -> str:
    """A hash of the web files, added to their URLs so browsers and CDNs (Cloudflare caches .js and .css for
    hours) fetch the new files right after a deploy."""
    h = hashlib.sha256()
    for f in sorted(WEB.rglob("*")):
        if f.is_file():
            h.update(f.read_bytes())
    return h.hexdigest()[:10]


@app.get("/")
def index():
    html = (WEB / "index.html").read_text()
    v = _asset_version()
    html = re.sub(r'(src|href)="(static/[^"?]+\.(?:js|css))"', rf'\1="\2?v={v}"', html)
    return HTMLResponse(html, headers={"Cache-Control": "no-cache"})


def main() -> None:
    import uvicorn

    uvicorn.run(app, host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "8000")))
