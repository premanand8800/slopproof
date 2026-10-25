"""Web app: submit a report, stream the triage live, browse the benchmark."""

import json
import os
import queue
import threading
import time
import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .benchscore import score
from .pipeline import fetch_report, triage

ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / "web"
BENCH = ROOT / "bench"

# The public demo can turn the sandbox off and cap spend; locally both default to on and unlimited.
SANDBOX_ENABLED = os.environ.get("SLOPPROOF_SANDBOX", "1") == "1"
DAILY_RUNS = int(os.environ.get("SLOPPROOF_DAILY_RUNS", "0"))

app = FastAPI(title="SlopProof")
jobs: dict[str, dict] = {}
_runs_today = {"day": "", "n": 0}
_lock = threading.Lock()


class TriageRequest(BaseModel):
    url: str | None = None
    title: str | None = None
    text: str | None = None
    repo: str | None = None
    sandbox: bool = True


@app.get("/api/health")
def health():
    return {"ok": True, "sandbox": SANDBOX_ENABLED, "daily_runs": DAILY_RUNS or None,
            "nebius_key": bool(os.environ.get("NEBIUS_API_KEY")), "tavily_key": bool(os.environ.get("TAVILY_API_KEY"))}


@app.post("/api/triage")
def start(req: TriageRequest):
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
    with _lock:
        day = time.strftime("%Y-%m-%d")
        if _runs_today["day"] != day:
            _runs_today.update(day=day, n=0)
        if DAILY_RUNS and _runs_today["n"] >= DAILY_RUNS:
            raise HTTPException(429, "The public demo hit today's budget. Browse the recorded runs, or run SlopProof locally.")
        _runs_today["n"] += 1

    job_id = uuid.uuid4().hex[:12]
    q: queue.Queue = queue.Queue()
    jobs[job_id] = {"queue": q, "events": [], "result": None}

    def emit(ev: dict) -> None:
        jobs[job_id]["events"].append(ev)
        q.put(ev)

    def work() -> None:
        try:
            emit({"stage": "report", "title": rep["title"], "body": rep["body"][:20000], "repo": repo,
                  "created_at": rep.get("created_at")})
            res = triage(rep["title"], rep["body"], repo, rep.get("created_at"),
                         run_sandbox=req.sandbox and SANDBOX_ENABLED, emit=emit)
            jobs[job_id]["result"] = res
            emit({"stage": "done"})
        except Exception as e:
            emit({"stage": "error", "message": str(e)[:500]})

    threading.Thread(target=work, daemon=True).start()
    return {"job": job_id}


@app.get("/api/jobs/{job_id}/events")
def events(job_id: str):
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(404, "unknown job")

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


def _bench_rows(mode: str) -> list[dict]:
    path = BENCH / f"results_{mode}.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


@app.get("/api/bench")
def bench():
    out = {}
    for mode in ("static", "sandbox"):
        rows = [{k: v for k, v in r.items() if k != "full"} for r in _bench_rows(mode)]
        out[mode] = {"score": score(rows) if rows else None, "rows": rows}
    return out


@app.get("/api/bench/{mode}/{report_id}")
def bench_run(mode: str, report_id: str):
    for r in _bench_rows(mode):
        if r["id"] == report_id:
            return r["full"]
    raise HTTPException(404, "no such run")


app.mount("/static", StaticFiles(directory=WEB), name="static")


@app.get("/")
def index():
    return FileResponse(WEB / "index.html")


def main() -> None:
    import uvicorn

    uvicorn.run(app, host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "8000")))
