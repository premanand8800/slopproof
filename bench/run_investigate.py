"""Run the investigator over stored benchmark runs: every report whose verdict is not already a close.

Claims, code checks, web checks, the text screen, code search and the static analysis come from the stored run
(same commit, same evidence). The current guards are re-applied to its verdict; if that is still open, the
investigator runs as of the report's filing date (replay: Tavily search with end_date, no extract, map, crawl or
research), and the verdict model decides again only if the investigator brings a verified refutation.
Closed rows are copied unchanged, so the output file scores the whole set.

  uv run python bench/run_investigate.py --source results_static_final.jsonl --out results_static_investigator.jsonl
  uv run python bench/run_investigate.py --source results_holdout_static.jsonl --dataset holdout \
      --out results_holdout_investigator.jsonl
  uv run python bench/run_investigate.py --out results_static_investigator.jsonl --score
"""

import argparse
import json
import os
import sys
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

os.environ["SLOPPROOF_MEMORY"] = "off"

from slopproof import codecheck  # noqa: E402
from slopproof.benchscore import score  # noqa: E402
from slopproof.investigate import investigate  # noqa: E402
from slopproof.llm import Ledger  # noqa: E402
from slopproof.pipeline import apply_guards, decide_again, send_feedback  # noqa: E402
from slopproof.verdict import allowed_cves  # noqa: E402

ROOT = Path(__file__).parent
REPO = "https://github.com/curl/curl"


def load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()] if path.exists() else []


def first_verdict(full: dict) -> tuple[dict, dict]:
    """The stored model verdict with the current guards applied (as bench/rescore.py does)."""
    raw = dict(full["verdict"])
    raw["verdict"] = raw.get("model_verdict", raw["verdict"])
    raw.pop("priority", None)
    raw["headline"] = raw["headline"].split("] ", 1)[-1] if raw["headline"].startswith("[") else raw["headline"]
    return raw, apply_guards(raw, full.get("analysis"), full.get("reproduction"), full.get("web"), full.get("screen"))


def run_one(row: dict, body: str) -> dict:
    full = dict(row["full"])
    raw, verdict = first_verdict(full)
    out = {**row, "full": full}
    if verdict["verdict"] != "PLAUSIBLE":
        full["verdict"] = verdict
        full["investigation"] = None
        return {**out, "verdict": verdict["verdict"], "priority": verdict.get("priority"),
                "headline": verdict.get("headline"), "investigated": False}
    bare = codecheck.ensure_repo(REPO)
    sha = full["ref"]["sha"]
    tree = codecheck.export_tree(bare, sha)
    ledger = Ledger()
    t0 = time.time()
    inv = investigate(row["title"], body, full.get("project", "curl/curl"), full["claims"], full["code"],
                      full.get("web") or {}, full.get("analysis") or {}, full.get("search"), verdict, tree, bare, sha,
                      ledger, as_of=row["created_at"])
    evidence = {"claims": full["claims"], "ref": full["ref"], "code_checks": full["code"], "web_checks": full["web"],
                "static_analysis": full.get("analysis"),
                "reproduction": {k: v for k, v in (full.get("reproduction") or {}).items() if k != "transcript"}
                or "not run"}
    raw2, verdict2 = decide_again(row["title"], body, evidence, raw, inv, full.get("analysis"),
                                  full.get("reproduction"), full.get("web"), full.get("screen"), ledger,
                                  allowed_cves(f"{row['title']}\n{body}", full.get("web") or {}))
    full["tavily_feedback"] = send_feedback(ledger, verdict2, full.get("web"), inv)
    full["first_verdict"] = verdict
    full["verdict"] = verdict2
    full["investigation"] = inv
    full["ledger"] = list(full.get("ledger") or []) + ledger.calls
    full["cost"] = Ledger(calls=full["ledger"]).summary()
    added = ledger.summary()
    return {**out, "verdict": verdict2["verdict"], "priority": verdict2.get("priority"),
            "confidence": verdict2.get("confidence"), "headline": verdict2.get("headline"), "investigated": True,
            "first_verdict": verdict["verdict"], "redecided": bool(inv["signals"]["refutes"]),
            "usd": round(row["usd"] + added["total_usd"], 5), "investigation_usd": added["total_usd"],
            "tavily_credits": added["tavily_credits"], "seconds": round(row["seconds"] + time.time() - t0, 1)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", default="results_static_final.jsonl")
    ap.add_argument("--dataset", default="dataset", help="report texts: dataset or holdout")
    ap.add_argument("--out", required=True)
    ap.add_argument("--ids", help="comma-separated report ids (default: all)")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--score", action="store_true")
    a = ap.parse_args()
    out = ROOT / a.out
    if a.score:
        rows = load(out)
        s = score([{k: v for k, v in r.items() if k != "full"} for r in rows])
        inv = [r for r in rows if r.get("investigated")]
        s["investigated"] = len(inv)
        s["avg_investigation_usd"] = round(sum(r["investigation_usd"] for r in inv) / max(1, len(inv)), 4)
        s["total_investigation_usd"] = round(sum(r["investigation_usd"] for r in inv), 3)
        s["avg_tavily_credits"] = round(sum(r["tavily_credits"] for r in inv) / max(1, len(inv)), 2)
        s["total_tavily_credits"] = sum(r["tavily_credits"] for r in inv)
        s["changed"] = [f"{r['label']} {r['id']} {r['first_verdict']} -> {r['verdict']}" for r in inv
                        if r["verdict"] != r["first_verdict"]]
        print(json.dumps(s, indent=1))
        return
    bodies = {d["id"]: d["body"] for d in load(ROOT / f"{a.dataset}.jsonl")}
    done = {r["id"] for r in load(out)}
    rows = [r for r in load(ROOT / a.source) if r["id"] not in done]
    if a.ids:
        want = set(a.ids.split(","))
        rows = [r for r in rows if r["id"] in want]
    print(f"{len(rows)} to run, {len(done)} already done", file=sys.stderr)
    with ThreadPoolExecutor(max_workers=a.workers) as pool, out.open("a") as f:
        futs = {pool.submit(run_one, r, bodies.get(r["id"], "")): r for r in rows}
        for fut in as_completed(futs):
            r = futs[fut]
            try:
                res = fut.result()
            except Exception:
                print(f"FAIL {r['id']}\n{traceback.format_exc()[-800:]}", file=sys.stderr)
                continue
            f.write(json.dumps(res, default=str) + "\n")
            f.flush()
            if res.get("investigated"):
                inv = res["full"]["investigation"]
                print(f"{res['label']:4} {res['id']:>8} {res['first_verdict']:>10} -> {res['verdict']:15} "
                      f"{inv['recommend']:14} calls {inv['calls']:2} ev {inv['evidence']['verified']}/"
                      f"{inv['evidence']['verified'] + inv['evidence']['dropped']} ${res['investigation_usd']:.3f} "
                      f"cr {res['tavily_credits']} {res['title'][:50]}", file=sys.stderr)


if __name__ == "__main__":
    main()
