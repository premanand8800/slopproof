"""Replay the curl dataset through SlopProof and score it.

Each report is triaged as of its submission date: the source tree is the commit from that day and web
evidence is limited to pages published before it. Titles of real reports were renamed to "CVE-...: ..."
after disclosure, so that prefix is stripped.

  uv run python bench/run_bench.py --mode static --workers 4
  uv run python bench/run_bench.py --mode sandbox --ids 2298307,2187833
  uv run python bench/run_bench.py --score
"""

import argparse
import json
import re
import sys
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import os

# Benchmark runs never read or write memory: the numbers must not be learned from the test set.
os.environ["SLOPPROOF_MEMORY"] = "off"

from slopproof.benchscore import score  # noqa: E402
from slopproof.pipeline import triage  # noqa: E402

ROOT = Path(__file__).parent
def load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()] if path.exists() else []


def run_one(row: dict, sandbox: bool) -> dict:
    title = re.sub(r"^CVE-\d{4}-\d+:\s*", "", row["title"])
    res = triage(title, row["body"], "https://github.com/curl/curl", row["created_at"],
                 run_sandbox=sandbox, replay=True)
    repro = res.get("reproduction") or {}
    return {"id": row["id"], "label": row["label"], "title": title, "created_at": row["created_at"],
            "verdict": res["verdict"].get("verdict"), "priority": res["verdict"].get("priority"),
            "confidence": res["verdict"].get("confidence"),
            "headline": res["verdict"].get("headline"), "repro_outcome": repro.get("outcome"),
            "usd": res["cost"]["total_usd"], "seconds": res["seconds"], "provider": res["cost"].get("provider", "nebius"),
            "full": res}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["static", "sandbox"], default="static")
    ap.add_argument("--ids", help="comma-separated report ids")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--score", action="store_true")
    ap.add_argument("--dataset", default="dataset", help="dataset name in bench/, e.g. holdout")
    ap.add_argument("--tag", default="", help="suffix for the results file, e.g. v2 -> results_static_v2.jsonl")
    a = ap.parse_args()
    prefix = "" if a.dataset == "dataset" else f"{a.dataset}_"
    out = ROOT / f"results_{prefix}{a.mode}{'_' + a.tag if a.tag else ''}.jsonl"
    if a.score:
        print(json.dumps(score([{k: v for k, v in r.items() if k != "full"} for r in load(out)]), indent=1))
        return
    done = {r["id"] for r in load(out)}
    rows = [r for r in load(ROOT / f"{a.dataset}.jsonl") if r["id"] not in done]
    if a.ids:
        rows = [r for r in rows if r["id"] in set(a.ids.split(","))]
    print(f"{len(rows)} to run, {len(done)} already done", file=sys.stderr)
    with ThreadPoolExecutor(max_workers=a.workers) as pool, out.open("a") as f:
        futs = {pool.submit(run_one, r, a.mode == "sandbox"): r for r in rows}
        for fut in as_completed(futs):
            r = futs[fut]
            try:
                res = fut.result()
            except Exception:
                print(f"FAIL {r['id']}\n{traceback.format_exc()[-600:]}", file=sys.stderr)
                continue
            f.write(json.dumps(res, default=str) + "\n")
            f.flush()
            print(f"{res['label']:4} {res['id']:>8} {res['verdict']:15} ${res['usd']:.3f} {res['title'][:60]}", file=sys.stderr)


if __name__ == "__main__":
    main()
