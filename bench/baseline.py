"""Baseline: ask one model to judge each report from its text alone, the way "AI slop" is spotted today.

Same model as SlopProof's verdict step (Nemotron 3 Ultra), same reports, same title cleanup, but no code,
no web evidence and no sandbox. Compare its closes with SlopProof's. The same call is SlopProof's text
screen (src/slopproof/screen.py), so rescore.py reuses these results as the stored screen votes.

  uv run python bench/baseline.py            # run (resumable), writes bench/results_baseline.jsonl
  uv run python bench/baseline.py --score
"""

import argparse
import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from slopproof.benchscore import score
from slopproof.llm import Ledger
from slopproof.screen import screen

ROOT = Path(__file__).parent
OUT = ROOT / "results_baseline.jsonl"


def load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()] if path.exists() else []


def run_one(row: dict) -> dict:
    ledger = Ledger()
    title = re.sub(r"^CVE-\d{4}-\d+:\s*", "", row["title"])
    out = screen(title, row["body"], "curl", ledger)
    return {"id": row["id"], "label": row["label"], "title": title,
            "verdict": "FABRICATED" if out.get("close") else "PLAUSIBLE",
            "confidence": out.get("confidence"), "headline": out.get("reason", ""),
            "usd": ledger.summary()["total_usd"], "seconds": sum(c["seconds"] for c in ledger.calls)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--score", action="store_true")
    ap.add_argument("--workers", type=int, default=6)
    a = ap.parse_args()
    if a.score:
        print(json.dumps(score(load(OUT)), indent=1))
        return
    done = {r["id"] for r in load(OUT)}
    rows = [r for r in load(ROOT / "dataset.jsonl") if r["id"] not in done]
    print(f"{len(rows)} to run, {len(done)} already done", file=sys.stderr)
    with ThreadPoolExecutor(max_workers=a.workers) as pool, OUT.open("a") as f:
        futs = {pool.submit(run_one, r): r for r in rows}
        for fut in as_completed(futs):
            try:
                res = fut.result()
            except Exception as e:
                print(f"FAIL {futs[fut]['id']}: {e}", file=sys.stderr)
                continue
            f.write(json.dumps(res) + "\n")
            f.flush()


if __name__ == "__main__":
    main()
