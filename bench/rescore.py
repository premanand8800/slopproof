"""Re-apply the verdict guards to stored benchmark results (no model calls).

Runs made before the text screen existed get its vote from results_baseline.jsonl, which is the same call.
Pass result file names (e.g. results_static_v3.jsonl) to rescore those instead of results_static/sandbox.
"""

import json
import sys
from pathlib import Path

from slopproof.pipeline import apply_guards

ROOT = Path(__file__).parent


def load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()] if path.exists() else []


screens = {r["id"]: {"close": r["verdict"] == "FABRICATED", "confidence": r["confidence"], "reason": r["headline"]}
           for r in load(ROOT / "results_baseline.jsonl")}

for name in sys.argv[1:] or ("results_static.jsonl", "results_sandbox.jsonl"):
    path = ROOT / name
    if not path.exists():
        continue
    rows = load(path)
    for r in rows:
        full = r["full"]
        if not full.get("screen") and r["id"] in screens:
            full["screen"] = screens[r["id"]]
        raw = dict(full["verdict"])
        raw["verdict"] = raw.get("model_verdict", raw["verdict"])
        raw.pop("priority", None)
        raw["headline"] = raw["headline"].split("] ", 1)[-1] if raw["headline"].startswith("[") else raw["headline"]
        full["verdict"] = apply_guards(raw, full.get("analysis"), full.get("reproduction"), full.get("web"),
                                       full.get("screen"))
        r["verdict"], r["headline"] = full["verdict"]["verdict"], full["verdict"]["headline"]
        r["priority"] = full["verdict"].get("priority")
    path.write_text("".join(json.dumps(r, default=str) + "\n" for r in rows))
    print(f"rescored {len(rows)} rows in {name}", file=sys.stderr)
