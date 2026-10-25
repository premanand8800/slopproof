"""Re-apply the verdict guards to stored benchmark results (no model calls)."""

import json
import sys
from pathlib import Path

from slopproof.pipeline import apply_guards

for mode in ("static", "sandbox"):
    path = Path(__file__).parent / f"results_{mode}.jsonl"
    if not path.exists():
        continue
    rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    for r in rows:
        full = r["full"]
        raw = dict(full["verdict"])
        raw["verdict"] = raw.get("model_verdict", raw["verdict"])
        raw["headline"] = raw["headline"].split("] ", 1)[-1] if raw["headline"].startswith("[") else raw["headline"]
        full["verdict"] = apply_guards(raw, full.get("analysis"), full.get("reproduction"))
        r["verdict"], r["headline"] = full["verdict"]["verdict"], full["verdict"]["headline"]
    path.write_text("".join(json.dumps(r, default=str) + "\n" for r in rows))
    print(f"rescored {len(rows)} {mode} rows", file=sys.stderr)
