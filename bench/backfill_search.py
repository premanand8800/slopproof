"""Add code search results to stored benchmark runs made before code search existed (no model calls).

They are marked "backfilled": the static analysis in those runs did not see them. The UI says so.

  uv run python bench/backfill_search.py
"""

import json
import sys
from pathlib import Path

from slopproof import codecheck, codesearch

ROOT = Path(__file__).parent

bare = codecheck.ensure_repo("https://github.com/curl/curl")
dataset = {r["id"]: r for r in map(json.loads, (ROOT / "dataset.jsonl").read_text().splitlines())}
for mode in ("static", "sandbox"):
    path = ROOT / f"results_{mode}.jsonl"
    rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    rows.sort(key=lambda r: r["full"]["ref"]["sha"])  # build each tree's index once
    for r in rows:
        full = r["full"]
        if full.get("search") is None:
            found = codesearch.find_code(bare, full["ref"]["sha"], r["title"], dataset[r["id"]]["body"], full["claims"])
            full["search"] = [dict(h, backfilled=True) for h in found]
    rows.sort(key=lambda r: r["created_at"])
    path.write_text("".join(json.dumps(r, default=str) + "\n" for r in rows))
    print(f"{mode}: {len(rows)} rows", file=sys.stderr)
