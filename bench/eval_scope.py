"""Run the policy scope check on stored runs (one model call per report) and store it in the results.

  uv run python bench/eval_scope.py results_static.jsonl
  uv run python bench/eval_scope.py results_holdout_static.jsonl
"""

import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from slopproof import codecheck
from slopproof.llm import Ledger
from slopproof.scope import check_scope

ROOT = Path(__file__).parent


def one(r: dict) -> dict:
    full = r["full"]
    if full.get("scope"):
        return r
    bare = codecheck.ensure_repo("https://github.com/curl/curl")
    tree = codecheck.export_tree(bare, full["ref"]["sha"])
    try:
        full["scope"] = check_scope(tree, r["title"], full["claims"].get("summary", ""), full.get("analysis"), Ledger())
    except Exception as e:  # noqa: BLE001 - leave it for the next run
        print(f"FAIL {r['id']}: {e}", file=sys.stderr)
        return r
    print(f"{r['label']:7} {r['id']:>8} {full['scope'].get('scope'):12} {full['scope'].get('section', '')[:40]}",
          file=sys.stderr)
    return r


path = ROOT / sys.argv[1]
rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
rows.sort(key=lambda r: r["full"]["ref"]["sha"])
with ThreadPoolExecutor(max_workers=4) as pool:
    rows = list(pool.map(one, rows))
rows.sort(key=lambda r: r["created_at"])
path.write_text("".join(json.dumps(r, default=str) + "\n" for r in rows))
