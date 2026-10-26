"""Re-apply the reproduction checks to stored sandbox runs, then re-apply the verdict guards.

Runs recorded before a check existed are held to it too: did the PoC run the project's own code, is there a
sanitizer or crash report in project code, and, if not, does an independent model see a security impact over
intended use. Uses one model call per stored "reproduced" run without a crash report.

  uv run python bench/recheck_reproductions.py && uv run python bench/rescore.py
"""

import json
import sys
from pathlib import Path

from slopproof.llm import Ledger
from slopproof.reproduce import _check_reproduction

ROOT = Path(__file__).parent
path = ROOT / "results_sandbox.jsonl"
dataset = {r["id"]: r for r in map(json.loads, (ROOT / "dataset.jsonl").read_text().splitlines())}
rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
for r in rows:
    rep = r["full"].get("reproduction") or {}
    claimed = rep.get("claimed_outcome", rep.get("outcome"))
    if claimed != "reproduced":
        continue
    rep["claimed_outcome"] = "reproduced"
    rep["outcome"] = "reproduced"
    rep.setdefault("impact", "boundary_crossed")  # older runs did not ask; the checks below decide
    rep.setdefault("reachable_by_attacker", True)
    report = dataset[r["id"]]["title"] + "\n\n" + dataset[r["id"]]["body"]
    _check_reproduction(rep, "curl", report, Ledger())
    r["repro_outcome"] = rep["outcome"]
    print(f"{r['label']:4} {r['id']:>8} reproduced -> {rep['outcome']}: {str(rep.get('impact_check'))[:120]}",
          file=sys.stderr)
path.write_text("".join(json.dumps(r, default=str) + "\n" for r in rows))
