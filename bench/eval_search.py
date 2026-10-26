"""Measure code search on real curl CVEs (no model calls).

Ground truth: the functions changed by each CVE's fix commit (from curl's vuln.json), found by mapping the
fix diff onto the functions of the commit before it. The search runs on the tree as of the report date,
with the claims extracted at triage time, so neither the fix nor any later write-up is visible to it.

  uv run python bench/eval_search.py            # writes bench/search_eval.json
"""

import json
import re
import subprocess
import sys
from pathlib import Path

import httpx

from slopproof import codecheck, codesearch

ROOT = Path(__file__).parent
KS = (1, 5, 10)


def git(bare: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(bare), *args], capture_output=True, text=True, check=True).stdout


def fix_commits() -> dict[str, str]:
    out = {}
    for v in httpx.get("https://curl.se/docs/vuln.json", timeout=30).json():
        m = re.search(r"hackerone\.com/reports/(\d+)", (v.get("database_specific") or {}).get("issue") or "")
        fixed = [e["fixed"] for a in v.get("affected", []) for r in a.get("ranges", []) if r.get("type") == "GIT"
                 for e in r["events"] if "fixed" in e]
        if m and fixed:
            out[m.group(1)] = fixed[0]
    return out


def changed_functions(bare: Path, fix: str) -> tuple[set, set]:
    """(file, function) pairs and files touched by the fix, in lib/, src/ and include/."""
    parent = git(bare, "rev-parse", f"{fix}^").strip()
    funcs = codesearch.load_functions(bare, parent)
    by_file: dict[str, list] = {}
    for f in funcs:
        by_file.setdefault(f.file, []).append(f)
    gold, files, cur = set(), set(), None
    for line in git(bare, "diff", "-U0", parent, fix, "--", *codesearch.SEARCH_DIRS).splitlines():
        if line.startswith("--- "):
            cur = line[6:] if line.startswith("--- a/") else None
        elif line.startswith("@@") and cur:
            m = re.match(r"@@ -(\d+)(?:,(\d+))?", line)
            start, count = int(m.group(1)), int(m.group(2) or 1)
            end = start + max(count, 1) - 1
            files.add(cur)
            for f in by_file.get(cur, []):
                if f.start <= end and start <= f.end:
                    gold.add((f.file, f.name))
    return gold, files


def hit_at(ranked: list[tuple[str, str]], gold: set, k: int, files: bool = False) -> bool:
    top = ranked[:k]
    return any((r[0] if files else r) in gold for r in top)


def main() -> None:
    bare = codecheck.ensure_repo("https://github.com/curl/curl")
    fixes = fix_commits()
    dataset = {r["id"]: r for r in map(json.loads, (ROOT / "dataset.jsonl").read_text().splitlines())}
    stored = {r["id"]: r for r in map(json.loads, (ROOT / "results_static.jsonl").read_text().splitlines())}
    cases = sorted((rid for rid in stored if stored[rid]["label"] == "real" and rid in fixes),
                   key=lambda rid: stored[rid]["full"]["ref"]["sha"])  # group by tree so each index builds once
    variants = {"cited": [], "bm25": []}
    per_case = []
    for n, rid in enumerate(cases, 1):
        full, body = stored[rid]["full"], dataset[rid]["body"]
        claims = full["claims"]
        gold, gold_files = changed_functions(bare, fixes[rid])
        if not gold:
            continue
        idx = codesearch.index_for(bare, full["ref"]["sha"])
        q = codesearch.report_query(stored[rid]["title"], body, claims)
        names = {re.sub(r"[^\w]", "", fn.split("(")[0]) for fn in claims["functions"]}
        # What SlopProof read before code search: the functions and files the report names.
        cited = [(f.file, f.name) for f in idx.funcs if f.name in names]
        cited += [(f.file, f.name) for f in idx.funcs if f.file in {p.lstrip("/") for p in claims["files"]}
                  and (f.file, f.name) not in cited]
        ranked = {
            "cited": cited,
            "bm25": [(f.file, f.name) for f, _, _ in idx.search(q, k=10)],
        }
        no_code = not claims["files"] and not claims["functions"] and not claims["code_quotes"]
        row = {"id": rid, "no_code_cited": no_code, "gold": sorted(map(list, gold)),
               "top5": ranked["bm25"][:5]}
        for v, r in ranked.items():
            row[v] = {f"fn@{k}": hit_at(r, gold, k) for k in KS} | {f"file@{k}": hit_at(r, gold_files, k, True) for k in KS}
        per_case.append(row)
        print(f"{n}/{len(cases)} {rid} gold={len(gold)} bm25 fn@5={row['bm25']['fn@5']}", file=sys.stderr)

    def rate(rows, v, key):
        return f"{sum(r[v][key] for r in rows)}/{len(rows)}"
    summary = {}
    for subset, rows in (("all", per_case), ("no_code_cited", [r for r in per_case if r["no_code_cited"]])):
        summary[subset] = {v: {key: rate(rows, v, key) for key in [f"fn@{k}" for k in KS] + [f"file@{k}" for k in KS]}
                           for v in variants}
    (ROOT / "search_eval.json").write_text(json.dumps({"summary": summary, "cases": per_case}, indent=1) + "\n")
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    main()
