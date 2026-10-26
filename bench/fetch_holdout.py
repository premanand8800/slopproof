"""Held-out set: disclosed curl reports that curl closed as not applicable or spam, and that are
not in bench/dataset.jsonl. None of them was looked at while SlopProof was built or tuned.

"Closed as not applicable" is broader than AI slop: some are real bugs that are not security issues, or out of
scope. The question here is how many of them SlopProof closes or sends to the bottom of the queue.

  uv run python bench/fetch_holdout.py --limit 80     # newest first; writes bench/holdout.jsonl
"""

import argparse
import json
import sys
import time
from pathlib import Path

import httpx
from fetch_dataset import fetch

ROOT = Path(__file__).parent
QUERY = ("query H($queryString: String!, $from: Int, $size: Int, $sort: SortInput!) { search(index: "
         "CompleteHacktivityReportIndex, query_string: $queryString, from: $from, size: $size, sort: $sort) "
         "{ nodes { ... on HacktivityDocument { report { _id substate } } } } }")
# "informative" is left out: in 2026 most are real bugs that are not security issues, a different question.
CLOSED = {"not-applicable", "spam"}


def disclosed_curl_reports(client: httpx.Client) -> list[dict]:
    out = []
    for start in range(0, 2000, 100):
        r = client.post("https://hackerone.com/graphql", json={"query": QUERY, "variables": {
            "queryString": "team:curl AND disclosed:true", "from": start, "size": 100,
            "sort": {"field": "latest_disclosable_activity_at", "direction": "DESC"}}}).json()
        page = [n["report"] for n in r["data"]["search"]["nodes"] if n.get("report")]
        out += page
        if len(page) < 100:
            return out
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=80)
    a = ap.parse_args()
    known = {json.loads(line)["id"] for line in (ROOT / "dataset.jsonl").read_text().splitlines()}
    rows = []
    with httpx.Client(timeout=30, follow_redirects=True) as client:
        candidates = [r for r in disclosed_curl_reports(client) if r["substate"] in CLOSED and r["_id"] not in known]
        for c in sorted(candidates, key=lambda r: int(r["_id"]), reverse=True):
            rec = fetch(client, c["_id"])
            time.sleep(0.4)
            if rec is None:
                continue
            rows.append(rec | {"label": "invalid"})
            print(f"{rec['substate']:15} {rec['id']} {rec['title'][:70]}", file=sys.stderr)
            if len(rows) >= a.limit:
                break
    (ROOT / "holdout.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    print(f"wrote {len(rows)} rows", file=sys.stderr)


if __name__ == "__main__":
    main()
