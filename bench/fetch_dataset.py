"""Build the benchmark dataset from public curl HackerOne reports.

Negatives: reports Daniel Stenberg lists as AI slop
(https://gist.github.com/bagder/07f7581f6e3d78ef37dfbfc81fd1d1cd).
Positives: disclosed HackerOne reports that became real curl CVEs
(https://curl.se/docs/vuln.json).
"""

import json
import re
import subprocess
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).parent
OUT = ROOT / "dataset.jsonl"
GIST_ID = "07f7581f6e3d78ef37dfbfc81fd1d1cd"


def slop_ids() -> list[str]:
    text = subprocess.run(
        ["gh", "api", f"gists/{GIST_ID}", "-q", ".files | to_entries[] | .value.content"],
        capture_output=True, text=True, check=True,
    ).stdout
    return sorted(set(re.findall(r"hackerone\.com/reports/(\d+)", text)))


def cve_reports() -> dict[str, dict]:
    vulns = httpx.get("https://curl.se/docs/vuln.json", timeout=30).json()
    out = {}
    for v in vulns:
        db = v.get("database_specific", {})
        m = re.search(r"hackerone\.com/reports/(\d+)", db.get("issue", "") or "")
        if not m:
            continue
        fixed = [e["fixed"] for a in v.get("affected", []) if a.get("type") == "GIT"
                 for e in a["events"] if "fixed" in e]
        out[m.group(1)] = {
            "cve": v["aliases"][0] if v.get("aliases") else v["id"],
            "summary": v.get("summary"),
            "severity": db.get("severity"),
            "cwe": (db.get("CWE") or {}).get("id"),
            "last_affected": db.get("last_affected"),
            "fixed_commit": fixed[0] if fixed else None,
        }
    return out


def fetch(client: httpx.Client, rid: str) -> dict | None:
    r = client.get(f"https://hackerone.com/reports/{rid}.json", headers={"Accept": "application/json"})
    if r.status_code != 200:
        return None
    j = r.json()
    body = j.get("vulnerability_information") or ""
    if not body.strip():
        return None
    return {
        "id": rid,
        "url": f"https://hackerone.com/reports/{rid}",
        "title": j.get("title"),
        "created_at": j.get("created_at"),
        "substate": j.get("substate"),
        "weakness": (j.get("weakness") or {}).get("name"),
        "body": body,
    }


def main() -> None:
    slop = slop_ids()
    real = cve_reports()
    print(f"slop ids: {len(slop)}, cve-linked ids: {len(real)}", file=sys.stderr)
    rows = []
    with httpx.Client(timeout=30, follow_redirects=True) as client:
        for label, ids in (("slop", slop), ("real", sorted(real))):
            for rid in ids:
                rec = fetch(client, rid)
                time.sleep(0.4)
                if rec is None:
                    continue
                rec["label"] = label
                if label == "real":
                    rec["cve"] = real[rid]
                rows.append(rec)
                print(f"{label} {rid} {rec['title'][:70]}", file=sys.stderr)
    OUT.write_text("".join(json.dumps(r) + "\n" for r in rows))
    print(f"wrote {len(rows)} rows to {OUT}", file=sys.stderr)


if __name__ == "__main__":
    main()
