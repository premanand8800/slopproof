"""Command line: slopproof <report-url> [--repo URL] [--no-sandbox] [--out result.json]"""

import argparse
import json
import sys

from .pipeline import fetch_report, triage


def show(event: dict) -> None:
    stage = event["stage"]
    if stage == "reproduce" and event.get("type") == "run":
        print(f"  $ {event['cmd'][:160]}", file=sys.stderr)
    elif stage == "reproduce" and event.get("type") == "output":
        tail = event["output"].strip().splitlines()[-2:]
        print(f"    -> exit {event['exit_code']}: {' | '.join(tail)[:200]}", file=sys.stderr)
    elif stage == "reproduce" and event.get("type") == "write":
        print(f"  write {event['path']}", file=sys.stderr)
    elif stage == "verdict":
        v = event["verdict"]
        print(f"\n== {v.get('verdict')} ({v.get('confidence')}) {v.get('headline')}", file=sys.stderr)
        print(f"   cost ${event['cost']['total_usd']}, {event['seconds']}s", file=sys.stderr)
    else:
        print(f"[{stage}]", file=sys.stderr)


def main() -> None:
    ap = argparse.ArgumentParser(prog="slopproof")
    ap.add_argument("url", help="HackerOne report or GitHub issue URL")
    ap.add_argument("--repo", help="GitHub repo URL, if it cannot be inferred")
    ap.add_argument("--no-sandbox", action="store_true", help="skip the reproduction step")
    ap.add_argument("--out", help="write the full result JSON here")
    a = ap.parse_args()
    rep = fetch_report(a.url)
    repo = a.repo or rep["repo"]
    if not repo:
        sys.exit("Cannot infer the repository; pass --repo.")
    result = triage(rep["title"], rep["body"], repo, rep["created_at"], run_sandbox=not a.no_sandbox, emit=show)
    if a.out:
        with open(a.out, "w") as f:
            json.dump(result, f, indent=1, default=str)
    print(json.dumps(result["verdict"], indent=1))


if __name__ == "__main__":
    main()
