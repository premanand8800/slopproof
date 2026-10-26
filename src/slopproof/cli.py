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


def verify_main(argv: list[str]) -> None:
    from .bundle import load, verify

    ap = argparse.ArgumentParser(prog="slopproof verify",
                                 description="Re-run a proof bundle in a fresh sandbox. No model is used.")
    ap.add_argument("bundle", help="path to a proof bundle JSON")
    ap.add_argument("--against", help="also run it at this commit or tag, e.g. the fix, where the bug should be gone")
    a = ap.parse_args(argv)
    res = verify(load(a.bundle), a.against, emit=lambda m: print(m, file=sys.stderr))
    for problem in res.get("problems", []):
        print(f"warning: {problem}", file=sys.stderr)
    for key, label in (("at_commit", "bundle commit"), ("at_against", a.against)):
        r = res.get(key)
        if r:
            state = "bug present" if r.get("bug_present") else "build failed" if not r.get("built") else "bug absent"
            print(f"{label} {r['commit'][:12]}: {state} ({r.get('seconds')}s)")
    print(res["verdict"])
    sys.exit(0 if res["verdict"].startswith("VERIFIED") else 1)


def main() -> None:
    if sys.argv[1:2] == ["verify"]:
        return verify_main(sys.argv[2:])
    ap = argparse.ArgumentParser(prog="slopproof")
    ap.add_argument("url", help="HackerOne report or GitHub issue URL (or: slopproof verify BUNDLE)")
    ap.add_argument("--repo", help="GitHub repo URL, if it cannot be inferred")
    ap.add_argument("--no-sandbox", action="store_true", help="skip the reproduction step")
    ap.add_argument("--out", help="write the full result JSON here")
    ap.add_argument("--markdown", help="write a Markdown triage summary here (for an issue comment)")
    ap.add_argument("--bundle", help="if the bug is reproduced, write its proof bundle here")
    a = ap.parse_args()
    rep = fetch_report(a.url)
    repo = a.repo or rep["repo"]
    if not repo:
        sys.exit("Cannot infer the repository; pass --repo.")
    result = triage(rep["title"], rep["body"], repo, rep["created_at"], run_sandbox=not a.no_sandbox, emit=show)
    if a.out:
        with open(a.out, "w") as f:
            json.dump(result, f, indent=1, default=str)
    bundle = (result.get("reproduction") or {}).get("bundle")
    if a.bundle and bundle:
        with open(a.bundle, "w") as f:
            json.dump(bundle, f, indent=1)
    if a.markdown:
        with open(a.markdown, "w") as f:
            f.write(to_markdown(result))
    print(json.dumps(result["verdict"], indent=1))


def to_markdown(r: dict) -> str:
    v = r["verdict"]
    icon = {"CONFIRMED": "🔴", "PLAUSIBLE": "🟡", "NOT_REPRODUCED": "🟢", "FABRICATED": "🟣"}.get(v["verdict"], "")
    lines = [f"### {icon} SlopProof: {v['verdict']} ({round(100 * (v.get('confidence') or 0))}% confidence)", "",
             f"**{v.get('headline', '')}**", ""]
    for f in v.get("findings", []):
        mark = {"confirmation": "✅", "contradiction": "❌"}.get(f.get("kind"), "❔")
        lines.append(f"- {mark} {f.get('text', '')}")
    repro = r.get("reproduction") or {}
    if repro:
        lines += ["", f"<details><summary>Sandbox reproduction: {repro.get('outcome')} "
                      f"({repro.get('steps')} steps, {repro.get('seconds')}s)</summary>", "",
                  repro.get("explanation", ""), "", "```", (repro.get("evidence") or "")[:3000], "```", "</details>"]
    if repro.get("bundle"):
        lines += ["", f"**Proof bundle** `sha256:{repro['bundle']['sha256'][:16]}`: "
                      f"{(repro.get('bundle_verification') or {}).get('verdict', 'not verified')} in a fresh sandbox. "
                      "Re-run it with `slopproof verify bundle.json`."]
    lines += ["", "<details><summary>Suggested reply to the reporter</summary>", "", v.get("maintainer_comment", ""),
              "</details>", "",
              f"<sub>Source tree {r['ref']['sha'][:12]} · cost ${r['cost']['total_usd']:.3f} · "
              f"NVIDIA Nemotron on Nebius Token Factory · Tavily</sub>"]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    main()
