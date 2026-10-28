"""Scope check against the project's own written security policy.

Many reports are accurate about the code but describe something the project has said, in writing, is not a
security issue: API misuse, local attackers, debug builds, test code. The project's policy file at the report's
commit is the evidence. The model must quote it, and the quote is checked against the file.
"""

from pathlib import Path

from rapidfuzz import fuzz

from .llm import Ledger, chat_json

POLICY_FILES = ("docs/VULN-DISCLOSURE-POLICY.md", "SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md")

SYSTEM = """You compare one vulnerability report with the project's own written security policy.
Decide whether the policy, as written, says this kind of issue is NOT a security vulnerability.
Only answer "out_of_scope" when a specific section of the policy clearly covers this report, and quote the
sentence from the policy that says so, word for word. If the policy does not clearly cover it, answer "in_scope"
or "unclear". The accuracy of the report is a separate question; judge only scope.
Reply with one JSON object only:
{"scope": "in_scope | out_of_scope | unclear", "section": "policy section title or empty",
 "quote": "exact sentence copied from the policy, or empty", "reason": "one or two sentences"}"""


def policy_text(tree: Path) -> tuple[str, str] | None:
    for name in POLICY_FILES:
        f = tree / name
        if f.is_file():
            return name, f.read_text(errors="replace")
    return None


def quote_in_policy(quote: str, policy: str) -> bool:
    q = " ".join(quote.split())
    return len(q) >= 20 and fuzz.partial_ratio(q, " ".join(policy.split())) >= 90


def policy_from_web(project: str, ledger: Ledger) -> tuple[str, str] | None:
    """Live runs only: a project with no policy file in its tree often publishes one on its site. Tavily search
    finds the page and extract returns the parts about what is and is not a vulnerability. The returned text is
    then the policy the quote is checked against."""
    from . import webtools

    name = project.split("/")[-1]
    res = webtools.search(f"{name} security policy what is not considered a vulnerability", ledger,
                          depth="basic", max_results=3)
    urls = [r["url"] for r in res.get("results", []) if r.get("url")]
    if not urls:
        return None
    page = webtools.extract(urls[:1], ledger, query=f"what the {name} project does and does not consider a "
                                                    "security vulnerability", chunks=5)
    got = [r for r in page.get("results", []) if (r.get("raw_content") or "").strip()]
    return (got[0]["url"], got[0]["raw_content"]) if got else None


def check_scope(tree: Path, title: str, summary: str, analysis: dict | None, ledger: Ledger,
                project: str | None = None, as_of: str | None = None) -> dict:
    found = policy_text(tree)
    if not found and project and not as_of:
        # Not in a replay: the web today may describe a policy written after the report.
        found = policy_from_web(project, ledger)
    if not found:
        return {"scope": "unclear", "reason": "the project has no written security policy in its tree"}
    name, policy = found
    reasoning = (analysis or {}).get("reasoning", "")
    out = chat_json("big", SYSTEM, f"POLICY ({name}):\n{policy[:30000]}\n\nREPORT TITLE: {title}\n\n"
                    f"WHAT THE REPORT CLAIMS: {summary}\n\nWHAT THE CODE SHOWS (static analysis):\n{reasoning[:4000]}",
                    ledger, "scope check", max_tokens=6000, think=True)
    out["policy_file"] = name
    if out.get("scope") == "out_of_scope" and not quote_in_policy(out.get("quote", ""), policy):
        # A policy quote that is not in the file is not evidence.
        out.update(scope="unclear", reason="the quoted policy text is not in the file: " + out.get("reason", ""))
    return out
