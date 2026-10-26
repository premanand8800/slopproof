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


def check_scope(tree: Path, title: str, summary: str, analysis: dict | None, ledger: Ledger) -> dict:
    found = policy_text(tree)
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
