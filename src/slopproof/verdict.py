"""Final triage decision from all collected evidence."""

import json
import re

from .llm import Ledger, chat_json

SYSTEM = """You are the final triage step for vulnerability reports sent to an open source project.
You receive the report, the claims extracted from it, checks of those claims against the real source tree,
web checks of the references it cites, prior-art search results, and (if it ran) a sandbox reproduction attempt.

Decide one verdict:
- "CONFIRMED": the sandbox reproduced the bug through a real code path.
- "PLAUSIBLE": not reproduced, but the claims check out against the code and nothing contradicts them. A human must look.
- "NOT_REPRODUCED": the reproduction exercised the claimed path and the bug did not occur, or the code shows it is impossible.
- "FABRICATED": the report rests on things that do not exist: invented code, functions, files, CVEs or sources,
  or it recycles an old fixed issue as new.

A similar CVE fixed earlier does not make a report a duplicate: it may be a bypass of that fix, and the code
you were given is from the report's date, after the fix. Judge whether the claim holds in THIS code.
"Documented behaviour" or "known limitation" is not a reason to close a security claim on its own.
Real reporters often get file or function names slightly wrong; a near-miss name is not fabrication.
Behaviour the project allows anyway is not a vulnerability: reaching a resource through an unusual spelling is no
issue if the user could request the same resource directly. Ask what the attacker gains over intended use.

Important: AI-assisted writing style is NOT evidence either way. Many real vulnerabilities are now found with AI tools.
Judge only verifiable facts. Never mark a report FABRICATED or NOT_REPRODUCED unless specific evidence supports it;
when in doubt choose PLAUSIBLE, because closing a real vulnerability is far worse than spending a maintainer's time.

Confidence must match the evidence: without a sandbox reproduction, a bug that depends on what callers pass or
what lies past a buffer is at most "plausible", never "confirmed" or "sound", and the reply says what is still open.
The maintainer_comment is posted by the maintainer, so it states only what the evidence shows and what is still
needed from the reporter. Never promise fixes, tests, releases, timelines or any other action on the maintainer's
behalf. Mention a CVE only if it appears in the report or in a verified check in the evidence. Do not suggest that a fix
regressed or was dropped unless verified evidence shows the issue was fixed before. When the analysis lists callers,
say which ones allow the bug and which block it.

Reply with one JSON object only:
{
  "verdict": "CONFIRMED | PLAUSIBLE | NOT_REPRODUCED | FABRICATED",
  "confidence": 0.0 to 1.0,
  "headline": "one sentence a maintainer reads first",
  "findings": [{"kind": "contradiction | confirmation | missing", "text": "specific fact with file:line or URL"}],
  "maintainer_comment": "a short, polite, factual reply that could be posted on the report, citing the evidence"
}"""


CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def allowed_cves(report_text: str, web: dict) -> set[str]:
    """CVEs a reply may mention: cited by the report itself, or checked and found to be about this project."""
    ok = {c.upper() for c in CVE_RE.findall(report_text)}
    for c in (web.get("prior_art") or {}).get("cve_checks", []):
        if c.get("exists") and c.get("affects_project") and c.get("same_issue"):
            ok.add(c["cve"].upper())
    return ok


def scrub_cves(verdict: dict, allowed: set[str]) -> dict:
    """Remove sentences and findings that name a CVE nobody verified: a wrong CVE in a posted reply is exactly
    the kind of confident error SlopProof exists to prevent."""
    def bad(text: str) -> bool:
        return any(c.upper() not in allowed for c in CVE_RE.findall(text or ""))

    def clean(text: str) -> str:
        sentences = re.split(r"(?<=[.!?])\s+", text or "")
        return " ".join(x for x in sentences if not bad(x))

    v = dict(verdict)
    dropped = [c for c in CVE_RE.findall(json.dumps(verdict)) if c.upper() not in allowed]
    v["findings"] = [f for f in v.get("findings", []) if not bad(f.get("text", ""))]
    # The reply is the maintainer's to send: no promises of fixes, tests or timelines made on their behalf.
    promise = re.compile(r"\b(we|i|our team|the team|maintainers)\s*('ll|will|shall|plan to|intend to|are going to|aim to)\b", re.I)
    v["maintainer_comment"] = " ".join(x for x in re.split(r"(?<=[.!?])\s+", clean(v.get("maintainer_comment", "")))
                                       if not promise.search(x.strip()))
    if bad(v.get("headline", "")):
        v["headline"] = clean(v["headline"]) or "Evidence summary below."
    if dropped:
        v["scrubbed_cves"] = sorted({c.upper() for c in dropped})
    return v


def decide(report_title: str, report_body: str, evidence: dict, ledger: Ledger) -> dict:
    user = (f"REPORT TITLE: {report_title}\n\nREPORT BODY:\n{report_body[:12000]}\n\n"
            f"EVIDENCE:\n{json.dumps(evidence, indent=1, default=str)[:30000]}")
    return chat_json("big", SYSTEM, user, ledger, "verdict", max_tokens=12000, think=True)
