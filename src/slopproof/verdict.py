"""Final triage decision from all collected evidence."""

import json

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

Reply with one JSON object only:
{
  "verdict": "CONFIRMED | PLAUSIBLE | NOT_REPRODUCED | FABRICATED",
  "confidence": 0.0 to 1.0,
  "headline": "one sentence a maintainer reads first",
  "findings": [{"kind": "contradiction | confirmation | missing", "text": "specific fact with file:line or URL"}],
  "maintainer_comment": "a short, polite, factual reply that could be posted on the report, citing the evidence"
}"""


def decide(report_title: str, report_body: str, evidence: dict, ledger: Ledger) -> dict:
    user = (f"REPORT TITLE: {report_title}\n\nREPORT BODY:\n{report_body[:12000]}\n\n"
            f"EVIDENCE:\n{json.dumps(evidence, indent=1, default=str)[:30000]}")
    return chat_json("big", SYSTEM, user, ledger, "verdict", max_tokens=12000, think=True)
