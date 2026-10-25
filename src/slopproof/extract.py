"""Turn a free-text report into checkable claims."""

from .llm import Ledger, chat_json

SYSTEM = """You read vulnerability and bug reports filed against open source projects.
Extract every concrete, checkable claim. Do not judge the report. Copy code exactly as the report quotes it.
Reply with one JSON object only, with these keys:
{
  "summary": "one sentence: what the reporter says is wrong",
  "vuln_class": "e.g. heap overflow, use-after-free, format string, logic bug, DoS",
  "claimed_version": "version string or null",
  "claimed_commit": "commit hash if the report links one, else null",
  "files": ["source file paths the report names, e.g. lib/ws.c"],
  "functions": ["function or macro names the report says are vulnerable"],
  "line_refs": [{"file": "lib/ws.c", "line": 581}],
  "code_quotes": [{"file": "lib/ws.c or null", "role": "project_code | suggested_fix | poc | other", "code": "code exactly as quoted in the report"}],
  "cves": ["CVE ids the report cites"],
  "urls": ["URLs the report cites, excluding the project homepage"],
  "repro_steps": ["concrete steps or commands the reporter gives"],
  "has_poc": true or false,
  "attack_surface": "how an attacker reaches the code: network input, CLI flag, API call, local file, env var, test code only, none stated"
}"""


def extract_claims(title: str, body: str, ledger: Ledger) -> dict:
    user = f"REPORT TITLE: {title}\n\nREPORT BODY:\n{body[:24000]}"
    try:
        claims = chat_json("fast", SYSTEM, user, ledger, "extract claims", max_tokens=6000)
    except ValueError:
        # Long reports with big code blocks sometimes break the small model's JSON; Super is steadier.
        claims = chat_json("mid", SYSTEM, user, ledger, "extract claims (fallback)", max_tokens=10000)
    for key in ("files", "functions", "line_refs", "code_quotes", "cves", "urls", "repro_steps"):
        if not isinstance(claims.get(key), list):
            claims[key] = []
    return claims
