"""Check a report's external references and prior art with Tavily."""

import os
import re

from tavily import TavilyClient

from .llm import Ledger, chat_json

_tv: TavilyClient | None = None


def tavily() -> TavilyClient:
    global _tv
    if _tv is None:
        _tv = TavilyClient(api_key=os.environ["TAVILY_API_KEY"])
    return _tv


JUDGE = """You check whether web evidence supports a claim made in a security report.
Reply with one JSON object only:
{"supported": true or false, "explanation": "one or two sentences citing what the evidence says", "evidence_url": "best URL or null"}"""


def _search(query: str, as_of: str | None, **kw) -> dict:
    """Tavily search. With as_of (benchmark replay) only pages published before the report are used."""
    if as_of:
        kw["end_date"] = as_of[:10]
        kw["exclude_domains"] = ["hackerone.com"]
    return tavily().search(query, **kw)


def check_cve(cve: str, project: str, report_summary: str, ledger: Ledger, as_of: str | None = None) -> dict:
    res = _search(f"{cve} {project}", as_of, max_results=5, search_depth="advanced")
    hits = [{"url": r["url"], "title": r["title"], "snippet": r["content"][:500]} for r in res.get("results", [])]
    evidence = "\n\n".join(f"[{h['url']}] {h['title']}\n{h['snippet']}" for h in hits) or "no results"
    judged = chat_json("mid", JUDGE,
                       f"Report claims {cve} is relevant to this issue in {project}: {report_summary}\n\n"
                       f"Does the evidence show that {cve} exists, affects {project}, and is the same issue the "
                       f"report describes (or is it an old, already fixed issue the report is recycling)?\n\nEVIDENCE:\n{evidence}",
                       ledger, f"judge {cve}", max_tokens=1500)
    return {"cve": cve, "results": hits[:3], **judged}


def check_urls(urls: list[str], report_summary: str, ledger: Ledger) -> list[dict]:
    urls = [u for u in dict.fromkeys(urls) if re.match(r"https?://", u)][:6]
    if not urls:
        return []
    res = tavily().extract(urls=urls)
    found = {r["url"]: r.get("raw_content") or "" for r in res.get("results", [])}
    failed = {f["url"] for f in res.get("failed_results", [])}
    out = []
    for u in urls:
        if u in failed or u not in found:
            out.append({"url": u, "reachable": False, "supports_claim": None, "explanation": "page could not be fetched"})
            continue
        # GitHub source links are verified against the real tree in codecheck; here we only confirm the page exists.
        if "github.com" in u and "/blob/" in u:
            out.append({"url": u, "reachable": True, "supports_claim": None, "explanation": "source link, checked against code"})
            continue
        judged = chat_json("mid", JUDGE,
                           f"Report claim: {report_summary}\nThe report cites {u} as support.\n\nPAGE TEXT:\n{found[u][:6000]}",
                           ledger, "judge url", max_tokens=1500)
        out.append({"url": u, "reachable": True, "supports_claim": judged.get("supported"),
                    "explanation": judged.get("explanation")})
    return out


CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)

CVE_FACT = """You check one CVE identifier against web evidence. Reply with one JSON object only:
{"exists": true or false, "affects_project": true or false, "same_issue": true or false,
 "summary": "what the CVE is about according to the evidence, one sentence, or empty"}
affects_project is true only if the evidence says this CVE is in the named project itself.
same_issue is true only if the evidence describes the same bug as the report (same component and same flaw)."""


def verify_cve(cve: str, project: str, ledger: Ledger, as_of: str | None = None, report_summary: str = "") -> dict:
    """Does this CVE exist, and is it about this project? Used for CVEs a model names, not the report."""
    res = _search(cve, as_of, max_results=5)
    hits = [{"url": r["url"], "title": r["title"], "snippet": r["content"][:400]} for r in res.get("results", [])]
    evidence = "\n\n".join(f"[{h['url']}] {h['title']}\n{h['snippet']}" for h in hits) or "no results"
    judged = chat_json("mid", CVE_FACT, f"CVE: {cve}\nProject: {project}\nReport: {report_summary}\n\nEVIDENCE:\n{evidence}",
                       ledger, f"verify {cve}", max_tokens=800)
    url = hits[0]["url"] if hits else None
    return {"cve": cve.upper(), "exists": bool(judged.get("exists")), "affects_project": bool(judged.get("affects_project")),
            "same_issue": bool(judged.get("same_issue")), "summary": judged.get("summary", ""), "evidence_url": url}


def prior_art(project: str, claims: dict, ledger: Ledger, as_of: str | None = None) -> dict:
    """Search for the same issue already reported, fixed, or documented as intended behaviour."""
    q = f"{project} {claims.get('vuln_class', '')} {' '.join(claims.get('functions', [])[:2])} {claims.get('summary', '')}"[:380]
    res = _search(q, as_of, max_results=6, search_depth="advanced")
    hits = [{"url": r["url"], "title": r["title"], "snippet": r["content"][:400]} for r in res.get("results", [])]
    evidence = "\n\n".join(f"[{h['url']}] {h['title']}\n{h['snippet']}" for h in hits) or "no results"
    judged = chat_json("mid", """You look for prior art on a security report. Reply with one JSON object only:
{"known_issue": true or false, "already_fixed": true or false, "documented_behaviour": true or false,
 "explanation": "one or two sentences", "evidence_url": "best URL or null"}""",
                       f"Project: {project}\nReport summary: {claims.get('summary')}\n\nSEARCH RESULTS:\n{evidence}",
                       ledger, "prior art", max_tokens=1500)
    out = {"query": q, "results": hits[:4], **judged}
    # A CVE the judge names is a claim too: check that it exists and is about this project before it is used.
    named = sorted({c.upper() for c in CVE_RE.findall(judged.get("explanation") or "")})[:2]
    if named:
        checks = [verify_cve(c, project, ledger, as_of, claims.get("summary", "")) for c in named]
        out["cve_checks"] = checks
        bad = [c["cve"] for c in checks if not (c["exists"] and c["affects_project"] and c["same_issue"])]
        if bad:
            out["explanation"] = (CVE_RE.sub(lambda m: m.group(0) if m.group(0).upper() not in bad else "[unverified CVE]",
                                             out.get("explanation") or "")
                                  + f" ({', '.join(bad)} could not be confirmed as this {project} issue and was dropped.)")
            if len(bad) == len(checks):
                # The judge's prior art rested on CVEs that are not this issue: none of it stands.
                why = "; ".join(f"{c['cve']}: {c['summary'] or 'not found'}" for c in checks)
                out.update(known_issue=False, already_fixed=False, evidence_url=None,
                           explanation=f"No confirmed prior report of this issue. The search pointed to {why}, "
                                       f"which is not the issue reported.")
    return out
