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
    return {"query": q, "results": hits[:4], **judged}
