"""Every Tavily endpoint SlopProof uses, behind one small interface.

- search: CVEs, prior art, agent web lookups. With as_of (benchmark replay) only pages published before the
  report are used, and hackerone.com is excluded so a report cannot find itself.
- extract: read cited pages; with a query, only the chunks relevant to the claim come back.
- map / crawl: walk a project's own documentation site (security policy, documented behaviour).
- research: Tavily's research agent with a JSON schema, for the hard prior-art question in live runs.
- feedback: after a verdict, tell Tavily which results were used and how useful they were.

map, crawl, extract and research return today's web and cannot be limited to a date, so in a replay (as_of set)
they are refused: a benchmark run must not read write-ups published after the report.
Each call is counted in the run's ledger (credits and an estimated USD at pay-as-you-go prices).
"""

import time

from .llm import Ledger
from .webcheck import tavily

USD_PER_CREDIT = 0.008


class ReplayRefused(Exception):
    """The endpoint returns today's web, which a replay as of the report date must not see."""


def _count(ledger: Ledger | None, tool: str, purpose: str, res: dict, t0: float, fallback: float) -> dict:
    credits = ((res or {}).get("usage") or {}).get("credits", fallback)
    if ledger is not None:
        ledger.add_tool(f"tavily/{tool}", purpose[:160], credits, credits * USD_PER_CREDIT, time.time() - t0)
    return res


def _live_only(as_of: str | None, what: str) -> None:
    if as_of:
        raise ReplayRefused(f"{what} reads today's web; it is off in a replay as of {as_of[:10]}")


def search(query: str, ledger: Ledger | None = None, as_of: str | None = None, *, depth: str = "advanced",
           max_results: int = 6, domains: list[str] | None = None, **kw) -> dict:
    if as_of:
        kw["end_date"] = as_of[:10]
        kw["exclude_domains"] = [*kw.get("exclude_domains", []), "hackerone.com"]
    if domains:
        kw["include_domains"] = domains
    t0 = time.time()
    res = tavily().search(query, search_depth=depth, max_results=max_results, include_usage=True, **kw)
    return _count(ledger, "search", f"search: {query}", res, t0, 2 if depth == "advanced" else 1)


def extract(urls: list[str], ledger: Ledger | None = None, as_of: str | None = None, *, query: str | None = None,
            chunks: int = 3, depth: str = "basic") -> dict:
    _live_only(as_of, "extract")
    kw = {"query": query, "chunks_per_source": chunks} if query else {}
    t0 = time.time()
    res = tavily().extract(urls=urls[:10], extract_depth=depth, format="markdown", include_usage=True, **kw)
    return _count(ledger, "extract", f"extract {len(urls)} page(s)" + (f" for: {query}" if query else ""), res, t0,
                  max(1, len(urls) // 5) * (2 if depth == "advanced" else 1))


def site_map(url: str, ledger: Ledger | None = None, as_of: str | None = None, *, instructions: str | None = None,
             limit: int = 40) -> dict:
    _live_only(as_of, "map")
    t0 = time.time()
    res = tavily().map(url, max_depth=2, limit=limit, instructions=instructions, include_usage=True)
    return _count(ledger, "map", f"map {url}" + (f": {instructions}" if instructions else ""), res, t0, 2)


def crawl(url: str, instructions: str, ledger: Ledger | None = None, as_of: str | None = None, *,
          limit: int = 15, chunks: int = 3) -> dict:
    _live_only(as_of, "crawl")
    t0 = time.time()
    res = tavily().crawl(url, max_depth=2, limit=limit, instructions=instructions, chunks_per_source=chunks,
                         format="markdown", include_usage=True)
    return _count(ledger, "crawl", f"crawl {url}: {instructions}", res, t0, 4)


def research(question: str, schema: dict, ledger: Ledger | None = None, as_of: str | None = None, *,
             model: str = "mini", wait: float = 240) -> dict:
    """Start a Tavily research task and wait for its structured answer (or a timeout)."""
    _live_only(as_of, "research")
    t0 = time.time()
    task = tavily().research(question, model=model, output_schema=schema)
    rid = task.get("request_id")
    res: dict = task
    while rid and time.time() - t0 < wait:
        res = tavily().get_research(rid, include_usage=True)
        if res.get("status") in ("completed", "failed"):
            break
        time.sleep(5)
    return _count(ledger, "research", f"research: {question}", res, t0, 10)


def feedback(request_id: str, score: float, used_urls: list[str], comment: str = "") -> None:
    """Close the loop with Tavily: which results the verdict actually used. Never fails a run."""
    try:
        tavily().feedback(request_id=request_id, agent_score=score, used_urls=used_urls[:20], comment=comment[:500])
    except Exception:  # noqa: BLE001 - feedback is a courtesy to the search provider
        pass
