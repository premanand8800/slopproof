"""End-to-end triage of one report. Emits progress events for the UI and CLI."""

import re
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

import httpx

from . import codecheck, codesearch, webcheck
from .analyze import analyze
from .extract import extract_claims
from .llm import MODELS, Ledger
from .reproduce import reproduce
from .screen import screen
from .verdict import decide


def fetch_report(url: str) -> dict:
    """Load a public HackerOne report or GitHub issue."""
    if m := re.search(r"hackerone\.com/reports/(\d+)", url):
        j = httpx.get(f"https://hackerone.com/reports/{m.group(1)}.json", headers={"Accept": "application/json"},
                      timeout=30, follow_redirects=True).json()
        repo = "https://github.com/curl/curl" if (j.get("team") or {}).get("handle") == "curl" else None
        return {"title": j.get("title", ""), "body": j.get("vulnerability_information", ""),
                "created_at": j.get("created_at"), "repo": repo, "url": url}
    if m := re.search(r"github\.com/([^/]+)/([^/]+)/issues/(\d+)", url):
        j = httpx.get(f"https://api.github.com/repos/{m.group(1)}/{m.group(2)}/issues/{m.group(3)}", timeout=30).json()
        return {"title": j.get("title", ""), "body": j.get("body") or "", "created_at": j.get("created_at"),
                "repo": f"https://github.com/{m.group(1)}/{m.group(2)}", "url": url}
    raise ValueError("Paste a hackerone.com/reports/<id> or github.com/<owner>/<repo>/issues/<n> URL, or the report text.")


def triage(title: str, body: str, repo_url: str, created_at: str | None = None,
           run_sandbox: bool = True, emit: Callable[[dict], None] = lambda e: None,
           replay: bool = False) -> dict:
    """Triage one report.

    replay=True is for the benchmark: web evidence is limited to pages published before the report,
    so a later CVE write-up cannot leak the answer.
    """
    as_of = created_at if replay else None
    ledger = Ledger()
    t0 = time.time()
    project = "/".join(codecheck.repo_slug(repo_url).split("__"))
    emit({"stage": "start", "models": MODELS, "project": project})

    claims = extract_claims(title, body, ledger)
    emit({"stage": "claims", "claims": claims})

    bare = codecheck.ensure_repo(repo_url)
    ref = codecheck.resolve_ref(bare, claims, created_at)
    ref["version_tag"] = codecheck.version_tag(bare, claims.get("claimed_version"))
    tree = codecheck.export_tree(bare, ref["sha"])
    emit({"stage": "ref", "ref": ref})

    # Code, reference and prior-art checks and the text screen are independent, so run them together.
    with ThreadPoolExecutor(max_workers=6) as pool:
        f_screen = pool.submit(screen, title, body, project.split("/")[-1], ledger)
        f_code = pool.submit(codecheck.check_code, tree, claims, bare, ref["sha"])
        f_search = pool.submit(codesearch.find_code, bare, ref["sha"], title, body, claims)
        f_cves = [pool.submit(webcheck.check_cve, c, project, claims.get("summary", ""), ledger, as_of)
                  for c in claims["cves"][:4]]
        f_urls = pool.submit(webcheck.check_urls, claims["urls"], claims.get("summary", ""), ledger)
        f_prior = pool.submit(webcheck.prior_art, project, claims, ledger, as_of)
        code = f_code.result()
        emit({"stage": "code", "code": code})
        web = {"cves": [_settled(f, {"supported": False, "explanation": "CVE check failed"}) for f in f_cves],
               "urls": _settled(f_urls, []),
               "prior_art": _settled(f_prior, {"known_issue": False, "already_fixed": False,
                                               "documented_behaviour": False, "explanation": "prior-art check failed"})}
        emit({"stage": "web", "web": web})
        text_screen = _settled(f_screen, {"close": False, "confidence": None, "reason": "screen failed"})
        emit({"stage": "screen", "screen": text_screen})

    found = f_search.result()
    emit({"stage": "search", "found": found})
    context = codecheck.code_context(tree, code, found)
    analysis = analyze(title, body, claims, context, ledger)
    emit({"stage": "analysis", "analysis": analysis})

    repro = None
    if run_sandbox:
        emit({"stage": "reproduce", "type": "begin"})
        repro = reproduce(tree, project, f"{title}\n\n{body}", claims, analysis, context, ledger, emit,
                          repo_url=repo_url, sha=ref["sha"])

    evidence = {"claims": claims, "ref": ref, "code_checks": code, "web_checks": web, "static_analysis": analysis,
                "reproduction": {k: v for k, v in (repro or {}).items() if k != "transcript"} or "not run"}
    # The screen's vote is kept out of the evidence so the verdict model stays an independent second vote.
    verdict = apply_guards(decide(title, body, evidence, ledger), analysis, repro, web, text_screen)
    result = {"title": title, "project": project, "ref": ref, "claims": claims, "code": code, "web": web,
              "screen": text_screen, "search": found,
              "analysis": analysis, "reproduction": repro, "verdict": verdict, "cost": ledger.summary(), "ledger": ledger.calls,
              "seconds": round(time.time() - t0, 1)}
    emit({"stage": "verdict", "verdict": verdict, "cost": result["cost"], "seconds": result["seconds"]})
    return result


def _settled(future, fallback):
    """A supporting check that fails (a model that returned no JSON, a search timeout) must not sink the triage:
    it falls back to a neutral result that can never close a report on its own."""
    try:
        return future.result()
    except Exception as e:  # noqa: BLE001 - any failure of an optional check degrades the same way
        return fallback | {"error": str(e)[:200]} if isinstance(fallback, dict) else fallback


def apply_guards(verdict: dict, analysis: dict | None, repro: dict | None, web: dict | None = None,
                 text_screen: dict | None = None) -> dict:
    """Hard rules the model cannot override.

    CONFIRMED needs a sandbox reproduction. Closing (NOT_REPRODUCED, FABRICATED) needs one of:
    a sandbox run exercised the claim without the bug, the text screen independently votes to close,
    or the code rules the claim out. Wrong file names, invented snippets or a similar old CVE are common in
    real reports too, so on their own they only lower the priority.
    Reading the code is not enough when prior art shows the same area had a real bug: the report may be a
    bypass or regression of that fix.
    """
    v = dict(verdict)
    v["model_verdict"] = verdict.get("verdict")
    outcome = (repro or {}).get("outcome")
    prior = (web or {}).get("prior_art") or {}
    known_area = bool(prior.get("known_issue") or prior.get("already_fixed"))
    screen_close = bool((text_screen or {}).get("close"))
    code_rules_out = (analysis or {}).get("claim_holds") == "no"
    may_close = outcome == "not_reproduced" or screen_close or (code_rules_out and not known_area)
    if v["model_verdict"] == "CONFIRMED" and outcome != "reproduced":
        v["verdict"] = "PLAUSIBLE"
        v["headline"] = "[Not yet reproduced] " + v.get("headline", "")
    elif v["model_verdict"] in ("NOT_REPRODUCED", "FABRICATED") and not may_close:
        v["verdict"] = "PLAUSIBLE"
        v["priority"] = "low"
        why = ("a related bug was fixed before, so this may be a bypass; reproduce before closing" if known_area
               else "references look wrong, but nothing rules the claim out yet")
        v["headline"] = f"[Low priority: {why}] " + v.get("headline", "")
    elif v["verdict"] == "PLAUSIBLE" and screen_close:
        v["priority"] = "low"
        v["headline"] = "[Low priority: the text screen flags this as likely slop; checks found no proof either way] " \
            + v.get("headline", "")
    if outcome == "reproduced":
        v["verdict"] = "CONFIRMED"
        v.pop("priority", None)
    return v
