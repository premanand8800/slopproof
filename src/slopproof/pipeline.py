"""End-to-end triage of one report. Emits progress events for the UI and CLI."""

import re
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

import httpx

from . import codecheck, webcheck
from .analyze import analyze
from .extract import extract_claims
from .llm import MODELS, Ledger
from .reproduce import reproduce
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

    # Code, reference and prior-art checks are independent, so run them together.
    with ThreadPoolExecutor(max_workers=6) as pool:
        f_code = pool.submit(codecheck.check_code, tree, claims)
        f_cves = [pool.submit(webcheck.check_cve, c, project, claims.get("summary", ""), ledger, as_of)
                  for c in claims["cves"][:4]]
        f_urls = pool.submit(webcheck.check_urls, claims["urls"], claims.get("summary", ""), ledger)
        f_prior = pool.submit(webcheck.prior_art, project, claims, ledger, as_of)
        code = f_code.result()
        emit({"stage": "code", "code": code})
        web = {"cves": [f.result() for f in f_cves], "urls": f_urls.result(), "prior_art": f_prior.result()}
        emit({"stage": "web", "web": web})

    context = codecheck.code_context(tree, code)
    analysis = analyze(title, body, claims, context, ledger)
    emit({"stage": "analysis", "analysis": analysis})

    repro = None
    if run_sandbox:
        emit({"stage": "reproduce", "type": "begin"})
        repro = reproduce(tree, project, f"{title}\n\n{body}", claims, analysis, context, ledger, emit)

    evidence = {"claims": claims, "ref": ref, "code_checks": code, "web_checks": web, "static_analysis": analysis,
                "reproduction": {k: v for k, v in (repro or {}).items() if k != "transcript"} or "not run"}
    verdict = apply_guards(decide(title, body, evidence, ledger), analysis, repro)
    result = {"title": title, "project": project, "ref": ref, "claims": claims, "code": code, "web": web,
              "analysis": analysis, "reproduction": repro, "verdict": verdict, "cost": ledger.summary(), "ledger": ledger.calls,
              "seconds": round(time.time() - t0, 1)}
    emit({"stage": "verdict", "verdict": verdict, "cost": result["cost"], "seconds": result["seconds"]})
    return result


def apply_guards(verdict: dict, analysis: dict | None, repro: dict | None) -> dict:
    """Hard rules the model cannot override.

    CONFIRMED needs a sandbox reproduction. Closing (NOT_REPRODUCED, FABRICATED) needs the code to rule the
    claim out, or a sandbox run that exercised it without the bug. Wrong file names, invented snippets or a
    similar old CVE are common in real reports too, so on their own they only lower the priority.
    """
    v = dict(verdict)
    v["model_verdict"] = verdict.get("verdict")
    outcome = (repro or {}).get("outcome")
    code_rules_out = (analysis or {}).get("claim_holds") == "no"
    if v["model_verdict"] == "CONFIRMED" and outcome != "reproduced":
        v["verdict"] = "PLAUSIBLE"
        v["headline"] = "[Not yet reproduced] " + v.get("headline", "")
    elif v["model_verdict"] in ("NOT_REPRODUCED", "FABRICATED") and not (code_rules_out or outcome == "not_reproduced"):
        v["verdict"] = "PLAUSIBLE"
        v["priority"] = "low"
        v["headline"] = "[Low priority: references look wrong, but nothing rules the claim out yet] " + v.get("headline", "")
    if outcome == "reproduced":
        v["verdict"] = "CONFIRMED"
    return v
