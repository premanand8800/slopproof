"""End-to-end triage of one report. Emits progress events for the UI and CLI."""

import re
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

import httpx

from . import codecheck, codesearch, memory, webcheck
from .analyze import analyze_deep
from .extract import extract_claims
from .llm import MODELS, Ledger
from .reproduce import reproduce
from .scope import check_scope
from .screen import screen
from .verdict import allowed_cves, decide, scrub_cves


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
           replay: bool = False, resume: dict | None = None, run_id: str | None = None) -> dict:
    """Triage one report.

    replay=True is for the benchmark: web evidence is limited to pages published before the report,
    so a later CVE write-up cannot leak the answer.
    resume holds results of an earlier, unfinished run of the same report (as saved in its events); those steps
    are not run again, which is how a run cut off by a rate limit or a restart continues where it stopped.
    """
    as_of = created_at if replay else None
    done = resume or {}
    ledger = Ledger()
    t0 = time.time()
    project = "/".join(codecheck.repo_slug(repo_url).split("__"))
    emit({"stage": "start", "models": MODELS, "project": project, "resumed": sorted(done)})

    def step(key: str, stage: str, field: str, compute: Callable[[], object]):
        """Reuse a saved result, or compute it; either way emit it so the run's timeline is complete."""
        value = done[key] if key in done else compute()
        emit({"stage": stage, field: value, **({"restored": True} if key in done else {})})
        emit({"stage": "cost", "usd": ledger.summary()["total_usd"]})
        return value

    claims = step("claims", "claims", "claims", lambda: extract_claims(title, body, ledger))
    bare = codecheck.ensure_repo(repo_url)

    def resolve():
        r = codecheck.resolve_ref(bare, claims, created_at)
        r["version_tag"] = tag = codecheck.version_tag(bare, claims.get("claimed_version"))
        if tag and r["why"].startswith("default branch HEAD"):
            # A pasted report with no date or commit but a version: check the code of that release, not today's.
            r = {"sha": codecheck.git(bare, "rev-parse", f"{tag}^{{commit}}").strip(),
                 "why": f"release {tag} named in the report (no date or commit)", "version_tag": tag}
        return r
    ref = step("ref", "ref", "ref", resolve)
    tree = codecheck.export_tree(bare, ref["sha"])

    # What earlier runs on this project taught: build recipes, caller facts, lessons. Leads only.
    recalled = memory.recall(project, bare, ref["sha"], {"files": claims.get("files", []),
                                                        "functions": claims.get("functions", []),
                                                        "summary": claims.get("summary", "")})
    if recalled and any(recalled.values()):
        memory.mark_used(recalled)
        emit({"stage": "memory", "recalled": {
            "skills": [{"kind": s["kind"], "title": s["title"], "successes": s["successes"]} for s in recalled["skills"]],
            "facts": [{"subject": f["subject"], "text": f["text"], "stale": f["stale"], "source": f["source"]}
                      for f in recalled["facts"]],
            "lessons": [{"text": x["text"], "source": x["source"]} for x in recalled["lessons"]]}})

    # Code, reference and prior-art checks and the text screen are independent, so run them together.
    with ThreadPoolExecutor(max_workers=6) as pool:
        need = lambda key: key not in done  # noqa: E731
        f_screen = pool.submit(screen, title, body, project.split("/")[-1], ledger) if need("screen") else None
        f_code = pool.submit(codecheck.check_code, tree, claims, bare, ref["sha"]) if need("code") else None
        f_search = pool.submit(codesearch.find_code, bare, ref["sha"], title, body, claims) if need("search") else None
        if need("web"):
            f_cves = [pool.submit(webcheck.check_cve, c, project, claims.get("summary", ""), ledger, as_of)
                      for c in claims["cves"][:4]]
            f_urls = pool.submit(webcheck.check_urls, claims["urls"], claims.get("summary", ""), ledger)
            f_prior = pool.submit(webcheck.prior_art, project, claims, ledger, as_of)
        code = step("code", "code", "code", lambda: f_code.result())
        web = step("web", "web", "web", lambda: {
            "cves": [_settled(f, {"supported": False, "explanation": "CVE check failed"}) for f in f_cves],
            "urls": _settled(f_urls, []),
            "prior_art": _settled(f_prior, {"known_issue": False, "already_fixed": False,
                                            "documented_behaviour": False, "explanation": "prior-art check failed"})})
        text_screen = step("screen", "screen", "screen",
                           lambda: _settled(f_screen, {"close": False, "confidence": None, "reason": "screen failed"}))
        found = step("search", "search", "found", lambda: f_search.result())

    context = codecheck.code_context(tree, code, found)
    if recalled:
        context += "\n\n" + memory.as_prompt(recalled)
    # The callers of the code in question: whether they bound lengths or NUL-terminate decides many reports.
    keys = list(dict.fromkeys([f["name"] for f in code.get("functions", []) if f.get("exists")][:2]
                              + [h["name"] for h in (found or [])[:1]]))
    reach = codesearch.callers(bare, ref["sha"], keys) if keys else ""
    if reach:
        context += f"\n\n=== Who calls this code (lines around each call, up to three levels)\n{reach}"
    analysis = step("analysis", "analysis", "analysis", lambda: analyze_deep(
        title, body, claims, context, ledger, lambda names: codesearch.definitions(bare, ref["sha"], names)))

    def policy_check():
        # The project's written policy, quoted for the maintainer. Shown only: in our benchmark curl issued CVEs
        # for a few reports its own policy lists as not security issues, so it never decides a verdict.
        try:
            return check_scope(tree, title, claims.get("summary", ""), analysis, ledger)
        except Exception as e:  # noqa: BLE001 - informative only
            return {"scope": "unclear", "reason": f"policy check failed: {str(e)[:200]}"}
    policy = step("scope", "scope", "scope", policy_check)

    repro = done.get("reproduction")
    if run_sandbox and repro is None:
        emit({"stage": "reproduce", "type": "begin"})
        builds = [s["body"] for s in (recalled or {}).get("skills", []) if s["kind"] == "build"]
        repro = reproduce(tree, project, f"{title}\n\n{body}", claims, analysis, context, ledger, emit,
                          repo_url=repo_url, sha=ref["sha"], remembered_build=builds[0] if builds else None)
        # Saved apart from the step-by-step events, so a resumed run can reuse it without the transcript.
        emit({"stage": "checkpoint", "key": "reproduction", "value": {k: v for k, v in repro.items() if k != "transcript"}})
    elif repro is not None:
        emit({"stage": "reproduce", "type": "finish", "outcome": repro.get("outcome"), "restored": True,
              "bundle": (repro.get("bundle_verification") or {}).get("verdict")})

    evidence = {"claims": claims, "ref": ref, "code_checks": code, "web_checks": web, "static_analysis": analysis,
                "reproduction": {k: v for k, v in (repro or {}).items() if k != "transcript"} or "not run"}
    # The screen's vote is kept out of the evidence so the verdict model stays an independent second vote.
    raw = scrub_cves(decide(title, body, evidence, ledger), allowed_cves(f"{title}\n{body}", web))
    verdict = apply_guards(raw, analysis, repro, web, text_screen)
    result = {"title": title, "project": project, "ref": ref, "claims": claims, "code": code, "web": web,
              "screen": text_screen, "search": found, "scope": policy,
              "analysis": analysis, "reproduction": repro, "verdict": verdict, "cost": ledger.summary(), "ledger": ledger.calls,
              "seconds": round(time.time() - t0, 1)}
    try:
        learned = memory.consolidate(run_id or f"run-{int(t0)}", result, bare, repo_url)
    except Exception as e:  # noqa: BLE001 - memory is a help, never a reason for a run to fail
        learned = {"error": str(e)[:200]}
    if learned:
        emit({"stage": "memory", "learned": learned})
    emit({"stage": "verdict", "verdict": verdict, "cost": result["cost"], "seconds": result["seconds"]})
    return result


def resume_from_events(events: list[dict]) -> dict:
    """The finished steps of an earlier run, read back from its saved events."""
    fields = {"claims": "claims", "ref": "ref", "code": "code", "web": "web", "screen": "screen",
              "search": "found", "analysis": "analysis", "scope": "scope"}
    done = {}
    for ev in events:
        if ev.get("stage") in fields and fields[ev["stage"]] in ev:
            done[ev["stage"]] = ev[fields[ev["stage"]]]
        if ev.get("stage") == "checkpoint" and ev.get("key") == "reproduction":
            done["reproduction"] = ev["value"]
    return done


def _settled(future, fallback):
    """A supporting check that fails (a model that returned no JSON, a search timeout) must not sink the triage:
    it falls back to a neutral result that can never close a report on its own."""
    try:
        return future.result()
    except Exception as e:  # noqa: BLE001 - any failure of an optional check degrades the same way
        return fallback | {"error": str(e)[:200]} if isinstance(fallback, dict) else fallback


# The text screen's confidence at or above which its vote to keep a report open blocks a close on code alone.
SCREEN_DISSENT = 0.8


def apply_guards(verdict: dict, analysis: dict | None, repro: dict | None, web: dict | None = None,
                 text_screen: dict | None = None) -> dict:
    """Hard rules the model cannot override.

    CONFIRMED needs a sandbox reproduction. Closing (NOT_REPRODUCED, FABRICATED) needs one of:
    a sandbox run exercised the claim without the bug, the text screen independently votes to close,
    or the code rules the claim out. Wrong file names, invented snippets or a similar old CVE are common in
    real reports too, so on their own they only lower the priority.
    Reading the code is not enough when prior art shows the same area had a real bug: the report may be a
    bypass or regression of that fix. A prior-art check that failed counts as unknown, not as "no prior art".
    Nor is it enough when the text screen confidently votes to keep the report open: two independent reads
    then disagree, and in our benchmark every real CVE closed on code alone was one the screen backed.
    """
    v = dict(verdict)
    v["model_verdict"] = verdict.get("verdict")
    outcome = (repro or {}).get("outcome")
    prior = (web or {}).get("prior_art") or {}
    prior_unknown = bool(prior.get("error"))
    known_area = bool(prior.get("known_issue") or prior.get("already_fixed"))
    screen_close = bool((text_screen or {}).get("close"))
    code_rules_out = (analysis or {}).get("claim_holds") == "no"
    # A failed screen has no confidence, so it never counts as a vote to keep the report open.
    ts = text_screen or {}
    screen_keeps = ts.get("close") is False and (ts.get("confidence") or 0) >= SCREEN_DISSENT
    may_close = outcome == "not_reproduced" or screen_close or (
        code_rules_out and not known_area and not prior_unknown and not screen_keeps)
    if v["model_verdict"] == "CONFIRMED" and outcome != "reproduced":
        v["verdict"] = "PLAUSIBLE"
        v["headline"] = "[Not yet reproduced] " + v.get("headline", "")
    elif v["model_verdict"] in ("NOT_REPRODUCED", "FABRICATED") and not may_close:
        v["verdict"] = "PLAUSIBLE"
        v["priority"] = "low"
        why = ("a related bug was fixed before, so this may be a bypass; reproduce before closing" if known_area
               else "the prior-art check failed, so a related fixed bug is not ruled out; reproduce before closing"
               if code_rules_out and prior_unknown
               else "the code reading rules the claim out but the text screen finds it credible; reproduce before closing"
               if code_rules_out and screen_keeps
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
