"""The investigator's rules, tested without any model or web call: evidence is checked in code, and only
verified findings reach the guards."""

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from slopproof import investigate as inv_mod
from slopproof import webtools
from slopproof.codecheck import quote_near
from slopproof.investigate import Investigation, investigate, signals
from slopproof.llm import Ledger
from slopproof.pipeline import apply_guards, resume_from_events


def v(verdict, **kw):
    return {"verdict": verdict, "headline": "h", "findings": [], "maintainer_comment": "", **kw}


def finding(status, verified=True):
    return {"claim": "the length can exceed the buffer", "status": status,
            "evidence": [{"kind": "code", "path": "lib/a.c", "line": 3, "quote": "x", "verified": verified}]}


def investigation(*findings, recommend="close"):
    return {"findings": list(findings), "recommend": recommend}


UNCLEAR = {"claim_holds": "unclear"}


# ---- Guards: a verified refutation is a second close signal only where a code-only close is allowed
def test_verified_refutation_is_a_second_close_signal():
    out = apply_guards(v("NOT_REPRODUCED"), UNCLEAR, None, {}, None, investigation(finding("refuted")))
    assert out["verdict"] == "NOT_REPRODUCED"
    # Without the investigation the same verdict stays open.
    assert apply_guards(v("NOT_REPRODUCED"), UNCLEAR, None, {}, None)["verdict"] == "PLAUSIBLE"


def test_refutation_cannot_close_a_known_area():
    web = {"prior_art": {"already_fixed": True}}
    out = apply_guards(v("NOT_REPRODUCED"), UNCLEAR, None, web, None, investigation(finding("refuted")))
    assert out["verdict"] == "PLAUSIBLE" and "bypass" in out["headline"]


def test_refutation_cannot_close_when_prior_art_failed():
    web = {"prior_art": {"error": "search failed"}}
    out = apply_guards(v("NOT_REPRODUCED"), UNCLEAR, None, web, None, investigation(finding("refuted")))
    assert out["verdict"] == "PLAUSIBLE" and "prior-art check failed" in out["headline"]


def test_refutation_cannot_close_against_a_confident_screen():
    keep = {"close": False, "confidence": 0.85}
    out = apply_guards(v("NOT_REPRODUCED"), UNCLEAR, None, {}, keep, investigation(finding("refuted")))
    assert out["verdict"] == "PLAUSIBLE" and "text screen finds it credible" in out["headline"]


def test_refutation_cannot_close_when_the_analysis_found_the_claim_holds():
    out = apply_guards(v("NOT_REPRODUCED"), {"claim_holds": "yes"}, None, {}, None, investigation(finding("refuted")))
    assert out["verdict"] == "PLAUSIBLE"


def test_unverified_refutation_or_no_close_recommendation_does_not_count():
    assert apply_guards(v("FABRICATED"), UNCLEAR, None, {}, None,
                        investigation(finding("refuted", verified=False)))["verdict"] == "PLAUSIBLE"
    assert apply_guards(v("FABRICATED"), UNCLEAR, None, {}, None,
                        investigation(finding("refuted"), recommend="keep_open"))["verdict"] == "PLAUSIBLE"


def test_verified_holds_blocks_every_close():
    holds = investigation(finding("refuted"), finding("holds"), recommend="close")
    assert signals(holds["findings"], "close") == {"holds": True, "refutes": False}
    for args in [({"claim_holds": "no"}, None, {}, None),            # code rules it out
                 (UNCLEAR, None, {}, {"close": True}),               # the text screen agrees
                 (UNCLEAR, {"outcome": "not_reproduced"}, {}, None)]:  # even the sandbox
        out = apply_guards(v("NOT_REPRODUCED"), *args, holds)
        assert out["verdict"] == "PLAUSIBLE" and "investigator verified evidence" in out["headline"]
    # An unverified "holds" blocks nothing.
    assert apply_guards(v("NOT_REPRODUCED"), {"claim_holds": "no"}, None, {}, None,
                        investigation(finding("holds", verified=False)))["verdict"] == "NOT_REPRODUCED"


def test_investigator_can_never_confirm():
    out = apply_guards(v("CONFIRMED"), {"claim_holds": "yes"}, None, {}, None,
                       investigation(finding("holds"), recommend="confirm_needed"))
    assert out["verdict"] == "PLAUSIBLE"


# ---- Evidence checks, in code
@pytest.fixture
def repo(tmp_path: Path):
    """A git repo with two commits; the investigation is pinned to the first."""
    work = tmp_path / "repo"
    (work / "lib").mkdir(parents=True)
    git = lambda *a: subprocess.run(["git", "-C", str(work), *a], check=True, capture_output=True, text=True).stdout  # noqa: E731
    git("init", "-q")
    git("config", "user.email", "t@example.com")
    git("config", "user.name", "t")
    src = "\n".join(["#include <string.h>", "", "static void copy(char *dst, const char *src, size_t n)", "{",
                     "  if(n >= sizeof(buf))", "    return;", "  memcpy(dst, src, n);", "}"] + ["/* pad */"] * 60
                    + ["int unrelated_function(void)", "{", "  return helper_value(42);", "}"])
    (work / "lib" / "a.c").write_text(src + "\n")
    git("add", ".")
    git("commit", "-q", "-m", "add copy with a length check")
    first = git("rev-parse", "HEAD").strip()
    (work / "lib" / "a.c").write_text(src + "\n/* later */\n")
    git("commit", "-qam", "a later commit, after the report")
    later = git("rev-parse", "HEAD").strip()
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "lib").mkdir()
    (tree / "lib" / "a.c").write_text(src + "\n")
    return SimpleNamespace(work=work, tree=tree, first=first, later=later)


def test_code_quote_must_be_at_that_path_near_that_line(repo):
    assert quote_near(repo.tree, "lib/a.c", 7, "memcpy(dst, src, n);")["ok"]
    assert quote_near(repo.tree, "lib/a.c", 8, "    7    memcpy(dst, src, n);")["ok"]  # copied line number
    assert not quote_near(repo.tree, "lib/a.c", 7, "memcpy(dst, src, n + 1); /* no check */")["ok"]  # invented
    assert not quote_near(repo.tree, "lib/a.c", 7, "return helper_value(42);")["ok"]  # real, but 60 lines away
    assert not quote_near(repo.tree, "lib/b.c", 7, "memcpy(dst, src, n);")["ok"]  # no such file
    assert not quote_near(repo.tree, "../etc/passwd", 1, "root:x:0:0:root")["ok"]  # outside the tree
    assert not quote_near(repo.tree, "lib/a.c", 8, "}")["ok"]  # too short to identify code


def test_findings_keep_only_verified_evidence(repo):
    inv = Investigation(repo.tree, repo.work, repo.first, Ledger(), None, lambda e: None)
    inv._keep("https://curl.se/docs/security.html", "Bugs in test servers are not considered security problems.")
    checked = inv.check_findings([
        {"claim": "length is checked", "status": "refuted", "evidence": [
            {"kind": "code", "path": "lib/a.c", "line": 5, "quote": "if(n >= sizeof(buf))"},
            {"kind": "web", "url": "https://curl.se/docs/security.html/",
             "quote": "Bugs in test servers are not considered security problems"}]},
        {"claim": "invented", "status": "holds", "evidence": [
            {"kind": "code", "path": "lib/a.c", "line": 5, "quote": "strcpy(dst, src); // overflow"},
            {"kind": "web", "url": "https://example.com/never-fetched", "quote": "this page was never returned"}]},
    ])
    assert checked[0]["status"] == "refuted" and all(e["verified"] for e in checked[0]["evidence"])
    assert checked[1]["status"] == "unknown" and checked[1]["claimed_status"] == "holds"
    assert [e["verified"] for e in checked[1]["evidence"]] == [False, False]
    assert "no tool in this run returned that URL" in checked[1]["evidence"][1]["why"]
    assert signals(checked, "close") == {"holds": False, "refutes": True}


def test_git_tools_stop_at_the_pinned_commit(repo):
    inv = Investigation(repo.tree, repo.work, repo.first, Ledger(), None, lambda e: None)
    assert "off limits" in inv.git_show(repo.later)
    assert "add copy with a length check" in inv.git_show(repo.first[:10])
    assert "later commit" not in inv.git_log_search("later", in_messages=True)
    ev = inv.check_evidence({"kind": "git", "commit": repo.first[:10], "quote": "add copy with a length check"})
    assert ev["verified"]
    assert not inv.check_evidence({"kind": "git", "commit": repo.later, "quote": "a later commit"})["verified"]


def _msg(*calls, content=""):
    return SimpleNamespace(content=content, tool_calls=[SimpleNamespace(
        id=f"c{i}", function=SimpleNamespace(name=n, arguments=json.dumps(a))) for i, (n, a) in enumerate(calls)])


def test_replay_refusal_comes_back_as_a_tool_result_and_the_agent_carries_on(repo, monkeypatch):
    turns = iter([
        _msg(("crawl_docs", {"url": "https://curl.se/docs/", "instructions": "security policy", "why": "policy"}),
             content="Check the project's policy first."),
        _msg(("read_lines", {"path": "lib/a.c", "start": 1, "end": 10, "why": "the length check"})),
        _msg(("finish", {"findings": [{"claim": "no length check", "status": "refuted", "evidence": [
            {"kind": "code", "path": "lib/a.c", "line": 5, "quote": "if(n >= sizeof(buf))"}]}],
            "recommend": "close", "confidence": 0.8, "summary": "The length is checked."})),
    ])
    seen = []

    def fake_chat(tier, messages, ledger, purpose, **kw):
        seen.append([m for m in messages if m["role"] == "tool"])
        return next(turns)

    monkeypatch.setattr(inv_mod, "chat", fake_chat)
    events = []
    res = investigate("t", "b", "curl/curl", {}, {}, {}, {}, [], {"verdict": "PLAUSIBLE"}, repo.tree, repo.work,
                      repo.first, Ledger(), as_of="2024-01-01T00:00:00Z", emit=events.append)
    assert res["steps"][0]["refused"] and "[refused]" in seen[1][-1]["content"]
    assert res["steps"][0]["endpoint"] == "Tavily crawl" and res["steps"][0]["target"] == "curl.se/docs"
    assert res["steps"][0]["thought"].startswith("Check the project's policy")
    assert res["calls"] == 2 and res["signals"]["refutes"] and res["evidence"] == {"verified": 1, "dropped": 0}
    kinds = [e.get("type") for e in events if e.get("stage") == "investigate"]
    assert kinds == ["begin", "call", "result", "call", "result", "finish"]


def test_hooks_stop_repeated_greps_and_rereading():
    steps = [{"tool": "grep_code", "args": {"pattern": "help_category"}},
             {"tool": "read_lines", "args": {"path": "src/a.c", "start": 100, "end": 160}}]
    assert inv_mod._hook("grep_code", {"pattern": "help_category", "path": "src"}, steps)
    assert inv_mod._hook("read_lines", {"path": "src/a.c", "start": 110, "end": 150}, steps)
    assert inv_mod._hook("read_lines", {"path": "src/a.c", "start": 150, "end": 250}, steps) is None
    assert inv_mod._hook("grep_code", {"pattern": "free_globalconfig"}, steps) is None


def test_tavily_feedback_names_only_the_results_used(monkeypatch):
    sent = []
    monkeypatch.setattr(webtools, "feedback", lambda rid, score, used, comment="": sent.append((rid, score, used)) or True)
    ledger = Ledger()
    ledger.add_tool("tavily/search", "q1", 1, 0.008, 0.1, {"request_id": "r1", "urls": ["https://a.org/x", "https://b.org/y"]})
    ledger.add_tool("tavily/search", "q2", 1, 0.008, 0.1, {"request_id": "r2", "urls": ["https://c.org/z"]})
    ledger.add_tool("tavily/extract", "e", 1, 0.008, 0.1)
    webtools.feedback_for_run(ledger, ["http://www.a.org/x/#frag"], "PLAUSIBLE")
    assert sent == [("r1", 1.0, ["https://a.org/x"]), ("r2", 0.0, [])]
    assert ledger.summary()["tavily_credits"] == 3


def test_resume_reads_a_finished_investigation():
    done = resume_from_events([{"stage": "checkpoint", "key": "investigation", "value": {"findings": []}}])
    assert done["investigation"] == {"findings": []}
