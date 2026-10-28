"""The fix agent's rules, tested without any model call or sandbox.

  uv run pytest -q
"""

import json
from pathlib import Path
from types import SimpleNamespace

from slopproof import fix
from slopproof.llm import Ledger


# ---- Reading curl's test summary
def test_parse_tests_reads_failures_and_counts():
    out = ("TESTDONE: 22 tests were considered during 7 seconds.\n"
           "TESTFAIL: These test cases failed: 680 1304 \nTESTDONE: 20 tests out of 22 reported OK: 90%\n")
    assert fix.parse_tests(out) == {"failed": ["680", "1304"], "ok": 20, "total": 22}


def test_parse_tests_all_ok():
    assert fix.parse_tests("TESTDONE: 22 tests out of 22 reported OK: 100%") == {"failed": [], "ok": 22, "total": 22}


# ---- What counts as done inside the loop
def judged(bug=False, new=(), edited=True, built=True, failed=None):
    tests = {"ids": ["1", "2", "3"], "ok": 3 - len(failed or new), "total": 3, "failed": list(failed or new),
             "new_failures": list(new), "details": {i: "expected 26, got 0" for i in new}}
    return {"edited": edited, "built": built, "bug_present": bug, "check_exit": 0 if bug else 1,
            "check_output": "", "tests": tests}


def test_done_needs_bug_gone_and_no_new_test_failures():
    assert fix.judge_ok(judged())
    assert not fix.judge_ok(judged(bug=True))
    assert not fix.judge_ok(judged(new=["2"]))
    assert not fix.judge_ok(judged(edited=False))
    assert not fix.judge_ok({"built": False, "edited": True})


def test_a_test_that_failed_before_the_patch_is_not_blamed_on_it():
    r = judged(failed=["3"])  # fails now, but also failed without the patch
    assert fix.judge_ok(r)
    assert "failing before your patch too" in fix.judge_text(r)


def test_judge_text_names_new_failures_with_their_output():
    text = fix.judge_text(judged(new=["2"]))
    assert "FAILING NOW BUT PASSED BEFORE YOUR PATCH: 2" in text and "expected 26, got 0" in text
    assert "BUG STILL PRESENT" in fix.judge_text(judged(bug=True))


# ---- Hooks
def test_read_budget_hook_asks_for_an_edit():
    reads = [{"tool": "run", "cmd": f"sed -n '{i},{i + 9}p' lib/a.c"} for i in range(fix.READ_BUDGET)]
    assert "reads in a row" in fix._hook("grep -n x lib/a.c", reads)
    assert fix._hook("grep -n x lib/a.c", reads + [{"tool": "edit"}]) is None
    assert fix._hook("make -j6", reads) is None
    assert "never end" in fix._hook("tail -f /work/log", [])


def test_compact_keeps_the_end():
    text = "a" * 5000 + "THE END"
    out = fix._compact(text, 1000)
    assert len(out) < 1100 and out.endswith("THE END")


def test_port_wait_targets_the_pocs_ports():
    cmd = fix.ports_free_cmd({"check": "bash /work/poc.sh", "files": {"/work/poc.sh": "port=18080\nsleep 0.3\n"}})
    assert ":(46A0)$" in cmd and "seq 75" in cmd  # 18080 == 0x46A0, as /proc/net/tcp writes it
    assert "$2 ~" not in fix.ports_free_cmd({"check": "true", "files": {}})


# ---- finish is refused until the judge says the patch is done
class FakeSandbox:
    def __init__(self, tree):
        self.workdir = Path("/nonexistent")

    def run(self, cmd, timeout=0, pipefail=True):
        return {"exit_code": 0, "output": "diff --git a/lib/a.c b/lib/a.c\n" if cmd == "git diff" else ""}

    def write(self, path, content):
        pass

    def background(self, cmd, tag="build"):
        pass

    def close(self):
        pass


def call(name, **args):
    return SimpleNamespace(id=name, function=SimpleNamespace(name=name, arguments=json.dumps(args)))


def run_agent(monkeypatch, judgements):
    """Agent that calls finish every step; the judge answers from `judgements` in order."""
    seen = []
    monkeypatch.setattr(fix, "Sandbox", FakeSandbox)
    monkeypatch.setattr(fix.codecheck, "ensure_repo", lambda repo: "bare")
    monkeypatch.setattr(fix.codecheck, "export_tree", lambda bare, sha: "tree")
    monkeypatch.setattr(fix, "Judge", lambda *a: (lambda: judgements.pop(0)))
    monkeypatch.setattr(fix, "verify_patch", lambda b, p, emit=None: {"verdict": "FIX_VERIFIED", "with_patch": {}})
    monkeypatch.setattr(fix, "related_tests", lambda *a: [])

    def chat(tier, messages, ledger, purpose, **kw):
        seen.append(messages[-1])
        return SimpleNamespace(content="", tool_calls=[call("finish", explanation="done")])

    monkeypatch.setattr(fix, "chat", chat)
    bundle = {"repo": "https://github.com/x/proj", "commit": "abc", "build": "true", "files": {}, "check": "c",
              "claim": "claim"}
    return fix._attempt(bundle, "report", Ledger(), lambda e: None, None, None, None), seen


def test_finish_is_refused_while_the_bug_is_present(monkeypatch):
    res, seen = run_agent(monkeypatch, [judged(bug=True), judged(new=["2"]), judged()])
    assert res["finish_refused"] == 2 and res["verdict"] == "FIX_VERIFIED"
    refusals = [m["content"] for m in seen if m["role"] == "tool"]
    assert "REFUSED" in refusals[0] and "BUG STILL PRESENT" in refusals[0]
    assert "FAILING NOW BUT PASSED BEFORE YOUR PATCH: 2" in refusals[1]


def test_finish_gate_gives_up_after_a_few_tries(monkeypatch):
    res, _ = run_agent(monkeypatch, [judged(bug=True)] * (fix.GATE_TRIES + 1))
    assert res["finish_refused"] == fix.GATE_TRIES and "bug" in res["in_loop"].lower()


def test_agent_prompt_has_no_project_answer():
    # The fix agent is told how to work, never where this CVE's fix is.
    for text in (fix.SYSTEM, json.dumps(fix.TOOLS)):
        assert "netrc" not in text.lower()
