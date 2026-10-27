"""The rules SlopProof enforces in code, tested without any model call.

  uv run pytest -q
"""

import json
from pathlib import Path

from slopproof.bundle import SCHEMA, digest, verify
from slopproof.codecheck import line_diff, lines_found, line_index, looks_like_prose
from slopproof.codesearch import tokens
from slopproof.llm import parse_json
from slopproof.pipeline import apply_guards, resume_from_events
from slopproof import bundle as bundle_mod
from slopproof.reproduce import _check_reproduction, _seal
from slopproof.verdict import allowed_cves, scrub_cves


def v(verdict, **kw):
    return {"verdict": verdict, "headline": "h", "findings": [], "maintainer_comment": "", **kw}


# ---- Verdict guards: doubt never closes a report, CONFIRMED needs a reproduction
def test_confirmed_needs_a_reproduction():
    out = apply_guards(v("CONFIRMED"), {"claim_holds": "yes"}, None)
    assert out["verdict"] == "PLAUSIBLE" and out["model_verdict"] == "CONFIRMED"


def test_reproduction_makes_it_confirmed():
    assert apply_guards(v("PLAUSIBLE"), None, {"outcome": "reproduced"})["verdict"] == "CONFIRMED"


def test_close_without_a_second_signal_stays_open():
    out = apply_guards(v("FABRICATED"), {"claim_holds": "unclear"}, None)
    assert out["verdict"] == "PLAUSIBLE" and out["priority"] == "low"


def test_close_with_code_ruling_it_out():
    assert apply_guards(v("NOT_REPRODUCED"), {"claim_holds": "no"}, None)["verdict"] == "NOT_REPRODUCED"


def test_close_with_the_text_screen_agreeing():
    assert apply_guards(v("FABRICATED"), {"claim_holds": "unclear"}, None, {}, {"close": True})["verdict"] == "FABRICATED"


def test_code_alone_cannot_close_a_known_area():
    web = {"prior_art": {"known_issue": True}}
    out = apply_guards(v("NOT_REPRODUCED"), {"claim_holds": "no"}, None, web)
    assert out["verdict"] == "PLAUSIBLE"


def test_sandbox_can_close_a_known_area():
    web = {"prior_art": {"already_fixed": True}}
    assert apply_guards(v("NOT_REPRODUCED"), None, {"outcome": "not_reproduced"}, web)["verdict"] == "NOT_REPRODUCED"


# ---- Replies: no unverified CVEs, no promises on the maintainer's behalf
def test_unverified_cve_is_removed_from_reply_and_findings():
    verdict = v("PLAUSIBLE", findings=[{"kind": "contradiction", "text": "CVE-2024-4321 was fixed in 4.2."},
                                       {"kind": "confirmation", "text": "Line 644 matches."}],
                maintainer_comment="Thanks. CVE-2024-4321 may be related. Please share the input.")
    out = scrub_cves(verdict, set())
    assert "CVE-2024-4321" not in json.dumps({k: out[k] for k in ("findings", "maintainer_comment")})
    assert out["findings"] == [{"kind": "confirmation", "text": "Line 644 matches."}]
    assert out["scrubbed_cves"] == ["CVE-2024-4321"]


def test_cves_from_the_report_or_a_verified_check_are_allowed():
    web = {"prior_art": {"cve_checks": [{"cve": "CVE-2026-1", "exists": True, "affects_project": True, "same_issue": True},
                                        {"cve": "CVE-2026-2", "exists": True, "affects_project": True, "same_issue": False}]}}
    assert allowed_cves("see CVE-2023-38545", web) == {"CVE-2023-38545", "CVE-2026-1"}


def test_promises_are_removed():
    out = scrub_cves(v("PLAUSIBLE", maintainer_comment="Thanks. In the meantime we will add a check. "
                                                        "We'll release a fix soon. Can you share the input?"), set())
    assert out["maintainer_comment"] == "Thanks. Can you share the input?"


# ---- Reproductions: the agent's word is not enough
def repro(cmds, **kw):
    return {"outcome": "reproduced", "explanation": "", "evidence": "", "impact": "boundary_crossed",
            "reachable_by_attacker": True, "transcript": [{"tool": "run", "cmd": c, "output": ""} for c in cmds], **kw}


def test_listing_the_binary_is_not_running_it():
    r = repro(["ls -la /work/repo/src/curl", "clang poc.c -o poc && ./poc"])
    _check_reproduction(r, "curl")
    assert r["outcome"] == "inconclusive"


def test_running_the_cli_counts():
    r = repro(["cd /work/repo && ./src/curl -v file:///x"], impact="memory_safety")
    r["transcript"][0]["output"] = "==1==ERROR: AddressSanitizer: heap-buffer-overflow\n #0 in f /work/repo/lib/x.c:12"
    _check_reproduction(r, "curl")
    assert r["outcome"] == "reproduced"


def test_unreachable_path_is_not_a_reproduction():
    r = repro(["./src/curl x"], reachable_by_attacker=False)
    _check_reproduction(r, "curl")
    assert r["outcome"] == "not_reproduced"


def test_no_impact_over_intended_use_is_not_a_reproduction():
    r = repro(["./src/curl file:///etc/passwd"], impact="none")
    _check_reproduction(r, "curl")
    assert r["outcome"] == "not_reproduced"


# ---- Quoted code checks
def test_prose_labelled_as_code_is_recognised():
    assert looks_like_prose("Curl_fopen() opens the destination with write mode before checking the target file")
    assert not looks_like_prose("if(len > max) {\n  return CURLE_TOO_LARGE; // the check\n}")


def test_lines_match_once_reporter_comments_are_removed(tmp_path: Path):
    src = tmp_path / "lib" / "a.c"
    src.parent.mkdir()
    src.write_text("int f(char *r) {\n  strcpy(r, \"--:--:--\");\n  return 0;\n}\n")
    index = line_index(tmp_path, {src: src.read_text()})
    found = lines_found('strcpy(r, "--:--:--");  // VULNERABLE LINE', index)
    assert found["found"] == found["total"] == 1


def test_line_diff_counts_exact_and_invented_lines(tmp_path: Path):
    src = tmp_path / "a.c"
    src.write_text("int a = 1;\nint b = 2;\nint c = 3;\n")
    d = line_diff("int a = 1;\nint b = 2;\nsystem(\"rm -rf /\");", tmp_path, "a.c", 1)
    assert d["exact"] == 2 and d["not_found_count"] == 1


# ---- Proof bundles
def test_bundle_digest_detects_edits():
    b = {"schema": SCHEMA, "check": "true", "files": {}}
    b["sha256"] = digest(b)
    assert digest(b) == b["sha256"]
    b["check"] = "false"
    assert digest(b) != b["sha256"]


def test_bundle_files_must_stay_under_work():
    b = {"schema": SCHEMA, "repo": "x", "commit": "y", "check": "true", "files": {"/etc/passwd": "x"}}
    assert verify(b)["verdict"] == "INVALID"


class FakeSandbox:
    """Stands in for Docker: the check and the control exit with the codes the test sets."""
    codes: dict[str, int] = {}

    def __init__(self, tree):
        pass

    def run(self, cmd, timeout=0, pipefail=True):
        return {"exit_code": self.codes.get(cmd, 0), "output": ""}

    def write(self, path, content):
        pass

    def close(self):
        pass


def fake_verify(monkeypatch, check_code, control_code):
    FakeSandbox.codes = {"check": check_code, "control": control_code}
    monkeypatch.setattr(bundle_mod, "Sandbox", FakeSandbox)
    monkeypatch.setattr(bundle_mod.codecheck, "ensure_repo", lambda repo: "bare")
    monkeypatch.setattr(bundle_mod.codecheck, "git", lambda *a: "abc123")
    monkeypatch.setattr(bundle_mod.codecheck, "export_tree", lambda bare, sha: "tree")
    monkeypatch.setattr(bundle_mod, "image_id", lambda: None)
    b = bundle_mod.make_bundle("r", "abc123", "true", {}, "check", "claim", control="control")
    return verify(b)


def test_bundle_needs_the_control_to_fail(monkeypatch):
    assert fake_verify(monkeypatch, 0, 1)["verdict"] == "VERIFIED"
    assert fake_verify(monkeypatch, 0, 0)["verdict"] == "NOT_VERIFIED"


def test_old_bundle_without_control_still_verifies(monkeypatch):
    fake_verify(monkeypatch, 0, 1)
    b = bundle_mod.make_bundle("r", "abc123", "true", {}, "check", "claim")
    del b["control"]
    b["sha256"] = digest(b)
    assert verify(b)["verdict"] == "VERIFIED"


def sealable(control):
    return {"outcome": "reproduced", "explanation": "e", "check_command": "check", "control_check": control,
            "transcript": []}


def test_seal_downgrades_a_check_that_passes_on_the_safe_case(monkeypatch):
    fake_verify(monkeypatch, 0, 0)
    r = sealable("control")
    _seal(r, "r", "abc123", "p", lambda e: None)
    assert r["outcome"] == "inconclusive" and "safe case" in r["explanation"]


def test_seal_without_a_control_is_not_confirmed(monkeypatch):
    fake_verify(monkeypatch, 0, 1)
    r = sealable("")
    _seal(r, "r", "abc123", "p", lambda e: None)
    assert r["outcome"] == "inconclusive" and "control" in r["explanation"]


def test_seal_keeps_a_check_that_fails_on_the_safe_case(monkeypatch):
    fake_verify(monkeypatch, 0, 1)
    r = sealable("control")
    _seal(r, "r", "abc123", "p", lambda e: None)
    assert r["outcome"] == "reproduced" and r["bundle"]["control"] == "control"


# ---- Plumbing
def test_json_with_raw_newlines_in_strings_parses():
    assert parse_json('{"code": "a\n\tb"}') == {"code": "a\n\tb"}


def test_resume_reads_finished_steps():
    events = [{"stage": "claims", "claims": {"summary": "s"}}, {"stage": "search", "found": []},
              {"stage": "checkpoint", "key": "reproduction", "value": {"outcome": "inconclusive"}},
              {"stage": "error", "message": "x"}]
    assert resume_from_events(events) == {"claims": {"summary": "s"}, "search": [],
                                          "reproduction": {"outcome": "inconclusive"}}


def test_code_tokens_split_identifiers():
    toks = tokens("CURLOPT_NETRC parseNetrc")
    assert {"curlopt", "netrc", "parse", "curlopt_netrc", "parsenetrc"} <= set(toks)


# ---- Agent hooks
def test_hooks_block_repeats_endless_loops_and_endless_reading():
    from slopproof.reproduce import READ_BUDGET, _hook
    done = [{"tool": "run", "cmd": "grep -n x a.c", "exit_code": 0}]
    assert "already ran" in _hook("grep -n x a.c", done)
    assert "never end" in _hook("tail -f build.log", [])
    reads = [{"tool": "run", "cmd": f"sed -n '{i},{i + 5}p' a.c", "exit_code": 0} for i in range(READ_BUDGET)]
    assert "Stop reading" in _hook("cat b.c", reads)
    assert _hook("cat b.c", reads + [{"tool": "write_file", "path": "/work/poc.c"}]) is None
    assert _hook("clang poc.c -o poc", reads) is None
    compiled = [{"tool": "run", "cmd": "clang poc.c -o poc", "exit_code": 1}]
    assert "already ran" in _hook("clang poc.c -o poc", compiled)
    assert _hook("clang poc.c -o poc", compiled + [{"tool": "write_file", "path": "/work/poc.c"}]) is None
