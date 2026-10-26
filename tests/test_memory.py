"""Memory: learns only what a hard check confirmed, and notices when the code changes."""

import subprocess
from pathlib import Path

import pytest

from slopproof import memory


@pytest.fixture()
def repo(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SLOPPROOF_MEMORY_DB", str(tmp_path / "memory.db"))
    monkeypatch.setenv("SLOPPROOF_MEMORY", "on")
    work = tmp_path / "work"
    work.mkdir()
    git = lambda *a: subprocess.run(["git", "-C", str(work), *a], check=True, capture_output=True, text=True).stdout  # noqa: E731
    git("init", "-q")
    (work / "conn.c").write_text("int f(char *b, int n) {\n  b[n] = '\\0';\n  return parse(b, n);\n}\n")
    git("add", "-A")
    git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "one")
    first = git("rev-parse", "HEAD").strip()
    (work / "conn.c").write_text("int f(char *b, int n) {\n  return parse(b, n);\n}\n")
    git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qam", "two")
    second = git("rev-parse", "HEAD").strip()
    return work, first, second


def result(sha, callers=(), transcript=()):
    return {"project": "t/t", "title": "x", "ref": {"sha": sha}, "seconds": 1, "cost": {"total_usd": 0.0},
            "verdict": {"verdict": "PLAUSIBLE"}, "analysis": {"callers": list(callers)},
            "reproduction": {"outcome": "inconclusive", "transcript": list(transcript)}}


def test_fact_is_kept_only_if_the_cited_line_exists(repo):
    work, first, _ = repo
    learned = memory.consolidate("r1", result(first, [
        {"caller": "conn.c:2 f", "allows": "no", "why": "NUL-terminates"},
        {"caller": "conn.c:99 f", "allows": "no", "why": "invented line"}]), work, "")
    assert learned["facts"] == ["conn.c:2 f"]


def test_fact_turns_stale_when_the_file_changes(repo):
    work, first, second = repo
    memory.consolidate("r1", result(first, [{"caller": "conn.c:2 f", "allows": "no", "why": "NUL-terminates"}]), work, "")
    same = memory.recall("t/t", work, first, {"files": ["conn.c"]})
    later = memory.recall("t/t", work, second, {"files": ["conn.c"]})
    assert same["facts"][0]["stale"] is False and later["facts"][0]["stale"] is True


def test_only_a_build_that_worked_becomes_a_skill(repo):
    work, first, _ = repo
    failed = [{"tool": "run", "cmd": "cmake .. && make", "exit_code": 2}]
    assert memory.consolidate("r1", result(first, transcript=failed), work, "")["skills"] == []
    worked = [{"tool": "run", "cmd": "cmake -DX=Off ..", "exit_code": 0}, {"tool": "run", "cmd": "make -j6", "exit_code": 0}]
    assert memory.consolidate("r2", result(first, transcript=worked), work, "")["skills"] == ["build"]
    assert "make -j6" in memory.recall("t/t", work, first, {})["skills"][0]["body"]


def test_benchmark_mode_neither_reads_nor_writes(repo, monkeypatch):
    work, first, _ = repo
    monkeypatch.setenv("SLOPPROOF_MEMORY", "off")
    assert memory.consolidate("r1", result(first, [{"caller": "conn.c:2 f", "allows": "no", "why": "x"}]), work, "") == {}
    assert memory.recall("t/t", work, first, {"files": ["conn.c"]}) == {}


def test_recalled_memory_is_labelled_as_leads_not_evidence(repo):
    work, first, _ = repo
    memory.add_lesson("*", "buffer", "check callers' terminators", "review", "review")
    text = memory.as_prompt(memory.recall("t/t", work, first, {"summary": "buffer read past the end"}))
    assert "not evidence" in text and "check callers' terminators" in text
