"""Memory across runs, modelled on how people remember, with the safeguards a triage tool needs.

- Episodes: what happened in each run (outcome, steps, cost, what failed).
- Facts: things seen in a project's code, each pinned to the git blob of the file it came from. When that file
  changes, the fact is stale until a run sees it again: memory notices when the world has changed.
- Skills: procedures that worked, such as a build that succeeded or a proof check that re-ran.
- Lessons: corrections from reviews or maintainers, applied as things to check.

Every item records where it came from. Nothing a reporter wrote is ever stored, items are only promoted after a hard
check (a build succeeded, a line exists, a proof re-ran), and memory only steers: it tells the agent where to look
and how to build, never whether a report is true. Benchmark runs turn memory off (SLOPPROOF_MEMORY=off), so the
numbers cannot be learned from the test set.
"""

import json
import os
import re
import sqlite3
import subprocess
import threading
import time
from pathlib import Path

from .codecheck import CACHE

SCHEMA = """
CREATE TABLE IF NOT EXISTS episodes (
  id TEXT PRIMARY KEY, ts REAL, project TEXT, title TEXT, sha TEXT, verdict TEXT, repro TEXT,
  steps INTEGER, seconds REAL, cost REAL, notes TEXT);
CREATE TABLE IF NOT EXISTS facts (
  id INTEGER PRIMARY KEY, project TEXT, kind TEXT, subject TEXT, text TEXT, file TEXT, blob TEXT, sha TEXT,
  source TEXT, uses INTEGER DEFAULT 0, created REAL, last_used REAL, episode TEXT, status TEXT DEFAULT 'active',
  UNIQUE(project, kind, subject, blob));
CREATE TABLE IF NOT EXISTS skills (
  id INTEGER PRIMARY KEY, project TEXT, kind TEXT, title TEXT, body TEXT, source TEXT,
  successes INTEGER DEFAULT 0, failures INTEGER DEFAULT 0, last_sha TEXT, created REAL, last_used REAL,
  status TEXT DEFAULT 'active', UNIQUE(project, kind, body));
CREATE TABLE IF NOT EXISTS lessons (
  id INTEGER PRIMARY KEY, project TEXT, trigger TEXT, text TEXT, evidence TEXT, source TEXT,
  approved INTEGER DEFAULT 0, created REAL, uses INTEGER DEFAULT 0);
"""

_lock = threading.Lock()


def mode() -> str:
    """on (read and learn), frozen (read only) or off."""
    return os.environ.get("SLOPPROOF_MEMORY", "on")


def db() -> sqlite3.Connection:
    path = Path(os.environ.get("SLOPPROOF_MEMORY_DB", CACHE / "memory.db"))
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path, timeout=30)
    con.row_factory = sqlite3.Row
    con.executescript(SCHEMA)
    return con


def blob_of(bare: Path, sha: str, file: str) -> str | None:
    out = subprocess.run(["git", "-C", str(bare), "rev-parse", f"{sha}:{file}"], capture_output=True, text=True)
    return out.stdout.strip() if out.returncode == 0 else None


# ---------------------------------------------------------------- recall
def recall(project: str, bare: Path, sha: str, cues: dict) -> dict:
    """What earlier runs taught about this project, checked against the code at this commit."""
    if mode() == "off":
        return {}
    files = {f.lstrip("/") for f in cues.get("files", [])}
    names = set(cues.get("functions", []))
    words = set(re.findall(r"[a-z_]{4,}", (cues.get("summary") or "").lower()))
    with _lock, db() as con:
        skills = [dict(r) for r in con.execute(
            "SELECT * FROM skills WHERE project=? AND status='active' AND successes > failures "
            "ORDER BY successes DESC, last_used DESC LIMIT 4", (project,))]
        rows = [dict(r) for r in con.execute(
            "SELECT * FROM facts WHERE project=? AND status!='retired' ORDER BY uses DESC, created DESC LIMIT 200", (project,))]
        lessons = [dict(r) for r in con.execute(
            "SELECT * FROM lessons WHERE approved=1 AND (project=? OR project='*')", (project,))]
    facts = []
    for f in rows:
        relevant = f["file"] in files or any(n and n in f["subject"] + f["text"] for n in names) \
            or len(words & set(re.findall(r"[a-z_]{4,}", f["text"].lower()))) >= 3
        if not relevant:
            continue
        # The file changed since the fact was seen: the fact may no longer hold.
        f["stale"] = blob_of(bare, sha, f["file"]) != f["blob"] if f["file"] else False
        facts.append(f)
    lessons = [x for x in lessons if not x["trigger"] or any(t in words for t in x["trigger"].split(","))]
    return {"skills": skills, "facts": facts[:8], "lessons": lessons[:4]}


def as_prompt(mem: dict) -> str:
    """Recalled memory as context. Labelled so the model treats it as a lead, never as evidence."""
    if not mem or not any(mem.values()):
        return ""
    lines = ["=== Memory from earlier runs (leads to check, not evidence; current code wins if it disagrees)"]
    for s in mem.get("skills", []):
        lines.append(f"- [{s['kind']} skill, worked {s['successes']}x, source {s['source']}] {s['title']}:\n{s['body']}")
    for f in mem.get("facts", []):
        state = "STALE: file changed since" if f.get("stale") else f"still matches {f['file']}"
        lines.append(f"- [fact, seen in {f['source']}, {state}] {f['subject']}: {f['text']}")
    for x in mem.get("lessons", []):
        lines.append(f"- [lesson from {x['source']}] {x['text']}")
    return "\n".join(lines)


def mark_used(mem: dict) -> None:
    if mode() != "on" or not mem:
        return
    now = time.time()
    with _lock, db() as con:
        for f in mem.get("facts", []):
            con.execute("UPDATE facts SET uses=uses+1, last_used=? WHERE id=?", (now, f["id"]))
        for s in mem.get("skills", []):
            con.execute("UPDATE skills SET last_used=? WHERE id=?", (now, s["id"]))
        for x in mem.get("lessons", []):
            con.execute("UPDATE lessons SET uses=uses+1 WHERE id=?", (x["id"],))


# ---------------------------------------------------------------- consolidation
LOC = re.compile(r"([\w./-]+\.(?:c|h|cc|cpp)):(\d+)")


def consolidate(run_id: str, result: dict, bare: Path, repo_url: str) -> dict:
    """After a run, keep what a hard check confirmed. Returns what was learned, for the timeline."""
    if mode() != "on":
        return {}
    project, sha = result["project"], result["ref"]["sha"]
    repro = result.get("reproduction") or {}
    transcript = repro.get("transcript") or []
    learned = {"facts": [], "skills": []}
    now = time.time()
    failed_builds = [t["cmd"] for t in transcript if t.get("tool") == "run" and t.get("exit_code")
                     and re.search(r"\b(cmake|configure|make)\b", t.get("cmd", ""))]
    with _lock, db() as con:
        con.execute("INSERT OR REPLACE INTO episodes VALUES (?,?,?,?,?,?,?,?,?,?,?)", (
            run_id, now, project, result.get("title"), sha, result["verdict"].get("verdict"), repro.get("outcome"),
            len(transcript), result.get("seconds"), result["cost"]["total_usd"],
            json.dumps({"failed_build_commands": len(failed_builds),
                        "bundle": (repro.get("bundle_verification") or {}).get("verdict")})))

        # Facts: caller behaviour the analysis described, kept only if the cited line exists in the tree. The
        # description is the model's reading of real code, so it is stored as a lead with that source.
        for c in (result.get("analysis") or {}).get("callers", []):
            m = LOC.search(c.get("caller", ""))
            if not m or c.get("allows") not in ("yes", "no"):
                continue
            file, line = m.group(1), int(m.group(2))
            blob = blob_of(bare, sha, file)
            if not blob or not _line_exists(bare, blob, line):
                continue
            text = f"{'allows' if c['allows'] == 'yes' else 'blocks'} the condition: {c.get('why', '')[:400]}"
            con.execute("INSERT OR IGNORE INTO facts (project, kind, subject, text, file, blob, sha, source, created, episode)"
                        " VALUES (?,?,?,?,?,?,?,?,?,?)",
                        (project, "caller", c["caller"][:200], text, file, blob, sha, "code (model reading)", now, run_id))
            learned["facts"].append(c["caller"][:120])

        # Skills: a build only counts if it produced something; a proof check only if it re-ran from scratch.
        build = _working_build(transcript)
        if build:
            _upsert_skill(con, project, "build", "build that worked in the sandbox", build, "sandbox", sha, now)
            learned["skills"].append("build")
        bundle = repro.get("bundle")
        if bundle and (repro.get("bundle_verification") or {}).get("verdict", "").startswith("VERIFIED"):
            body = f"check: {bundle['check']}\nfiles: {', '.join(bundle['files'])}"
            _upsert_skill(con, project, "proof", "proof check that re-ran from scratch", body, "sandbox", sha, now)
            learned["skills"].append("proof")
        # A remembered build that this run tried and could not use loses standing.
        if failed_builds and not build:
            con.execute("UPDATE skills SET failures=failures+1 WHERE project=? AND kind='build'", (project,))
    return learned


def _line_exists(bare: Path, blob: str, line: int) -> bool:
    text = subprocess.run(["git", "-C", str(bare), "cat-file", "blob", blob], capture_output=True, text=True).stdout
    return 0 < line <= text.count("\n") + 1


def _working_build(transcript: list[dict]) -> str | None:
    """The configure and build commands of the last build that finished with exit 0."""
    steps = []
    for t in transcript:
        cmd = t.get("cmd", "")
        if t.get("tool") != "run" or not re.search(r"\b(cmake|configure|autoreconf|meson|ninja|make|clang|gcc)\b", cmd):
            continue
        if re.search(r"\b(cat|grep|ls|find|sed -n|head|tail -f)\b", cmd.split("&&")[-1].split("|")[0]):
            continue
        if t.get("exit_code") == 0:
            steps.append(cmd)
        elif re.search(r"\bmake\b", cmd):
            steps = [s for s in steps if not re.search(r"\bmake\b", s)]  # a failed make undoes earlier makes
    makes = [s for s in steps if re.search(r"\b(make|ninja|clang|gcc)\b", s)]
    return "\n".join(steps[-6:]) if makes else None


def _upsert_skill(con, project, kind, title, body, source, sha, now):
    con.execute("INSERT OR IGNORE INTO skills (project, kind, title, body, source, created, last_sha) VALUES (?,?,?,?,?,?,?)",
                (project, kind, title, body, source, now, sha))
    con.execute("UPDATE skills SET successes=successes+1, last_sha=?, last_used=? WHERE project=? AND kind=? AND body=?",
                (sha, now, project, kind, body))


# ---------------------------------------------------------------- maintainer controls
def add_lesson(project: str, trigger: str, text: str, evidence: str, source: str = "maintainer") -> int:
    """Lessons come from people (a maintainer or a review), so they are approved when added."""
    with _lock, db() as con:
        cur = con.execute("INSERT INTO lessons (project, trigger, text, evidence, source, approved, created) "
                          "VALUES (?,?,?,?,?,1,?)", (project, trigger, text, evidence, source, time.time()))
        return cur.lastrowid


def forget(table: str, item_id: int) -> None:
    if table not in ("facts", "skills", "lessons", "episodes"):
        raise ValueError(table)
    with _lock, db() as con:
        con.execute(f"DELETE FROM {table} WHERE {'id' if table != 'episodes' else 'id'}=?", (item_id,))


def overview() -> dict:
    with _lock, db() as con:
        return {t: [dict(r) for r in con.execute(f"SELECT * FROM {t} ORDER BY rowid DESC LIMIT 100")]
                for t in ("skills", "facts", "lessons", "episodes")}
