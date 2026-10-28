"""Fix agent: from a verified proof bundle to a verified patch.

Nemotron Ultra writes a minimal patch in a sandbox where the bug reproduces. Inside its own loop it has a `test`
tool that rebuilds, re-runs the bundle's check and the project's own tests for the files it changed, and finish is
refused while either still fails. The patch only counts when, in a fresh sandbox, the bundle's check stops passing
with it applied and the related project tests that passed before still pass. If the project's real fix is known,
the two patches are compared afterwards; the agent never sees it.
"""

import json
import re
import subprocess
import time
from collections.abc import Callable
from pathlib import Path

from . import codecheck
from .bundle import run_check, verify_patch
from .llm import Ledger, chat, chat_json
from .reproduce import READ_ONLY, _assistant_dict, _shrink_old_outputs
from .sandbox import Sandbox

MAX_STEPS = 50
WALL_SECONDS = 40 * 60
GATE_TRIES = 3  # finish is refused at most this many times; after that the patch is judged as it is
READ_BUDGET = 12  # read-only commands in a row before the agent is told to edit and test
OUTPUT_CHARS = 5000  # tool output the agent sees per call

SYSTEM = """You fix a confirmed security bug in an open source C project. The project source is at /work/repo and is
already built with the bug present. The bug is proven by a CHECK COMMAND that exits 0 while the bug is present.

Tools:
- run: a bash command in /work/repo. You see at most 5000 characters of output, so read by line range
  (grep -n, sed -n 'A,Bp'), several ranges in one command.
- edit: replace one exact, unique snippet of a project file with new text.
- test: rebuilds the project, runs the bug check, then runs the project's own test cases for the files your patch
  changes. These are the same tests your patch is judged by afterwards. It reports whether the bug is gone and which
  tests now fail that passed before your change, with their failure output. No arguments.
- finish: submit. finish runs test first and is refused while the bug is present or a test that passed before fails.

How to work:
1. Read the code the report points at and find the root cause. Also read how existing tests use that code (the test
   cases in tests/ that mention the function or feature): they show which return codes, error paths and outputs
   callers rely on.
2. Make the smallest correct fix at the root cause with edit. Keep every behaviour except the bug: the same return
   values and error codes for all other cases, including malformed input.
3. Call test right after the edit. If a test fails, read that test's definition, adjust the patch, call test again.
4. Call finish once test shows the bug gone and no new test failures.

Rules:
- Fix the root cause in project code. Never change the PoC, the check, or the tests to make them pass.
- Do not weaken a feature to hide the bug (for example by turning the feature off or rejecting every input of a kind).
- Never use tail -f or other commands that wait forever.
- If a PoC you run by hand fails with "Address already in use", its fixed port is still in TIME_WAIT from the last
  run: the test tool waits for that; for your own runs, change the port in a copy of the PoC.
- Budget: {steps} tool calls and {minutes} minutes in total. Make your first edit by tool call 12 and test it at once:
  the test output tells you more than further reading."""

TOOLS = [
    {"type": "function", "function": {
        "name": "run", "description": "Run a bash command in /work/repo inside the sandbox.",
        "parameters": {"type": "object", "properties": {"cmd": {"type": "string"},
                                                        "timeout": {"type": "integer", "default": 300}},
                       "required": ["cmd"]}}},
    {"type": "function", "function": {
        "name": "edit", "description": "Replace one exact, unique snippet in a project file, e.g. lib/foo.c.",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string", "description": "path relative to /work/repo"},
            "old_text": {"type": "string", "description": "exact current text, unique in the file"},
            "new_text": {"type": "string"}}, "required": ["path", "old_text", "new_text"]}}},
    {"type": "function", "function": {
        "name": "test", "description": ("Rebuild, run the bug check, and run the project's own tests for the files "
                                        "your patch changes. Reports the bug state and new test failures."),
        "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {
        "name": "finish", "description": ("Submit the fix. The patch is taken from git diff of your edits. Refused "
                                          "while the bug check passes or a related test newly fails."),
        "parameters": {"type": "object", "properties": {
            "explanation": {"type": "string", "description": "root cause and why the fix is correct, citing file:line"},
            "check_after": {"type": "string", "description": "output and exit code of the check with the fix"}},
            "required": ["explanation"]}}},
]

COMPARE = """Two patches fix the same reported vulnerability: one written by an AI agent, one shipped by the project.
You get the reported bug, the upstream commit message, the upstream test changes (they show what behaviour the
project decided is correct) and both code diffs. Compare them on the reported bug first. A large upstream patch may
also refactor or harden other things: list those separately, and do not call them risks of the agent patch unless
the upstream message or tests show they are part of this vulnerability. Judge only what the diffs and message show.
Reply with one JSON object only:
{"same_root_cause": true or false, "same_location": true or false,
 "same_behaviour_for_reported_bug": true or false,
 "summary": "two sentences: what each patch changes and how they differ",
 "upstream_extra": "what the upstream fix changes beyond the reported bug, or 'nothing'",
 "agent_patch_risks": "anything the agent patch breaks or misses for this vulnerability that the upstream patch handles, or 'none seen'"}"""


def upstream_diff(repo_url: str, fix_commit: str, paths: tuple[str, ...] = ("lib", "src", "include")) -> str:
    bare = codecheck.ensure_repo(repo_url)
    return subprocess.run(["git", "-C", str(bare), "diff", f"{fix_commit}^", fix_commit, "--", *paths],
                          capture_output=True, text=True).stdout


def compare_with_upstream(result: dict, bundle: dict, upstream_fix: str, ledger: Ledger) -> dict | None:
    """After the agent is done: how its patch relates to the project's own fix. Never shown to the agent."""
    bare = codecheck.ensure_repo(bundle["repo"])
    message = subprocess.run(["git", "-C", str(bare), "log", "-1", "--format=%B", upstream_fix],
                             capture_output=True, text=True).stdout
    tests = upstream_diff(bundle["repo"], upstream_fix, ("tests",))
    try:
        return chat_json("big", COMPARE, (
            f"REPORTED BUG:\n{bundle['claim'][:1500]}\n\nUPSTREAM COMMIT MESSAGE ({upstream_fix[:12]}):\n{message[:2000]}\n\n"
            f"UPSTREAM TEST CHANGES:\n{tests[:5000] or 'none'}\n\nAGENT PATCH:\n{result['patch'][:8000]}\n\n"
            f"UPSTREAM CODE PATCH:\n{upstream_diff(bundle['repo'], upstream_fix)[:14000]}"), ledger, "compare fix")
    except ValueError:
        return None


# How to run a project's own tests for one area, given test ids. curl's runtests.pl takes test numbers.
TEST_BUILD = {"curl": "cd tests && make -j6"}
TEST_RUNNERS = {
    "curl": ("cd tests && make -j6 >/dev/null 2>&1; perl runtests.pl -a -n {ids} 2>&1 | "
             "grep -E '^(TESTFAIL|TESTDONE|test [0-9]+.*(FAILED|OK))' | tail -40"),
}
# One test with its failure output (runtests prints a diff of what was expected and what came out).
TEST_DETAIL = {"curl": "cd tests && perl runtests.pl -n {id} 2>&1 | grep -v -e '^\\*' -e '^\\s*$' | tail -30"}
TEST_NOTES = {"curl": ("Project tests: tests/data/test<N> defines test N (command, input files, expected output and "
                       "<errorcode>); unit tests are tests/unit/unit<N>.c. The related tests for a patch are the test "
                       "cases that mention a changed file's name (a change to lib/foo.c runs the tests mentioning "
                       "foo). Run single tests by hand with: cd /work/repo/tests && perl runtests.pl -a -n <N> ...")}


def related_tests(bare, commit: str, patch: str, limit: int = 30) -> list[str]:
    """curl test cases that mention the feature a patch touches (named after its files, e.g. netrc for lib/netrc.c)."""
    words = {Path(f).stem for f in re.findall(r"^\+\+\+ b/(\S+)", patch, re.M)} - {"url", "transfer", "multi", "easy"}
    ids: set[int] = set()
    for w in words:
        out = subprocess.run(["git", "-C", str(bare), "grep", "-l", "-i", w, commit, "--", "tests/data"],
                             capture_output=True, text=True).stdout
        ids |= {int(m) for m in re.findall(r"tests/data/test(\d+)$", out, re.M)}
    return [str(i) for i in sorted(ids)[:limit]]


def parse_tests(out: str) -> dict:
    """Failed ids and the OK count from runtests.pl's summary lines."""
    m = re.search(r"TESTFAIL: These test cases failed: ([\d ]+)", out)
    failed = sorted(set(m.group(1).split()), key=int) if m else []
    done = re.search(r"TESTDONE: (\d+) tests out of (\d+) reported OK", out)
    return {"failed": failed, "ok": int(done.group(1)) if done else None, "total": int(done.group(2)) if done else None}


def run_tests(bundle: dict, patch: str | None, ids: list[str], project: str = "curl") -> dict:
    """Run the given project tests in a fresh build, with or without the patch."""
    bare = codecheck.ensure_repo(bundle["repo"])
    sb = Sandbox(codecheck.export_tree(bare, bundle["commit"]))
    try:
        if patch:
            sb.write("/work/fix.patch", patch)
            sb.run("patch -p1 --forward < /work/fix.patch", timeout=60)
        if sb.run(bundle["build"], timeout=1500)["exit_code"] != 0:
            return {"built": False}
        out = sb.run(TEST_RUNNERS[project].format(ids=" ".join(ids)), timeout=1500)["output"]
        return {"built": True, **parse_tests(out), "output": out[-1500:]}
    finally:
        sb.close()


def _edit(repo_dir, rel: str, old: str, new: str) -> str:
    """Replace one exact snippet; refuse anything ambiguous or outside the project tree."""
    target = (repo_dir / rel.removeprefix("/work/repo/")).resolve()
    if not str(target).startswith(str(repo_dir.resolve())) or not target.is_file():
        return f"refused: {rel} is not a file in the project"
    text = target.read_text(errors="replace")
    count = text.count(old) if old else 0
    if count != 1:
        return f"refused: old_text found {count} times in {rel}; it must match exactly once"
    target.write_text(text.replace(old, new))
    return f"edited {rel}"


def _compact(text: str, limit: int = OUTPUT_CHARS) -> str:
    """Keep the start and most of the end of a long output; the end is usually where the answer is."""
    if len(text) <= limit:
        return text
    head = limit // 4
    return text[:head] + f"\n... [{len(text) - limit} chars cut] ...\n" + text[-(limit - head):]


def _hook(cmd: str, transcript: list[dict]) -> str | None:
    """Rules checked before a command runs. Returns a message instead of running it, or None."""
    if re.search(r"\btail\s+-f\b|while\s+true|while\s+:\s*;", cmd):
        return "[hook] Commands that never end are not allowed. Use a bounded loop with a timeout."
    if READ_ONLY.search(cmd):
        reads = 0
        for t in reversed(transcript):
            if t.get("tool") != "run" or not READ_ONLY.search(t.get("cmd", "")):
                break
            reads += 1
        if reads >= READ_BUDGET:
            return (f"[hook] {reads} reads in a row without an edit or a test. Make your best edit at the root cause "
                    "now and call test: its output shows what is still wrong.")
    return None


def ports_free_cmd(bundle: dict) -> str:
    """Shell loop that waits (at most 75 s) until no TCP socket on a port the PoC names is in TIME_WAIT, so a PoC
    with a fixed port can bind it again. With no port named, it waits for every TIME_WAIT socket."""
    text = bundle.get("check", "") + "\n" + "\n".join(bundle.get("files", {}).values())
    ports = sorted({int(p) for p in re.findall(r"(?<![\d.])(\d{4,5})(?![\d.])", text) if 1024 <= int(p) <= 65535})
    local = f" && $2 ~ /:({'|'.join(f'{p:04X}' for p in ports)})$/" if ports else ""
    busy = f"awk '$4==\"06\"{local}' /proc/net/tcp /proc/net/tcp6 2>/dev/null"
    return f"for i in $(seq 75); do [ -z \"$({busy})\" ] && break; sleep 1; done"


class Judge:
    """What `test` and finish report inside the agent's sandbox: build, bug check, related project tests.

    Baselines for failing tests are measured in the same sandbox with the agent's edits stashed, so a test that
    already failed before the patch is not blamed on it."""

    def __init__(self, sb: Sandbox, bundle: dict, bare, project: str):
        self.sb, self.bundle, self.bare, self.project = sb, bundle, bare, project
        self.baseline: dict[str, bool] = {}  # test id -> passed without the patch
        self.last: tuple[str, dict] | None = None

    def __call__(self) -> dict:
        sb = self.sb
        diff = sb.run("git diff", timeout=60)["output"]
        if self.last and self.last[0] == diff:
            return self.last[1]
        res: dict = {"edited": bool(diff.strip())}
        built = sb.run("make -j6 >/work/make.log 2>&1; rc=$?; grep -E 'error' /work/make.log | head -20; exit $rc",
                       timeout=900)
        res["built"] = built["exit_code"] == 0
        if not res["built"]:
            res["build_errors"] = built["output"][-2000:]
            return self._keep(diff, res)
        for path, content in self.bundle["files"].items():
            sb.write(path, content)  # the bundle's own PoC, even if the agent changed its copy
        sb.run(ports_free_cmd(self.bundle), timeout=90)
        check = run_check(sb, self.bundle)
        res.update(bug_present=check["bug_present"], check_exit=check["exit_code"], check_output=check["output"][-800:])
        res["tests"] = self._tests(diff) if res["edited"] and self.project in TEST_RUNNERS else None
        return self._keep(diff, res)

    def _keep(self, diff: str, res: dict) -> dict:
        self.last = (diff, res)
        return res

    def _tests(self, diff: str) -> dict:
        ids = related_tests(self.bare, self.bundle["commit"], diff)
        if not ids:
            return {"ids": [], "new_failures": []}
        self.sb.run("for i in $(seq 120); do [ -f /work/tests.done ] && break; sleep 5; done", timeout=660)
        now = parse_tests(self.sb.run(TEST_RUNNERS[self.project].format(ids=" ".join(ids)), timeout=1200)["output"])
        unknown = [i for i in now["failed"] if i not in self.baseline]
        if unknown:
            # Same tests without the patch: stash the edits, rebuild, run, restore, rebuild.
            out = self.sb.run("git stash -q && make -j6 >/dev/null 2>&1; " + TEST_RUNNERS[self.project].format(
                ids=" ".join(unknown)) + "; cd /work/repo && git stash pop -q && make -j6 >/dev/null 2>&1",
                timeout=1800)["output"]
            before = parse_tests(out)
            self.baseline.update({i: i not in before["failed"] for i in unknown})
        new = [i for i in now["failed"] if self.baseline.get(i)]
        details = {}
        if new:  # relink the test programs against the current (patched) build first
            self.sb.run(TEST_BUILD[self.project] + " >/dev/null 2>&1", timeout=900)
        for i in new[:2]:
            details[i] = self.sb.run(TEST_DETAIL[self.project].format(id=i), timeout=300)["output"][-1500:]
        return {"ids": ids, "ok": now["ok"], "total": now["total"], "failed": now["failed"], "new_failures": new,
                "details": details}


def judge_text(res: dict) -> str:
    """The judge's result as the agent reads it."""
    if not res.get("built"):
        return "BUILD FAILED:\n" + res.get("build_errors", "")
    lines = ["build: ok",
             f"bug check: exit {res['check_exit']} -> " + ("BUG STILL PRESENT" if res["bug_present"] else "bug gone")]
    if res["bug_present"]:
        lines.append("check output (end):\n" + res["check_output"])
    t = res.get("tests")
    if not res.get("edited"):
        lines.append("no edits yet, so no project tests were run")
    elif t is None:
        lines.append("no project test runner is known for this project")
    elif not t["ids"]:
        lines.append("no project test case mentions the files you changed")
    else:
        lines.append(f"related project tests ({len(t['ids'])}: {' '.join(t['ids'])}): {t['ok']}/{t['total']} OK")
        if t["new_failures"]:
            lines.append(f"FAILING NOW BUT PASSED BEFORE YOUR PATCH: {', '.join(t['new_failures'])}")
            for i, d in t["details"].items():
                lines.append(f"--- test {i} output (end) ---\n{d}")
        old = [i for i in t["failed"] if i not in t["new_failures"]]
        if old:
            lines.append(f"failing before your patch too (not counted): {', '.join(old)}")
    return "\n".join(lines)


def judge_ok(res: dict) -> bool:
    return bool(res.get("built")) and res.get("edited") and not res.get("bug_present") \
        and not (res.get("tests") or {}).get("new_failures")


def propose_fix(bundle: dict, report: str, ledger: Ledger, emit: Callable[[dict], None] = lambda e: None,
                upstream_fix: str | None = None, rounds: int = 2) -> dict:
    """Write a fix, verify it, run the related tests; if tests break, give the failures back and try again."""
    feedback, prior, res = None, None, {}
    for attempt in range(1, rounds + 1):
        res = _attempt(bundle, report, ledger, emit, upstream_fix, prior, feedback)
        res["attempt"] = attempt
        if res.get("verdict") != "FIX_BREAKS_TESTS":
            return res
        prior = res["patch"]
        failing = res["tests"]["new_failures"]
        feedback = (f"Your previous patch (already applied below) stops the bug, but it breaks these project tests "
                    f"that passed before: {', '.join(failing)}. Read their definitions, call test to see the "
                    f"failures, then change the fix so the bug check fails AND these tests pass.\n\n"
                    f"Previous patch:\n{prior}")
    return res


def _attempt(bundle: dict, report: str, ledger: Ledger, emit: Callable[[dict], None], upstream_fix: str | None,
             prior: str | None, feedback: str | None) -> dict:
    bare = codecheck.ensure_repo(bundle["repo"])
    project = bundle["repo"].rstrip("/").split("/")[-1]
    sb = Sandbox(codecheck.export_tree(bare, bundle["commit"]))
    t0 = time.time()
    emit({"stage": "fix", "type": "run", "cmd": "# building the project at the bundle's commit"})
    built = sb.run(bundle["build"], timeout=1500)
    if built["exit_code"] != 0:
        sb.close()
        return {"verdict": "BUILD_FAILED", "output": built["output"][-2000:]}
    for path, content in bundle["files"].items():
        sb.write(path, content)
    if bundle.get("setup"):
        sb.run(bundle["setup"], timeout=600)
    # Snapshot the sources, so the patch is exactly what the agent changed (build output is not tracked).
    sb.run("git init -q && git add -A '*.c' '*.h' && git -c user.name=x -c user.email=x@x commit -qm base", timeout=300)
    if project in TEST_BUILD:
        sb.background(TEST_BUILD[project], tag="tests")  # the test harness builds while the agent reads
    repo_dir = sb.workdir / "repo"
    if prior:
        sb.write("/work/prior.patch", prior)
        sb.run("git apply /work/prior.patch && make -j6 >/dev/null 2>&1", timeout=900)
    judge = Judge(sb, bundle, bare, project)
    system = SYSTEM.format(steps=MAX_STEPS, minutes=WALL_SECONDS // 60)
    messages = [{"role": "system", "content": system},
                {"role": "user", "content": (
                    f"CHECK COMMAND (exits 0 while the bug is present):\n{bundle['check']}\n\n"
                    f"PoC files already in place: {', '.join(bundle['files'])}\n\n"
                    + (TEST_NOTES.get(project, "") + "\n\n" if project in TEST_NOTES else "")
                    + f"Confirmed claim: {bundle['claim']}\n\nOriginal report:\n{report[:8000]}"
                    + (f"\n\nFEEDBACK FROM THE LAST ATTEMPT:\n{feedback}" if feedback else ""))}]
    transcript, result, refusals = [], None, 0
    try:
        for step in range(MAX_STEPS):
            if time.time() - t0 > WALL_SECONDS:
                break
            _shrink_old_outputs(messages)
            left = MAX_STEPS - step
            if left in (25, 12):
                messages.append({"role": "user", "content": f"{left} tool calls left. If you have not edited yet, "
                                                            "make your best edit now and call test."})
            elif left == 4:
                messages.append({"role": "user", "content": "4 tool calls left. Finish with your best patch."})
            msg = chat("big", messages, ledger, "fix", tools=TOOLS, tool_choice="auto", max_tokens=8000, temperature=0.2)
            messages.append(_assistant_dict(msg))
            if not msg.tool_calls:
                messages.append({"role": "user", "content": "Use the tools. Call finish with the patch when done."})
                continue
            for tc in msg.tool_calls:
                try:
                    args = json.loads(tc.function.arguments or "{}")
                except json.JSONDecodeError:
                    args = {}
                tool = tc.function.name
                if tool in ("test", "finish"):
                    emit({"stage": "fix", "type": "run", "cmd": f"# {tool}: rebuild, bug check, related project tests"})
                    j = judge()
                    text = judge_text(j)
                    emit({"stage": "fix", "type": "output", "exit_code": 0 if judge_ok(j) else 1, "output": text[-1500:]})
                    transcript.append({"tool": tool, "result": text, "ok": judge_ok(j),
                                       **({"explanation": args.get("explanation", "")} if tool == "finish" else {})})
                    if tool == "finish" and (judge_ok(j) or refusals >= GATE_TRIES or left <= 1):
                        result = {"explanation": args.get("explanation", ""), "check_after": args.get("check_after", ""),
                                  "steps": step + 1, "in_loop": text, "finish_refused": refusals}
                        break
                    if tool == "finish":
                        refusals += 1
                        text = ("finish REFUSED: the patch is not done yet.\n" + text +
                                "\nFix the problems above, call test, then finish again.")
                    messages.append({"role": "tool", "tool_call_id": tc.id, "content": text})
                    continue
                if tool == "edit":
                    content = _edit(repo_dir, str(args.get("path", "")), str(args.get("old_text", "")),
                                    str(args.get("new_text", "")))
                    emit({"stage": "fix", "type": "write", "path": str(args.get("path", "")), "content": content})
                    transcript.append({"tool": "edit", **{k: str(v)[:4000] for k, v in args.items()}, "result": content})
                    messages.append({"role": "tool", "tool_call_id": tc.id, "content": content})
                    continue
                if tool == "run":
                    cmd = str(args.get("cmd", ""))
                    emit({"stage": "fix", "type": "run", "cmd": cmd[:400]})
                    blocked = _hook(cmd, transcript)
                    if blocked:
                        out = {"exit_code": 2, "output": blocked}
                        transcript.append({"tool": "run", "cmd": cmd, **out, "hook": True})
                    else:
                        out = sb.run(cmd, min(int(args.get("timeout", 300) or 300), 900))
                        transcript.append({"tool": "run", "cmd": cmd, "exit_code": out["exit_code"],
                                           "output": out["output"][-1500:]})
                    emit({"stage": "fix", "type": "output", "exit_code": out["exit_code"], "output": out["output"][-1500:]})
                    content = f"exit {out['exit_code']}\n{_compact(out['output'])}"
                else:
                    content = f"unknown tool {tool}"
                messages.append({"role": "tool", "tool_call_id": tc.id, "content": content})
            if result:
                break
            emit({"stage": "cost", "usd": ledger.summary()["total_usd"]})
        if not result:
            # Out of budget: the edits made so far can still be judged on their merits below.
            why = "time" if time.time() - t0 > WALL_SECONDS else "step"
            result = {"explanation": f"{why} budget ran out; patch taken from the edits made", "check_after": "",
                      "steps": len(transcript), "finish_refused": refusals}
        result["patch"] = sb.run("git diff", timeout=60)["output"]
    finally:
        sb.close()
    result["agent_seconds"] = round(time.time() - t0)
    if not result["patch"].strip():
        return {"verdict": "NO_FIX", "seconds": round(time.time() - t0), "transcript": transcript}

    # The agent's word is not enough: apply its patch in a fresh sandbox and re-run the bundle's check.
    emit({"stage": "fix", "type": "run", "cmd": "# verifying the patch in a fresh sandbox"})
    check = verify_patch(bundle, result["patch"], emit=lambda m: emit({"stage": "fix", "type": "log", "message": m}))
    result.update(verdict=check["verdict"], verification=check["with_patch"], transcript=transcript)
    if check["verdict"] == "FIX_VERIFIED" and project in TEST_RUNNERS:
        # The patch must not break the feature it touches: run the project's own tests for it, before and after,
        # each in a fresh build.
        ids = related_tests(bare, bundle["commit"], result["patch"])
        if ids:
            emit({"stage": "fix", "type": "log", "message": f"running {len(ids)} related project tests, before and after"})
            before, after = run_tests(bundle, None, ids, project), run_tests(bundle, result["patch"], ids, project)
            new_failures = sorted(set(after.get("failed", [])) - set(before.get("failed", [])), key=int)
            result["tests"] = {"ids": ids, "before": {k: before.get(k) for k in ("ok", "total", "failed")},
                               "after": {k: after.get(k) for k in ("ok", "total", "failed")},
                               "new_failures": new_failures}
            if new_failures or not after.get("built"):
                result["verdict"] = "FIX_BREAKS_TESTS"
    result["seconds"] = round(time.time() - t0)
    if upstream_fix:
        # Only now, after the agent is done, is the project's own fix looked at.
        result["comparison"] = compare_with_upstream(result, bundle, upstream_fix, ledger)
        result["upstream_fix"] = upstream_fix
    return result
