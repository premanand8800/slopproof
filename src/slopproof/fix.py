"""Fix agent: from a verified proof bundle to a verified patch.

Nemotron Ultra writes a minimal patch in a sandbox where the bug reproduces. The patch only counts when, in a
fresh sandbox, the bundle's check stops passing with it applied. If the project's real fix is known, the two
patches are compared.
"""

import json
import re
import subprocess
import time
from collections.abc import Callable
from pathlib import Path

from . import codecheck
from .bundle import verify_patch
from .llm import Ledger, chat, chat_json
from .reproduce import _assistant_dict, _shrink_old_outputs
from .sandbox import Sandbox

MAX_STEPS = 50
WALL_SECONDS = 25 * 60

SYSTEM = """You fix a confirmed security bug in an open source C project. The project source is at /work/repo and is
already built. The bug is proven by a CHECK COMMAND that exits 0 while the bug is present.

Steps:
1. Run the check command once to see the bug.
2. Read the relevant code (batch reads with grep -n and sed -n) and find the root cause.
3. Make the smallest correct fix with the edit tool: it replaces one exact, unique snippet of a file with new text.
   Include enough surrounding lines in old_text to make it unique, and keep the code compiling.
4. Rebuild with: cd /work/repo && make -j6 2>&1 | grep -E "error|warning: unused" | head -20; echo build=$?
5. Run the check command again: it must now exit non-zero, and the normal use it touches must still work.
Fix the root cause in project code. Never change the PoC, the check, or tests to make the check pass.
Do not weaken a feature to hide the bug (for example by disabling .netrc support entirely).
Never use tail -f or other commands that wait forever.
If the PoC fails with "Address already in use", its fixed port is still in TIME_WAIT from the last run: change the
port in your copy of the PoC (sed -i) instead of investigating.
You have 50 tool calls. Call finish when the check fails with your fix applied; the patch is taken from git diff."""

TOOLS = [
    {"type": "function", "function": {
        "name": "run", "description": "Run a bash command in /work/repo inside the sandbox.",
        "parameters": {"type": "object", "properties": {"cmd": {"type": "string"},
                                                        "timeout": {"type": "integer", "default": 300}},
                       "required": ["cmd"]}}},
    {"type": "function", "function": {
        "name": "edit", "description": "Replace one exact, unique snippet in a project file, e.g. lib/netrc.c.",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string", "description": "path relative to /work/repo"},
            "old_text": {"type": "string", "description": "exact current text, unique in the file"},
            "new_text": {"type": "string"}}, "required": ["path", "old_text", "new_text"]}}},
    {"type": "function", "function": {
        "name": "finish", "description": "Submit the fix. The patch is taken from git diff of your edits.",
        "parameters": {"type": "object", "properties": {
            "explanation": {"type": "string", "description": "root cause and why the fix is correct, citing file:line"},
            "check_after": {"type": "string", "description": "output and exit code of the check with the fix"}},
            "required": ["explanation"]}}},
]

COMPARE = """Two patches fix the same reported vulnerability: one written by an AI agent, one shipped by the project.
Compare them. Reply with one JSON object only:
{"same_root_cause": true or false, "same_location": true or false,
 "summary": "two sentences: what each patch changes and how they differ",
 "agent_patch_risks": "anything the agent patch breaks or misses that the upstream patch handles, or 'none seen'"}"""


def upstream_diff(repo_url: str, fix_commit: str) -> str:
    bare = codecheck.ensure_repo(repo_url)
    return subprocess.run(["git", "-C", str(bare), "diff", f"{fix_commit}^", fix_commit, "--", "lib", "src", "include"],
                          capture_output=True, text=True).stdout


# How to run a project's own tests for one area, given test ids. curl's runtests.pl takes test numbers.
TEST_RUNNERS = {
    "curl": ("cd tests && make -j6 >/dev/null 2>&1; perl runtests.pl -a -n {ids} 2>&1 | "
             "grep -E '^(TESTFAIL|TESTDONE|test [0-9]+.*(FAILED|OK))' | tail -40"),
}


def related_tests(bare, commit: str, patch: str, limit: int = 30) -> list[str]:
    """curl test cases that mention the feature a patch touches (named after its files, e.g. netrc for lib/netrc.c)."""
    words = {Path(f).stem for f in re.findall(r"^\+\+\+ b/(\S+)", patch, re.M)} - {"url", "transfer", "multi", "easy"}
    ids: set[int] = set()
    for w in words:
        out = subprocess.run(["git", "-C", str(bare), "grep", "-l", "-i", w, commit, "--", "tests/data"],
                             capture_output=True, text=True).stdout
        ids |= {int(m) for m in re.findall(r"tests/data/test(\d+)$", out, re.M)}
    return [str(i) for i in sorted(ids)[:limit]]


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
        failed = sorted(set(re.findall(r"TESTFAIL: These test cases failed: ([\d ]+)", out)[0].split())) \
            if "TESTFAIL" in out else []
        done = re.search(r"TESTDONE: (\d+) tests out of (\d+) reported OK", out)
        return {"built": True, "failed": failed, "ok": int(done.group(1)) if done else None,
                "total": int(done.group(2)) if done else None, "output": out[-1500:]}
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
        runner = TEST_RUNNERS["curl"].format(ids=" ".join(failing))
        feedback = (f"Your previous patch (already applied below) stops the bug, but it breaks these project tests "
                    f"that passed before: {', '.join(failing)}. Read the test definitions in tests/data/test<N> "
                    f"(and tests/unit/ for unit tests), run them with:\n  cd /work/repo && {runner}\n"
                    f"then change the fix so the bug check fails AND these tests pass.\n\nPrevious patch:\n{prior}")
    return res


def _attempt(bundle: dict, report: str, ledger: Ledger, emit: Callable[[dict], None], upstream_fix: str | None,
             prior: str | None, feedback: str | None) -> dict:
    bare = codecheck.ensure_repo(bundle["repo"])
    sb = Sandbox(codecheck.export_tree(bare, bundle["commit"]))
    emit({"stage": "fix", "type": "run", "cmd": "# building the project at the bundle's commit"})
    built = sb.run(bundle["build"], timeout=1500)
    if built["exit_code"] != 0:
        sb.close()
        return {"verdict": "BUILD_FAILED", "output": built["output"][-2000:]}
    for path, content in bundle["files"].items():
        sb.write(path, content)
    # Snapshot the sources, so the patch is exactly what the agent changed (build output is not tracked).
    sb.run("git init -q && git add -A '*.c' '*.h' && git -c user.name=x -c user.email=x@x commit -qm base", timeout=300)
    repo_dir = sb.workdir / "repo"
    if prior:
        sb.write("/work/prior.patch", prior)
        sb.run("git apply /work/prior.patch && make -j6 >/dev/null 2>&1", timeout=900)
    messages = [{"role": "system", "content": SYSTEM},
                {"role": "user", "content": (
                    f"CHECK COMMAND (exits 0 while the bug is present):\n{bundle['check']}\n\n"
                    f"PoC files already in place: {', '.join(bundle['files'])}\n\n"
                    f"Confirmed claim: {bundle['claim']}\n\nOriginal report:\n{report[:8000]}"
                    + (f"\n\nFEEDBACK FROM THE LAST ATTEMPT:\n{feedback}" if feedback else ""))}]
    transcript, t0, result = [], time.time(), None
    try:
        for step in range(MAX_STEPS):
            if time.time() - t0 > WALL_SECONDS:
                break
            _shrink_old_outputs(messages)
            if MAX_STEPS - step == 4:
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
                if tool == "finish":
                    result = {"explanation": args.get("explanation", ""),
                              "check_after": args.get("check_after", ""), "steps": step + 1}
                    break
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
                    out = sb.run(cmd, min(int(args.get("timeout", 300) or 300), 900))
                    emit({"stage": "fix", "type": "output", "exit_code": out["exit_code"], "output": out["output"][-1500:]})
                    transcript.append({"tool": "run", "cmd": cmd, **out})
                    content = json.dumps(out)
                elif tool == "write_file":
                    path, body = str(args.get("path", "")), str(args.get("content", ""))
                    emit({"stage": "fix", "type": "write", "path": path, "content": body[:3000]})
                    transcript.append({"tool": "write_file", "path": path, "content": body})
                    content = sb.write(path, body)
                else:
                    content = f"unknown tool {tool}"
                messages.append({"role": "tool", "tool_call_id": tc.id, "content": content})
            if result:
                break
        if not result:
            # Out of budget: the edits made so far can still be judged on their merits below.
            result = {"explanation": "budget ran out; patch taken from the edits made", "check_after": "",
                      "steps": MAX_STEPS}
        result["patch"] = sb.run("git diff", timeout=60)["output"]
    finally:
        sb.close()
    if not result or not result["patch"].strip():
        return {"verdict": "NO_FIX", "seconds": round(time.time() - t0), "transcript": transcript}

    # The agent's word is not enough: apply its patch in a fresh sandbox and re-run the bundle's check.
    emit({"stage": "fix", "type": "run", "cmd": "# verifying the patch in a fresh sandbox"})
    check = verify_patch(bundle, result["patch"], emit=lambda m: emit({"stage": "fix", "type": "log", "message": m}))
    result.update(verdict=check["verdict"], verification=check["with_patch"], seconds=round(time.time() - t0),
                  transcript=transcript)
    project = bundle["repo"].rstrip("/").split("/")[-1]
    if check["verdict"] == "FIX_VERIFIED" and project in TEST_RUNNERS:
        # The patch must not break the feature it touches: run the project's own tests for it, before and after.
        ids = related_tests(bare, bundle["commit"], result["patch"])
        if ids:
            emit({"stage": "fix", "type": "log", "message": f"running {len(ids)} related project tests, before and after"})
            before, after = run_tests(bundle, None, ids, project), run_tests(bundle, result["patch"], ids, project)
            new_failures = sorted(set(after.get("failed", [])) - set(before.get("failed", [])), key=int)
            result["tests"] = {"ids": ids, "before": {k: before.get(k) for k in ("ok", "total", "failed")},
                               "after": {k: after.get(k) for k in ("ok", "total", "failed")},
                               "new_failures": new_failures}
            if new_failures:
                result["verdict"] = "FIX_BREAKS_TESTS"
    if upstream_fix:
        diff = upstream_diff(bundle["repo"], upstream_fix)
        try:
            result["comparison"] = chat_json("big", COMPARE, f"AGENT PATCH:\n{result['patch'][:8000]}\n\n"
                                             f"UPSTREAM PATCH ({upstream_fix[:12]}):\n{diff[:12000]}", ledger, "compare fix")
        except ValueError:
            result["comparison"] = None
        result["upstream_fix"] = upstream_fix
    return result
