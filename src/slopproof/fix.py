"""Fix agent: from a verified proof bundle to a verified patch.

Nemotron Ultra writes a minimal patch in a sandbox where the bug reproduces. The patch only counts when, in a
fresh sandbox, the bundle's check stops passing with it applied. If the project's real fix is known, the two
patches are compared.
"""

import json
import subprocess
import time
from collections.abc import Callable

from . import codecheck
from .bundle import verify_patch
from .llm import Ledger, chat, chat_json
from .reproduce import _assistant_dict, _shrink_old_outputs
from .sandbox import Sandbox

MAX_STEPS = 30
WALL_SECONDS = 25 * 60

SYSTEM = """You fix a confirmed security bug in an open source C project. The project source is at /work/repo and a
build was started in the background (log /work/build.log; /work/build.done holds its exit code when done).
The bug is proven by a CHECK COMMAND that exits 0 while the bug is present.

Steps:
1. Wait for the build, then run the check command once to see the bug.
2. Read the relevant code (batch reads with grep -n and sed -n) and find the root cause.
3. Write the smallest correct fix as a unified diff to /work/fix.patch, with paths like a/lib/url.c and b/lib/url.c,
   and apply it: cd /work/repo && patch -p1 < /work/fix.patch
4. Rebuild with: cd /work/repo && make -j6 2>&1 | tail -5
5. Run the check command again: it must now exit non-zero, and the normal use it touches must still work.
Fix the root cause in project code. Never change the PoC, the check, or tests to make the check pass.
Do not weaken a feature to hide the bug (for example by disabling .netrc support entirely).
You have 30 tool calls. Call finish with the patch when the check fails with your fix applied."""

TOOLS = [
    {"type": "function", "function": {
        "name": "run", "description": "Run a bash command in /work/repo inside the sandbox.",
        "parameters": {"type": "object", "properties": {"cmd": {"type": "string"},
                                                        "timeout": {"type": "integer", "default": 300}},
                       "required": ["cmd"]}}},
    {"type": "function", "function": {
        "name": "write_file", "description": "Write a file under /work (for example /work/fix.patch).",
        "parameters": {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
                       "required": ["path", "content"]}}},
    {"type": "function", "function": {
        "name": "finish", "description": "Submit the fix.",
        "parameters": {"type": "object", "properties": {
            "patch": {"type": "string", "description": "the final unified diff, exactly as in /work/fix.patch"},
            "explanation": {"type": "string", "description": "root cause and why the fix is correct, citing file:line"},
            "check_after": {"type": "string", "description": "output and exit code of the check with the fix"}},
            "required": ["patch", "explanation"]}}},
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


def propose_fix(bundle: dict, report: str, ledger: Ledger, emit: Callable[[dict], None] = lambda e: None,
                upstream_fix: str | None = None) -> dict:
    bare = codecheck.ensure_repo(bundle["repo"])
    sb = Sandbox(codecheck.export_tree(bare, bundle["commit"]))
    sb.background(bundle["build"])
    for path, content in bundle["files"].items():
        sb.write(path, content)
    messages = [{"role": "system", "content": SYSTEM},
                {"role": "user", "content": (
                    f"CHECK COMMAND (exits 0 while the bug is present):\n{bundle['check']}\n\n"
                    f"PoC files already in place: {', '.join(bundle['files'])}\n\n"
                    f"Confirmed claim: {bundle['claim']}\n\nOriginal report:\n{report[:8000]}")}]
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
                    result = {"patch": args.get("patch", ""), "explanation": args.get("explanation", ""),
                              "check_after": args.get("check_after", ""), "steps": step + 1}
                    break
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
    finally:
        sb.close()
    if not result or not result["patch"].strip():
        return {"verdict": "NO_FIX", "seconds": round(time.time() - t0), "transcript": transcript}

    # The agent's word is not enough: apply its patch in a fresh sandbox and re-run the bundle's check.
    emit({"stage": "fix", "type": "run", "cmd": "# verifying the patch in a fresh sandbox"})
    check = verify_patch(bundle, result["patch"], emit=lambda m: emit({"stage": "fix", "type": "log", "message": m}))
    result.update(verdict=check["verdict"], verification=check["with_patch"], seconds=round(time.time() - t0),
                  transcript=transcript)
    if upstream_fix:
        diff = upstream_diff(bundle["repo"], upstream_fix)
        try:
            result["comparison"] = chat_json("big", COMPARE, f"AGENT PATCH:\n{result['patch'][:8000]}\n\n"
                                             f"UPSTREAM PATCH ({upstream_fix[:12]}):\n{diff[:12000]}", ledger, "compare fix")
        except ValueError:
            result["comparison"] = None
        result["upstream_fix"] = upstream_fix
    return result
