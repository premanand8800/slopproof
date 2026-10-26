"""Reproduction agent: Nemotron Ultra builds the project and tries to trigger the claimed bug in a sandbox."""

import json
import re
import time
from collections.abc import Callable
from pathlib import Path

from .llm import Ledger, chat, chat_json
from .sandbox import Sandbox

MAX_STEPS = 40
WALL_SECONDS = 25 * 60

# Build commands started in the background as soon as the sandbox is up, while the agent reads code.
BUILDS = {
    "curl": ("(autoreconf -fi || ./buildconf) && ./configure --with-openssl --disable-shared --enable-debug "
             "--enable-websockets CC=clang CFLAGS='-fsanitize=address,undefined -g -O1' "
             "LDFLAGS='-fsanitize=address,undefined' && make -j6"),
}

# A reproduction must run the project's own code: the built CLI run as a command (not just listed), or a PoC
# compiled against the built library.
_CMD_START = r"(?:^|[;&|(`]\s*|\b(?:then|do|exec|timeout\s+\S+|valgrind|gdb\s+-batch.*?--args)\s+)(?:\w+=\S*\s+)*"
ENTRY_POINTS = {
    "curl": (re.compile(_CMD_START + r"(?:\./|/work/repo/|\.\./repo/)?src/curl\b", re.M),
             re.compile(r"\b(?:clang|gcc|cc)\b[^\n]*(?:libcurl\.a|-lcurl)")),
}

RECIPES = {
    "curl": (
        "An ASan+UBSan build of curl was started in the background with:\n  " + BUILDS["curl"] + "\n"
        "Its log is /work/build.log; /work/build.done holds the exit code when it finishes (about 2 to 4 minutes).\n"
        "Wait for it with: while [ ! -f /work/build.done ]; do sleep 10; done; cat /work/build.done; tail -5 /work/build.log\n"
        "If it failed (old trees with new OpenSSL), reconfigure with fewer features, e.g. --without-ssl.\n"
        "The CLI is src/curl and the static library is lib/.libs/libcurl.a.\n"
        "Link a libcurl test program with: clang -fsanitize=address,undefined -g poc.c -Iinclude lib/.libs/libcurl.a "
        "$(pkg-config --libs openssl libpsl libnghttp2 zlib libbrotlidec libzstd 2>/dev/null) -lpthread -o poc\n"
        "Use timeout 600 for any rebuild. Never write wait loops on files you did not create; for your own background jobs, redirect output and poll with a bounded loop."
    ),
}

SYSTEM = """You are a security engineer triaging a vulnerability report filed against an open source project.
Your job is to find out whether the reported bug is REAL by reproducing it, not by reading the report's arguments.

Environment:
- A Linux container with the project's source at /work/repo, checked out at the commit the reporter was looking at.
- No internet. Loopback works, so you can run local test servers with python3 or nc on 127.0.0.1.
- Tools: clang, gcc, make, autotools, cmake, python3, OpenSSL and common -dev libraries.

Rules:
1. Build the project with AddressSanitizer and UndefinedBehaviorSanitizer when it is C or C++.
2. Trigger the bug the way a real attacker could: through the project's public API, CLI, network input or files,
   exactly as the report claims. Do not call internal functions with inputs the project can never pass them.
3. A PoC that is itself buggy (for example passing user input as a format string in YOUR code, or overflowing
   YOUR OWN buffer) proves nothing about the project. Do not count it.
4. Evidence of a real bug is: a sanitizer report or crash whose stack is inside project code, a hang, or observable
   wrong behaviour (for example a leaked credential in captured traffic) produced by the project.
5. If the report has no concrete reproduction, design the most direct test you can for the claim.
6. Read the relevant source before writing a PoC. Check the bounds, lengths and states the report ignores.
7. Stay efficient: you have 40 tool calls in total. The relevant source is already in the prompt: read more only
   if you must, and batch reads into one command (grep -n, sed -n for several ranges). Aim to have a PoC running
   by tool call 10. The build runs in the background, so write the PoC while it builds. Call finish as soon as you have strong evidence either way.
8. Impact, not just behaviour. Behaviour that looks wrong is only a vulnerability if it gives an attacker something
   the intended use does not. Before calling it reproduced, run the plain, intended way to reach the same effect
   (for example the same request without the encoding trick, or the same option used directly). If the
   plain way already gives the same result, the behaviour is by design: the outcome is not_reproduced.
   A sanitizer report or crash with its stack in project code always counts as impact.

Call finish with outcome:
- "reproduced": you triggered the claimed bug through a real code path, with evidence.
- "not_reproduced": you built the project, exercised the claimed path, and the bug did not occur; or the source
   shows the claimed condition is impossible (cite the lines that prevent it).
- "inconclusive": you could not build or could not reach the code path."""

TOOLS = [
    {"type": "function", "function": {
        "name": "run", "description": "Run a bash command in /work/repo inside the sandbox. Returns exit code and output.",
        "parameters": {"type": "object", "properties": {
            "cmd": {"type": "string"},
            "timeout": {"type": "integer", "description": "seconds, max 600", "default": 300}},
            "required": ["cmd"]}}},
    {"type": "function", "function": {
        "name": "write_file", "description": "Write a file inside /work (for example /work/poc.c).",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string"}, "content": {"type": "string"}}, "required": ["path", "content"]}}},
    {"type": "function", "function": {
        "name": "finish", "description": "Report the result of the reproduction attempt.",
        "parameters": {"type": "object", "properties": {
            "outcome": {"type": "string", "enum": ["reproduced", "not_reproduced", "inconclusive"]},
            "explanation": {"type": "string", "description": "what you tried and what happened, citing file:line"},
            "evidence": {"type": "string", "description": "the decisive output, e.g. the sanitizer report or test log, verbatim"},
            "poc": {"type": "string", "description": "the PoC source or command you ran"},
            "reachable_by_attacker": {"type": "boolean",
                                      "description": "can attacker-controlled input reach this code path in a real deployment"},
            "impact": {"type": "string", "enum": ["memory_safety", "crash_or_hang", "boundary_crossed", "none"],
                       "description": "what the attacker gains; none if the effect is reachable by intended use"},
            "baseline": {"type": "string",
                         "description": "the plain, intended-use command you compared against and its result"}},
            "required": ["outcome", "explanation", "evidence", "impact", "reachable_by_attacker"]}}},
]


def reproduce(tree: Path, project: str, report: str, claims: dict, analysis: dict, context: str,
              ledger: Ledger, emit: Callable[[dict], None]) -> dict:
    name = project.split("/")[-1]
    recipe = RECIPES.get(name, "Find the build instructions in the repository (README, INSTALL, CI files).")
    messages = [
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content": (
            f"Project: {project}\nBuild notes: {recipe}\n\n"
            f"Extracted claims:\n{json.dumps(claims, indent=1)[:5000]}\n\n"
            f"Static analysis already done on the real code (verify it, do not trust it blindly):\n"
            f"{json.dumps(analysis, indent=1)[:6000]}\n\n"
            f"Relevant source excerpts:\n{context[:20000]}\n\n"
            f"Full report:\n{report[:12000]}")},
    ]
    sb = Sandbox(tree)
    if name in BUILDS:
        sb.background(BUILDS[name])
    transcript = []
    t0 = time.time()
    try:
        for step in range(MAX_STEPS):
            if time.time() - t0 > WALL_SECONDS:
                break
            _shrink_old_outputs(messages)
            left = MAX_STEPS - step
            if left in (25, 12):
                messages.append({"role": "user", "content": f"{left} tool calls left. If no PoC has run yet, write and run it now."})
            elif left == 3:
                messages.append({"role": "user", "content": "3 tool calls left. Call finish with the evidence you have."})
            msg = chat("big", messages, ledger, "reproduce", tools=TOOLS, tool_choice="auto",
                       max_tokens=8000, temperature=0.3)
            messages.append(_assistant_dict(msg))
            if not msg.tool_calls:
                messages.append({"role": "user", "content": "Use the tools. Call finish when done."})
                continue
            for tc in msg.tool_calls:
                try:
                    args = json.loads(tc.function.arguments or "{}")
                except json.JSONDecodeError:
                    args = {}
                name = tc.function.name
                if name == "finish":
                    result = {"outcome": args.get("outcome", "inconclusive"), "explanation": args.get("explanation", ""),
                              "evidence": args.get("evidence", ""), "poc": args.get("poc", ""),
                              "impact": args.get("impact", "none"), "baseline": args.get("baseline", ""),
                              "steps": step + 1, "seconds": round(time.time() - t0), "transcript": transcript}
                    result["reachable_by_attacker"] = args.get("reachable_by_attacker")
                    _check_reproduction(result, name, report, ledger)
                    emit({"stage": "reproduce", "type": "finish", "outcome": result["outcome"]})
                    return result
                if name == "run":
                    cmd = str(args.get("cmd", ""))
                    timeout = min(int(args.get("timeout", 300) or 300), 600)
                    emit({"stage": "reproduce", "type": "run", "step": step + 1, "cmd": cmd[:400]})
                    out = sb.run(cmd, timeout)
                    emit({"stage": "reproduce", "type": "output", "step": step + 1,
                          "exit_code": out["exit_code"], "output": out["output"][-1500:]})
                    content = json.dumps(out)
                    transcript.append({"tool": "run", "cmd": cmd, **out})
                elif name == "write_file":
                    path, body = str(args.get("path", "")), str(args.get("content", ""))
                    emit({"stage": "reproduce", "type": "write", "step": step + 1, "path": path, "content": body[:3000]})
                    content = sb.write(path, body)
                    transcript.append({"tool": "write_file", "path": path, "content": body})
                else:
                    content = f"unknown tool {name}"
                messages.append({"role": "tool", "tool_call_id": tc.id, "content": content})
        return {"outcome": "inconclusive", "explanation": "step or time budget exhausted", "evidence": "",
                "poc": "", "steps": MAX_STEPS, "seconds": round(time.time() - t0), "transcript": transcript}
    finally:
        sb.close()


# Output that proves a memory error or crash in the project itself: a sanitizer report or a fatal signal,
# with a stack frame in the project's source.
_SANITIZER = re.compile(r"ERROR: \w+Sanitizer|runtime error:|SUMMARY: \w+Sanitizer|Segmentation fault|Aborted \(core")
_PROJECT_FRAME = re.compile(r"/work/repo/(?!tests?/)[\w./-]+\.(?:c|h|cc|cpp):\d+")

IMPACT_JUDGE = """You check one claimed vulnerability reproduction. Decide whether it shows a SECURITY impact:
the attacker gains something that the intended use of the software does not already give them.

Work it out in this order:
1. Who controls the input in the attack, and what could that same person get by using the software plainly?
   If the attacker controls a whole URL, path or option, anything they could name directly is already theirs:
   an unusual spelling that reaches the same thing is not a bypass.
2. Is there a security boundary the intended behaviour enforces (credentials scoped to a host or user, a
   sandboxed directory, a size limit, an authentication step), and did the evidence show it being crossed?
3. Ignore the agent's conclusion and the report's wording; judge the evidence and the baseline.

Not a security impact: reaching a resource the attacker could request directly, behaviour the user explicitly asked
for, a cosmetic difference, or a problem only in code attacker input cannot reach.
Reply with one JSON object only:
{"plain_way": "how the attacker could get the same result with intended use, or 'none'",
 "boundary": "the boundary crossed, or 'none'", "security_impact": true or false, "reason": "one or two sentences"}"""


def _check_reproduction(result: dict, project: str, report: str = "", ledger: Ledger | None = None) -> None:
    """Hard checks on a claimed reproduction; the agent's word is not enough."""
    if result["outcome"] != "reproduced":
        return
    patterns = ENTRY_POINTS.get(project)
    if patterns:
        ran = "\n".join(t.get("cmd", "") + "\n" + t.get("content", "") for t in result["transcript"])
        if not any(p.search(ran) for p in patterns):
            # A PoC that re-implements the logic in its own code shows nothing about the project.
            _demote(result, "inconclusive", "The PoC never ran the project's own code (its CLI or library), so it "
                                            "proves nothing about the project.")
            return
    if result.get("reachable_by_attacker") is False:
        _demote(result, "not_reproduced", "Reproduced only on a path attacker input cannot reach.")
        return
    if result.get("impact") == "none":
        _demote(result, "not_reproduced", "Behaviour reproduced, but it gives an attacker nothing the intended use "
                                          "does not.")
        return
    outputs = "\n".join(t.get("output", "") for t in result["transcript"] if t.get("tool") == "run")
    if _SANITIZER.search(outputs) and _PROJECT_FRAME.search(outputs):
        result["impact_check"] = "sanitizer or crash report with a frame in project code"
        return
    if result.get("impact") in ("memory_safety", "crash_or_hang"):
        result["impact"] = "unverified"  # claimed a memory error, but no sanitizer or crash output shows one
    if ledger is None:
        return
    # No crash to point at: an independent model judges whether the shown behaviour is a security impact at all.
    try:
        verdict = chat_json("big", IMPACT_JUDGE, (
            f"REPORT (excerpt):\n{report[:4000]}\n\nAGENT EXPLANATION:\n{result['explanation'][:3000]}\n\n"
            f"EVIDENCE:\n{result['evidence'][:3000]}\n\nBASELINE (intended use):\n{result.get('baseline') or 'none given'}"),
            ledger, "impact check", max_tokens=6000, think=True)
    except ValueError:
        verdict = {"security_impact": False, "reason": "the impact check gave no answer"}
    result["impact_check"] = verdict.get("reason", "")
    if not verdict.get("security_impact"):
        _demote(result, "not_reproduced", f"Behaviour reproduced, but no security impact: {verdict.get('reason', '')}")


def _demote(result: dict, outcome: str, why: str) -> None:
    result["outcome"] = outcome
    result["explanation"] = f"{why} {result['explanation']}"


def _assistant_dict(msg) -> dict:
    d = {"role": "assistant", "content": msg.content or ""}
    if msg.tool_calls:
        d["tool_calls"] = [{"id": tc.id, "type": "function",
                            "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                           for tc in msg.tool_calls]
    return d


def _shrink_old_outputs(messages: list[dict], keep_last: int = 4, limit: int = 800) -> None:
    """Cut old tool outputs so the context, and the bill, do not grow with every step."""
    tool_idx = [i for i, m in enumerate(messages) if m["role"] == "tool"]
    for i in tool_idx[:-keep_last]:
        if len(messages[i]["content"]) > limit:
            messages[i]["content"] = messages[i]["content"][:300] + " ...[older output trimmed]... " + messages[i]["content"][-400:]
