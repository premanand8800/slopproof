"""Investigator: a Nemotron 3 Ultra tool-calling agent for reports the fixed pipeline left open.

The pipeline runs every check on every report. When its verdict is still open (PLAUSIBLE), this agent gets
everything found so far and decides what to look at next: more code at the commit the reporter saw, the
project's git history up to that commit, and the web through every Tavily endpoint (search, extract with a
question, map, crawl, research).

It cannot decide anything on its word. Its findings must cite evidence, and code checks every piece of it:
a code quote must be in the pinned tree at that path near that line, a web quote must be in content a tool
returned in this run, a git quote must be in a commit before the pinned one. Evidence that fails is dropped
(and shown as dropped); a finding left with none becomes unknown. The guards in pipeline.apply_guards decide
what a verified finding may do; the agent can never produce CONFIRMED.
"""

import json
import re
import subprocess
import time
from collections.abc import Callable
from pathlib import Path

from rapidfuzz import fuzz

from . import codecheck, codesearch, webtools
from .llm import Ledger, chat
from .reproduce import _assistant_dict

MAX_CALLS = 12
OUTPUT_LIMIT = 3500  # characters of one tool result the agent sees
WALL_SECONDS = 7 * 60
RESEARCH_SCHEMA = {
    "type": "object",
    "properties": {
        "already_reported_or_fixed": {"type": "string", "description": "yes, no or unknown, with the advisory, "
                                                                     "commit or release that shows it"},
        "documented_behaviour": {"type": "string", "description": "does the project document this behaviour as "
                                                                 "intended or out of scope, quoting the page"},
        "key_sources": {"type": "array", "items": {"type": "string"}, "description": "URLs of the main sources"},
        "summary": {"type": "string", "description": "two or three sentences"},
    },
    "required": ["already_reported_or_fixed", "documented_behaviour", "summary"],
}

SYSTEM = """You are a security engineer investigating a vulnerability report filed against an open source project.
A fixed pipeline already checked it: extracted claims, checked them against the source tree, searched the web,
and a static analysis read the code. The report is still open. Your job: decide what to look at next to settle it,
look, and report what you found with evidence.

You have tools for the source tree at the exact commit the reporter saw (search_code, read_function, read_lines,
grep_code), its git history up to that commit (git_log_search, git_show), and the web (web_search, read_pages,
map_docs, crawl_docs, deep_research). Some web tools can be unavailable; if a tool is refused, carry on with the
others. Plan first: what single fact would settle the report? Check that first. Good targets:
- the precondition the bug needs (a length check, a NUL terminator, a state) in the code and in its real callers;
- whether the claimed code, option or behaviour exists at all in this version;
- earlier fixes or advisories in the same area (git history, the project's security pages), and whether this
  report is a bypass of one;
- whether the project documents the behaviour as intended;
- the impact: what an attacker gains that intended use does not already give them (memory a command-line tool
  leaks once before it exits, or reaching what the user could request directly, gives an attacker nothing).
Check the web at least once (web_search, with domains set to the project's own site when that is where the
answer is): an advisory, a fix, or documentation of the behaviour can settle in one call what code reading cannot.
Every tool call takes a "why": one sentence on what you expect to learn. Do not repeat a call. You have about
{calls} tool calls; call finish as soon as the evidence settles it, or when you have done what you can.

In finish, each finding is one security claim the report makes, stated as the report states it, including what
the attacker gains (for example "a malicious server can make curl write past the end of buf"). Usually one to three.
Facts that are true whether or not the vulnerability is real (a file exists, a function uses memcpy, a value comes
from an environment variable) are not findings: they are evidence for the claim they bear on.
status: holds (the evidence shows the claim is true as stated, impact included), refuted (the evidence shows it
cannot happen as stated, or gives the attacker nothing intended use does not), unknown (you could not tell).
Not finding something is not a refutation: "I found no caller that does X" means unknown. refuted needs the code
that prevents the claim (the check, the bound, the reset, the documented rule), quoted.
Every holds or refuted needs evidence copied EXACTLY from tool output in this run:
- {{"kind": "code", "path": "lib/x.c", "line": 123, "quote": "one to five lines of code exactly as shown"}}
- {{"kind": "web", "url": "https://...", "quote": "a sentence exactly as the page returned it"}}
- {{"kind": "git", "commit": "abc123", "quote": "a line from that commit's message or diff, as shown"}}
Evidence is checked by code against the tree and the pages; anything not found is dropped and its finding becomes
unknown. Research answers are leads, not sources: quote the page itself.
recommend: close (the central claim is refuted by verified evidence), keep_open (it may be real, or you cannot
tell), confirm_needed (it looks real and needs a sandbox reproduction). You can never confirm a vulnerability:
only a sandbox reproduction can. Closing a real vulnerability is far worse than keeping slop open."""


def _fn(name: str, desc: str, props: dict, required: list[str]) -> dict:
    props = {**props, "why": {"type": "string", "description": "one sentence: what you expect to learn"}}
    return {"type": "function", "function": {"name": name, "description": desc, "parameters": {
        "type": "object", "properties": props, "required": [*required, "why"]}}}


_S = {"type": "string"}
EVIDENCE = {"type": "object", "properties": {
    "kind": {"type": "string", "enum": ["code", "web", "git"]}, "path": _S, "line": {"type": "integer"},
    "url": _S, "commit": _S, "quote": _S}, "required": ["kind", "quote"]}
TOOLS = [
    _fn("search_code", "BM25 search over the project's functions at the pinned commit. Returns file:lines and names.",
        {"query": _S}, ["query"]),
    _fn("read_function", "Source of a function by name, with line numbers (short wrappers bring their callees).",
        {"name": _S}, ["name"]),
    _fn("read_lines", "Lines start..end of a file in the pinned tree (at most 100 lines).",
        {"path": _S, "start": {"type": "integer"}, "end": {"type": "integer"}}, ["path", "start", "end"]),
    _fn("grep_code", "git grep -n -E over the pinned tree. Returns path:line:text (at most 40 lines).",
        {"pattern": _S, "path": {"type": "string", "description": "optional directory or file to limit to"}},
        ["pattern"]),
    _fn("git_log_search", "Commits up to the pinned commit whose diff adds or removes this text (git log -S), or "
                          "whose message contains it (in_messages=true).",
        {"text": _S, "in_messages": {"type": "boolean"}}, ["text"]),
    _fn("git_show", "One commit (before the pinned one): message and diff, optionally limited to a path.",
        {"commit": _S, "path": _S}, ["commit"]),
    _fn("web_search", "Tavily web search. Optional domains limits it to sites such as the project's own.",
        {"query": _S, "domains": {"type": "array", "items": _S}}, ["query"]),
    _fn("read_pages", "Tavily extract: read up to 5 pages, returning only the parts relevant to the question.",
        {"urls": {"type": "array", "items": _S}, "question": _S}, ["urls", "question"]),
    _fn("map_docs", "Tavily map: list the pages of a documentation site that match what you look for.",
        {"url": _S, "what": _S}, ["url", "what"]),
    _fn("crawl_docs", "Tavily crawl: read the project's own docs or security pages under a URL, following "
                      "instructions, and return the relevant parts.",
        {"url": _S, "instructions": _S}, ["url", "instructions"]),
    _fn("deep_research", "Tavily research agent with a structured answer: prior reports, fixes, documented "
                         "behaviour. Slow and costly; at most once per run.", {"question": _S}, ["question"]),
    {"type": "function", "function": {"name": "finish", "description": "Report the findings, each with evidence.",
     "parameters": {"type": "object", "properties": {
         "findings": {"type": "array", "items": {"type": "object", "properties": {
             "claim": _S, "status": {"type": "string", "enum": ["holds", "refuted", "unknown"]},
             "evidence": {"type": "array", "items": EVIDENCE}}, "required": ["claim", "status", "evidence"]}},
         "recommend": {"type": "string", "enum": ["keep_open", "close", "confirm_needed"]},
         "confidence": {"type": "number"},
         "summary": {"type": "string", "description": "two or three sentences for the maintainer"}},
         "required": ["findings", "recommend", "confidence", "summary"]}}},
]
FINISH_ONLY = [t for t in TOOLS if t["function"]["name"] == "finish"]

# In a replay, pages about the benchmark's own labels (maintainers listing reports as AI slop, links to HackerOne
# reports) would give the answer away: they are dropped before the agent sees them.
_LEAK = re.compile(r"hackerone\.com/reports/|\bAI[- ]slop\b|\bslop\b", re.I)


def _norm_text(text: str) -> str:
    text = re.sub(r"[*_`#>|\[\]]+", " ", text or "")
    return re.sub(r"\s+", " ", text).strip().lower()


class Investigation:
    """One run of the agent: its tools, the content they returned (for checking quotes), and its steps."""

    def __init__(self, tree: Path, bare: Path, sha: str, ledger: Ledger, as_of: str | None,
                 emit: Callable[[dict], None]):
        self.tree, self.bare, self.sha, self.ledger, self.as_of, self.emit = tree, bare, sha, ledger, as_of, emit
        self.pages: dict[str, str] = {}  # normalised URL -> text returned for it in this run
        self.commits: dict[str, str] = {}  # full sha -> text git_show / git_log returned for it
        self.steps: list[dict] = []
        self.researched = False

    # ---- code tools: the pinned tree and its history, never later commits
    def search_code(self, query: str) -> str:
        hits = codesearch.index_for(self.bare, self.sha).search(codesearch.tokens(query), k=8)
        return "\n".join(f"{f.file}:{f.start}-{f.end} {f.name} (matches {', '.join(t)})" for f, _, t in hits) \
            or "no matching functions"

    def read_function(self, name: str) -> str:
        out = codesearch.definitions(self.bare, self.sha, [name], budget=6000)
        return out or f"No function named {name} in this tree. Try search_code or grep_code."

    def read_lines(self, path: str, start: int, end: int) -> str:
        rel = str(path or "").strip().lstrip("/")
        f = (self.tree / rel).resolve()
        if not rel or not f.is_file() or not f.is_relative_to(self.tree.resolve()):
            return f"{rel} is not a file in this tree."
        lines = f.read_text(errors="replace").splitlines()
        start = max(1, int(start or 1))
        end = min(len(lines), int(end or start + 60), start + 99)
        return f"=== {rel}:{start}-{end} (of {len(lines)})\n" + "\n".join(
            f"{i:5d}  {lines[i - 1]}" for i in range(start, end + 1))

    def _git(self, *args: str, timeout: int = 40) -> str:
        try:
            r = subprocess.run(["git", "-C", str(self.bare), *args], capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return "[git timed out]"
        return r.stdout if r.returncode == 0 else f"[git error] {r.stderr.strip()[:300]}"

    def grep_code(self, pattern: str, path: str | None = None) -> str:
        args = ["grep", "-n", "-I", "-E", "-e", pattern, self.sha, "--"]
        args += [path.strip().lstrip("/")] if path else [":!tests", ":!docs"]
        out = self._git(*args, timeout=30)
        rows = [ln.split(":", 1)[1] if ln.startswith(self.sha) else ln for ln in out.splitlines()]
        more = f"\n... {len(rows) - 40} more lines" if len(rows) > 40 else ""
        return "\n".join(r[:200] for r in rows[:40]) + more if rows else "no matches"

    def git_log_search(self, text: str, in_messages: bool = False) -> str:
        how = ["--grep", text, "-i", "-F"] if in_messages else ["-S", text]
        out = self._git("log", *how, "--format=%H %as %s", "-n", "20", self.sha, timeout=60)
        for line in out.splitlines():
            if re.match(r"[0-9a-f]{40} ", line):
                self.commits.setdefault(line[:40], "")
                self.commits[line[:40]] += line + "\n"
        rows = [ln[:12] + ln[40:] if re.match(r"[0-9a-f]{40} ", ln) else ln for ln in out.splitlines()]
        return "\n".join(rows) or f"no commits before {self.sha[:12]} match"

    def _ancestor(self, commit: str) -> str | None:
        full = self._git("rev-parse", "--verify", "-q", f"{commit}^{{commit}}").strip()
        if not re.fullmatch(r"[0-9a-f]{40}", full):
            return None
        r = subprocess.run(["git", "-C", str(self.bare), "merge-base", "--is-ancestor", full, self.sha])
        return full if r.returncode == 0 else None

    def git_show(self, commit: str, path: str | None = None) -> str:
        full = self._ancestor(str(commit).strip())
        if not full:
            return (f"{commit} is not a commit in the history up to {self.sha[:12]} (later commits are off limits: "
                    f"they did not exist when the report was filed).")
        args = ["show", "--stat", "--patch", "--format=commit %H%nDate: %as%n%n%s%n%n%b", full]
        if path:
            args += ["--", path.strip().lstrip("/")]
        out = self._git(*args)
        out = out if len(out) <= 7000 else out[:6500] + "\n...[diff cut]...\n" + out[-400:]
        self.commits[full] = self.commits.get(full, "") + out
        return out

    # ---- web tools, all through webtools (credits counted; extract/map/crawl/research are refused in a replay)
    def _keep(self, url: str, text: str) -> None:
        key = webtools.norm_url(url)
        self.pages[key] = self.pages.get(key, "") + "\n" + text

    def _leaks(self, *texts: str) -> bool:
        return bool(self.as_of) and any(_LEAK.search(t or "") for t in texts)

    def web_search(self, query: str, domains: list[str] | None = None) -> str:
        extra = {"exclude_domains": ["gist.github.com"]} if self.as_of else {}
        res = webtools.search(query, self.ledger, self.as_of, depth="basic" if self.as_of else "advanced",
                              max_results=6, domains=[d for d in domains or [] if isinstance(d, str)][:5] or None,
                              **extra)
        out, dropped = [], 0
        for r in res.get("results", []):
            text = (r.get("content") or "")[:900]
            if self._leaks(r.get("url", ""), r.get("title", ""), text):
                dropped += 1
                continue
            self._keep(r["url"], f"{r.get('title', '')}\n{text}")
            out.append(f"[{r['url']}] {r.get('title', '')}\n{text}")
        note = f"\n({dropped} result(s) about benchmark labels dropped in this replay)" if dropped else ""
        when = f" (pages published before {self.as_of[:10]} only)" if self.as_of else ""
        return ("\n\n".join(out) if out else f"no results{when}") + note

    def read_pages(self, urls: list[str], question: str) -> str:
        urls = [u for u in dict.fromkeys(urls or []) if isinstance(u, str) and re.match(r"https?://", u)][:5]
        if not urls:
            return "no valid URLs"
        res = webtools.extract(urls, self.ledger, self.as_of, query=question, chunks=4)
        out = []
        for r in res.get("results", []):
            text = (r.get("raw_content") or "")[:3000]
            self._keep(r["url"], text)
            out.append(f"=== {r['url']}\n{text}")
        for f in res.get("failed_results", []):
            out.append(f"=== {f.get('url')}: could not be read")
        return "\n\n".join(out) or "nothing returned"

    def map_docs(self, url: str, what: str) -> str:
        res = webtools.site_map(url, self.ledger, self.as_of, instructions=what, limit=40)
        urls = res.get("results") or []
        return "\n".join(str(u) for u in urls[:40]) or "no pages found"

    def crawl_docs(self, url: str, instructions: str) -> str:
        res = webtools.crawl(url, instructions, self.ledger, self.as_of, limit=12, chunks=3)
        out = []
        for r in res.get("results", []):
            text = (r.get("raw_content") or "")[:1800]
            self._keep(r["url"], text)
            out.append(f"=== {r['url']}\n{text}")
        return "\n\n".join(out[:8]) or "no pages returned"

    def deep_research(self, question: str) -> str:
        if self.researched:
            return "deep_research was already used in this run (once per run). Use web_search or read_pages."
        self.researched = True
        res = webtools.research(question, RESEARCH_SCHEMA, self.ledger, self.as_of)
        if res.get("status") != "completed":
            return f"research did not finish (status {res.get('status')}); carry on with other tools"
        answer = res.get("content")
        srcs = [s.get("url") for s in res.get("sources") or [] if isinstance(s, dict) and s.get("url")]
        text = answer if isinstance(answer, str) else json.dumps(answer, indent=1)
        return (f"{text[:4000]}\n\nSources (read them with read_pages to quote them):\n" + "\n".join(srcs[:10]))

    # ---- one tool call
    def call(self, tool: str, args: dict) -> tuple[str, bool]:
        """Run a tool. Returns (output, refused)."""
        try:
            if tool == "search_code":
                return self.search_code(str(args.get("query", ""))), False
            if tool == "read_function":
                return self.read_function(str(args.get("name", ""))), False
            if tool == "read_lines":
                return self.read_lines(str(args.get("path", "")), args.get("start", 1), args.get("end", 0)), False
            if tool == "grep_code":
                return self.grep_code(str(args.get("pattern", "")), args.get("path")), False
            if tool == "git_log_search":
                return self.git_log_search(str(args.get("text", "")), bool(args.get("in_messages"))), False
            if tool == "git_show":
                return self.git_show(str(args.get("commit", "")), args.get("path")), False
            if tool == "web_search":
                return self.web_search(str(args.get("query", "")), args.get("domains")), False
            if tool == "read_pages":
                return self.read_pages(args.get("urls") or [], str(args.get("question", ""))), False
            if tool == "map_docs":
                return self.map_docs(str(args.get("url", "")), str(args.get("what", ""))), False
            if tool == "crawl_docs":
                return self.crawl_docs(str(args.get("url", "")), str(args.get("instructions", ""))), False
            if tool == "deep_research":
                return self.deep_research(str(args.get("question", ""))), False
            return f"unknown tool {tool}", False
        except webtools.ReplayRefused as e:
            return (f"[refused] {e}. This run is a replay as of the report date: use web_search (limited to pages "
                    f"published before then) and the code tools instead."), True
        except Exception as e:  # noqa: BLE001 - a failed tool is a result the agent can work around
            return f"[tool failed] {type(e).__name__}: {str(e)[:300]}", False

    # ---- checking the agent's evidence, in code
    def check_evidence(self, ev: dict) -> dict:
        kind, quote = ev.get("kind"), str(ev.get("quote") or "")
        out = {k: ev.get(k) for k in ("kind", "path", "line", "url", "commit", "quote") if ev.get(k) is not None}
        if kind == "code":
            if not isinstance(ev.get("line"), int):
                return {**out, "verified": False, "why": "no line number"}
            m = codecheck.quote_near(self.tree, str(ev.get("path") or ""), ev["line"], quote)
            return {**out, "verified": m["ok"], **({"line": m["line"]} if m["ok"] else {"why": m["why"]})}
        if kind == "web":
            q = _norm_text(quote)
            page = self.pages.get(webtools.norm_url(str(ev.get("url") or "")))
            if page is None:
                return {**out, "verified": False, "why": "no tool in this run returned that URL"}
            if len(q) < 20:
                return {**out, "verified": False, "why": "quote too short"}
            text = _norm_text(page)
            ok = q in text or fuzz.partial_ratio(q, text) >= 92
            return {**out, "verified": ok, **({} if ok else {"why": "quote not in what the page returned"})}
        if kind == "git":
            full = self._ancestor(str(ev.get("commit") or "").strip()) if ev.get("commit") else None
            if not full:
                return {**out, "verified": False, "why": "not a commit up to the pinned one"}
            text = self.commits.get(full)
            if text is None:
                return {**out, "verified": False, "why": "that commit was not shown in this run"}
            q = re.sub(r"\s+", " ", quote).strip()
            ok = len(q) >= 10 and (q in re.sub(r"\s+", " ", text) or fuzz.partial_ratio(q, text) >= 95)
            return {**out, "commit": full[:12], "verified": ok, **({} if ok else {"why": "quote not in that commit"})}
        return {**out, "verified": False, "why": f"unknown evidence kind {kind}"}

    def check_findings(self, findings: list) -> list[dict]:
        checked = []
        for f in findings if isinstance(findings, list) else []:
            if not isinstance(f, dict):
                continue
            evs = [self.check_evidence(e) for e in (f.get("evidence") or []) if isinstance(e, dict)][:6]
            status = f.get("status") if f.get("status") in ("holds", "refuted", "unknown") else "unknown"
            item = {"claim": str(f.get("claim", ""))[:400], "status": status, "evidence": evs}
            if status != "unknown" and not any(e["verified"] for e in evs):
                item["status"], item["claimed_status"] = "unknown", status  # nothing it cited stands
            checked.append(item)
        return checked[:8]


def _last_sentences(text: str, limit: int = 450) -> str:
    """The end of the agent's reasoning (where it says what it will do next), starting at a sentence."""
    text = " ".join(text.split())
    if len(text) <= limit:
        return text
    tail = text[-limit:]
    m = re.search(r"(?<=[.!?:])\s+(?=[A-Z`])", tail)
    return tail[m.end():] if m else "…" + tail


def _hook(tool: str, args: dict, steps: list[dict]) -> str | None:
    """Rules checked before each call, like the reproduction agent's hooks: no repeats, no re-reading."""
    for st in steps:
        a = st["args"]
        if st["tool"] == tool == "grep_code" and a.get("pattern") == args.get("pattern"):
            return ("[hook] You already grepped this pattern. Its matches were:\n" + st.get("preview", "")[:1200]
                    + "\nUse them: read a match, or call finish.")
        if st["tool"] == tool == "read_lines" and a.get("path") == args.get("path"):
            try:
                # What the earlier call actually returned: read_lines gives at most 100 lines.
                a_start = int(a.get("start") or 1)
                a_end = min(int(a.get("end") or a_start + 60), a_start + 99)
                lo, hi = max(a_start, int(args.get("start") or 0)), min(a_end, int(args.get("end") or 0))
                span = max(1, int(args.get("end") or 0) - int(args.get("start") or 0))
            except (TypeError, ValueError):
                continue
            if hi - lo >= 0.7 * span:
                return ("[hook] You already read these lines (step " + str(st.get("step", "?")) + "). Decide what they show, "
                        "look somewhere new, or call finish.")
        if st["tool"] == tool and json.dumps(a, sort_keys=True) == json.dumps(args, sort_keys=True):
            return "[hook] You already made exactly this call; its output is above."
    return None


def _shrink(messages: list[dict], keep_last: int = 3) -> None:
    """Old tool outputs shrink to their first lines, so the context (and the bill) stays flat."""
    tool_idx = [i for i, m in enumerate(messages) if m["role"] == "tool"]
    for i in tool_idx[:-keep_last]:
        c = messages[i]["content"]
        if len(c) > 400:
            messages[i]["content"] = c[:300] + " ...[older output trimmed; it was read]"


def well_cited(finding: dict) -> bool:
    """A refutation can help close a report only if the agent read the code right: at least two of its quotes
    are where it says, and more of them check out than fail. An agent that misquotes most of what it cites has
    not read the code it argues from (in the pilot, the one real CVE closed rested on 1 verified quote of 5)."""
    evs = finding.get("evidence") or []
    ok = sum(1 for e in evs if e.get("verified"))
    return ok >= 2 and ok > len(evs) - ok


def signals(findings: list[dict], recommend: str | None) -> dict:
    """What the investigation may do in the guards. Only findings backed by verified evidence count, and a
    refutation only when it is well cited. Keeping a report open needs less than closing it."""
    backed = [f for f in findings or [] if any(e.get("verified") for e in f.get("evidence") or [])]
    holds = any(f["status"] == "holds" for f in backed)
    refutes = recommend == "close" and not holds and any(f["status"] == "refuted" and well_cited(f) for f in backed)
    return {"holds": holds, "refutes": refutes}


ENDPOINT = {"search_code": "code search", "read_function": "read function", "read_lines": "read lines",
            "grep_code": "git grep", "git_log_search": "git log -S", "git_show": "git show",
            "web_search": "Tavily search", "read_pages": "Tavily extract", "map_docs": "Tavily map",
            "crawl_docs": "Tavily crawl", "deep_research": "Tavily research"}


def _target(tool: str, args: dict) -> str:
    """A short label of what a call looks at, e.g. curl.se/docs or lib/ws.c:120."""
    host = lambda u: re.sub(r"^https?://(www\.)?", "", str(u)).rstrip("/")[:60]  # noqa: E731
    if tool in ("map_docs", "crawl_docs"):
        return host(args.get("url", ""))
    if tool == "read_pages":
        urls = args.get("urls") or []
        return ", ".join(host(u) for u in urls[:2]) + (f" +{len(urls) - 2}" if len(urls) > 2 else "")
    if tool == "read_lines":
        return f"{args.get('path')}:{args.get('start')}-{args.get('end')}"
    if tool == "git_show":
        return str(args.get("commit", ""))[:12] + (f" {args['path']}" if args.get("path") else "")
    for k in ("query", "name", "pattern", "text", "question"):
        if args.get(k):
            return str(args[k])[:90]
    return ""


def _brief(claims: dict, code: dict, web: dict, analysis: dict, found: list | None, first: dict) -> str:
    """What the pipeline found, compact: the agent reads more with its tools."""
    c = {k: claims.get(k) for k in ("summary", "vuln_class", "attack_surface", "files", "functions", "line_refs",
                                    "cves", "urls", "claimed_version")}
    checks = {
        "files": [f"{f['path']}: {'exists' if f['exists'] else 'missing'}" for f in code.get("files", [])],
        "functions": [f"{f['name']}: {'defined at ' + ', '.join(f['definitions'][:2]) if f['exists'] else 'not in the project'}"
                      for f in code.get("functions", [])],
        "line_refs": [f"{r['file']}:{r['line']} is {r['actual']!r}" for r in code.get("line_refs", [])][:6],
        "quotes": [f"{q['verdict']} (best match {q['match'].get('file')}:{q['match'].get('line')}): {q['quote'][:120]}"
                   for q in code.get("code_quotes", [])][:6]}
    pa = (web or {}).get("prior_art") or {}
    w = {"cves": [{k: x.get(k) for k in ("cve", "supported", "explanation", "evidence_url")} for x in web.get("cves", [])],
         "urls": [{k: x.get(k) for k in ("url", "reachable", "supports_claim", "explanation")} for x in web.get("urls", [])],
         "prior_art": {k: pa.get(k) for k in ("known_issue", "already_fixed", "documented_behaviour", "explanation",
                                              "evidence_url", "error")}}
    a = {"claim_holds": analysis.get("claim_holds"), "reasoning": str(analysis.get("reasoning", ""))[:3500],
         "key_lines": (analysis.get("key_lines") or [])[:8],
         "callers": [{k: x.get(k) for k in ("caller", "allows", "why")} for x in (analysis.get("callers") or [])[:6]],
         "test_plan": str(analysis.get("test_plan", ""))[:600]}
    hits = [f"{h['file']}:{h['start']}-{h['end']} {h['name']}" for h in (found or [])[:8]]
    return (f"CLAIMS:\n{json.dumps(c, indent=1)[:3000]}\n\nCODE CHECKS:\n{json.dumps(checks, indent=1)[:2500]}\n\n"
            f"WEB CHECKS:\n{json.dumps(w, indent=1)[:2500]}\n\nSTATIC ANALYSIS:\n{json.dumps(a, indent=1)[:6000]}\n\n"
            f"CODE SEARCH TOP HITS: {', '.join(hits)}\n\n"
            f"PIPELINE VERDICT SO FAR: {first.get('verdict')} (model said {first.get('model_verdict')}): "
            f"{str(first.get('headline', ''))[:400]}")


def investigate(title: str, body: str, project: str, claims: dict, code: dict, web: dict, analysis: dict,
                found: list | None, first: dict, tree: Path, bare: Path, sha: str, ledger: Ledger,
                as_of: str | None = None, emit: Callable[[dict], None] = lambda e: None,
                max_calls: int = MAX_CALLS, wall: float = WALL_SECONDS) -> dict:
    inv = Investigation(tree, bare, sha, ledger, as_of, emit)
    usd0, credits0 = ledger.summary()["total_usd"], ledger.summary()["tavily_credits"]
    where = (f"This is a replay as of {as_of[:10]}: the web is limited to pages published before that day."
             if as_of else "This is a live run.")
    messages = [
        {"role": "system", "content": SYSTEM.format(calls=max_calls)},
        {"role": "user", "content": (
            f"Project: {project}. Source tree and history pinned at commit {sha[:12]}. {where}\n\n"
            f"REPORT TITLE: {title}\n\nREPORT:\n{body[:7000]}\n\n{_brief(claims, code, web or {}, analysis or {}, found, first)}")},
    ]
    emit({"stage": "investigate", "type": "begin", "budget": {"calls": max_calls, "seconds": wall},
          "replay": bool(as_of)})
    t0, calls, final, stopped = time.time(), 0, None, None
    for _ in range(max_calls + 4):
        if time.time() - t0 > wall:
            stopped = "time budget used up"
            break
        if calls >= max_calls:
            stopped = "step budget used up"
            break
        _shrink(messages)
        msg = chat("big", messages, ledger, "investigate", tools=TOOLS, tool_choice="auto", max_tokens=5000,
                   temperature=0.3, extra_body={"chat_template_kwargs": {"enable_thinking": True}})
        messages.append(_assistant_dict(msg))
        # The agent's reasoning for this turn: its thinking, or what it wrote before the calls.
        thought = getattr(msg, "reasoning_content", None) or \
            (getattr(msg, "model_extra", None) or {}).get("reasoning_content") or ""
        thought = str(thought).strip() or re.sub(r"<think>.*?</think>", "", msg.content or "", flags=re.S).strip()
        if not msg.tool_calls:
            messages.append({"role": "user", "content": "Use the tools, or call finish."})
            continue
        for tc in msg.tool_calls:
            try:
                args = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {}
            tool = tc.function.name
            if tool == "finish":
                final = args
                messages.append({"role": "tool", "tool_call_id": tc.id, "content": "finished"})
                continue
            if final is not None or calls >= max_calls:
                messages.append({"role": "tool", "tool_call_id": tc.id, "content": "not run: budget used up"})
                continue
            calls += 1
            why = str(args.pop("why", "") or "").strip() or (thought.splitlines()[0] if thought else "")
            step = {"step": calls, "tool": tool, "endpoint": ENDPOINT.get(tool, tool), "target": _target(tool, args),
                    "why": why[:300], "args": dict(args)}
            if thought:
                step["thought"], thought = _last_sentences(thought), ""  # the agent's own words, once per turn
            emit({"stage": "investigate", "type": "call", **step})
            blocked = _hook(tool, args, inv.steps)
            if blocked:
                content, refused = blocked, False
                step["hook"] = True
                if len(inv.steps) >= 1 and inv.steps[-1].get("hook"):
                    stopped = "repeated calls the hooks had already answered"
            else:
                c0 = ledger.summary()["tavily_credits"]
                content, refused = inv.call(tool, args)
                step["credits"] = ledger.summary()["tavily_credits"] - c0
            step.update(refused=refused, chars=len(content), preview=content[:600])
            inv.steps.append(step)
            emit({"stage": "investigate", "type": "result", "step": calls, "refused": refused,
                  "credits": step.get("credits", 0), "preview": content[:600], "chars": len(content)})
            if len(content) > OUTPUT_LIMIT:
                content = content[:OUTPUT_LIMIT - 300] + "\n...[cut]...\n" + content[-250:]
            left = max_calls - calls
            note = f"\n[{left} tool calls left]" if left > 2 else f"\n[{left} tool calls left: call finish now]"
            if left == max_calls // 2 and not any(st["endpoint"].startswith("Tavily") for st in inv.steps):
                note += ("\n[You have not checked the web yet. Do one web_search now: an advisory, a fix or the "
                         "project's documentation of this behaviour.]")
            messages.append({"role": "tool", "tool_call_id": tc.id, "content": content + note})
        emit({"stage": "cost", "usd": ledger.summary()["total_usd"], "credits": ledger.summary()["tavily_credits"]})
        if final is not None or stopped:
            break
    if final is None:
        # Out of budget: one last turn that can only report.
        messages.append({"role": "user", "content": f"Stop: {stopped or 'budget used up'}. Call finish now with "
                                                    "the findings and the evidence you have. If you were still "
                                                    "looking for something, the claim it bears on is unknown, "
                                                    "not refuted."})
        try:
            msg = chat("big", messages, ledger, "investigate", tools=FINISH_ONLY,
                       tool_choice={"type": "function", "function": {"name": "finish"}}, max_tokens=4000,
                       temperature=0.2)
            for tc in msg.tool_calls or []:
                if tc.function.name == "finish":
                    final = json.loads(tc.function.arguments or "{}")
        except Exception:  # noqa: BLE001 - no report means no findings, which never closes anything
            final = None
    final = final or {}
    findings = inv.check_findings(final.get("findings") or [])
    recommend = final.get("recommend") if final.get("recommend") in ("keep_open", "close", "confirm_needed") \
        else "keep_open"
    evs = [e for f in findings for e in f["evidence"]]
    summary = ledger.summary()
    result = {
        "findings": findings, "recommend": recommend, "confidence": final.get("confidence"),
        "summary": str(final.get("summary", ""))[:1200], "signals": signals(findings, recommend),
        "steps": inv.steps, "calls": calls, "seconds": round(time.time() - t0), "stopped": stopped,
        "evidence": {"verified": sum(e["verified"] for e in evs), "dropped": sum(not e["verified"] for e in evs)},
        "usd": round(summary["total_usd"] - usd0, 5), "credits": summary["tavily_credits"] - credits0,
        "used_urls": sorted({e["url"] for e in evs if e["verified"] and e.get("kind") == "web"}),
        "replay": bool(as_of), "budget": {"calls": max_calls, "seconds": wall},
    }
    if not final:
        result["stopped"] = stopped or "no report from the agent"
    emit({"stage": "investigate", "type": "finish", **{k: result[k] for k in (
        "findings", "recommend", "confidence", "summary", "signals", "calls", "evidence", "credits", "usd",
        "stopped", "seconds")}})
    return result
