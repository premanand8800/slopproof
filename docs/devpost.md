# Devpost submission draft

## Name
SlopProof

## Tagline
Proof, not vibes: checks every vulnerability report against the real code, the live web and a sandbox run.

## Inspiration
In 2026 curl shut down its bug bounty. AI made convincing vulnerability reports nearly free to write, and each one
still costs a maintainer hours to disprove. The usual answer is to guess from the wording whether a report is
AI slop. But many real curl CVEs this year were found with AI tools, and we found that a model judging the
wording is often right for the wrong reasons: it told us `lib/ws.c` does not exist and that `curl_easy_setopt`
is invented. A maintainer cannot post that. We wanted every verdict to come with proof.

## What it does
Paste a HackerOne report or GitHub issue. SlopProof:
1. extracts every checkable claim (files, functions, lines, quoted code, CVEs, URLs, attack surface);
2. checks them against the project's git tree as of the report date: do the files and functions exist, is the
   quoted code real or invented;
3. finds the code the report is about, even when it names none (tree-sitter, BM25 and the call graph);
4. checks cited CVEs, pages and prior art with Tavily;
5. reads the real code with Nemotron 3 Ultra to decide whether the claimed condition can happen;
6. lets a Nemotron 3 Ultra agent build the project with AddressSanitizer in a locked-down sandbox and try to
   trigger the bug through the real attack surface;
7. returns CONFIRMED, PLAUSIBLE, NOT_REPRODUCED or FABRICATED, the evidence, and a reply ready to post.

Hard rules in code: CONFIRMED needs a sandbox reproduction; closing needs a second independent signal; doubt
never closes a report.

## How we built it
Python, FastAPI with server-sent events, a single-page UI, Docker. Every model call goes through Nebius Token
Factory: Nemotron 3.5 Lightning for extraction, Nemotron 3 Super for judging web evidence, Nemotron 3 Ultra for
analysis, the reproduction agent and the verdict. Tavily search and extract, with `end_date` for time-travel replay.

## Benchmark
196 public curl HackerOne reports (49 AI slop, 147 real CVEs), each replayed as of its filing date.
- 0 of 147 real CVE reports wrongly closed.
- 24 of 49 slop reports closed, each with checked evidence; 39 of 49 closed or moved to the bottom of the queue.
- Text-only baseline (same model): closes 31 of 49, but 13 of its 31 closing reasons are false.
- Sandbox: reproduced a real CVE (#3735184, .netrc credential leak) in 161 s for $0.31.
- About $0.02 per report for the static checks.
- Code search finds a function the CVE fix changed in its top 5 for 104 of 139 real reports (75%), against 70 when
  reading only the code a report names; for reports that name no code, 10 of 16 against 0.

## Challenges
- Benchmark leakage: titles of real reports name the CVE and the web has later write-ups. We strip the prefix,
  pin the source tree to the report date, and cut web search off at the filing date.
- The model's own verdict wrongly closed 14 of 130 real reports at first. Hard guards in code fixed that.
- AddressSanitizer in a container, and an agent that wasted steps; solved with a background build, code
  context and step budgets.

## What we learned
Judging wording gets the right answer often and the right reason rarely. Evidence is cheaper than we thought.

## What's next
More languages and build recipes, embeddings and an LLM reranker for code search, a hosted GitHub App.

## Built with
nvidia-nemotron, nebius-token-factory, tavily, python, fastapi, docker, addresssanitizer, tree-sitter
