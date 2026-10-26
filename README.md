# SlopProof

**Proof, not vibes, for vulnerability reports.**

SlopProof triages security reports sent to open source projects. It checks every claim against the project's
real source code and every reference against the live web, then an NVIDIA Nemotron agent tries to **reproduce
the bug in a locked-down sandbox**. Maintainers get a verdict backed by evidence, plus a reply they can post.

Built for the Nebius x NVIDIA Global AI Hackathon, **Coding and Agentic Engineering** track.
It runs on **NVIDIA Nemotron models served by Nebius Token Factory**, with **Tavily** for web evidence.

**Live demo: https://slopproof.aether-soft.tech** (recorded runs, plus live static checks; sandbox runs need the
judges' passcode from the submission).

<!-- BENCH:START -->
**Results on 196 public curl HackerOne reports, each replayed as of the day it was filed:**

| | SlopProof (static checks) | Text-only baseline (same model) |
|---|---|---|
| Real CVE reports wrongly closed | **0 of 147** | 0 of 148 |
| AI-slop reports closed | 24 of 49 (49%) | 31 of 49 (63%) |
| Closes whose stated reason is false | 0 of 24 headlines on manual check; reasons cite `file:line` or a source. One supporting finding (#2905552) cites a wrong CVE number | **13 of 31**, verified against the git tree |
| Slop closed or sent to the bottom of the queue | 39 of 49 (80%), vs 16 of 147 real | - |
| Cost per report | $0.02, median 25 s | $0.0014 |

With the sandbox (8-report sample, about $0.44 and 4 to 8 minutes each), SlopProof **reproduced a real CVE**
(HackerOne #3735184, a `.netrc` credential leak) and closed 3 of 5 slop reports with a run that exercised the claim.
<!-- BENCH:END -->

## The problem

AI tools made it nearly free to write a convincing vulnerability report. Reviewing one still costs a maintainer hours.

- curl ended its HackerOne bug bounty in early 2026 after a flood of fabricated AI reports, and its maintainer
  [keeps a public list of them](https://gist.github.com/bagder/07f7581f6e3d78ef37dfbfc81fd1d1cd).
- Report volume roughly doubled in 2026. Django and Node.js tightened their policies; GitHub added controls to
  limit pull requests and says automated triage is still in development.
- The OpenSSF vulnerability disclosure working group notes there is no reliable technical signal for AI-generated
  reports: detection is "vibes".

Detecting AI *style* is the wrong fix. In our own dataset, **62 real curl CVEs reported in 2026 were found with AI
help**. The right question is not "was this written by AI?" but "is this true?" That question can be answered
with evidence.

## How it works

```
report URL ──► 1. Extract claims ─────────── Nemotron 3.5 Lightning
                  files, functions, line numbers, quoted code, CVEs, URLs, attack surface
           ──► 2. Check claims against code ─ git tree at the commit the reporter saw
                  do files and functions exist? is quoted code real or invented? (fuzzy match)
           ──► 2b. Find the code ──────────── tree-sitter functions + BM25 (no model)
                  ranks the project's functions against the report, even when it names none
           ──► 3. Check references ─────────── Tavily search + extract, judged by Nemotron 3 Super
                  does each CVE exist and match? do cited pages say what the report says? prior art?
           ──► 3b. Text screen ───────────── Nemotron 3 Ultra, report text only
                  a vote, never evidence: it can lower priority or second a close
           ──► 4. Static analysis ─────────── Nemotron 3 Ultra (reasoning on)
                  reads the real code, traces sizes, bounds and ownership; cites file:line
           ──► 5. Reproduce ──────────────── Nemotron 3 Ultra agent + Docker sandbox
                  builds with AddressSanitizer, writes a PoC through the real attack surface, runs it
                  (no network, capped CPU/memory/pids, all capabilities dropped)
           ──► 6. Verdict ────────────────── Nemotron 3 Ultra
                  CONFIRMED · PLAUSIBLE · NOT_REPRODUCED · FABRICATED, findings, suggested reply, cost
```

Rules the system holds itself to:

- **Wording is never evidence.** The text screen may vote; every reason SlopProof shows is a checked fact.
- **CONFIRMED requires a sandbox reproduction.** The code enforces this; the model cannot override it.
- **Doubt means PLAUSIBLE.** Closing a real vulnerability is far worse than spending a maintainer's minute.
  A close needs the verdict model plus one more signal: a sandbox run, the code ruling the claim out, or the text
  screen agreeing. When prior art shows the same area had a real bug, reading the code is not enough, since the
  report may be a bypass of that fix.
- **A buggy PoC proves nothing.** Passing user input as a format string in *your own* test program is not a curl bug.

## Benchmark

We replay every public curl HackerOne report we could collect:

- **AI slop**: the reports curl's maintainer lists as AI slop.
- **Real**: disclosed HackerOne reports linked from [curl's CVE database](https://curl.se/docs/vuln.json).

Each report is judged **as of the day it was filed**: the source tree comes from that day, and Tavily searches use
`end_date` set to the filing date, with hackerone.com excluded, so later CVE write-ups cannot leak the answer.
Titles of real reports were renamed to `CVE-XXXX: ...` after disclosure; that prefix is stripped.

### Baseline: why not just ask a model "is this slop?"

`bench/baseline.py` asks Nemotron 3 Ultra to judge each report from its text alone. It is a strong baseline: it
closes 31 of 49 slop reports and no real ones. But it is often right for the wrong reasons.
`bench/factcheck_baseline.py` checks its stated reasons against curl's git tree on the report's date and public
sources: **13 of its 31 closes give at least one false reason**. It says `lib/ws.c` does not exist, that
`curl_easy_setopt` is invented, that CVE-2023-38545 is not real, and that `ngtcp2` is a fake library.
A maintainer who posts those replies answers slop with slop, and a reporter can easily prove the reply wrong.

SlopProof uses the same call as its text screen, only as a vote, and its replies cite only checked facts.

### Code search: finding the code a report is about

Before code search, the static analysis only saw code the report named, so a report that names no file or function
got no code at all. `src/slopproof/codesearch.py` splits the project into functions with tree-sitter (cached by git
blob hash) and ranks them with BM25 over code-aware tokens: `CURLOPT_NETRC` becomes `curlopt`, `netrc`, and the
whole identifier. The top functions go to the analysis next to any cited code.

`bench/eval_search.py` measures it without any model calls. For each real curl CVE, the right answer is the set of
functions its fix commit changed; the search runs on the tree as of the report date, before the fix.

| Fixed function found in the top… | 1 | 5 | 10 |
|---|---|---|---|
| Functions the report names (before) | 45 / 139 | 70 / 139 | 74 / 139 |
| **Code search** | **61 / 139** | **104 / 139** | **113 / 139** |
| Reports that name no code: before | 0 / 16 | 0 / 16 | 0 / 16 |
| Reports that name no code: **code search** | **5 / 16** | **10 / 16** | **10 / 16** |

The fixed file is in the top 5 for 126 of 139. We also tried adding the callees of the best hits (call-graph
expansion, as in repo maps); it found the fixed function slightly less often, so it is off. Embeddings and an LLM
reranker are the next step. Semantic matching is used only to find code, never to decide whether quoted code is
real: a meaning-based match would let invented code pass as "similar".

### Checking quoted code: line by line, with history

A quote gets three checks against the tree as of the report date:

- **Closest window** (fuzzy match): verbatim, paraphrased, or not in the codebase.
- **Line by line**: how many of its significant lines exist anywhere in the tree, character for character. This
  catches quotes stitched together from several places, and the UI shows a line diff against the real code
  (`- real code`, `+ report`) so a maintainer sees exactly which lines were changed or invented.
- **History** (`git log -S`): a line that is gone now but existed before marks the quote as *older version*, not
  invented. That protects reporters on old releases and exposes recycled, already-fixed issues.

Explanations that the extractor mislabelled as code (`Curl_fopen() opens the file with...`) are no longer checked,
and escaped `\n` line breaks are restored. On the same extracted claims, quotes from real CVE reports flagged as
"not in the codebase" fell from 122 to 68; for slop, from 23 to 18. The flag still does not separate slop from
real reports on its own (about 4 in 10 quotes for both), which is why it only lowers priority and never closes.

### Honest limits

- The guard rules were chosen after error analysis on this same dataset; there is no held-out set yet.
- The sandbox numbers are a small sample (8 reports) because each run costs about $0.44.
- One report (#2604391) is missing from the static results: claim extraction returned no JSON twice. The pipeline
  now continues without structured claims in that case.
- Build recipes are tuned for curl.

### Run the benchmark

```bash
uv run python bench/fetch_dataset.py              # build bench/dataset.jsonl
uv run python bench/run_bench.py --mode static    # all reports, steps 1-4 and 6
uv run python bench/run_bench.py --mode sandbox --ids 2298307,4022003
uv run python bench/run_bench.py --score
uv run python bench/baseline.py && uv run python bench/factcheck_baseline.py
uv run python bench/rescore.py                    # re-apply the guard rules to stored runs, no model calls
uv run python bench/eval_search.py                # code search vs. the functions each CVE fix changed
```

## How we use NVIDIA Nemotron and Nebius Token Factory

Every model call goes to Token Factory's OpenAI-compatible endpoint (`https://api.tokenfactory.nebius.com/v1/`).
Each step uses the smallest model that does the job well, which keeps the static pass at about two cents per report:

| Step | Model | Why |
|---|---|---|
| Claim extraction | `nvidia/Nemotron-3_5-Lightning` | Fast, cheap structured extraction; thinking off |
| Reference and prior-art judging | `nvidia/nemotron-3-super-120b-a12b` | Reliable reading of search results; fallback extractor for long reports |
| Static analysis, reproduction agent, verdict | `nvidia/Nemotron-3-Ultra-550b-a55b` | Long-context code reasoning and multi-step tool use with thinking on |
| Text screen and baseline | `nvidia/Nemotron-3-Ultra-550b-a55b` | One short call per report, thinking off, about $0.0014 |

Token Factory made it practical to run a 550B reasoning model as a tool-calling agent for minutes at a time, and to
replay a dataset of hundreds of reports for a few dollars. Every run records a per-model token and cost ledger
(see `src/slopproof/llm.py`) that the UI shows.

## How we use Tavily

Tavily is how SlopProof checks the outside world, not decoration:

- **CVE verification**: `search` for every cited CVE; Nemotron Super decides whether it exists, affects the
  project, and is the same issue (slop often recycles old, fixed CVEs).
- **Source verification**: `extract` on every cited URL, then a check that the page supports the claim.
- **Prior art**: `search` for the same issue already reported, fixed, or documented as intended behaviour.
- **Time travel**: `end_date` lets the benchmark judge each report with only the web as it was that day.

## Prior art and how SlopProof differs

| Tool | What it does | Difference |
|---|---|---|
| [ProjectDiscovery Neo Triage](https://projectdiscovery.io/triage) | Reproduces incoming findings against a company's live web and cloud assets in a sandbox | Closed, enterprise, web targets. SlopProof builds the project's source as of the report date and tests memory-safety and logic claims in C code |
| [HackerOne Hai Triage](https://www.hackerone.com/platform/triage) | AI-assisted triage for programs on HackerOne | Platform-bound and paid. curl left HackerOne in 2026; SlopProof runs anywhere, including as a GitHub Action |
| [Elastic's triage pipeline](https://www.elastic.co/security-labs/blog/ai-vulnerability-triage-bug-bounty-hackerone) | Internal agent for Elastic's bug bounty: 85% agreement with humans, about $2 per report | Internal, not released. SlopProof is open, about $0.02 per report statically, and publishes a replayable benchmark |
| [Anthropic OSS Scanner](https://red.anthropic.com/oss-scanner/), [ossscanner.org](https://ossscanner.org/), [Argo](https://github.com/gigioneggiando/argo) | AI agents that scan repositories to find new bugs | They find bugs; SlopProof checks reports other people send. More AI bug finding means more reports to check |
| [Pydantic AI sandboxes](https://pydantic.dev/docs/ai/harness/index.md) (Docker, E2B, Modal, BoxLite and others) | Execution environments for agents | Infrastructure, not triage. SlopProof's own sandbox is a small hardened Docker runner with optional gVisor |

## Run it

Requirements: Python 3.12+, [uv](https://docs.astral.sh/uv/), Docker, a Nebius Token Factory key and a Tavily key.

```bash
git clone https://github.com/premanand8800/slopproof && cd slopproof
cp .env.example .env            # add NEBIUS_API_KEY and TAVILY_API_KEY
docker build -t slopproof-sandbox -f docker/Dockerfile.sandbox docker
uv sync

uv run slopproof https://hackerone.com/reports/2298307              # CLI, with sandbox
uv run slopproof https://hackerone.com/reports/2298307 --no-sandbox # static checks only
uv run slopproof-web                                                # web app on http://127.0.0.1:8000
```

The CLI also accepts GitHub issue URLs (`https://github.com/<owner>/<repo>/issues/<n>`) and `--repo` for any
GitHub project. Build recipes are tuned for curl; for other projects the agent reads the build files itself.

### Hosted demo

The live demo runs the full app on a home server behind a Cloudflare tunnel (`deploy/update_live.sh`): static checks
for anyone (40 a day), sandbox runs behind a passcode, since they execute model-written code on the host.
A backup is a static Hugging Face Space (`deploy/hf_space.sh`, built by `deploy/build_static.py`): the same
UI replaying every recorded benchmark run, with no keys and no running cost, so it stays up through judging.
Triaging a new report needs your own Token Factory and Tavily keys: run it locally as above, or deploy the full app
anywhere that runs a container (`docker build .`, port 7860).

## Project layout

```
src/slopproof/
  llm.py        Token Factory client, model tiers, cost ledger
  extract.py    claims from free text
  codecheck.py  claims vs. the real git tree; source excerpts for the reasoning model
  codesearch.py find the functions a report is about (tree-sitter + BM25)
  screen.py     text-only vote
  webcheck.py   Tavily CVE, URL and prior-art checks
  analyze.py    static analysis on real code
  sandbox.py    Docker sandbox (no network, caps dropped, resource limits)
  reproduce.py  Nemotron Ultra reproduction agent
  verdict.py    final decision and maintainer reply
  pipeline.py   orchestration and progress events
  server.py     FastAPI + server-sent events
web/            single-page UI
bench/          dataset builder, replay runner, results
```

## Safety

Reproduction runs untrusted, model-written code. The sandbox has no network (`--network none`), runs as an
unprivileged user, drops all Linux capabilities, sets `no-new-privileges`, mounts the root filesystem read-only
(with a small `/tmp` tmpfs), and caps memory, CPU and process count. Each run gets a fresh copy of the source tree
that is deleted afterwards. A container shares the host kernel, so for anything beyond a demo set
`SLOPPROOF_RUNTIME=runsc` to run it under [gVisor](https://gvisor.dev), or use a microVM. SlopProof never posts anything; it drafts a reply for a human to send.

## License

MIT, see [LICENSE](LICENSE).
