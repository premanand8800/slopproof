# SlopProof

**Proof, not vibes, for vulnerability reports.**

SlopProof triages security reports sent to open source projects. It checks every claim against the project's
real source code and every reference against the live web, then an NVIDIA Nemotron agent tries to **reproduce
the bug in a locked-down sandbox**. Maintainers get a verdict backed by evidence, plus a reply they can post.

Built for the Nebius x NVIDIA Global AI Hackathon, **Coding and Agentic Engineering** track.
It runs on **NVIDIA Nemotron models served by Nebius Token Factory**, with **Tavily** for web evidence.

<!-- BENCH:START -->
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
           ──► 3. Check references ─────────── Tavily search + extract, judged by Nemotron 3 Super
                  does each CVE exist and match? do cited pages say what the report says? prior art?
           ──► 4. Static analysis ─────────── Nemotron 3 Ultra (reasoning on)
                  reads the real code, traces sizes, bounds and ownership; cites file:line
           ──► 5. Reproduce ──────────────── Nemotron 3 Ultra agent + Docker sandbox
                  builds with AddressSanitizer, writes a PoC through the real attack surface, runs it
                  (no network, capped CPU/memory/pids, all capabilities dropped)
           ──► 6. Verdict ────────────────── Nemotron 3 Ultra
                  CONFIRMED · PLAUSIBLE · NOT_REPRODUCED · FABRICATED, findings, suggested reply, cost
```

Rules the system holds itself to:

- **Writing style is never evidence.** Only verifiable facts count.
- **CONFIRMED requires a sandbox reproduction.** The code enforces this; the model cannot override it.
- **Doubt means PLAUSIBLE.** Closing a real vulnerability is far worse than spending a maintainer's minute.
- **A buggy PoC proves nothing.** Passing user input as a format string in *your own* test program is not a curl bug.

## Benchmark

We replay every public curl HackerOne report we could collect:

- **AI slop**: the reports curl's maintainer lists as AI slop.
- **Real**: disclosed HackerOne reports linked from [curl's CVE database](https://curl.se/docs/vuln.json).

Each report is judged **as of the day it was filed**: the source tree comes from that day, and Tavily searches use
`end_date` set to the filing date, with hackerone.com excluded, so later CVE write-ups cannot leak the answer.
Titles of real reports were renamed to `CVE-XXXX: ...` after disclosure; that prefix is stripped.

```bash
uv run python bench/fetch_dataset.py              # build bench/dataset.jsonl
uv run python bench/run_bench.py --mode static    # all reports, steps 1-4 and 6
uv run python bench/run_bench.py --mode sandbox --ids 2298307,4022003
uv run python bench/run_bench.py --score
```

## How we use NVIDIA Nemotron and Nebius Token Factory

Every model call goes to Token Factory's OpenAI-compatible endpoint (`https://api.tokenfactory.nebius.com/v1/`).
Each step uses the smallest model that does the job well, which keeps the static pass at about two cents per report:

| Step | Model | Why |
|---|---|---|
| Claim extraction | `nvidia/Nemotron-3_5-Lightning` | Fast, cheap structured extraction; thinking off |
| Reference and prior-art judging | `nvidia/nemotron-3-super-120b-a12b` | Reliable reading of search results; fallback extractor for long reports |
| Static analysis, reproduction agent, verdict | `nvidia/Nemotron-3-Ultra-550b-a55b` | Long-context code reasoning and multi-step tool use with thinking on |

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

## Run it

Requirements: Python 3.12+, [uv](https://docs.astral.sh/uv/), Docker, a Nebius Token Factory key and a Tavily key.

```bash
git clone <this repo> && cd slopproof
cp .env.example .env            # add NEBIUS_API_KEY and TAVILY_API_KEY
docker build -t slopproof-sandbox -f docker/Dockerfile.sandbox docker
uv sync

uv run slopproof https://hackerone.com/reports/2298307              # CLI, with sandbox
uv run slopproof https://hackerone.com/reports/2298307 --no-sandbox # static checks only
uv run slopproof-web                                                # web app on http://127.0.0.1:8000
```

The CLI also accepts GitHub issue URLs (`https://github.com/<owner>/<repo>/issues/<n>`) and `--repo` for any
GitHub project. Build recipes are tuned for curl; for other projects the agent reads the build files itself.

## Project layout

```
src/slopproof/
  llm.py        Token Factory client, model tiers, cost ledger
  extract.py    claims from free text
  codecheck.py  claims vs. the real git tree; source excerpts for the reasoning model
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

Reproduction runs untrusted, model-written code. The sandbox has no network (`--network none`), drops all Linux
capabilities, sets `no-new-privileges`, and caps memory, CPU and process count. Each run gets a fresh copy of the
source tree that is deleted afterwards. SlopProof never posts anything; it drafts a reply for a human to send.

## License

MIT, see [LICENSE](LICENSE).
