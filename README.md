# SlopProof

**Proof before priority, for every vulnerability report.**

SlopProof triages security reports sent to open source projects. It checks every claim against the project's
real source code as of the day the report was filed, checks every reference on the web, follows the code to the
callers real input comes through, and lets an NVIDIA Nemotron agent try to **reproduce the bug in a locked-down
sandbox**. A reproduced bug becomes a **proof bundle anyone can re-run with no AI involved**. Maintainers get a
verdict backed by evidence, plus a reply they can post.

Built for the Nebius x NVIDIA Global AI Hackathon, **Coding and Agentic Engineering** track.
It runs on **NVIDIA Nemotron models served by Nebius Token Factory**, with **Tavily** for web evidence.

**Live demo: https://slopproof.aether-soft.tech** (recorded runs, plus live static checks; sandbox runs need the
judges' passcode from the submission).

<!-- BENCH:START -->
**Results on 197 public curl HackerOne reports, each replayed as of the day it was filed** (final run: NVIDIA
Nemotron on Nebius Token Factory, web search working; see [Benchmark notes](#benchmark-notes)):

| | SlopProof (static checks) | Text-only baseline (same model) |
|---|---|---|
| Real CVE reports wrongly closed | **0 of 148** | 0 of 148 |
| AI-slop reports closed | 21 of 49 (43%) | 31 of 49 (63%) |
| Closes whose stated reason is false | Reasons cite `file:line` or a source (the manual check of 24 headlines was on the v1 run) | **13 of 31**, verified against the git tree |
| Slop closed or sent to the bottom of the queue | 38 of 49 (78%), vs 6 of 148 real | - |
| Cost per report | $0.065 on average, median 44 s | $0.0014 |

With the sandbox (27-report sample: 19 slop, 8 real; $0.12 to $1.13 and 3 to 35 minutes each): **9 of 19 slop
reports closed with a run that exercised the claim, 0 of 8 real ones closed**, and two real CVEs reproduced and
turned into proof bundles that re-run as **VERIFIED_AND_FIXED** (bug present at the reported commit, gone at
curl's fix): HackerOne #3735184, the `.netrc` credential leak (CVE-2026-8926), and #4041053, a `.netrc` password
leaking into `CURLINFO_EFFECTIVE_URL` after a redirect.
<!-- BENCH:END -->

## The problem

AI tools made it nearly free to write a convincing vulnerability report. Reviewing one still costs a maintainer hours.
The problem has two halves, and the second is now the larger one:

1. **Fabricated reports** ("slop"): invented code, impossible bugs. curl ended its bug bounty over them.
2. **Accurate reports whose impact is unclear.** By spring 2026 the obvious hallucinations had largely given way to
   a high volume of plausible, well-written reports where the hard part is deciding whether the bug is real,
   reachable and serious ([The Register, April 2026](https://www.theregister.com/2026/04/06/ai_coding_tools_more_work/)).
   Three in four maintainers already use AI to vet what comes in
   ([Linux Foundation survey via Help Net Security, October 2026](https://www.helpnetsecurity.com/2026/10/26/linux-foundation-open-source-ai-slop/)),
   which makes it matter that the vetting rests on evidence rather than on a model's word.

Both halves need the same answer: proof before priority. Some background on the first:

- curl ended its HackerOne bug bounty in early 2026 after a flood of fabricated AI reports, and its maintainer
  [keeps a public list of them](https://gist.github.com/bagder/07f7581f6e3d78ef37dfbfc81fd1d1cd).
- Report volume roughly doubled in 2026. Django and Node.js tightened their policies; GitHub added controls to
  limit pull requests and says automated triage is still in development.
- The OpenSSF vulnerability disclosure working group notes there is no reliable technical signal for AI-generated
  reports: detection is "vibes".

Detecting AI *style* is the wrong fix. In our own dataset, **62 real curl CVEs reported in 2026 were found with AI
help**. The right question is not "was this written by AI?" but "is this true?" That question can be answered
with evidence.

## Example: an accurate report, where the question is reachability

A fluent-bit report, "heap out-of-bounds read in chunked parser on a
split read" is well written and its code citations are exact. SlopProof confirms the quoted code verbatim, fetches
`mk_string_search_n` and the function it wraps when the analysis asks for them, and walks the callers up to where
network input enters. It finds that the search can read one byte past `len`, that `plugins/in_http/http_conn.c`
NUL-terminates that byte (so it cannot be the `\n` the bug needs on that path), and names the monkey-server and
HTTP/1 paths that need checking. Verdict: PLAUSIBLE, with the open question stated, at about $0.15 for the static
path. A text-only screen voted to keep it too; deciding it takes evidence, not wording.

## Proof bundles: reports that carry their own proof

Slop is cheap to write and expensive to disprove. SlopProof turns every bug it reproduces into a **proof bundle**:
the project commit, the sandbox image, the build command, the PoC files and one check command that exits 0 only
while the bug is present. Anyone can re-run it, and **no model is involved in verifying**:

```bash
uv run slopproof verify examples/bundles/curl-3735184-netrc.json --against 4ae1d7cc2643e4773a136395f12bc02fc6867854
# bundle commit e9b9bbac22c2: bug present (116s)
# 4ae1d7cc2643 (curl's fix for CVE-2026-8926): bug absent (116s)
# VERIFIED_AND_FIXED
```

A reproduction only counts as CONFIRMED if its bundle passes again from scratch in a fresh sandbox. A real
reporter can ship a bundle with the report; a slop reporter cannot, because there is no bug for the check to find.
That moves the cost of proof to whoever makes the claim. The live demo re-runs the example bundle on demand
(*Verify a proof* tab); arbitrary bundles are verified locally, since a bundle is code.

### From proof to fix: and why the agent's patch is never trusted on its word

For a verified bundle, a Nemotron Ultra agent writes a patch with exact edits in the sandbox. SlopProof then
applies it in a fresh sandbox (the bundle's check must stop passing) and runs the project's own tests for the area
it touched, before and after. On the `.netrc` CVE the agent's three-line patch stops the leak, but SlopProof's test
step found it breaks two of curl's 22 netrc tests (680, 1304), so it is reported as `FIX_BREAKS_TESTS`, not as a
fix. A repair round that feeds the failing tests back to the agent is in progress. curl's own fix was a parser
rewrite (`4ae1d7cc2643`, 581 lines).

## Memory: learning across runs, without being taught by attackers

SlopProof remembers across runs the way people do, with the safeguards a tool reading strangers' reports needs
(`src/slopproof/memory.py`, one SQLite file):

- **Episodes**: what happened in each run: outcome, commands, cost, builds that failed.
- **Facts**, pinned to the exact file version (git blob) they were seen in. When the file changes, the fact is
  shown as **stale** and re-checked, never trusted.
- **Skills**: procedures that worked: a build that finished in the sandbox, a proof check that re-ran. A project
  without a build recipe starts from the build that worked last time.
- **Lessons**: corrections from reviews and maintainers, recalled when their trigger words match a report.

Every item records its source. **Nothing a reporter wrote is stored**; items are kept only after a hard check (a
build that worked, a cited line that exists, a proof that re-ran). Memory steers where to look and how to build;
it **never decides a verdict**. Benchmark runs switch it off, so no number is learned from the test set.
Maintainers inspect it on the Memory page and edit it with `slopproof memory list | lesson | forget`.

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
| **Code search** | **69 / 139** | **103 / 139** | **114 / 139** |
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

- The guard rules were chosen after error analysis on this same dataset. The held-out set below is the only
  check on reports never seen during development.
- Two slop reports were first CONFIRMED by the sandbox: one PoC re-implemented curl's logic in its own program, and
  one read `/etc/passwd` through an encoded `file://` path, which a plain `file:///etc/passwd` also does. The checks
  that now catch both (the PoC must run curl's own CLI or library; without a sanitizer report in curl's code, an
  independent model must see a gain over intended use) were written after seeing these two cases.
- The sandbox numbers are a small sample (27 reports) because each run costs about $0.59 (median).
- Held-out check: 60 reports curl closed as *not applicable* between May and October 2026, never seen during
  development. SlopProof closed 2 and sent 3 more to the bottom of the queue. For 51 of the 60, the code does
  behave as the report says: these are accurate reports that curl judged out of scope, not invented ones.
  SlopProof checks truth; deciding scope stays with the maintainer, helped by a quote from the project's own
  policy. (The text-only screen kept 55 of the 60 too.)
- Build recipes are tuned for curl. For other projects the sandbox agent reads the build files itself; outside
  curl and fluent-bit this is untested.

### Beyond curl

The benchmark is curl (C). Code search and the code checks also parse Python, Go, JavaScript and Rust
(tree-sitter), and a pasted report that names a release is checked at that release. A handful of live static runs
on the demo server, with report texts we wrote (one from a public advisory, two invented the way AI slop is):

| Project | Report | Verdict |
|---|---|---|
| psf/requests (Python) | real CVE-2024-35195 (`verify=False` sticks to the connection pool), from the advisory | PLAUSIBLE: the code at v2.31.0 shows the pool reuse |
| gin-gonic/gin (Go) | invented heap overflow via `memcpy` in `Context.Query()` | FABRICATED: the function and the code do not exist |
| expressjs/express (JavaScript) | invented prototype pollution in `res.json()` | PLAUSIBLE, low priority: `deepMergeJson()` does not exist, but a related fix keeps a code-only close off |
| fluent/fluent-bit (C, sandbox) | read past the end in the chunked parser | PLAUSIBLE: two callers lack the NUL terminator; not reproduced |

These runs found and fixed three gaps that a curl-only benchmark could not: a release named without a date was
checked at HEAD, `res.json` was looked up as `resjson`, and JavaScript functions assigned as
`res.json = function () {}` were not indexed. Three runs are an example, not a measurement.

### Benchmark notes

- **Headline run.** The numbers above are the final run (`bench/results_static_final.jsonl`): current code,
  NVIDIA Nemotron on Nebius Token Factory, Tavily web search working. 197 reports: 0 of 148 real CVE reports
  wrongly closed, 21 of 49 AI slop closed, $0.065 per report on average.
- **Earlier runs, kept for transparency.** `results_static.jsonl` (v1, an older pipeline, 196 reports) rescored
  with the current guards: 0 of 147 real closed, 22 of 49 slop closed. `results_static_v2.jsonl` is a partial
  cross-check through OpenRouter (100 reports). `results_static_v3.jsonl` ran while the Tavily quota was exhausted,
  so every web check failed; it is why a failed prior-art search now blocks a code-only close.
- **A threshold chosen on the benchmark.** In the final run the code check alone closed 4 real CVEs while the
  text screen voted to keep each open with confidence 0.85 to 0.95. A code-only close is now blocked when the text
  screen disagrees with confidence 0.8 or more. That threshold was picked on this benchmark, so the 0 of 148 is
  not an unbiased estimate. The held-out result (2 of 60 closed) did not change.
- **Proof needs a negative control.** A proof bundle's check must pass when the bug is present and its control
  check must fail on the safe case. #3583983 (bearer token leak with a redirect and `.netrc`) reproduced in the
  sandbox, but its check grepped `curl -v` output that also matched the header sent to the first host and had no
  control, so it stays PLAUSIBLE rather than CONFIRMED.
- **Sandbox subset.** The sandbox numbers come from 27 of the 197 reports (19 slop, 8 real), not the full set.

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

## Related work and how SlopProof differs

The core loop (an AI that reads a report and tries to reproduce it) is not new, and the closest systems show it is
worth doing. What SlopProof adds is the combination in the open, for any project: claim checks, web checks, caller
analysis and sandbox reproduction in one pipeline; proof bundles that verify without a model; and a benchmark that
replays each report as of its filing date and checks whether a baseline's stated reasons are true.

| Tool | What it does | Difference |
|---|---|---|
| [HackerOne Hai Triage / Agentic Validation](https://www.hackerone.com/press-release/hackerone-unveils-hai-triage-upgraded-ai-powered-vulnerability-response) (2025) | AI agents assess incoming reports in minutes as likely valid, invalid or needing review; [human analysts confirm outcomes and reproduce findings](https://docs.hackerone.com/en/articles/8837878-how-hai-triage-works) | Commercial and tied to the HackerOne platform; reproduction is done by people. SlopProof is open, runs anywhere, and reproduces in a sandbox |
| [Elastic's AI triage pipeline](https://www.elastic.co/security-labs/blog/ai-vulnerability-triage-bug-bounty-hackerone) | Analyses HackerOne reports and reproduces them in sandboxed VMs; 85% agreement with engineers on 764 reports, about $2 per report | The closest match. Internal to Elastic and its products, not released. SlopProof is open source, about $0.07 per report for the static path, and publishes a replayable benchmark |
| [Nikasha](https://pypi.org/project/nikasha/) | Deterministic check of a report's factual claims against the source at the named version, with commit/path/line evidence | Roughly SlopProof's claim-checking step, without web checks, analysis or reproduction |
| [ProjectDiscovery Neo Triage](https://projectdiscovery.io/triage) | Reproduces incoming findings against a company's live web and cloud assets in a sandbox | Closed, enterprise, web targets. SlopProof builds the project's source as of the report date and tests memory-safety and logic claims in C code |
| [HackerOne Hai Triage](https://www.hackerone.com/platform/triage) | AI-assisted triage for programs on HackerOne | Platform-bound and paid. curl left HackerOne in 2026; SlopProof runs anywhere, including as a GitHub Action |
| [Elastic's triage pipeline](https://www.elastic.co/security-labs/blog/ai-vulnerability-triage-bug-bounty-hackerone) | Internal agent for Elastic's bug bounty: 85% agreement with humans, about $2 per report | Internal, not released. SlopProof is open, about $0.07 per report statically, and publishes a replayable benchmark |
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
uv run pytest -q                                                    # the rules, tested without any model call
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
