# Demo video script (final cut 2:53, hard limit 3:00)

Lead with proof, not "AI triages bug reports". Real screen footage of https://slopproof.aether-soft.tech, voice
narration with burned-in captions, no music (a quiet self-synthesised tone bed only). No new paid runs: the gin
report is the recorded run of the home page's "run one live" sample, replayed at the pace it was recorded.

## 0:00–0:08 Hook
Screen: the CONFIRMED stamp of #3735184 (proof sha chip), then the VERIFIED_AND_FIXED seal on the Proofs page.
> Most AI triage asks you to trust the AI. SlopProof gives you proof you can re-run, without AI.

## 0:08–0:29 Problem and what it does
Screen: home page (hero, headline numbers), pan down to "What happens to a report".
> AI made fake vulnerability reports almost free to write, and each one still costs a maintainer hours to
> disprove. In 2026, curl shut down its bug bounty.
> SlopProof checks the report, not its style: the claims against the real code, the references on the web, and
> real-looking bugs in a sandbox.

## 0:29–1:24 One report, paste to verdict, nothing cut
Screen: paste the invented gin report (repo, title, body) into the form; then its recorded run, replayed at real
speed (32 s): stages light up, the claim check expands, the FABRICATED stamp lands with the 95% ring and the
`context.go:412` chip, then the evidence list and the suggested reply. On-screen badge: "Recorded run of this
report · replayed at real speed".
> Here is a report written like AI slop: a heap overflow in gin's Context.Query(). This is SlopProof's recorded run
> of it, replayed at real speed.
> Nemotron 3.5 Lightning extracts the claims, and each is checked against gin's real source. parseQueryBuffer()
> does not exist, and the quoted code is nowhere in the codebase.
> Tavily checks the web, Nemotron 3 Super reads it, and Nemotron 3 Ultra reads the real code.
> Verdict: FABRICATED, 95% confidence. Line 412 of context.go is just a closing brace.
> Every reason cites a checked fact, with a reply ready to paste. 32 seconds, 2 cents.

## 1:24–1:54 Proof bundle
Screen: replay of #3735184 (CONFIRMED stamp lands), then Proofs page: commit + check command, the
VERIFIED_AND_FIXED seal, reported commit "bug present" vs fix commit "bug gone".
> Real bugs get more than a verdict. For curl's .netrc password leak, a Nemotron agent built curl with
> AddressSanitizer, in a sandbox with no network, and reproduced it.
> That run becomes a proof bundle: a pinned commit, a test, and one check command. Re-run from scratch: bug present
> at the reported commit, gone at curl's fix. No AI in the loop.
> The fix commit is the negative control: a check that never fails proves nothing.

## 1:54–2:10 Plain-model baseline
Screen: Benchmark scoreboard, then the baseline's false statements (#2298307 "lib/ws.c does not exist").
> Why not just ask a model "is this slop?" Same Nemotron, text only: 13 of its 31 closing reasons are false. It
> says lib/ws.c does not exist. That is answering slop with slop.

## 2:10–2:28 Numbers
Screen: Benchmark stat tiles and scoreboard.
> We replayed 197 curl reports, as of their filing dates. 0 of 148 real CVEs wrongly closed. 21 of 49 slop reports
> closed, with checked evidence. 2 real CVEs proved. About $0.065 a report.

## 2:28–2:38 Beyond curl
Screen: Benchmark "Beyond curl" (requests, gin, express, fluent-bit).
> Beyond curl, it ran live on requests, gin, express and fluent-bit, and the code checks parse C, Python, Go,
> JavaScript and Rust.

## 2:38–2:53 Close
Screen: end card: NVIDIA Nemotron 3.5 Lightning · 3 Super · 3 Ultra via Nebius Token Factory · Tavily,
https://slopproof.aether-soft.tech, github.com/premanand8800/slopproof.
> Every model call runs on NVIDIA Nemotron (3.5 Lightning, 3 Super, 3 Ultra) through Nebius Token Factory, with
> Tavily for the web. SlopProof is open source. Proof, not vibes.
