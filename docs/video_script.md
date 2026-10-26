# Demo video script (target 2:45, hard limit 3:00)

Screen recording of the web app, voice or captions. Numbers are from the current benchmark; update after the
final runs.

## 0:00–0:20 Problem
Screen: curl's public list of AI-slop reports, then a news line about curl ending its bug bounty.
> In 2026 curl shut down its bug bounty. AI made fake vulnerability reports almost free to write, and each one
> still costs a maintainer hours to disprove. Guessing from the wording is not enough: many real CVEs this year
> were found with AI too.

## 0:20–0:35 What SlopProof does
Screen: How it works tab (pipeline).
> SlopProof checks a report instead of judging its style. It checks every claim against the project's real code on
> the day of the report, checks every reference on the live web, and then lets an NVIDIA Nemotron agent try to
> reproduce the bug in a locked-down sandbox.

## 0:35–1:20 Live: a slop report
Screen: paste a slop report URL, stages fill in live.
> This report claims a buffer overflow in curl's WebSocket code. Nemotron Lightning pulls out the claims.
> The quoted code is checked line by line against the real file: here is the diff. Tavily checks the cited sources.
> Nemotron Ultra reads the real code: the bounds check two lines earlier makes this impossible.
> Verdict: not reproduced, with file and line, and a polite reply the maintainer can paste. About two cents.

## 1:20–1:55 Sandbox: a real CVE
Screen: replay of report #3735184, terminal stage.
> Now a real report: curl sends a .netrc password for the wrong user. The report names no code, so code search
> finds it: override_login in lib/url.c. The agent builds curl with AddressSanitizer, writes a test through the
> real command line, and reproduces the leak in 161 seconds, for 31 cents. Confirmed.

## 1:55–2:30 Benchmark and baseline
Screen: Benchmark tab, comparison table, the false-statements list.
> We replayed 196 public curl reports, each as of the day it was filed. Zero of 147 real CVE reports were
> wrongly closed. Half of the slop is closed with evidence, and 80 percent is closed or moved to the bottom.
> Why not just ask a model "is this slop?" We tried. It closes more, but 13 of its 31 reasons are false:
> it says lib/ws.c does not exist. That is answering slop with slop.

## 2:30–2:45 Close
Screen: GitHub Action comment on an issue, then the repo.
> Every model call runs on NVIDIA Nemotron through Nebius Token Factory, with Tavily for the web. It runs as a web
> app, a CLI or a GitHub Action, and it is open source. Proof, not vibes.
