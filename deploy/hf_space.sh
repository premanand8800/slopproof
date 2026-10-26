#!/usr/bin/env bash
# Publish the demo as a static Hugging Face Space: the UI with the benchmark and every recorded run.
# Static Spaces are free and need no keys. Docker Spaces need a PRO plan; the full app runs anywhere with
# `docker build .` instead.
#   HF_TOKEN must be set (or present in .env). Usage: deploy/hf_space.sh [owner/space]
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] && { set -a; . ./.env; set +a; }
: "${HF_TOKEN:?set HF_TOKEN}"
SPACE="${1:-premmm/slopproof}"

# Create the Space if it does not exist yet (409 means it already does).
code=$(curl -s -o /tmp/hf_create.$$ -w '%{http_code}' -X POST https://huggingface.co/api/repos/create \
  -H "Authorization: Bearer $HF_TOKEN" -H "Content-Type: application/json" \
  -d "{\"type\":\"space\",\"name\":\"${SPACE#*/}\",\"sdk\":\"static\",\"private\":false}")
case "$code" in 200|201|409) ;; *) echo "creating the Space failed (HTTP $code): $(cat /tmp/hf_create.$$)" >&2; exit 1 ;; esac
rm -f /tmp/hf_create.$$

out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
git clone -q "https://user:${HF_TOKEN}@huggingface.co/spaces/${SPACE}" "$out/space"


# Built from the last commit, so a benchmark that is still running is never published half-done.
uv run python deploy/build_static.py --out "$out/space" --from-head
cat > "$out/space/README.md" <<'MD'
---
title: SlopProof
emoji: 🔎
colorFrom: blue
colorTo: green
sdk: static
app_file: index.html
license: mit
short_description: Proof, not vibes, for vulnerability reports
---

SlopProof checks vulnerability reports against the real code, the web and a sandbox reproduction, using NVIDIA
Nemotron on Nebius Token Factory and Tavily. This Space replays the recorded benchmark runs.
Code: https://github.com/premanand8800/slopproof
MD

rev=$(git rev-parse --short HEAD)
cd "$out/space"
git add -A
git -c user.name=premanand8800 -c user.email=talkprem384@gmail.com commit -q -m "Deploy SlopProof $rev" || true
git push -q origin HEAD:main
echo "Deployed: https://huggingface.co/spaces/${SPACE}"
