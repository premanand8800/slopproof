#!/usr/bin/env bash
# Publish the web demo as a Hugging Face Docker Space.
#   HF_TOKEN must be set (or present in .env). Usage: deploy/hf_space.sh [owner/space]
# After the first deploy, add NEBIUS_API_KEY and TAVILY_API_KEY under Space settings -> Secrets.
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] && { set -a; . ./.env; set +a; }
: "${HF_TOKEN:?set HF_TOKEN}"
SPACE="${1:-premmm/slopproof}"

# Create the Space if it does not exist yet (409 means it already does).
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST https://huggingface.co/api/repos/create \
  -H "Authorization: Bearer $HF_TOKEN" -H "Content-Type: application/json" \
  -d "{\"type\":\"space\",\"name\":\"${SPACE#*/}\",\"organization\":null,\"sdk\":\"docker\",\"private\":false}")
case "$code" in 200|201|409) ;; *) echo "creating the Space failed (HTTP $code)" >&2; exit 1 ;; esac

out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
git clone -q "https://user:${HF_TOKEN}@huggingface.co/spaces/${SPACE}" "$out/space"
cd "$out/space"
find . -mindepth 1 -maxdepth 1 ! -name .git -exec rm -rf {} +
cd - >/dev/null

# Only what the image needs. Screenshots stay on GitHub: the Hub rejects binaries outside LFS.
cp -r Dockerfile pyproject.toml uv.lock LICENSE src web bench "$out/space/"
{
  cat <<'EOF'
---
title: SlopProof
emoji: 🔎
colorFrom: blue
colorTo: green
sdk: docker
app_port: 7860
license: mit
short_description: Proof, not vibes, for vulnerability reports
---

EOF
  cat README.md
} > "$out/space/README.md"

cd "$out/space"
git add -A
git -c user.name=premanand8800 -c user.email=talkprem384@gmail.com commit -q -m "Deploy SlopProof $(git -C "$OLDPWD" rev-parse --short HEAD)" || true
git push -q origin HEAD:main
echo "Deployed: https://huggingface.co/spaces/${SPACE}"
