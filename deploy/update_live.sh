#!/usr/bin/env bash
# Update the self-hosted demo (slopproof.aether-soft.tech) to the latest local commit and restart it.
# The demo runs from a separate worktree, so benchmark runs in progress here never show up live.
set -euo pipefail
cd "$(dirname "$0")/.."
git -C ../slopproof-live checkout -q --detach "$(git rev-parse HEAD)"
(cd ../slopproof-live && uv sync -q --no-dev)
# Do not cut off someone's run: wait (up to 30 minutes) until no triage is in progress.
for _ in $(seq 1 180); do
  n=$(curl -sf http://127.0.0.1:7860/api/health | python3 -c "import json,sys; print(json.load(sys.stdin).get('active_jobs', 0))" 2>/dev/null || echo 0)
  [ "$n" = "0" ] && break
  echo "waiting for $n running job(s) to finish..."; sleep 10
done
systemctl --user restart slopproof-web.service
sleep 3
curl -sf http://127.0.0.1:7860/api/health && echo && echo "live at $(git rev-parse --short HEAD)"
