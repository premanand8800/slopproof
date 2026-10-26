#!/usr/bin/env bash
# Update the self-hosted demo (slopproof.aether-soft.tech) to the latest local commit and restart it.
# The demo runs from a separate worktree, so benchmark runs in progress here never show up live.
set -euo pipefail
cd "$(dirname "$0")/.."
git -C ../slopproof-live checkout -q --detach "$(git rev-parse HEAD)"
(cd ../slopproof-live && uv sync -q --no-dev)
systemctl --user restart slopproof-web.service
sleep 3
curl -sf http://127.0.0.1:7860/api/health && echo && echo "live at $(git rev-parse --short HEAD)"
