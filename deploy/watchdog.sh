#!/usr/bin/env bash
# Keep the live demo up: every run checks the public URL and the local server. If either is down, restart the
# matching service and, when SLOPPROOF_ALERT_TO is set, send a WhatsApp alert through the local bridge.
# Installed as a systemd user timer by: deploy/watchdog.sh --install
set -u
URL="${SLOPPROOF_URL:-https://slopproof.aether-soft.tech/api/health}"
LOCAL="http://127.0.0.1:7860/api/health"
STATE="$HOME/.cache/slopproof-watchdog"
mkdir -p "$STATE"

if [ "${1:-}" = "--install" ]; then
  dir="$HOME/.config/systemd/user"
  cat > "$dir/slopproof-watchdog.service" <<EOF
[Unit]
Description=SlopProof live demo watchdog
[Service]
Type=oneshot
Environment=SLOPPROOF_ALERT_TO=${SLOPPROOF_ALERT_TO:-}
ExecStart=$(realpath "$0")
EOF
  cat > "$dir/slopproof-watchdog.timer" <<EOF
[Unit]
Description=Check the SlopProof live demo every 5 minutes
[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
[Install]
WantedBy=timers.target
EOF
  systemctl --user daemon-reload && systemctl --user enable --now slopproof-watchdog.timer
  exit
fi

ok() { curl -fsS -m 20 -o /dev/null "$1"; }
alert() {
  echo "$(date -Is) $1" >> "$STATE/log"
  [ -n "${SLOPPROOF_ALERT_TO:-}" ] && curl -fsS -m 10 -o /dev/null -X POST http://localhost:8080/api/send \
    -H 'Content-Type: application/json' \
    -d "{\"recipient\":\"$SLOPPROOF_ALERT_TO\",\"message\":\"SlopProof watchdog: $1\"}" || true
}

if ! ok "$LOCAL"; then
  systemctl --user restart slopproof-web
  alert "local server was down, restarted slopproof-web"
  exit
fi
if ! ok "$URL"; then
  # One failed check can be a blip; restart the tunnel on the second in a row.
  if [ -f "$STATE/public_down" ]; then
    systemctl --user restart slopproof-tunnel
    alert "public URL down twice in a row, restarted slopproof-tunnel"
    rm -f "$STATE/public_down"
  else
    touch "$STATE/public_down"
  fi
  exit
fi
if [ -f "$STATE/public_down" ]; then rm -f "$STATE/public_down"; fi
