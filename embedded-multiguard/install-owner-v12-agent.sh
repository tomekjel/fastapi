#!/usr/bin/env bash
# One-time root install inside FastAPI LXC. The agent makes only OUTBOUND HTTPS
# requests; NEVER asks for server SSH credentials or exposes another port.
set -Eeuo pipefail

if [ "${EUID}" -ne 0 ]; then
  echo "BLOCKED: open FastAPI container console as root." >&2
  exit 1
fi
SOURCE_REF="${1:-}"
if [[ ! "$SOURCE_REF" =~ ^[a-f0-9]{40}$ ]]; then
  echo "BLOCKED: expected pinned 40-char GitHub source revision." >&2
  exit 1
fi
test -f /opt/multiservis/app/main.py ||
  { echo "BLOCKED: not the Multi-Servis FastAPI container" >&2; exit 1; }
test -x /opt/multiservis/.venv/bin/python ||
  { echo "BLOCKED: missing Multi-Servis Python environment" >&2; exit 1; }
test "$(systemctl is-active multiservis-api.service)" = "active" ||
  { echo "BLOCKED: API is not healthy" >&2; exit 1; }
command -v curl >/dev/null || exit 1

# This is the live version confirmed by OWNER after the second V12 rollout.
# Bootstrap only establishes an inert baseline. It will NEVER deploy the
# later, still unapproved changes automatically.
BASELINE="892a8c66e1e3cae662136ddf1360bf880b785ba8"
STATE_DIR="/var/lib/multiservis-owner-v12"
EXEC_DIR="/usr/local/libexec"
AGENT="$EXEC_DIR/multiservis-owner-v12-agent.py"
DEPLOY="$EXEC_DIR/multiservis-owner-v12-deploy.sh"
RAW="https://raw.githubusercontent.com/tomekjel/fastapi/$SOURCE_REF/embedded-multiguard"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

curl --fail --silent --show-error --location --retry 3 --max-time 30 \
  "$RAW/scripts/owner_v12_pull_agent.py" -o "$TMP/agent.py"
curl --fail --silent --show-error --location --retry 3 --max-time 30 \
  "$RAW/deploy-owner-web-v12.sh" -o "$TMP/deploy.sh"
python3 -m py_compile "$TMP/agent.py"
bash -n "$TMP/deploy.sh"

# Never discard a previous deployment state on reinstall.
install -d -m 0700 "$STATE_DIR"
install -d -m 0755 "$EXEC_DIR"
if [ ! -f "$STATE_DIR/state.json" ]; then
  printf '{"applied_sha":"%s","sequence":0,"failed_sequence":null,"last_failed_sha":null}\n' "$BASELINE" \
    > "$STATE_DIR/state.json"
  chmod 0600 "$STATE_DIR/state.json"
fi
install -m 0700 "$TMP/agent.py" "$AGENT"
install -m 0700 "$TMP/deploy.sh" "$DEPLOY"

cat > /etc/systemd/system/multiservis-owner-v12-pull.service <<'EOF'
[Unit]
Description=Multi-Servis OWNER V12 outbound-only approved GitHub deployment poller
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
Group=root
ExecStart=/usr/bin/python3 /usr/local/libexec/multiservis-owner-v12-agent.py
WorkingDirectory=/opt/multiservis
NoNewPrivileges=yes
UMask=0077
# LXC-safe: avoid mount-namespace sandbox flags, which fail in unprivileged Proxmox CT.
TimeoutStartSec=300
EOF

cat > /etc/systemd/system/multiservis-owner-v12-pull.timer <<'EOF'
[Unit]
Description=Check approved OWNER web releases without SSH or inbound ports

[Timer]
OnBootSec=3min
OnUnitActiveSec=5min
RandomizedDelaySec=30s
Persistent=true
Unit=multiservis-owner-v12-pull.service

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
# First run now, before activating the timer. The manifest initially points
# at the INSTALLED revision, so this action must never redeploy anything.
systemctl start multiservis-owner-v12-pull.service
systemctl enable --now multiservis-owner-v12-pull.timer
systemctl is-active --quiet multiservis-owner-v12-pull.timer
echo "SUCCESS: GitHub OWNER-web release agent is installed and enabled."
echo "Mode: outbound-only; source SHA $SOURCE_REF; initial production SHA $BASELINE"
echo "Further owner web releases require a passing CI and a changed approved manifest."
