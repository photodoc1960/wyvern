#!/usr/bin/env bash
# Wyvern one-line installer — system service, least privilege, passive only.
#
#   curl -fsSL https://raw.githubusercontent.com/photodoc1960/wyvern/main/install.sh | sudo bash
#
# Installs into /opt/wyvern (venv), config in /etc/wyvern, runs as a dedicated
# 'wyvern' user with only CAP_NET_RAW/CAP_NET_ADMIN. Enables but does NOT start
# the service, so you can confirm the capture interface first.
set -euo pipefail

REPO_URL="${WYVERN_REPO:-https://github.com/photodoc1960/wyvern.git}"
PREFIX="/opt/wyvern"
CONF_DIR="/etc/wyvern"
SERVICE="/etc/systemd/system/wyvern.service"

log() { printf '\033[36m[wyvern]\033[0m %s\n' "$*"; }
die() { printf '\033[31m[wyvern] error:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root (pipe to 'sudo bash')"
command -v python3 >/dev/null || die "python3 (>=3.10) is required"
command -v git >/dev/null || die "git is required"

log "creating service user 'wyvern'"
id -u wyvern >/dev/null 2>&1 || \
  useradd --system --no-create-home --shell /usr/sbin/nologin wyvern

log "installing Wyvern into ${PREFIX}"
python3 -m venv "${PREFIX}/venv"
"${PREFIX}/venv/bin/pip" install --quiet --upgrade pip
"${PREFIX}/venv/bin/pip" install --quiet "git+${REPO_URL}"

IFACE="$(ip route show default 2>/dev/null | awk '{print $5; exit}')"
IFACE="${IFACE:-eth0}"
log "detected default interface: ${IFACE}"

log "writing configuration to ${CONF_DIR}"
mkdir -p "${CONF_DIR}"
if [ ! -f "${CONF_DIR}/config.yaml" ]; then
  cat > "${CONF_DIR}/config.yaml" <<'YAML'
# Wyvern configuration — https://github.com/photodoc1960/wyvern
internal_cidrs: [192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12]
gpu_hosts: []            # IPs of machines that legitimately run local LLMs
learning_window_hours: 24
web_enabled: true
web_port: 8787
notify:
  desktop_enabled: false # headless service — desktop notifications won't show
  min_severity: 3
YAML
fi
cat > "${CONF_DIR}/wyvern.env" <<ENV
WYVERN_INTERFACE=${IFACE}
WYVERN_WEB_HOST=127.0.0.1
WYVERN_DATA_DIR=/var/lib/wyvern
# WYVERN_SMTP_PASSWORD=
ENV
chmod 640 "${CONF_DIR}/wyvern.env"

log "installing systemd unit"
cat > "${SERVICE}" <<'UNIT'
[Unit]
Description=Wyvern passive AI-worm network sentinel
Documentation=https://github.com/photodoc1960/wyvern
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=wyvern
Group=wyvern
EnvironmentFile=/etc/wyvern/wyvern.env
ExecStart=/opt/wyvern/venv/bin/wyvern -c /etc/wyvern/config.yaml monitor
Restart=always
RestartSec=10
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=true
StateDirectory=wyvern
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/wyvern

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable wyvern >/dev/null 2>&1 || true

log "installed."
cat <<EOF

  Next steps:
    1. Confirm the capture interface:  sudo nano ${CONF_DIR}/wyvern.env   (currently ${IFACE})
    2. Start the sentinel:             sudo systemctl start wyvern
    3. Follow the logs:                journalctl -u wyvern -f
    4. Open the dashboard:             http://127.0.0.1:8787

  Want to see it work first (safe, no privileges)?
    ${PREFIX}/venv/bin/wyvern simulate

EOF
