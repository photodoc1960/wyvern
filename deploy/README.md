# Deploying Wyvern as a service

Three ways to run Wyvern permanently. All are passive/read-only.

## Fastest: one-line installer

```bash
curl -fsSL https://raw.githubusercontent.com/photodoc1960/wyvern/main/install.sh | sudo bash
```

Installs into `/opt/wyvern` (a venv), writes config to `/etc/wyvern/`, installs a
hardened systemd unit that runs as a dedicated **`wyvern`** user with only
`CAP_NET_RAW`/`CAP_NET_ADMIN` (not root), and **enables but does not start** it so
you can confirm the interface first.

```bash
sudo nano /etc/wyvern/wyvern.env     # set WYVERN_INTERFACE=<your LAN iface>
sudo systemctl start wyvern
journalctl -u wyvern -f
```

## Docker

```bash
docker build -t wyvern ..
docker run -d --name wyvern --net=host \
  --cap-drop=ALL --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -e WYVERN_INTERFACE=eth0 -e WYVERN_WEB_HOST=127.0.0.1 \
  -v wyvern-data:/data wyvern
```

or, from the repo root:

```bash
WYVERN_INTERFACE=eth0 docker compose up -d
```

`--net=host` is required so the container sees LAN traffic. The dashboard binds
to `WYVERN_WEB_HOST` on the host (keep it `127.0.0.1` unless you mean to expose it).

## systemd (manual)

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin wyvern
sudo python3 -m venv /opt/wyvern/venv
sudo /opt/wyvern/venv/bin/pip install "git+https://github.com/photodoc1960/wyvern.git"
sudo mkdir -p /etc/wyvern && sudo cp wyvern.env /etc/wyvern/
# create /etc/wyvern/config.yaml from ../config.example.yaml
sudo cp wyvern.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now wyvern
```

## Metrics

The dashboard exposes Prometheus metrics at **`/metrics`** — point Prometheus at
`http://<host>:8787/metrics` and build Grafana panels on `wyvern_threat_level`,
`wyvern_worm_suspects`, `wyvern_alerts_by_severity{severity=…}`, and the
per-device `wyvern_device_threat_score{device,role,level}`.
