# Deploy Wyvern on your home network in 10 minutes

Wyvern is passive — it only listens. The whole job is **getting it somewhere it
can see your LAN traffic**, then letting it learn.

## 0. Prerequisites (1 min)

- Python 3.10+
- A Linux/macOS box that can see network traffic (a spare laptop, a Raspberry
  Pi, your always-on desktop, or your router if it runs Linux/OpenWrt).

```bash
git clone https://github.com/photodoc1960/wyvern.git
cd wyvern
pip install -r requirements.txt
```

## 1. Prove it works — no privileges needed (1 min)

```bash
python -m wyvern simulate --web
```

This fabricates a full Toronto-worm outbreak on a pretend home network, detects
it, and opens the dashboard at **http://127.0.0.1:8787**. If you see two
**CRITICAL** worm suspects (a workstation and a printer), you're good. Nothing
real was touched.

## 2. Decide where it captures (3 min)

Home networks are *switched*, so a host normally only sees its own traffic plus
broadcasts. Pick the option that fits you:

| Setup | Visibility | How |
|---|---|---|
| **Router / OpenWrt** (best) | everything | run Wyvern on the router; capture the LAN bridge (e.g. `br-lan`) |
| **Raspberry Pi on a mirror/SPAN port** | everything | enable port mirroring on a managed switch to the Pi's NIC |
| **Pi between modem & router** (bridge) | all WAN-bound traffic | two NICs bridged; capture the bridge |
| **Your main PC** (quick start) | that PC + broadcasts (ARP/DNS/DHCP/mDNS) | capture your normal interface |

Even the "main PC" option sees all ARP/DNS/DHCP broadcasts, so device discovery
and many signatures (scans *targeting* you, beacons *from* you) still work — it's
a fine starting point.

## 3. Configure for your network (2 min)

```bash
cp config.example.yaml config.yaml
```

Edit three things:

```yaml
interface: br-lan            # your capture interface (or null for default)
internal_cidrs: [192.168.1.0/24]   # YOUR LAN range(s)
gpu_hosts: ["192.168.1.50"]  # PCs that legitimately run local LLMs (avoids false positives)
```

## 4. Start monitoring + learning (1 min)

```bash
sudo python -m wyvern -c config.yaml monitor      # live capture needs privileges
```

- The dashboard is at http://127.0.0.1:8787.
- Wyvern now **learns each device's normal behaviour for 24 hours**. During this
  window it still catches the hard worm signatures (scans, beacons, inference
  proxying) using absolute thresholds; after it, deviation-based detection
  sharpens and false positives drop.

> Tip: run it under `tmux`/`screen` or as a systemd service so it survives logout.
> A minimal unit:
> ```ini
> [Unit]
> Description=Wyvern sentinel
> After=network-online.target
> [Service]
> ExecStart=/usr/bin/python3 -m wyvern -c /etc/wyvern/config.yaml monitor --no-web
> Restart=on-failure
> [Install]
> WantedBy=multi-user.target
> ```

## 5. Turn on alerts (1 min)

Desktop notifications are on by default (HIGH+). For an email digest, set the
SMTP fields in `config.yaml` and **export the password in the environment**:

```bash
export WYVERN_SMTP_PASSWORD='your-app-password'   # never put it in the file
```

## 6. Know what to do when it fires

Read [ALERTS.md](ALERTS.md) — it explains every alert and the manual steps to
take. Remember: **Wyvern never acts for you.** When in doubt, isolate the named
device and investigate.

## Run it permanently (Docker · systemd · installer)

**One-line installer** — system service as a least-privilege `wyvern` user:

```bash
curl -fsSL https://raw.githubusercontent.com/photodoc1960/wyvern/main/install.sh | sudo bash
sudo nano /etc/wyvern/wyvern.env        # set WYVERN_INTERFACE=<your LAN iface>
sudo systemctl start wyvern && journalctl -u wyvern -f
```

**Docker** (live capture needs host networking + raw-socket caps):

```bash
docker build -t wyvern .
docker run -d --name wyvern --net=host \
  --cap-drop=ALL --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -e WYVERN_INTERFACE=eth0 -e WYVERN_WEB_HOST=127.0.0.1 \
  -v wyvern-data:/data wyvern
```

or `WYVERN_INTERFACE=eth0 docker compose up -d`.

**systemd (manual):** copy `deploy/wyvern.service` to `/etc/systemd/system/` and
`deploy/wyvern.env` to `/etc/wyvern/`, then `systemctl enable --now wyvern`. The
unit runs unprivileged with only `CAP_NET_RAW`/`CAP_NET_ADMIN`.

**Metrics / Grafana / SIEM:** the dashboard exposes Prometheus metrics at
`/metrics` (`wyvern_threat_level`, `wyvern_worm_suspects`,
`wyvern_alerts_by_severity{…}`, per-device scores). Point Prometheus at
`http://<host>:8787/metrics`.

## Updating

```bash
git pull && pip install -r requirements.txt
```

Releases are cut roughly monthly and track new public threat research — watch the
repo to be notified.
