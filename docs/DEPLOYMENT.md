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

## 2. Decide where it captures (3 min) — this decides what Wyvern can detect

Home networks are *switched*: a host normally sees only its own traffic plus
broadcasts. **Capture position puts a hard ceiling on what any detector can do**,
and it matters more than every configuration choice below put together.

| Setup | What it sees | Detectors that can fire |
|---|---|---|
| **Router / OpenWrt** (best) | everything on the LAN | all 10 |
| **Pi on a managed-switch mirror/SPAN port** | everything crossing that switch | all 10 |
| **Between modem & router** (mirror or bridge) | all WAN-bound traffic | 6 of 10 — no intra-LAN stages |
| **Your main PC** (quick start) | that PC, plus broadcasts | effectively one host |

### The quick-start tier is much weaker than it looks

Measured on a 48-day production run — WiFi client NIC, switched /22, 87 devices:

- **`port_scan`, `lateral_movement`, `credential_spray` and `ssh_key_injection`
  raised zero alerts in 48 days.** All four need *other* devices' unicast traffic,
  which a client-mode NIC on a switched network never receives.
- Of 86 learned device profiles, **exactly one** — the monitoring host — had any
  external domain in its history. The other 85 held only `.local` and `.arpa`
  names, both of which are multicast.
- `zero_egress`, and therefore the `no_egress_hosts` control, is **inert** for any
  device whose traffic never reaches the sensor — on this tier, all but one.

**On this tier, an absence of alerts is not evidence that your network is clean.**
It is substantially evidence that the sensor cannot see your network. The quick
start is a good way to confirm Wyvern runs, and a reasonable way to watch one
important machine. It is not home-network monitoring, and §4b below will tell you
exactly which detectors are asleep.

### If your router is a consumer mesh (eero, Google Wifi, Deco…)

These expose no port mirroring and run no custom firmware, so the first two rows
above are unavailable to you. Wireless clients on the same access point also talk
*through* that AP, which will not mirror — so **traffic between wireless devices
is unobservable on a consumer mesh no matter what you do.** Four detectors stay
dark permanently. You can still get complete *egress* visibility:

1. Find the ethernet cable running from your modem/ONT to the mesh gateway. That
   cable carries every packet your household sends to the internet.
2. Insert a managed switch that supports port mirroring — about $40, e.g. a
   TP-Link TL-SG108E or Netgear GS308E.
3. Wire it: modem → port 1, mesh gateway → port 2, Wyvern's spare NIC → port 3.
4. In the switch's web UI, mirror **port 1, both directions**, to port 3.
5. Bring that NIC up with no IP address and point Wyvern at it:
   `sudo ip link set eth1 up`, then set `interface: eth1` in your config.

Prefer mirroring over an inline bridge. The visibility is identical, but Wyvern
stays out of the traffic path, so a crash, a reboot or a kernel upgrade cannot take
your household's internet down with it. Keep a second interface — WiFi is fine —
for the dashboard, because mirror destination ports do not forward normally.

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

## 4b. Confirm what your sensor can actually see (1 min)

Do not infer your coverage — Wyvern reports it:

```bash
curl -s localhost:8787/api/stats | jq .visibility
```

```json
{
  "scope": "host-only",
  "devices_seen": 39,
  "devices_with_egress": 1,
  "devices_with_internal_unicast": 2,
  "dormant_detectors": ["credential_spray", "lateral_movement", "port_scan",
                        "ssh_key_injection", "zero_egress"],
  "unenforceable_no_egress": []
}
```

- **`scope`** — `host-only`, `egress`, or `lan`. Compare it against the tier you
  thought you deployed.
- **`dormant_detectors`** — detectors that *cannot* fire from this capture
  position, because the class of traffic they need has never been observed. Their
  silence carries no information. A detector that has fired before is never listed
  here, so this reflects real evidence rather than a guess.
- **`unenforceable_no_egress`** — hosts you declared in `no_egress_hosts` whose
  traffic is never seen, which makes the declaration unenforceable.

`wyvern report`, `wyvern replay` and `wyvern simulate` print the same thing as a
`CAPTURE VISIBILITY` block. Check it once after deploying: if `scope` is
`host-only` and you expected LAN coverage, your capture position is wrong and no
amount of tuning will compensate.

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

**systemd from a git checkout:** the unit above assumes the packaged layout
(`/opt/wyvern`, `/etc/wyvern`, a dedicated `wyvern` user). To run from a clone as
yourself, use `deploy/wyvern-checkout.service` — edit the three paths at the top,
copy it to `/etc/systemd/system/wyvern.service`, then
`sudo systemctl enable --now wyvern`. Because it runs as you rather than as root,
the learned state in your data directory stays readable without `sudo`.

> **Do not run live capture with `nohup … &`.** A transient interface drop closes
> the capture socket, and the process keeps running *without capturing anything* —
> so monitoring stops silently, with no error and no gap visible on the dashboard.
> One deployment lost 22 days that way before anyone noticed, then lost the
> process entirely at the next reboot. `Restart=always` plus
> `WantedBy=multi-user.target` is the fix, and it is the only reason to prefer a
> unit file over a terminal.

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
