# 🐉 Wyvern — Passive AI-Worm Network Sentinel

[![CI](https://github.com/photodoc1960/wyvern/actions/workflows/ci.yml/badge.svg)](https://github.com/photodoc1960/wyvern/actions/workflows/ci.yml)
[![Docker](https://github.com/photodoc1960/wyvern/actions/workflows/docker.yml/badge.svg)](https://github.com/photodoc1960/wyvern/actions/workflows/docker.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Tests](https://img.shields.io/badge/tests-123-brightgreen)
![Coverage](https://img.shields.io/badge/coverage-88%25-brightgreen)

Wyvern is a **passive, read-only** network monitor and anomaly detector for home
and small-office LANs. It watches internal traffic, tracks every device, learns
what "normal" looks like, and raises threat-scored alerts when it sees the
behavioural signatures of an **AI-driven adaptive computer worm** — the
"Toronto AI worm" characterised by Guan et al., *AI Agents Enable Adaptive
Computer Worms* ([arXiv:2606.03811](https://arxiv.org/abs/2606.03811)).

It is built with **scapy** (capture), **dpkt** (analysis) and **Flask**
(dashboard), exactly as a defensive blue-team tool should be.

---

## ⚖️ What Wyvern will and won't do

Wyvern **only observes, alerts, and recommends.** By design it will **never**:

- modify any device, kill a process, or delete a file;
- change network settings, firewall rules, or credentials;
- transmit attack traffic or actively probe hosts.

Every remediation it suggests is a **manual action for you to take**. The single
state-changing operation it exposes is letting *you* flag a device as
"suspicious" for closer monitoring. Run it **only on networks you own or are
authorised to monitor.**

---

## Why this tool exists

In 2026, researchers at the University of Toronto, the Vector Institute,
Cambridge and ServiceNow demonstrated the first **self-sustaining, AI-driven
adaptive computer worm** — and explicitly named the network signatures it leaves
behind as *"concrete targets for network monitoring and intrusion detection."*
The vendor-side safety controls that guard cloud LLMs are **structurally
irrelevant** to a worm that runs an open-weight model on *stolen* GPUs, and
commercial EDR is out of reach for most households. Home and small-office
networks — flat, unmonitored, full of weak IoT devices — are the soft underbelly.

Wyvern exists to give those owners a fighting chance: a free, passive, read-only
sentinel that watches for exactly those signatures and tells you, in plain
language, what to do. Read the full [threat model](docs/THREAT_MODEL.md).

> **▶ 60-second walkthrough:** `python -m wyvern simulate --web` fabricates a full
> worm outbreak, detects it, and opens the dashboard — the fastest way to see what
> Wyvern does. _(A screen-recorded video walkthrough will be linked here.)_

## The threat, in one paragraph

A traditional worm ships a *fixed* set of exploits; patch them and it stops. The
AI worm instead carries an LLM-backed agent that **reasons about each target at
runtime** — it discovers hosts, picks an exploit, gains a foothold, escalates,
and **replicates**, hopping across Linux, Windows and IoT devices. Crucially, the
proof-of-concept is *not* built to hide, so it leaves concrete network
signatures (the paper, §5): **beacon callbacks on non-standard ports, automated
SSH-public-key injection, and systematic credential reuse across hosts** — plus,
from its architecture, **port/host scanning, lateral movement, LLM inference
proxied from non-GPU devices to compromised GPU hosts,** and **code execution on
normally-idle devices** (printers, cameras, NAS, ICS sensors). Wyvern detects
each of these and **fuses them** into a single AI-worm verdict.

## Quick start

```bash
pip install -r requirements.txt        # scapy, dpkt, Flask, flask-cors, PyYAML

# Safe, no-privileges demo: synthesises a full worm outbreak and detects it
python -m wyvern simulate

# Same, but open the live dashboard
python -m wyvern simulate --web        # http://127.0.0.1:8787

# Analyse a capture you already have
python -m wyvern replay capture.pcap --web

# Live monitoring (needs capture privileges)
sudo python -m wyvern monitor -i eth0
```

**Run it permanently** — Docker, Compose, a hardened systemd unit, a one-line
installer, and Prometheus `/metrics` are documented in
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md):

```bash
docker build -t wyvern . && docker run -d --net=host \
  --cap-drop=ALL --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -e WYVERN_INTERFACE=eth0 -v wyvern-data:/data wyvern
# ...or:  curl -fsSL https://raw.githubusercontent.com/photodoc1960/wyvern/main/install.sh | sudo bash
```

The `simulate` demo prints a report like:

```
  THREAT LEVEL: CRITICAL
  Critical threat: AI-worm propagation signatures on 2 device(s)
  Likely compromised device: 192.168.1.50

  • 192.168.1.50 (workstation) — Critical score=100 [WORM SUSPECT]
      stages: beacon_callback, credential_reuse, discovery, lateral_movement, ssh_key_injection
      → Isolate 192.168.1.50 from the network immediately ...
  • 192.168.1.30 (printer) — Critical score=100 [WORM SUSPECT]
      stages: ... idle_device_exec, inference_proxy ...
```

## How detection works

Each detector targets one worm behaviour and tags its alert with a **stage**.
All operate on normalised, immutable events — never raw packets — so they are
pure and fully unit-tested.

| Detector | Worm behaviour (paper) | Fires when… |
|---|---|---|
| `port_scan` | network/host **discovery** | a host opens SYNs to **>50 ports / 5 min** |
| `lateral_movement` | **lateral movement** | a host contacts **>10 internal IPs / hour** |
| `credential_spray` | **credential reuse across hosts** (§5) | auth (SSH/SMB/RDP/WinRM) to many hosts, or rapid retries |
| `ssh_key_injection` | **SSH public-key injection** (§5) | SSH fan-out from an idle / never-SSH device |
| `inference_api` | **reasoning proxy** (Fig. 1) | LLM inference (`/v1/chat/completions`, vLLM/ollama ports) **from a non-GPU device** |
| `beacon` | **beacon callbacks on non-standard ports** (§5) | regular low-jitter callbacks to a non-standard port |
| `idle_exec` | **self-replication / code exec** | a printer/router/NAS/camera starts **originating** connections |
| `dns_anomaly` | C2 lookups | query spikes, NXDOMAIN bursts, DGA-looking domains |

### The composite signature

The `worm_signature` correlator is the centrepiece. No single behaviour proves a
worm — but **one device exhibiting several stages together** does. It tracks the
distinct stages seen per device within a window and escalates:

- **≥ 2 stages → HIGH** "AI-worm propagation" verdict
- **≥ 3 stages → CRITICAL**, naming the **likely-compromised device**

It also encodes the worm's exploit fingerprint from the paper's Table 1 (SMB 445,
Docker 2375, Redis 6379, ActiveMQ 61616, Exim 25, Jupyter 8888, PrintNightmare,
Modbus 502, Marimo 2718, …) to recognise the worm's actual exploit traffic.

### Baseline learning

For each device, Wyvern learns "normal" over a 24-hour window (configurable):
the ports it initiates to, internal peers, domains, packet-rate envelope, active
hours, and whether it *ever* makes inference calls or auth fan-outs. Detectors
use this to turn raw activity into *deviation from this device's own normal* and
to suppress false positives. Baselines persist across restarts.

### Threat assessment & remediation

Alerts are aggregated per device into a **Low / Medium / High / Critical** level
with a 0-100 score, the worm stages observed, and **manual** remediation steps:

> *Isolate [device] · Change credentials on [targets] · Reboot [device] · Run a
> process scan · Check [device]'s recent connections in system logs.*

## Dashboard

`--web` serves a dark, offline-friendly Flask dashboard (no external CDNs):

- **radial network topology** (echoing the paper's propagation tree) — radius ∝
  threat, pulsing red ring = worm suspect, red edges = worm-service flows;
- **live threat timeline** streamed over Server-Sent-Events;
- **device table** with OS/vendor/role fingerprints and a one-click
  "watch / suspicious" toggle;
- **forensic export** to JSON or CSV.

## CLI reference

```
wyvern simulate [--web] [--pcap OUT]   # synthetic worm outbreak (safe demo)
wyvern replay PCAP [--web] [--realtime] [--speed N]
wyvern monitor [-i IFACE] [--no-web] [--no-learn]
wyvern report                          # print current assessment from stored data
wyvern export OUT [--format json|csv]  # forensic bundle / alert CSV
wyvern -c config.yaml <command>        # use a config file
```

## Configuration

Copy [`config.example.yaml`](config.example.yaml), edit, and pass with `-c`. You
can declare known `gpu_hosts` (to silence inference false-positives), tune every
threshold, set `internal_cidrs`, and configure alerting. **Secrets never live in
the file** — the SMTP password is read only from `WYVERN_SMTP_PASSWORD`.

## Architecture

```
capture/   scapy live capture + dpkt frame decoding  -> normalised events
models/    immutable Device / Alert / Event / Profile dataclasses
tracking/  device registry + passive OS/role fingerprinting (OUI, TTL, DHCP)
baseline/  24h per-device behavioural learning + persistence
detectors/ 8 stage detectors + the worm_signature correlator
assessment/ threat scoring + manual remediation
storage/   SQLite + append-only JSONL forensic log + exporters
alerting/  desktop notifications + optional email digest (off by default)
engine/    Monitor orchestrator + SSE bus
web/       Flask dashboard (topology, timeline, devices, export)
simulate/  synthetic Toronto-worm trace generator (demo + tests)
```

The pipeline: **capture → decode → track + learn → detect → correlate →
assess → store + alert + dashboard.** Everything funnels through
`Monitor.process_event`, which is also how replay, the simulator and the tests
drive it — no live interface or root required for testing.

## Testing

```bash
make test     # 123 tests
make cov      # coverage report (88% line coverage)
```

The suite covers decoding (against dpkt-crafted frames), every detector
(above/below threshold + negative cases), fingerprinting, baseline learning and
persistence, threat scoring, storage, and a full end-to-end integration test
that replays the synthetic worm trace and asserts a Critical verdict.

## Limitations & honesty

- Encrypted payloads are opaque; SSH-key-injection and credential detection are
  **behavioural inferences** (fan-out patterns), not payload inspection.
- Passive OS/role fingerprinting is heuristic (OUI + TTL + DHCP + service ports).
- Thresholds ship with sensible defaults; tune them and declare your `gpu_hosts`
  to fit your network and cut false positives.
- A future, stealth-hardened worm could suppress these signatures — the paper
  notes the PoC deliberately does not. Wyvern targets the signatures that exist.

## Documentation

| Doc | What's in it |
|---|---|
| [Threat model](docs/THREAT_MODEL.md) | Why this exists, the worm, what Wyvern can/can't see |
| [Deploy in 10 minutes](docs/DEPLOYMENT.md) | Where to capture, configure, learn, alert |
| [What alerts mean](docs/ALERTS.md) | Per-alert playbook + what to do when one fires |
| [Design](docs/DESIGN.md) | Architecture, data model, threading, testing |
| [Contributing](CONTRIBUTING.md) | Dev setup + a guide to writing your own detector |
| [Changelog](CHANGELOG.md) | Release history |

## Community & contributing

Wyvern is a **public, MIT-licensed** community blue-team tool — detection rules
get better with more networks watching.

- 🟡 **Found a false positive?** Open a
  [GitHub Discussion](https://github.com/photodoc1960/wyvern/discussions) so we can
  tune the defaults for everyone.
- 🛡️ **Add your own detection rule** — the detector architecture is pluggable;
  [CONTRIBUTING.md](CONTRIBUTING.md#writing-your-own-detector) walks through a
  complete example end to end.
- 📦 **Releases** are cut roughly **monthly, tracking new public threat research**
  (new signatures, fingerprints, tuning). Watch the repo to stay current.

## Reference

Jonas Guan, Tom Blanchard, Hanna Foerster, Hengrui Jia, Gabriel Huang, Nicolas
Papernot. *AI Agents Enable Adaptive Computer Worms.* arXiv:2606.03811 (2026).
University of Toronto · Vector Institute · University of Cambridge · ServiceNow.

## License

MIT — see [LICENSE](LICENSE). Use responsibly and only on networks you are
authorised to monitor.
