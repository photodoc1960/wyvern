# Changelog

All notable changes to Wyvern are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/); releases are cut roughly monthly
and track new public threat research.

## [0.1.0] — 2026-06-06

Initial public release.

### Added
- **Passive capture** (scapy, read-only) and **dpkt** frame decoding into
  immutable network events (ARP / TCP / UDP / DNS / HTTP / TLS-SNI / DHCP).
- **Device registry** with passive OS/role fingerprinting (OUI, TTL, DHCP,
  service ports) and GPU-host inference.
- **Eight stage detectors** for the Toronto AI worm signatures: port scan,
  lateral movement, credential reuse, SSH-key propagation, inference proxying,
  beacon callbacks, idle-device code execution, and DNS anomalies.
- **Composite `worm_signature` correlator** that fuses stages per device into a
  HIGH/CRITICAL AI-worm verdict and names the likely-compromised device.
- **24-hour per-device baseline learning** with persistence.
- **Threat assessment** (Low/Medium/High/Critical + score) and **manual
  remediation** recommendations.
- **Flask dashboard**: radial topology, live SSE threat timeline, device table,
  one-click "mark suspicious", JSON/CSV forensic export.
- **Storage**: SQLite + append-only JSONL forensic log + exporters.
- **Desktop notifications**; optional email digest (off by default, secrets from
  env only).
- **CLI**: `simulate`, `replay`, `monitor`, `report`, `export`.
- **Synthetic worm simulator** for safe demos and end-to-end tests.
- **Deployment**: Dockerfile + Docker Compose, a hardened systemd unit
  (`CAP_NET_RAW`/`CAP_NET_ADMIN` only, not root), a one-line installer
  (`install.sh`), and a Prometheus `/metrics` endpoint for Grafana/SIEM.
- Container/service env overrides: `WYVERN_INTERFACE`, `WYVERN_DATA_DIR`,
  `WYVERN_WEB_HOST`, `WYVERN_WEB_PORT`.
- 120+ tests, ~88% line coverage; full docs (threat model, design, deployment,
  alert playbook, contributing).

[0.1.0]: https://github.com/photodoc1960/wyvern/releases/tag/v0.1.0
