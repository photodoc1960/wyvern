# Changelog

All notable changes to Wyvern are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/); releases are cut roughly monthly
and track new public threat research.

## [Unreleased]

### Added
- **Confirm-mode approval and release.** `response.mode: confirm` now works: approve
  a pending quarantine, or release/dismiss one, from the dashboard's *Response engine*
  panel, with `wyvern quarantine list|approve|release`, or via
  `GET /api/quarantines` and `POST /api/quarantines/<id>/approve|release`. Approval
  re-checks the severity threshold, protected hosts and an approval circuit breaker
  against the current config. The write endpoints accept only loopback, JSON,
  same-origin requests. Quarantine records now store the verdict's severity (the DB
  column is added automatically).

### Changed
- Releasing a quarantine whose release command fails now leaves it active (and says
  so) instead of marking it released while the rule may still be in place.

## [0.2.0] — 2026-11-24

Five months of dogfooding and monthly threat-research updates. The headline changes
are fewer false positives, a sensor that reports its own blind spots, and an opt-in
response layer that is inert unless you configure it.

### Added
- **`stream_timing` detector** (#16): passive detection of LLM inference tunnelled
  over HTTPS from the inter-packet rhythm of the streamed response (Alhazbi et al.
  2025). Timing metadata only — no TLS interception. A corroborating hint: it is never
  surfaced on its own and only raises confidence in an `inference_api` finding (#64).
- **`zero_egress` detector** (#26): declare isolated hosts in `no_egress_hosts`; any
  egress from them raises a high-confidence alert (#28).
- **Detection → enforcement bridge** (#27): optionally POST HMAC-signed high-confidence
  findings to an *external* actuator. Off unless configured; Wyvern itself blocks
  nothing on this path.
- **Tier-1 response engine** (#30, #31, #32). **Inert by default:** `mode: observe`
  only records what Wyvern *would* quarantine. If you opt in to `confirm` or `auto`
  with `responder: firewall`, Wyvern runs your own quarantine/release command
  templates (no shell) against a device on a CRITICAL worm verdict, guarded by
  protected hosts, a circuit breaker, TTL auto-release, and durable state that is
  reconciled on restart.
- **Visibility reporting** (#54): the sensor reports what its capture position lets
  it see and which detectors are dormant (`/api/stats` → `visibility`).
- **mDNS device identification** (#51) from service-discovery records.

### Changed
- `beacon` grades jitter over two bands; jittered-but-periodic callbacks raise a LOW
  signal and no longer count as a worm stage (#36, #45).
- `idle_exec` keys on worm behaviour rather than a device's label (#52).
- Cooldown tables prune expired entries, so a long-running sensor's memory stays
  bounded (#64).

### Fixed
- **Dual-stack networks** (#63): a device with IPv4 and IPv6 link-local addresses
  counted once as a device, a peer and an alert source. Previously a peer reached over
  both stacks counted twice, enough to trip credential-spray on three SMB hosts.
- mDNS names were scored as algorithmically generated domains — 78% of all alerts in
  dogfooding (#44); reverse-DNS is excluded from DNS anomalies and DGA now requires
  novelty (#50).
- Inference API paths match on segment boundaries, ending captive-portal false
  positives (#42).
- Subnet-aware gateway detection; a wrong router guess no longer sticks (#43).
- The visibility report named the wrong detectors as dormant, and counted devices by
  address instead of MAC (#57, #59).
- Colourblind-safe severity palette on the dashboard (#47).

### Documentation
- 14 documented evasions and limitations in `docs/THREAT_MODEL.md`, each with sources
  and a design-scope verdict, from the monthly literature watch.
- Capture position decides what Wyvern can detect — stated plainly in the README and
  deployment guide (#53, #58); known blind spots listed in the README (#65).
- Contributor readiness: ruff, a read-only invariant guard, PR template, security
  policy and code of conduct (#8).

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

[0.2.0]: https://github.com/photodoc1960/wyvern/releases/tag/v0.2.0
[0.1.0]: https://github.com/photodoc1960/wyvern/releases/tag/v0.1.0
