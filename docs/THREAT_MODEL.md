# Wyvern Threat Model

## Why this tool exists

In 2026, Guan et al. published *AI Agents Enable Adaptive Computer Worms*
([arXiv:2606.03811](https://arxiv.org/abs/2606.03811)) — a University of Toronto
/ Vector Institute / Cambridge / ServiceNow proof-of-concept of a fundamentally
new class of malware. Unlike WannaCry or NotPetya, which carry a **fixed**
exploit chain you can patch away, the "Toronto AI worm" carries an **LLM-backed
agent** that *reasons about each target at runtime*: it discovers hosts, picks
or synthesises an exploit, gains a foothold, escalates privilege, and
**replicates** — across Linux, Windows and IoT devices — with the attacker's
marginal cost per new infection approaching zero.

The paper is explicit that its proof-of-concept is **not** built to hide
(§"Mitigations", §5). It therefore leaves concrete network signatures, and the
authors name them as *"concrete targets for network monitoring and intrusion
detection."* Wyvern is a defensive tool that implements exactly those targets for
the people most exposed and least resourced: **home and small-office network
owners.**

## Assets at risk on a home network

- **Compute & GPUs** — the worm parasitises GPU hosts to run its LLM. Your gaming
  PC or workstation is fuel.
- **IoT / OT devices** — printers, cameras, NAS, smart-home hubs, ICS sensors are
  both targets (weak/default creds) and stepping stones.
- **Credentials** — reused across hosts, harvested and broadcast by the worm's
  swarm.
- **Data & privacy** — exfiltration over the worm's command channels.
- **Availability & trust** — a flat home network is a worst-case "everything can
  reach everything" topology (the paper's FakeCorp is exactly this).

## Adversary model

| Property | Assumption |
|---|---|
| Capability | Autonomous LLM agent; reasons, adapts, synthesises exploits at runtime |
| Knowledge | Zero-knowledge start: no prior map of your network |
| Entry | One initially-compromised host (phishing, a vulnerable service, a malicious download) |
| Goal | Maximise compromised hosts, with no human in the loop |
| Stealth | PoC does **not** encrypt C2, use polymorphism, or hide compute use. A future variant might. |
| Reach | Linux, Windows, IoT/ICS; uses common CVEs + misconfigurations (Table 1 of the paper) |

## Kill chain → what Wyvern watches

| Worm stage (paper) | Observable signature | Wyvern detector |
|---|---|---|
| Network/host discovery | many ports/hosts probed | `port_scan` |
| Lateral movement | one host → many internal hosts | `lateral_movement` |
| Foothold (exploitation) | traffic to worm service ports (SMB/Docker/Redis/Exim/Jupyter/…) | encoded across detectors + `worm_signature` |
| Credential reuse across hosts (§5) | auth to many hosts / rapid retries | `credential_spray` |
| SSH public-key injection (§5) | SSH fan-out from idle/never-SSH device | `ssh_key_injection` |
| Reasoning proxy (Fig. 1) | LLM inference from a non-GPU device → GPU host | `inference_api` |
| Beacon callbacks on non-standard ports (§5) | regular low-jitter callbacks | `beacon` |
| Self-replication / code exec | a printer/router/NAS/camera **originates** connections | `idle_exec` |
| (support) C2 lookups | DNS spikes / NXDOMAIN bursts / DGA domains | `dns_anomaly` |
| **Composite** | ≥2–3 of the above on one device | `worm_signature` → HIGH/CRITICAL |

## What Wyvern can and cannot see

**Can:** L2/L3/L4 metadata, ARP/DNS/DHCP, TCP flags & flows, cleartext HTTP
request lines, TLS SNI, and the *behavioural shape* of the above.

**Cannot:** the contents of encrypted payloads. SSH-key-injection and credential
detection are **behavioural inferences** (fan-out, timing), not payload reads. A
worm variant that mimics human traffic timing, rides only standard ports, and
encrypts its reasoning channel would evade some signatures — the paper notes the
PoC deliberately forgoes such evasion.

## Wyvern's own security posture

- **Passive & read-only.** Capture uses scapy with `store=False` and never
  transmits. Replay reads pcaps. There is no code path that writes to the network
  or to another device.
- **No automated response.** Wyvern never isolates, kills, reboots, or rotates
  anything. It produces *recommendations* a human executes.
- **Least authority.** It needs packet-capture privilege for live mode (or none
  for replay/simulate). It opens a **localhost** dashboard by default.
- **One user-write.** Marking a device "suspicious" is the only state change the
  UI offers, and it only affects Wyvern's own monitoring focus.
- **Secrets.** No secret is read from config files; SMTP credentials come only
  from the environment.

## Out of scope / non-goals

- Active scanning, vulnerability assessment, or exploitation.
- Endpoint/host agents, EDR, or process inspection (Wyvern is network-only).
- Automated blocking/quarantine (intentionally — see posture above).
- Deep packet inspection of encrypted traffic or TLS interception.
