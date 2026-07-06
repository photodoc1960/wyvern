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

## Known limitations and evasions

### MCP-based aperiodic C2 bypasses BeaconDetector (2026-06)
- **Affected detector / component:** `beacon` stage (`BeaconDetector`, `wyvern/detectors/beacon.py`); secondarily `inference_api` detector
- **Finding:** Janjusevic et al. (2025) document a C2 architecture that routes commands through the Model Context Protocol (MCP) over HTTPS. MCP's asynchronous task-polling is demand-driven and interval-irregular, producing a CoV well above Wyvern's `beacon_max_cov` threshold (≤ 0.20). The traffic is TLS-encrypted and runs on standard HTTPS ports, so neither the beacon stage nor the inference-API detector can distinguish it from ordinary LLM API traffic. The paper explicitly claims "drastic reductions in detection footprint" with "no periodic beaconing."
- **Within design scope to fix?** No. Resolving this would require TLS interception to inspect JSON-RPC path or application-layer payload — explicitly excluded by Wyvern's passive-sensor design (see "Out of scope" above). JA3/JA4 TLS fingerprinting could narrow the signal but would not defeat a client that randomises its TLS stack.
- **Candidate future hardening:** JA3/JA4 fingerprint matching against known MCP client libraries as a weak signal (note: Encrypted Client Hello / ECH in TLS 1.3 is now removing the ClientHello fields JA3/JA4 rely on — Lipcsey-Magyar et al. 2026 find only 64.9% of malware families had unique JA4 signatures even before ECH deployment, and ECH is enabled by default in major browsers and CDNs; this substantially narrows the JA4 path — https://consensus.app/papers/details/6d15e62fe0ac5906b74f2eb26254fcbe/); flag persistent long-lived HTTPS sessions to LLM API endpoints from non-GPU hosts as a corroborating indicator.
- **Source:** Strahinja Janjusevic et al., "Hiding in the AI Traffic: Abusing MCP for LLM-Powered Agentic Red Teaming," arXiv, 2025. https://arxiv.org/abs/2506.02293

### Application-layer LLM-ecosystem worms leave no network signatures (2026-06)
- **Affected detector / component:** All Wyvern detectors — this propagation class is invisible at the IP/TCP layer
- **Finding:** Three independent 2025–2026 papers (RAGworm / Cohen et al. at ACM CCS 2025; ClawWorm / Zhang et al. 2026; Zha et al. 2026) confirm a distinct class of self-replicating malware that propagates via LLM application-layer mechanisms: adversarial prompt injection into RAG-indexed content, cross-agent message injection within agent frameworks, and persistent-state hijacking across multi-agent pipelines. Propagation produces no TCP scanning, no lateral movement flows, no port probes, and no beacon callbacks — none of Wyvern's detectors fire. Cohen et al. (ACM CCS 2025) demonstrate super-linear spread (~20 new clients per infected client within 1–3 days). Wyvern may still observe `inference_api` signals if the worm drives high LLM call volume from a non-GPU device, but this is indirect and non-specific.
- **Within design scope to fix?** No. Detection would require inspecting LLM prompt/response payloads or monitoring agent framework internals — both require endpoint-level access and are outside Wyvern's network-only, passive-sensor scope.
- **Candidate future hardening:** Anomalous LLM API call volume from a non-GPU device (partially covered by `inference_api`) could be flagged at a lower threshold as a weak corroborating signal; direct detection requires application-layer agent monitoring outside Wyvern's scope.
- **Source:** Stav Cohen et al., "Here Comes the AI Worm: Preventing the Propagation of Adversarial Self-Replicating Prompts Within GenAI Ecosystems," ACM CCS, 2025. https://dl.acm.org/doi/10.1145/3698900 | Yihao Zhang et al., "ClawWorm: Self-Propagating Attacks Across LLM Agent Ecosystems," arXiv, 2026. https://arxiv.org/abs/2506.02503 | Mingming Zha et al., "Autonomous LLM Agent Worms: Cross-Platform Propagation, Automated Discovery and Temporal Re-Entry Defense," arXiv, 2026.

### AI-assisted micro-pacing evades `port_scan` volumetric threshold (2026-06)
- **Affected detector / component:** `port_scan` detector (`wyvern/detectors/port_scan.py`); fires when a host opens SYNs to >50 ports in 5 min
- **Finding:** Carbajal et al. (2026) analyse 192 million real darknet packets (2021–2025) from the Merit ORION Network Telescope and find that modern AI-assisted botnets deliberately use inter-packet micro-pacing (1–100 ms delays) to smooth their scan rate below volumetric thresholds. A simulated anomaly-based IDS with standard thresholds failed to detect 97.47% of this traffic; compensatory threshold lowering triggered a 68.10% false-positive rate. ICS-relevant ports targeted by this traffic (SMB 445, Modbus 502) nearly doubled as a share of darknet traffic from 2021 to 2025, overlapping directly with the Toronto AI worm's exploit fingerprint.
- **Within design scope to fix?** No. Lowering Wyvern's >50-ports/5-min threshold to catch paced scanners produces an unacceptably high FPR (Carbajal: 68.10% at compensatory settings). A proper fix requires flow aggregation over longer temporal windows — significant redesign, not a focused change.
- **Candidate future hardening:** Flow-aggregation anomaly scoring over 15–30 min windows, tracking cumulative unique-destination-port count per source IP, as demonstrated by PortScout (Sangeen et al., ICC 2025) — 89.5% detection rate at 0.34% FPR using only (src IP, dst IP, dst port) attributes already available to Wyvern.
- **Source:** A. Carbajal et al., "Characterizing AI-Assisted Bot Traffic in Darknet Data: Implications for ICS and IIoT Security," 2026. https://consensus.app/papers/details/e69b3b4ddabd5a17ba9a1d42c3079a12/ | Muhammad Sangeen et al., "PortScout: A Communication Flow-Based Approach to Detect Port Scanning Evasion Attacks," ICC 2025 (IEEE International Conference on Communications), 2025. https://consensus.app/papers/details/3e393ae75dbd5a6ba8470afc925a2d60/

### LLM-driven polymorphic exploit synthesis defeats endpoint AV/EDR behavioral heuristics (2026-07)
- **Affected detector / component:** Adversary model ("Stealth" assumption); indirectly elevates all Wyvern network-behavioral detectors (especially `worm_signature`) to primary effective detection layer
- **Finding:** Hortea et al. (2026) quantify LLM-generated offensive payloads as structurally diverse yet behaviorally identical at $0.41–$0.73 each, with historical-injection prompting amplifying structural divergence 5×, defeating both signature-based detection and similarity clustering. I.E et al. (2026) demonstrate 100% Windows Defender evasion including Controlled Folder Access — a behavioral heuristic control, not a signature control — for Python payloads performing network tunneling and file encryption. Together these papers confirm that the Toronto AI worm's runtime exploit-synthesis capability achieves near-complete endpoint AV/EDR bypass across both signature and behavioral detection. The current threat model justifies Wyvern partly on the assumption that commercial EDR is unavailable to home users, implying deployed EDR *would* catch AI-worm exploits. These papers refute that assumption: network-layer behavioral detection is the primary effective sensor for AI-worm exploit traffic on any home or small-office network, including those running endpoint security products.
- **Within design scope to fix?** N/A — this is a threat-model framing clarification, not an evasion of a Wyvern detector. Wyvern's passive network-behavioral approach is confirmed as the correct architectural choice, not merely a cost-constrained fallback.
- **Candidate future hardening:** None required — existing passive network-behavioral detectors remain the appropriate sensor class. The adversary model's "Stealth" note ("A future variant might [use polymorphism]") should now be read as confirmed for endpoint detection. No Wyvern code change is warranted.
- **Source:** Gabriel Hortea et al., "The Infinite Mutation Engine? Measuring Polymorphism in LLM-Generated Offensive Code," preprint, 2026. https://consensus.app/papers/details/b7ff4b9b04ba5a2c8f4b4609be7aa292/ | I. E et al., "Demonstrating Code Mutations Using LLMs: A Sandbox Approach to Safe Malware Testing," 2026 Second International Conference on Multi-Agent Systems for Collaborative Intelligence (ICMSCI), 2026. https://consensus.app/papers/details/43b6db68b6825f898c8308a6b30731bf/
