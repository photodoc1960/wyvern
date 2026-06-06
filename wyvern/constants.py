"""Threat intelligence constants distilled from the Toronto AI worm paper.

Guan et al., *AI Agents Enable Adaptive Computer Worms* (arXiv:2606.03811),
characterise an AI-driven worm that:

* performs network + host **discovery** (port/service scanning),
* exploits a fixed catalogue of common services to gain a **foothold**
  (Table 1 / Appendix B — encoded in :data:`WORM_SERVICE_PORTS`),
* moves **laterally** to other internal hosts,
* reuses **credentials** systematically across hosts (§5),
* injects **SSH public keys** (§5),
* forwards **LLM inference** from non-GPU hosts to compromised GPU hosts
  (Figure 1 — the "reasoning proxy"),
* opens **beacon callbacks on non-standard ports** (§5), and
* **self-replicates**, executing code on normally-idle devices
  (printers, routers, NAS, cameras, ICS sensors).

These are *concrete targets for network monitoring and intrusion detection*
(the paper's own words). Everything here is observable, defensive intelligence —
no exploit code.
"""

from __future__ import annotations

# --------------------------------------------------------------------------- #
# Worm exploit fingerprint — services the worm attacks (Table 1, Appendix B).  #
# port -> (service label, host class it targets, associated CVE/CWE)           #
# --------------------------------------------------------------------------- #
WORM_SERVICE_PORTS: dict[int, tuple[str, str, str]] = {
    22: ("ssh", "linux", "credential-reuse / SSH-key-injection"),
    23: ("telnet", "iot", "default-credentials"),
    25: ("smtp-exim", "linux", "CVE-2019-10149 (Exim RCE)"),
    80: ("http", "web", "Drupalgeddon/Struts/Webmin/printer-UI"),
    111: ("rpcbind", "linux", "nfs/rpc enumeration"),
    135: ("msrpc", "windows", "PrintNightmare/EternalBlue staging"),
    139: ("netbios-ssn", "windows", "CVE-2017-0144 (EternalBlue) / SambaCry"),
    443: ("https", "web", "JWT alg:none gateway / camera API"),
    445: ("smb", "windows", "CVE-2017-0144 (EternalBlue) / CVE-2017-7494 (SambaCry)"),
    502: ("modbus", "ics", "CWE-862 unauth ICS/sensor (aquila)"),
    554: ("rtsp", "camera", "camera stream / hard-coded API key (sigma)"),
    631: ("ipp", "printer", "printer firmware upload (omikron)"),
    1433: ("mssql", "windows", "credential-reuse"),
    2375: ("docker-api", "linux", "CWE-306 exposed Docker API (kappa)"),
    2376: ("docker-api-tls", "linux", "exposed Docker API (kappa)"),
    2718: ("marimo", "linux-gpu", "CVE-2026-39987 (Marimo pre-auth RCE, beta)"),
    3000: ("http-app", "web", "Flask/Node app server"),
    3306: ("mysql", "linux", "credential-reuse (LAMP zeta/eta)"),
    3389: ("rdp", "windows", "credential-reuse (theta)"),
    5000: ("http-flask", "linux", "CWE-78 command injection (epsilon)"),
    5432: ("postgres", "linux", "credential-reuse"),
    5900: ("vnc", "any", "weak/again credential-reuse"),
    5985: ("winrm-http", "windows", "WinRM credential-reuse (gamma/theta)"),
    5986: ("winrm-https", "windows", "WinRM credential-reuse"),
    6379: ("redis", "linux", "Redis unauth escape (psi)"),
    8080: ("http-tomcat", "web", "weak Tomcat creds (xi) / PHP portal (tau)"),
    8081: ("http-alt", "web", "app server"),
    8161: ("activemq-web", "linux", "CVE-2023-46604 (ActiveMQ, omega)"),
    8443: ("https-alt", "web", "app server"),
    8888: ("jupyter", "linux-gpu", "CWE-306 unauth Jupyter (lambda) / Flask (rho)"),
    9100: ("jetdirect", "printer", "raw print / printer compromise (omikron)"),
    10000: ("webmin", "linux", "CVE-2019-15107 (Webmin, pi)"),
    61616: ("activemq-openwire", "linux", "CVE-2023-46604 (ActiveMQ, omega)"),
}

# Ports that authenticate a session; repeated/fan-out hits are credential abuse. #
AUTH_PORTS: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    139: "smb",
    445: "smb",
    1433: "mssql",
    3306: "mysql",
    3389: "rdp",
    5432: "postgres",
    5900: "vnc",
    5985: "winrm",
    5986: "winrm",
}

# Well-known/expected ports — a beacon to anything *outside* this set on a regular
# cadence is the worm's "callback on a non-standard port" signature (§5).
STANDARD_SERVICE_PORTS: frozenset[int] = frozenset(
    {20, 21, 22, 25, 53, 67, 68, 80, 110, 123, 135, 137, 138, 139, 143, 161,
     389, 443, 445, 465, 514, 587, 631, 636, 853, 993, 995, 1900, 3389, 5353}
)

# --------------------------------------------------------------------------- #
# LLM inference "reasoning proxy" markers (Figure 1 / §2.5 / Appendix D.4).    #
# A non-GPU device POSTing to an OpenAI-compatible endpoint = the worm routing #
# its reasoning to a compromised GPU host.                                     #
# --------------------------------------------------------------------------- #
INFERENCE_PORTS: frozenset[int] = frozenset({8000, 8001, 1234, 11434, 5001, 9000})
INFERENCE_PATH_MARKERS: tuple[str, ...] = (
    "/v1/chat/completions",
    "/v1/completions",
    "/v1/embeddings",
    "/v1/models",
    "/api/generate",
    "/api/chat",
    "/generate",
    "/completion",
    "/infer",
)
INFERENCE_HOST_MARKERS: tuple[str, ...] = (
    "llm", "vllm", "ollama", "inference", "triton", "tgi", "gpu",
)

# --------------------------------------------------------------------------- #
# Worm propagation "stages" — the composite signature correlator fuses these   #
# per-device weak signals into a high-confidence AI-worm verdict.              #
# --------------------------------------------------------------------------- #
STAGE_RECON = "discovery"            # port/service scanning
STAGE_LATERAL = "lateral_movement"   # many internal peers
STAGE_EXPLOIT = "exploit_attempt"    # traffic to worm service ports
STAGE_CREDENTIAL = "credential_reuse"
STAGE_SSH_KEY = "ssh_key_injection"
STAGE_INFERENCE = "inference_proxy"  # reasoning routed to GPU host
STAGE_BEACON = "beacon_callback"
STAGE_REPLICATION = "idle_device_exec"

WORM_STAGES: tuple[str, ...] = (
    STAGE_RECON, STAGE_LATERAL, STAGE_EXPLOIT, STAGE_CREDENTIAL,
    STAGE_SSH_KEY, STAGE_INFERENCE, STAGE_BEACON, STAGE_REPLICATION,
)

# Human-readable paper reference attached to worm-signature alerts.
PAPER_REFERENCE = (
    "Guan et al., 'AI Agents Enable Adaptive Computer Worms', "
    "arXiv:2606.03811 (2026)"
)
