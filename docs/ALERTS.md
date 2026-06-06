# What Wyvern's alerts mean — and what to do

Every alert carries a **severity**, a **confidence**, the **device** involved, and
**manual remediation steps**. Wyvern never acts; you do. Start here when
something fires.

## Severity & the threat banner

| Level | Meaning | Urgency |
|---|---|---|
| 🟢 Low | minor anomaly / single soft signal | watch |
| 🟡 Medium | suspicious, worth a look | investigate when convenient |
| 🟠 High | strong single signal **or** 2 worm stages on one device | investigate now |
| 🔴 Critical | confirmed worm-grade behaviour / 3+ stages | **isolate & investigate immediately** |

The dashboard banner shows the **overall** level and the **likely-compromised
device**. A 🔴 banner naming a device is your top priority.

## 🚨 The one that matters most: "Toronto AI worm signature"

**What it means:** one device showed **multiple** worm propagation stages
(scan + lateral + credential reuse + …) within an hour. This is the composite
verdict; it is rarely a false positive.

**Do this, in order:**
1. **Isolate** the named device — unplug it, disable its Wi-Fi, or block it at the
   router/AP. (Capture evidence first if you can.)
2. **Run a process / anti-malware scan** on it; look for unexpected agents,
   Python/LLM runtimes, or new scheduled tasks/services.
3. **Check its recent connections and auth logs.**
4. **Change credentials** on every host it contacted, and rotate shared SSH keys.
5. Only then **reboot/re-image** — note a reboot may not remove persistence.

## Per-alert playbook

| Alert | What it suggests | Common benign causes (false positives) | What to do |
|---|---|---|---|
| **Outbound port scan** | a host is mapping services | vuln scanners you run (Nessus/nmap), some backup/discovery tools | Confirm you didn't start a scan; if not, treat the host as suspect. |
| **Lateral movement** | one host → many internal hosts | backup servers, monitoring/NMS, a media server, mDNS-heavy apps | Check the *role* — a printer/camera doing this is far worse than your NAS. |
| **Credential reuse across hosts** | same creds tried on many hosts | config-management (Ansible), an admin's jump box | Expected only from known admin tooling; otherwise rotate creds + isolate. |
| **Repeated auth attempts** | failed-login / brute pattern | a wrong saved password, a flapping mount | Fix the bad credential, or treat as attack if unexplained. |
| **SSH key/credential propagation** | worm seeding keys across Linux hosts | a dev who SSHes everywhere | Check `~/.ssh/authorized_keys` on the targets for unknown keys. |
| **Inference/GPU API query from non-GPU device** | a printer/camera/IoT is proxying LLM reasoning | almost none — IoT devices don't call LLM APIs | High-signal. Isolate the device and scan it. Declare real GPU hosts in config. |
| **Beacon callback on non-standard port** | automated C2 check-in | some apps poll on odd ports at fixed intervals | Identify the destination; block it at the firewall if it's not legitimate. |
| **Code execution on idle device** | a printer/router/NAS/camera is running code | firmware update checks, cloud-connected appliances phoning home | If it's contacting *other LAN hosts* or worm ports, treat as compromised. |
| **DNS query spike / NXDOMAIN burst / DGA domain** | possible C2 rendezvous | misconfigured app retry loops, ad/tracker churn | Review the domains; block confirmed-bad ones at your resolver. |

## Reducing false positives

- **Declare your `gpu_hosts`** so PCs that legitimately run local LLMs don't trip
  the inference detector.
- **Let the 24-hour baseline finish** — deviation-based scoring then knows each
  device's normal and quiets routine fan-out (your NAS, your NMS).
- **Tune thresholds** in `config.yaml` for your environment.
- **Mark a noisy-but-known device** as not-suspicious; flag genuinely odd ones as
  suspicious for closer watching.

Found a false positive? Please open a
[GitHub Discussion](https://github.com/photodoc1960/wyvern/discussions) with the
alert details — it helps us tune the defaults for everyone.

## Forensics & evidence

- **Export** a JSON/CSV bundle from the dashboard or `wyvern export out.json`.
- The append-only `events.jsonl` is a tamper-evident timeline you can grep.
- The SQLite DB (`wyvern.db`) holds all devices and alerts for later analysis.
