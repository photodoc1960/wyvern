# Security Policy

Wyvern is a defensive, passive, read-only network monitor. We take the security
of the tool itself — and of the people who run it — seriously.

## Supported versions

Wyvern is pre-1.0 and ships from `main`. Security fixes land on `main` and in the
next tagged release. Please run the latest release or `main`.

| Version | Supported |
| ------- | --------- |
| `0.1.x` | ✅ |
| `< 0.1` | ❌ |

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately via GitHub Security Advisories:
**<https://github.com/photodoc1960/wyvern/security/advisories/new>**

Include, as far as you can:

- a description of the issue and its impact;
- steps or a proof-of-concept to reproduce it;
- the Wyvern version / commit and your environment (OS, Python version);
- any suggested remediation.

We aim to acknowledge a report within **5 business days** and to provide a fix or
mitigation timeline after triage. We'll keep you updated through the advisory and
credit you in the release notes unless you prefer to remain anonymous.

## Scope

In scope:

- the Wyvern package, CLI, and web dashboard;
- the packaging/deploy artifacts (Dockerfile, systemd unit, installer).

Particularly valuable reports:

- any path by which Wyvern could be made to **transmit, modify, or act on** a
  device — this would break its core read-only invariant (see
  [`CONTRIBUTING.md`](CONTRIBUTING.md));
- dashboard issues (XSS, SSRF, auth bypass, info disclosure);
- parsing/decoder crashes or resource exhaustion from crafted packets;
- secret handling (the SMTP password must only come from the environment).

Out of scope:

- vulnerabilities in third-party dependencies (report those upstream; we'll bump
  the pin once a fix is available);
- findings that require root/local access the operator already has;
- the deliberately synthetic "worm" traffic produced by `wyvern simulate`.

## Operator note

Wyvern observes traffic and never sends packets, runs remote commands, or changes
device or network state. If you ever see it appear to do so, treat that as a
security report — it would be a violation of the tool's central guarantee.
