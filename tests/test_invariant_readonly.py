"""Guards Wyvern's core invariant: the tool is **passive and read-only**.

Wyvern observes, alerts, and recommends. It must never transmit packets, run
shell commands that touch the host or network, or otherwise act on a device.
``CONTRIBUTING.md`` states this rule in prose; this test enforces it on every
commit so a well-meaning change can't quietly cross the line.

If a contribution legitimately needs one of the patterns below, that is a design
decision worth a human's eyes: add an inline ``# invariant-ok: <reason>`` comment
on the offending line and explain it in the PR. The scanner honours that marker,
so the escape hatch is explicit and reviewable rather than silent.
"""

from __future__ import annotations

import re
from pathlib import Path

WYVERN_SRC = Path(__file__).resolve().parent.parent / "wyvern"

# Explicit, reviewable escape hatch — see module docstring.
ALLOW_MARKER = "invariant-ok"

# (regex, human reason). Each pattern describes an *active* capability Wyvern
# must not have. Read-only helpers that happen to share a module (e.g.
# ``socket.inet_ntop`` for formatting, ``sqlite3.connect`` for the local DB) are
# deliberately NOT matched.
FORBIDDEN = [
    # Active packet injection via scapy.
    (r"\bsendp?fast\(", "scapy packet injection (sendpfast)"),
    (r"\bsendp\(", "scapy layer-2 packet injection (sendp)"),
    (r"(?<![A-Za-z0-9_])send\(", "raw/scapy packet transmit (send)"),
    (r"\bsr\(", "scapy send-and-receive (sr)"),
    (r"\bsr1\(", "scapy send-and-receive (sr1)"),
    (r"\bsrp1?\(", "scapy send-and-receive at layer 2 (srp/srp1)"),
    # Raw socket transmit.
    (r"\.sendall\(", "socket transmit (sendall)"),
    (r"\.sendto\(", "socket transmit (sendto)"),
    (r"SOCK_RAW", "raw socket creation"),
    # Arbitrary host command execution.
    (r"\bos\.system\(", "shell command execution (os.system)"),
    (r"\bos\.popen\(", "shell command execution (os.popen)"),
    (r"\bpty\.spawn\(", "pseudo-terminal spawn (pty.spawn)"),
    (r"(?<![A-Za-z0-9_.])eval\(", "dynamic code evaluation (eval)"),
    (r"(?<![A-Za-z0-9_.])exec\(", "dynamic code execution (exec)"),
    # Shell-interpreted subprocess.
    (r"shell\s*=\s*True", "subprocess with shell=True"),
]

# scapy transmit symbols that must never be imported.
SCAPY_TRANSMIT_IMPORTS = {"send", "sendp", "sendpfast", "sr", "sr1", "srp", "srp1"}

# The ONLY subprocess invocation Wyvern is allowed to make: a desktop
# notification via notify-send (list form, no shell). Any other use is a finding.
ALLOWED_SUBPROCESS_HINT = "notify-send"


def _source_files() -> list[Path]:
    return sorted(WYVERN_SRC.rglob("*.py"))


def test_source_tree_exists() -> None:
    assert _source_files(), "no wyvern/*.py sources found — wrong path?"


def test_no_active_or_exec_calls() -> None:
    """No transmit / shell-exec primitives anywhere in the package."""
    findings: list[str] = []
    for path in _source_files():
        for lineno, line in enumerate(path.read_text().splitlines(), start=1):
            if ALLOW_MARKER in line:
                continue
            for pattern, reason in FORBIDDEN:
                if re.search(pattern, line):
                    rel = path.relative_to(WYVERN_SRC.parent)
                    findings.append(f"{rel}:{lineno}: {reason} -> {line.strip()}")
    assert not findings, (
        "Read-only invariant violated — Wyvern must only observe, never act:\n  "
        + "\n  ".join(findings)
    )


def test_scapy_is_capture_only() -> None:
    """scapy may be imported for sniffing, never for transmitting."""
    import_re = re.compile(r"from\s+scapy[.\w]*\s+import\s+(.+)")
    findings: list[str] = []
    for path in _source_files():
        for lineno, line in enumerate(path.read_text().splitlines(), start=1):
            if ALLOW_MARKER in line:
                continue
            m = import_re.search(line)
            if not m:
                continue
            imported = {tok.strip().split(" as ")[0] for tok in m.group(1).split(",")}
            bad = imported & SCAPY_TRANSMIT_IMPORTS
            if bad:
                rel = path.relative_to(WYVERN_SRC.parent)
                findings.append(f"{rel}:{lineno}: imports scapy transmit {sorted(bad)}")
    assert not findings, "scapy transmit primitives imported:\n  " + "\n  ".join(findings)


def test_subprocess_only_for_desktop_notification() -> None:
    """Subprocess spawns are confined to the notify-send call and explicitly
    reviewed exceptions marked ``invariant-ok`` (e.g. the gated, off-by-default
    Tier-1 firewall responder, #29).

    Only process-*spawning* calls are findings — bare attribute references such
    as ``subprocess.DEVNULL`` or ``except subprocess.SubprocessError`` don't run
    anything, so they are intentionally ignored.
    """
    spawn_re = re.compile(
        r"subprocess\.(run|Popen|call|check_call|check_output|getoutput|getstatusoutput)\("
    )
    findings: list[str] = []
    for path in _source_files():
        text = path.read_text()
        if "subprocess" not in text:
            continue
        lines = text.splitlines()
        for lineno, line in enumerate(lines, start=1):
            if not spawn_re.search(line) or ALLOW_MARKER in line:
                continue
            # argv may sit on the next line; allow only if notify-send is nearby.
            window = "\n".join(lines[max(0, lineno - 1) : lineno + 4])
            if ALLOWED_SUBPROCESS_HINT in window:
                continue
            rel = path.relative_to(WYVERN_SRC.parent)
            findings.append(f"{rel}:{lineno}: {line.strip()}")
    assert not findings, (
        "Unexpected subprocess spawn (only notify-send is allowed):\n  " + "\n  ".join(findings)
    )
