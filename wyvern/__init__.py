"""Wyvern — a passive, read-only home-network worm sentinel.

Wyvern observes internal network traffic (ARP, DNS, TCP/UDP flows), tracks every
device, learns a per-device behavioural baseline, and raises threat-scored alerts
when it sees the behavioural signatures of an AI-driven adaptive computer worm —
the "Toronto AI worm" characterised by Guan et al., *AI Agents Enable Adaptive
Computer Worms* (arXiv:2606.03811).

Design axioms (enforced throughout the codebase):

* **Passive & read-only.** Wyvern only ever *captures*, *analyses*, *alerts*, and
  *recommends*. It never modifies a device, kills a process, deletes a file, or
  changes a network setting or credential. Every remediation is a manual
  suggestion that requires explicit user action.
* **Immutable domain models.** Events, devices, alerts and baseline profiles are
  frozen dataclasses; updates return new copies rather than mutating in place.
* **Small, cohesive modules.** Capture, decoding, tracking, detection, baseline,
  assessment, storage, alerting, engine and web are independent layers.
"""

from __future__ import annotations

__version__ = "0.1.0"
__all__ = ["__version__"]
