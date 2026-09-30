"""Shared indicator predicates over the worm-intelligence constants.

A single source of truth for "is this an inference endpoint?", "is this a worm
service port?", etc., used by both the device registry (to classify hosts) and
the detectors (to score traffic). Pure functions, no state.
"""

from __future__ import annotations

from .constants import (
    AUTH_PORTS,
    INFERENCE_HOST_MARKERS,
    INFERENCE_PATH_MARKERS,
    INFERENCE_PORTS,
    STANDARD_SERVICE_PORTS,
    WORM_SERVICE_PORTS,
)


def is_inference_endpoint(host: str | None, path: str | None, port: int) -> bool:
    """True if (host, path, port) looks like an OpenAI-compatible LLM endpoint."""
    return inference_confidence(host, path, port) > 0.0


# Path markers must land on a segment boundary. Naive substring matching made
# captive-portal probes (``/generate_204``) match the ``/generate`` marker and
# score as LLM inference — 342 CRITICAL false positives in a 41-day run (#38).
_PATH_BOUNDARY = ("/", "?", "#")


def _path_has_marker(path: str, marker: str) -> bool:
    """True if ``marker`` occurs in ``path`` as a complete path segment.

    A marker counts only when it ends at the end of the path or at a segment /
    query boundary, so ``/generate`` matches ``/generate``, ``/generate/stream``
    and ``/generate?x=1`` but not ``/generate_204``.
    """
    start = 0
    while True:
        found = path.find(marker, start)
        if found < 0:
            return False
        end = found + len(marker)
        if end == len(path) or path[end] in _PATH_BOUNDARY:
            return True
        start = found + 1


def inference_confidence(host: str | None, path: str | None, port: int) -> float:
    """A 0..1 confidence that this request targets an LLM inference service.

    A matching API *path* is the strongest signal; a known inference port or a
    host name like ``vllm``/``ollama`` reinforce it.
    """
    score = 0.0
    if path:
        p = path.lower()
        if any(_path_has_marker(p, marker) for marker in INFERENCE_PATH_MARKERS):
            score = max(score, 0.9)
    if port in INFERENCE_PORTS:
        score = max(score, 0.6)
    if host:
        h = host.lower()
        if any(marker in h for marker in INFERENCE_HOST_MARKERS):
            score = max(score, 0.55)
    return score


# Multicast-DNS service labels (RFC 6763). Service-discovery names embed UUIDs by
# design, so they always score high on entropy.
_MDNS_SERVICE_LABELS = ("_tcp.", "_udp.")


def is_mdns_name(name: str | None) -> bool:
    """True for a multicast-DNS name, which must never be scored as DGA.

    ``.local`` is reserved for mDNS (RFC 6762): it is resolved by link-local
    multicast on the LAN and never by a recursive resolver, so a high-entropy
    ``.local`` name cannot act as a C2 rendezvous. Treating these as
    algorithmically-generated domains produced 78% of all alerts in a 41-day live
    run (#40).
    """
    if not name:
        return False
    n = name.strip().lower().rstrip(".")
    if not n:
        return False
    if n == "local" or n.endswith(".local"):
        return True
    return any(label in n + "." for label in _MDNS_SERVICE_LABELS)


def is_worm_service_port(port: int) -> bool:
    return port in WORM_SERVICE_PORTS


def worm_service_label(port: int) -> str | None:
    entry = WORM_SERVICE_PORTS.get(port)
    return entry[0] if entry else None


def worm_service_note(port: int) -> str | None:
    entry = WORM_SERVICE_PORTS.get(port)
    return entry[2] if entry else None


def is_auth_port(port: int) -> bool:
    return port in AUTH_PORTS


def auth_service(port: int) -> str | None:
    return AUTH_PORTS.get(port)


def is_nonstandard_port(port: int) -> bool:
    """True for ports outside the well-known set (beacon callback candidates)."""
    return port not in STANDARD_SERVICE_PORTS
