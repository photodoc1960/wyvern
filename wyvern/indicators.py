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


def inference_confidence(host: str | None, path: str | None, port: int) -> float:
    """A 0..1 confidence that this request targets an LLM inference service.

    A matching API *path* is the strongest signal; a known inference port or a
    host name like ``vllm``/``ollama`` reinforce it.
    """
    score = 0.0
    if path:
        p = path.lower()
        if any(marker in p for marker in INFERENCE_PATH_MARKERS):
            score = max(score, 0.9)
    if port in INFERENCE_PORTS:
        score = max(score, 0.6)
    if host:
        h = host.lower()
        if any(marker in h for marker in INFERENCE_HOST_MARKERS):
            score = max(score, 0.55)
    return score


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
