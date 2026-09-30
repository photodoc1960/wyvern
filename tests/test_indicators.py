"""Tests for the shared indicator predicates."""

from __future__ import annotations

from wyvern.indicators import (
    auth_service,
    inference_confidence,
    is_auth_port,
    is_inference_endpoint,
    is_nonstandard_port,
    is_worm_service_port,
    worm_service_label,
)


def test_inference_endpoint_by_path():
    assert is_inference_endpoint("anything", "/v1/chat/completions", 443)
    assert inference_confidence(None, "/v1/completions", 12345) >= 0.9


def test_inference_endpoint_by_port_and_host():
    assert is_inference_endpoint(None, None, 8000)  # vLLM port
    assert is_inference_endpoint(None, None, 11434)  # ollama
    assert is_inference_endpoint("ollama-box", "/", 9999)
    assert not is_inference_endpoint("example.com", "/index.html", 443)


def test_worm_service_ports():
    assert is_worm_service_port(445)
    assert worm_service_label(445) == "smb"
    assert worm_service_label(2375) == "docker-api"
    assert not is_worm_service_port(12345)


def test_auth_ports():
    assert is_auth_port(22) and auth_service(22) == "ssh"
    assert is_auth_port(3389) and auth_service(3389) == "rdp"
    assert not is_auth_port(80)


def test_nonstandard_ports():
    assert is_nonstandard_port(4444)
    assert not is_nonstandard_port(443)
    assert not is_nonstandard_port(53)


def test_captive_portal_probe_is_not_inference():
    """Regression (#38): ``/generate_204`` must not match the ``/generate`` marker.

    Apple/Android captive-portal detection fetches ``GET /generate_204``. Naive
    substring matching scored it 0.9 ("strongest signal") and produced 342
    CRITICAL false positives in a 41-day live run.
    """
    assert inference_confidence("captive.apple.com", "/generate_204", 80) == 0.0
    assert not is_inference_endpoint("captive.apple.com", "/generate_204", 80)
    assert not is_inference_endpoint("connectivitycheck.gstatic.com", "/generate_204", 80)


def test_inference_paths_match_on_segment_boundaries():
    # Real endpoints must still score as inference.
    assert inference_confidence(None, "/generate", 9999) >= 0.9
    assert inference_confidence(None, "/api/generate", 9999) >= 0.9
    assert inference_confidence(None, "/api/chat", 9999) >= 0.9
    assert inference_confidence(None, "/v1/chat/completions", 9999) >= 0.9
    assert inference_confidence(None, "/v1/chat/completions?stream=true", 9999) >= 0.9
    assert inference_confidence(None, "/generate/stream", 9999) >= 0.9
    # Near-misses on the short, generic markers must not.
    assert inference_confidence(None, "/generate_204", 9999) == 0.0
    assert inference_confidence(None, "/inference-docs", 9999) == 0.0
    assert inference_confidence(None, "/completions-guide", 9999) == 0.0
