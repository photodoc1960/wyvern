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
