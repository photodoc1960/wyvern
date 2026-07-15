"""Builds the default detector set and the worm-signature correlator."""

from __future__ import annotations

from ..config import Config
from .base import Detector
from .beacon import BeaconDetector
from .credential_spray import CredentialSprayDetector
from .dns_anomaly import DnsAnomalyDetector
from .idle_exec import IdleDeviceExecDetector
from .inference_api import InferenceApiDetector
from .lateral_movement import LateralMovementDetector
from .port_scan import PortScanDetector
from .ssh_key_injection import SshKeyInjectionDetector
from .stream_timing import StreamTimingDetector
from .worm_signature import WormSignatureCorrelator


def default_detectors(config: Config) -> list[Detector]:
    """The per-stage detectors, in a sensible evaluation order."""
    return [
        PortScanDetector(config),
        LateralMovementDetector(config),
        CredentialSprayDetector(config),
        SshKeyInjectionDetector(config),
        InferenceApiDetector(config),
        IdleDeviceExecDetector(config),
        BeaconDetector(config),
        DnsAnomalyDetector(config),
        StreamTimingDetector(config),
    ]


def make_correlator(config: Config) -> WormSignatureCorrelator:
    return WormSignatureCorrelator(config)
