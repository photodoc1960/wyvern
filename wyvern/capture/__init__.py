"""Packet capture (scapy, live) and frame decoding (dpkt, analysis).

The division of labour matches the brief: **scapy** acquires packets off the
wire; **dpkt** performs the structural analysis that turns raw frames into the
normalised events the detectors consume.
"""

from __future__ import annotations

from .decode import decode_frame

__all__ = ["decode_frame"]
