"""Shannon entropy and a lightweight DGA / random-domain heuristic.

The DNS-anomaly detector uses this to flag queries to algorithmically generated
or otherwise unusual domains — a softer signal than the worm's hard signatures
but useful for surfacing command-and-control lookups.
"""

from __future__ import annotations

import math
from collections import Counter

_VOWELS = set("aeiou")


def shannon_entropy(text: str) -> float:
    """Bits of Shannon entropy of the character distribution of ``text``."""
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def longest_label(domain: str) -> str:
    """The longest dot-separated label, ignoring a trailing public-ish suffix.

    We deliberately avoid a full public-suffix list (no network/dep); for DGA
    detection the longest label is a good proxy for the random component.
    """
    labels = [l for l in domain.strip(".").split(".") if l]
    if not labels:
        return ""
    # Drop an obvious final TLD label so "x7f3q9zk.com" scores on "x7f3q9zk".
    if len(labels) >= 2 and len(labels[-1]) <= 4:
        candidates = labels[:-1]
    else:
        candidates = labels
    return max(candidates, key=len)


def digit_ratio(text: str) -> float:
    if not text:
        return 0.0
    return sum(ch.isdigit() for ch in text) / len(text)


def vowel_ratio(text: str) -> float:
    letters = [ch for ch in text.lower() if ch.isalpha()]
    if not letters:
        return 0.0
    return sum(ch in _VOWELS for ch in letters) / len(letters)


def dga_score(domain: str) -> float:
    """A 0..1 'looks algorithmically generated' score for ``domain``.

    Combines entropy of the longest label, an unusually low vowel ratio, and a
    high digit ratio. Tuned to stay quiet on ordinary domains (google.com,
    cdn.example.net) and speak up on random strings (kq3z9x1m7wp.net).
    """
    label = longest_label(domain.lower())
    if len(label) < 7:
        return 0.0
    ent = shannon_entropy(label)
    # Normalise entropy: ~log2(len) is the max; random ~>3.2 bits for len>=8.
    ent_score = max(0.0, min(1.0, (ent - 2.8) / 1.4))
    vlow = 1.0 if vowel_ratio(label) < 0.30 else 0.0
    dhigh = min(1.0, digit_ratio(label) / 0.40)
    length_boost = min(1.0, (len(label) - 7) / 18.0)
    score = 0.55 * ent_score + 0.2 * vlow + 0.15 * dhigh + 0.10 * length_boost
    return round(min(1.0, score), 3)


def looks_like_dga(domain: str, threshold: float = 0.62) -> bool:
    return dga_score(domain) >= threshold
