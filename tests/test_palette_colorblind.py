"""The severity palette must stay legible with red/green colour blindness.

The original palette paired ``--none: #3fb950`` (green) with
``--critical: #f85149`` (red) — the classic confusion pair. Simulated under
deuteranopia those two differ by only **dE 8.2**, i.e. "all clear" and "CRITICAL"
are perceptually near-identical on a security dashboard. The three warm levels
(amber/orange/red) collapsed similarly.

This test enforces measurable separation rather than taste: it parses the palette
out of the stylesheet, simulates dichromacy with the Machado (2009) matrices, and
asserts a minimum CIELAB separation between every pair of severity levels. It also
guards against the palette being duplicated in JavaScript, which is how the
topology graph originally kept rendering the old colours after the CSS was fixed.
"""

from __future__ import annotations

import itertools
import math
import re
from pathlib import Path

WEB = Path(__file__).resolve().parents[1] / "wyvern" / "web"
LEVELS = ("none", "low", "medium", "high", "critical")

# Machado et al. (2009), severity 1.0 — applied to linear RGB.
DICHROMAT = {
    "deuteranopia": (
        (0.367322, 0.860646, -0.227968),
        (0.280085, 0.672501, 0.047413),
        (-0.011820, 0.042940, 0.968881),
    ),
    "protanopia": (
        (0.152286, 1.052583, -0.204868),
        (0.114503, 0.786281, 0.099216),
        (-0.003882, -0.048116, 1.051998),
    ),
}

# Minimum CIELAB separation. 2.3 is a just-noticeable difference; these are large
# patches, so we demand a comfortable margin.
MIN_PAIR_DE = 15.0
MIN_NONE_VS_CRITICAL_DE = 25.0


def _srgb_to_linear(c: float) -> float:
    return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4


def _hex_to_linear(value: str) -> tuple[float, float, float]:
    h = value.lstrip("#")
    return tuple(_srgb_to_linear(int(h[i : i + 2], 16) / 255) for i in (0, 2, 4))


def _simulate(rgb: tuple[float, float, float], matrix) -> tuple[float, ...]:
    return tuple(sum(matrix[i][j] * rgb[j] for j in range(3)) for i in range(3))


def _lab(rgb: tuple[float, ...]) -> tuple[float, float, float]:
    r, g, b = (max(0.0, min(1.0, c)) for c in rgb)
    x = (0.4124 * r + 0.3576 * g + 0.1805 * b) / 0.95047
    y = 0.2126 * r + 0.7152 * g + 0.0722 * b
    z = (0.0193 * r + 0.1192 * g + 0.9505 * b) / 1.08883
    f = lambda t: t ** (1 / 3) if t > 0.008856 else 7.787 * t + 16 / 116  # noqa: E731
    fx, fy, fz = f(x), f(y), f(z)
    return (116 * fy - 16, 500 * (fx - fy), 200 * (fy - fz))


def _palette() -> dict[str, str]:
    css = (WEB / "static" / "style.css").read_text()
    found = {}
    for level in LEVELS:
        m = re.search(rf"--{level}:\s*(#[0-9a-fA-F]{{6}})", css)
        assert m, f"--{level} not found in style.css"
        found[level] = m.group(1)
    return found


def test_severity_levels_are_separable_for_dichromats():
    pal = _palette()
    for mode, matrix in DICHROMAT.items():
        seen = {lvl: _simulate(_hex_to_linear(pal[lvl]), matrix) for lvl in LEVELS}
        for a, b in itertools.combinations(LEVELS, 2):
            de = math.dist(_lab(seen[a]), _lab(seen[b]))
            assert de >= MIN_PAIR_DE, (
                f"{mode}: '{a}' ({pal[a]}) and '{b}' ({pal[b]}) are only dE {de:.1f} "
                f"apart; need >= {MIN_PAIR_DE}"
            )


def test_clear_and_critical_are_unmistakable_for_dichromats():
    """The safety-critical pair: 'nothing wrong' must never resemble 'CRITICAL'."""
    pal = _palette()
    for mode, matrix in DICHROMAT.items():
        none = _lab(_simulate(_hex_to_linear(pal["none"]), matrix))
        crit = _lab(_simulate(_hex_to_linear(pal["critical"]), matrix))
        de = math.dist(none, crit)
        assert de >= MIN_NONE_VS_CRITICAL_DE, (
            f"{mode}: none ({pal['none']}) vs critical ({pal['critical']}) is only "
            f"dE {de:.1f}; need >= {MIN_NONE_VS_CRITICAL_DE}"
        )


def test_palette_is_not_duplicated_in_javascript():
    """The graph must read the CSS custom properties, not its own copy.

    A hardcoded second palette in app.js is why the topology kept rendering the old
    red/green scheme even after the stylesheet was corrected.
    """
    js = (WEB / "static" / "app.js").read_text()
    hexes = re.findall(r"#[0-9a-fA-F]{6}", js)
    palette_values = set(_palette().values())
    leaked = sorted(set(hexes) & palette_values)
    assert not leaked, f"app.js hardcodes severity colours {leaked}; read CSS vars instead"
