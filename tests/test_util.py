"""Tests for the utility layer: nets, sliding windows, entropy, OUI."""

from __future__ import annotations

import pytest

from wyvern.util import oui
from wyvern.util.entropy import dga_score, looks_like_dga, shannon_entropy
from wyvern.util.nets import (
    is_internal_ip,
    is_usable_host_ip,
    normalize_mac,
)
from wyvern.util.timewindow import (
    KeyedWindows,
    SlidingWindow,
    coefficient_of_variation,
    intervals,
)


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("AA-BB-CC-DD-EE-FF", "aa:bb:cc:dd:ee:ff"),
        ("aabb.ccdd.eeff", "aa:bb:cc:dd:ee:ff"),
        (b"\xaa\xbb\xcc\xdd\xee\xff", "aa:bb:cc:dd:ee:ff"),
        ("not-a-mac", None),
        (None, None),
    ],
)
def test_normalize_mac(raw, expected):
    assert normalize_mac(raw) == expected


def test_internal_and_usable_ip():
    assert is_internal_ip("192.168.1.5")
    assert is_internal_ip("10.0.0.9")
    assert not is_internal_ip("8.8.8.8")
    assert not is_internal_ip("garbage")
    assert is_usable_host_ip("192.168.1.5")
    assert not is_usable_host_ip("255.255.255.255")
    assert not is_usable_host_ip("224.0.0.1")  # multicast
    assert not is_usable_host_ip("127.0.0.1")  # loopback


def test_custom_cidrs():
    assert is_internal_ip("172.20.0.1", ("172.20.0.0/16",))
    assert not is_internal_ip("192.168.1.1", ("172.20.0.0/16",))


def test_sliding_window_evicts():
    w = SlidingWindow(10)
    for t in range(0, 12):
        w.add(float(t), t)
    # at t=11, window covers (1, 11] -> values >= 1
    assert w.count(11.0) == 11
    assert 0 not in w.items(11.0)
    assert w.distinct_count(11.0) == 11


def test_keyed_windows():
    kw = KeyedWindows(5)
    kw.add("a", 0.0, "x")
    kw.add("a", 1.0, "y")
    kw.add("b", 1.0, "z")
    assert kw.get("a").distinct_count(1.0) == 2
    kw.prune(100.0)
    assert kw.get("a").is_empty(100.0)


def test_cov_and_intervals():
    assert coefficient_of_variation([5, 5, 5, 5]) == 0.0
    assert coefficient_of_variation([1]) is None
    assert intervals([0, 60, 120, 180]) == [60, 60, 60]
    jittery = coefficient_of_variation([10, 90, 5, 200])
    assert jittery and jittery > 0.5


def test_entropy_and_dga():
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("abcd") == 2.0
    assert looks_like_dga("kq3z9x1m7wp4t")
    assert not looks_like_dga("google")
    assert dga_score("google.com") < 0.4
    assert dga_score("x7f3q9zk1mwp.net") > 0.6


def test_oui_lookup_and_roles():
    assert oui.lookup_vendor("00:80:77:11:22:33") == "Brother"
    assert oui.role_hint("00:80:77:11:22:33") == "printer"
    assert oui.lookup_vendor("00:04:4b:aa:bb:cc") == "NVIDIA"
    assert oui.role_hint("00:04:4b:aa:bb:cc") == "gpu_host"
    assert oui.lookup_vendor("de:ad:be:ef:00:01") is None
    assert oui.is_locally_administered("02:00:00:00:00:01")
    assert not oui.is_locally_administered("00:80:77:11:22:33")


def test_oui_file_merge(tmp_path):
    f = tmp_path / "manuf"
    f.write_text("AC:DE:48\tPrivate\tPrivate Vendor\n# comment\n")
    added = oui.load_oui_file(str(f))
    assert added == 1
    assert oui.lookup_vendor("ac:de:48:00:00:01") == "Private Vendor"
