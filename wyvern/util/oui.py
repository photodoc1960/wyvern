"""MAC OUI -> vendor lookup and a vendor -> device-role hint.

A compact, curated built-in table covers vendors common on home networks. It is
deliberately small; an installation can merge a full IEEE OUI registry at
runtime via :func:`load_oui_file`. Role hints feed passive device-role
classification (printers/cameras/NAS/routers are "normally idle" and therefore
high-signal when they suddenly run code — the worm's replication targets).
"""

from __future__ import annotations

from .nets import normalize_mac

# Role hint strings intentionally match wyvern.models.device.DeviceRole values.
_BUILTIN_OUI: dict[str, tuple[str, str]] = {
    # prefix (6 hex, upper) -> (vendor, role-hint)
    # --- computers / phones ---
    "001451": ("Apple", "phone"),
    "3C0754": ("Apple", "phone"),
    "F0DBE2": ("Apple", "phone"),
    "A4D1D2": ("Apple", "phone"),
    "AC87A3": ("Apple", "phone"),
    "001422": ("Dell", "workstation"),
    "B8CA3A": ("Dell", "workstation"),
    "180373": ("Dell", "workstation"),
    "F8BC12": ("Dell", "workstation"),
    "0021CC": ("Lenovo", "workstation"),
    "8C1645": ("Lenovo", "workstation"),
    "001B21": ("Intel", "workstation"),
    "3C970E": ("Intel", "workstation"),
    "94659C": ("Intel", "workstation"),
    "002185": ("Micro-Star MSI", "workstation"),
    "D43D7E": ("Micro-Star MSI", "workstation"),
    "1C872C": ("ASUSTek", "workstation"),
    "2C56DC": ("ASUSTek", "workstation"),
    "0012FB": ("Samsung", "phone"),
    "5C0A5B": ("Samsung", "phone"),
    "8C7712": ("Samsung", "phone"),
    "3423BA": ("Samsung", "phone"),
    # --- GPU / compute (the worm's reasoning hosts) ---
    "00044B": ("NVIDIA", "gpu_host"),
    "48B02D": ("NVIDIA", "gpu_host"),
    "04D9F5": ("NVIDIA", "gpu_host"),
    # --- routers / network gear ---
    "24A43C": ("Ubiquiti", "router"),
    "802AA8": ("Ubiquiti", "router"),
    "FCECDA": ("Ubiquiti", "router"),
    "687251": ("Ubiquiti", "router"),
    "00095B": ("Netgear", "router"),
    "204E7F": ("Netgear", "router"),
    "2C3033": ("Netgear", "router"),
    "50C7BF": ("TP-Link", "router"),
    "14CC20": ("TP-Link", "router"),
    "EC086B": ("TP-Link", "router"),
    "001B0C": ("Cisco", "router"),
    "F4CFE2": ("Cisco", "router"),
    "00180A": ("Cisco Meraki", "router"),
    # --- NAS ---
    "001132": ("Synology", "nas"),
    "245EBE": ("QNAP", "nas"),
    "00089B": ("QNAP", "nas"),
    "0090A9": ("Western Digital", "nas"),
    "0014EE": ("Western Digital", "nas"),
    # --- printers ---
    "008077": ("Brother", "printer"),
    "30055C": ("Brother", "printer"),
    "001E8F": ("Canon", "printer"),
    "2C9EFC": ("Canon", "printer"),
    "000048": ("Seiko Epson", "printer"),
    "64EB8C": ("Seiko Epson", "printer"),
    "000400": ("Lexmark", "printer"),
    "00074D": ("Zebra", "printer"),
    "001B78": ("HP Printer", "printer"),
    "9457A5": ("HP Printer", "printer"),
    # --- cameras ---
    "4419B6": ("Hikvision", "camera"),
    "C0560E": ("Hikvision", "camera"),
    "BCAD28": ("Hikvision", "camera"),
    "3CE36B": ("Dahua", "camera"),
    "9002A9": ("Dahua", "camera"),
    "00408C": ("Axis", "camera"),
    "ACCC8E": ("Axis", "camera"),
    # --- IoT / smart home / ICS ---
    "B827EB": ("Raspberry Pi", "iot"),
    "DCA632": ("Raspberry Pi", "iot"),
    "E45F01": ("Raspberry Pi", "iot"),
    "28CDC1": ("Raspberry Pi", "iot"),
    "240AC4": ("Espressif", "iot"),
    "3C71BF": ("Espressif", "iot"),
    "8CAAB5": ("Espressif", "iot"),
    "A4CF12": ("Espressif", "iot"),
    "3C5AB4": ("Google Nest", "iot"),
    "1CF29A": ("Google Nest", "iot"),
    "0C47C9": ("Amazon", "iot"),
    "44650D": ("Amazon", "iot"),
    "FC65DE": ("Amazon", "iot"),
    "000E8C": ("Siemens", "iot"),
    "001B1B": ("Siemens", "iot"),
    "0080F4": ("Schneider Electric", "iot"),
    "004084": ("Honeywell", "iot"),
}

# Runtime-mergeable extension table (e.g. loaded from an IEEE OUI registry).
_EXT_OUI: dict[str, tuple[str, str | None]] = {}


def _prefix(mac: str | None) -> str | None:
    norm = normalize_mac(mac)
    if norm is None:
        return None
    return norm.replace(":", "")[:6].upper()


def lookup_vendor(mac: str | None) -> str | None:
    """Return the vendor name for ``mac``'s OUI, or ``None`` if unknown."""
    pfx = _prefix(mac)
    if pfx is None:
        return None
    if pfx in _EXT_OUI:
        return _EXT_OUI[pfx][0]
    entry = _BUILTIN_OUI.get(pfx)
    return entry[0] if entry else None


def role_hint(mac: str | None) -> str | None:
    """Return a device-role hint derived from the OUI, or ``None``."""
    pfx = _prefix(mac)
    if pfx is None:
        return None
    if pfx in _EXT_OUI:
        return _EXT_OUI[pfx][1]
    entry = _BUILTIN_OUI.get(pfx)
    return entry[1] if entry else None


def is_locally_administered(mac: str | None) -> bool:
    """True if the MAC is locally administered / randomised (privacy MAC).

    A randomised MAC has the second-least-significant bit of the first octet
    set; such devices won't match an OUI and are treated as unknown-vendor.
    """
    norm = normalize_mac(mac)
    if norm is None:
        return False
    first = int(norm.split(":")[0], 16)
    return bool(first & 0x02)


def load_oui_file(path: str) -> int:
    """Merge an IEEE-style OUI registry. Returns the number of entries added.

    Accepts lines of the form ``AABBCC<sep>Vendor Name`` (Wireshark ``manuf``
    format) or the classic IEEE ``AA-BB-CC   (hex)   Vendor`` format. Vendors
    are stored without role hints (``None``); the built-in table still supplies
    role hints for known consumer brands.
    """
    added = 0
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                pfx, vendor = _parse_oui_line(line)
                if pfx and vendor:
                    _EXT_OUI[pfx] = (vendor, role_hint_for_vendor(vendor))
                    added += 1
    except OSError:
        return 0
    return added


def role_hint_for_vendor(vendor: str) -> str | None:
    """Best-effort role from a free-text vendor name (used when merging files)."""
    v = vendor.lower()
    table = (
        (("synology", "qnap", "western digital", "netgear readynas"), "nas"),
        (("hikvision", "dahua", "axis comm", "reolink", "amcrest"), "camera"),
        (("brother", "canon", "epson", "lexmark", "zebra", "xerox", "kyocera"), "printer"),
        (("ubiquiti", "netgear", "tp-link", "cisco", "mikrotik", "aruba"), "router"),
        (("raspberry", "espressif", "nest", "amazon tech", "tuya", "sonos"), "iot"),
        (("nvidia",), "gpu_host"),
        (("apple", "samsung", "xiaomi", "huawei", "oneplus", "google"), "phone"),
        (("dell", "lenovo", "intel", "asustek", "micro-star", "gigabyte"), "workstation"),
    )
    for needles, role in table:
        if any(n in v for n in needles):
            return role
    return None


def _parse_oui_line(line: str) -> tuple[str | None, str | None]:
    # Wireshark manuf: "AA:BB:CC\tShortName\tLong Name"
    if "\t" in line:
        head, _, rest = line.partition("\t")
        pfx = head.replace(":", "").replace("-", "").upper()[:6]
        vendor = rest.split("\t")[-1].strip() or rest.strip()
        return (pfx if len(pfx) == 6 else None, vendor or None)
    # IEEE: "AA-BB-CC   (hex)   Vendor Name"
    parts = line.split()
    if parts and "-" in parts[0]:
        pfx = parts[0].replace("-", "").upper()[:6]
        idx = 2 if len(parts) > 2 and parts[1].lower().strip("()") == "hex" else 1
        vendor = " ".join(parts[idx:]).strip()
        return (pfx if len(pfx) == 6 else None, vendor or None)
    return (None, None)
