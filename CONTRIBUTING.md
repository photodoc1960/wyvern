# Contributing to Wyvern

Thanks for helping defend home networks against AI-driven worms. Wyvern is a
community blue-team tool — detection rules, fingerprints, and tuning all get
better with more eyes and more networks.

## Ground rules

Wyvern is and will remain **passive and read-only**. Contributions must never add
code that:

- transmits packets, actively probes, or scans;
- modifies, blocks, quarantines, kills, reboots, or reconfigures any device;
- changes credentials or network settings;
- automatically "responds" to a threat.

Wyvern **observes, alerts, and recommends.** That boundary is the whole point.

## Dev setup

```bash
git clone https://github.com/photodoc1960/wyvern.git
cd wyvern
pip install -e ".[dev,desktop]"
make lint          # ruff check + format check
make test          # 127 tests
make cov           # coverage (keep it ≥ 80%)
```

Optional but recommended — install the git hooks so lint/format run on commit:

```bash
pip install pre-commit && pre-commit install
make format        # auto-fix lint + format the whole tree
```

## Style

- **Immutability:** domain objects (events, alerts, devices, profiles) are frozen
  dataclasses; return copies, don't mutate. Detector counters may mutate.
- **Small, focused modules** (200–400 lines typical).
- **Handle untrusted input safely** — decoders return `[]` rather than raise.
- **Type hints**, clear names, comments that explain *why*.
- **Linting/formatting** is handled by [ruff](https://docs.astral.sh/ruff/);
  `make format` fixes most issues and `make lint` is enforced in CI.
- Run `make lint && make test` before opening a PR; add tests for new behaviour.

## Writing your own detector

Detection rules are the most valuable contribution. The architecture is built for
it. Here's a complete example — a detector for SMBv1 (EternalBlue) negotiation,
which the worm uses against Windows hosts.

**1. Create `wyvern/detectors/smbv1.py`:**

```python
from ..constants import STAGE_EXPLOIT
from ..models.alert import Alert, Severity
from ..models.events import ConnEvent, NetworkEvent
from ..util.timewindow import KeyedWindows
from .base import Cooldown, Detector, DetectorContext, clamp01, source_id


class SmbV1Detector(Detector):
    name = "smbv1"

    def __init__(self, config):
        super().__init__(config)
        self._hits = KeyedWindows(self.t.lateral_window_s)
        self._cool = Cooldown(self.t.lateral_window_s)

    def inspect(self, event: NetworkEvent, ctx: DetectorContext) -> list[Alert]:
        if not isinstance(event, ConnEvent) or not event.is_syn:
            return []
        if event.dst_port not in (139, 445) or not ctx.internal(event.src_ip):
            return []
        win = self._hits.add(source_id(event), event.ts, event.dst_ip)
        hosts = win.distinct(event.ts)
        if len(hosts) < 3 or not self._cool.fire(source_id(event), event.ts):
            return []
        device = ctx.device_for(event)
        conf = clamp01(0.5 + 0.1 * len(hosts))
        return [
            Alert(
                detector=self.name,
                title=f"SMB sweep to {len(hosts)} hosts (EternalBlue/SambaCry)",
                severity=Severity.from_confidence(conf),
                confidence=conf,
                stage=STAGE_EXPLOIT,
                description=f"{device.label if device else event.src_ip} probed SMB on "
                f"{len(hosts)} hosts — worm foothold attempt.",
                src_mac=device.mac if device else event.src_mac,
                src_ip=event.src_ip,
                ts=event.ts,
                evidence={"smb_targets": sorted(hosts)[:20]},
            )
        ]
```

**2. Register it in `wyvern/detectors/loader.py`** (add to the `default_detectors`
list).

**3. Add a test** `tests/test_smbv1.py` using the `feed` / `mk` fixtures:

```python
from wyvern.detectors.smbv1 import SmbV1Detector


def test_smb_sweep(config, feed, mk):
    det = SmbV1Detector(config)
    events = [
        mk.syn("192.168.1.50", f"192.168.1.{h}", 445, 1.0 + h, mac="00:14:22:00:00:50")
        for h in range(10, 14)
    ]
    assert feed(det, events)
```

Because the alert is tagged with a worm `stage` (`STAGE_EXPLOIT`), it **feeds the
composite `worm_signature` correlator automatically** — no extra wiring.

Detector checklist:
- [ ] One behaviour, one detector; tag the worm `stage` if applicable.
- [ ] Use `Cooldown` to debounce; use `KeyedWindows` for per-source counters.
- [ ] Confidence in `[0,1]`; let `Severity.from_confidence` set severity.
- [ ] Put actionable detail in `evidence`; keep `description` human-readable.
- [ ] Add a positive test, a below-threshold (quiet) test, and a negative test.
- [ ] Threshold knobs go in `config.Thresholds` with validation.

## Reporting false positives

False positives make the tool noisy and erode trust. If a benign device trips an
alert, please open a **[GitHub Discussion](https://github.com/photodoc1960/wyvern/discussions)**
(category: *False Positives*) with:

- the alert title, detector, and severity;
- the device role/vendor and what it actually does;
- a sanitised snippet of the alert `evidence` (redact public IPs if you like).

We use these to tune default thresholds and fingerprints. For reproducible bugs,
open an Issue instead.

## Threat-research contributions

New worm/CVE intelligence is welcome. To add a worm service port, update
`WORM_SERVICE_PORTS` in `wyvern/constants.py` with the port, host class and
CVE/CWE reference. To improve device fingerprints, extend `wyvern/util/oui.py` or
`wyvern/tracking/fingerprint.py`. Cite a public source in your PR.

## Releases

We aim for **monthly releases tied to new public threat research** — new
signatures, fingerprints, and tuning from real-world reports and papers. Breaking
changes are called out in [CHANGELOG.md](CHANGELOG.md).

## Pull requests

1. Branch from `main`.
2. Keep PRs focused; describe the behaviour and include a test plan.
3. `make lint`, `make test`, and `make cov` are green (coverage ≥ 80%).
4. No network-modifying code (see ground rules) — this is enforced by
   `tests/test_invariant_readonly.py`. If you must cross that line, mark it with
   `# invariant-ok: <reason>` and explain it in the PR.
