# Wyvern Design

## Pipeline

```
        scapy (live)            dpkt
   ┌──────────────────┐   ┌──────────────┐
   │  LiveSniffer /   │──▶│ decode_frame │──▶ NetworkEvent(s)
   │  replay_pcap     │   │  (analysis)  │      (immutable)
   └──────────────────┘   └──────────────┘
                                  │
                                  ▼
        ┌───────────────────────────────────────────────┐
        │                Monitor.process_event           │
        │                                                │
        │  registry.observe ──▶ device tracking + OUI/   │
        │                       TTL/DHCP fingerprinting  │
        │  baseline.observe ──▶ 24h per-device learning  │
        │  detectors[*].inspect ─▶ per-stage Alerts      │
        │  worm_signature.correlate ─▶ composite verdict │
        │  assessor.assess ──▶ per-device threat + recs  │
        │  storage + eventlog + bus + notifier           │
        └───────────────────────────────────────────────┘
                                  │
                 ┌────────────────┼────────────────┐
                 ▼                ▼                ▼
            SQLite + JSONL    SSE bus → Flask     desktop / email
            (forensics)        dashboard          notifications
```

Everything funnels through `Monitor.process_event(event)`. Live capture, pcap
replay, the simulator, and the tests all drive that one method — so the entire
detection pipeline runs without a live interface or root.

## Layers & responsibilities

| Package | Responsibility |
|---|---|
| `capture/` | scapy live capture (`store=False`, passive); dpkt frame decoding → events |
| `models/` | immutable `Device` / `Alert` / `*Event` / `DeviceProfile` dataclasses |
| `indicators.py` | shared predicates over the worm-intelligence constants |
| `tracking/` | `DeviceRegistry` + passive OS/role fingerprinting |
| `baseline/` | per-device behavioural learning + JSON persistence |
| `detectors/` | 8 stage detectors + `worm_signature` correlator |
| `assessment/` | threat scoring + manual remediation mapping |
| `storage/` | SQLite store, append-only JSONL log, exporters |
| `alerting/` | desktop notifications + optional email digest |
| `engine/` | `Monitor` orchestrator + in-process SSE bus |
| `web/` | Flask dashboard (topology, timeline, devices, export) |
| `simulate/` | synthetic Toronto-worm trace generator |

## Key design decisions

**Immutable domain objects.** Events, alerts, devices and profiles are frozen
dataclasses; updates return copies (`device.evolve(...)`). Only detector
*counters* mutate — the standard, efficient pattern for streaming windows.

**Detectors see events, not packets.** Decoding is isolated in `capture/decode.py`
(dpkt). Detectors operate on normalised events, so they are pure and unit-tested
against hand-built events — no interface, no privilege.

**Absolute thresholds + baseline deviation.** Hard worm signatures (50-port scan,
beacon regularity) fire on absolute thresholds even before a baseline exists.
Once learned, per-device deviation raises confidence and suppresses routine
behaviour.

**Correlation over single signals.** Individual stages are noisy; the
`worm_signature` correlator escalates only when *several distinct stages* land on
one device, which is what makes a worm a worm.

**Fail-safe, never fail-dangerous.** Untrusted packet data never raises
(decoders return `[]`); storage/notifier errors are logged but never kill the
pipeline; there is no code path that modifies the network.

## Threading model

- One capture thread (scapy `AsyncSniffer`) calls `process_frame`.
- One daemon **sweeper** thread runs `sweep()` every `sweep_interval_s` for
  time-window detectors (beaconing) and assessment refresh.
- Flask serves on its own threads; the SSE bus hands each subscriber a bounded
  queue. The SQLite connection is guarded by a lock.

## Adding a detector

See [CONTRIBUTING.md](../CONTRIBUTING.md#writing-your-own-detector). In short:
subclass `Detector`, emit `Alert`s tagged with a worm `stage`, register it in
`detectors/loader.py`, and add a test. If the stage is one of the worm stages,
it automatically feeds the composite correlator.

## Testing strategy

- **Unit:** every detector (above/below threshold + negatives), decoding against
  dpkt-crafted frames, fingerprinting, baseline learning/persistence, scoring,
  storage.
- **Integration:** `Monitor.feed_events(worm_scenario())` must yield a Critical
  verdict naming the right devices and cover all stages.
- ~87% line coverage; run `make cov`.
