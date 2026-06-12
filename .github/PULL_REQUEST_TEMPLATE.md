<!--
Thanks for contributing to Wyvern! Keep PRs focused and small.
See CONTRIBUTING.md for the detector-writing guide and ground rules.
-->

## What & why

<!-- What does this change do, and what problem does it solve? Link any issue. -->

Closes #

## Type of change

- [ ] New / improved detection rule
- [ ] Threat intelligence (new worm port, CVE, fingerprint)
- [ ] Bug fix
- [ ] Docs / packaging / CI
- [ ] Refactor (no behaviour change)

## The read-only invariant (required)

Wyvern only **observes, alerts, and recommends** — it must never act on a device.

- [ ] This PR adds **no** code that transmits packets, probes, or scans.
- [ ] This PR adds **no** code that modifies, blocks, kills, reboots, or
      reconfigures a device, or changes credentials / network settings.
- [ ] `make test` passes, including `tests/test_invariant_readonly.py`.

<!-- If you genuinely need an exception, mark the line with `# invariant-ok: <reason>`
     and explain it here so a maintainer can review it. -->

## Test plan

<!-- How did you verify this? For detectors, include the positive, below-threshold,
     and negative cases described in CONTRIBUTING.md. -->

- [ ] `make lint` is green (ruff check + format).
- [ ] `make cov` ≥ 80%.
- [ ] Added tests for new behaviour.

## Notes for reviewers

<!-- Anything that needs a closer look: threshold choices, false-positive risk, etc. -->
