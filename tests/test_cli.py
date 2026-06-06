"""Tests for the command-line interface."""

from __future__ import annotations

import pytest

from wyvern.cli import main


def test_simulate_command(tmp_path, capsys):
    rc = main(["--data-dir", str(tmp_path), "simulate"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "CRITICAL" in out.upper()
    assert (tmp_path / "wyvern.db").exists()


def test_simulate_then_report_and_export(tmp_path, capsys):
    main(["--data-dir", str(tmp_path), "simulate"])
    assert main(["--data-dir", str(tmp_path), "report"]) == 0
    assert "THREAT LEVEL" in capsys.readouterr().out

    out_file = tmp_path / "f.json"
    assert main(["--data-dir", str(tmp_path), "export", str(out_file)]) == 0
    assert out_file.exists()
    csv_file = tmp_path / "f.csv"
    assert main(["--data-dir", str(tmp_path), "export", str(csv_file), "--format", "csv"]) == 0
    assert csv_file.exists()


def test_simulate_writes_pcap(tmp_path):
    pcap = tmp_path / "out.pcap"
    rc = main(["--data-dir", str(tmp_path), "simulate", "--pcap", str(pcap)])
    assert rc == 0 and pcap.exists()


def test_report_without_data(tmp_path, capsys):
    rc = main(["--data-dir", str(tmp_path), "report"])
    assert rc == 0
    assert "No alerts" in capsys.readouterr().out


def test_replay_command(tmp_path, capsys):
    from wyvern.simulate.worm_trace import write_pcap

    pcap = tmp_path / "s.pcap"
    write_pcap(str(pcap))
    rc = main(["--data-dir", str(tmp_path), "replay", str(pcap)])
    assert rc == 0
    assert "replayed" in capsys.readouterr().out


def test_bad_config_returns_error(tmp_path):
    assert main(["-c", str(tmp_path / "nope.yaml"), "report"]) == 2


def test_version_exits_zero():
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
