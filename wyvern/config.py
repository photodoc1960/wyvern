"""Configuration: thresholds, network scope, storage paths and alerting.

Configuration is validated at construction (fail fast, clear messages). Secrets
(SMTP password) are *never* read from the YAML file — only from the environment
(``WYVERN_SMTP_PASSWORD``) — per the project's secret-management rules.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from pathlib import Path

from .util.nets import DEFAULT_PRIVATE_CIDRS


class ConfigError(ValueError):
    """Raised when configuration is missing or invalid."""


@dataclass(frozen=True, slots=True)
class Thresholds:
    # Port scanning: >50 distinct dst ports in 5 minutes (worm reconnaissance).
    scan_ports: int = 50
    scan_window_s: float = 300.0
    # Lateral movement: a device contacting >10 internal IPs in 1 hour.
    lateral_peers: int = 10
    lateral_window_s: float = 3600.0
    # DNS anomalies.
    dns_rate_per_min: float = 120.0
    dns_window_s: float = 60.0
    dns_nxdomain_burst: int = 25
    dga_score: float = 0.62
    # Credential spray / reuse: one source hitting auth services on N hosts.
    cred_distinct_hosts: int = 5
    cred_window_s: float = 600.0
    cred_fail_reconnects: int = 8        # rapid re-tries to one host = failed auth
    # Inference proxy: inference requests/min from a single device.
    inference_rate_per_min: float = 6.0
    inference_window_s: float = 300.0
    # Beaconing: regular callbacks on a non-standard port.
    beacon_min_callbacks: int = 6
    beacon_window_s: float = 1800.0
    beacon_max_cov: float = 0.20         # inter-arrival coefficient of variation
    beacon_min_interval_s: float = 2.0
    # Idle-device code execution (printer/router/NAS suddenly active).
    idle_outbound_conns: int = 3
    idle_window_s: float = 600.0
    # Composite worm signature: distinct stages within the correlation window.
    worm_stages_high: int = 2
    worm_stages_critical: int = 3
    worm_window_s: float = 3600.0

    def validate(self) -> None:
        for name in (
            "scan_ports", "lateral_peers", "dns_nxdomain_burst",
            "cred_distinct_hosts", "cred_fail_reconnects",
            "beacon_min_callbacks", "idle_outbound_conns",
            "worm_stages_high", "worm_stages_critical",
        ):
            if getattr(self, name) <= 0:
                raise ConfigError(f"threshold '{name}' must be positive")
        for name in (
            "scan_window_s", "lateral_window_s", "dns_window_s", "cred_window_s",
            "inference_window_s", "beacon_window_s", "idle_window_s", "worm_window_s",
        ):
            if getattr(self, name) <= 0:
                raise ConfigError(f"window '{name}' must be positive")
        if not (0.0 < self.dga_score <= 1.0):
            raise ConfigError("dga_score must be in (0, 1]")
        if not (0.0 < self.beacon_max_cov <= 1.0):
            raise ConfigError("beacon_max_cov must be in (0, 1]")
        if self.worm_stages_critical < self.worm_stages_high:
            raise ConfigError("worm_stages_critical must be >= worm_stages_high")


@dataclass(frozen=True, slots=True)
class NotifyConfig:
    desktop_enabled: bool = True
    min_severity: int = 3                 # notify on HIGH+ by default
    email_enabled: bool = False           # OFF unless explicitly configured
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_user: str | None = None
    smtp_password: str | None = None      # injected from env only
    email_from: str | None = None
    email_to: tuple[str, ...] = ()
    email_digest_min_s: float = 3600.0

    def validate(self) -> None:
        if not (1 <= self.min_severity <= 4):
            raise ConfigError("notify.min_severity must be 1..4")
        if self.email_enabled:
            if not self.smtp_host:
                raise ConfigError("email enabled but smtp_host is unset")
            if not self.email_to:
                raise ConfigError("email enabled but email_to is empty")
            if not self.smtp_password:
                raise ConfigError(
                    "email enabled but no SMTP password "
                    "(set WYVERN_SMTP_PASSWORD in the environment)"
                )


@dataclass(frozen=True, slots=True)
class Config:
    interface: str | None = None
    internal_cidrs: tuple[str, ...] = DEFAULT_PRIVATE_CIDRS
    bpf_filter: str | None = None
    gpu_hosts: tuple[str, ...] = ()        # IPs or MACs declared GPU-capable
    learning_window_hours: float = 24.0
    data_dir: str = "./wyvern-data"
    web_enabled: bool = True
    web_host: str = "127.0.0.1"
    web_port: int = 8787
    sweep_interval_s: float = 30.0
    oui_file: str | None = None
    thresholds: Thresholds = field(default_factory=Thresholds)
    notify: NotifyConfig = field(default_factory=NotifyConfig)

    # ---- derived paths ----
    @property
    def db_path(self) -> str:
        return str(Path(self.data_dir) / "wyvern.db")

    @property
    def baseline_path(self) -> str:
        return str(Path(self.data_dir) / "baselines.json")

    @property
    def eventlog_path(self) -> str:
        return str(Path(self.data_dir) / "events.jsonl")

    def ensure_data_dir(self) -> None:
        Path(self.data_dir).mkdir(parents=True, exist_ok=True)

    def validate(self) -> "Config":
        if self.learning_window_hours <= 0:
            raise ConfigError("learning_window_hours must be positive")
        if not (0 < self.web_port < 65536):
            raise ConfigError("web_port must be a valid TCP port")
        if self.sweep_interval_s <= 0:
            raise ConfigError("sweep_interval_s must be positive")
        if not self.internal_cidrs:
            raise ConfigError("internal_cidrs must not be empty")
        import ipaddress
        for cidr in self.internal_cidrs:
            try:
                ipaddress.ip_network(cidr, strict=False)
            except ValueError as exc:
                raise ConfigError(f"invalid internal CIDR {cidr!r}: {exc}") from exc
        self.thresholds.validate()
        self.notify.validate()
        return self

    # ---- constructors ----
    @classmethod
    def default(cls) -> "Config":
        return cls().validate()

    @classmethod
    def from_dict(cls, data: dict) -> "Config":
        data = dict(data or {})
        thresholds = Thresholds(**(data.pop("thresholds", {}) or {}))
        notify_raw = dict(data.pop("notify", {}) or {})
        notify_raw.pop("smtp_password", None)  # never accept secrets from file
        if "email_to" in notify_raw and isinstance(notify_raw["email_to"], list):
            notify_raw["email_to"] = tuple(notify_raw["email_to"])
        notify = NotifyConfig(**notify_raw)
        for seq_key in ("internal_cidrs", "gpu_hosts"):
            if seq_key in data and isinstance(data[seq_key], list):
                data[seq_key] = tuple(data[seq_key])
        cfg = cls(thresholds=thresholds, notify=notify, **data)
        cfg = cfg._with_env_overrides()
        return cfg.validate()

    @classmethod
    def from_file(cls, path: str) -> "Config":
        import yaml  # lazy: only needed when loading a file
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
        except OSError as exc:
            raise ConfigError(f"cannot read config file {path!r}: {exc}") from exc
        if not isinstance(data, dict):
            raise ConfigError(f"config file {path!r} must contain a mapping")
        return cls.from_dict(data)

    def _with_env_overrides(self) -> "Config":
        """Apply environment overrides — secrets and a few CLI-equivalents."""
        notify = self.notify
        pw = os.environ.get("WYVERN_SMTP_PASSWORD")
        if pw:
            notify = replace(notify, smtp_password=pw)
        iface = os.environ.get("WYVERN_INTERFACE")
        data_dir = os.environ.get("WYVERN_DATA_DIR")
        return replace(
            self,
            notify=notify,
            interface=iface or self.interface,
            data_dir=data_dir or self.data_dir,
        )

    def is_declared_gpu_host(self, ip: str | None, mac: str | None) -> bool:
        if not self.gpu_hosts:
            return False
        targets = {t.lower() for t in self.gpu_hosts}
        return (ip and ip.lower() in targets) or (mac and mac.lower() in targets)
