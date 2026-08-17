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
    cred_fail_reconnects: int = 8  # rapid re-tries to one host = failed auth
    # Inference proxy: inference requests/min from a single device.
    inference_rate_per_min: float = 6.0
    inference_window_s: float = 300.0
    # Stream-timing corroboration: passive detection of LLM token streaming over
    # HTTPS by the inter-packet rhythm of the response (Alhazbi et al. 2025).
    # A *corroborating* hint only — deliberately conservative to avoid firing on
    # ordinary long-lived 443 (video, downloads, websockets, keep-alives).
    stream_timing_ports: tuple[int, ...] = (443,)
    stream_timing_window_s: float = 120.0
    stream_timing_min_segments: int = 40  # need a sustained stream, not a burst
    stream_timing_min_gap_ms: float = 8.0  # faster ⇒ bulk transfer, not tokens
    stream_timing_max_gap_ms: float = 120.0  # slower ⇒ interactive, not streaming
    stream_timing_cov_lo: float = 0.10  # too regular ⇒ CBR media pacing
    stream_timing_cov_hi: float = 1.20  # too erratic ⇒ bursty web traffic
    stream_timing_max_payload_mean: float = 800.0  # token chunks are small
    stream_timing_confidence: float = 0.30  # standalone weak signal
    # Beaconing: regular callbacks on a non-standard port.
    beacon_min_callbacks: int = 6
    beacon_window_s: float = 1800.0
    beacon_max_cov: float = 0.20  # inter-arrival coefficient of variation
    beacon_min_interval_s: float = 2.0
    # Idle-device code execution (printer/router/NAS suddenly active).
    idle_outbound_conns: int = 3
    idle_window_s: float = 600.0
    # Zero-egress: a host declared no-egress reaching an external network. The
    # window re-arms the per-destination alert so a persistent violation re-surfaces.
    no_egress_window_s: float = 3600.0
    no_egress_confidence: float = 0.9  # containment escape => high confidence
    # Composite worm signature: distinct stages within the correlation window.
    worm_stages_high: int = 2
    worm_stages_critical: int = 3
    worm_window_s: float = 3600.0

    def validate(self) -> None:
        for name in (
            "scan_ports",
            "lateral_peers",
            "dns_nxdomain_burst",
            "cred_distinct_hosts",
            "cred_fail_reconnects",
            "beacon_min_callbacks",
            "idle_outbound_conns",
            "worm_stages_high",
            "worm_stages_critical",
            "stream_timing_min_segments",
        ):
            if getattr(self, name) <= 0:
                raise ConfigError(f"threshold '{name}' must be positive")
        for name in (
            "scan_window_s",
            "lateral_window_s",
            "dns_window_s",
            "cred_window_s",
            "inference_window_s",
            "beacon_window_s",
            "idle_window_s",
            "worm_window_s",
            "stream_timing_window_s",
            "no_egress_window_s",
        ):
            if getattr(self, name) <= 0:
                raise ConfigError(f"window '{name}' must be positive")
        if not (0.0 < self.no_egress_confidence <= 1.0):
            raise ConfigError("no_egress_confidence must be in (0, 1]")
        if not (0.0 < self.dga_score <= 1.0):
            raise ConfigError("dga_score must be in (0, 1]")
        if not (0.0 < self.beacon_max_cov <= 1.0):
            raise ConfigError("beacon_max_cov must be in (0, 1]")
        if self.worm_stages_critical < self.worm_stages_high:
            raise ConfigError("worm_stages_critical must be >= worm_stages_high")
        if not self.stream_timing_ports:
            raise ConfigError("stream_timing_ports must not be empty")
        if not (0.0 < self.stream_timing_min_gap_ms < self.stream_timing_max_gap_ms):
            raise ConfigError("stream_timing gap bounds must satisfy 0 < min < max")
        if not (0.0 <= self.stream_timing_cov_lo < self.stream_timing_cov_hi):
            raise ConfigError("stream_timing cov bounds must satisfy 0 <= lo < hi")
        if self.stream_timing_max_payload_mean <= 0:
            raise ConfigError("stream_timing_max_payload_mean must be positive")
        if not (0.0 < self.stream_timing_confidence <= 1.0):
            raise ConfigError("stream_timing_confidence must be in (0, 1]")


@dataclass(frozen=True, slots=True)
class NotifyConfig:
    desktop_enabled: bool = True
    min_severity: int = 3  # notify on HIGH+ by default
    email_enabled: bool = False  # OFF unless explicitly configured
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_user: str | None = None
    smtp_password: str | None = None  # injected from env only
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
class EnforceConfig:
    """Detection->enforcement bridge (issue #22, Piece 2).

    Wyvern stays passive: on a high-confidence alert it POSTs a signed finding to
    an EXTERNAL actuator (firewall / egress controller) that decides whether to
    act. Off by default. The signing secret is injected from the environment only
    (``WYVERN_ENFORCE_SECRET``), never read from the YAML file, per the project's
    secret-management rules.
    """

    enabled: bool = False
    webhook_url: str | None = None
    min_severity: int = 4  # CRITICAL only, by default
    timeout_s: float = 5.0
    signing_secret: str | None = None  # injected from env only

    def validate(self) -> None:
        if not self.enabled:
            return
        if not self.webhook_url:
            raise ConfigError("enforcement enabled but webhook_url is unset")
        if not (self.webhook_url.startswith(("http://", "https://"))):
            raise ConfigError("enforce.webhook_url must be an http(s) URL")
        if not (1 <= self.min_severity <= 4):
            raise ConfigError("enforce.min_severity must be 1..4")
        if self.timeout_s <= 0:
            raise ConfigError("enforce.timeout_s must be positive")


@dataclass(frozen=True, slots=True)
class ResponsePolicy:
    """Tier-1 active-response policy (issue #29).

    Governs whether/how Wyvern proposes or takes containment action on a
    high-confidence worm verdict. Defaults are deliberately inert:
    ``mode='observe'`` means Wyvern only *records* "would quarantine X" and never
    enforces. Autonomy is earned (observe -> confirm -> auto), never assumed —
    Wyvern lacks anti-virus's signature precision and reputation feed, so it must
    stay more conservative than AV.
    """

    mode: str = "observe"  # observe | confirm | auto
    min_severity: int = 4  # only act on CRITICAL worm verdicts by default
    protected_hosts: tuple[str, ...] = ()  # IPs/MACs that can NEVER be actioned
    max_actions_per_window: int = 5  # circuit breaker: max actions per window
    window_s: float = 300.0
    quarantine_ttl_s: float = 3600.0  # auto-expiry / auto-release horizon
    # Responder that actually enforces a quarantine. "none" (default) => the engine
    # only proposes/records, never enforces. "firewall" runs the operator-supplied
    # command templates below (with {ip}/{mac} substituted; no shell).
    responder: str = "none"  # none | firewall
    firewall_quarantine_cmd: str | None = None
    firewall_release_cmd: str | None = None

    def validate(self) -> None:
        if self.mode not in ("observe", "confirm", "auto"):
            raise ConfigError("response.mode must be 'observe', 'confirm' or 'auto'")
        if not (1 <= self.min_severity <= 4):
            raise ConfigError("response.min_severity must be 1..4")
        if self.max_actions_per_window <= 0:
            raise ConfigError("response.max_actions_per_window must be positive")
        for name in ("window_s", "quarantine_ttl_s"):
            if getattr(self, name) <= 0:
                raise ConfigError(f"response.{name} must be positive")
        if self.responder not in ("none", "firewall"):
            raise ConfigError("response.responder must be 'none' or 'firewall'")
        if self.responder == "firewall" and not (
            self.firewall_quarantine_cmd and self.firewall_release_cmd
        ):
            raise ConfigError(
                "response.responder='firewall' requires firewall_quarantine_cmd "
                "and firewall_release_cmd"
            )


@dataclass(frozen=True, slots=True)
class Config:
    interface: str | None = None
    internal_cidrs: tuple[str, ...] = DEFAULT_PRIVATE_CIDRS
    bpf_filter: str | None = None
    gpu_hosts: tuple[str, ...] = ()  # IPs or MACs declared GPU-capable
    # IPs or MACs of hosts that must have NO external egress (isolated/quarantined
    # segments). Any outbound to an external network from these is a high-confidence
    # containment-escape signal. Empty => the zero-egress detector is inert.
    no_egress_hosts: tuple[str, ...] = ()
    learning_window_hours: float = 24.0
    data_dir: str = "./wyvern-data"
    web_enabled: bool = True
    web_host: str = "127.0.0.1"
    web_port: int = 8787
    sweep_interval_s: float = 30.0
    oui_file: str | None = None
    thresholds: Thresholds = field(default_factory=Thresholds)
    notify: NotifyConfig = field(default_factory=NotifyConfig)
    enforce: EnforceConfig = field(default_factory=EnforceConfig)
    response: ResponsePolicy = field(default_factory=ResponsePolicy)

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

    def validate(self) -> Config:
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
        self.enforce.validate()
        self.response.validate()
        return self

    # ---- constructors ----
    @classmethod
    def default(cls) -> Config:
        return cls().validate()

    @classmethod
    def from_dict(cls, data: dict) -> Config:
        data = dict(data or {})
        thresholds = Thresholds(**(data.pop("thresholds", {}) or {}))
        notify_raw = dict(data.pop("notify", {}) or {})
        notify_raw.pop("smtp_password", None)  # never accept secrets from file
        if "email_to" in notify_raw and isinstance(notify_raw["email_to"], list):
            notify_raw["email_to"] = tuple(notify_raw["email_to"])
        notify = NotifyConfig(**notify_raw)
        enforce_raw = dict(data.pop("enforce", {}) or {})
        enforce_raw.pop("signing_secret", None)  # never accept secrets from file
        enforce = EnforceConfig(**enforce_raw)
        response_raw = dict(data.pop("response", {}) or {})
        if isinstance(response_raw.get("protected_hosts"), list):
            response_raw["protected_hosts"] = tuple(response_raw["protected_hosts"])
        response = ResponsePolicy(**response_raw)
        for seq_key in ("internal_cidrs", "gpu_hosts", "no_egress_hosts"):
            if seq_key in data and isinstance(data[seq_key], list):
                data[seq_key] = tuple(data[seq_key])
        cfg = cls(thresholds=thresholds, notify=notify, enforce=enforce, response=response, **data)
        cfg = cfg._with_env_overrides()
        return cfg.validate()

    @classmethod
    def from_file(cls, path: str) -> Config:
        import yaml  # lazy: only needed when loading a file

        try:
            with open(path, encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
        except OSError as exc:
            raise ConfigError(f"cannot read config file {path!r}: {exc}") from exc
        if not isinstance(data, dict):
            raise ConfigError(f"config file {path!r} must contain a mapping")
        return cls.from_dict(data)

    def _with_env_overrides(self) -> Config:
        """Apply environment overrides — secrets and a few CLI-equivalents.

        Lets containers / systemd configure Wyvern with env vars alone:
        ``WYVERN_INTERFACE``, ``WYVERN_DATA_DIR``, ``WYVERN_WEB_HOST``,
        ``WYVERN_WEB_PORT``, and the secret ``WYVERN_SMTP_PASSWORD``.
        """
        notify = self.notify
        pw = os.environ.get("WYVERN_SMTP_PASSWORD")
        if pw:
            notify = replace(notify, smtp_password=pw)
        enforce = self.enforce
        secret = os.environ.get("WYVERN_ENFORCE_SECRET")
        if secret:
            enforce = replace(enforce, signing_secret=secret)
        web_port = self.web_port
        port_env = os.environ.get("WYVERN_WEB_PORT")
        if port_env:
            try:
                web_port = int(port_env)
            except ValueError:
                pass
        return replace(
            self,
            notify=notify,
            enforce=enforce,
            interface=os.environ.get("WYVERN_INTERFACE") or self.interface,
            data_dir=os.environ.get("WYVERN_DATA_DIR") or self.data_dir,
            web_host=os.environ.get("WYVERN_WEB_HOST") or self.web_host,
            web_port=web_port,
        )

    def is_declared_gpu_host(self, ip: str | None, mac: str | None) -> bool:
        if not self.gpu_hosts:
            return False
        targets = {t.lower() for t in self.gpu_hosts}
        return (ip and ip.lower() in targets) or (mac and mac.lower() in targets)

    def is_no_egress_host(self, ip: str | None, mac: str | None) -> bool:
        if not self.no_egress_hosts:
            return False
        targets = {t.lower() for t in self.no_egress_hosts}
        return bool((ip and ip.lower() in targets) or (mac and mac.lower() in targets))
