"""Configuration management for the vulnerability manager."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

try:  # pragma: no cover - optional dependency handled at runtime
    import yaml
except ModuleNotFoundError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]


@dataclass
class APIConfig:
    """Settings for communicating with the CyberCNS API."""

    base_url: str
    token: str
    endpoint: str = "/v4/vulnerabilities"
    page_size: int = 200
    verify_ssl: bool = True
    additional_params: Dict[str, Any] = field(default_factory=dict)
    rate_limit_sleep: float = 0.0


@dataclass
class DatabaseConfig:
    """Location of the SQLite database used for persistence."""

    path: Path = Path("data/vulnerabilities.sqlite3")


@dataclass
class TimelineConfig:
    """Rules used for establishing remediation target dates."""

    default_days: int = 90
    level_overrides: Dict[str, int] = field(default_factory=lambda: {
        "critical": 7,
        "high": 30,
        "medium": 60,
        "low": 90,
    })

    def days_for_level(self, level: str) -> int:
        return self.level_overrides.get(level.lower(), self.default_days)


@dataclass
class ScoringConfig:
    """Tunable knobs that influence the computed risk score."""

    cvss_weight: float = 1.0
    severity_overrides: Dict[str, float] = field(
        default_factory=lambda: {
            "critical": 40.0,
            "high": 25.0,
            "medium": 10.0,
            "low": 0.0,
        }
    )
    exploit_bonus: float = 20.0
    patch_bonus: float = 10.0
    age_weight: float = 1.0
    age_breakpoints: Dict[int, float] = field(
        default_factory=lambda: {
            30: 5.0,
            60: 10.0,
            90: 15.0,
        }
    )
    criticality_weight: float = 5.0
    risk_thresholds: Dict[str, float] = field(
        default_factory=lambda: {
            "critical": 90.0,
            "high": 70.0,
            "medium": 40.0,
            "low": 0.0,
        }
    )
    max_score: float = 100.0

    def ordered_age_breakpoints(self) -> Dict[int, float]:
        return dict(sorted(self.age_breakpoints.items(), key=lambda item: item[0]))

    def ordered_thresholds(self) -> Dict[str, float]:
        return dict(sorted(self.risk_thresholds.items(), key=lambda item: item[1], reverse=True))


@dataclass
class Config:
    api: APIConfig
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    scoring: ScoringConfig = field(default_factory=ScoringConfig)
    timelines: TimelineConfig = field(default_factory=TimelineConfig)


def _load_yaml(path: Path) -> Mapping[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Configuration file not found: {path}")
    if yaml is None:
        raise ModuleNotFoundError(
            "PyYAML is required to load configuration files. Install it with 'pip install PyYAML'."
        )
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, Mapping):
        raise ValueError("Configuration file must contain a mapping at the top level")
    return data


def load_config(path: str | Path) -> Config:
    """Load configuration data from a YAML file."""

    path = Path(path)
    raw = _load_yaml(path)

    def build(section: str, cls: Any) -> Any:
        values: Mapping[str, Any] = raw.get(section, {})
        if not isinstance(values, Mapping):
            raise ValueError(f"Configuration section '{section}' must be a mapping")
        data = {k.replace("-", "_"): v for k, v in values.items()}
        return cls(**data)

    api_cfg = build("api", APIConfig)
    db_cfg = build("database", DatabaseConfig) if "database" in raw else DatabaseConfig()
    scoring_cfg = build("scoring", ScoringConfig) if "scoring" in raw else ScoringConfig()
    timeline_cfg = build("timelines", TimelineConfig) if "timelines" in raw else TimelineConfig()

    return Config(api=api_cfg, database=db_cfg, scoring=scoring_cfg, timelines=timeline_cfg)


__all__ = [
    "APIConfig",
    "DatabaseConfig",
    "TimelineConfig",
    "ScoringConfig",
    "Config",
    "load_config",
]
