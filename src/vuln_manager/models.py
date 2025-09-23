"""Core domain models used by the vulnerability manager."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Optional


@dataclass
class Vulnerability:
    """Represents a vulnerability instance associated with an asset."""

    vulnerability_id: str
    asset_id: str
    title: str
    asset_name: Optional[str] = None
    severity: Optional[str] = None
    cvss_score: Optional[float] = None
    exploit_available: bool = False
    patch_available: bool = False
    published_date: Optional[datetime] = None
    discovered_date: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    asset_criticality: Optional[float] = None
    status: str = "open"
    metadata: Dict[str, Any] = field(default_factory=dict)

    # Fields enriched by the scoring pipeline
    risk_score: Optional[float] = None
    risk_level: Optional[str] = None
    target_date: Optional[datetime] = None
    risk_reasons: Dict[str, float] = field(default_factory=dict)


@dataclass
class RiskComputation:
    """Outcome of running a vulnerability through the scoring engine."""

    score: float
    level: str
    reasons: Dict[str, float]


__all__ = ["Vulnerability", "RiskComputation"]
