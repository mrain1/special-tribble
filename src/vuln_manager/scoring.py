"""Risk scoring implementation for CyberCNS vulnerabilities."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

from .config import ScoringConfig, TimelineConfig
from .models import RiskComputation, Vulnerability


class RiskCalculator:
    """Compute risk scores and remediation targets for vulnerabilities."""

    def __init__(self, config: ScoringConfig, timelines: TimelineConfig):
        self.config = config
        self.timelines = timelines

    def calculate(self, vulnerability: Vulnerability, reference: Optional[datetime] = None) -> RiskComputation:
        reference = reference or datetime.now(timezone.utc)
        score = 0.0
        reasons: Dict[str, float] = {}

        # Severity override provides a baseline for the risk
        severity_key = (vulnerability.severity or "").strip().lower()
        if severity_key in self.config.severity_overrides:
            severity_score = self.config.severity_overrides[severity_key]
            if severity_score:
                score += severity_score
                reasons["severity"] = severity_score

        # CVSS score contributes linearly
        if vulnerability.cvss_score is not None:
            cvss_component = max(0.0, min(vulnerability.cvss_score, 10.0)) * self.config.cvss_weight
            if cvss_component:
                score += cvss_component
                reasons["cvss"] = cvss_component

        if vulnerability.exploit_available:
            score += self.config.exploit_bonus
            reasons["exploit"] = self.config.exploit_bonus

        if vulnerability.patch_available:
            score += self.config.patch_bonus
            reasons["patch"] = self.config.patch_bonus

        if vulnerability.asset_criticality:
            criticality_component = float(vulnerability.asset_criticality) * self.config.criticality_weight
            score += criticality_component
            reasons["asset_criticality"] = criticality_component

        opened = vulnerability.discovered_date or vulnerability.published_date
        if opened and opened.tzinfo is None:
            opened = opened.replace(tzinfo=timezone.utc)
        if opened:
            opened_utc = opened.astimezone(timezone.utc)
            age_days = (reference - opened_utc).days
            if age_days > 0:
                for threshold, weight in self.config.ordered_age_breakpoints().items():
                    if age_days >= threshold:
                        age_component = weight * self.config.age_weight
                        score += age_component
                        reasons[f"age>{threshold}"] = age_component

        score = min(score, self.config.max_score)

        level = "low"
        for name, threshold in self.config.ordered_thresholds().items():
            if score >= threshold:
                level = name
                break

        return RiskComputation(score=round(score, 2), level=level, reasons=reasons)

    def target_remediation_date(self, level: str, reference: Optional[datetime] = None) -> datetime:
        reference = reference or datetime.now(timezone.utc)
        days = self.timelines.days_for_level(level)
        return reference + timedelta(days=days)

    def enrich(self, vulnerability: Vulnerability, reference: Optional[datetime] = None) -> Vulnerability:
        """Mutate a vulnerability with risk score metadata."""

        result = self.calculate(vulnerability, reference=reference)
        vulnerability.risk_score = result.score
        vulnerability.risk_level = result.level
        vulnerability.risk_reasons = result.reasons
        vulnerability.target_date = self.target_remediation_date(result.level, reference=reference)
        return vulnerability


__all__ = ["RiskCalculator"]
