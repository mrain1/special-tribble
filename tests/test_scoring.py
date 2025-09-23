from datetime import datetime, timedelta, timezone

import pytest

from vuln_manager.config import ScoringConfig, TimelineConfig
from vuln_manager.models import Vulnerability
from vuln_manager.scoring import RiskCalculator


def test_risk_calculation_combines_multiple_factors():
    config = ScoringConfig(
        cvss_weight=5.0,
        severity_overrides={"critical": 60.0, "high": 25.0, "medium": 10.0, "low": 0.0},
        exploit_bonus=12.0,
        patch_bonus=6.0,
        age_weight=1.0,
        age_breakpoints={30: 4.0, 60: 8.0},
        criticality_weight=3.0,
        risk_thresholds={"critical": 90.0, "high": 70.0, "medium": 40.0, "low": 0.0},
        max_score=120.0,
    )
    timelines = TimelineConfig(level_overrides={"critical": 7, "high": 30, "medium": 60, "low": 90})
    calculator = RiskCalculator(config, timelines)

    reference = datetime(2025, 1, 1, tzinfo=timezone.utc)
    vulnerability = Vulnerability(
        vulnerability_id="v-1",
        asset_id="asset-1",
        title="Critical OpenSSL vulnerability",
        severity="High",
        cvss_score=8.5,
        exploit_available=True,
        patch_available=True,
        discovered_date=reference - timedelta(days=65),
        asset_criticality=3,
    )

    result = calculator.calculate(vulnerability, reference=reference)

    expected_score = 25.0 + (8.5 * 5.0) + 12.0 + 6.0 + (3 * 3.0) + 4.0 + 8.0
    assert result.score == pytest.approx(round(expected_score, 2))
    assert result.level == "critical"
    assert "cvss" in result.reasons
    assert "age>30" in result.reasons
    assert "age>60" in result.reasons

    enriched = calculator.enrich(vulnerability, reference=reference)
    assert enriched.risk_level == "critical"
    assert enriched.target_date == reference + timedelta(days=7)
    assert enriched.risk_score == pytest.approx(result.score)
