from datetime import datetime, timezone

from vuln_manager.database import VulnerabilityDatabase
from vuln_manager.models import Vulnerability


def make_vulnerability(identifier: str, title: str, score: float) -> Vulnerability:
    return Vulnerability(
        vulnerability_id=identifier,
        asset_id="asset-123",
        title=title,
        severity="High",
        cvss_score=8.0,
        risk_score=score,
        risk_level="high",
        status="open",
        target_date=datetime(2025, 1, 10, tzinfo=timezone.utc),
        risk_reasons={"cvss": 40.0},
    )


def test_upsert_and_status_tracking(tmp_path):
    database_path = tmp_path / "vulns.sqlite"
    with VulnerabilityDatabase(database_path) as db:
        db.initialize()
        first = make_vulnerability("v1", "Original title", 70.0)
        second = make_vulnerability("v2", "Second vuln", 50.0)

        inserted = db.upsert_vulnerabilities([first, second])
        assert inserted == 2

        records = db.fetch_vulnerabilities()
        assert [v.vulnerability_id for v in records] == ["v1", "v2"]

        first.title = "Updated title"
        first.status = "in-progress"
        db.upsert_vulnerabilities([first])

        updated = db.fetch_vulnerabilities(status="in-progress")
        assert len(updated) == 1
        assert updated[0].title == "Updated title"

        db.mark_status("v1", "closed", note="Patched")
        closed = db.fetch_vulnerabilities(status="closed")
        assert len(closed) == 1
        assert closed[0].status == "closed"
