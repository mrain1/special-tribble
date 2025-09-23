"""End-to-end synchronisation workflow."""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Dict, Optional

from .client import CyberCNSClient
from .config import Config
from .database import VulnerabilityDatabase
from .models import Vulnerability
from .scoring import RiskCalculator
from .utils import parse_datetime, safe_float

logger = logging.getLogger(__name__)


def synchronize(
    config: Config,
    *,
    params: Optional[Dict[str, object]] = None,
    reference: Optional[datetime] = None,
) -> int:
    """Fetch vulnerabilities from the API, score them, and persist to the DB."""

    calculator = RiskCalculator(config.scoring, config.timelines)
    reference = reference or datetime.now(timezone.utc)
    stored = 0

    with CyberCNSClient(config.api) as client, VulnerabilityDatabase(config.database.path) as db:
        db.initialize()
        vulnerabilities: list[Vulnerability] = []
        for record in client.iter_vulnerabilities(params=params):
            vulnerability = _record_to_vulnerability(record)
            if not vulnerability:
                logger.debug("Skipping record without unique identifiers: %s", record)
                continue
            calculator.enrich(vulnerability, reference=reference)
            vulnerabilities.append(vulnerability)
        if vulnerabilities:
            stored = db.upsert_vulnerabilities(vulnerabilities)
            logger.info("Persisted %s vulnerabilities", stored)
        else:
            logger.info("No vulnerabilities returned from API")
    return stored


def _record_to_vulnerability(record: Dict[str, object]) -> Optional[Vulnerability]:
    def first(*keys: str) -> Optional[object]:
        for key in keys:
            if key in record and record[key] not in (None, ""):
                return record[key]
        return None

    def to_bool(value: Optional[object]) -> bool:
        if isinstance(value, bool):
            return value
        if value is None:
            return False
        if isinstance(value, (int, float)):
            return value != 0
        return str(value).strip().lower() in {"true", "1", "yes", "y"}

    vulnerability_id = first("vulnerabilityId", "id", "vulnId", "vulnerability_id", "findingId")
    asset_id = first("assetId", "asset_id", "deviceId", "siteId")
    title = first("title", "name", "vulnerabilityName", "cve")

    if not (vulnerability_id and asset_id and title):
        return None

    severity = first("severity", "severityLevel", "severity_name")
    cvss = safe_float(first("cvss", "cvssScore", "cvss_score", "cvssBase"))
    exploit_available = to_bool(first("exploitAvailable", "knownExploits", "exploit"))
    patch_available = to_bool(first("patchAvailable", "patchExists", "patch"))
    published_date = parse_datetime(first("publishedDate", "published_on", "publishDate"))
    discovered_date = parse_datetime(first("discoveredDate", "firstSeen", "found_on"))
    last_seen = parse_datetime(first("lastSeen", "lastSeenOn", "last_seen"))
    asset_name = first("assetName", "asset_name", "deviceName")
    asset_criticality = safe_float(first("assetCriticality", "criticality", "businessImpact"))
    status = str(first("status", "state", "findingStatus") or "open")

    known_keys = {
        "vulnerabilityId",
        "id",
        "vulnId",
        "vulnerability_id",
        "findingId",
        "assetId",
        "asset_id",
        "deviceId",
        "siteId",
        "title",
        "name",
        "vulnerabilityName",
        "cve",
        "severity",
        "severityLevel",
        "severity_name",
        "cvss",
        "cvssScore",
        "cvss_score",
        "cvssBase",
        "exploitAvailable",
        "knownExploits",
        "exploit",
        "patchAvailable",
        "patchExists",
        "patch",
        "publishedDate",
        "published_on",
        "publishDate",
        "discoveredDate",
        "firstSeen",
        "found_on",
        "lastSeen",
        "lastSeenOn",
        "last_seen",
        "assetName",
        "asset_name",
        "deviceName",
        "assetCriticality",
        "criticality",
        "businessImpact",
        "status",
        "state",
        "findingStatus",
    }

    metadata = {k: v for k, v in record.items() if k not in known_keys}

    return Vulnerability(
        vulnerability_id=str(vulnerability_id),
        asset_id=str(asset_id),
        title=str(title),
        asset_name=str(asset_name) if asset_name is not None else None,
        severity=str(severity) if severity is not None else None,
        cvss_score=cvss,
        exploit_available=exploit_available,
        patch_available=patch_available,
        published_date=published_date,
        discovered_date=discovered_date,
        last_seen=last_seen,
        asset_criticality=asset_criticality,
        status=status,
        metadata=metadata,
    )


__all__ = ["synchronize"]
