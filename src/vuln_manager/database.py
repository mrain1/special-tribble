"""SQLite persistence layer for vulnerability data."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from .models import Vulnerability


def _ensure_directory(path: Path) -> None:
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)


def _isoformat(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _fromiso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class VulnerabilityDatabase:
    """Thin wrapper around SQLite for storing vulnerability information."""

    def __init__(self, path: Path):
        self.path = Path(path)
        _ensure_directory(self.path)
        self._conn = sqlite3.connect(str(self.path))
        self._conn.row_factory = sqlite3.Row

    def initialize(self) -> None:
        cursor = self._conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                vulnerability_id TEXT PRIMARY KEY,
                asset_id TEXT NOT NULL,
                asset_name TEXT,
                title TEXT NOT NULL,
                severity TEXT,
                cvss_score REAL,
                exploit_available INTEGER,
                patch_available INTEGER,
                published_date TEXT,
                discovered_date TEXT,
                last_seen TEXT,
                asset_criticality REAL,
                status TEXT DEFAULT 'open',
                risk_score REAL,
                risk_level TEXT,
                target_date TEXT,
                risk_reasons TEXT,
                metadata TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS remediation_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vulnerability_id TEXT NOT NULL,
                old_status TEXT,
                new_status TEXT,
                note TEXT,
                changed_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(vulnerability_id) REFERENCES vulnerabilities(vulnerability_id)
            )
            """
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "VulnerabilityDatabase":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # type: ignore[override]
        self.close()

    def upsert_vulnerabilities(self, vulnerabilities: Iterable[Vulnerability]) -> int:
        query = (
            """
            INSERT INTO vulnerabilities (
                vulnerability_id, asset_id, asset_name, title, severity, cvss_score,
                exploit_available, patch_available, published_date, discovered_date,
                last_seen, asset_criticality, status, risk_score, risk_level,
                target_date, risk_reasons, metadata, updated_at
            )
            VALUES (
                :vulnerability_id, :asset_id, :asset_name, :title, :severity, :cvss_score,
                :exploit_available, :patch_available, :published_date, :discovered_date,
                :last_seen, :asset_criticality, :status, :risk_score, :risk_level,
                :target_date, :risk_reasons, :metadata, CURRENT_TIMESTAMP
            )
            ON CONFLICT(vulnerability_id) DO UPDATE SET
                asset_id=excluded.asset_id,
                asset_name=excluded.asset_name,
                title=excluded.title,
                severity=excluded.severity,
                cvss_score=excluded.cvss_score,
                exploit_available=excluded.exploit_available,
                patch_available=excluded.patch_available,
                published_date=excluded.published_date,
                discovered_date=excluded.discovered_date,
                last_seen=excluded.last_seen,
                asset_criticality=excluded.asset_criticality,
                status=excluded.status,
                risk_score=excluded.risk_score,
                risk_level=excluded.risk_level,
                target_date=excluded.target_date,
                risk_reasons=excluded.risk_reasons,
                metadata=excluded.metadata,
                updated_at=CURRENT_TIMESTAMP
            """
        )
        rows = 0
        with self._conn:
            for vulnerability in vulnerabilities:
                payload = self._serialise(vulnerability)
                self._conn.execute(query, payload)
                rows += 1
        return rows

    def mark_status(
        self,
        vulnerability_id: str,
        new_status: str,
        note: str | None = None,
    ) -> None:
        with self._conn:
            current = self._conn.execute(
                "SELECT status FROM vulnerabilities WHERE vulnerability_id = ?",
                (vulnerability_id,),
            ).fetchone()
            old_status = current["status"] if current else None
            self._conn.execute(
                """
                UPDATE vulnerabilities
                SET status = ?, updated_at = CURRENT_TIMESTAMP
                WHERE vulnerability_id = ?
                """,
                (new_status, vulnerability_id),
            )
            self._conn.execute(
                """
                INSERT INTO remediation_history (vulnerability_id, old_status, new_status, note)
                VALUES (?, ?, ?, ?)
                """,
                (vulnerability_id, old_status, new_status, note),
            )

    def fetch_vulnerabilities(self, status: Optional[str] = None) -> List[Vulnerability]:
        query = "SELECT * FROM vulnerabilities"
        params: tuple = ()
        if status:
            query += " WHERE status = ?"
            params = (status,)
        query += " ORDER BY CASE WHEN risk_score IS NULL THEN 1 ELSE 0 END, risk_score DESC"
        rows = self._conn.execute(query, params).fetchall()
        return [self._deserialize(row) for row in rows]

    def _serialise(self, vulnerability: Vulnerability) -> Dict[str, object]:
        record = {
            "vulnerability_id": vulnerability.vulnerability_id,
            "asset_id": vulnerability.asset_id,
            "asset_name": vulnerability.asset_name,
            "title": vulnerability.title,
            "severity": vulnerability.severity,
            "cvss_score": vulnerability.cvss_score,
            "exploit_available": 1 if vulnerability.exploit_available else 0,
            "patch_available": 1 if vulnerability.patch_available else 0,
            "published_date": _isoformat(vulnerability.published_date),
            "discovered_date": _isoformat(vulnerability.discovered_date),
            "last_seen": _isoformat(vulnerability.last_seen),
            "asset_criticality": vulnerability.asset_criticality,
            "status": vulnerability.status,
            "risk_score": vulnerability.risk_score,
            "risk_level": vulnerability.risk_level,
            "target_date": _isoformat(vulnerability.target_date),
            "risk_reasons": json.dumps(vulnerability.risk_reasons or {}),
            "metadata": json.dumps(vulnerability.metadata or {}),
        }
        return record

    def _deserialize(self, row: sqlite3.Row) -> Vulnerability:
        return Vulnerability(
            vulnerability_id=row["vulnerability_id"],
            asset_id=row["asset_id"],
            title=row["title"],
            asset_name=row["asset_name"],
            severity=row["severity"],
            cvss_score=row["cvss_score"],
            exploit_available=bool(row["exploit_available"]),
            patch_available=bool(row["patch_available"]),
            published_date=_fromiso(row["published_date"]),
            discovered_date=_fromiso(row["discovered_date"]),
            last_seen=_fromiso(row["last_seen"]),
            asset_criticality=row["asset_criticality"],
            status=row["status"],
            metadata=json.loads(row["metadata"]) if row["metadata"] else {},
            risk_score=row["risk_score"],
            risk_level=row["risk_level"],
            target_date=_fromiso(row["target_date"]),
            risk_reasons=json.loads(row["risk_reasons"]) if row["risk_reasons"] else {},
        )


__all__ = ["VulnerabilityDatabase"]
