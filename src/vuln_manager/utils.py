"""Utility helpers shared across the project."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional


def parse_datetime(value: Optional[str]) -> Optional[datetime]:
    """Parse a variety of timestamp representations into :class:`datetime`.

    The CyberCNS API surfaces timestamps in ISO-8601 format with or without
    timezone information. The helper gracefully handles ``None`` values and
    returns timezone-aware datetimes normalised to UTC when possible.
    """

    if not value:
        return None

    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)

    text = value.strip()
    if not text:
        return None

    # Normalise trailing Z designator for UTC
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"

    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def safe_float(value: Optional[object]) -> Optional[float]:
    """Best-effort conversion to float."""

    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return None


__all__ = ["parse_datetime", "safe_float"]
