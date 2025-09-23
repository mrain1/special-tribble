"""HTTP client for interacting with the CyberCNS API."""
from __future__ import annotations

import time
from typing import Dict, Iterator, List, Optional
from urllib.parse import urljoin

try:  # pragma: no cover - optional dependency handled at runtime
    import requests
except ModuleNotFoundError:  # pragma: no cover
    requests = None  # type: ignore[assignment]

from .config import APIConfig


class CyberCNSClient:
    """Lightweight wrapper around the CyberCNS REST API."""

    def __init__(self, config: APIConfig):
        if requests is None:
            raise ModuleNotFoundError("The 'requests' package is required to use the API client. Install it with 'pip install requests'.")
        self.config = config
        self._session = requests.Session()
        self._session.headers.update(
            {
                "Authorization": f"Bearer {config.token}",
                "Accept": "application/json",
                "User-Agent": "vuln-manager/0.1",
            }
        )

    def close(self) -> None:
        self._session.close()

    def __enter__(self) -> "CyberCNSClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # type: ignore[override]
        self.close()

    def _url(self) -> str:
        base = self.config.base_url.rstrip("/") + "/"
        endpoint = self.config.endpoint.lstrip("/")
        return urljoin(base, endpoint)

    def fetch_page(
        self,
        page: int = 1,
        page_size: Optional[int] = None,
        params: Optional[Dict[str, object]] = None,
    ) -> Dict[str, object]:
        """Fetch a single page of vulnerabilities from the API."""

        query: Dict[str, object] = dict(self.config.additional_params)
        if params:
            query.update(params)

        # Provide multiple pagination parameter spellings to satisfy the API
        query.setdefault("page", page)
        query.setdefault("pageNumber", page)
        if page_size is None:
            page_size = self.config.page_size
        query.setdefault("pageSize", page_size)
        query.setdefault("page_size", page_size)

        response = self._session.get(
            self._url(),
            params=query,
            verify=self.config.verify_ssl,
            timeout=30,
        )
        response.raise_for_status()
        return response.json()

    def iter_vulnerabilities(
        self,
        params: Optional[Dict[str, object]] = None,
    ) -> Iterator[Dict[str, object]]:
        page = 1
        page_size = self.config.page_size
        while True:
            payload = self.fetch_page(page=page, page_size=page_size, params=params)
            items = self._extract_items(payload)
            if not items:
                break
            for record in items:
                yield record
            if len(items) < page_size:
                break
            page += 1
            if self.config.rate_limit_sleep:
                time.sleep(self.config.rate_limit_sleep)

    @staticmethod
    def _extract_items(payload: Dict[str, object]) -> List[Dict[str, object]]:
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        if not isinstance(payload, dict):
            return []
        for key in ("items", "data", "records", "vulnerabilities"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
        return []


__all__ = ["CyberCNSClient"]
