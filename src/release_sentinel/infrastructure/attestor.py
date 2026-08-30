from __future__ import annotations

import json
from typing import Any
from urllib.request import Request as UrlRequest, urlopen


class EvidenceAttestorClient:
    def __init__(self, base_url: str, *, audience: str | None = None, timeout_seconds: float = 30.0) -> None:
        value = base_url.rstrip("/")
        if not value.startswith(("http://", "https://")):
            raise ValueError("attestor URL must be http(s)")
        self.base_url = value
        self.audience = audience
        self.timeout_seconds = timeout_seconds

    def _authorization_header(self) -> str | None:
        if not self.audience:
            return None
        try:
            from google.auth.transport.requests import Request
            from google.oauth2 import id_token
        except ImportError as exc:
            raise RuntimeError("google-auth is required for authenticated attestor calls") from exc
        token = id_token.fetch_id_token(Request(), self.audience)
        return f"Bearer {token}"

    def attest_fixture(self, fixture_name: str, *, release_id: str) -> dict[str, Any]:
        headers = {"Content-Type": "application/json"}
        auth = self._authorization_header()
        if auth:
            headers["Authorization"] = auth
        req = UrlRequest(
            f"{self.base_url}/v1/attest/release/{fixture_name}",
            data=json.dumps({"release_id": release_id}, separators=(",", ":")).encode(),
            headers=headers,
            method="POST",
        )
        with urlopen(req, timeout=self.timeout_seconds) as response:
            payload = json.loads(response.read().decode("utf-8"))
        if not payload.get("attested"):
            raise RuntimeError("evidence attestor did not produce a signed bundle")
        return payload
