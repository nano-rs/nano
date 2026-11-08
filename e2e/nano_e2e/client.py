"""HTTP clients for the nano API (nanosiem-api) and search (nanosiem-search).

- Auth: `X-API-Key` (the admin key the runner minted) or a session JWT.
- Retries are infra-only: a request that never reached the server (connection
  refused/reset, connect timeout) is retried with backoff, because a service
  restart in a scenario must not read as a product failure. An HTTP response,
  whatever its status, is never retried: that is the product talking.
- Every exchange is journaled (method, path, status, truncated body, secrets
  redacted) to the test's artifact dir, so a failure has the API story attached.
"""

from __future__ import annotations

import json
import os
import re
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx

from nano_e2e import artifact_guard

# Only failures where the request provably never reached the server: a
# protocol error mid-response could follow a processed POST, and retrying that
# would double-submit.
_INFRA_ERRORS = (httpx.ConnectError, httpx.ConnectTimeout)
_SECRET_KEYS = re.compile(r"(?i)(password|secret|token|key|credentials_json|connection_string|authorization)")


class ApiError(AssertionError):
    """The product returned an unexpected status (E2E-PRODUCT)."""


def _redact(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: ("<redacted>" if _SECRET_KEYS.search(str(k)) else _redact(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_redact(v) for v in obj]
    return obj


def _secret_values() -> list[str]:
    """Values that must never reach an artifact: cloud test credentials and the
    stack's own secrets, whatever key they end up under."""
    pat = re.compile(r"(SECRET|PASSWORD|_KEY|TOKEN|SA_JSON|ADC|CONNECTION_STRING)")
    return sorted(
        (v for k, v in os.environ.items() if pat.search(k) and len(v) >= 12),
        key=len,
        reverse=True,
    )


class Journal:
    """Append-only JSONL of API exchanges for one test (secrets scrubbed)."""

    def __init__(self, path: Path | None):
        self.path = path
        self._secrets = _secret_values()
        if path:
            path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, record: dict[str, Any]) -> None:
        if not self.path:
            return
        line = json.dumps(record, default=str)
        for s in self._secrets:
            line = line.replace(s, "<redacted>").replace(json.dumps(s)[1:-1], "<redacted>")
        with self.path.open("a") as f:
            f.write(line + "\n")


class Http:
    """Thin httpx wrapper: base URL, auth header, infra-only retries, journaling."""

    def __init__(self, base_url: str, headers: dict[str, str], journal: Journal, timeout: float = 60.0):
        self.base_url = base_url.rstrip("/")
        self._client = httpx.Client(base_url=self.base_url, headers=headers, timeout=timeout)
        self.journal = journal

    def close(self) -> None:
        self._client.close()

    def request(self, method: str, path: str, *, retries: int = 5, **kw: Any) -> httpx.Response:
        delay = 1.0
        for attempt in range(retries + 1):
            started = time.monotonic()
            try:
                resp = self._client.request(method, path, **kw)
            except _INFRA_ERRORS as exc:
                self.journal.write({"t": _now(), "method": method, "path": path, "infra_error": repr(exc)})
                if attempt == retries:
                    raise ConnectionError(
                        f"E2E-INFRA: {method} {self.base_url}{path} unreachable: {exc}"
                    ) from exc
                time.sleep(delay)
                delay = min(delay * 2, 10)
                continue
            self._log(method, path, kw, resp, time.monotonic() - started)
            return resp
        raise AssertionError("unreachable")

    def _log(self, method: str, path: str, kw: dict[str, Any], resp: httpx.Response, secs: float) -> None:
        body: Any = kw.get("json")
        try:
            out: Any = resp.json()
        except ValueError:
            out = resp.text[:2000]
        self.journal.write(
            {
                "t": _now(),
                "method": method,
                "path": path,
                "params": kw.get("params"),
                "request": _redact(body),
                "status": resp.status_code,
                "ms": round(secs * 1000),
                "response": _truncate(_redact(out)),
            }
        )

    def get(self, path: str, **kw: Any) -> httpx.Response:
        return self.request("GET", path, **kw)

    def post(self, path: str, **kw: Any) -> httpx.Response:
        return self.request("POST", path, **kw)

    def put(self, path: str, **kw: Any) -> httpx.Response:
        return self.request("PUT", path, **kw)

    def patch(self, path: str, **kw: Any) -> httpx.Response:
        return self.request("PATCH", path, **kw)

    def delete(self, path: str, **kw: Any) -> httpx.Response:
        return self.request("DELETE", path, **kw)


def expect(resp: httpx.Response, *codes: int) -> Any:
    """Assert the status is one of `codes`; return the JSON body (or text)."""
    if resp.status_code not in codes:
        raise ApiError(
            f"{resp.request.method} {resp.request.url.path} -> {resp.status_code} "
            f"(expected {codes}): {resp.text[:1500]}"
        )
    if not resp.content:
        return None
    try:
        return resp.json()
    except ValueError:
        return resp.text


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _truncate(obj: Any, limit: int = 4000) -> Any:
    text = json.dumps(obj, default=str)
    return obj if len(text) <= limit else text[:limit] + "...<truncated>"


def time_range(minutes_back: int = 60, minutes_ahead: int = 10) -> dict[str, str]:
    now = datetime.now(UTC)
    return {
        "start": (now - timedelta(minutes=minutes_back)).isoformat(),
        "end": (now + timedelta(minutes=minutes_ahead)).isoformat(),
    }


class Nano:
    """Domain helpers over the api + search services. One instance per test."""

    def __init__(self, api_url: str, search_url: str, headers: dict[str, str], journal: Journal):
        self.api = Http(api_url, headers, journal)
        self.search_http = Http(search_url, headers, journal)

    def close(self) -> None:
        self.api.close()
        self.search_http.close()

    # ---------------------------------------------------------------- auth
    def login(self, email: str, password: str) -> str:
        body = expect(self.api.post("/api/auth/login", json={"email": email, "password": password}), 200)
        return body["tokens"]["access_token"]

    # ---------------------------------------------------------------- log sources + tokens
    def create_draft_source(self, name: str, route_key: str, parser_vrl: str = "") -> dict[str, Any]:
        return expect(
            self.api.post(
                "/api/log-sources",
                json={
                    "name": name,
                    "description": "nano-e2e scenario source (NAN-4920)",
                    "source_type": "routed",
                    "parser_vrl": parser_vrl,
                    "match_values": [route_key],
                    "lifecycle_status": "draft",
                },
            ),
            200,
            201,
        )

    def delete_source(self, source_id: str) -> None:
        self.api.delete(f"/api/log-sources/{source_id}")

    def issue_token(self, source_id: str, name: str) -> tuple[str, str]:
        """-> (credential_id, raw token)."""
        body = expect(self.api.post("/api/ingest-tokens", json={"name": name, "source_id": source_id}), 201)
        artifact_guard.remember(body["token"])
        return body["credential"]["credential_id"], body["token"]

    def rotate_token(self, credential_id: str) -> tuple[str, str]:
        body = expect(self.api.post(f"/api/ingest-tokens/{credential_id}/rotate"), 201)
        artifact_guard.remember(body["token"])
        return body["credential"]["credential_id"], body["token"]

    def revoke_token(self, credential_id: str) -> None:
        expect(self.api.post(f"/api/ingest-tokens/{credential_id}/revoke"), 200, 409)

    def list_tokens(self) -> dict[str, Any]:
        return expect(self.api.get("/api/ingest-tokens"), 200)

    # ---------------------------------------------------------------- search
    def search(
        self, query: str, *, limit: int = 1000, minutes_back: int = 60, **extra: Any
    ) -> dict[str, Any]:
        body = {
            "query": query,
            "limit": limit,
            "skip_histogram": True,
            "skip_field_stats": True,
            "use_cache": False,
            "time_range": time_range(minutes_back),
            "request_id": f"e2e-{uuid.uuid4().hex[:12]}",
            **extra,
        }
        # x-nano-cache-bypass: a polled query must never be answered from the
        # Dragonfly result cache (the first, empty answer would repeat).
        return expect(
            self.search_http.post("/api/search", json=body, headers={"x-nano-cache-bypass": "1"}), 200
        )

    def rows(self, query: str, **kw: Any) -> list[dict[str, Any]]:
        return self.search(query, **kw).get("results") or []

    # ---------------------------------------------------------------- capabilities
    def source_config_types(self) -> set[str]:
        body = expect(self.api.get("/api/source-configurations/types"), 200)
        items = body if isinstance(body, list) else body.get("types", [])
        return {str(t["config_type"]) for t in items if isinstance(t, dict) and t.get("config_type")}


def row_text(row: dict[str, Any]) -> str:
    """A search row as text, for marker/sequence matching independent of which
    column (message, raw, ext) the value landed in."""
    return json.dumps(row, default=str, sort_keys=True)
