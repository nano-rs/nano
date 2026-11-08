"""Real GCP Pub/Sub test resources (REST v1, service-account auth via google-auth)."""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from google.auth.transport.requests import AuthorizedSession
from google.oauth2 import credentials as user_credentials
from google.oauth2 import service_account

from nano_e2e.creds import GcpCreds
from nano_e2e.runid import gc_eligible, owner_tags

_API = "https://pubsub.googleapis.com/v1"
_SCOPES = ["https://www.googleapis.com/auth/pubsub"]


def authed(creds: GcpCreds) -> AuthorizedSession:
    info = json.loads(creds.sa_json)
    if info.get("type") == "authorized_user":
        # gcloud ADC (user credentials): bill quota to the test project.
        # User credentials carry the scopes granted at `gcloud auth
        # application-default login` (cloud-platform); requesting a narrower
        # scope on refresh is rejected with invalid_scope.
        user = user_credentials.Credentials.from_authorized_user_info(info)
        return AuthorizedSession(user.with_quota_project(info.get("quota_project_id") or creds.project))
    sa = service_account.Credentials.from_service_account_info(info, scopes=_SCOPES)
    return AuthorizedSession(sa)


def _ok(resp: Any, *codes: int) -> dict[str, Any]:
    if resp.status_code not in codes:
        raise RuntimeError(
            f"E2E-INFRA: Pub/Sub {resp.request.method} {resp.url} -> {resp.status_code}: {resp.text[:800]}"
        )
    return resp.json() if resp.content else {}


def _labels() -> dict[str, str]:
    return owner_tags()


def delete_verified(s: Any, url: str, attempts: int = 5) -> None:
    """DELETE and verify: 2xx or 404 (already gone) only. Retries 409/429/5xx;
    anything else (e.g. 403) raises, so teardown never reports a phantom
    success while the resource stays billable."""
    for i in range(attempts):
        r = s.delete(url, timeout=30)
        if r.status_code in (200, 204, 404):
            return
        if r.status_code in (409, 429) or r.status_code >= 500:
            time.sleep(2 * (i + 1))
            continue
        break
    raise RuntimeError(f"E2E-INFRA: DELETE {url} -> {r.status_code}: {r.text[:300]}")


@dataclass
class PubSub:
    creds: GcpCreds
    topic: str
    subscription: str
    _s: Any = field(default=None, repr=False)

    @property
    def topic_path(self) -> str:
        return f"projects/{self.creds.project}/topics/{self.topic}"

    @property
    def subscription_path(self) -> str:
        return f"projects/{self.creds.project}/subscriptions/{self.subscription}"

    def create(self) -> PubSub:
        self._s = authed(self.creds)
        _ok(self._s.put(f"{_API}/{self.topic_path}", json={"labels": _labels()}, timeout=30), 200)
        _ok(
            self._s.put(
                f"{_API}/{self.subscription_path}",
                json={
                    "topic": self.topic_path,
                    "ackDeadlineSeconds": 60,
                    "messageRetentionDuration": "3600s",
                    "expirationPolicy": {"ttl": "86400s"},
                    "labels": _labels(),
                },
                timeout=30,
            ),
            200,
        )
        return self

    def publish(self, bodies: list[str]) -> None:
        for i in range(0, len(bodies), 100):
            msgs = [{"data": base64.b64encode(b.encode()).decode()} for b in bodies[i : i + 100]]
            _ok(self._s.post(f"{_API}/{self.topic_path}:publish", json={"messages": msgs}, timeout=30), 200)

    def delete(self) -> None:
        if not self._s:
            return
        delete_verified(self._s, f"{_API}/{self.subscription_path}")
        delete_verified(self._s, f"{_API}/{self.topic_path}")


def gc(
    creds: GcpCreds, older_than: timedelta, exclude_runs: set[str] | frozenset[str] = frozenset()
) -> list[str]:
    cutoff = (datetime.now(UTC) - older_than).timestamp()
    s = authed(creds)
    removed: list[str] = []
    for kind in ("subscriptions", "topics"):
        token = ""
        while True:
            params = {"pageSize": 500, **({"pageToken": token} if token else {})}
            body = _ok(s.get(f"{_API}/projects/{creds.project}/{kind}", params=params, timeout=30), 200)
            for item in body.get(kind, []):
                name = item["name"]
                short = name.rsplit("/", 1)[-1]
                labels = item.get("labels") or {}
                if gc_eligible(short, labels, cutoff_epoch=cutoff, exclude_runs=set(exclude_runs)):
                    delete_verified(s, f"{_API}/{name}")
                    removed.append(name)
            token = body.get("nextPageToken", "")
            if not token:
                break
    return removed
