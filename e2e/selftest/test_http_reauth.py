"""Long-lived JWT clients re-authenticate once on a 401, and only when the
Bearer JWT they sent has expired (NAN-5827): the RBAC matrix admin outlived
its 15 min access token and its cleanup DELETEs 401'd. Every other 401 (bad
credentials, revoked session, invalid token) must reach the test unchanged."""

from __future__ import annotations

import base64
import json
import time

import httpx
import pytest

from nano_e2e.client import Http, Journal, bearer_jwt_expired

API = "http://127.0.0.1:5555"


def _jwt(exp: float | None, **extra: object) -> str:
    def seg(obj: dict[str, object]) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    claims: dict[str, object] = {"sub": "u1", **extra}
    if exp is not None:
        claims["exp"] = exp
    return f"{seg({'alg': 'HS256', 'typ': 'JWT'})}.{seg(claims)}.sig"


FRESH = _jwt(time.time() + 900)
EXPIRED = _jwt(time.time() - 5)


def _http(sent: str, accepted: str) -> tuple[Http, list[str]]:
    """An Http that starts with Bearer `sent`; the server accepts only `accepted`."""
    seen: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        auth = req.headers.get("Authorization", "")
        seen.append(auth)
        if auth == f"Bearer {accepted}":
            return httpx.Response(204)
        return httpx.Response(401, json={"error": "unauthorized"})

    http = Http(API, {}, Journal(None))
    http._client = httpx.Client(base_url=API, headers={"Authorization": f"Bearer {sent}"},
                                transport=httpx.MockTransport(handler))
    return http, seen


def test_an_expired_token_is_replaced_and_the_request_retried_once() -> None:
    new = _jwt(time.time() + 900, n=2)
    http, seen = _http(EXPIRED, new)
    calls: list[int] = []
    http.reauth = lambda: calls.append(1) or {"Authorization": f"Bearer {new}"}
    assert http.delete("/api/rules/r1").status_code == 204
    assert calls == [1]
    assert seen == [f"Bearer {EXPIRED}", f"Bearer {new}"]
    # The new token sticks: the next call needs no second login.
    assert http.delete("/api/rules/r2").status_code == 204
    assert calls == [1]


def test_a_401_on_a_fresh_token_is_not_retried() -> None:
    """Revoked session, bad credentials, invalid token: surfaced, not masked."""
    http, seen = _http(FRESH, "never")
    calls: list[int] = []
    http.reauth = lambda: calls.append(1) or {"Authorization": f"Bearer {_jwt(time.time() + 900, n=2)}"}
    assert http.get("/api/roles").status_code == 401
    assert calls == []
    assert seen == [f"Bearer {FRESH}"]


@pytest.mark.parametrize("auth", ["Bearer not-a-jwt", "Bearer a.%%%.c", "Basic dXNlcjpwYXNz", ""])
def test_a_401_on_an_undecodable_credential_is_not_retried(auth: str) -> None:
    http = Http(API, {}, Journal(None))
    seen: list[str] = []
    http._client = httpx.Client(
        base_url=API, headers={"Authorization": auth} if auth else {},
        transport=httpx.MockTransport(lambda r: seen.append(r.headers.get("Authorization", ""))
                                      or httpx.Response(401)))
    calls: list[int] = []
    http.reauth = lambda: calls.append(1) or {"Authorization": "Bearer x"}
    assert http.get("/api/roles").status_code == 401
    assert calls == [] and len(seen) == 1


def test_an_expired_token_whose_relogin_still_401s_is_retried_only_once() -> None:
    http, seen = _http(EXPIRED, "never")
    calls: list[int] = []
    http.reauth = lambda: calls.append(1) or {"Authorization": f"Bearer {_jwt(time.time() - 1, n=2)}"}
    assert http.get("/api/roles").status_code == 401
    assert calls == [1]
    assert len(seen) == 2


def test_without_reauth_a_401_is_returned_as_is() -> None:
    http, seen = _http(EXPIRED, FRESH)
    assert http.get("/api/roles").status_code == 401
    assert seen == [f"Bearer {EXPIRED}"]


def test_expiry_check_honors_the_skew_window() -> None:
    now = 1_000_000.0
    assert bearer_jwt_expired(f"Bearer {_jwt(now + 10)}", now=now)        # inside 30 s of exp
    assert not bearer_jwt_expired(f"Bearer {_jwt(now + 120)}", now=now)
    assert bearer_jwt_expired(f"Bearer {_jwt(now - 1)}", now=now)
    assert not bearer_jwt_expired(f"Bearer {_jwt(None)}", now=now)        # no exp claim
    assert not bearer_jwt_expired(f"Bearer {_jwt('soon')}", now=now)      # non-numeric exp
    assert not bearer_jwt_expired(None, now=now)
