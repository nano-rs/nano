"""Base smoke: the stack is healthy, an admin can log in, and API keys work
end to end on both services (api + search)."""

from __future__ import annotations

import httpx

from nano_e2e.client import Http, Journal, Nano, expect
from nano_e2e.stack import Stack
from nano_e2e.waits import eventually


def test_health_endpoints(stack: Stack) -> None:
    api = httpx.get(f"{stack.api_url}/health", timeout=10)
    assert api.status_code == 200 and api.json().get("status") == "ok", api.text
    search = httpx.get(f"{stack.search_url}/health", timeout=10)
    assert search.status_code == 200 and search.json().get("status") == "healthy", search.text
    jobs = httpx.get(f"{stack.jobs_url}/health", timeout=10)
    assert jobs.status_code == 200 and jobs.text.strip() == "ok", jobs.text
    ready = httpx.get(f"{stack.api_url}/ready", timeout=10)
    assert ready.status_code == 200, ready.text
    hec = httpx.get(f"{stack.hec_url}/services/collector/health", timeout=10)
    assert hec.status_code == 200, hec.text


def test_setup_initialized_and_capabilities(stack: Stack) -> None:
    status = httpx.get(f"{stack.api_url}/api/setup/status", timeout=10).json()
    assert status.get("initialized") is True, status
    # A second initialize must be refused (first-run endpoint is one-shot).
    again = httpx.post(
        f"{stack.api_url}/api/setup/initialize",
        json={"email": "intruder@e2e.invalid", "name": "x", "password": "Another-Passw0rd!"},
        timeout=10,
    )
    assert again.status_code in (403, 409), again.text
    caps = httpx.get(f"{stack.api_url}/api/capabilities", timeout=10)
    assert caps.status_code == 200, caps.text
    edition = caps.json().get("edition")
    assert edition in (None, stack.edition), f"capabilities edition {edition!r} != stack {stack.edition!r}"


def test_login_and_api_key_lifecycle(stack: Stack, nano: Nano, artifact_dir) -> None:
    # Wrong password: 401, no token.
    bad = nano.api.post(
        "/api/auth/login", json={"email": stack.admin_email, "password": "wrong-password-e2e"}
    )
    assert bad.status_code == 401, bad.text

    jwt = nano.login(stack.admin_email, stack.admin_password)
    session = Http(stack.api_url, {"Authorization": f"Bearer {jwt}"}, Journal(artifact_dir / "api.jsonl"))
    try:
        created = expect(
            session.post(
                "/api/api-keys",
                json={
                    "name": f"e2e-{stack.run_id}-base",
                    "permissions": ["detections:view", "search:execute"],
                },
            ),
            201,
        )
        key, key_id = created["key"], created["id"]

        keyed = Nano(stack.api_url, stack.search_url, {"X-API-Key": key}, Journal(artifact_dir / "api.jsonl"))
        try:
            # The key works on the api and on the search service.
            assert isinstance(expect(keyed.api.get("/api/rules"), 200), list)
            res = keyed.search('"nano-e2e-base-probe-that-matches-nothing"', limit=1, minutes_back=5)
            assert res.get("results") == [] and res.get("total_count", 0) == 0, res

            # Least privilege: a key without settings:system cannot mint ingest tokens.
            denied = keyed.api.post(
                "/api/ingest-tokens",
                json={"name": "x", "source_id": "00000000-0000-0000-0000-000000000000"},
            )
            assert denied.status_code == 403, denied.text

            # An API key cannot mint API keys (session-only endpoint).
            esc = keyed.api.post("/api/api-keys", json={"name": "child", "permissions": []})
            assert esc.status_code in (401, 403), esc.text

            # Delete -> the key stops working.
            expect(session.delete(f"/api/api-keys/{key_id}"), 200, 204)
            eventually(
                lambda: keyed.api.get("/api/rules").status_code,
                timeout=30,
                desc="deleted API key to be rejected",
                ok=lambda s: s == 401,
            )
        finally:
            keyed.close()

        garbage = httpx.get(
            f"{stack.api_url}/api/rules", headers={"X-API-Key": "nano_garbage_key"}, timeout=10
        )
        assert garbage.status_code == 401, garbage.text
    finally:
        session.close()
