"""Phase-2 plumbing (NAN-4937), without a stack or cloud credentials:

- web: the SPA server routes like vite.config.ts / nginx, never serves a file
  outside dist, and streams proxied responses (SSE) instead of buffering them;
- mock-vendor: every mocked vendor route is one the spec's host policy admits
  (checked against nano-connector/specs), credentials are enforced, paging is
  forced, and the GWS service-account JWT is verified;
- firstrun: the deferred admin key is written back into stack.env (0600);
- the runner: `ui` is a suite, `--profile` validates, mock-vendor needs native
  mode, and the connector env holds the lab seam and no secrets.
"""

from __future__ import annotations

import base64
import http.client
import json
import os
import stat
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import yaml
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from nano_e2e import firstrun
from nano_e2e.mockvendor import GWS_SCOPE, GWS_TOKEN_URL, GwsServiceAccount, MockVendor, MockVendorServer
from nano_e2e.web import WebServer, route, static_file

# ---------------------------------------------------------------- web


@pytest.mark.parametrize(
    ("path", "want"),
    [
        ("/api/search", "search"),
        ("/api/search/stream", "search"),
        ("/api/search/history", "api"),
        ("/api/search/shared/abc", "api"),
        ("/api/search/explanation", "api"),
        ("/api/log-sources", "api"),
        ("/health", "api"),
        ("/swagger-ui/index.html", "api"),
        ("/search", None),
        ("/assets/index.js", None),
    ],
)
def test_web_routes_like_vite(path: str, want: str | None) -> None:
    assert route(path) == want


def test_web_static_never_escapes_dist(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<html>")
    (dist / "assets" / "a.js").write_text("x")
    (tmp_path / "secret.txt").write_text("no")
    assert static_file(dist, "/assets/a.js") == (dist / "assets" / "a.js").resolve()
    assert static_file(dist, "/../secret.txt").name == "index.html"
    assert static_file(dist, "/assets/../../secret.txt").name == "index.html"
    assert static_file(dist, "/search").name == "index.html"  # SPA fallback


class _Upstream(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a: object) -> None:
        pass

    def do_GET(self) -> None:  # noqa: N802
        if self.path.startswith("/api/search/stream"):
            # SSE without a length: chunks must reach the client one by one.
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Connection", "close")
            self.end_headers()
            for i in range(3):
                self.wfile.write(f"data: {i}\n\n".encode())
                self.wfile.flush()
                time.sleep(0.3)
            self.close_connection = True
            return
        name = getattr(self.server, "name", "")
        body = json.dumps({"svc": name, "path": self.path, "auth": self.headers.get("X-API-Key")}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _upstream(name: str) -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Upstream)
    srv.name = name  # type: ignore[attr-defined]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_web_proxies_and_streams(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text("<html>spa</html>")
    api, search = _upstream("api"), _upstream("search")
    web = WebServer(
        dist, f"http://127.0.0.1:{api.server_address[1]}", f"http://127.0.0.1:{search.server_address[1]}"
    ).start()
    try:
        host, port = web.url.removeprefix("http://").split(":")
        c = http.client.HTTPConnection(host, int(port), timeout=10)
        c.request("GET", "/api/rules", headers={"X-API-Key": "k"})
        r = json.loads(c.getresponse().read())
        assert r == {"svc": "api", "path": "/api/rules", "auth": "k"}
        c.request("GET", "/api/search/history")
        assert json.loads(c.getresponse().read())["svc"] == "api"
        c.request("GET", "/search?q=x")
        assert c.getresponse().read() == b"<html>spa</html>"
        c.close()
        c = http.client.HTTPConnection(host, int(port), timeout=10)
        c.request("GET", "/api/search/stream")
        resp = c.getresponse()
        t0 = time.monotonic()
        first = resp.read1(64)
        assert first.startswith(b"data: 0"), first
        assert time.monotonic() - t0 < 0.5, "the proxy buffered the stream instead of passing it through"
        rest = resp.read()
        assert b"data: 2" in first + rest
    finally:
        web.stop()
        api.shutdown()
        search.shutdown()


# ---------------------------------------------------------------- mock-vendor

SPECS = Path(__file__).resolve().parents[2] / "nano-connector" / "specs"


def _call(
    mock: MockVendor, method: str, host: str, target: str, headers: dict | None = None, body: bytes = b""
):
    return mock.handle(method, host, target, {k.lower(): v for k, v in (headers or {}).items()}, body)


def test_mock_routes_are_admitted_by_the_specs() -> None:
    """Drift guard: each (host, path) the mock serves must be allowed by the
    connector spec, or the runner would never send it there."""
    if not SPECS.is_dir():
        pytest.skip("nano-connector/specs not in this tree")
    allow: list[tuple[str, list[str], list[str]]] = []
    for f in SPECS.glob("*.yaml"):
        for a in yaml.safe_load(f.read_text()).get("allow", []):
            allow.append((a["host"], a.get("host_suffixes", []), a.get("path_prefixes", [])))

    def admitted(host: str, path: str) -> bool:
        for h, suffixes, prefixes in allow:
            host_ok = host == h or (h.startswith("{{") and any(host.endswith(s) for s in suffixes))
            if host_ok and any(path.startswith(p) for p in prefixes):
                return True
        return False

    served = [
        ("e2e-x.okta.com", "/api/v1/logs"),
        ("oauth2.googleapis.com", "/token"),
        ("admin.googleapis.com", "/admin/reports/v1/activity/users/all/applications/login"),
        ("slack.com", "/api/team.accessLogs"),
        ("e2e-x.goskope.com", "/api/v2/events/dataexport/events/application"),
    ]
    for host, path in served:
        assert admitted(host, path), f"mock route {host}{path} is not admitted by any connector spec"


def test_mock_okta_auth_window_and_link_paging() -> None:
    m = MockVendor(page_size=2)
    m.okta_tenant("t.okta.com", "tok123")
    m.okta_add("t.okta.com", [{"uuid": str(i), "published": f"2026-11-03T10:00:0{i}.000Z"} for i in range(5)])
    assert _call(m, "GET", "t.okta.com", "/api/v1/logs", {"Authorization": "SSWS nope"})[0] == 401
    q = "/api/v1/logs?since=2026-11-03T10:00:01Z&until=2026-11-03T10:00:09Z&limit=1000"
    got, nxt = [], q
    while nxt:
        status, hdrs, page = _call(m, "GET", "t.okta.com", nxt, {"Authorization": "SSWS tok123"})
        assert status == 200
        got += [e["uuid"] for e in page]
        link = hdrs.get("Link", "")
        assert not link or link.startswith("<https://t.okta.com/api/v1/logs?")  # policy-checkable next URL
        nxt = link[len("<https://t.okta.com") : link.index(">")] if link else ""
    assert got == ["1", "2", "3", "4"]  # window [since, until), ascending, every page


def test_mock_gws_verifies_the_service_account_jwt() -> None:
    m = MockVendor(page_size=1)
    sa = GwsServiceAccount.generate("e2e@x.iam.gserviceaccount.com")
    m.gws_account(sa, "admin@e2e.invalid")
    m.gws_add(
        "login", [{"id": {"time": f"2026-11-03T10:00:0{i}Z", "uniqueQualifier": str(i)}} for i in range(3)]
    )
    key = serialization.load_pem_private_key(sa.private_key_pem.encode(), None)

    def jwt(claims: dict, signer=key) -> str:
        enc = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()  # noqa: E731
        head = f"{enc({'alg': 'RS256', 'typ': 'JWT'})}.{enc(claims)}"
        sig = signer.sign(head.encode(), padding.PKCS1v15(), hashes.SHA256())  # type: ignore[union-attr]
        return head + "." + base64.urlsafe_b64encode(sig).rstrip(b"=").decode()

    now = int(time.time())
    claims = {
        "iss": sa.client_email,
        "scope": GWS_SCOPE,
        "aud": GWS_TOKEN_URL,
        "iat": now,
        "exp": now + 3600,
        "sub": "admin@e2e.invalid",
    }

    def form(a: str) -> bytes:
        return f"grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion={a}".encode()

    other = GwsServiceAccount.generate(sa.client_email)
    other_key = serialization.load_pem_private_key(other.private_key_pem.encode(), None)
    assert _call(m, "POST", "oauth2.googleapis.com", "/token", body=form(jwt(claims, other_key)))[0] == 400
    assert (
        _call(m, "POST", "oauth2.googleapis.com", "/token", body=form(jwt({**claims, "sub": "x@y"})))[0]
        == 401
    )
    status, _, tok = _call(m, "POST", "oauth2.googleapis.com", "/token", body=form(jwt(claims)))
    assert status == 200, tok
    path = (
        "/admin/reports/v1/activity/users/all/applications/login"
        "?startTime=2026-11-03T10:00:00Z&endTime=2026-11-03T11:00:00Z"
    )
    status, _, page = _call(
        m, "GET", "admin.googleapis.com", path, {"Authorization": f"Bearer {tok['access_token']}"}
    )
    assert status == 200 and len(page["items"]) == 1 and page["nextPageToken"] == "1"
    assert page["items"][0]["id"]["uniqueQualifier"] == "2"  # newest first
    assert _call(m, "GET", "admin.googleapis.com", path, {"Authorization": "Bearer bogus"})[0] == 401


def test_mock_slack_cursor_and_netskope_iterator() -> None:
    m = MockVendor(page_size=2)
    m.slack_add("xoxp-1", [{"date_last": i, "user_id": str(i)} for i in range(3)])
    _, _, p1 = _call(
        m, "GET", "slack.com", "/api/team.accessLogs?limit=200", {"Authorization": "Bearer xoxp-1"}
    )
    assert [r["date_last"] for r in p1["logins"]] == [2, 1] and p1["response_metadata"]["next_cursor"] == "2"
    _, _, p2 = _call(
        m, "GET", "slack.com", "/api/team.accessLogs?cursor=2", {"Authorization": "Bearer xoxp-1"}
    )
    assert [r["date_last"] for r in p2["logins"]] == [0] and p2["response_metadata"]["next_cursor"] == ""
    assert (
        _call(m, "GET", "slack.com", "/api/team.accessLogs", {"Authorization": "Bearer bad"})[2]["ok"]
        is False
    )

    m.netskope_tenant("t.goskope.com", "nsk")
    m.netskope_add("t.goskope.com", "application", [{"_id": str(i), "timestamp": 100 + i} for i in range(3)])
    base = "/api/v2/events/dataexport/events/application?index=nano_application&operation="
    hdr = {"Netskope-Api-Token": "nsk"}
    assert _call(m, "GET", "t.goskope.com", base + "100", {"Netskope-Api-Token": "x"})[0] == 403
    ids = lambda r: [e["_id"] for e in r[2]["result"]]  # noqa: E731
    assert ids(_call(m, "GET", "t.goskope.com", base + "100", hdr)) == ["0", "1"]
    assert ids(_call(m, "GET", "t.goskope.com", base + "resend", hdr)) == ["0", "1"]  # same page again
    assert ids(_call(m, "GET", "t.goskope.com", base + "next", hdr)) == ["2"]
    assert ids(_call(m, "GET", "t.goskope.com", base + "next", hdr)) == []


def test_mock_server_binds_loopback_and_records() -> None:
    srv = MockVendorServer(port=0).start()
    try:
        assert srv.url.startswith("http://127.0.0.1:")
        host, port = srv.url.removeprefix("http://").split(":")
        c = http.client.HTTPConnection(host, int(port), timeout=5)
        c.request("GET", "/api/v1/logs", headers={"x-mock-host": "nobody.okta.com"})
        assert c.getresponse().status == 401
        assert srv.mock.hits("okta.com", "/api/v1/logs")[0].status == 401
        with pytest.raises(RuntimeError, match="cannot bind"):
            MockVendorServer(port=int(port))
    finally:
        srv.stop()


# ---------------------------------------------------------------- firstrun


def test_firstrun_writes_the_key_back(tmp_path: Path) -> None:
    env = tmp_path / "stack.env"
    env.write_text("E2E_RUN_ID=x\nNANOSIEM_API_KEY=\nE2E_ADMIN_DEFERRED=1\nOTHER=1\n")
    firstrun._rewrite_stack_env(env, "nano_k")
    assert env.read_text().splitlines() == [
        "E2E_RUN_ID=x",
        "NANOSIEM_API_KEY=nano_k",
        "E2E_ADMIN_DEFERRED=done",
        "OTHER=1",
    ]
    assert stat.S_IMODE(env.stat().st_mode) == 0o600


def test_firstrun_is_a_noop_unless_deferred(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("E2E_ADMIN_DEFERRED", raising=False)
    assert firstrun.ensure_admin().deferred is False


# ---------------------------------------------------------------- runner


def _bash(runner: Path, script: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", "-c", f'set -euo pipefail; source "{runner}" "$@"; {script}', "e2e.sh", *[]],
        env={**os.environ, **(env or {})},
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def test_runner_ui_suite_and_selection(runner: Path) -> None:
    out = _bash(
        runner,
        "POSITIONAL=(ui); suite_paths; selects_suite ui && echo SEL; selects_suite pull || echo NOPULL",
    )
    assert out.returncode == 0, out.stderr
    lines = out.stdout.splitlines()
    assert lines[0].endswith("/e2e/tests/ui")
    # enterprise UI scenarios ride along, not coverage-gated (`+` companion)
    if (Path(runner).parents[1] / "e2e" / "tests" / "enterprise" / "ui").is_dir():  # stripped in open core
        assert any(x.startswith("+") and x.endswith("/e2e/tests/enterprise/ui") for x in lines), lines
    assert "SEL" in out.stdout and "NOPULL" in out.stdout
    out = _bash(runner, "POSITIONAL=(all); selects_suite pull && selects_suite ui && echo BOTH")
    assert "BOTH" in out.stdout


def test_runner_profile_validation(runner: Path) -> None:
    bad = subprocess.run(
        ["bash", str(runner), "status", "--profile", "nope"], capture_output=True, text=True, timeout=30
    )
    assert bad.returncode != 0 and "unknown --profile" in bad.stderr
    docker = subprocess.run(
        ["bash", str(runner), "up", "--app", "docker", "--profile", "mock-vendor"],
        capture_output=True,
        text=True,
        timeout=60,
        env={**os.environ, "E2E_NEW_RUN_ID": "sel-0000aaaa"},
    )
    assert docker.returncode != 0
    assert "needs --app native" in docker.stderr or "docker daemon not reachable" in docker.stderr
    # never left anything behind
    root = Path(runner).parents[1]
    assert not (root / "target" / "e2e" / "sel-0000aaaa" / "compose.env").exists()


def test_runner_connector_env_is_the_lab_seam_without_secrets(runner: Path, tmp_path: Path) -> None:
    run = tmp_path / "run"
    (run / "pids").mkdir(parents=True)
    (run / "run.env").write_text("E2E_HEC_PORT=4001\nE2E_MOCK_VENDOR_PORT=4002\nE2E_PROFILES=mock-vendor\n")
    out = _bash(
        runner,
        f'RUN_DIR="{run}"; PROJECT=nanoe2e-x; write_connector_env; run_has_profile mock-vendor && echo ON',
    )
    assert out.returncode == 0, out.stderr
    env = (run / "connector.env").read_text()
    assert "CONNECTOR_TEST_MODE=1" in env
    assert "CONNECTOR_TEST_MOCK_URL=http://127.0.0.1:4002" in env
    assert "CONNECTOR_HEC_URL=http://127.0.0.1:4001" in env
    assert not any(w in env for w in ("PASSWORD", "SECRET", "TOKEN=", "ENCRYPTION_KEY"))
    assert stat.S_IMODE((run / "connector.env").stat().st_mode) == 0o600
    assert "ON" in out.stdout


def test_ui_driver_env_has_no_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    from nano_e2e import ui

    monkeypatch.setenv("NANO_E2E_AZURE_CLIENT_SECRET", "azure-secret-value-123")
    monkeypatch.setenv("NANO_ADMIN_PASSWORD", "admin-password-value-123")
    monkeypatch.setenv("DATABASE_URL", "postgres://u:pw@h/db")
    env = ui.driver_env("http://127.0.0.1:1")
    assert env["E2E_UI_BASE"] == "http://127.0.0.1:1"
    assert not {"NANO_E2E_AZURE_CLIENT_SECRET", "NANO_ADMIN_PASSWORD", "DATABASE_URL"} & set(env)


def _chrome() -> bool:
    import shutil as _sh

    cands = [
        os.environ.get("CHROME_PATH", ""),
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/usr/bin/google-chrome",
        "/usr/bin/chromium",
    ]
    return bool(_sh.which("node")) and any(c and os.path.exists(c) for c in cands)


def test_ui_driver_protocol_and_artifact_scrub(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The real driver against a static page: finder ops work, a failure
    writes artifacts, and a secret on the page or typed into a field never
    reaches them."""
    from nano_e2e import ui

    if not _chrome() or not (ui.WEB / "node_modules" / "puppeteer-core").is_dir():
        pytest.skip("needs node, nanosiem-web/node_modules/puppeteer-core and a local Chrome")
    secret = "s3cr3t-value-for-selftest-0001"
    monkeypatch.setenv("NANO_E2E_SELFTEST_SECRET", secret)
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text(
        "<html><body><main><h1>e2e selftest</h1><label for=k>API key *</label><input id=k>"
        f"<button aria-label='Go'>go</button><p data-testid=leak>{secret}</p></main></body></html>"
    )
    api = _upstream("api")
    web = WebServer(
        dist, f"http://127.0.0.1:{api.server_address[1]}", f"http://127.0.0.1:{api.server_address[1]}"
    )
    web.start()
    driver = ui.Driver(web.url, tmp_path / "driver.log")
    try:
        page = ui.UiPage.open(driver, tmp_path / "ui", "selftest")
        page.goto("/anything")  # SPA fallback
        page.wait_for({"role": "heading", "name": "e2e selftest"})
        assert page.count({"role": "button", "name": "Go"}) == 1
        page.fill(ui.field({"role": "textbox", "name": "API key *"}, "typed-secret-0002-xyz", secret=True))
        with pytest.raises(ui.UiError):
            page.click({"role": "button", "name": "does-not-exist"}, timeout_ms=500)
        page.finish(failed=True)
        out = tmp_path / "ui"
        assert (out / "failure.png").is_file() and (out / "page.html").is_file()
        blob = "".join(f.read_text(errors="replace") for f in out.glob("*") if f.suffix != ".png")
        # Masked on the page before capture (bullets), scrubbed in text otherwise.
        assert secret not in blob and ("<redacted>" in blob or "\u2022" * 8 in blob)
        assert "typed-secret-0002-xyz" not in blob
    finally:
        driver.close()
        web.stop()
        api.shutdown()


def test_mock_netskope_serves_events_added_after_open() -> None:
    m = MockVendor(page_size=2)
    m.netskope_tenant("t.goskope.com", "nsk")
    m.netskope_add("t.goskope.com", "application", [{"_id": "a", "timestamp": 100}])
    base = "/api/v2/events/dataexport/events/application?index=nano_application&operation="
    hdr = {"Netskope-Api-Token": "nsk"}
    ids = lambda r: [e["_id"] for e in r[2]["result"]]  # noqa: E731
    assert ids(_call(m, "GET", "t.goskope.com", base + "100", hdr)) == ["a"]
    assert ids(_call(m, "GET", "t.goskope.com", base + "next", hdr)) == []
    m.netskope_add("t.goskope.com", "application", [{"_id": "b", "timestamp": 200}])
    assert ids(_call(m, "GET", "t.goskope.com", base + "next", hdr)) == ["b"]


def test_mock_okta_cursor_survives_events_added_mid_walk() -> None:
    m = MockVendor(page_size=2)
    m.okta_tenant("t.okta.com", "tok123")
    m.okta_add(
        "t.okta.com", [{"uuid": str(i), "published": f"2026-11-03T10:00:0{i}.000Z"} for i in (1, 3, 5)]
    )
    auth = {"Authorization": "SSWS tok123"}
    _, hdrs, p1 = _call(m, "GET", "t.okta.com", "/api/v1/logs?limit=1000", auth)
    # an earlier-dated event lands between pages: the cursor neither repeats nor skips
    m.okta_add("t.okta.com", [{"uuid": "2", "published": "2026-11-03T10:00:02.000Z"}])
    nxt = hdrs["Link"][len("<https://t.okta.com") : hdrs["Link"].index(">")]
    _, _, p2 = _call(m, "GET", "t.okta.com", nxt, auth)
    assert [e["uuid"] for e in p1] == ["1", "3"] and [e["uuid"] for e in p2] == ["5"]
