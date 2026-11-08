"""mock-vendor: a local HTTP mock of the SaaS APIs the connector feeds poll
(NAN-4937). Shaped from `nano-connector/specs/*.yaml`:

| connector (slug)   | vendor host(s)                               | spec                    |
|--------------------|----------------------------------------------|-------------------------|
| `okta_system_log`  | `<OKTA_DOMAIN>` (suffix `.okta.com`)         | okta_system_log.yaml    |
| `google_workspace` | `oauth2.googleapis.com`, `admin.googleapis.com` | google_workspace.yaml |
| `slack`            | `slack.com`                                  | slack.yaml              |
| `netskope` (`saas_api` provider) | `<TENANT_HOST>` (suffix `.goskope.com`) | netskope.yaml   |

How nano reaches it: the runner's sanctioned lab seam, `CONNECTOR_TEST_MODE=1`
+ `CONNECTOR_TEST_MOCK_URL=http://127.0.0.1:<port>` (nano-connector-runner.rs,
loopback.rs). Every request first passes the spec's own vendor host policy
(https, vendor host suffix, path prefix), then goes over plain HTTP to this
mock with the original host in `x-mock-host`. The SSRF guard is not relaxed;
the mock only ever sees requests a real tenant would also have allowed.

The mock checks credentials the way the vendor does (SSWS token, bearer,
API-token header, RS256 service-account JWT verified against the seeded key),
filters by the requested window, and pages (Okta `Link: rel="next"`, Google
`nextPageToken`, Slack `response_metadata.next_cursor`, Netskope server-side
iterator), with a small page size so paging is always exercised.

It runs in a daemon thread inside the pytest process (port pre-allocated by
`scripts/e2e.sh up --profile mock-vendor` as E2E_MOCK_VENDOR_PORT, because the
runner is started with the URL).
"""

from __future__ import annotations

import base64
import json
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

GWS_TOKEN_URL = "https://oauth2.googleapis.com/token"  # noqa: S105 - a URL, not a secret
GWS_SCOPE = "https://www.googleapis.com/auth/admin.reports.audit.readonly"


def parse_ts(value: str) -> datetime:
    """RFC 3339 (the engine renders `{{window.*}}` this way) -> aware datetime."""
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


@dataclass
class GwsServiceAccount:
    """A throwaway RSA service-account key: the connector signs its JWT
    assertion with PRIVATE_KEY; the mock verifies it with the public half."""

    client_email: str
    private_key_pem: str
    public_key: Any

    @classmethod
    def generate(cls, client_email: str) -> GwsServiceAccount:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ).decode()
        return cls(client_email=client_email, private_key_pem=pem, public_key=key.public_key())

    def credentials_json(self) -> str:
        return json.dumps(
            {
                "type": "service_account",
                "client_email": self.client_email,
                "private_key": self.private_key_pem,
                "token_uri": GWS_TOKEN_URL,
            }
        )


def verify_jwt(assertion: str, sa: GwsServiceAccount) -> dict[str, Any]:
    """Verify an RS256 JWT bearer assertion; returns its claims or raises ValueError."""
    try:
        h64, p64, s64 = assertion.split(".")
    except ValueError as exc:
        raise ValueError("assertion is not a JWT") from exc
    header = json.loads(_b64url_decode(h64))
    if header.get("alg") != "RS256":
        raise ValueError(f"alg {header.get('alg')!r} != RS256")
    try:
        sa.public_key.verify(
            _b64url_decode(s64), f"{h64}.{p64}".encode(), padding.PKCS1v15(), hashes.SHA256()
        )
    except Exception as exc:  # noqa: BLE001 - cryptography raises InvalidSignature
        raise ValueError("bad signature") from exc
    claims = json.loads(_b64url_decode(p64))
    now = time.time()
    if not (claims.get("iat", 0) - 300 <= now <= claims.get("exp", 0) + 300):
        raise ValueError("assertion expired or not yet valid")
    return claims


@dataclass
class Recorded:
    host: str
    method: str
    path: str
    query: dict[str, list[str]]
    status: int
    t: float = field(default_factory=time.time)


class MockVendor:
    """State + routing for every mocked vendor. Thread-safe."""

    def __init__(self, page_size: int = 2):
        self.page_size = page_size
        self.lock = threading.Lock()
        self.requests: list[Recorded] = []
        # Okta: domain -> (token, events)
        self.okta: dict[str, dict[str, Any]] = {}
        # GWS: client_email -> service account; issued bearer tokens
        self.gws_accounts: dict[str, GwsServiceAccount] = {}
        self.gws_subjects: set[str] = set()
        self.gws_tokens: dict[str, str] = {}
        self.gws_events: dict[str, list[dict[str, Any]]] = {}
        # Slack: token -> logins
        self.slack: dict[str, list[dict[str, Any]]] = {}
        # Netskope: tenant host -> {token, events by item, iterators}
        self.netskope: dict[str, dict[str, Any]] = {}
        # Destructive vendor actions (SOAR) are recorded, never performed.
        self.actions: list[dict[str, Any]] = []
        # Optional pacing hook for Okta log pages: called (outside the lock,
        # before the page is built) with (domain, index of this request for
        # that domain). A scenario uses it to hold a page until something it
        # is racing (e.g. a Vector reload) has happened; it must return well
        # inside the runner's 30 s response-header timeout.
        self.okta_page_gate: Callable[[str, int], None] | None = None
        self._okta_page_requests: dict[str, int] = {}

    # ------------------------------------------------------------ seeding
    def okta_tenant(self, domain: str, token: str) -> None:
        with self.lock:
            self.okta.setdefault(domain, {"token": token, "events": []})["token"] = token

    def okta_add(self, domain: str, events: list[dict[str, Any]]) -> None:
        with self.lock:
            self.okta[domain]["events"].extend(events)

    def gws_account(self, sa: GwsServiceAccount, admin_email: str) -> None:
        with self.lock:
            self.gws_accounts[sa.client_email] = sa
            self.gws_subjects.add(admin_email)

    def gws_add(self, application: str, items: list[dict[str, Any]]) -> None:
        with self.lock:
            self.gws_events.setdefault(application, []).extend(items)

    def slack_add(self, token: str, logins: list[dict[str, Any]]) -> None:
        with self.lock:
            self.slack.setdefault(token, []).extend(logins)

    def netskope_tenant(self, host: str, token: str) -> None:
        with self.lock:
            self.netskope.setdefault(host, {"token": token, "events": {}, "iters": {}})["token"] = token

    def netskope_add(self, host: str, item: str, events: list[dict[str, Any]]) -> None:
        with self.lock:
            self.netskope[host]["events"].setdefault(item, []).extend(events)

    def hits(self, host_suffix: str = "", path_prefix: str = "") -> list[Recorded]:
        with self.lock:
            return [
                r for r in self.requests if r.host.endswith(host_suffix) and r.path.startswith(path_prefix)
            ]

    # ------------------------------------------------------------ dispatch
    def handle(
        self, method: str, host: str, target: str, headers: dict[str, str], body: bytes
    ) -> tuple[int, dict[str, str], Any]:
        u = urlsplit(target)
        q = parse_qs(u.query, keep_blank_values=True)
        auth = headers.get("authorization", "")
        if host.endswith((".okta.com", ".oktapreview.com")):
            if u.path == "/api/v1/logs" and method == "GET":
                return self._okta_logs(host, q, auth)
            if u.path.startswith("/api/v1/users/") and method == "POST":
                return self._record_action("okta", host, method, u.path, auth)
        elif host == "oauth2.googleapis.com" and u.path == "/token" and method == "POST":
            return self._gws_token(body)
        elif host == "admin.googleapis.com" and u.path.startswith(
            "/admin/reports/v1/activity/users/all/applications/"
        ):
            return self._gws_activities(u.path.rsplit("/", 1)[-1], q, auth)
        elif host == "slack.com" and u.path == "/api/team.accessLogs":
            return self._slack_access_logs(q, auth)
        elif host.endswith(".goskope.com") and u.path.startswith("/api/v2/events/dataexport/events/"):
            return self._netskope(host, u.path.rsplit("/", 1)[-1], q, headers.get("netskope-api-token", ""))
        return 404, {}, {"error": f"mock-vendor: no route for {method} {host}{u.path}"}

    # ------------------------------------------------------------ okta
    def _okta_logs(self, host: str, q: dict[str, list[str]], auth: str) -> tuple[int, dict[str, str], Any]:
        with self.lock:
            index = self._okta_page_requests.get(host, 0)
            self._okta_page_requests[host] = index + 1
            gate = self.okta_page_gate
        if gate is not None:
            gate(host, index)
        with self.lock:
            tenant = self.okta.get(host)
            if not tenant or auth != f"SSWS {tenant['token']}":
                return 401, {}, {"errorCode": "E0000011", "errorSummary": "Invalid token provided"}
            since = parse_ts(q["since"][0]) if q.get("since") else datetime.min.replace(tzinfo=UTC)
            until = parse_ts(q["until"][0]) if q.get("until") else datetime.max.replace(tzinfo=UTC)
            evs = sorted(
                (e for e in tenant["events"] if since <= parse_ts(e["published"]) < until),
                key=lambda e: (e["published"], e["uuid"]),
            )
        limit = min(int((q.get("limit") or ["1000"])[0]), self.page_size)
        # `after` is a cursor (published|uuid of the last served event), not an
        # offset: events added mid-walk neither shift nor duplicate a page.
        after = (q.get("after") or [""])[0]
        if after:
            evs = [e for e in evs if f"{e['published']}|{e['uuid']}" > after]
        page = evs[:limit]
        hdrs = {
            "X-Rate-Limit-Remaining": "100",
            "X-Rate-Limit-Reset": str(int(time.time()) + 60),
        }
        if len(evs) > limit:
            last = page[-1]
            nq = {k: v[0] for k, v in q.items() if k != "after"} | {
                "after": f"{last['published']}|{last['uuid']}"
            }
            hdrs["Link"] = f'<https://{host}/api/v1/logs?{urlencode(nq)}>; rel="next"'
        return 200, hdrs, page

    def _record_action(
        self, vendor: str, host: str, method: str, path: str, auth: str
    ) -> tuple[int, dict[str, str], Any]:
        with self.lock:
            self.actions.append({"vendor": vendor, "host": host, "method": method, "path": path})
        return 200, {}, {}

    # ------------------------------------------------------------ google workspace
    def _gws_token(self, body: bytes) -> tuple[int, dict[str, str], Any]:
        form = parse_qs(body.decode())
        if form.get("grant_type") != ["urn:ietf:params:oauth:grant-type:jwt-bearer"]:
            return 400, {}, {"error": "unsupported_grant_type"}
        assertion = (form.get("assertion") or [""])[0]
        try:
            unverified = json.loads(_b64url_decode(assertion.split(".")[1]))
        except (IndexError, ValueError):
            return 400, {}, {"error": "invalid_grant", "error_description": "malformed assertion"}
        with self.lock:
            sa = self.gws_accounts.get(unverified.get("iss", ""))
        if sa is None:
            return 400, {}, {"error": "invalid_grant", "error_description": "unknown client_email"}
        try:
            claims = verify_jwt(assertion, sa)
        except ValueError as exc:
            return 400, {}, {"error": "invalid_grant", "error_description": str(exc)}
        if claims.get("aud") != GWS_TOKEN_URL or claims.get("scope") != GWS_SCOPE:
            return 400, {}, {"error": "invalid_scope", "error_description": f"aud/scope mismatch: {claims}"}
        with self.lock:
            if claims.get("sub") not in self.gws_subjects:
                return 401, {}, {"error": "unauthorized_client", "error_description": "subject not delegated"}
            tok = "ya29.mock-" + secrets.token_hex(16)
            self.gws_tokens[tok] = sa.client_email
        return 200, {}, {"access_token": tok, "expires_in": 3599, "token_type": "Bearer"}

    def _gws_activities(
        self, application: str, q: dict[str, list[str]], auth: str
    ) -> tuple[int, dict[str, str], Any]:
        with self.lock:
            if not auth.startswith("Bearer ") or auth[7:] not in self.gws_tokens:
                return 401, {}, {"error": {"code": 401, "message": "Invalid Credentials"}}
            start = parse_ts(q["startTime"][0]) if q.get("startTime") else datetime.min.replace(tzinfo=UTC)
            end = parse_ts(q["endTime"][0]) if q.get("endTime") else datetime.max.replace(tzinfo=UTC)
            items = sorted(
                (e for e in self.gws_events.get(application, []) if start <= parse_ts(e["id"]["time"]) < end),
                key=lambda e: e["id"]["time"],
                reverse=True,  # Reports API is newest-first
            )
        off = int((q.get("pageToken") or ["0"])[0])
        page = items[off : off + self.page_size]
        out: dict[str, Any] = {"kind": "admin#reports#activities", "items": page}
        if off + self.page_size < len(items):
            out["nextPageToken"] = str(off + self.page_size)
        return 200, {}, out

    # ------------------------------------------------------------ slack
    def _slack_access_logs(self, q: dict[str, list[str]], auth: str) -> tuple[int, dict[str, str], Any]:
        with self.lock:
            if not auth.startswith("Bearer ") or auth[7:] not in self.slack:
                return 200, {}, {"ok": False, "error": "invalid_auth"}
            logins = sorted(self.slack[auth[7:]], key=lambda r: r["date_last"], reverse=True)
        off = int((q.get("cursor") or ["0"])[0] or 0)
        page = logins[off : off + self.page_size]
        nxt = str(off + self.page_size) if off + self.page_size < len(logins) else ""
        return 200, {}, {"ok": True, "logins": page, "response_metadata": {"next_cursor": nxt}}

    # ------------------------------------------------------------ netskope (saas_api)
    def _netskope(
        self, host: str, item: str, q: dict[str, list[str]], token: str
    ) -> tuple[int, dict[str, str], Any]:
        with self.lock:
            tenant = self.netskope.get(host)
            if not tenant or token != tenant["token"]:
                return 403, {}, {"ok": 0, "message": "Invalid token"}
            index = (q.get("index") or [""])[0]
            op = (q.get("operation") or [""])[0]
            key = (index, item)
            # Server-side iterator over the LIVE event list: the position is the
            # (timestamp, _id) of the last served event, so events that arrive
            # after the iterator opened are served by a later `next`.
            evs = sorted(tenant["events"].get(item, []), key=lambda e: (e["timestamp"], e["_id"]))
            it = tenant["iters"].get(key)
            if op.isdigit():
                it = {"start": int(op), "pos": None, "last": None}
            elif op == "next" and it:
                it["last"] = it["pos"]
            elif op == "resend" and it:
                pass  # re-serve from the previous position
            else:
                return 400, {}, {"ok": 0, "message": f"operation {op!r} without an open iterator"}
            frm = it["last"]
            remaining = [
                e
                for e in evs
                if e["timestamp"] >= it["start"] and (frm is None or (e["timestamp"], e["_id"]) > frm)
            ]
            page = remaining[: self.page_size]
            if page:
                it["pos"] = (page[-1]["timestamp"], page[-1]["_id"])
            else:
                it["pos"] = frm
            tenant["iters"][key] = it
        return 200, {}, {"ok": 1, "result": page, "wait_time": 0}


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: _Server

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass

    def _go(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        host = self.headers.get("x-mock-host", "")
        headers = {k.lower(): v for k, v in self.headers.items()}
        try:
            status, hdrs, payload = self.server.mock.handle(self.command, host, self.path, headers, body)
        except Exception as exc:  # noqa: BLE001 - a mock bug must surface as a 500, not a hang
            status, hdrs, payload = 500, {}, {"error": f"mock-vendor: {type(exc).__name__}: {exc}"}
        u = urlsplit(self.path)
        with self.server.mock.lock:
            self.server.mock.requests.append(
                Recorded(host, self.command, u.path, parse_qs(u.query, keep_blank_values=True), status)
            )
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        for k, v in hdrs.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _go  # noqa: N815


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, port: int, mock: MockVendor):
        self.allow_reuse_address = True
        super().__init__(("127.0.0.1", port), _Handler)
        self.mock = mock


class MockVendorServer:
    """Binds 127.0.0.1:<port> (0 = ephemeral, for selftests)."""

    def __init__(self, port: int = 0, page_size: int = 2):
        self.mock = MockVendor(page_size=page_size)
        try:
            self._srv = _Server(port, self.mock)
        except OSError as exc:
            raise RuntimeError(
                f"E2E-INFRA: mock-vendor cannot bind 127.0.0.1:{port} ({exc}); another pytest session on "
                "this stack is running, or the port was taken after `up`"
            ) from exc
        self._thread = threading.Thread(target=self._srv.serve_forever, name="mock-vendor", daemon=True)

    @property
    def url(self) -> str:
        host, port = self._srv.server_address[:2]
        return f"http://{host}:{port}"

    def start(self) -> MockVendorServer:
        self._thread.start()
        return self

    def stop(self) -> None:
        self._srv.shutdown()
        self._srv.server_close()
