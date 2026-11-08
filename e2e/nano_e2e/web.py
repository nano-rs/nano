"""Serve the built web SPA for a probe stack (NAN-4937).

Native app mode runs api/search as host processes and no web container, so the
UI scenarios need something that serves `nanosiem-web/dist` and routes the
SPA's same-origin API calls the way production nginx (and the vite dev proxy,
`nanosiem-web/vite.config.ts`) does: a handful of search paths that the api
owns, the rest of `/api/search*` to nanosiem-search, everything else under
`/api` to nanosiem-api.

The proxy runs in a daemon thread inside the pytest process, so it lives and
dies with the run and has no pid to manage. It binds 127.0.0.1 on an
ephemeral port. Responses are streamed (search uses SSE over fetch), never
buffered whole.
"""

from __future__ import annotations

import http.client
import mimetypes
import threading
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

# Order matters: the first matching prefix wins (mirrors vite.config.ts).
API_OWNED_SEARCH_PREFIXES = (
    "/api/search/history",
    "/api/search/share",
    "/api/search/shared",
    "/api/search/explanation",
)
_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
}


def route(path: str) -> str | None:
    """'api' | 'search' | None (static). Pure, for selftests."""
    if any(
        path == p or path.startswith(p + "/") or path.startswith(p + "?") for p in API_OWNED_SEARCH_PREFIXES
    ):
        return "api"
    if path == "/api/search" or path.startswith("/api/search"):
        return "search"
    if path.startswith(("/api/", "/swagger-ui", "/api-docs")) or path in ("/api", "/health"):
        return "api"
    return None


def static_file(dist: Path, path: str) -> Path:
    """The file to serve for `path`: the asset when it exists inside `dist`,
    else index.html (SPA fallback). Never escapes `dist`."""
    root = dist.resolve()
    rel = path.lstrip("/")
    if rel:
        candidate = (root / rel).resolve()
        if candidate.is_relative_to(root) and candidate.is_file():
            return candidate
    return root / "index.html"


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: _Server

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib signature
        self.server.log(f"{self.address_string()} {format % args}")

    def _dispatch(self) -> None:
        path = urlsplit(self.path).path
        target = route(path)
        if target is None:
            self._static(path)
        else:
            self._proxy(self.server.upstreams[target])

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_HEAD = _dispatch  # noqa: N815

    def _static(self, path: str) -> None:
        f = static_file(self.server.dist, path)
        body = f.read_bytes()
        ctype = mimetypes.guess_type(f.name)[0] or "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _proxy(self, upstream: tuple[str, int]) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None
        headers = {k: v for k, v in self.headers.items() if k.lower() not in _HOP}
        headers["Host"] = f"{upstream[0]}:{upstream[1]}"
        conn = http.client.HTTPConnection(upstream[0], upstream[1], timeout=600)
        try:
            try:
                conn.request(self.command, self.path, body=body, headers=headers)
                resp = conn.getresponse()
            except OSError as exc:
                msg = f"e2e web proxy: upstream {upstream} unreachable: {exc}".encode()
                self.send_response(502)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(msg)))
                self.end_headers()
                self.wfile.write(msg)
                return
            self.send_response(resp.status, resp.reason)
            length_hdr = resp.getheader("Content-Length")
            for k, v in resp.getheaders():
                if k.lower() not in _HOP and k.lower() != "content-length":
                    self.send_header(k, v)
            no_body = self.command == "HEAD" or resp.status in (204, 304)
            if length_hdr is not None:
                self.send_header("Content-Length", length_hdr)
                self.end_headers()
                if not no_body:
                    while chunk := resp.read(64 * 1024):
                        self.wfile.write(chunk)
                return
            if no_body:
                self.end_headers()
                return
            # Unknown length (SSE, chunked): re-chunk as it arrives.
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            while chunk := resp.read1(64 * 1024):
                self.wfile.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
                self.wfile.flush()
            self.wfile.write(b"0\r\n\r\n")
        except OSError:
            # The browser navigated away, or the upstream stalled/died
            # mid-stream (headers already sent): drop the connection.
            self.close_connection = True
        finally:
            conn.close()


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request: object, client_address: object) -> None:
        # A client hanging up is routine (navigation, page close): no traceback.
        import sys

        if isinstance(sys.exc_info()[1], OSError):
            return
        super().handle_error(request, client_address)  # type: ignore[arg-type]

    def __init__(self, dist: Path, upstreams: dict[str, tuple[str, int]], log: Callable[[str], None]):
        super().__init__(("127.0.0.1", 0), _Handler)
        self.dist = dist
        self.upstreams = upstreams
        self.log = log


def _hostport(url: str) -> tuple[str, int]:
    u = urlsplit(url)
    if not u.hostname or not u.port:
        raise ValueError(f"need an explicit host:port in {url!r}")
    return u.hostname, u.port


class WebServer:
    """The SPA + same-origin routing for one stack. `url` is the browser's base."""

    def __init__(self, dist: Path, api_url: str, search_url: str, log_path: Path | None = None):
        if not (dist / "index.html").is_file():
            raise FileNotFoundError(
                f"{dist}/index.html missing: build the web UI first (scripts/e2e.sh run ui)"
            )
        self._log_path = log_path
        self._lock = threading.Lock()
        self._srv = _Server(dist, {"api": _hostport(api_url), "search": _hostport(search_url)}, self._log)
        self._thread = threading.Thread(target=self._srv.serve_forever, name="e2e-web", daemon=True)

    def _log(self, line: str) -> None:
        if not self._log_path:
            return
        with self._lock, self._log_path.open("a") as f:
            f.write(line + "\n")

    @property
    def url(self) -> str:
        host, port = self._srv.server_address[:2]
        return f"http://{host}:{port}"

    def start(self) -> WebServer:
        self._thread.start()
        return self

    def stop(self) -> None:
        self._srv.shutdown()
        self._srv.server_close()


class EdgeSite:
    """The stack's nginx edge (scripts/e2e.sh `edge` service, the shipped
    nginx.opensource.conf): publish the SPA build into the run dir it serves
    from, and browse through it like a customer does."""

    def __init__(self, url: str, web_dir: Path, dist: Path):
        import shutil

        if not (dist / "index.html").is_file():
            raise FileNotFoundError(
                f"{dist}/index.html missing: build the web UI first (scripts/e2e.sh run ui)"
            )
        web_dir.mkdir(parents=True, exist_ok=True)
        for child in web_dir.iterdir():
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
        shutil.copytree(dist, web_dir, dirs_exist_ok=True)
        self.url = url.rstrip("/")

    def start(self) -> EdgeSite:
        return self

    def stop(self) -> None:
        pass


def site_for(dist: Path, api_url: str, search_url: str, log_path: Path | None = None) -> WebServer | EdgeSite:
    """The nginx edge when the stack has one (NANOSIEM_EDGE_URL), else the
    in-process proxy (an older stack, or one brought up without the edge)."""
    import os

    edge = os.environ.get("NANOSIEM_EDGE_URL", "")
    run_dir = os.environ.get("E2E_RUN_DIR", "")
    if edge and run_dir and (Path(run_dir) / "edge" / "nginx.conf").is_file():
        return EdgeSite(edge, Path(run_dir) / "edge" / "web", dist)
    return WebServer(dist, api_url, search_url, log_path)
