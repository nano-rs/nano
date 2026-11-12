"""Step-by-step browser helper for exploratory persona agents (NAN-5291).

An agent drives the real web UI of a KEPT e2e stack one command at a time.
`start` launches a small background daemon that owns the puppeteer driver
(`nanosiem-web/tests/e2e/ui/driver.mjs`), one browser context and, for a
persona, a throwaway role/group/user with that persona's permission set (the
same sets the scripted persona suite uses). Every later command talks to the
daemon over a unix socket in the run dir and prints ONE JSON object:

    {"ok": true, "result": ..., "url": "...", "events": {"console": [...], "network": [...]}}

`events` holds the console errors and failed requests (status >= 400 or no
response) since the previous command, so every step reports what it broke.

    PY=e2e/.venv/bin/python
    $PY -m nano_e2e.explore start --persona soc_analyst      # or --admin
    $PY -m nano_e2e.explore goto /search
    $PY -m nano_e2e.explore search 'actor.user.name="alice"' --start 2000-01-01T00:00:00Z
    $PY -m nano_e2e.explore click --role button --name Save
    $PY -m nano_e2e.explore type --css '.cm-content' 'src_endpoint.ip='
    $PY -m nano_e2e.explore wait --text 'Query complete' --timeout 60
    $PY -m nano_e2e.explore text                             # visible main text
    $PY -m nano_e2e.explore screenshot /tmp/finding-1.png
    $PY -m nano_e2e.explore events                           # errors since last step
    $PY -m nano_e2e.explore idle 10 --reload                 # idle N min, then recheck
    $PY -m nano_e2e.explore op sidebar_fields                # any driver op, raw
    $PY -m nano_e2e.explore stop                             # deletes the persona user

Several agents can share a stack: give each its own `--session` name.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import shutil
import signal
import socket
import socketserver
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from nano_e2e import personas
from nano_e2e import ui as uilib
from nano_e2e.stack import Stack

PERSONAS: dict[str, tuple[str, ...]] = {
    "soc_analyst": personas.SOC_ANALYST_PERMISSIONS,
    "siem_engineer": personas.SIEM_ENGINEER_PERMISSIONS,
    "detection_engineer": personas.DETECTION_ENGINEER_PERMISSIONS,
    "incident_responder": personas.INCIDENT_RESPONDER_PERMISSIONS,
    "platform_admin": personas.PLATFORM_ADMIN_PERMISSIONS,
}
# A blank page after an idle return: less visible text than this in <main>.
BLANK_TEXT_CHARS = 40


# ---------------------------------------------------------------- web site
def web_base(stack: Stack, web_dist: str | None, stack_exit: contextlib.ExitStack) -> str:
    """The SPA's base URL: the stack's nginx edge when it already serves a
    build (a kept `run personas` stack does), else publish/serve `web_dist`."""
    edge_web = stack.run_dir / "edge" / "web" / "index.html"
    if edge_web.is_file() and not web_dist:
        return stack.edge_url
    dist = web_dist or os.environ.get("E2E_WEB_DIST", "")
    if not dist:
        raise RuntimeError(
            "this stack's edge serves no web build: pass --web-dist <nanosiem-web dist> "
            "(scripts/e2e.sh builds one under target/e2e/web/) or set E2E_WEB_DIST"
        )
    from nano_e2e.web import site_for

    site = site_for(Path(dist), stack.api_url, stack.search_url, stack.artifact_dir / "explore-web.log")
    site.start()
    stack_exit.callback(site.stop)
    return site.url


@contextlib.contextmanager
def session(
    stack: Stack, *, persona: str | None = None, out: Path, web_dist: str | None = None
) -> Iterator[uilib.UiPage]:
    """A logged-in UiPage on the stack (admin, or a throwaway persona user that
    is deleted on exit). Used by the daemon and by the field-invariant UI pass."""
    from nano_e2e.client import Journal, Nano

    with contextlib.ExitStack() as es:
        base = web_base(stack, web_dist, es)
        out.mkdir(parents=True, exist_ok=True)
        driver = uilib.Driver(base, out / "ui-driver.log")
        es.callback(driver.close)
        if persona:
            if persona not in PERSONAS:
                raise ValueError(f"unknown persona {persona!r}; known: {', '.join(PERSONAS)}")
            nano = Nano(stack.api_url, stack.search_url, {"X-API-Key": stack.api_key}, Journal(None))
            es.callback(nano.close)
            pb = es.enter_context(
                personas.login_persona(stack, nano, driver, out, persona.replace("_", "-"), PERSONAS[persona])
            )
            yield pb.page
        else:
            page = uilib.UiPage.open(driver, out / "ui-admin", name="explore:admin")
            es.callback(page.finish, False)
            driver.register_secret(stack.admin_password)
            uilib.login(page, stack.admin_email, stack.admin_password)
            yield page


def run_search(page: uilib.UiPage, query: str, start: str | None = None, end: str | None = None) -> str:
    """Open /search with the query (and a fixed range when `start` is given),
    press the linked-query Run (NAN-5235: a link loads but never auto-runs)
    and wait for the run to finish. Returns the URL."""
    from datetime import UTC, datetime, timedelta
    from urllib.parse import urlencode

    params = {"q": query}
    if start:
        params["start"] = start
        params["end"] = end or (datetime.now(UTC) + timedelta(days=1)).isoformat()
    page.goto("/search?" + urlencode(params))
    prompt = {"testid": "linked-query-run-prompt"}
    page.wait_for({"css": ".cm-content"}, timeout_ms=30_000)
    if page.count(prompt):
        page.click({"role": "button", "name": "Run", "exact": True, "within": prompt})
    page.wait_text("Query complete", exact=False, timeout_ms=90_000)
    return page.url


# ---------------------------------------------------------------- daemon
def _sock_path(stack: Stack, name: str) -> Path:
    """Unix sockets have a ~104-byte path limit (macOS), and run dirs under a
    worktree exceed it: the socket lives in a private 0700 dir under /tmp."""
    d = Path("/tmp") / f"nano-explore-{os.getuid()}"  # noqa: S108 - 0700, owner-checked below
    d.mkdir(mode=0o700, exist_ok=True)
    st = d.stat()
    if st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise RuntimeError(f"{d} is not a private directory owned by this user")
    if not name.replace("-", "").replace("_", "").isalnum():
        raise ValueError(f"session name must be alphanumeric (-/_ allowed): {name!r}")
    return d / f"{stack.run_id}-{name}.sock"


class Daemon:
    def __init__(self, page: uilib.UiPage, out: Path):
        self.page = page
        self.out = out
        self.mark = page.now_ms()
        self.lock = threading.Lock()
        self.stop = threading.Event()

    def events(self) -> dict[str, Any]:
        ev = self.page.op("events_since", since=self.mark)
        self.mark = self.page.now_ms()
        return ev

    def handle(self, req: dict[str, Any]) -> dict[str, Any]:
        cmd, a = req.get("cmd", ""), req.get("args", {})
        with self.lock:
            try:
                result = self.dispatch(cmd, a)
                resp: dict[str, Any] = {"ok": True, "result": result}
            except Exception as exc:  # noqa: BLE001 - every failure is reported to the agent
                resp = {"ok": False, "error": f"{type(exc).__name__}: {str(exc)[:3000]}"}
            if cmd != "stop":
                with contextlib.suppress(Exception):
                    resp["url"] = self.page.url
                with contextlib.suppress(Exception):
                    resp["events"] = self.events()
            return resp

    def dispatch(self, cmd: str, a: dict[str, Any]) -> Any:
        p = self.page
        if cmd == "goto":
            return p.goto(a["path"])
        if cmd == "reload":
            return p.reload()
        if cmd == "click":
            return p.click(a["find"], timeout_ms=a.get("timeout_ms"))
        if cmd == "fill":
            return p.fill(uilib.field(a["find"], a["text"]))
        if cmd == "type":
            return p.op("type_text", find=a["find"], text=a["text"], clear=a.get("clear", False))
        if cmd == "editor":
            return p.editor_fill(a["find"], a["text"])
        if cmd == "press":
            return p.press_key(a["find"], a["key"])
        if cmd == "wait":
            if a.get("url"):
                return p.wait_url(a["url"], timeout_ms=a["timeout_ms"])
            if a.get("find"):
                return p.wait_for(a["find"], timeout_ms=a["timeout_ms"], gone=a.get("gone", False))
            if a.get("ms"):
                time.sleep(a["ms"] / 1000)
                return True
            raise ValueError("wait needs --url, a finder (--text/--role/--css/...) or --ms")
        if cmd == "search":
            return run_search(p, a["query"], a.get("start"), a.get("end"))
        if cmd == "text":
            return p.main_text()
        if cmd == "texts":
            return p.texts(a["find"])
        if cmd == "count":
            return p.count(a["find"])
        if cmd == "screenshot":
            return self.screenshot(a["path"])
        if cmd == "events":
            return "see events"
        if cmd == "idle":
            return self.idle(float(a["minutes"]), a.get("reload", False))
        if cmd == "op":
            return p.op(a["op"], **a.get("args", {}))
        if cmd == "stop":
            self.stop.set()
            return "stopping"
        raise ValueError(f"unknown command {cmd!r}")

    def screenshot(self, target: str) -> str:
        name = f"shot-{int(time.time() * 1000)}.png"
        made = self.page.screenshot(name)
        dest = Path(target).expanduser().resolve()
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(made, dest)
        return str(dest)

    def idle(self, minutes: float, reload: bool) -> dict[str, Any]:
        """Leave the page alone (token expiry, background polling, sleep-like
        gaps), then report what a returning user sees."""
        before = self.page.main_text()
        time.sleep(minutes * 60)
        after = self.page.main_text()
        res: dict[str, Any] = {
            "idled_minutes": minutes,
            "text_chars_before": len(before),
            "text_chars_after": len(after),
            "blank_after_idle": len(after) < BLANK_TEXT_CHARS,
            "url_after_idle": self.page.url,
        }
        if reload:
            self.page.reload()
            time.sleep(3)
            again = self.page.main_text()
            res |= {
                "text_chars_after_reload": len(again),
                "blank_after_reload": len(again) < BLANK_TEXT_CHARS,
                "url_after_reload": self.page.url,
            }
        return res


def serve(stack: Stack, name: str, persona: str | None, web_dist: str | None, ready_fd: int | None) -> None:
    out = stack.artifact_dir / "explore" / name
    sock = _sock_path(stack, name)
    with contextlib.suppress(FileNotFoundError):
        sock.unlink()
    with session(stack, persona=persona, out=out, web_dist=web_dist) as page:
        daemon = Daemon(page, out)

        class Handler(socketserver.StreamRequestHandler):
            def handle(self) -> None:
                line = self.rfile.readline()
                try:
                    req = json.loads(line)
                except ValueError:
                    resp = {"ok": False, "error": "bad request"}
                else:
                    resp = daemon.handle(req)
                self.wfile.write((json.dumps(resp, default=str) + "\n").encode())

        srv = socketserver.UnixStreamServer(str(sock), Handler)
        os.chmod(sock, 0o600)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        signal.signal(signal.SIGTERM, lambda *_: daemon.stop.set())
        if ready_fd is not None:
            os.write(ready_fd, b"ready\n")
            os.close(ready_fd)
        daemon.stop.wait()
        srv.shutdown()
        srv.server_close()
    with contextlib.suppress(FileNotFoundError):
        sock.unlink()


# ---------------------------------------------------------------- client
def _alive(sock: Path) -> bool:
    """A daemon answers on `sock`. A socket file left by a killed daemon is
    removed, so `start` is not refused forever."""
    if not sock.exists():
        return False
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        try:
            s.connect(str(sock))
            return True
        except OSError:
            pass
    with contextlib.suppress(FileNotFoundError):
        sock.unlink()
    return False


def call(stack: Stack, name: str, cmd: str, args: dict[str, Any], timeout: float) -> dict[str, Any]:
    sock = _sock_path(stack, name)
    if not _alive(sock):
        return {"ok": False, "error": f"no explore session {name!r} (run `start` first)"}
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect(str(sock))
            s.sendall((json.dumps({"cmd": cmd, "args": args}) + "\n").encode())
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
    except OSError as exc:
        return {"ok": False, "error": f"explore daemon unreachable: {type(exc).__name__}: {exc}"}
    return json.loads(buf or b'{"ok": false, "error": "daemon closed the connection"}')


def start(stack: Stack, ns: argparse.Namespace) -> dict[str, Any]:
    if _alive(_sock_path(stack, ns.session)):
        return {"ok": False, "error": f"session {ns.session!r} is already running (stop it first)"}
    r, w = os.pipe()
    argv = [
        sys.executable,
        "-m",
        "nano_e2e.explore",
        "--stack-env",
        os.environ["E2E_STACK_ENV_PATH"],
        "--session",
        ns.session,
        "_serve",
        "--ready-fd",
        str(w),
    ]
    if ns.persona:
        argv += ["--persona", ns.persona]
    if ns.web_dist:
        argv += ["--web-dist", str(Path(ns.web_dist).resolve())]
    log = stack.artifact_dir / "explore" / f"{ns.session}.daemon.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    if ns.headed:
        env["E2E_UI_HEADED"] = "1"
    with log.open("a") as lf:
        proc = subprocess.Popen(  # noqa: S603 - fixed argv
            argv, stdout=lf, stderr=lf, pass_fds=(w,), start_new_session=True, env=env
        )
    os.close(w)
    deadline = time.monotonic() + ns.timeout
    with os.fdopen(r) as rf:
        import select

        while time.monotonic() < deadline:
            ready, _, _ = select.select([rf], [], [], 1.0)
            if ready:
                if rf.readline().strip() == "ready":
                    return {
                        "ok": True,
                        "result": {
                            "session": ns.session,
                            "pid": proc.pid,
                            "persona": ns.persona or "admin",
                            "log": str(log),
                        },
                    }
                break
            if proc.poll() is not None:
                break
    with contextlib.suppress(Exception):
        proc.terminate()
    tail = log.read_text()[-2000:] if log.exists() else ""
    return {"ok": False, "error": f"explore daemon did not start; log {log}:\n{tail}"}


def _finder(ns: argparse.Namespace) -> dict[str, Any] | None:
    f: dict[str, Any] = {}
    for key in ("role", "testid", "css", "placeholder", "text", "has"):
        v = getattr(ns, key, None)
        if v is not None:
            f[key] = v
    if getattr(ns, "name", None) is not None:
        f["name"] = ns.name
    if getattr(ns, "regex", False):
        for key in ("name", "text", "has"):
            if isinstance(f.get(key), str):
                f[key] = {"re": f[key], "flags": "i"}
    if getattr(ns, "exact", False):
        f["exact"] = True
    if getattr(ns, "nth", None) is not None:
        f["nth"] = ns.nth
    return f or None


def _add_finder(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("element finder (driver.mjs FINDER)")
    g.add_argument("--role", help="button|textbox|tab|option|menuitem|combobox|dialog|row|heading|link|cell")
    g.add_argument("--name", help="accessible name (with --role)")
    g.add_argument("--text", help="visible text")
    g.add_argument("--testid")
    g.add_argument("--css")
    g.add_argument("--placeholder")
    g.add_argument("--has", help="keep matches whose text contains this")
    g.add_argument(
        "--regex", action="store_true", help="treat --name/--text/--has as a case-insensitive regex"
    )
    g.add_argument("--exact", action="store_true")
    g.add_argument("--nth", type=int)


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="nano_e2e.explore", description=(__doc__ or "").split("\n\n")[0])
    ap.add_argument("--run", help="e2e run id (default: the current kept stack)")
    ap.add_argument("--stack-env", help="explicit stack.env path")
    ap.add_argument("--session", default="default", help="session name (one browser per session)")
    ap.add_argument("--timeout", type=float, default=600, help="seconds to wait for this command")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("start", help="start a logged-in browser session")
    who = s.add_mutually_exclusive_group(required=True)
    who.add_argument("--persona", choices=sorted(PERSONAS))
    who.add_argument("--admin", action="store_true")
    s.add_argument("--web-dist", help="nanosiem-web dist to serve when the edge has none")
    s.add_argument("--headed", action="store_true")

    srv = sub.add_parser("_serve")
    srv.add_argument("--persona")
    srv.add_argument("--web-dist")
    srv.add_argument("--ready-fd", type=int)

    sub.add_parser("stop", help="close the browser; delete the persona user")
    p = sub.add_parser("goto")
    p.add_argument("path")
    sub.add_parser("reload")
    for cmd in ("click", "texts", "count"):
        _add_finder(sub.add_parser(cmd))
    for cmd in ("fill", "type", "editor"):
        p = sub.add_parser(
            cmd,
            help={
                "fill": "set an input's value",
                "type": "real keystrokes",
                "editor": "replace a CodeMirror document",
            }[cmd],
        )
        p.add_argument("value")
        p.add_argument("--clear", action="store_true", help="type: select-all + delete first")
        _add_finder(p)
    p = sub.add_parser("press")
    p.add_argument("key", help="e.g. Enter, Escape, ArrowDown")
    _add_finder(p)
    p = sub.add_parser("wait")
    p.add_argument("--url", help="regex the URL must match")
    p.add_argument("--gone", action="store_true", help="wait for the element to disappear")
    p.add_argument("--ms", type=int, help="plain wait")
    p.add_argument("--wait-timeout", type=float, default=20, help="seconds")
    _add_finder(p)
    p = sub.add_parser("search", help="open /search with the query and run it")
    p.add_argument("query")
    p.add_argument("--start", help="ISO start (corpus events keep native timestamps: go wide)")
    p.add_argument("--end", help="ISO end")
    sub.add_parser("text", help="visible <main> text")
    p = sub.add_parser("screenshot")
    p.add_argument("path")
    sub.add_parser("events", help="console errors + failed requests since the last step")
    p = sub.add_parser("idle", help="idle N minutes, then report what the page shows")
    p.add_argument("minutes", type=float)
    p.add_argument("--reload", action="store_true", help="also reload and recheck")
    p = sub.add_parser("op", help="raw driver op (see driver.mjs OPS)")
    p.add_argument("op")
    p.add_argument("json_args", nargs="?", default="{}")
    return ap


def request_args(ns: argparse.Namespace) -> dict[str, Any]:
    cmd = ns.cmd
    f = _finder(ns)
    if cmd == "goto":
        return {"path": ns.path}
    if cmd in ("click", "texts", "count", "press", "fill", "type", "editor"):
        if not f:
            raise SystemExit(f"{cmd} needs a finder (--role/--text/--css/--testid/--placeholder)")
        a: dict[str, Any] = {"find": f}
        if cmd == "press":
            a["key"] = ns.key
        if cmd in ("fill", "type", "editor"):
            a |= {"text": ns.value, "clear": ns.clear}
        return a
    if cmd == "wait":
        return {
            "url": ns.url,
            "find": f,
            "gone": ns.gone,
            "ms": ns.ms,
            "timeout_ms": int(ns.wait_timeout * 1000),
        }
    if cmd == "search":
        return {"query": ns.query, "start": ns.start, "end": ns.end}
    if cmd == "screenshot":
        return {"path": ns.path}
    if cmd == "idle":
        return {"minutes": ns.minutes, "reload": ns.reload}
    if cmd == "op":
        return {"op": ns.op, "args": json.loads(ns.json_args)}
    return {}


def main(argv: list[str] | None = None) -> int:
    sys.stdout.reconfigure(line_buffering=True)  # type: ignore[union-attr] - progress when piped
    from nano_e2e import stackenv

    ns = build_parser().parse_args(argv)
    path = stackenv.locate(ns.run, ns.stack_env)
    os.environ["E2E_STACK_ENV_PATH"] = str(path)
    stack = stackenv.load(env_file=str(path))
    if ns.cmd == "_serve":
        serve(stack, ns.session, ns.persona, ns.web_dist, ns.ready_fd)
        return 0
    if ns.cmd == "start":
        resp = start(stack, ns)
    else:
        timeout = ns.timeout + (ns.minutes * 60 if ns.cmd == "idle" else 0)
        resp = call(stack, ns.session, ns.cmd, request_args(ns), timeout)
    print(json.dumps(resp, indent=2, default=str))
    return 0 if resp.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
