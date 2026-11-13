"""Browser layer for the UI scenarios (NAN-4937).

The browser is driven by `nanosiem-web/tests/e2e/ui/driver.mjs`, which uses
puppeteer-core (the dependency the repo already ships for crawl-404.mjs) and a
locally installed Chrome/Chromium (CHROME_PATH, else the usual install paths).
The harness starts ONE driver process per pytest session and talks to it over
JSON lines on stdin/stdout; every op performs a UI action and returns what the
page SHOWS, and the scenario compares that to the API/ClickHouse.

- One isolated browser context per scenario (`UiPage`); nothing is shared
  between scenarios but the browser process.
- Secrets reach the driver only over stdin (its environment is stripped of
  them). The driver scrubs them from every artifact and blanks the fields they
  were typed into before a screenshot.
- Artifacts per scenario under `target/e2e/<run>/artifacts/scenarios/<test>/ui/`:
  `console.log` always; on failure `failure.png`, `page.html`, `network.jsonl`.
"""

from __future__ import annotations

import atexit
import itertools
import json
import os
import re
import shutil
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from nano_e2e import artifact_guard
from nano_e2e.client import _secret_values

ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / "nanosiem-web"
DRIVER = WEB / "tests" / "e2e" / "ui" / "driver.mjs"
OP_TIMEOUT = 300.0  # ops wait on the UI themselves (20-60 s); this only bounds a hung driver
_SECRET_ENV = re.compile(r"(SECRET|PASSWORD|_KEY|TOKEN|SA_JSON|ADC|CONNECTION_STRING|DATABASE_URL)")


class UiError(AssertionError):
    """The UI did not show what a step needed (E2E-PRODUCT: a red result)."""


def rx(pattern: str, flags: str = "") -> dict[str, str]:
    """A regex accessible-name / text matcher for the driver's finder."""
    return {"re": pattern, "flags": flags}


def driver_env(base_url: str) -> dict[str, str]:
    """The driver's environment: the base URL, and NO harness secret."""
    env = {k: v for k, v in os.environ.items() if not _SECRET_ENV.search(k)}
    env["E2E_UI_BASE"] = base_url
    return env


class Driver:
    """The puppeteer driver process (one per pytest session)."""

    def __init__(self, base_url: str, log_path: Path | None = None):
        node = shutil.which("node")
        if not node:
            raise RuntimeError("node not found: the UI driver runs under Node.js (nanosiem-web)")
        if not (WEB / "node_modules" / "puppeteer-core").is_dir():
            raise RuntimeError(
                "nanosiem-web/node_modules/puppeteer-core missing: `scripts/e2e.sh run ui` installs it"
            )
        self._log = open(log_path or os.devnull, "a")  # noqa: SIM115 - closed in close()
        self._proc = subprocess.Popen(  # noqa: S603 - fixed argv
            [node, str(DRIVER)],
            cwd=str(WEB),  # resolves puppeteer-core from nanosiem-web/node_modules
            env=driver_env(base_url),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self._log,
            text=True,
            bufsize=1,
            # Node and every Chrome descendant get a dedicated process group.
            # Forced cleanup can therefore target only this driver's browser
            # tree, never another lane's Chrome.
            start_new_session=True,
        )
        self._closed = False
        self._ids = itertools.count(1)
        self._lock = threading.Lock()
        atexit.register(self.close)
        try:
            self.call("secrets", values=_secret_values())
        except BaseException:
            self.close()
            raise

    def call(self, op: str, **args: Any) -> Any:
        # `timeout` (ms) belongs to the op and goes to the driver. It used to be
        # swallowed as this method's own read timeout, so every wait ran at the
        # driver's 20 s default (NAN-5335). Bound the read by the op's own wait.
        if args.get("timeout") is None:
            args.pop("timeout", None)  # JSON null would defeat the driver's default
        op_ms = args.get("timeout")
        read_timeout = max(OP_TIMEOUT, op_ms / 1000 + 30) if isinstance(op_ms, (int, float)) else OP_TIMEOUT
        with self._lock:
            rid = next(self._ids)
            assert self._proc.stdin and self._proc.stdout
            try:
                self._proc.stdin.write(json.dumps({"id": rid, "op": op, "args": args}) + "\n")
                self._proc.stdin.flush()
            except BrokenPipeError as exc:
                raise RuntimeError("E2E-INFRA: UI driver is gone; see artifacts/ui-driver.log") from exc
            line = _readline(self._proc.stdout, read_timeout)
            if not line:
                raise RuntimeError(f"E2E-INFRA: UI driver exited during {op}; see artifacts/ui-driver.log")
            resp = json.loads(line)
        if resp.get("id") != rid:
            raise RuntimeError(f"E2E-INFRA: UI driver protocol out of sync ({resp.get('id')} != {rid})")
        if not resp.get("ok"):
            raise UiError(f"UI {op}: {resp.get('error')}")
        return resp.get("result")

    def register_secret(self, value: str) -> None:
        """A secret the UI showed or that was typed (a key file, an issued
        token): scrubbed by the driver and by the artifact guard."""
        artifact_guard.remember(value)
        self.call("secrets", values=[value])

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        atexit.unregister(self.close)
        try:
            if self._proc.stdin:
                self._proc.stdin.close()
            self._proc.wait(timeout=30)
        except Exception:  # noqa: BLE001 - a hung driver tree is terminated below
            self._terminate_group()
        finally:
            # A crashed Node leader can exit while Chrome descendants remain.
            # Reap that exact process group even when wait() itself succeeded.
            self._terminate_group()
            self._log.close()

    def _terminate_group(self) -> None:
        pgid = self._proc.pid
        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            return
        except PermissionError:
            return
        try:
            os.killpg(pgid, signal.SIGTERM)
        except ProcessLookupError:
            return
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                os.killpg(pgid, 0)
            except ProcessLookupError:
                return
            time.sleep(0.1)
        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            self._proc.wait(timeout=5)
        except Exception:  # noqa: BLE001 - the OS owns any already-reaped child
            pass


def _readline(stream: Any, timeout: float) -> str:
    out: list[str] = []
    t = threading.Thread(target=lambda: out.append(stream.readline()), daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        raise RuntimeError(f"E2E-INFRA: UI driver did not answer within {timeout:.0f}s")
    return out[0] if out else ""


_SID = itertools.count(1)


@dataclass
class UiPage:
    """One scenario's isolated browser context."""

    driver: Driver
    sid: int
    out: Path

    @classmethod
    def open(cls, driver: Driver, out: Path, name: str = "") -> UiPage:
        sid = next(_SID)
        driver.call("open", sid=sid, out=str(out), name=name)
        return cls(driver, sid, out)

    def finish(self, failed: bool) -> None:
        self.driver.call("close", sid=self.sid, failed=failed)

    def op(self, op: str, **args: Any) -> Any:
        return self.driver.call(op, sid=self.sid, **args)

    # navigation
    def goto(self, path: str) -> str:
        return self.op("goto", path=path)

    @property
    def url(self) -> str:
        return self.op("url")

    def reload(self) -> str:
        return self.op("reload")

    def wait_url(self, pattern: str, timeout_ms: int = 30_000) -> str:
        return self.op("wait_url", re=pattern, timeout=timeout_ms)

    # generic finder ops (FINDER in driver.mjs)
    def click(self, find: dict[str, Any], timeout_ms: int | None = None) -> None:
        self.op("click", find=find, timeout=timeout_ms)

    def count(self, find: dict[str, Any]) -> int:
        return self.op("count", find=find)

    def texts(self, find: dict[str, Any]) -> list[str]:
        return self.op("texts", find=find)

    def wait_text(
        self, text: str | dict[str, str], exact: bool = True, timeout_ms: int = 20_000, gone: bool = False
    ) -> None:
        self.op("wait_text", text=text, exact=exact, timeout=timeout_ms, gone=gone)

    def wait_for(self, find: dict[str, Any], timeout_ms: int = 20_000, gone: bool = False) -> None:
        self.op("wait_for", find=find, timeout=timeout_ms, gone=gone)

    def fill(self, *fields: dict[str, Any]) -> None:
        self.op("fill", fields=list(fields))

    def choose(self, trigger: dict[str, Any], option: str | dict[str, str], exact: bool = False) -> None:
        self.op("choose", trigger=trigger, option=option, exact=exact)

    def row_cells(self, contains: str, within: dict[str, Any] | None = None) -> dict[str, str]:
        """The first table row containing `contains`, as {lowercased header: cell}."""
        return self.op("row_cells", contains=contains, within=within)

    def clipboard(self) -> str:
        """What the page put on the clipboard (copy buttons)."""
        return self.op("clipboard")

    def download(self, find: dict[str, Any], timeout_ms: int = 30_000) -> tuple[str, str]:
        """Click a download control; (file name, contents) of what was saved."""
        d = self.op("download", find=find, timeout=timeout_ms)
        return d["name"], d["text"]

    def screenshot(self, name: str, *, full_page: bool = True) -> Path:
        """Save a secret-scrubbed acceptance screenshot in this scenario's UI artifacts."""
        return Path(self.op("screenshot", name=name, full_page=full_page))

    def attr(self, find: dict[str, Any], name: str) -> str | None:
        return self.op("attr", find=find, name=name)

    def rect(self, find: dict[str, Any]) -> dict[str, float]:
        """Bounding box of the element (left/top/right/bottom/width/height) and
        the viewport size (viewport_width/viewport_height)."""
        return self.op("rect", find=find)

    def value(self, find: dict[str, Any]) -> str:
        return self.op("value", find=find)

    def editor_fill(self, find: dict[str, Any], value: str) -> None:
        """Replace a CodeMirror document through its contenteditable surface."""
        self.op("editor_fill", find=find, value=value)

    def wait_attr(self, find: dict[str, Any], name: str, value: str, timeout_ms: int = 20_000) -> None:
        self.op("wait_attr", find=find, name=name, value=value, timeout=timeout_ms)

    def contains(self, text: str) -> bool:
        """Whether the page's current DOM contains `text` (never returns the DOM)."""
        return self.op("page_contains", text=text)

    def responses_containing(self, text: str, since_ms: int = 0, except_path: str | None = None) -> list[str]:
        """`METHOD /path` of every API response since `since_ms` whose body
        contains `text` (bodies themselves never leave the driver)."""
        return self.op("responses_containing", text=text, since=since_ms, except_path=except_path)

    def requests_containing(self, text: str, since_ms: int = 0) -> list[str]:
        """`METHOD url` of every request since `since_ms` whose URL contains `text`."""
        return self.op("requests_containing", text=text, since=since_ms)

    def upload(self, find: dict[str, Any], path: str) -> None:
        """Choose `path` in a file input (the native picker is bypassed)."""
        self.op("upload", find=find, path=path)

    def page_errors(self) -> list[str]:
        """Uncaught page errors seen in this context so far."""
        return self.op("page_errors")

    def main_text(self) -> str:
        """The page's visible main-content text (bounded)."""
        return self.op("main_text")

    def press_key(self, find: dict[str, Any], key: str) -> None:
        self.op("press_key", find=find, key=key)

    def now_ms(self) -> int:
        return self.driver.call("now")

    def select_native(self, find: dict[str, Any], value: str) -> None:
        self.op("select_native", find=find, value=value)


def field(find: dict[str, Any], value: str, secret: bool = False) -> dict[str, Any]:
    """A form field to fill; `secret` ones are scrubbed and never photographed."""
    return {"find": find, "value": value, "secret": secret}


def press(find: dict[str, Any]) -> dict[str, Any]:
    """A click inside a fill sequence (e.g. pick an auth mode before its fields)."""
    return {"find": find, "click": True}


# ---------------------------------------------------------------- flows
def login(page: UiPage, email: str, password: str) -> None:
    """The terminal-style login; returns once the app left /login."""
    page.op("login", email=email, password=password)


def login_attempt(page: UiPage, email: str, password: str) -> None:
    """Type the credentials without expecting to get in."""
    page.op("login_attempt", email=email, password=password)


def first_run_setup(page: UiPage, name: str, email: str, password: str, setup_token: str = "") -> None:
    """/setup: the first-run admin form, through to the redirect to /login.
    `setup_token` fills the setup-token field when the page shows it (NAN-5237)."""
    page.op("first_run_setup", name=name, email=email, password=password, setupToken=setup_token)


def run_search(page: UiPage, query: str, extra: str = "") -> str:
    """Open /search with the query and run it (`?q=<query>&run=true`, the
    share-link contract), then wait for the run to finish. Returns the URL."""
    return page.op("search", query=query, extra=extra)


def results_count(page: UiPage) -> int:
    """The event count the Results header shows ("N events")."""
    return page.op("results_count")


def result_rows_text(page: UiPage) -> list[str]:
    """One text per rendered result row (the virtualized list's items)."""
    return page.op("result_rows")


def table_rows(page: UiPage) -> tuple[list[str], list[list[str]]]:
    """(header, rows) of the results table (stats/timechart)."""
    t = page.op("table")
    return t["header"], t["rows"]


def tail(page: UiPage, interval: str) -> None:
    """Turn the live tail on at `interval` (the interval menu enables it)."""
    page.op("tail", interval=interval)


@dataclass
class FieldValues:
    unique: int
    events: int
    percent: dict[str, float]


def sidebar_group(page: UiPage, label: str) -> None:
    """Open a field group of the search sidebar (Unmapped / Extended)."""
    page.op("sidebar_group", label=label)


def sidebar_field(page: UiPage, field_name: str) -> FieldValues:
    """Expand a sidebar field (once); return "N unique · M events" and value
    percents as shown now. Counts start from the loaded page and settle when
    the full field stats arrive: poll with `eventually` to compare."""
    v = page.op("sidebar_field", field=field_name)
    return FieldValues(v["unique"], v["events"], v["percent"])
