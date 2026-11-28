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
- Layout invariants (NAN-5762): after every op `UiPage` asks the driver to
  measure the page (no sideways overflow in the main pane, scrollers, flyouts
  and drawers; nothing escaping its card; no link or button painted over). A
  violation fails the scenario with `layout-<n>.png` (offenders outlined) and
  `layout.jsonl`. `NANO_E2E_LAYOUT=report` records without failing, `off`
  skips it; intentional exceptions go in `e2e/coverage/layout-allowlist.json`.
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
from dataclasses import dataclass, field as dc_field
from pathlib import Path
from typing import Any

from nano_e2e import artifact_guard
from nano_e2e.client import _secret_values

ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / "nanosiem-web"
DRIVER = WEB / "tests" / "e2e" / "ui" / "driver.mjs"
OP_TIMEOUT = 300.0  # ops wait on the UI themselves (20-60 s); this only bounds a hung driver
_SECRET_ENV = re.compile(r"(SECRET|PASSWORD|_KEY|TOKEN|SA_JSON|ADC|CONNECTION_STRING|DATABASE_URL|_DSN)")
LAYOUT_ALLOWLIST = ROOT / "e2e" / "coverage" / "layout-allowlist.json"
A11Y_ALLOWLIST = ROOT / "e2e" / "coverage" / "a11y-allowlist.json"
_A11Y_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_A11Y_RULE_RE = re.compile(r"^[a-z][a-z0-9-]*$")
_A11Y_ISSUE_RE = re.compile(r"^NAN-\d+$")
_A11Y_BLOCKING_IMPACTS = frozenset({"critical", "serious"})
# Ops after which the page cannot have changed (protocol, reads of harness
# state, artifacts): no layout or a11y check follows them.
_LAYOUT_QUIET_OPS = frozenset(
    {
        "secrets", "open", "close", "url", "now", "layout_check", "a11y_scan",
        "events_since", "api_responses_since",
        "page_errors", "responses_containing", "requests_containing", "screenshot", "mask_secrets", "dump",
        "session_fetch", "end_session", "clipboard", "page_contains", "storage_clear", "capture_window_open",
        "opened",
        # NAN-5864: only updates the driver's stub table; the page is untouched.
        "stub_api",
    }
)


def layout_mode() -> str:
    """`enforce` (default): a layout violation fails the scenario; `report`:
    recorded in layout.jsonl only; `off`: not measured (NAN-5762)."""
    mode = os.environ.get("NANO_E2E_LAYOUT", "enforce").strip().lower() or "enforce"
    if mode not in ("enforce", "report", "off"):
        raise RuntimeError(f"NANO_E2E_LAYOUT={mode!r}: expected enforce, report or off")
    return mode


def parse_a11y_mode(raw: str | None) -> str:
    """One strict parser, the same as driver.mjs parseA11yMode(): off, report or
    enforce in any case, surrounding spaces ignored, unset or empty = off. Any
    other value raises, so a typo never silently turns the scan on or off."""
    mode = (raw or "").strip().lower() or "off"
    if mode not in ("enforce", "report", "off"):
        raise RuntimeError(f"NANO_E2E_A11Y={raw!r}: expected enforce, report or off")
    return mode


def a11y_mode() -> str:
    """`off` (default): not measured; `report`: recorded in a11y.jsonl only;
    `enforce`: unallowlisted critical/serious WCAG violations fail the scenario."""
    return parse_a11y_mode(os.environ.get("NANO_E2E_A11Y"))


def _redact_a11y(value: Any) -> Any:
    """Run the shared pytest report scrubber (nano_e2e.redact: registered run
    secrets, URL passwords, auth and cookie headers, secret-named key=value
    pairs) over every string of an a11y_scan result."""
    try:
        from nano_e2e import redact  # lazy: nano-suite imports this module without pytest plugins
    except Exception:  # noqa: BLE001 - fall back to the artifact guard's secret set
        secrets = artifact_guard.expand(artifact_guard.env_secrets())

        def text(t: str) -> str:
            for v in secrets:
                if v and v in t:
                    t = t.replace(v, artifact_guard.REDACTED)
            return t
    else:
        known = redact.known_secrets()

        def text(t: str) -> str:
            return redact.redact_text(t, known)

    def walk(v: Any) -> Any:
        if isinstance(v, str):
            return text(v)
        if isinstance(v, list):
            return [walk(x) for x in v]
        if isinstance(v, dict):
            return {k: walk(x) for k, x in v.items()}
        return v

    return walk(value)


class UiError(AssertionError):
    """The UI did not show what a step needed (E2E-PRODUCT: a red result)."""


class LayoutError(AssertionError):
    """A page broke a layout invariant (NAN-5762). Deliberately NOT a UiError:
    scenarios that catch UiError around a probing op must not swallow it."""


class A11yError(AssertionError):
    """A page broke a WCAG 2.0/2.1 A/AA critical or serious axe-core rule.
    Deliberately NOT a UiError so probing ops cannot swallow it."""


def a11y_selector_problem(sel: str) -> str | None:
    """Why an allowlist selector or within is too broad, or None when it is
    specific. Mirrors driver.mjs a11ySelectorProblem() exactly: CSS escapes,
    quoted strings, [attribute] bodies and (...) arguments are blanked first;
    then a universal "*" or a selector list is refused, and the last compound
    (the element the rule applies to) needs a non-empty id, class or
    attribute. So *, html, body, :root, div, ".", "div, *", "body *" and
    :not(.x) are all refused. Nor may the last part be the document root
    (html[lang], body.dark, :root:not(.x), html > body), whatever its
    qualifiers: as a within every element is inside it."""
    s = re.sub(r"\\.", "_", sel)
    s = re.sub(r"\"[^\"]*\"|'[^']*'", '"x"', s)
    s = re.sub(r"\[([^\]]*)\]", lambda m: "[a]" if m.group(1).strip() else "[]", s)
    while True:
        nxt = re.sub(r"\([^()]*\)", "()", s)
        if nxt == s:
            break
        s = nxt
    if "*" in s:
        return 'uses the universal "*" selector'
    if "," in s:
        return "is a selector list; use one selector per entry"
    parts = [p for p in re.split(r"\s*[>+~]\s*|\s+", s.strip()) if p]
    subject = parts[-1] if parts else ""
    if not re.search(r"#[A-Za-z0-9_-]|\.[A-Za-z0-9_-]|\[a\]", subject):
        return "is too broad; its last part needs an id (#x), a class (.x) or an attribute ([x=y])"
    if re.match(r"(?:html|body)(?![A-Za-z0-9_-])", subject, re.I) or re.search(r":root(?![A-Za-z0-9_-])", subject, re.I):
        return "is the whole page; every element is inside html, body or :root"
    return None


def _a11y_route_regex(route: str) -> str:
    escaped = re.escape(route)
    escaped = re.sub(r"\\?:[A-Za-z_][A-Za-z0-9_]*", r"[^/]+", escaped)
    return f"^{escaped}/?$"


def validate_a11y_allowlist(
    doc: dict[str, Any], *, valid_surfaces: set[str] | None = None
) -> list[str]:
    """Validate `e2e/coverage/a11y-allowlist.json` schema; return list of errors."""
    errors: list[str] = []
    if not isinstance(doc, dict) or not isinstance(doc.get("entries"), list):
        return ['a11y-allowlist.json: requires an "entries" list']
    seen: set[str] = set()
    for idx, entry in enumerate(doc["entries"]):
        where = f"a11y-allowlist.json entry {idx}"
        if not isinstance(entry, dict):
            errors.append(f"{where}: must be an object")
            continue
        eid = entry.get("id")
        if not isinstance(eid, str) or not _A11Y_ID_RE.fullmatch(eid):
            errors.append(f'{where}: needs an "id" (letters, digits, . _ -)')
        elif eid in seen:
            errors.append(f"{where}: duplicate id {eid!r}")
        else:
            seen.add(eid)
            where = f"a11y-allowlist.json {eid}"
        rule = entry.get("rule")
        if (
            not isinstance(rule, str)
            or not _A11Y_RULE_RE.fullmatch(rule)
            or rule in ("any", "all")
        ):
            errors.append(f'{where}: "rule" must be an exact axe rule ID (wildcards forbidden)')
        selector = entry.get("selector")
        within = entry.get("within")
        has_selector = isinstance(selector, str) and bool(selector.strip())
        has_within = isinstance(within, str) and bool(within.strip())
        if not has_selector and not has_within:
            errors.append(f'{where}: needs at least one of "selector" or "within"')
        for name, value, present in (("selector", selector, has_selector), ("within", within, has_within)):
            problem = a11y_selector_problem(value.strip()) if present else None
            if problem:
                errors.append(f'{where}: "{name}" {value.strip()!r} {problem}')
        reason = entry.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            errors.append(f'{where}: needs a non-empty "reason"')
        surfaces = entry.get("surfaces", [])
        if not isinstance(surfaces, list) or any(
            not isinstance(s, str) or not s.strip() or s != s.strip() or "*" in s or not s.startswith("/")
            for s in surfaces
        ):
            errors.append(
                f'{where}: "surfaces" must be a list of concrete "/..." ui-surfaces.json keys without wildcards'
            )
        elif valid_surfaces is not None:
            for surface in surfaces:
                if surface not in valid_surfaces:
                    errors.append(f"{where}: surface {surface!r} is not in ui-surfaces.json")
        raw_temporary = entry.get("temporary", False)
        if not isinstance(raw_temporary, bool):
            errors.append(f'{where}: "temporary" must be a boolean')
            is_temp = False
        else:
            is_temp = raw_temporary
        issue = entry.get("issue")
        if issue is not None and not (isinstance(issue, str) and _A11Y_ISSUE_RE.fullmatch(issue)):
            errors.append(f'{where}: "issue" must match NAN-<id>')
        if is_temp and not (isinstance(issue, str) and _A11Y_ISSUE_RE.fullmatch(issue)):
            errors.append(f'{where}: temporary entry needs "issue" matching NAN-<id>')
    return errors


_CSS_SIMPLE_TOKEN_RE = re.compile(
    r"#(?:[A-Za-z0-9_-]|\\.)+|\.(?:[A-Za-z0-9_-]|\\.)+|\[[^\]]+\]|::?[A-Za-z0-9_-]+(?:\([^)]*\))?|[A-Za-z][A-Za-z0-9_-]*"
)
_CSS_ATTR_NORM_RE = re.compile(r'^\[\s*([^\s=~|^$*\]]+)\s*([~|^$*]?=)\s*(?:"([^"]*)"|\'([^\']*)\'|([^\]]*))\s*\]$')


def _normalize_css_token(token: str) -> str:
    m = _CSS_ATTR_NORM_RE.match(token)
    if not m:
        return token
    val = m.group(3) if m.group(3) is not None else (m.group(4) if m.group(4) is not None else m.group(5).strip())
    return f"[{m.group(1)}{m.group(2)}{val}]"


def _split_css_parts(selector: str) -> tuple[list[str], list[str]]:
    """Split one CSS selector into compound segments and the combinators
    between them (" ", ">", "+" or "~"), outside brackets, parens, quotes and
    backslash escapes."""
    segments: list[str] = []
    combs: list[str] = []
    buf: list[str] = []
    pending = ""
    bracket_depth = 0
    paren_depth = 0
    quote: str | None = None
    escape = False
    for ch in selector.strip():
        if escape:
            buf.append(ch)
            escape = False
            continue
        if ch == "\\":
            buf.append(ch)
            escape = True
            continue
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
            buf.append(ch)
        elif ch == "[":
            bracket_depth += 1
            buf.append(ch)
        elif ch == "]":
            bracket_depth = max(0, bracket_depth - 1)
            buf.append(ch)
        elif ch == "(":
            paren_depth += 1
            buf.append(ch)
        elif ch == ")":
            paren_depth = max(0, paren_depth - 1)
            buf.append(ch)
        elif bracket_depth == 0 and paren_depth == 0 and (ch.isspace() or ch in (">", "+", "~")):
            if buf:
                if segments:
                    combs.append(pending or " ")
                segments.append("".join(buf))
                buf = []
                pending = ""
            if ch in (">", "+", "~"):
                pending = ch
        else:
            buf.append(ch)
    if buf:
        if segments:
            combs.append(pending or " ")
        segments.append("".join(buf))
    return segments, combs


def _split_css_segments(selector: str) -> list[str]:
    """Split a single CSS selector into compound segments (combinators dropped)."""
    return _split_css_parts(selector)[0]


# A wanted combinator matches the actual one when every element pair the
# actual relation picks also satisfies the wanted one: a child is also a
# descendant, an adjacent sibling is also a general sibling. Never the reverse.
_CSS_COMB_OK = {" ": {" ", ">"}, ">": {">"}, "~": {"~", "+"}, "+": {"+"}}


def _css_combs_match(want: list[str], actual: list[str]) -> bool:
    return len(want) == len(actual) and all(a in _CSS_COMB_OK[w] for w, a in zip(want, actual, strict=True))


def _split_top_level_commas(selector: str) -> list[str]:
    """Split a selector list on commas outside brackets, parens, quotes and escapes."""
    out: list[str] = []
    buf: list[str] = []
    depth = 0
    quote: str | None = None
    escape = False
    for ch in selector:
        if escape:
            buf.append(ch)
            escape = False
        elif ch == "\\":
            buf.append(ch)
            escape = True
        elif quote:
            buf.append(ch)
            if ch == quote:
                quote = None
        elif ch in ("'", '"'):
            quote = ch
            buf.append(ch)
        elif ch in "[(":
            depth += 1
            buf.append(ch)
        elif ch in "])":
            depth = max(0, depth - 1)
            buf.append(ch)
        elif ch == "," and depth == 0:
            out.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    out.append("".join(buf).strip())
    return [p for p in out if p]


def _css_compound_tokens(segment: str) -> set[str] | None:
    tokens = _CSS_SIMPLE_TOKEN_RE.findall(segment)
    if not tokens or "".join(tokens) != segment:
        return None
    return {_normalize_css_token(t) for t in tokens}


def _css_segment_matches(want_seg: str, actual_seg: str) -> bool:
    if want_seg == actual_seg:
        return True
    want_tokens = _css_compound_tokens(want_seg)
    actual_tokens = _css_compound_tokens(actual_seg)
    if want_tokens is None or actual_tokens is None:
        return False
    return want_tokens.issubset(actual_tokens)


def _css_selector_leaf_matches(want_selector: str, actual_selector: str) -> bool:
    want_segs, want_combs = _split_css_parts(want_selector)
    if not want_segs:
        return False
    for part in _split_top_level_commas(actual_selector):
        actual_segs, actual_combs = _split_css_parts(part)
        if len(actual_segs) < len(want_segs):
            continue
        n = len(want_segs)
        tail = actual_segs[-n:]
        tail_combs = actual_combs[len(actual_combs) - (n - 1) :] if n > 1 else []
        if _css_combs_match(want_combs, tail_combs) and all(
            _css_segment_matches(w, a) for w, a in zip(want_segs, tail, strict=True)
        ):
            return True
    return False


def _css_within_matches(want_within: str, actual_selector: str, ancestors: list[str]) -> bool:
    want_segs, want_combs = _split_css_parts(want_within)
    if not want_segs:
        return False
    candidates = [*ancestors, *_split_top_level_commas(actual_selector)]
    n = len(want_segs)
    for cand in candidates:
        cand_segs, cand_combs = _split_css_parts(cand)
        if len(cand_segs) < n:
            continue
        for start in range(len(cand_segs) - n + 1):
            window = cand_segs[start : start + n]
            window_combs = cand_combs[start : start + n - 1]
            if _css_combs_match(want_combs, window_combs) and all(
                _css_segment_matches(w, a) for w, a in zip(want_segs, window, strict=True)
            ):
                return True
    return False


def match_a11y_allowlist(
    violation: dict[str, Any],
    entries: list[dict[str, Any]],
) -> str | None:
    """Return matching allowlist entry id for a violation dict, or None.

    The same rules as driver.mjs a11yMatchAll(), on selector strings instead
    of the DOM: exact rule; a surface (if any) matches the path or path+query
    (`search`); "selector" matches the offending element's selector;
    "within" matches it or one of `ancestors`. It can only miss a match the
    DOM would find (it never allows more); the parity fixtures pin this."""
    rule = str(violation.get("rule") or "")
    route = str(violation.get("route") or "")
    full = route + str(violation.get("search") or "")
    selector = str(violation.get("selector") or "")
    ancestors = [str(a) for a in (violation.get("ancestors") or ())]
    for entry in entries:
        if entry.get("rule") != rule:
            continue
        surfaces = entry.get("surfaces") or []
        if surfaces and not any(
            re.search(_a11y_route_regex(s), route) or re.search(_a11y_route_regex(s), full) for s in surfaces
        ):
            continue
        want_sel = entry.get("selector")
        if want_sel and not _css_selector_leaf_matches(str(want_sel), selector):
            continue
        want_within = entry.get("within")
        if want_within and not _css_within_matches(str(want_within), selector, ancestors):
            continue
        return str(entry.get("id"))
    return None


def format_layout(violations: list[dict[str, Any]], after: str, screenshot: str | None) -> str:
    lines = [f"LAYOUT (NAN-5762): {len(violations)} violation(s) after `{after}`:"]
    for v in violations:
        where = f" in {v['container']}" if v.get("container") else ""
        lines.append(f"  - {v['kind']} on {v['route']}: {v['element']}{where} {json.dumps(v.get('detail'))}")
    if screenshot:
        lines.append(f"  screenshot (offenders outlined): {screenshot}")
    lines.append(
        f"  intentional? add an entry with a reason to {LAYOUT_ALLOWLIST.relative_to(ROOT)}; "
        "a bug? fix it, or pin the step with known_bug"
    )
    return "\n".join(lines)


def format_a11y(violations: list[dict[str, Any]], after: str) -> str:
    lines = [f"A11Y (WCAG 2.1 AA): {len(violations)} blocking violation(s) after `{after}`:"]
    for v in violations:
        rule = v.get("rule", "unknown")
        impact = v.get("impact", "serious")
        route = v.get("route", "")
        theme = v.get("theme", "")
        selector = v.get("selector", "")
        help_txt = v.get("help", "")
        suffix = f" ({help_txt})" if help_txt else ""
        lines.append(f"  - [{impact}] {rule} on {route} [{theme}]: {selector}{suffix}")
    lines.append(
        f"  intentional? add a justified entry to {A11Y_ALLOWLIST.relative_to(ROOT)}; "
        "a bug? fix it or add a temporary entry with issue: NAN-<id>"
    )
    return "\n".join(lines)


def rx(pattern: str, flags: str = "") -> dict[str, str]:
    """A regex accessible-name / text matcher for the driver's finder."""
    return {"re": pattern, "flags": flags}


def driver_env(base_url: str) -> dict[str, str]:
    """The driver's environment: the base URL, and NO harness secret."""
    env = {k: v for k, v in os.environ.items() if not _SECRET_ENV.search(k)}
    env["E2E_UI_BASE"] = base_url
    env.setdefault("E2E_LAYOUT_ALLOWLIST", str(LAYOUT_ALLOWLIST))
    env.setdefault("E2E_A11Y_ALLOWLIST", str(A11Y_ALLOWLIST))
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
    layout: str = dc_field(default_factory=layout_mode)
    layout_violations: list[dict[str, Any]] = dc_field(default_factory=list)
    a11y: str = dc_field(default_factory=a11y_mode)
    a11y_violations: list[dict[str, Any]] = dc_field(default_factory=list)
    a11y_warnings: list[dict[str, Any]] = dc_field(default_factory=list)
    a11y_unavailable_reason: str | None = None

    @classmethod
    def open(cls, driver: Driver, out: Path, name: str = "") -> UiPage:
        sid = next(_SID)
        driver.call("open", sid=sid, out=str(out), name=name)
        return cls(driver, sid, out)

    def finish(self, failed: bool) -> None:
        """Close the context. A layout or a11y violation that a scenario
        swallowed (an `eventually` retry catches AssertionError) or that the
        final state shows still fails it here, after the artifacts are written."""
        if not failed and self.layout != "off":
            try:
                self.check_layout("finish", force=True, raise_=False)  # no later op re-measures
            except (UiError, RuntimeError) as exc:  # a dead page: the close below reports it
                print(f"WARNING: final layout check failed to run: {exc}")
        if not failed and self.a11y != "off":
            try:
                self.check_a11y("finish", force=True, raise_=False)
            except (UiError, RuntimeError) as exc:
                print(f"WARNING: final a11y check failed to run: {exc}")
        late_layout = bool(self.layout_violations) and self.layout == "enforce" and not failed
        late_a11y = bool(self.a11y_violations) and self.a11y == "enforce" and not failed
        late_a11y_unavail = bool(self.a11y_unavailable_reason) and self.a11y == "enforce" and not failed
        self.driver.call(
            "close",
            sid=self.sid,
            failed=failed or late_layout or late_a11y or late_a11y_unavail,
        )
        if late_layout:
            raise LayoutError(format_layout(self.layout_violations, "the scenario (reported at teardown)", None))
        if late_a11y:
            raise A11yError(format_a11y(self.a11y_violations, "the scenario (reported at teardown)"))
        if late_a11y_unavail:
            raise RuntimeError(f"NANO_E2E_A11Y=enforce: {self.a11y_unavailable_reason}")

    def op(self, op: str, **args: Any) -> Any:
        result = self.driver.call(op, sid=self.sid, **args)
        if op not in _LAYOUT_QUIET_OPS and self.layout != "off":
            self.check_layout(op)
        if op not in _LAYOUT_QUIET_OPS and self.a11y != "off":
            self.check_a11y(op)
        return result

    def check_layout(self, after: str = "explicit", *, force: bool = False, raise_: bool = True) -> list[dict[str, Any]]:
        """Measure the layout invariants now (NAN-5762); every op already does
        this. Returns the new violations (allowlisted ones excluded)."""
        r = self.driver.call("layout_check", sid=self.sid, force=force, after=after) or {}
        bad = r.get("violations") or []
        if bad:
            self.layout_violations.extend(bad)
            if raise_ and self.layout == "enforce":
                raise LayoutError(format_layout(bad, after, r.get("screenshot")))
        return bad

    def check_a11y(
        self, after: str = "explicit", *, force: bool = False, raise_: bool = True
    ) -> dict[str, Any]:
        """Run an axe-core WCAG 2.0/2.1 A/AA scan on the current UI state.

        `off` skips the scan unless `force=True`; `report` logs findings without
        failing; `enforce` fails on unallowlisted critical/serious violations
        while keeping moderate/minor findings as warnings.
        """
        if self.a11y == "off" and not force:
            return {"available": True, "skipped": True, "blocking": [], "warnings": [], "allowed": []}
        try:
            return self._check_a11y(after, force=force, raise_=raise_)
        except A11yError:
            raise
        except Exception as exc:  # noqa: BLE001 - report mode must never fail a scenario
            if self.a11y == "enforce":
                raise
            reason = _redact_a11y(f"a11y scan failed: {type(exc).__name__}: {exc}")
            self.a11y_unavailable_reason = reason
            print(f"WARNING: a11y_scan failed after `{after}` (NANO_E2E_A11Y={self.a11y}, not failing): {reason}")
            return {"available": False, "reason": reason, "blocking": [], "warnings": [], "allowed": []}

    def _check_a11y(self, after: str, *, force: bool, raise_: bool) -> dict[str, Any]:
        r = self.driver.call("a11y_scan", sid=self.sid, force=force, after=after, mode=self.a11y)
        if r is None:
            r = {}
        if not isinstance(r, dict):
            raise RuntimeError(f"a11y_scan returned {type(r).__name__}, not an object")
        r = _redact_a11y(r)
        records = r.pop("records", None) or []
        if records:
            self.out.mkdir(parents=True, exist_ok=True)
            with (self.out / "a11y.jsonl").open("a", encoding="utf-8") as fh:
                for rec in records:
                    fh.write(json.dumps(rec) + "\n")
        if r.get("available") is False:
            reason = str(r.get("reason") or "axe-core unavailable")
            self.a11y_unavailable_reason = reason
            print(f"WARNING: a11y_scan unavailable after `{after}`: {reason}")
            if raise_ and self.a11y == "enforce":
                raise RuntimeError(f"NANO_E2E_A11Y=enforce: {reason}")
            return r
        raw_blocking = r.get("blocking")
        raw_warnings = r.get("warnings")
        if raw_blocking is None and raw_warnings is None:
            all_v = r.get("violations") or []
            blocking = [
                v for v in all_v
                if not v.get("allowed") and str(v.get("impact") or "").lower() in _A11Y_BLOCKING_IMPACTS
            ]
            warnings = [
                v for v in all_v
                if not v.get("allowed") and str(v.get("impact") or "").lower() not in _A11Y_BLOCKING_IMPACTS
            ]
        else:
            blocking = list(raw_blocking or [])
            warnings = list(raw_warnings or [])
        if warnings:
            self.a11y_warnings.extend(warnings)
        if blocking:
            self.a11y_violations.extend(blocking)
            if raise_ and self.a11y == "enforce":
                raise A11yError(format_a11y(blocking, after))
        return r

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

    def theme(self, mode: str) -> str:
        """Switch the app theme in place (`light` | `dark`, NAN-5561)."""
        return self.op("theme", mode=mode)

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

    # page health (NAN-5586)
    def events_since(self, since_ms: int = 0) -> dict[str, list[dict[str, Any]]]:
        """Console errors and failed requests (>= 400 or no response) since `since_ms`."""
        return self.op("events_since", since=since_ms)

    def api_responses_since(self, since_ms: int = 0) -> list[dict[str, Any]]:
        """Every completed /api response since `since_ms` (any status), as
        {method, url, status}: what the page fetched (bodies never cross)."""
        return self.op("api_responses_since", since=since_ms)

    def viewport(self, width: int, height: int | None = None) -> None:
        self.op("viewport", width=width, height=height)

    def overflow(self) -> dict[str, Any]:
        """Horizontal overflow at the current viewport: `document` / `main` px past
        the edge (0 = none) and up to five unclipped offending elements."""
        return self.op("overflow")

    def scroll_extent(self, find: dict[str, Any]) -> dict[str, Any]:
        """Horizontal scroll inside one container (NAN-5758): its scroll_width /
        client_width, descendant scrollers that scroll sideways, and up to five
        descendants whose box ends past its right edge."""
        return self.op("scroll_extent", find=find)

    def occlusion(self, find: dict[str, Any]) -> list[dict[str, Any]]:
        """For every match (NAN-5758): `covered` = the hit tests (centre and four
        corners) that land on something else, `on_top` when none do; `overlaps`
        = other text in its enclosing row (found from the parent, `scope`)
        whose box intersects it; `opacity` down the ancestor chain; its size."""
        return self.op("occlusion", find=find)

    def session_fetch(self, method: str, path: str, body: Any = None) -> dict[str, Any]:
        """`{status, json}` of an /api request made AS the logged-in browser user.
        A fetch torn down by a navigation in flight is retried."""
        for attempt in range(3):
            try:
                return self.op("session_fetch", method=method, path=path, body=body)
            except UiError as exc:
                if "Failed to fetch" not in str(exc) or attempt == 2:
                    raise
                time.sleep(1.0)
        raise AssertionError("unreachable")

    # deep workflows (NAN-5684)
    def drag(
        self, find: dict[str, Any], frm: tuple[float, float], to: tuple[float, float], hover: bool = False
    ) -> dict[str, float]:
        """A real mouse drag across the element; points are fractions of its box."""
        return self.op("drag", find=find, **{"from": list(frm)}, to=list(to), hover=hover)

    def chord(self, *keys: str) -> None:
        """Press a keyboard chord, e.g. chord("Meta", "k")."""
        self.op("chord", keys=list(keys))

    def hover(self, find: dict[str, Any]) -> None:
        self.op("hover", find=find)

    def stub_api(self, method: str, path: str, body: Any, status: int = 200) -> int:
        """Answer `method path` (an /api path, with its query string when the
        app sends one) with this JSON body from now on, in this session only
        (NAN-5864: banner and bell states a throwaway stack cannot reach).
        Returns how many requests the stub answered before this call."""
        return self.op("stub_api", method=method, path=path, body=body, status=status)

    def unstub_api(self, method: str, path: str) -> int:
        """Drop a stub; returns how many requests it answered."""
        return self.op("stub_api", method=method, path=path, clear=True)

    def scroll_bottom(self) -> int:
        """Scroll the app's scrollers to the bottom (infinite-scroll lists)."""
        return self.op("scroll_bottom")

    def capture_window_open(self) -> None:
        """Record window.open() URLs instead of opening tabs (see `opened`)."""
        self.op("capture_window_open")

    def opened(self) -> list[str]:
        return self.op("opened")

    def attrs(self, find: dict[str, Any], name: str) -> list[str | None]:
        """Attribute `name` of every match."""
        return self.op("attrs", find=find, name=name)

    def boxes(self, find: dict[str, Any], name: str | None = None) -> list[dict[str, Any]]:
        """Bounding boxes of every match, keyed by attribute `name`."""
        return self.op("boxes", find=find, name=name)

    def editor_text(self, find: dict[str, Any]) -> str:
        """The CodeMirror document inside `find`."""
        return self.op("editor_text", find=find)

    def end_session(self) -> dict[str, Any]:
        """DELETE this context's own server session (never POST /api/auth/logout,
        which ends every session of the user, NAN-5573)."""
        return self.op("end_session")


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
