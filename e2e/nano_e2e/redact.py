"""Redact secrets from pytest output (NAN-5869).

Assertion messages, exception text, pytest's traceback locals and captured
stdout/stderr go to the terminal, the lane log and junit XML, none of which
the artifact guard scrubs. A failing `psql <dsn>` call printed a throwaway
Postgres URL with its password there (CalledProcessError repeats its argv,
and the traceback shows `popenargs`). So every report pytest makes, test
phases and collection alike, passing or not, is rewritten before any reporter
sees it:

- URL userinfo passwords (`scheme://user:PASSWORD@host`) become `<redacted>`;
- `password=` / `password: ` values, quoted or not, become `<redacted>`;
- `Authorization: Bearer|Basic|Splunk <token>` and `X-API-Key: <key>` values
  become `<redacted>`;
- every known secret value becomes `<redacted>`: the same set the artifact
  guard scrubs (the process env, the run's 0600 registry, the run's
  compose.env and admin.env, and the C05 license file).

The module is a pytest plugin (hooks at the bottom). Stdlib + pytest only.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable, Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from nano_e2e import artifact_guard

REDACTED = artifact_guard.REDACTED
# scheme://user:password@ ; the password runs up to the `@` and never spans
# whitespace, quotes or `/` (so `http://host:8080/a@b` keeps its port).
_URL_USERINFO = re.compile(r"(?P<head>\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:/@'\"]*:)(?P<pw>[^\s@'\"/]+)(?=@)")
# KEY=VALUE / KEY: VALUE / "KEY": "VALUE" for any key ENDING in a secret
# word: password, PGPASSWORD, ch_admin_password, access_token, ingest_token,
# client_secret, api_key, x-api-key. Values:
# - quoted ('...' or "..."), escapes inside honored ("a\"b" is one value);
# - escaped-quote delimited (\"...\" in a source line or a repr);
# - bare, up to whitespace or a separator.
_KEY_HEAD = r"(?P<head>\b[\w-]*?(?:password|passwd|pwd|secret|api[_-]?key|token)\\?[\"']?\s*[=:]\s*)"
_VALUE = (
    r"(?:(?P<bs>\\+)(?P<q>[\"'])(?P<qv>(?:(?!\\+(?P=q)).)*)\\+(?P=q)"
    r"|(?P<q2>[\"'])(?P<qv2>(?:\\.|(?!(?P=q2))[^\\])*)(?P=q2)"
    r"|(?P<bare>[^\s'\"&;,)\]}]+))"
)
_KV_PASSWORD = re.compile(_KEY_HEAD + _VALUE, re.I)
_AUTH_HEADER = re.compile(
    r"(?P<head>\bauthorization\\?[\"']?\s*[=:]\s*\\?[\"']?(?:bearer|basic|splunk)\s+)(?P<tok>[A-Za-z0-9._~+/=\-]+)", re.I
)


def _strip_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1]
    return value


def known_secrets() -> list[str]:
    """The values the artifact guard scrubs for this run (scripts/e2e.sh
    `scrub_artifacts`), plus env-file values with their quotes removed."""
    try:
        run_dir = os.environ.get("E2E_RUN_DIR")
        env_files = [Path(run_dir) / name for name in ("compose.env", "admin.env")] if run_dir else []
        lic = os.environ.get("NANO_E2E_C05_LICENSE_FILE")
        vals = artifact_guard.env_secrets()
        vals += artifact_guard.load(artifact_guard.registry_path(), env_files, [Path(lic)] if lic else [])
        vals += [_strip_quotes(v) for v in vals]
        return artifact_guard.expand(v for v in vals if len(v) >= artifact_guard.MIN_LEN)
    except Exception:  # noqa: BLE001 - redaction must never fail a report
        return []


def _kv(m: re.Match[str]) -> str:
    if m.group("q") is not None:
        quote = m.group("bs") + m.group("q")
        return f"{m.group('head')}{quote}{REDACTED}{quote}"
    if m.group("q2") is not None:
        return f"{m.group('head')}{m.group('q2')}{REDACTED}{m.group('q2')}"
    return m.group("head") + REDACTED


def redact_text(text: str, secrets: Iterable[str] = ()) -> str:
    if not text:
        return text
    for value in secrets:
        if value and value in text:
            text = text.replace(value, REDACTED)
    text = _URL_USERINFO.sub(lambda m: m.group("head") + REDACTED, text)
    text = _AUTH_HEADER.sub(lambda m: m.group("head") + REDACTED, text)
    return _KV_PASSWORD.sub(_kv, text)


class RedactedRepr:
    """A failure repr whose text was redacted. Keeps `reprcrash` (with a
    redacted message) so the short summary and junit `message` still work."""

    def __init__(self, text: str, reprcrash: Any = None):
        self.text = text
        self.reprcrash = reprcrash

    def toterminal(self, tw: Any) -> None:
        for line in self.text.splitlines():
            tw.line(line)

    def __str__(self) -> str:
        return self.text


def redact_report(report: Any, secrets: Iterable[str] | None = None) -> None:
    """Rewrite any pytest report in place: captured sections always; the
    longrepr whenever there is one (failures, errors, skips, xfails)."""
    secrets = known_secrets() if secrets is None else list(secrets)
    report.sections = [(title, redact_text(body, secrets)) for title, body in report.sections]
    if isinstance(getattr(report, "wasxfail", None), str):
        report.wasxfail = redact_text(report.wasxfail, secrets)
    longrepr = report.longrepr
    if longrepr is None:
        return
    if isinstance(longrepr, tuple) and len(longrepr) == 3:
        # A skip: (path, lineno, reason); reporters unpack it, keep the shape.
        path, lineno, reason = longrepr
        report.longrepr = (path, lineno, redact_text(str(reason), secrets))
        return
    try:
        text = report.longreprtext
    except Exception:  # noqa: BLE001
        text = str(longrepr)
    clean = redact_text(text, secrets)
    if clean == text:
        return
    crash = getattr(longrepr, "reprcrash", None)
    if crash is not None:
        try:
            crash = replace(crash, message=redact_text(crash.message, secrets))
        except Exception:  # noqa: BLE001 - not a dataclass on this pytest
            crash = None
    report.longrepr = RedactedRepr(clean, crash)


# Loaded as a plugin: `-p nano_e2e.redact`, or tests/conftest.py's
# pytest_configure. Hookwrappers, so every reporter (terminal, junit, the
# harness's own rep_<when>) reads the redacted report.
@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo) -> Iterator[None]:
    outcome = yield
    redact_report(outcome.get_result())


@pytest.hookimpl(hookwrapper=True)
def pytest_make_collect_report(collector: pytest.Collector) -> Iterator[None]:
    outcome = yield
    redact_report(outcome.get_result())
