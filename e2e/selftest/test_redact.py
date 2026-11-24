"""Output redaction (NAN-5869): a DSN with its password reached the lane log
through a CalledProcessError and pytest's traceback locals. Every class of
secret must be masked in the longrepr, the captured output (every phase,
passing tests too) and junit XML, and in collection errors."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from nano_e2e import redact
from nano_e2e.stack import Stack

# Each value must vanish from every output. Unique, so a hit names the class.
URL_PW = "UrlPw-111aaaa"
SQ_PW = "SqPw-222bbbb"
DQ_PW = "DqPw-333cccc"
ESC_PW = "EscPw-444dddd"
JSON_PW = "JsonPw-555eeee"
BEARER = "BearerTok-666ffff"
COMPOSE = "ComposeTok-777gggg"
ADMIN = "AdminPw-888hhhh"
LICENSE = "LicenseBody-999iiii"
REGISTRY = "RegistryTok-000jjjj"
ENVIRON = "EnvironSecret-121kkkk"
TEARDOWN = "TeardownPw-232llll"
PASSING = "PassingPw-343mmmm"
SKIP = "SkipPw-454nnnn"
XFAIL = "XfailPw-565oooo"
COLLECT = "CollectPw-676pppp"
ACCESS = "AccessTok-787qqqq"
PGPW = "PgPw-898rrrr"
INNER = "InnerQuote-909ssss"
ALL = [URL_PW, SQ_PW, DQ_PW, ESC_PW, JSON_PW, BEARER, COMPOSE, ADMIN, LICENSE, REGISTRY, ENVIRON,
       TEARDOWN, PASSING, SKIP, XFAIL, COLLECT, ACCESS, PGPW, INNER]

SCENARIOS = f'''
import json, os, subprocess, sys
import pytest

@pytest.fixture
def noisy():
    yield
    print("teardown postgres://u:{TEARDOWN}@db/x")
    print("teardown stderr password={TEARDOWN}", file=sys.stderr)

def test_fails_with_every_class(noisy):
    print("stdout postgres://u:{URL_PW}@db/x {COMPOSE}")
    print("stderr Authorization: Bearer {BEARER} {ADMIN}", file=sys.stderr)
    print("compound access_token='{ACCESS}' PGPASSWORD={PGPW}")
    # The value arrives at runtime (never a source literal), so only the
    # escaped-quote rule can mask it.
    print('inner password="ab' + chr(92) + '"' + os.environ["E2E_INNER_VALUE"] + '"', file=sys.stderr)
    dsn = "host=db password='{SQ_PW}' user=u"
    other = 'password="{DQ_PW}"'
    escaped = "password=\\"{ESC_PW}\\""
    body = json.dumps({{"password": "{JSON_PW}"}})
    assert False, f"{{dsn}} {{other}} {{escaped}} {{body}} {LICENSE} {REGISTRY} {ENVIRON}"

def test_psql_like_failure():
    subprocess.run([sys.executable, "-c", "raise SystemExit(1)", "postgres://u:{URL_PW}@db/x"], check=True)

def test_passes_but_prints():
    print("passing postgres://u:{PASSING}@db/x")

def test_skips():
    pytest.skip("skip postgres://u:{SKIP}@db/x")

@pytest.mark.xfail(reason="xfail password={XFAIL}")
def test_xfails():
    print("xfail out password={XFAIL}")
    assert False, "password={XFAIL}"
'''


@pytest.fixture
def run(tmp_path: Path) -> tuple[str, str]:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "compose.env").write_text(f"NANO_PLATFORM_INGEST_TOKEN='{COMPOSE}'\nPLAIN=not-a-secret\n")
    (run_dir / "admin.env").write_text(f"NANO_ADMIN_PASSWORD={ADMIN}\n")
    (run_dir / ".secrets.jsonl").write_text(json.dumps(REGISTRY) + "\n")
    lic = tmp_path / "c05.json"
    lic.write_text(LICENSE)
    tests = tmp_path / "suite"
    tests.mkdir()
    (tests / "test_scenarios.py").write_text(textwrap.dedent(SCENARIOS))
    (tests / "test_broken_import.py").write_text(f'raise RuntimeError("postgres://u:{COLLECT}@db/x")\n')
    junit = tmp_path / "junit.xml"
    env = {**os.environ, "E2E_RUN_DIR": str(run_dir), "NANO_E2E_C05_LICENSE_FILE": str(lic),
           "E2E_TEST_SECRET": ENVIRON, "E2E_INNER_VALUE": INNER}
    r = subprocess.run(
        [sys.executable, "-m", "pytest", "-p", "nano_e2e.redact", "-p", "no:cacheprovider", "-rA", "-l",
         "--continue-on-collection-errors", "-o", "junit_logging=all", f"--junitxml={junit}", str(tests)],
        capture_output=True, text=True, env=env, cwd=tmp_path, timeout=120, check=False,
    )
    assert "test_fails_with_every_class" in r.stdout, r.stdout + r.stderr
    return r.stdout + r.stderr, junit.read_text()


def test_every_secret_class_is_masked_in_terminal_and_junit(run: tuple[str, str]) -> None:
    out, junit = run
    for where, text in (("terminal", out), ("junit", junit)):
        leaked = [s for s in ALL if s in text]
        assert not leaked, f"{where} leaked {leaked}"
    assert "<redacted>" in out and "redacted" in junit
    # The reports keep their shape: summary lines and the skip / xfail stay.
    assert "1 skipped" in out and "1 xfailed" in out and "1 passed" in out, out[-1500:]
    assert "error" in out.lower()


@pytest.mark.parametrize(
    "text, secret",
    [
        ("access_token='at-1234567'", "at-1234567"),
        ("client_secret=cs-1234567", "cs-1234567"),
        ("ingest_token: it-1234567", "it-1234567"),
        ("csrf_token=\"cf-1234567\"", "cf-1234567"),
        ("PGPASSWORD=pg-1234567 psql", "pg-1234567"),
        ('"ch_admin_password": "ch-1234567"', "ch-1234567"),
        ("x-api-key: xk-1234567", "xk-1234567"),
        ('password="before\\"es-1234567"', "es-1234567"),
        ("password='it\\'s-1234567'", "s-1234567"),
        ('escaped = "password=\\"eq-1234567\\""', "eq-1234567"),
    ],
)
def test_compound_keys_and_escaped_quotes(text: str, secret: str) -> None:
    out = redact.redact_text(text)
    assert secret not in out and "<redacted>" in out, out


def test_ordinary_names_are_not_redacted() -> None:
    text = "max_tokens=5 secret_name=foo token_count=3 password_policy=strict"
    assert redact.redact_text(text) == text


def test_url_kv_and_header_forms() -> None:
    text = (
        "postgres://nanosiem:s3cretPW@127.0.0.1:5432/nanosiem host=db password=hunter22 "
        "password='q1q1q1q1' \"password\": \"j2j2j2j2\" Authorization: Splunk abcd1234efgh "
        "X-API-Key: k3k3k3k3 http://host:8080/a@b stays"
    )
    out = redact.redact_text(text)
    for secret in ("s3cretPW", "hunter22", "q1q1q1q1", "j2j2j2j2", "abcd1234efgh", "k3k3k3k3"):
        assert secret not in out, out
    assert "postgres://nanosiem:<redacted>@127.0.0.1:5432/nanosiem" in out
    assert "http://host:8080/a@b" in out


def test_stack_repr_hides_its_secrets() -> None:
    hidden = {"api_key", "admin_password", "ch_admin_password"}
    shown = {f.name for f in Stack.__dataclass_fields__.values() if f.repr}
    assert not hidden & shown
