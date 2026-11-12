"""Shared fixtures for the nano-e2e scenarios.

Collection needs no stack; fixtures fail fast (with how to fix it) when the
stack env is missing, so a misconfigured run never reads as "all skipped".
"""

from __future__ import annotations

import json
import os
import re
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from nano_e2e import artifact_guard

from nano_e2e import ingest
from nano_e2e.client import Journal, Nano
from nano_e2e.firstrun import ensure_admin
from nano_e2e.mockvendor import MockVendor, MockVendorServer
from nano_e2e.runid import marker as make_marker
from nano_e2e.runid import route_key as make_route_key
from nano_e2e.stack import Stack, StackNotConfigured
from nano_e2e.waits import INGEST_VISIBLE, eventually


def pytest_sessionstart(session: pytest.Session) -> None:
    """Record every secret this session holds (the stack's and the cloud test
    credentials `with_creds` loaded) in the run's 0600 registry, so the
    artifact guard can scrub them and fail the run if one survives."""
    artifact_guard.remember(*artifact_guard.env_secrets())


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    open_edition = os.environ.get("E2E_EDITION", "enterprise") == "open"
    skip = pytest.mark.skip(reason="enterprise-only scenario; stack runs EDITION=open")
    for item in items:
        if any(part in Path(str(item.path)).as_posix() for part in ("/ui/", "/personas/")):
            item.add_marker(pytest.mark.ui)
        if open_edition and item.get_closest_marker("enterprise"):
            item.add_marker(skip)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo) -> Iterator[None]:
    """Expose each phase's report as item.rep_<when> (UI fixtures save the
    trace/screenshot only when the scenario failed)."""
    outcome = yield
    rep = outcome.get_result()  # type: ignore[attr-defined]
    setattr(item, f"rep_{rep.when}", rep)


@pytest.fixture(scope="session")
def stack() -> Stack:
    try:
        # `up --defer-admin` (what `run ui` uses): first-run setup happens here,
        # in the browser when the UI build is present (nano_e2e.firstrun).
        ensure_admin()
        return Stack.from_env()
    except StackNotConfigured as exc:
        pytest.fail(str(exc), pytrace=False)


def _safe(nodeid: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", nodeid)[-150:]


@pytest.fixture
def artifact_dir(stack: Stack, request: pytest.FixtureRequest) -> Path:
    d = stack.artifact_dir / "scenarios" / _safe(request.node.nodeid)
    d.mkdir(parents=True, exist_ok=True)
    return d


@pytest.fixture
def nano(stack: Stack, artifact_dir: Path) -> Iterator[Nano]:
    client = Nano(
        stack.api_url, stack.search_url, {"X-API-Key": stack.api_key}, Journal(artifact_dir / "api.jsonl")
    )
    yield client
    client.close()


class Timeline:
    """Per-scenario step log (timeline.jsonl): what ran, when, what it saw."""

    def __init__(self, path: Path):
        self.path = path
        self.t0 = time.monotonic()

    def step(self, name: str, **data: Any) -> None:
        rec = {"t": round(time.monotonic() - self.t0, 2), "step": name, **data}
        with self.path.open("a") as f:
            f.write(json.dumps(rec, default=str) + "\n")
        print(f"[{rec['t']:>7}s] {name} {data if data else ''}")


@pytest.fixture
def timeline(artifact_dir: Path) -> Timeline:
    return Timeline(artifact_dir / "timeline.jsonl")


@pytest.fixture
def mark(request: pytest.FixtureRequest) -> str:
    return make_marker(request.node.nodeid)


@dataclass
class TokenSource:
    """A draft log source with a bound per-source ingest token."""

    source_id: str
    route_key: str
    credential_id: str
    token: str


@pytest.fixture
def token_source(
    stack: Stack, nano: Nano, request: pytest.FixtureRequest
) -> Iterator[Callable[..., TokenSource]]:
    """Factory: create a draft source + token and wait until Vector accepts the
    token (Vector re-reads the hashed tokens file every ~2s). Everything it
    creates is revoked/deleted at teardown."""
    created: list[TokenSource] = []

    def make(
        label: str = "", parser_vrl: str = "", settle: bool = False, warm: bool = True
    ) -> TokenSource:
        rk = make_route_key(request.node.nodeid, label)
        src = nano.create_draft_source(name=rk, route_key=rk, parser_vrl=parser_vrl)
        cred, tok = nano.issue_token(src["id"], name=f"{rk}-tok")
        ts = TokenSource(source_id=src["id"], route_key=rk, credential_id=cred, token=tok)
        created.append(ts)
        if warm:
            # A health-check event with the token; accepted == token file reloaded.
            # Several CONSECUTIVE acceptances: with Vector scaled out (Helm chart,
            # HPA) every pod reloads the tokens file on its own ~2 s cycle, and each
            # request (a fresh HEC channel) can land on a different pod (NAN-4973).
            streak = {"n": 0}

            def warm_probe() -> int:
                code = ingest.hec(
                    stack.hec_url, tok, {"message": f"token-warmup {rk}"}
                ).status_code
                streak["n"] = streak["n"] + 1 if code == 200 else 0
                return streak["n"]

            eventually(
                warm_probe,
                timeout=INGEST_VISIBLE,
                interval=1,
                desc=f"Vector (every replica) to accept the new ingest token for {rk}",
                ok=lambda n: n >= 6,
            )
        if settle:
            # Issuing (and revoking) a token rewrites the tokens file, which
            # triggers a Vector topology reload ~1s later. HEC events accepted
            # (200) during that reload can sit stranded until a LATER reload
            # (observed: 2.5 min, NAN-4937 finding). `settle` waits until the
            # warm-up event is searchable: the pipeline is past this token's
            # reload, so a scenario that measures something else (UI == API)
            # does not race it. A fresh probe per poll: a probe that was itself
            # stranded must not hold the wait.
            n = {"i": 0}

            def probe() -> list:
                n["i"] += 1
                ingest.hec(stack.hec_url, tok, {"message": f"token-settle {rk} {n['i']}"})
                return nano.rows(f'source_type={rk} "token-settle"', limit=5, minutes_back=15)

            eventually(
                probe,
                timeout=INGEST_VISIBLE,
                interval=3,
                desc=f"a settle probe for {rk} searchable (pipeline past the token reload)",
            )
        return ts

    yield make
    for ts in created:
        try:
            nano.revoke_token(ts.credential_id)
        except Exception:  # noqa: BLE001,S110 - best-effort teardown (may already be revoked)
            pass
        nano.delete_source(ts.source_id)


def pytest_report_header(config: pytest.Config) -> str:
    from nano_e2e.runid import SESSION, run_id

    return f"nano-e2e run {run_id()} session {SESSION} (pin with E2E_SESSION={SESSION})"


# ---------------------------------------------------------------- suite coverage
# An explicitly selected suite that executes zero scenarios is a FAILURE: lost
# credentials or a build that silently stopped exposing a feature must not
# read as green. scripts/e2e.sh exports the selected suite paths; local
# exploration opts out with --allow-skips (E2E_ALLOW_SKIPS=1).
_executed: dict[str, int] = {}


def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    # Executed = ran and produced a verdict. A skip (in a fixture or the body)
    # is not coverage; a setup error is (it is a red result, not a skip).
    ran = report.when == "call" and (not report.skipped or hasattr(report, "wasxfail"))  # xfail ran
    if ran or (report.when == "setup" and report.failed):
        _executed[report.nodeid] = 1


def suite_coverage_failures(suite_paths: list[str], executed_nodeids: list[str], rootdir: str) -> list[str]:
    """Suites (paths) under which no test executed. Pure, for selftests."""
    failures = []
    for path in suite_paths:
        rel = os.path.relpath(path, rootdir)
        rel = "" if rel == "." else rel.rstrip("/")
        if not any(
            n == rel or n.startswith(rel + "/") or n.startswith(rel + "::") or not rel
            for n in executed_nodeids
        ):
            failures.append(rel or ".")
    return failures


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    paths = [p for p in os.environ.get("E2E_SUITE_PATHS", "").split(":") if p]
    if not paths or os.environ.get("E2E_ALLOW_SKIPS") == "1":
        return
    if session.config.getoption("collectonly", default=False):
        return
    empty = suite_coverage_failures(paths, list(_executed), str(session.config.rootpath))
    if empty:
        tr = session.config.pluginmanager.get_plugin("terminalreporter")
        msg = (
            f"E2E: selected suite(s) executed ZERO scenarios (all skipped/deselected): {', '.join(empty)}. "
            "Fix the credentials/build, or pass --allow-skips for local exploration."
        )
        if tr:
            tr.write_line(msg, red=True, bold=True)
        session.exitstatus = pytest.ExitCode.TESTS_FAILED


# ---------------------------------------------------------------- mock-vendor
@pytest.fixture(scope="session")
def mock_vendor(stack: Stack) -> Iterator[MockVendor]:
    """The vendor mock the stack's connector runner was started against
    (`up --profile mock-vendor`). SKIPs, with the reason, on a stack without
    the profile: connector feeds need the runner, which only that profile runs."""
    if "mock-vendor" not in os.environ.get("E2E_PROFILES", "").split():
        pytest.skip(
            "connector feeds need the mock-vendor profile (runner + vendor mock): "
            "`scripts/e2e.sh up --profile mock-vendor` (native app mode; "
            "`run pull|ui` adds it to a stack it owns)"
        )
    port = int(os.environ.get("E2E_MOCK_VENDOR_PORT") or 0)
    if not port:
        pytest.fail("E2E_MOCK_VENDOR_PORT missing from stack.env (stack predates the mock-vendor profile)")
    server = MockVendorServer(port=port).start()
    yield server.mock
    server.stop()


# ---------------------------------------------------------------- OCSF lane
# The product defaults to OCSF (install.sh), so search scenarios lead with real
# OCSF field names. One token-bound source per session with a PUBLISHED parser
# that turns {"message", "user", "ip", "host"} into an OCSF Authentication
# event (class 3002): actor.user.name, src_endpoint.ip, device.hostname,
# metadata.log_source. Scenarios filter by their own marker.
OCSF_AUTH_PARSER = """
.class_uid = 3002
.category_uid = 3
.activity_id = 1
.type_uid = 300201
.severity_id = 1
.actor.user.name = del(.user)
.src_endpoint.ip = del(.ip)
.device.hostname = del(.host)
.metadata.log_source = "{lane}"
.metadata.product.name = "nano-e2e"
"""


@dataclass
class OcsfLane:
    lane: str
    token: str
    source_id: str

    def send(self, stack: Stack, mark: str, user: str, ip: str, host: str, note: str = "") -> None:
        r = ingest.hec(
            stack.hec_url,
            self.token,
            {"message": f"{mark} {note} ocsf e2e".strip(), "user": user, "ip": ip, "host": host},
        )
        assert r.status_code == 200, r.text


@pytest.fixture(scope="session")
def ocsf_lane(stack: Stack) -> Iterator[OcsfLane]:
    if not os.environ.get("NANO_SCHEMA_PROFILE", "udm").startswith("ocsf"):
        pytest.skip("OCSF field scenarios need an ocsf stack (`scripts/e2e.sh run ui` brings one up)")
    nano = Nano(stack.api_url, stack.search_url, {"X-API-Key": stack.api_key}, Journal(None))
    rk = make_route_key("ocsf-lane", "session")
    src = nano.create_draft_source(name=rk, route_key=rk, parser_vrl=OCSF_AUTH_PARSER.format(lane=rk))
    cred, tok = nano.issue_token(src["id"], name=f"{rk}-tok")
    from nano_e2e.client import expect as api_expect

    # NAN-5079: a custom parser's first publish needs a passing OCSF sample or
    # an audited unattested acknowledgement. This minimal auth parser is not a
    # complete OCSF event (no metadata.version), so acknowledge.
    res = api_expect(
        nano.api.post(f"/api/log-sources/{src['id']}/publish", json={"acknowledge_unattested": True}), 200
    )
    assert res.get("success") is True, f"publishing the OCSF lane parser failed: {res}"
    n = {"i": 0}

    def probe() -> list:
        # Fresh probe per poll: one sent during the publish reload may strand.
        n["i"] += 1
        ingest.hec(stack.hec_url, tok, {"message": f"ocsf-settle {rk} {n['i']}", "user": f"settle-{rk}"})
        return nano.rows(f'actor.user.name="settle-{rk}"', limit=5, minutes_back=15)

    eventually(probe, timeout=180, interval=3, desc=f"OCSF lane {rk} parsing (actor.user.name searchable)")
    yield OcsfLane(lane=rk, token=tok, source_id=src["id"])
    try:
        nano.revoke_token(cred)
    except Exception:  # noqa: BLE001,S110 - best-effort
        pass
    nano.delete_source(src["id"])
    nano.close()
