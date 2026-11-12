"""Two-phase activation of a routed log source (NAN-5132, PR 5) black-box.

Adding a router-fed source goes out as two Vector generations: A stages the
source's chain PARKED (its entry reads the never-matching fan-in slot filter,
the router has no route for it, so routing is unchanged), and only after A is
acknowledged does B add the route. An undeploy mirrors it: A unroutes and parks
the chain, B drops it.

Needs stable fan-in slots on the stack (`VECTOR_FANIN_SLOTS=on` in the app env;
run with `NANO_E2E_TWO_PHASE=1`). The scenario watches the rendered tree the
stack's Vector reads while the deploy job runs, so it sees phase A itself.
"""

from __future__ import annotations

import os
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from nano_e2e import ingest
from nano_e2e.client import Nano, expect, row_text
from nano_e2e.runid import route_key as make_route_key
from nano_e2e.stack import Stack
from nano_e2e.waits import INGEST_VISIBLE, eventually

pytestmark = pytest.mark.skipif(
    os.environ.get("NANO_E2E_TWO_PHASE") != "1",
    reason="needs a stack with VECTOR_FANIN_SLOTS=on (NANO_E2E_TWO_PHASE=1)",
)

PARKED = "nano-slot-parked"


class TreeWatch:
    """Samples `_router.toml` and the source's parser file every 50 ms."""

    def __init__(self, parsers: Path, name: str) -> None:
        self.router = parsers / "_router.toml"
        self.parser = parsers / f"{name}.toml"
        self.route_line = f"{name} = "
        self.states: list[tuple[bool, bool, bool]] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _read(self, path: Path) -> str | None:
        try:
            return path.read_text()
        except OSError:
            return None

    def _run(self) -> None:
        while not self._stop.is_set():
            router = self._read(self.router) or ""
            parser = self._read(self.parser)
            routed = any(line.startswith(self.route_line) for line in router.splitlines())
            state = (parser is not None, parser is not None and PARKED in parser, routed)
            if not self.states or self.states[-1] != state:
                self.states.append(state)
            time.sleep(0.05)

    def __enter__(self) -> TreeWatch:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        self._thread.join(timeout=5)


def _run_job(nano: Nano, path: str) -> tuple[dict[str, Any], list[str]]:
    job = expect(nano.api.post(f"{path}?wait=false"), 202)
    phases = [job["phase"]]
    deadline = time.time() + 400
    while job["state"] in ("queued", "running"):
        assert time.time() < deadline, f"job did not finish: {job}"
        time.sleep(0.25)
        job = expect(nano.api.get(job["status_path"]), 200)
        if job["phase"] != phases[-1]:
            phases.append(job["phase"])
    return job, phases


def test_deploy_stages_parked_then_activates_and_undeploy_mirrors_it(
    stack: Stack, nano: Nano, mark: str, request, timeline
) -> None:
    name = make_route_key(request.node.nodeid, "twophase")
    src = expect(
        nano.api.post(
            "/api/log-sources",
            json={
                "name": name,
                "description": "nano-e2e two-phase activation (NAN-5132)",
                "source_type": "routed",
                "parser_vrl": '.message = "twophase-parsed " + to_string!(.message)',
                "match_values": [name],
            },
        ),
        200,
        201,
    )
    cred, token = nano.issue_token(src["id"], f"{name}-tok")
    parsers = stack.vector_dynamic_dir / "sources" / "parsers"
    try:
        with TreeWatch(parsers, name) as watch:
            job, phases = _run_job(nano, f"/api/log-sources/{src['id']}/deploy")
        timeline.step("deploy job", phases=phases, states=watch.states, message=job.get("message"))
        assert job["state"] == "succeeded", job
        assert "activating" in phases, f"no second (activation) phase: {phases}"
        assert "staged on every ingest host, then activated" in (job.get("message") or ""), job
        # Phase A was on disk: the chain present and parked, the router unchanged.
        assert (True, True, False) in watch.states, f"phase A never seen: {watch.states}"
        assert watch.states[-1] == (True, False, True), f"not active at the end: {watch.states}"
        assert watch.states.index((True, True, False)) < watch.states.index((True, False, True))

        n = {"i": 0}

        def send_and_read() -> list:
            n["i"] += 1
            m = f"{mark}-twophase-{n['i']}"
            assert ingest.http(stack.vector_http_url, token, [{"message": m}]).status_code == 200
            return eventually(lambda: nano.rows(f'"{m}"', limit=5), timeout=INGEST_VISIBLE, desc=m)

        eventually(
            send_and_read,
            timeout=180,
            interval=3,
            desc="events parsed by the activated source",
            ok=lambda rs: any("twophase-parsed" in row_text(r) for r in rs),
        )
        timeline.step("activated source parses events")

        with TreeWatch(parsers, name) as watch:
            job, phases = _run_job(nano, f"/api/log-sources/{src['id']}/undeploy")
        timeline.step("undeploy job", phases=phases, states=watch.states, message=job.get("message"))
        assert job["state"] == "succeeded", job
        assert "activating" in phases, f"undeploy ran in one phase: {phases}"
        # Phase A of the removal: unrouted, chain still installed and parked.
        assert (True, True, False) in watch.states, f"removal phase A never seen: {watch.states}"
        assert watch.states[-1] == (False, False, False), f"chain not dropped: {watch.states}"
    finally:
        try:
            nano.revoke_token(cred)
        except Exception:  # noqa: BLE001,S110 - best-effort teardown
            pass
        nano.delete_source(src["id"])
