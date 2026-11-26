"""`Nano.run_deploy_job` starts a log-source deploy job with `?wait=false` and
polls it, so a large parser's publish (NAN-5889: about 80 s for palo_alto)
never holds one request past the 60 s client timeout."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from nano_e2e.client import ApiError, Http, Journal, Nano

API = "http://127.0.0.1:5555"


def _nano(handler: Any) -> Nano:
    nano = Nano.__new__(Nano)
    nano.api = Http(API, {}, Journal(None))
    nano.api._client = httpx.Client(base_url=API, transport=httpx.MockTransport(handler))
    return nano


def _job(state: str, phase: str, **extra: Any) -> dict[str, Any]:
    return {"id": "djob_1", "state": state, "phase": phase, "status_path": "/api/log-sources/deploy-jobs/djob_1", **extra}


def test_publish_starts_without_waiting_and_returns_the_job_result() -> None:
    seen: list[str] = []
    polls = iter([_job("running", "validating"), _job("running", "reloading"),
                  _job("succeeded", "done", result={"success": True, "action": "publish"})])

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(f"{req.method} {req.url.path}?{req.url.query.decode()}")
        if req.method == "POST":
            return httpx.Response(202, json=_job("queued", "queued"))
        return httpx.Response(200, json=next(polls))

    result = _nano(handler).publish_source("lsrc_1", {"acknowledge_unattested": True}, poll=0)
    assert result == {"success": True, "action": "publish"}
    assert seen[0] == "POST /api/log-sources/lsrc_1/publish?wait=false"
    assert seen[1:] == ["GET /api/log-sources/deploy-jobs/djob_1?"] * 3


def test_a_failed_job_raises_with_its_status_and_message() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        if req.method == "POST":
            return httpx.Response(202, json=_job("running", "validating"))
        return httpx.Response(200, json=_job("failed", "done", error_status=422, message="sample 1 failed"))

    with pytest.raises(ApiError, match=r"error_status 422.*sample 1 failed"):
        _nano(handler).deploy_source("lsrc_1", poll=0)


def test_a_server_without_deploy_jobs_returns_the_blocking_result() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"success": True})

    assert _nano(handler).publish_source("lsrc_1", poll=0) == {"success": True}


def test_a_job_that_never_finishes_times_out_with_its_phase() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        if req.method == "POST":
            return httpx.Response(202, json=_job("running", "reloading"))
        return httpx.Response(200, json=_job("running", "reloading"))

    with pytest.raises(ApiError, match=r"still running .*phase reloading"):
        _nano(handler).publish_source("lsrc_1", timeout=-1, poll=0)
