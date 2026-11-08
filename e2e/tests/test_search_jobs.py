"""Search background jobs (NAN-4915): a query handed off to a durable job
completes, its result set pages correctly out of the results store, and an
async_mode search returns a job handle instead of rows."""

from __future__ import annotations

import time

from nano_e2e import ingest
from nano_e2e.client import Nano, expect, row_text, time_range
from nano_e2e.stack import Stack
from nano_e2e.waits import INGEST_VISIBLE, eventually

N = 25


def _seed(stack: Stack, nano: Nano, token: str, mark: str) -> None:
    docs = [{"message": f"{mark} seq={i:03d} job-handoff"} for i in range(N)]
    assert ingest.http(stack.vector_http_url, token, docs).status_code == 200
    eventually(
        lambda: nano.search(f'"{mark}"', limit=N + 5)["results"],
        timeout=INGEST_VISIBLE,
        desc=f"{N} seeded events searchable",
        ok=lambda rs: len(rs) >= N,
    )


def _job_request(query: str) -> dict:
    return {"query": query, "limit": 1000, "skip_histogram": True, "time_range": time_range(60)}


def test_background_job_completes_and_pages(
    stack: Stack, nano: Nano, token_source, mark: str, timeline
) -> None:
    src = token_source()
    _seed(stack, nano, src.token, mark)
    timeline.step("seeded", n=N)

    submitted = expect(nano.search_http.post("/api/search/jobs", json=_job_request(f'"{mark}"')), 202)
    job_id = submitted["job_id"]
    assert job_id.startswith("sjob_"), submitted
    timeline.step("job submitted", job_id=job_id, status=submitted["status"])

    status = eventually(
        lambda: expect(nano.search_http.get(f"/api/search/jobs/{job_id}", params={"limit": 5}), 200),
        timeout=180,
        interval=2,
        desc="job completion",
        ok=lambda s: s.get("status") in ("completed", "failed", "cancelled"),
    )
    assert status["status"] == "completed", status
    timeline.step("job completed", durable=status.get("durable"))

    seen: list[str] = []
    offset: int | None = 0
    pages = 0
    while offset is not None:
        page = expect(
            nano.search_http.get(f"/api/search/jobs/{job_id}/results", params={"offset": offset, "limit": 7}),
            200,
        )
        pages += 1
        seen += [row_text(r) for r in page["rows"]]
        offset = page.get("next_offset")
        assert pages < 20, "paging did not terminate"
    seqs = sorted({s.split("seq=")[1][:3] for s in seen if "seq=" in s})
    assert len(seen) == N, f"expected {N} rows across pages, got {len(seen)}"
    assert seqs == [f"{i:03d}" for i in range(N)], f"missing or duplicated rows across pages: {seqs}"
    timeline.step("paged", pages=pages, rows=len(seen))

    # The job shows up in the owner's list.
    listed = expect(nano.search_http.get("/api/search/jobs"), 200)
    assert any(j.get("job_id") == job_id for j in listed), listed


def test_async_mode_returns_job_handle(stack: Stack, nano: Nano, token_source, mark: str) -> None:
    src = token_source()
    _seed(stack, nano, src.token, mark)
    body = nano.search(f'"{mark}" | stats count', async_mode=True)
    assert "results" not in body and body.get("job_id", "").startswith("sjob_"), body
    final = eventually(
        lambda: expect(nano.search_http.get(f"/api/search/jobs/{body['job_id']}"), 200),
        timeout=180,
        desc="async job completion",
        ok=lambda s: s.get("status") in ("completed", "failed", "cancelled"),
    )
    assert final["status"] == "completed", final
    rows = (final.get("result") or {}).get("results") or []
    assert rows and str(N) in row_text(rows[0]), f"stats count over the seeded set should be {N}: {rows}"


def test_cancel_job(stack: Stack, nano: Nano) -> None:
    # A wide query over a long window; cancel immediately. Either the cancel
    # wins (status cancelled) or the job already finished — both are valid, a
    # failed/stuck job is not.
    req = {"query": "* | stats count by source_type", "limit": 100, "time_range": time_range(60 * 24 * 7)}
    job = expect(nano.search_http.post("/api/search/jobs", json=req), 202)
    cancelled = expect(nano.search_http.delete(f"/api/search/jobs/{job['job_id']}"), 200)
    assert isinstance(cancelled.get("cancelled"), bool), cancelled
    time.sleep(1)
    final = eventually(
        lambda: expect(nano.search_http.get(f"/api/search/jobs/{job['job_id']}"), 200),
        timeout=120,
        desc="job reaches a terminal state",
        ok=lambda s: s.get("status") in ("completed", "cancelled", "failed"),
    )
    expected = "cancelled" if cancelled["cancelled"] else "completed"
    assert final["status"] == expected, final
