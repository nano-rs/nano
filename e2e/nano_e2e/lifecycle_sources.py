"""Log-source lifecycle setup shared by the open and enterprise lifecycle
scenarios (NAN-5765): three published, token-bound sources each send real
events (HEC, an OCSF auth parser); the senders stop; one source is deleted
alone and two in one bulk request.

`deleted_sources(...)` does all of it and yields the `Deleted` record; a
`before_delete(deleted, nano)` hook adds a module's own positive controls
(e.g. SIEM Health, enterprise-only) before anything is deleted.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

from nano_e2e import ingest, lifecycle
from nano_e2e.client import Journal, Nano
from nano_e2e.client import expect as api_expect
from nano_e2e.runid import route_key as make_route_key
from nano_e2e.soar_ui import Cleanup
from nano_e2e.stack import Stack
from nano_e2e.waits import INGEST_VISIBLE, eventually

PARSER = """
.class_uid = 3002
.category_uid = 3
.activity_id = 1
.type_uid = 300201
.severity_id = 1
.actor.user.name = del(.user)
.metadata.log_source = "{lane}"
.metadata.product.name = "nano-e2e"
"""


@dataclass
class Src:
    id: str
    name: str
    route_key: str
    credential_id: str
    token: str
    user: str


@dataclass
class Deleted:
    single: Src
    bulk: list[Src]
    siem_before: dict[str, Any] = field(default_factory=dict)

    @property
    def all(self) -> list[Src]:
        return [self.single, *self.bulk]

    @property
    def needles(self) -> set[str]:
        out: set[str] = set()
        for s in self.all:
            out |= lifecycle.id_spellings(s.id, "lsrc") | {s.name, s.route_key}
        return out


def _published(nano: Nano, label: str, module: str = "tests/ui/test_lifecycle_log_source.py",
               stale_threshold_minutes: int | None = None) -> Src:
    rk = make_route_key(module, label)
    src = nano.create_draft_source(name=rk, route_key=rk, parser_vrl=PARSER.format(lane=rk))
    if stale_threshold_minutes is not None:
        api_expect(nano.api.put(f"/api/log-sources/{src['id']}",
                                json={"stale_threshold_minutes": stale_threshold_minutes}), 200)
    res = api_expect(
        nano.api.post(f"/api/log-sources/{src['id']}/publish", json={"acknowledge_unattested": True}), 200
    )
    assert res.get("success") is True, f"publishing {rk} failed: {res}"
    cred, tok = nano.issue_token(src["id"], name=f"{rk}-tok")
    return Src(src["id"], src.get("name") or rk, rk, cred, tok, f"nan5765-{rk[-10:]}")


def _send_until_searchable(stack: Stack, nano: Nano, s: Src) -> None:
    n = {"i": 0}

    def probe() -> int:
        n["i"] += 1
        r = ingest.hec(stack.hec_url, s.token, {"message": f"nan5765 lifecycle {n['i']}", "user": s.user})
        if r.status_code != 200:  # Vector reloads the new token's hash every ~2 s
            return 0
        return len(nano.rows(f'actor.user.name="{s.user}"', limit=5, minutes_back=30))

    eventually(probe, timeout=INGEST_VISIBLE * 2, interval=3, desc=f"{s.name} events searchable", ok=bool)


def _series(nano: Nano) -> Any:
    return api_expect(nano.api.get("/api/log-sources/health-series", params={"hours": 24}), 200)


def _latest(nano: Nano) -> dict[str, Any]:
    return api_expect(nano.api.get("/api/siem-health/reports/latest"), 200)


def _ingestion(report: dict[str, Any]) -> dict[str, Any]:
    return (report.get("metrics") or {}).get("ingestion") or {}


def _live_sources(nano: Nano) -> list[dict[str, Any]]:
    body = api_expect(nano.api.get("/api/log-sources"), 200)
    return body if isinstance(body, list) else body.get("sources", body.get("log_sources", body.get("items", [])))


@contextmanager
def deleted_sources(
    stack: Stack,
    module: str,
    before_delete: Callable[[Deleted, Nano], None] | None = None,
) -> Iterator[Deleted]:
    """Publish, feed and delete the lifecycle sources (see the module doc).
    `module` names the calling test module (route keys, the setup journal)."""
    nano = Nano(stack.api_url, stack.search_url, {"X-API-Key": stack.api_key},
                Journal(stack.artifact_dir / "scenarios" / f"lifecycle-log-source-setup-{module.rsplit('/', 1)[-1]}.jsonl"))
    made: list[Src] = []
    try:
        for label in ("single", "bulk-a", "bulk-b"):
            made.append(_published(nano, label, module))
        for s in made:
            _send_until_searchable(stack, nano, s)
        d = Deleted(made[0], made[1:])

        # Every summary lists them while they exist (else "absent" proves nothing).
        lifecycle.present(lambda: _series(nano), {s.id for s in made}, what="log source health-series")
        if before_delete is not None:
            before_delete(d, nano)

        # Stop the senders, then delete one alone and two in one bulk request.
        for s in made:
            nano.revoke_token(s.credential_id)
        assert nano.api.delete(f"/api/log-sources/{d.single.id}").status_code == 200
        bulk = api_expect(nano.api.post("/api/log-sources/bulk-delete",
                                        json={"ids": [s.id for s in d.bulk]}, timeout=320), 200)
        assert bulk["deleted"] == 2 and bulk["failed"] == 0, bulk
        yield d
    finally:
        cleanup = Cleanup()
        cleanup.add("close the setup client", nano.close)
        for src in made:
            cleanup.add(f"log source {src.id}",
                        lambda src=src: api_expect(nano.api.delete(f"/api/log-sources/{src.id}"), 200, 204, 404))
        cleanup.close()
