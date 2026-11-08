"""The cloud-pull scenario lifecycle, shared by every provider.

On clickhouse/dev a pull source is a stored cloud credential
(`/api/credentials`) plus a source configuration
(`/api/source-configurations`, config_type aws_s3 | aws_sqs | gcp_pubsub |
azure_event_hubs) that Vector runs after an explicit deploy. The lifecycle:

  1. create credential + source config, deploy
  2. events published to the real cloud resource land (exactly the set sent)
  3. restart Vector mid-stream: no loss; duplicates (at-least-once) are
     bounded and reported
  4. pause (undeploy) -> nothing lands, backlog retained; resume (deploy) ->
     the backlog lands
  5. credential rotate (+ redeploy) -> ingest continues
  6. delete -> rendered config removed, nothing more is read

A provider adapter supplies the cloud side (`PullProvider`).
"""

from __future__ import annotations

import json
import re
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

from nano_e2e.client import Nano, expect, row_text
from nano_e2e.stack import Stack
from nano_e2e.waits import PULL_VISIBLE, eventually, stays

# Deploy/undeploy write the rendered config and return; Vector applies it
# asynchronously (--watch-config debounce + topology reload), and a running
# source keeps polling until then. Observed ~2-4s locally; this is the budget
# before asserting "nothing is read any more".
VECTOR_APPLY_SETTLE = 15.0

SEQ = re.compile(r"\bb=(\w+) seq=(\d+)\b")


class PullProvider(Protocol):
    config_type: str
    credential_provider: str
    # True when the cloud keeps undelivered messages we can count (SQS depth).
    can_count_backlog: bool
    # Worst-case delay before a message in flight at a Vector stop is delivered
    # again (SQS visibility timeout, Pub/Sub ack deadline, checkpoint replay).
    redelivery_secs: float

    def credential_payload(self, rotated: bool = False) -> dict[str, Any]: ...
    def connection_config(self) -> dict[str, Any]: ...
    def publish(self, bodies: list[str]) -> None: ...
    def backlog(self) -> int: ...


@dataclass
class PullRun:
    stack: Stack
    nano: Nano
    provider: PullProvider
    mark: str
    source_type: str
    step: Callable[..., None]
    credential_id: str = ""
    config_id: str = ""
    report: dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------ events
    def bodies(self, batch: str, n: int) -> list[str]:
        return [
            json.dumps({"message": f"{self.mark} b={batch} seq={i} pull e2e", "e2e_marker": self.mark})
            for i in range(n)
        ]

    def landed(self) -> Counter[tuple[str, int]]:
        """(batch, seq) -> number of rows stored for this run's marker."""
        rows = self.nano.rows(f'"{self.mark}"', limit=5000, minutes_back=120)
        seen: Counter[tuple[str, int]] = Counter()
        for r in rows:
            m = SEQ.search(row_text(r))
            if m:
                seen[(m.group(1), int(m.group(2)))] += 1
        return seen

    def wait_batch(self, batch: str, n: int, timeout: float = PULL_VISIBLE) -> Counter[tuple[str, int]]:
        want = {(batch, i) for i in range(n)}
        return eventually(
            self.landed,
            timeout=timeout,
            interval=5,
            desc=f"all {n} events of batch {batch} to land",
            ok=lambda seen: want <= set(seen),
        )

    def rendered_configs(self) -> list[str]:
        """Rendered Vector config files belonging to this run's source (matched
        by the source name / default source type they embed)."""
        d = self.stack.rendered_source_configs
        return [p.name for p in d.glob("*.toml") if _mentions(p, self.mark) or _mentions(p, self.source_type)]

    # ------------------------------------------------------------ api
    def create(self) -> None:
        cred = expect(
            self.nano.api.post(
                "/api/credentials",
                json={
                    "name": f"{self.mark}-cred",
                    "provider": self.provider.credential_provider,
                    "credentials": self.provider.credential_payload(),
                    "description": "nano-e2e (NAN-4920) throwaway",
                    "environment": "dev",
                },
            ),
            200,
            201,
        )
        self.credential_id = cred["id"]
        cfg = expect(
            self.nano.api.post(
                "/api/source-configurations",
                json={
                    "name": f"{self.mark}-src",
                    "description": "nano-e2e (NAN-4920) throwaway",
                    "config_type": self.provider.config_type,
                    "connection_config": self.provider.connection_config(),
                    "credential_id": self.credential_id,
                    "default_source_type": self.source_type,
                },
            ),
            200,
            201,
        )
        self.config_id = cfg["id"]
        self.step("credential + source config created", credential=self.credential_id, config=self.config_id)

    def deploy(self) -> None:
        res = expect(self.nano.api.post(f"/api/source-configurations/{self.config_id}/deploy"), 200)
        assert res.get("success") is True, f"deploy failed: {res}"
        self.step("deployed", message=res.get("message"))

    def undeploy(self) -> None:
        res = expect(self.nano.api.post(f"/api/source-configurations/{self.config_id}/undeploy"), 200)
        assert res.get("success") is True, f"undeploy failed: {res}"
        self.step("undeployed (paused)")

    def rotate(self) -> None:
        body = expect(
            self.nano.api.post(
                f"/api/credentials/{self.credential_id}/rotate",
                json={
                    "credentials": self.provider.credential_payload(rotated=True),
                    "note": "nano-e2e rotate",
                },
            ),
            200,
        )
        redeployed = body.get("redeployed")
        self.step("credential rotated", version=body.get("version"), redeployed=redeployed)
        if redeployed is None:
            # Older contract (no redeploy-on-rotate): redeploy explicitly.
            self.deploy()
        else:
            assert any(
                r.get("source_configuration_id") == self.config_id and r.get("success") for r in redeployed
            ), f"rotate did not redeploy the bound source config: {redeployed}"

    def delete(self) -> None:
        if self.config_id:
            expect(self.nano.api.delete(f"/api/source-configurations/{self.config_id}"), 200, 204)
            self.step("source config deleted")
            self.config_id = ""

    def cleanup(self) -> None:
        if self.config_id:
            self.nano.api.delete(f"/api/source-configurations/{self.config_id}")
        if self.credential_id:
            self.nano.api.delete(f"/api/credentials/{self.credential_id}")


def _mentions(path: Any, needle: str) -> bool:
    try:
        return needle in path.read_text()
    except OSError:
        return False


def run_lifecycle(run: PullRun, *, n: int = 40, quiet_secs: float = 45) -> dict[str, Any]:
    """The full lifecycle; returns a report (also written to the timeline)."""
    p = run.provider
    run.create()
    run.deploy()
    eventually(run.rendered_configs, timeout=30, desc="rendered Vector source config")

    # 1. Warm-up: the source is reading (Event Hubs starts at `latest`, and
    #    Vector needs a moment to load the new source). Probe until one lands.
    probes = {"k": 0}

    def probe() -> bool:
        probes["k"] += 1
        p.publish(run.bodies(f"warm{probes['k']}", 1))
        return any(b.startswith("warm") for b, _ in run.landed())

    eventually(probe, timeout=PULL_VISIBLE, interval=10, desc="first warm-up event to land")
    run.step("source is reading", probes=probes["k"])

    # 2. A batch lands, exactly.
    p.publish(run.bodies("a", n))
    seen = run.wait_batch("a", n)
    dups_a = sum(c - 1 for (b, _), c in seen.items() if b == "a")
    run.step("batch a landed", n=n, duplicates=dups_a)

    # 3. Vector restart mid-stream: no loss, bounded duplicates.
    p.publish(run.bodies("b", n))
    run.stack.svc("restart", "vector")
    run.step("vector restarted mid-stream", redelivery_budget_s=p.redelivery_secs)
    seen = run.wait_batch("b", n, timeout=PULL_VISIBLE + p.redelivery_secs)
    dups_b = sum(c - 1 for (b, _), c in seen.items() if b == "b")
    assert dups_b <= n, f"duplicates after restart exceed the batch size: {dups_b} > {n}"
    run.step("batch b landed after restart (no loss)", duplicates=dups_b)

    # 4. Pause / resume.
    run.undeploy()
    eventually(lambda: not run.rendered_configs(), timeout=30, desc="rendered config removed on pause")
    time.sleep(VECTOR_APPLY_SETTLE)
    p.publish(run.bodies("c", n // 2))
    stays(
        run.landed,
        duration=quiet_secs,
        interval=5,
        desc="no events land while paused",
        ok=lambda s: not any(b == "c" for b, _ in s),
    )
    backlog = p.backlog() if p.can_count_backlog else None
    if backlog is not None:
        assert backlog >= 1, "paused source: the cloud must still hold the undelivered messages"
    run.step("paused: nothing landed, backlog retained", backlog=backlog)
    run.deploy()
    run.wait_batch("c", n // 2)
    run.step("resumed: backlog landed")

    # 5. Credential rotation keeps ingest flowing.
    run.rotate()
    p.publish(run.bodies("d", n // 2))
    run.wait_batch("d", n // 2)
    run.step("ingest continues after rotate")

    # 6. Delete: config gone, nothing more read.
    run.delete()
    eventually(lambda: not run.rendered_configs(), timeout=30, desc="rendered config removed on delete")
    time.sleep(VECTOR_APPLY_SETTLE)
    p.publish(run.bodies("e", 5))
    stays(
        run.landed,
        duration=quiet_secs,
        interval=5,
        desc="no events land after delete",
        ok=lambda s: not any(b == "e" for b, _ in s),
    )
    run.step("deleted: nothing more read")

    final = run.landed()
    # Duplicates are judged at the END: a replay can arrive later than the
    # first copy (Event Hubs re-read batch b from the last committed Blob
    # checkpoint after the pause/resume redeploy, real Azure 11-03). At-least-
    # once is the contract; each batch may be duplicated at most once over.
    sizes = {"a": n, "b": n, "c": n // 2, "d": n // 2}
    per_batch = {b: sum(c - 1 for (bb, _), c in final.items() if bb == b) for b in sizes}
    for b, size in sizes.items():
        missing = {(b, i) for i in range(size)} - set(final)
        assert not missing, f"batch {b}: lost {sorted(missing)[:10]}"
        assert per_batch[b] <= size, f"batch {b}: {per_batch[b]} duplicates > batch size {size}"
    report = {
        "rows": sum(final.values()),
        "distinct": len(final),
        "duplicates": sum(c - 1 for c in final.values()),
        "duplicates_by_batch": per_batch,
        "duplicates_when_b_first_landed": dups_b,
        "warmup_probes": probes["k"],
    }
    run.step("report", **report)
    return report
