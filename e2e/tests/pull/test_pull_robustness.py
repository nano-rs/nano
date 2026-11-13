"""Pull-source failure isolation (no cloud credentials needed).

Product finding (2026-11-03, while running the real-GCP scenario): nano
accepts and "successfully" deploys a gcp_pubsub source whose credential the
Vector fork rejects. Vector then fails EVERY later topology reload
("Reload was not successful ... topology_build_failed"), because the rejected
file stays in the watched config dir. Unrelated changes, such as a parser
publish or another source's deploy, never go live until that file is removed.

This scenario pins the contract (NAN-4936): one bad pull source is quarantined
with Vector's reason, other config changes still go live, and a cold Vector
restart with the bad source configured still comes up and ingests.
"""

from __future__ import annotations

import json

import pytest

from nano_e2e import ingest
from nano_e2e.client import Nano, expect, row_text
from nano_e2e.stack import Stack
from nano_e2e.waits import INGEST_VISIBLE, eventually

# authorized_user-shaped JSON: well-formed and accepted by nano's credential
# store; the Vector fork cannot build a source with it (Google refuses the
# token request), so the source must be quarantined, not deployed.
BOGUS_ADC = json.dumps(
    {
        "type": "authorized_user",
        "client_id": "e2e.apps.googleusercontent.com",
        "client_secret": "e2e-not-a-secret",
        "refresh_token": "e2e-not-a-token",
    }
)
PARSER = '. = { "message": .message, "ext": { "e2e_parsed": "yes" } }'


def test_rejected_pull_credential_does_not_block_other_deploys(
    stack: Stack, nano: Nano, token_source, mark: str, timeline
) -> None:
    if "gcp_pubsub" not in nano.source_config_types():
        pytest.skip("gcp_pubsub source type not in this build")
    cred = expect(
        nano.api.post(
            "/api/credentials",
            json={
                "name": f"{mark}-bad",
                "provider": "gcp_pubsub",
                "credentials": {"credentials_json": BOGUS_ADC},
            },
        ),
        200,
        201,
    )
    cfg = expect(
        nano.api.post(
            "/api/source-configurations",
            json={
                "name": f"{mark}-bad-src",
                "config_type": "gcp_pubsub",
                "connection_config": {"project": "nano-e2e-none", "subscription": "nano-e2e-none"},
                "credential_id": cred["id"],
                "default_source_type": "e2e_bad_pull",
            },
        ),
        200,
        201,
    )
    try:
        deployed = expect(nano.api.post(f"/api/source-configurations/{cfg['id']}/deploy"), 200)
        timeline.step("bad source deploy", success=deployed.get("success"), message=deployed.get("message"))
        # NAN-4936: the deploy reports the real outcome, and the source is
        # quarantined with Vector's reason instead of entering the topology.
        assert deployed.get("success") is False, deployed
        shown = expect(nano.api.get(f"/api/source-configurations/{cfg['id']}"), 200)
        last = shown.get("last_deployment") or {}
        timeline.step("bad source status", deployed=shown.get("deployed"), last_deployment=last)
        assert shown.get("deployed") is False, shown
        assert last.get("status") == "quarantined", shown
        # Vector's own reason: the token request Google refuses (fork 0.61
        # nano.3+, which accepts ADC files) or the credential shape it rejects.
        assert "GCP" in (last.get("error_message") or ""), shown
        listed = expect(nano.api.get("/api/source-configurations"), 200)
        assert any(
            c["id"] == cfg["id"] and (c.get("last_deployment") or {}).get("status") == "quarantined"
            for c in listed
        ), "the list view must carry the quarantine too"

        # An unrelated change: publish a parser on a fresh source; it must go live.
        src = token_source()
        expect(nano.api.put(f"/api/log-sources/{src.source_id}", json={"parser_vrl": PARSER}), 200)
        published = expect(nano.api.post(f"/api/log-sources/{src.source_id}/publish", json={"acknowledge_unattested": True}), 200)
        assert published.get("success") is True, published
        n = {"i": 0}

        def send_and_read() -> list:
            n["i"] += 1
            m = f"{mark}-post-{n['i']}"
            assert ingest.http(stack.vector_http_url, src.token, [{"message": m}]).status_code == 200
            return eventually(lambda: nano.rows(f'"{m}"', limit=5), timeout=INGEST_VISIBLE, desc=m)

        eventually(
            send_and_read,
            timeout=150,
            interval=3,
            desc="parser published AFTER the bad pull source to go live",
            ok=lambda rs: any("e2e_parsed" in row_text(r) for r in rs),
        )
        timeline.step("publish after bad source went live")

        # NAN-4936: a cold Vector start with the bad source still configured
        # must come up and keep ingesting (the quarantined source is not in
        # the topology, so it cannot refuse the whole config).
        stack.svc("restart", "vector")
        timeline.step("vector restarted")
        # Strict: one event, accepted after the restart, must land within a
        # bounded window; it lands in ~5-15s. A longer wait would hide a stall:
        # the disk-buffer reader on 0.61.0-nano.3 sometimes never picked up the
        # final write after a restart (vectordotdev/vector#26946, fixed in
        # nano.4): the event sat in the clickhouse_logs buffer
        # (buffer_size_events=1, sink received 0) until the next write.
        after = f"{mark}-after-restart"
        eventually(
            lambda: ingest.http(stack.vector_http_url, src.token, [{"message": after}]).status_code,
            timeout=120,
            interval=2,
            desc="Vector to accept events after a cold restart with the bad source configured",
            ok=lambda status: status == 200,
        )
        eventually(
            lambda: nano.rows(f'"{after}"', limit=5),
            timeout=60,
            interval=3,
            desc="the one event accepted after the cold restart to land, parsed (a stall here is "
            "the disk-buffer visibility bug, not latency)",
            ok=lambda rs: any("e2e_parsed" in row_text(r) for r in rs),
        )
        timeline.step("ingest after cold restart")
    finally:
        nano.api.delete(f"/api/source-configurations/{cfg['id']}")
        nano.api.delete(f"/api/credentials/{cred['id']}")


def test_concurrent_deploys_each_report_their_own_outcome(nano: Nano, mark: str, timeline) -> None:
    """NAN-4936 (codex P1): two source deploys at once, one that Vector cannot
    build. Each must report its own outcome: the bad one is quarantined, never
    "Deployed successfully" on the strength of the other's reload, and the good
    one is confirmed live. Undeploying the good one is confirmed too."""
    import concurrent.futures

    if "gcp_pubsub" not in nano.source_config_types():
        pytest.skip("gcp_pubsub source type not in this build")
    cred = expect(
        nano.api.post(
            "/api/credentials",
            json={"name": f"{mark}-cbad", "provider": "gcp_pubsub", "credentials": {"credentials_json": BOGUS_ADC}},
        ),
        200,
        201,
    )
    bad = expect(
        nano.api.post(
            "/api/source-configurations",
            json={
                "name": f"{mark}-cbad-src",
                "config_type": "gcp_pubsub",
                "connection_config": {"project": "nano-e2e-none", "subscription": "nano-e2e-none"},
                "credential_id": cred["id"],
                "default_source_type": "e2e_cbad",
            },
        ),
        200,
        201,
    )
    good = expect(
        nano.api.post(
            "/api/source-configurations",
            json={
                "name": f"{mark}-cgood-src",
                "config_type": "aws_sqs",
                "connection_config": {
                    "queue_url": "https://sqs.us-east-1.amazonaws.com/000000000000/nano-e2e-none",
                    "region": "us-east-1",
                },
                "default_source_type": "e2e_cgood",
            },
        ),
        200,
        201,
    )
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            futures = {
                name: pool.submit(lambda i=cfg["id"]: expect(nano.api.post(f"/api/source-configurations/{i}/deploy"), 200))
                for name, cfg in (("bad", bad), ("good", good))
            }
            results = {name: f.result() for name, f in futures.items()}
        timeline.step("concurrent deploys", bad=results["bad"].get("message"), good=results["good"].get("message"))

        assert results["bad"].get("success") is False, results["bad"]
        bad_status = expect(nano.api.get(f"/api/source-configurations/{bad['id']}"), 200)
        assert (bad_status.get("last_deployment") or {}).get("status") == "quarantined", bad_status
        assert bad_status.get("deployed") is False, bad_status

        assert results["good"].get("success") is True, results["good"]
        good_status = expect(nano.api.get(f"/api/source-configurations/{good['id']}"), 200)
        assert good_status.get("deployed") is True, good_status
        assert (good_status.get("last_deployment") or {}).get("status") == "success", good_status

        undeployed = expect(nano.api.post(f"/api/source-configurations/{good['id']}/undeploy"), 200)
        timeline.step("undeploy good", result=undeployed)
        assert undeployed.get("success") is True, undeployed
    finally:
        nano.api.delete(f"/api/source-configurations/{good['id']}")
        nano.api.delete(f"/api/source-configurations/{bad['id']}")
        nano.api.delete(f"/api/credentials/{cred['id']}")


ROUNDS = 8
EVENTS_PER_ROUND = 5


def test_events_accepted_during_a_vector_reload_all_land(
    stack: Stack, nano: Nano, token_source, mark: str, timeline
) -> None:
    """NAN-4936 / NAN-4937 finding: events accepted (200) while Vector reloads
    its topology must all become searchable, promptly. The browser suite saw a
    pull feed that started during a reload deliver 5 events and lose 1-2 of
    them for 5.5 minutes on 0.61.0-nano.3, and HEC events accepted during a
    reload sat ~2.5 minutes until a later reload. Connector feeds post to the
    same http_ingest listener as this test.

    Each round makes Vector reload, alternating an ingest-token issue (nano-api
    rewrites the tokens file; Vector reloads ~1 s later) and a parser publish
    (the reload rewires parser and combiner transforms), while a sender posts a
    short burst across the
    reload window, over HTTP and HEC, and then goes SILENT, like a feed run
    that has delivered its page. Nothing else touches Vector until that burst
    has landed: a later write or reload would flush a stalled buffer and hide
    the bug. Each burst must land within a bounded window; a stall here is the
    disk-buffer visibility bug or a reload-window drop, never latency."""
    import threading
    import time

    src = token_source()
    expect(nano.api.put(f"/api/log-sources/{src.source_id}", json={"parser_vrl": PARSER}), 200)
    assert expect(nano.api.post(f"/api/log-sources/{src.source_id}/publish", json={"acknowledge_unattested": True}), 200).get("success") is True

    for round_no in range(ROUNDS):
        sent: list[str] = []

        def sender() -> None:
            for i in range(EVENTS_PER_ROUND):
                m = f"{mark}-reload-{round_no}-{i}"
                if i % 2:
                    r = ingest.hec(stack.hec_url, src.token, {"message": m})
                else:
                    r = ingest.http(stack.vector_http_url, src.token, [{"message": m}])
                if r.status_code == 200:
                    sent.append(m)
                time.sleep(0.4)

        t = threading.Thread(target=sender)
        t.start()
        time.sleep(0.3)
        cred = None
        if round_no % 2 == 0:
            # Rewrites the hashed tokens file on the dynamic volume: Vector reloads.
            cred, _ = nano.issue_token(src.source_id, name=f"{mark}-reload-{round_no}")
        else:
            # A parser publish: the reload rewires the parser and combiner
            # transforms (the "feed starts right after its lane is published" case).
            vrl = PARSER + f"\n# round {round_no}"
            expect(nano.api.put(f"/api/log-sources/{src.source_id}", json={"parser_vrl": vrl}), 200)
            expect(nano.api.post(f"/api/log-sources/{src.source_id}/publish", json={"acknowledge_unattested": True}), 200)
        t.join()
        assert len(sent) >= EVENTS_PER_ROUND - 1, f"round {round_no}: too few accepted: {sent}"

        def missing() -> list[str]:
            rows = nano.rows(f'"{mark}-reload-{round_no}-"', limit=100)
            seen = {m for m in sent for r in rows if m in row_text(r)}
            return sorted(set(sent) - seen)

        left = eventually(
            missing,
            timeout=60,
            interval=3,
            desc=f"round {round_no}: every event accepted during the reload to land, with nothing "
            "else writing to Vector (a stall is the disk-buffer visibility bug)",
            ok=lambda m: not m,
        )
        timeline.step("reload round landed", round=round_no, accepted=len(sent), missing=left)
        if cred:
            nano.revoke_token(cred)
