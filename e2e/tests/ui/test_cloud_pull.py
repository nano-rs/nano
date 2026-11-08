"""Cloud pull set up through the web UI against REAL clouds (AWS SQS, Azure
Event Hubs, GCP Pub/Sub), then verified end to end.

Per cloud: the credential, the source config, its connection, routing and the
deploy are all done in the browser (nano_e2e.ui_pull). The scenario then
checks that what was saved is what was typed (API), publishes to the real
cloud resource, and asserts the events land exactly (API search) and that the
search UI shows the same rows.

Only per-run cloud resources are created (`nano-e2e-<runid>-...`, ownership
tags) and they are always deleted by the fixtures; base resources (Event Hubs
namespace, storage account, project) are never touched.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import pytest

from nano_e2e import feeds, ui_pull
from nano_e2e import ui as uilib
from nano_e2e.client import Nano, row_text
from nano_e2e.client import expect as api_expect
from nano_e2e.providers import AwsSqsPayload, AzureEventHubs, GcpPubSub, require_config_type
from nano_e2e.runid import route_key
from nano_e2e.ui import field, press, rx
from nano_e2e.stack import Stack
from nano_e2e.waits import PULL_VISIBLE, eventually

# Vector's aws_sqs visibility_timeout_secs default: a message the previous
# topology received during a credential reload is redelivered after it.
SQS_REDELIVERY = 300

pytestmark = [pytest.mark.cloud, pytest.mark.slow]

SEQ = re.compile(r"\bb=(\w+) seq=(\d+)\b")
N = 10


@dataclass
class CloudCase:
    config_type: str
    provider: Any  # nano_e2e.pull.PullProvider
    credential_fields: list[dict[str, Any]]
    connection_fields: list[dict[str, Any]]
    expect_conn: dict[str, Any]
    region: str | None = None
    # Credential lifecycle in the UI after the pull works (NAN-4941 layout):
    # (secret, rotate_fields) or None.
    lifecycle: tuple[str, list[dict[str, Any]]] | None = None


@pytest.fixture
def ui_pull_cleanup(stack: Stack, nano: Nano, mark: str) -> Iterator[None]:
    """Delete what this scenario created (the browser created most of it, so
    found by name). Order matters: the parser bound to the source config goes
    first, or deleting the config leaves a parser that wedges every deploy."""
    yield
    for s in api_expect(nano.api.get("/api/log-sources"), 200):
        if str(s.get("description", "")).startswith(f"nano-e2e ui pull {mark}"):
            feeds.delete_log_source(nano, s["id"])
    configs = nano.api.get("/api/source-configurations")
    if configs.status_code == 200:
        body = configs.json()
        for c in body if isinstance(body, list) else body.get("items", []):
            # Deployed or not, right after the parser delete: a source-config
            # change re-renders the whole parser tree, so no route the
            # deletes removed is left named (NAN-4956).
            if str(c.get("name", "")).startswith(mark):
                api_expect(nano.api.delete(f"/api/source-configurations/{c['id']}"), 200, 204)
    creds = nano.api.get("/api/credentials")
    if creds.status_code == 200:
        body = creds.json()
        for c in body if isinstance(body, list) else body.get("credentials", body.get("items", [])):
            if str(c.get("name", "")).startswith(mark):
                nano.api.delete(f"/api/credentials/{c['id']}")


def _landed(nano: Nano, mark: str) -> Counter[tuple[str, int]]:
    seen: Counter[tuple[str, int]] = Counter()
    for r in nano.rows(f'"{mark}"', limit=2000, minutes_back=120):
        if m := SEQ.search(row_text(r)):
            seen[(m.group(1), int(m.group(2)))] += 1
    return seen


def _bodies(mark: str, batch: str, n: int) -> list[str]:
    return [json.dumps({"message": f"{mark} b={batch} seq={i} ui pull e2e"}) for i in range(n)]


def _run(page: uilib.UiPage, nano: Nano, mark: str, case: CloudCase, rk: str, timeline) -> None:
    require_config_type(nano, case.config_type, "clickhouse/dev source configurations")
    cred_name, cfg_name = f"{mark}-cred", f"{mark}-src"
    layout, cfg_id = ui_pull.setup_pull_source(
        page,
        case.config_type,
        cfg_name,
        cred_name,
        case.credential_fields,
        case.connection_fields,
        region=case.region,
    )
    timeline.step("ui: credential, source config and connection", layout=layout, id=cfg_id)

    # Deploy the transport first: a parser bound to a source config that is not
    # deployed renders an input (`<config>_route`) that does not exist yet, and
    # Vector rejects that whole generation (NAN-4937 finding).
    ui_pull.deploy(page)
    first = api_expect(nano.api.get(f"/api/source-configurations/{cfg_id}"), 200)
    assert first["deployed"] is True, first
    timeline.step("ui: deployed (transport)", deployed_at=first.get("deployed_at"))

    # Routing target: a deployed parser of this transport, bound to this source
    # config, claiming the route key. (Parser authoring in the UI is the
    # unified Add source flow, NAN-4922, not on dev yet: the API stands in.)
    parser = f"e2e-ui-pull-{rk}"
    feeds.ensure_lane_source(
        nano,
        rk,
        transport=case.config_type,
        name=parser,
        extra={"dispatch_source_config_id": cfg_id, "description": f"nano-e2e ui pull {mark}"},
    )
    page.reload()
    ui_pull.route_single(page, parser)
    timeline.step("ui: routed", parser=parser)
    ui_pull.deploy(page)
    eventually(
        lambda: api_expect(nano.api.get(f"/api/source-configurations/{cfg_id}"), 200),
        timeout=60,
        desc="routing deployed (deployed_at advanced)",
        ok=lambda c: c.get("deployed") is True and c.get("deployed_at") != first.get("deployed_at"),
    )
    full = api_expect(nano.api.get(f"/api/source-configurations/{cfg_id}/full"), 200)
    rules = full.get("routing_rules") or []
    timeline.step(
        "ui: deployed (routing)",
        default_source_type=full.get("default_source_type"),
        rules=[
            {k: r.get(k) for k in ("source_type", "match_field", "match_value", "is_default")} for r in rules
        ],
    )

    # What the UI saved is what was typed.
    cfg = api_expect(nano.api.get(f"/api/source-configurations/{cfg_id}"), 200)
    creds = api_expect(nano.api.get("/api/credentials"), 200)
    cred_list = creds if isinstance(creds, list) else creds.get("credentials", creds.get("items", []))
    cred = next(c for c in cred_list if c.get("name") == cred_name)
    assert cfg["config_type"] == case.config_type, cfg
    assert cfg["credential_id"] == cred["id"], (cfg, cred)
    assert cfg["deployed"] is True, cfg
    for k, v in case.expect_conn.items():
        allowed = v if isinstance(v, tuple) else (v,)
        assert cfg["connection_config"].get(k) in allowed, (
            f"connection_config.{k}: {cfg['connection_config']}"
        )
    timeline.step(
        "api agrees with the UI",
        connection=cfg["connection_config"],
        default_source_type=cfg.get("default_source_type"),
    )

    # Real cloud → nano. Warm up (sources start at current activity), then a batch.
    probes = {"k": 0}

    def probe() -> bool:
        probes["k"] += 1
        case.provider.publish(_bodies(mark, f"warm{probes['k']}", 1))
        return any(b.startswith("warm") for b, _ in _landed(nano, mark))

    eventually(probe, timeout=PULL_VISIBLE, interval=10, desc="first warm-up event from the cloud to land")
    case.provider.publish(_bodies(mark, "main", N))
    want = {("main", i) for i in range(N)}
    seen = eventually(
        lambda: _landed(nano, mark),
        timeout=PULL_VISIBLE,
        interval=5,
        desc=f"{N} events from {case.config_type}",
        ok=lambda s: want <= set(s),
    )
    main = {k: c for k, c in seen.items() if k[0] == "main"}
    timeline.step("landed", main=len(main), duplicates=sum(c - 1 for c in main.values()), probes=probes["k"])
    rows = nano.rows(f'"{mark}" "b=main"', limit=100, minutes_back=120)
    assert {str(r.get("source_type")) for r in rows} == {rk}, "events did not take the UI-configured route"

    # The search UI shows exactly what the API returns.
    uilib.run_search(page, f'"{mark}" "b=main"')
    api_total = nano.search(f'"{mark}" "b=main"', minutes_back=60)["total_count"]
    assert uilib.results_count(page) == api_total >= N
    page.goto(ui_pull.source_config_path(layout, cfg_id))
    page.wait_text("Deployed")

    if case.lifecycle and layout == ui_pull.LOG_SOURCES_TABS:
        _credential_lifecycle(page, nano, mark, case, cfg_id, cfg_name, cred_name, timeline)


def _credential_lifecycle(
    page: uilib.UiPage,
    nano: Nano,
    mark: str,
    case: CloudCase,
    cfg_id: str,
    cfg_name: str,
    cred_name: str,
    timeline,
) -> None:
    """Rotate in place, versions, roll back, delete refused while in use (the
    source named), undeploy; the secret is never shown back."""
    assert case.lifecycle
    secret, rotate_fields = case.lifecycle
    creds = api_expect(nano.api.get("/api/credentials"), 200)
    cred = next(
        c
        for c in (creds if isinstance(creds, list) else creds.get("credentials", []))
        if c["name"] == cred_name
    )
    since = page.now_ms()

    page.goto(ui_pull.CLOUD_PULL_PATH)
    page.click({"text": cred_name, "exact": True, "within": {"testid": "credentials-manager"}})
    insp = {"testid": "credential-inspector"}
    page.wait_for(insp)
    masked = " ".join(page.texts({"testid": "credential-secret-masked"}))
    assert "••" in masked and "v1" in masked, masked
    assert not page.contains(secret), "the stored secret is in the DOM"

    # Rotate in place (the second key pair): v2 active, events keep landing.
    page.click({"role": "button", "name": "Rotate", "exact": True, "within": insp})
    page.fill(*rotate_fields)
    page.click({"role": "button", "name": rx("^Rotate & activate")})
    page.wait_text("Credential rotated", exact=False, timeout_ms=60_000)
    versions = api_expect(nano.api.get(f"/api/credentials/{cred['id']}/versions"), 200)
    vlist = versions if isinstance(versions, list) else versions.get("versions", [])
    assert len(vlist) == 2, versions
    case.provider.publish(_bodies(mark, "rot", 5))
    # A message the PREVIOUS topology received while the rotation reloaded is
    # redelivered only after the SQS visibility timeout (Vector's aws_sqs
    # default: 300 s): at-least-once, not loss. Allow for it.
    eventually(
        lambda: _landed(nano, mark),
        timeout=PULL_VISIBLE + SQS_REDELIVERY,
        interval=5,
        desc="events after rotate",
        ok=lambda s: {("rot", i) for i in range(5)} <= set(s),
    )
    timeline.step("rotated in place: events keep landing")

    # Versions → roll back to v1.
    page.goto(ui_pull.CLOUD_PULL_PATH)
    page.click({"text": cred_name, "exact": True, "within": {"testid": "credentials-manager"}})
    page.click({"role": "button", "name": "Versions", "exact": True, "within": insp})
    page.click({"role": "button", "name": "Rollback to v1", "within": insp})
    page.wait_text("Credential rolled back", exact=False)
    # Rollback is forward-only: it activates a NEW version carrying v1's
    # secret (v3), and the source keeps reading with it.
    after = api_expect(nano.api.get(f"/api/credentials/{cred['id']}"), 200)
    vs = api_expect(nano.api.get(f"/api/credentials/{cred['id']}/versions"), 200)
    vlist = vs if isinstance(vs, list) else vs.get("versions", [])
    assert len(vlist) == 3 and int(after.get("active_version") or 0) == 3, (after, vlist)
    case.provider.publish(_bodies(mark, "rb", 5))
    # Same as after the rotation: an in-flight message comes back after the
    # SQS visibility timeout.
    eventually(
        lambda: _landed(nano, mark),
        timeout=PULL_VISIBLE + SQS_REDELIVERY,
        interval=5,
        desc="events after rollback",
        ok=lambda s: {("rb", i) for i in range(5)} <= set(s),
    )
    timeline.step("rolled back to v1's secret (as v3): events keep landing")

    # Delete while in use: refused, naming the source config.
    page.click({"role": "button", "name": "Danger", "exact": True, "within": insp})
    page.fill(field({"placeholder": cred_name, "within": insp}, cred_name))
    page.click({"role": "button", "name": "Delete permanently", "within": insp})
    page.wait_text("Credential is in use", exact=False)
    page.wait_text(rx(re.escape(f'source configuration "{cfg_name}"')), exact=False)
    assert nano.api.get(f"/api/credentials/{cred['id']}").status_code == 200, (
        "an in-use credential was deleted"
    )
    timeline.step("delete refused while in use, source named")

    # Undeploy from the source config page.
    page.goto(ui_pull.source_config_path(ui_pull.LOG_SOURCES_TABS, cfg_id))
    page.click({"role": "button", "name": "Undeploy", "exact": True})
    page.click({"role": "button", "name": "Undeploy", "exact": True, "within": {"role": "alertdialog"}})
    eventually(
        lambda: api_expect(nano.api.get(f"/api/source-configurations/{cfg_id}"), 200),
        timeout=60,
        desc="undeployed",
        ok=lambda c: c.get("deployed") is False,
    )
    leaks = page.responses_containing(secret, since_ms=since)
    assert not leaks, f"the stored secret came back from: {leaks}"
    timeline.step("undeployed; secret never returned")


def test_ui_aws_sqs_pull(
    page: uilib.UiPage, nano: Nano, mark: str, aws_creds, sqs_queue, ui_pull_cleanup, request, timeline
) -> None:
    cred = [
        field({"role": "textbox", "name": rx("^Region")}, aws_creds.region),
        field({"role": "textbox", "name": rx("^Access key ID")}, aws_creds.access_key_id),
        field(
            {"role": "textbox", "name": rx("^Secret access key")}, aws_creds.secret_access_key, secret=True
        ),
    ]
    conn = [field({"placeholder": "https://sqs.ap-south-1.amazonaws.com/123456789/my-queue"}, sqs_queue.url)]

    _run(
        page,
        nano,
        mark,
        CloudCase(
            "aws_sqs",
            AwsSqsPayload(aws_creds, sqs_queue),
            cred,
            conn,
            # region: the select shows us-east-1 and saves it only when
            # changed; the effective value is what must match.
            {
                "queue_url": sqs_queue.url,
                "region": (aws_creds.region, None) if aws_creds.region == "us-east-1" else aws_creds.region,
            },
            region=aws_creds.region,
            lifecycle=(
                aws_creds.secret_access_key,
                [
                    field(
                        {"role": "textbox", "name": rx("^Access key ID")},
                        aws_creds.rotate_access_key_id or aws_creds.access_key_id,
                    ),
                    field(
                        {"role": "textbox", "name": rx("^Secret access key")},
                        aws_creds.rotate_secret_access_key or aws_creds.secret_access_key,
                        secret=True,
                    ),
                ],
            ),
        ),
        route_key(request.node.nodeid, "ui-pull"),
        timeline,
    )


def test_ui_azure_event_hubs_pull(
    page: uilib.UiPage, nano: Nano, mark: str, azure_hub, ui_pull_cleanup, request, timeline
) -> None:
    c = azure_hub.creds
    conn_cfg = azure_hub.connection_config()

    cred = [
        press({"role": "button", "name": "Service principal", "exact": True}),
        field({"role": "textbox", "name": rx(r"^Directory \(tenant\) ID")}, c.tenant_id),
        field({"role": "textbox", "name": rx(r"^Application \(client\) ID")}, c.client_id),
        field({"role": "textbox", "name": rx("^Client secret")}, c.client_secret, secret=True),
    ]
    conn = [
        field({"placeholder": "insights-activity-logs"}, conn_cfg["event_hub_name"]),
        field({"placeholder": "$Default"}, conn_cfg["consumer_group"]),
        field({"placeholder": "acme-logs"}, conn_cfg["namespace"]),
        field({"placeholder": "nano-checkpoints"}, conn_cfg["checkpoint_container"]),
        field({"placeholder": "acmecheckpoints"}, conn_cfg["checkpoint_account"]),
    ]

    _run(
        page,
        nano,
        mark,
        CloudCase(
            "azure_event_hubs",
            AzureEventHubs(azure_hub),
            cred,
            conn,
            {
                "event_hub_name": conn_cfg["event_hub_name"],
                "consumer_group": conn_cfg["consumer_group"],
                "checkpoint_container": conn_cfg["checkpoint_container"],
            },
        ),
        route_key(request.node.nodeid, "ui-pull"),
        timeline,
    )


def test_ui_gcp_pubsub_pull(
    page: uilib.UiPage, nano: Nano, mark: str, gcp_pubsub, ui_pull_cleanup, request, timeline
) -> None:
    # authorized_user ADC is accepted since NAN-4935 (credential + Vector
    # 0.61.0-nano.3); a service-account key works the same way.
    # "Credentials JSON" (current dev) / "Service account JSON" (NAN-4941).
    cred = [field({"css": "textarea[placeholder^='{\"type\"']"}, gcp_pubsub.creds.sa_json, secret=True)]
    conn = [
        field({"placeholder": "my-gcp-project"}, gcp_pubsub.creds.project),
        field({"placeholder": "my-subscription"}, gcp_pubsub.subscription),
    ]

    _run(
        page,
        nano,
        mark,
        CloudCase(
            "gcp_pubsub",
            GcpPubSub(gcp_pubsub.creds, gcp_pubsub),
            cred,
            conn,
            {"project": gcp_pubsub.creds.project, "subscription": gcp_pubsub.subscription},
        ),
        route_key(request.node.nodeid, "ui-pull"),
        timeline,
    )
