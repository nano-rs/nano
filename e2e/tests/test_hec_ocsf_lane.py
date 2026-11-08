"""A connector-style HEC event lands on its lane (NAN-4963).

`nano-connector-runner` delivers an `okta_system_log` feed to Vector HEC with
the platform ingest token (multiplex route `*`) and `sourcetype=okta`. The
first-party `okta_ocsf` parser (imported LINKED from nano-rs/parsers and
published) claims `okta` and replaces the event root with an OCSF object
without setting `metadata.log_source`. Before the fix nothing on the HEC lane
stashed the lane for `_ocsf_prepare`, so the row was stored as `unknown`.

Here: the exact delivery, no vendor credentials. The event must be parsed
(User Management 3007, the target as `user.name`), carry
`metadata.log_source = okta`, and be found by `metadata.log_source="okta"`.
`source_type="okta"` resolves to the same routing column on OCSF and must
agree; `metadata.log_source="unknown"` must not find it.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest

from nano_e2e import feeds_live, ingest
from nano_e2e.client import Nano
from nano_e2e.feeds_live import OKTA_PARSER, row_get
from nano_e2e.stack import Stack
from nano_e2e.waits import INGEST_VISIBLE, eventually, vector_reloads_quiet


def _platform_token(run_dir: Path) -> str:
    """The platform ingest token the connector runner holds (the run's 0600
    compose.env; never printed)."""
    for line in (run_dir / "compose.env").read_text().splitlines():
        key, _, value = line.partition("=")
        if key.strip() == "NANO_PLATFORM_INGEST_TOKEN":
            return value.strip().strip("'\"")
    pytest.fail("NANO_PLATFORM_INGEST_TOKEN missing from the run's compose.env")


def _okta_deactivate(event_uuid: str, login: str) -> dict:
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    return {
        "uuid": event_uuid,
        "published": now,
        "eventType": "user.lifecycle.deactivate",
        "version": "0",
        "severity": "INFO",
        "displayMessage": "Deactivate Okta user",
        "actor": {"id": "00uADMINE2E", "type": "User", "alternateId": "admin@example.com", "displayName": "Ops Admin"},
        "client": {"ipAddress": "192.0.2.77", "userAgent": {"rawUserAgent": "nano-e2e", "os": "Unknown"}},
        "outcome": {"result": "SUCCESS"},
        "target": [{"id": "00uTARGETE2E", "type": "User", "alternateId": login, "displayName": "E2E Target"}],
        "transaction": {"type": "WEB", "id": event_uuid[:16]},
    }


def test_connector_hec_event_lands_on_its_lane(stack: Stack, nano: Nano, mark: str, timeline) -> None:
    if not os.environ.get("NANO_SCHEMA_PROFILE", "udm").startswith("ocsf"):
        pytest.skip("the lane is an OCSF field: needs an ocsf stack (`scripts/e2e.sh up` with NANO_SCHEMA_PROFILE=ocsf)")
    source_id = feeds_live.ensure_vendor_parser(nano, OKTA_PARSER)
    timeline.step("okta_ocsf published", source=source_id, lanes=OKTA_PARSER.lanes)
    timeline.step("vector reloads settled", waited=round(vector_reloads_quiet(stack.project)))
    token = _platform_token(stack.run_dir)
    login = f"{mark[-8:]}.target@example.com"
    sent: list[str] = []

    def probe() -> list:
        # A fresh event per poll: one sent during a reload may strand.
        event_uuid = str(uuid.uuid4())
        sent.append(event_uuid)
        r = ingest.hec(stack.hec_url, token, _okta_deactivate(event_uuid, login), sourcetype="okta")
        assert r.status_code == 200, r.text
        uids = " OR ".join(f'metadata.uid="{u}"' for u in sent)
        return nano.rows(f'metadata.log_source="okta" ({uids})', limit=50, minutes_back=30)

    rows = eventually(
        probe, timeout=INGEST_VISIBLE + 120, interval=5, desc="okta event searchable on metadata.log_source=okta"
    )
    row = rows[0]
    uid = str(row_get(row, "metadata.uid"))
    sample = {k: row_get(row, k) for k in ("class_uid", "metadata.log_source", "source_type", "user.name")}
    timeline.step("landed", uid=uid, sample=json.loads(json.dumps(sample, default=str)))
    assert uid in sent
    assert int(row_get(row, "class_uid")) == 3007, sample
    assert str(row_get(row, "user.name")).lower() == login, sample
    assert row_get(row, "metadata.log_source") == "okta", sample

    # On OCSF `source_type` and `metadata.log_source` both resolve to the
    # row's routing column: the UDM-era name finds the same event.
    by_source_type = nano.rows(f'source_type="okta" metadata.uid="{uid}"', limit=5, minutes_back=30)
    unknown = nano.rows(f'metadata.log_source="unknown" metadata.uid="{uid}"', limit=5, minutes_back=30)
    timeline.step("aliases", source_type_hits=len(by_source_type), unknown_hits=len(unknown))
    assert len(by_source_type) == 1, by_source_type
    assert not unknown, unknown
