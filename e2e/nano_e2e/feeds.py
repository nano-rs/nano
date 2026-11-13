"""Connector pull feeds (NAN-4914 runner) against the mock-vendor profile.

A feed is `POST /api/connector-feeds {name, connector, config, credentials}`;
`nano-connector-runner` polls the vendor (here: `nano_e2e.mockvendor` through
the runner's lab seam), and ships each vendor event to Vector HEC as
`sourcetype=<lane>`. A feed can only be created when every lane it emits into
has an enabled, deployed, active Splunk HEC log source claiming it
(connector_feeds.rs `require_deployed_parsers`).

`VendorAdapter` is one connector: how to provision the mock tenant, how to
make N marker-carrying vendor events (timestamped inside the first
point-forward window: activation - 300 s .. now - lag), and the feed body.
"""

from __future__ import annotations

import json
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from nano_e2e.client import Nano, expect
from nano_e2e.mockvendor import GwsServiceAccount, MockVendor, iso

# Events are dated this far in the past: inside the first window (which starts
# at activation - 300 s) and older than every spec's lag (Okta 30 s, GWS 60 s).
EVENT_AGE = timedelta(seconds=120)

# Lane parser: keeps the vendor JSON as the message (searchable by marker),
# tags the lane, and makes the event an OCSF Base Event (class_uid 0). Without
# `class_uid` a parsed event leaves the parser on the UDM path, which an
# OCSF-profile stack's search never reads (NAN-4937 finding); on a UDM stack
# the extra keys are inert. `metadata.log_source` is what an OCSF parser sets;
# without it the OCSF prepare step stores source_type `unknown` for HEC-lane
# events (it reads `%source_type`, which that lane does not set; NAN-4937
# finding).
LANE_PARSER = """.e2e_connector_lane = "{lane}"
.metadata.log_source = "{lane}"
.class_uid = 0
.category_uid = 0
.activity_id = 0
.type_uid = 0
.severity_id = 1
"""


def through_lane_parser(row: dict[str, Any], lane: str) -> bool:
    """The row was produced by this harness's lane parser for `lane`.

    UDM stacks: a DB parser's output keeps only `message`, `metadata`, `ext`
    and `udm.*` (parser_config.rs output wrapper), so LANE_PARSER's top-level
    `e2e_connector_lane` is dropped there by design; the parser stamps
    `metadata.parser_name` (`e2e-lane-<lane>`, see ensure_lane_source) and
    `metadata.log_source` instead. OCSF stacks keep the parser's own field.
    """
    meta = row.get("metadata")
    if isinstance(meta, str):
        try:
            meta = json.loads(meta)
        except ValueError:
            meta = {}
    meta = meta if isinstance(meta, dict) else {}
    if meta.get("parser_name") == f"e2e-lane-{lane}" and meta.get("log_source") == lane:
        return True
    return "e2e_connector_lane" in json.dumps(row, default=str) and lane in json.dumps(row, default=str)


class VendorAdapter(Protocol):
    connector: str
    lanes: tuple[str, ...]

    def provision(self, mock: MockVendor, mark: str) -> None: ...
    def seed(self, mock: MockVendor, mark: str, n: int) -> None: ...
    def feed_body(self, name: str) -> dict[str, Any]: ...
    def hits(self, mock: MockVendor) -> int: ...


def _when() -> datetime:
    return datetime.now(UTC) - EVENT_AGE


@dataclass
class Okta:
    connector: str = "okta_system_log"
    lanes: tuple[str, ...] = ("okta",)
    domain: str = ""
    token: str = ""

    def provision(self, mock: MockVendor, mark: str) -> None:
        self.domain = f"e2e-{mark[-8:]}.okta.com"
        self.token = "00e2e" + secrets.token_hex(16)
        mock.okta_tenant(self.domain, self.token)

    def seed(self, mock: MockVendor, mark: str, n: int) -> None:
        t = _when()
        mock.okta_add(
            self.domain,
            [
                {
                    "uuid": str(uuid.uuid4()),
                    "published": iso(t + timedelta(milliseconds=i)),
                    "eventType": "user.session.start",
                    "displayMessage": f"{mark} seq={i} okta sign-in",
                    "severity": "INFO",
                    "actor": {"id": "00u-e2e", "type": "User", "alternateId": "alice@e2e.invalid"},
                    "outcome": {"result": "SUCCESS"},
                    "client": {"ipAddress": f"203.0.113.{i + 1}"},
                }
                for i in range(n)
            ],
        )

    def feed_body(self, name: str) -> dict[str, Any]:
        return {
            "name": name,
            "connector": self.connector,
            "config": {"OKTA_DOMAIN": self.domain},
            "credentials": {"API_TOKEN": self.token},
        }

    def hits(self, mock: MockVendor) -> int:
        return len(mock.hits(self.domain, "/api/v1/logs"))


@dataclass
class GoogleWorkspace:
    connector: str = "google_workspace"
    lanes: tuple[str, ...] = ("gws_login",)
    sa: GwsServiceAccount | None = None
    admin: str = ""

    def provision(self, mock: MockVendor, mark: str) -> None:
        self.sa = GwsServiceAccount.generate(f"nano-e2e-{mark[-8:]}@e2e-project.iam.gserviceaccount.com")
        self.admin = f"admin-{mark[-8:]}@e2e.invalid"
        mock.gws_account(self.sa, self.admin)

    def seed(self, mock: MockVendor, mark: str, n: int) -> None:
        t = _when()
        mock.gws_add(
            "login",
            [
                {
                    "kind": "admin#reports#activity",
                    "id": {
                        "time": iso(t + timedelta(milliseconds=i)),
                        "uniqueQualifier": str(secrets.randbits(62)),
                        "applicationName": "login",
                        "customerId": "C0e2e",
                    },
                    "actor": {"email": "alice@e2e.invalid"},
                    "ipAddress": f"198.51.100.{i + 1}",
                    "events": [
                        {
                            "type": "login",
                            "name": "login_success",
                            "parameters": [{"name": "e2e", "value": f"{mark} seq={i} gws login"}],
                        }
                    ],
                }
                for i in range(n)
            ],
        )

    def feed_body(self, name: str) -> dict[str, Any]:
        assert self.sa
        return {
            "name": name,
            "connector": self.connector,
            "config": {"ADMIN_EMAIL": self.admin, "STREAMS": "login"},
            "credentials": {"PRIVATE_KEY": self.sa.private_key_pem, "CLIENT_EMAIL": self.sa.client_email},
        }

    def hits(self, mock: MockVendor) -> int:
        return len(mock.hits("admin.googleapis.com", "/admin/reports/v1/activity/"))


@dataclass
class Slack:
    connector: str = "slack"
    lanes: tuple[str, ...] = ("slack_access_log",)
    token: str = ""

    def provision(self, mock: MockVendor, mark: str) -> None:
        self.token = "xoxp-e2e-" + secrets.token_hex(12)
        mock.slack_add(self.token, [])

    def seed(self, mock: MockVendor, mark: str, n: int) -> None:
        t = int(_when().timestamp())
        mock.slack_add(
            self.token,
            [
                {
                    "user_id": f"U0E2E{i}",
                    "username": f"user{i}",
                    "date_first": t + i,
                    "date_last": t + i,
                    "count": 1,
                    "ip": f"192.0.2.{i + 1}",
                    "user_agent": f"{mark} seq={i} slack",
                    "isp": "e2e",
                    "country": "US",
                    "region": "CA",
                }
                for i in range(n)
            ],
        )

    def feed_body(self, name: str) -> dict[str, Any]:
        return {
            "name": name,
            "connector": self.connector,
            "config": {"TEAM_ID": ""},
            "credentials": {"USER_TOKEN": self.token},
        }

    def hits(self, mock: MockVendor) -> int:
        return len(mock.hits("slack.com", "/api/team.accessLogs"))


@dataclass
class Netskope:
    """The `saas_api` credential provider's connector."""

    connector: str = "netskope"
    lanes: tuple[str, ...] = ("netskope_application",)
    host: str = ""
    token: str = ""

    def provision(self, mock: MockVendor, mark: str) -> None:
        self.host = f"e2e-{mark[-8:]}.goskope.com"
        self.token = "nsk" + secrets.token_hex(16)
        mock.netskope_tenant(self.host, self.token)

    def seed(self, mock: MockVendor, mark: str, n: int) -> None:
        t = int(_when().timestamp())
        mock.netskope_add(
            self.host,
            "application",
            [
                {
                    "_id": secrets.token_hex(12),
                    "timestamp": t + i,
                    "type": "nspolicy",
                    "app": "e2e",
                    "activity": f"{mark} seq={i} netskope",
                }
                for i in range(n)
            ],
        )

    def feed_body(self, name: str) -> dict[str, Any]:
        return {
            "name": name,
            "connector": self.connector,
            "config": {"TENANT_HOST": self.host, "STREAMS": "application", "INDEX_NAME": ""},
            "credentials": {"API_TOKEN": self.token},
        }

    def hits(self, mock: MockVendor) -> int:
        return len(mock.hits(self.host, "/api/v2/events/dataexport/events/"))


ADAPTERS: dict[str, type] = {
    "okta": Okta,
    "google_workspace": GoogleWorkspace,
    "slack": Slack,
    "saas_api_netskope": Netskope,
}


def ensure_lane_source(
    nano: Nano, lane: str, transport: str = "splunk_hec", name: str = "", extra: dict[str, Any] | None = None
) -> str:
    """An enabled, deployed, active log source of `transport` claiming `lane`,
    with this harness's lane parser (idempotent: lanes are shared by every
    scenario on the stack; a stale parser is replaced and republished)."""
    name = name or f"e2e-lane-{lane}"
    vrl = LANE_PARSER.format(lane=lane)
    sources = expect(nano.api.get("/api/log-sources"), 200)
    items = sources if isinstance(sources, list) else sources.get("sources") or sources.get("items") or []
    src = next((s for s in items if s.get("name") == name), None)
    if src and src.get("deployed") and src.get("enabled") and src.get("parser_vrl") == vrl:
        return src["id"]
    if src is None:
        src = expect(
            nano.api.post(
                "/api/log-sources",
                json={
                    "name": name,
                    "description": f"nano-e2e connector lane {lane} (NAN-4937)",
                    "source_type": transport,
                    "parser_vrl": vrl,
                    "match_values": [lane],
                    "lifecycle_status": "active",
                    **(extra or {}),
                },
            ),
            200,
            201,
        )
    elif src.get("parser_vrl") != vrl:
        expect(nano.api.put(f"/api/log-sources/{src['id']}", json={"parser_vrl": vrl}), 200)
    res = expect(nano.api.post(f"/api/log-sources/{src['id']}/publish", json={"acknowledge_unattested": True}), 200)
    assert res.get("success") is True, f"publishing lane parser {lane} failed: {res}"
    return src["id"]


def delete_log_source(nano: Nano, source_id: str) -> None:
    """Delete a log source; recover a pull-transport parser that wedges deploys.

    Every log-source delete redeploys Vector config. A pull-transport parser
    whose source config is gone ("no usable source-configuration dispatch")
    fails that deploy, so NO delete succeeds, its own included (NAN-4937
    finding). Retyping it to `routed` takes it out of the dispatch check."""
    r = nano.api.delete(f"/api/log-sources/{source_id}")
    if r.status_code in (200, 204, 404):
        return
    if "source-configuration dispatch" in r.text:
        expect(nano.api.put(f"/api/log-sources/{source_id}", json={"source_type": "routed"}), 200)
        expect(nano.api.delete(f"/api/log-sources/{source_id}"), 200, 204)
        return
    raise AssertionError(f"delete log source {source_id} -> {r.status_code}: {r.text[:500]}")
