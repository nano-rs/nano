"""Real Azure Event Hubs (+ Blob checkpoint container) test resources.

Plain REST over httpx with the service principal: Entra client-credentials
tokens, ARM for the per-run Event Hub and consumer group, the Event Hubs REST
send API for publishing, and the Blob REST API for the checkpoint container.

Isolation: every run gets its own consumer group and checkpoint container,
also on a pre-provisioned hub, so concurrent runs never share checkpoints.
Ownership: Event Hub entities cannot carry tags, so ownership is recorded in
the consumer group's `userMetadata` (JSON of nano_e2e.runid.owner_tags()) and
in the container's `x-ms-meta-*`. GC deletes only what carries those markers.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from xml.etree import ElementTree

import httpx

from nano_e2e.creds import AzureCreds
from nano_e2e.runid import CLOUD_PREFIX, gc_eligible, owner_tags

_ARM = "https://management.azure.com"
_ARM_VERSION = "2024-01-01"
_BLOB_VERSION = "2023-11-03"
_OK_DELETE = (200, 202, 204, 404)


def token(creds: AzureCreds, scope: str) -> str:
    r = httpx.post(
        f"https://login.microsoftonline.com/{creds.tenant_id}/oauth2/v2.0/token",
        data={
            "grant_type": "client_credentials",
            "client_id": creds.client_id,
            "client_secret": creds.client_secret,
            "scope": scope,
        },
        timeout=30,
    )
    if r.status_code != 200:
        raise RuntimeError(f"E2E-INFRA: Entra token for {scope} -> {r.status_code}: {r.text[:300]}")
    return r.json()["access_token"]


def _hub_url(creds: AzureCreds, hub: str) -> str:
    return (
        f"{_ARM}/subscriptions/{creds.subscription_id}/resourceGroups/{creds.resource_group}"
        f"/providers/Microsoft.EventHub/namespaces/{creds.namespace_name}/eventhubs/{hub}"
    )


def _blob(creds: AzureCreds) -> str:
    return f"https://{creds.storage_account}.blob.core.windows.net"


def delete_verified(url: str, headers: dict[str, str], attempts: int = 6) -> None:
    """DELETE and verify (2xx/404 only). ARM deletes can be asynchronous (202)
    or conflict while an operation is in flight (409): retry those. Anything
    else raises, so a failed teardown is never reported as clean."""
    r: httpx.Response | None = None
    for i in range(attempts):
        r = httpx.delete(url, headers=headers, timeout=60)
        if r.status_code in _OK_DELETE:
            return
        if r.status_code in (409, 429) or r.status_code >= 500:
            time.sleep(3 * (i + 1))
            continue
        break
    assert r is not None
    raise RuntimeError(f"E2E-INFRA: DELETE {url} -> {r.status_code}: {r.text[:300]}")


def _meta_to_tags(meta: dict[str, str]) -> dict[str, str]:
    # Blob metadata names must be C# identifiers: nano_e2e_run <-> nano-e2e-run.
    return {k.replace("_", "-"): v for k, v in meta.items()}


@dataclass
class EventHub:
    creds: AzureCreds
    name: str  # per-run hub name (replaced by the pre-provisioned hub when configured)
    container: str  # per-run checkpoint container
    consumer_group: str  # per-run consumer group
    created_hub: bool = False
    created_group: bool = False
    created_container: bool = False
    _arm: str = field(default="", repr=False)

    def _arm_headers(self) -> dict[str, str]:
        if not self._arm:
            self._arm = token(self.creds, f"{_ARM}/.default")
        return {"Authorization": f"Bearer {self._arm}"}

    def _blob_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {token(self.creds, 'https://storage.azure.com/.default')}",
            "x-ms-version": _BLOB_VERSION,
        }

    def create(self) -> EventHub:
        c, tags = self.creds, owner_tags()
        if c.eventhub_name:
            self.name = c.eventhub_name
        else:
            r = httpx.put(
                f"{_hub_url(c, self.name)}?api-version={_ARM_VERSION}",
                headers=self._arm_headers(),
                json={"properties": {"partitionCount": 2, "messageRetentionInDays": 1}},
                timeout=60,
            )
            if r.status_code not in (200, 201):
                raise RuntimeError(f"E2E-INFRA: create Event Hub -> {r.status_code}: {r.text[:500]}")
            self.created_hub = True
        r = httpx.put(
            f"{_hub_url(c, self.name)}/consumergroups/{self.consumer_group}?api-version={_ARM_VERSION}",
            headers=self._arm_headers(),
            json={"properties": {"userMetadata": json.dumps(tags)}},
            timeout=60,
        )
        if r.status_code not in (200, 201):
            raise RuntimeError(f"E2E-INFRA: create consumer group -> {r.status_code}: {r.text[:300]}")
        self.created_group = True
        meta = {f"x-ms-meta-{k.replace('-', '_')}": v for k, v in tags.items()}
        r = httpx.put(
            f"{_blob(c)}/{self.container}?restype=container",
            headers={**self._blob_headers(), **meta},
            timeout=30,
        )
        if r.status_code != 201:
            raise RuntimeError(f"E2E-INFRA: create checkpoint container -> {r.status_code}: {r.text[:300]}")
        self.created_container = True
        return self

    def send(self, bodies: list[str]) -> None:
        c = self.creds
        url = f"https://{c.namespace_host}/{self.name}/messages?timeout=60&api-version=2014-01"
        auth = f"Bearer {token(c, 'https://eventhubs.azure.net/.default')}"
        for i in range(0, len(bodies), 100):
            r = httpx.post(
                url,
                headers={"Authorization": auth, "Content-Type": "application/vnd.microsoft.servicebus.json"},
                json=[{"Body": b} for b in bodies[i : i + 100]],
                timeout=60,
            )
            if r.status_code not in (200, 201):
                raise RuntimeError(f"E2E-INFRA: Event Hubs send -> {r.status_code}: {r.text[:300]}")

    def credential_payload(self) -> dict[str, str]:
        c = self.creds
        return {
            "azure_tenant_id": c.tenant_id,
            "azure_client_id": c.client_id,
            "azure_client_secret": c.client_secret,
        }

    def connection_config(self) -> dict[str, Any]:
        return {
            "event_hub_name": self.name,
            "namespace": self.creds.namespace_host,
            "consumer_group": self.consumer_group,
            "checkpoint_container": self.container,
            "checkpoint_account": self.creds.storage_account,
        }

    def delete(self) -> None:
        errors: list[str] = []
        c = self.creds
        try:
            if self.created_hub:
                delete_verified(f"{_hub_url(c, self.name)}?api-version={_ARM_VERSION}", self._arm_headers())
            elif self.created_group:
                group = f"{_hub_url(c, self.name)}/consumergroups/{self.consumer_group}"
                delete_verified(f"{group}?api-version={_ARM_VERSION}", self._arm_headers())
        except RuntimeError as exc:
            errors.append(str(exc))
        try:
            if self.created_container:
                delete_verified(f"{_blob(c)}/{self.container}?restype=container", self._blob_headers())
        except RuntimeError as exc:
            errors.append(str(exc))
        if errors:
            raise RuntimeError("; ".join(errors))


def gc(
    creds: AzureCreds, older_than: timedelta, exclude_runs: set[str] | frozenset[str] = frozenset()
) -> list[str]:
    """Delete harness-owned hubs/consumer groups/containers (ownership markers,
    inactive run, past the cutoff). Returns what was verifiably deleted."""
    cutoff = (datetime.now(UTC) - older_than).timestamp()
    excl = set(exclude_runs)
    removed: list[str] = []
    arm = {"Authorization": f"Bearer {token(creds, f'{_ARM}/.default')}"}
    base = _hub_url(creds, "").rstrip("/")
    r = httpx.get(f"{base}?api-version={_ARM_VERSION}", headers=arm, timeout=60)
    r.raise_for_status()
    for hub in r.json().get("value", []):
        hname = hub["name"]
        g = httpx.get(f"{base}/{hname}/consumergroups?api-version={_ARM_VERSION}", headers=arm, timeout=60)
        g.raise_for_status()
        for cg in g.json().get("value", []):
            try:
                tags = json.loads((cg.get("properties") or {}).get("userMetadata") or "{}")
            except ValueError:
                continue
            if not isinstance(tags, dict) or not gc_eligible(
                cg["name"], tags, cutoff_epoch=cutoff, exclude_runs=excl
            ):
                continue
            # A hub the harness created is named for the same run: delete the
            # hub. On a pre-provisioned hub, delete only the run's group.
            if gc_eligible(hname, tags, cutoff_epoch=cutoff, exclude_runs=excl):
                delete_verified(f"{base}/{hname}?api-version={_ARM_VERSION}", arm)
                removed.append(f"eventhub:{hname}")
                break
            delete_verified(f"{base}/{hname}/consumergroups/{cg['name']}?api-version={_ARM_VERSION}", arm)
            removed.append(f"consumergroup:{hname}/{cg['name']}")
    st = {
        "Authorization": f"Bearer {token(creds, 'https://storage.azure.com/.default')}",
        "x-ms-version": _BLOB_VERSION,
    }
    r = httpx.get(f"{_blob(creds)}/?comp=list&prefix={CLOUD_PREFIX}&include=metadata", headers=st, timeout=30)
    r.raise_for_status()
    root = ElementTree.fromstring(r.text)  # noqa: S314 - trusted Azure response
    for cont in root.iter("Container"):
        name = cont.findtext("Name") or ""
        meta = {m.tag: (m.text or "") for m in (cont.find("Metadata") or [])}
        if gc_eligible(name, _meta_to_tags(meta), cutoff_epoch=cutoff, exclude_runs=excl):
            delete_verified(f"{_blob(creds)}/{name}?restype=container", st)
            removed.append(f"blob:{name}")
    return removed
