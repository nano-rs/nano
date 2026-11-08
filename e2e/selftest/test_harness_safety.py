"""Harness safety properties (no stack, no cloud).

P1-2  GC deletes only resources carrying the ownership tags, for an inactive
      run, past the cutoff; the name prefix alone never authorizes deletion.
P1-3  an explicitly selected suite/lane that executes nothing FAILS.
P1-5  Azure refuses modes that cannot isolate a run; every run gets its own
      consumer group and checkpoint container, also on a pre-provisioned hub.
P2-7  cloud DELETEs are verified (2xx/404 only, conflicts retried).
P2-8  a timed-out legacy lane's whole process group is terminated.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from botocore.stub import Stubber

from nano_e2e import creds, legacy, runid
from nano_e2e.cloud import aws, azure, gcp

NOW = time.time()
OLD = str(int(NOW - 3 * 3600))
NEW = str(int(NOW - 60))
CUTOFF = NOW - 3600


# ---------------------------------------------------------------- P1-2 ownership
@pytest.mark.parametrize(
    ("name", "tags", "exclude", "want"),
    [
        (
            "nano-e2e-gh1-1-q-abc",
            {"nano-e2e": "1", "nano-e2e-run": "gh1-1", "nano-e2e-created": OLD},
            set(),
            True,
        ),
        # prefix alone: no ownership tags -> never
        ("nano-e2e-gh1-1-q-abc", {}, set(), False),
        ("nano-e2e-gh1-1-q-abc", {"nano-e2e-run": "gh1-1", "nano-e2e-created": OLD}, set(), False),
        # tags claim another run than the name -> never
        (
            "nano-e2e-gh1-1-q-abc",
            {"nano-e2e": "1", "nano-e2e-run": "gh9-9", "nano-e2e-created": OLD},
            set(),
            False,
        ),
        # active run -> never, even when old
        (
            "nano-e2e-gh1-1-q-abc",
            {"nano-e2e": "1", "nano-e2e-run": "gh1-1", "nano-e2e-created": OLD},
            {"gh1-1"},
            False,
        ),
        # too recent -> never
        (
            "nano-e2e-gh1-1-q-abc",
            {"nano-e2e": "1", "nano-e2e-run": "gh1-1", "nano-e2e-created": NEW},
            set(),
            False,
        ),
        # no / garbage creation stamp -> never
        (
            "nano-e2e-gh1-1-q-abc",
            {"nano-e2e": "1", "nano-e2e-run": "gh1-1", "nano-e2e-created": "x"},
            set(),
            False,
        ),
        # outside the prefix -> never
        ("prod-queue", {"nano-e2e": "1", "nano-e2e-run": "gh1-1", "nano-e2e-created": OLD}, set(), False),
    ],
)
def test_gc_eligibility(name: str, tags: dict[str, str], exclude: set[str], want: bool) -> None:
    assert runid.gc_eligible(name, tags, cutoff_epoch=CUTOFF, exclude_runs=exclude) is want


def test_owner_tags_carry_run_and_stamp(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("E2E_RUN_ID", "gh7-2")
    tags = runid.owner_tags()
    assert tags["nano-e2e"] == "1" and tags["nano-e2e-run"] == "gh7-2"
    assert abs(int(tags["nano-e2e-created"]) - NOW) < 60


def test_aws_gc_deletes_only_owned_inactive_old(monkeypatch: pytest.MonkeyPatch) -> None:
    c = creds.AwsCreds(access_key_id="AKIAEXAMPLE", secret_access_key="x" * 40, region="us-east-1")
    sess = aws.session(c)
    s3, sqs = sess.client("s3", region_name="us-east-1"), sess.client("sqs", region_name="us-east-1")
    old_dt = datetime.now(UTC) - timedelta(hours=5)
    s3s, sqss = Stubber(s3), Stubber(sqs)
    s3s.add_response(
        "list_buckets",
        {
            "Buckets": [
                {"Name": "nano-e2e-gh1-1-b-own", "CreationDate": old_dt},
                {"Name": "nano-e2e-gh2-1-b-untagged", "CreationDate": old_dt},
                {"Name": "nano-e2e-gh3-1-b-active", "CreationDate": old_dt},
            ]
        },
    )
    owned = [{"Key": "nano-e2e", "Value": "1"}, {"Key": "nano-e2e-created", "Value": OLD}]
    s3s.add_response("get_bucket_tagging", {"TagSet": [*owned, {"Key": "nano-e2e-run", "Value": "gh1-1"}]})
    # owned, inactive, old: emptied and deleted
    s3s.add_response("list_objects_v2", {"KeyCount": 0})
    s3s.add_response("delete_bucket", {}, {"Bucket": "nano-e2e-gh1-1-b-own"})
    # untagged (prefix only): kept
    s3s.add_client_error("get_bucket_tagging", service_error_code="NoSuchTagSet")
    # owned but its run is active: kept
    s3s.add_response("get_bucket_tagging", {"TagSet": [*owned, {"Key": "nano-e2e-run", "Value": "gh3-1"}]})
    sqss.add_response("list_queues", {"QueueUrls": ["https://sqs/1/nano-e2e-gh2-1-q-x"]})
    sqss.add_response("list_queue_tags", {"Tags": {}})  # untagged: kept
    monkeypatch.setattr(aws, "session", lambda _c: _Sess(s3, sqs))
    with s3s, sqss:
        removed = aws.gc(c, timedelta(hours=1), frozenset({"gh3-1"}))
    assert removed == ["s3://nano-e2e-gh1-1-b-own"]


class _Sess:
    def __init__(self, s3: Any, sqs: Any):
        self._c = {"s3": s3, "sqs": sqs}

    def client(self, name: str, **_: Any) -> Any:
        return self._c[name]


def test_cloud_gc_cli_refuses_unsafe_cutoff() -> None:
    r = subprocess.run(
        [sys.executable, "-m", "nano_e2e.cloud.gc", "--older-than-hours", "0"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert r.returncode != 0 and "older-than-hours" in r.stderr


# ---------------------------------------------------------------- P2-7 verified deletes
class _Resp:
    def __init__(self, code: int):
        self.status_code, self.text = code, "x"


class _FakeSession:
    def __init__(self, codes: list[int]):
        self.codes, self.calls = list(codes), 0

    def delete(self, url: str, timeout: int) -> _Resp:
        self.calls += 1
        return _Resp(self.codes.pop(0))


@pytest.mark.parametrize(("codes", "ok"), [([200], True), ([404], True), ([409, 200], True), ([403], False)])
def test_gcp_delete_is_verified(codes: list[int], ok: bool, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gcp.time, "sleep", lambda _s: None)
    s = _FakeSession(codes)
    if ok:
        gcp.delete_verified(s, "https://x/topic")
        assert s.calls == len(codes)
    else:
        with pytest.raises(RuntimeError, match="403"):
            gcp.delete_verified(s, "https://x/topic")


@pytest.mark.parametrize(
    ("codes", "ok"), [([202], True), ([404], True), ([409, 409, 200], True), ([401], False)]
)
def test_azure_delete_is_verified(codes: list[int], ok: bool, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(azure.time, "sleep", lambda _s: None)
    seq = list(codes)
    monkeypatch.setattr(azure.httpx, "delete", lambda *a, **k: httpx.Response(seq.pop(0)))
    if ok:
        azure.delete_verified("https://x/hub", {})
    else:
        with pytest.raises(RuntimeError, match="401"):
            azure.delete_verified("https://x/hub", {})


# ---------------------------------------------------------------- P1-5 Azure isolation
def test_azure_refuses_connection_string_only(monkeypatch: pytest.MonkeyPatch) -> None:
    for k in list(os.environ):
        if k.startswith("NANO_E2E_AZURE_"):
            monkeypatch.delenv(k)
    monkeypatch.setenv(
        "NANO_E2E_AZURE_EVENTHUB_CONNECTION_STRING", "Endpoint=sb://x.servicebus.windows.net/;k=v"
    )
    c, reason = creds.azure()
    assert c is None and "cannot create the per-run consumer group" in reason


def test_azure_pre_provisioned_hub_still_gets_per_run_group_and_container(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    c = creds.AzureCreds(
        namespace="ns1",
        tenant_id="t",
        client_id="c",
        client_secret="s",
        subscription_id="sub",
        resource_group="rg",
        eventhub_name="shared-hub",
        storage_account="acct",
    )
    calls: list[tuple[str, dict]] = []

    def fake_put(
        url: str, headers: dict | None = None, json: dict | None = None, timeout: int = 0
    ) -> httpx.Response:
        calls.append((url, {"headers": headers or {}, "json": json}))
        return httpx.Response(201)

    monkeypatch.setattr(azure, "token", lambda *_a: "tok")
    monkeypatch.setattr(azure.httpx, "put", fake_put)
    hub = azure.EventHub(
        c, name="nano-e2e-r-eh-1", container="nano-e2e-r-ckpt-1", consumer_group="nano-e2e-r-cg-1"
    )
    hub.create()
    urls = [u for u, _ in calls]
    assert not any(u.endswith("/eventhubs/shared-hub?api-version=2024-01-01") for u in urls), (
        "must not recreate"
    )
    assert any("/eventhubs/shared-hub/consumergroups/nano-e2e-r-cg-1" in u for u in urls)
    assert any(u.endswith("/nano-e2e-r-ckpt-1?restype=container") for u in urls)
    cfg = hub.connection_config()
    assert cfg["consumer_group"] == "nano-e2e-r-cg-1" and cfg["consumer_group"] != "$Default"
    assert cfg["checkpoint_container"] == "nano-e2e-r-ckpt-1"
    group_put = next(j for u, j in calls if "consumergroups" in u)
    assert '"nano-e2e-run"' in group_put["json"]["properties"]["userMetadata"]  # ownership marker
    # Teardown removes only the run's group (never the shared hub) and container.
    deleted: list[str] = []
    monkeypatch.setattr(azure, "delete_verified", lambda url, _h: deleted.append(url))
    hub.delete()
    assert any("consumergroups/nano-e2e-r-cg-1" in u for u in deleted)
    assert not any(u.split("?")[0].endswith("/eventhubs/shared-hub") for u in deleted)


# ---------------------------------------------------------------- P1-3 coverage gating
SKIP_ONLY = textwrap.dedent(
    """
    import pytest

    def test_needs_creds():
        pytest.skip("credentials absent")
    """
)


@pytest.mark.parametrize(("allow", "want_rc"), [("0", 1), ("1", 0)])
def test_selected_suite_with_zero_executed_scenarios_fails(tmp_path: Path, allow: str, want_rc: int) -> None:
    e2e = Path(__file__).resolve().parents[1]
    suite = tmp_path / "tests" / "pull"
    suite.mkdir(parents=True)
    (tmp_path / "tests" / "conftest.py").write_text((e2e / "tests" / "conftest.py").read_text())
    (suite / "test_x.py").write_text(SKIP_ONLY)
    r = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-p",
            "no:cacheprovider",
            "--rootdir",
            str(tmp_path),
            str(suite),
        ],
        cwd=tmp_path,
        env={**os.environ, "E2E_SUITE_PATHS": str(suite), "E2E_ALLOW_SKIPS": allow},
        capture_output=True,
        text=True,
        check=False,
    )
    assert r.returncode == want_rc, r.stdout + r.stderr
    if want_rc:
        assert "executed ZERO scenarios" in r.stdout


@pytest.mark.parametrize(
    ("results", "explicit", "allow", "want"),
    [
        ([("a", "pass", "")], True, False, 0),
        ([("a", "skip", "r")], True, False, 1),  # explicitly named lane skipped
        ([("a", "skip", "r"), ("b", "pass", "")], False, False, 0),  # `all` with some ran
        ([("a", "skip", "r")], False, False, 1),  # `all`, nothing ran
        ([("a", "skip", "r")], True, True, 0),  # --allow-skips
        ([("a", "FAIL (exit 1)", "")], False, True, 1),
    ],
)
def test_legacy_verdict(results: list, explicit: bool, allow: bool, want: int) -> None:
    assert legacy.verdict(results, explicit=explicit, allow_skips=allow) == want


# ---------------------------------------------------------------- P2-8 lane process groups
def test_timed_out_lane_kills_its_whole_process_group(tmp_path: Path) -> None:
    marker = tmp_path / "child.pid"
    script = tmp_path / "lane.sh"
    script.write_text(f"#!/usr/bin/env bash\nsleep 300 &\necho $! > {marker}\nsleep 300\n")
    script.chmod(0o755)
    status = legacy.run_lane_process(
        [str(script)], cwd=tmp_path, env=dict(os.environ), log=tmp_path / "lane.log", timeout=2
    )
    assert status.startswith("FAIL (timeout")
    child = int(marker.read_text())
    time.sleep(0.5)
    with pytest.raises(ProcessLookupError):
        os.kill(child, 0)
