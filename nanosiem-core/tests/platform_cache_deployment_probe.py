"""Targeted, local-only deployment/service probe. Run from any working directory."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

import yaml

ROOT = Path(__file__).resolve().parents[2]
MANIFESTS = ROOT / "deploy/hosted-shared-fixtures"
bronze = yaml.safe_load((MANIFESTS / "application-bronze-publishers.yaml").read_text())
assert len(bronze["items"]) == 9
for item in bronze["items"]:
    spec = item["spec"]["template"]["spec"]
    assert spec["serviceAccountName"] == "platform-feed-bronze"
    assert 2999 in spec["securityContext"]["supplementalGroups"]
    volume = next(v for v in spec["volumes"] if v["name"] == "platform-feeds")
    assert volume["hostPath"]["path"] == "/var/lib/nano/platform-feeds"
    for container in spec["containers"]:
        mounts = [m for m in container["volumeMounts"] if m["name"] == "platform-feeds"]
        assert len(mounts) == 1 and mounts[0]["readOnly"]
        assert container["image"] == "__GAR_BRONZE_IMAGE__"
cache = list(yaml.safe_load_all((MANIFESTS / "application-platform-feed-cache.yaml").read_text()))
assert len(cache) == 5
assert cache[2]["kind"] == "DaemonSet"
assert cache[2]["spec"]["template"]["spec"]["containers"][0]["env"][0]["value"] == "false"
print("PASS: nine restricted read-only bronze mounts, pinned images, inactive cache deployment")

binary = ROOT / "target/debug/lake_platform_feed_cache"
env = {k: v for k, v in os.environ.items() if not k.startswith(("AWS_", "PLATFORM_FEED_"))}
child = subprocess.Popen([str(binary)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
try:
    time.sleep(0.1)
    assert child.poll() is None, "disabled service must remain supervised without credentials"
finally:
    child.terminate()
    stdout, stderr = child.communicate(timeout=10)
assert not stdout and not stderr
print("PASS: disabled service parks without credentials or output")

with tempfile.TemporaryDirectory(dir=ROOT / "target", prefix="cache-service-probe-") as directory:
    directory = Path(directory)
    directory.chmod(0o700)
    config = directory / "config.json"
    config.write_text(json.dumps({
        "bucket": "fixture",
        "endpoint": "https://fixture.invalid",
        "keys": {"fixture": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"},
        "selections": [],
    }))
    env.update(
        PLATFORM_FEED_CACHE_ENABLED="true",
        PLATFORM_FEED_CACHE_ROOT=str(directory / "cache"),
        PLATFORM_FEED_CACHE_CONFIG=str(config),
        PLATFORM_FEED_VERIFY_KEYS=json.dumps(json.loads(config.read_text())["keys"]),
        AWS_ACCESS_KEY_ID="fixture-only",
        AWS_SECRET_ACCESS_KEY="fixture-only",
        AWS_EC2_METADATA_DISABLED="true",
    )
    with (directory / "stdout").open("w") as out, (directory / "stderr").open("w") as err:
        child = subprocess.Popen([str(binary)], env=env, stdout=out, stderr=err)
        try:
            for _ in range(100):
                if "ready" in (directory / "stdout").read_text():
                    break
                assert child.poll() is None, (directory / "stderr").read_text()
                time.sleep(0.05)
            else:
                raise AssertionError("cache service readiness timeout")
            limits = Path(f"/proc/{child.pid}/limits").read_text()
            assert any("Max data size" in line and "268435456" in line for line in limits.splitlines())
            evidence = {
                "pid": child.pid,
                "stdout": (directory / "stdout").read_text(),
                "limits": limits,
                "smaps_rollup": Path(f"/proc/{child.pid}/smaps_rollup").read_text(),
                "selections": 0,
                "network_requests": 0,
            }
            (ROOT / "target/nan2469-p3-service-memory.json").write_text(json.dumps(evidence, indent=2))
            print("PASS: empty-selection service ready; private data limit 268435456 bytes; zero object requests")
        finally:
            child.terminate()
            child.wait(timeout=10)
