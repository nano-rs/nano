#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Check cargo metadata for the exact default/released binary graph."""
import json
import sys

if "--artifacts" in sys.argv:
    expected = {"nanosiem-api", "nanosiem-jobs", "nanosiem-search",
                "nanosiem-lake-worker", "nanosiem-lake-cell", "nano-connector", "nano-connector-runner"}
    seen_binaries = set()
    seen_core = False
    for line in sys.stdin:
        artifact = json.loads(line)
        if artifact.get("reason") != "compiler-artifact":
            continue
        name = artifact["target"]["name"]
        if name == "nanosiem_core":
            seen_core = True
        if name in expected and "bin" in artifact["target"]["kind"]:
            seen_binaries.add(name)
        if name.startswith(("nanosiem", "nano_connector", "nano-connector")) and (
            "enterprise" in artifact["features"] or name.endswith("_enterprise")
        ):
            sys.exit("FAIL: compiled enterprise artifact in OSS build")
    if not seen_core or seen_binaries != expected:
        sys.exit("FAIL: build report lacks core or a released binary")
    print("OK: compiled core and all released binaries contain no enterprise feature")
    sys.exit(0)

metadata = json.load(sys.stdin)
packages = {p["id"]: p for p in metadata["packages"]}
nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
pending = list(metadata["workspace_default_members"])
seen = set()
while pending:
    package_id = pending.pop()
    if package_id in seen:
        continue
    seen.add(package_id)
    package = packages[package_id]
    node = nodes[package_id]
    if package["name"].endswith("-enterprise") or (
        package["name"].startswith(("nanosiem-", "nano-connector")) and "enterprise" in node["features"]
    ):
        sys.exit("FAIL: enterprise code reachable in the OSS graph")
    for dep in node["deps"]:
        # Include dev edges too: cargo test must remain open-only.
        pending.append(dep["pkg"])
print("OK: default build/test and released binary graph is enterprise-free")
