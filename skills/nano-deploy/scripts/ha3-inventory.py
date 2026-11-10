#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Write a 3-node HA inventory.yaml for the nano enterprise role-split installer.

Layout (nano.rs/docs "High availability", without ingest on the app host):
  node 1: app, postgres, keeper 1
  node 2: clickhouse (shard 1 replica 1), keeper 2, ingest
  node 3: clickhouse (shard 1 replica 2), keeper 3, ingest
Ingest is deliberately NOT on the app host: in 2.0.x the ingest role's Vector
re-owns the shared vector-dynamic volume that nano-api writes, so the API can
never publish a Vector config generation and the app+ingest install deadlocks
(validated on 2.0.0; see references/known-issues.md).

The product's renderer (deploy/compose/render-inventory.py, run by install.sh)
stays the authority: it re-validates everything. This helper only fills the
documented schema from the intake so names, ids and ports are consistent.

Example:
  ha3-inventory.py --cluster-name prod --deployment-id deploy_01abc... \
    --app-hostname nano.example.com --ingest-hostname ingest.nano.example.com \
    --node nano-1=10.20.0.11 --node nano-2=10.20.0.12 --node nano-3=10.20.0.13 \
    --tls-server-name nano-private.example.com --trusted-proxy-cidr 10.20.0.5/32 \
    --out inventory.yaml

Use --plaintext-lab ONLY for a disposable, isolated lab (it also requires
NANO_LAB_ONLY_PLAINTEXT=1 on every installer run, and the installer warns).
"""
from __future__ import annotations

import argparse
import ipaddress
import re
import sys

ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
HOST_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$")


def fail(msg: str) -> None:
    print(f"ha3-inventory: {msg}", file=sys.stderr)
    raise SystemExit(2)


def q(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--cluster-name", required=True)
    p.add_argument("--deployment-id", required=True,
                   help="use the app.nano.rs NANO_DEPLOYMENT_ID so licence check-in and volume names agree")
    p.add_argument("--app-hostname", required=True)
    p.add_argument("--ingest-hostname", required=True)
    p.add_argument("--node", action="append", required=True, metavar="NAME=ADDRESS",
                   help="exactly three, in order node1 node2 node3")
    p.add_argument("--tls-dir", default="/var/lib/nano/tls/staged",
                   help="output of scripts/nano-tls-stage on every host")
    p.add_argument("--tls-server-name", help="private certificate name (required unless --plaintext-lab)")
    p.add_argument("--trusted-proxy-cidr", action="append", default=[],
                   help="load balancer source CIDR(s) allowed to set X-Forwarded-For")
    p.add_argument("--lb-ingest-address", help="private DNS/IP of the ingest load balancer (port 443)")
    p.add_argument("--lb-ingest-tls-name")
    p.add_argument("--lb-ingest-trusted-cidr")
    p.add_argument("--plaintext-lab", action="store_true")
    p.add_argument("--out", default="-")
    a = p.parse_args()

    for label, value in (("cluster-name", a.cluster_name), ("deployment-id", a.deployment_id)):
        if not ID_RE.match(value):
            fail(f"--{label} must match {ID_RE.pattern} (lowercase letters, digits, _ and -)")
    for label, value in (("app-hostname", a.app_hostname), ("ingest-hostname", a.ingest_hostname)):
        if not HOST_RE.match(value):
            fail(f"--{label} is not a valid host name")
    if a.app_hostname == a.ingest_hostname:
        fail("--app-hostname and --ingest-hostname must differ")
    if len(a.node) != 3:
        fail("give exactly three --node NAME=ADDRESS values")
    nodes = []
    for item in a.node:
        if "=" not in item:
            fail(f"--node {item!r} must be NAME=ADDRESS")
        name, addr = item.split("=", 1)
        if not ID_RE.match(name):
            fail(f"node name {name!r} must match {ID_RE.pattern}")
        try:
            ip = ipaddress.ip_address(addr)
            if not ip.is_private:
                fail(f"node address {addr} is not a private address")
        except ValueError:
            if not HOST_RE.match(addr):
                fail(f"node address {addr!r} is not an IP or host name")
        nodes.append((name, addr))
    if len({n for n, _ in nodes}) != 3 or len({ad for _, ad in nodes}) != 3:
        fail("node names and addresses must be unique")
    for cidr in a.trusted_proxy_cidr + ([a.lb_ingest_trusted_cidr] if a.lb_ingest_trusted_cidr else []):
        try:
            ipaddress.ip_network(cidr, strict=True)
        except ValueError:
            fail(f"{cidr!r} is not a canonical CIDR (no host bits)")
    lb = [a.lb_ingest_address, a.lb_ingest_tls_name, a.lb_ingest_trusted_cidr]
    if any(lb) and not all(lb):
        fail("--lb-ingest-address, --lb-ingest-tls-name and --lb-ingest-trusted-cidr go together")
    if not a.plaintext_lab and not a.tls_server_name:
        fail("--tls-server-name is required (private TLS is the default); --plaintext-lab is for disposable labs only")

    out = ["# nano role-split inventory: 3-node HA (generated by nano-deploy ha3-inventory.py)",
           "# Shared byte-for-byte by every host at /etc/nano/inventory.yaml (owner = installer user, mode 0600).",
           "# Never change deployment_id, host names/ids, roles or shard/replica after the first install.",
           "version: 1", "cluster:",
           f"  name: {a.cluster_name}",
           f"  deployment_id: {a.deployment_id}"]
    if a.plaintext_lab:
        out += ["  # TEST/LAB ONLY: private traffic is NOT encrypted. Requires NANO_LAB_ONLY_PLAINTEXT=1.",
                "  allow_plaintext_private_network: true"]
    else:
        out += ["  tls:",
                f"    cert: {a.tls_dir}/server.crt",
                f"    key: {a.tls_dir}/server.key",
                f"    ca: {a.tls_dir}/ca.crt",
                f"    server_name: {a.tls_server_name}"]
    if a.trusted_proxy_cidr:
        out.append(f"  trusted_proxy_cidrs: [{', '.join(a.trusted_proxy_cidr)}]")
    out += [f"  app_hostname: {a.app_hostname}", f"  ingest_hostname: {a.ingest_hostname}"]
    if all(lb):
        out += ["load_balancer:", "  ingest_endpoint:",
                f"    address: {a.lb_ingest_address}",
                f"    tls_name: {a.lb_ingest_tls_name}",
                f"    trusted_cidr: {a.lb_ingest_trusted_cidr}"]
    letters = "abc"
    out.append("hosts:")
    for i, (name, addr) in enumerate(nodes, start=1):
        out += [f"  - name: {name}", f"    id: {a.cluster_name}-{letters[i - 1]}", f"    address: {addr}"]
        if i == 1:
            out += ["    roles: [app, postgres, keeper]",
                    "    keeper: {\"id\": 1}"]
        else:
            out += ["    roles: [clickhouse, keeper, ingest]",
                    f"    clickhouse: {{\"shard\": 1, \"replica\": {i - 1}}}",
                    f"    keeper: {{\"id\": {i}}}"]
    text = "\n".join(out) + "\n"
    if a.out == "-":
        sys.stdout.write(text)
    else:
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"wrote {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
