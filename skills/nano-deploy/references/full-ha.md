# Full HA: no single point of failure (NAN-5215)

Use this when the operator wants every component to survive the loss of any
one host: UI, API, search, detections, alerting and ingest. It builds on
[multi-node-ha.md](multi-node-ha.md) (several app hosts, NAN-5213) and the
PostgreSQL/Valkey failover lane (NAN-5214).

## Layout

Minimum shape, one role group per failure domain (separate physical hosts):

| Hosts | Roles | Why |
| -- | -- | -- |
| 2+ | `app` | api, search, web, jobs active/active behind the LB; jobs singletons on a PostgreSQL lease |
| 3 | `postgres` | Patroni + etcd, Valkey + Sentinel (NAN-5214). Until it ships: one `postgres` host = the one remaining single point of failure |
| 2 x N | `clickhouse` | N shards x 2 replicas (`internal_replication`) |
| 3 | `keeper` | Raft quorum; may share hosts with ClickHouse or postgres |
| 2+ | `ingest` | Vector behind the LB |
| 2 | load balancer | operator-owned; managed LB or HAProxy + keepalived |

Small installs may stack roles (for example `clickhouse,keeper,ingest` on
three hosts). Losing a stacked host loses all its roles at once, which is
still survivable as long as no role group drops below its quorum or replica
count.

## Load balancer (required)

Ship the tested examples in the bundle:
`deploy/compose/examples/load-balancer/haproxy.cfg` and `keepalived.conf`
(proven by `scripts/tests/customer-lb-examples.test.sh`).

- App hostname: every app host on port 80, health check `GET /readyz`.
- Ingest hostname: every ingest host on port 80, health check `GET /healthz`,
  consistent hash on the HEC request channel (header, then `?channel=`).
- Retries: `retries 3`, `option redispatch`, `retry-on conn-failure` ONLY.
  Never `response-timeout`, `empty-response` or 5xx: the host may already
  have applied the request, and the LB would apply it twice.
- Replace `X-Forwarded-For` with the client address; put the LB's private
  address in `cluster.trusted_proxy_cidrs`.
- No managed LB: two small hosts with OS-package HAProxy + keepalived and the
  floating IP from `keepalived.conf` (nopreempt; ~3 s failover). Needs L2
  adjacency, VRRP (IP protocol 112) allowed, `net.ipv4.ip_nonlocal_bind=1`.

## Inside the cluster (rendered, nothing to configure)

- `clickhouse-proxy` and `ingest-proxy` are HAProxy with active checks
  (`/ping`, `/healthz`), ~2 s to drop a dead peer, and a failed connection
  re-sent to a healthy one. Ports: 8123 (all replicas), 18100+N (shard N),
  18200+i (one replica, for node-local SYSTEM commands).
- `ssh <host> docker compose exec clickhouse-proxy sh -c 'echo "show servers state" | socat stdio /tmp/haproxy.sock'`
  shows each peer (column 6: 2 = up).
- Ingest hosts stay ready through an API/PostgreSQL outage of up to 300 s
  (`API_OUTAGE_GRACE_SECS` on the config consumer). HEC/HTTP keep accepting on
  cached tokens. OTLP needs the API for every request.

## Background duties

- Opt-ins in the shared `.env` now apply on EVERY app host:
  `COMPOSE_PROFILES=...,pull-feeds` (connector-runner) and
  `backup-schedule --configure` (nano-backup). Before NAN-5215 neither ever
  started on a role-split host. Re-run each app host's install after changing
  them.
- Backups: every app host runs the scheduler; a PostgreSQL lock plus a
  "slot already stored" check make exactly one host take each slot. If that
  host dies mid-run, another takes over within 30 s. Requirements: a SHARED
  destination (S3/RustFS or NFS mounted at the same path), the same
  `.nano-backup/keys/` copied to every app host, the same install path and TZ.
  With a host-local path destination each app host would keep its own copy.
- connector-runner claims feeds under a PostgreSQL lease, so a dead host's
  feeds resume on another runner when the lease expires (run time + 60 s).

## What is NOT HA (tell the operator)

| Situation | Customer-visible effect |
| -- | -- |
| An ingest host dies | Events still in its Vector disk buffer arrive when it returns (not lost while its disk survives; lost if the disk is). HEC ackIds it issued can't be polled; senders resend, so duplicates are possible. NAN-5178 (end-to-end acks), NAN-5208 |
| Both replicas of one shard down | Writes to that shard block, and Vector's per-shard route back-pressures ALL ingest; searches error. Not a one-host failure |
| 2 of 3 Keepers down | Replicated tables go read-only: inserts fail, Vector buffers fill and block |
| A ClickHouse replica down > ~40 min | Its prevalence verdicts for keys that changed meanwhile stay stale until the key is seen again |
| The load balancer | Operator-owned; must be redundant itself (managed LB or keepalived pair) |
| `scripts/nano upgrade`, `backup-set` | Refuse while any host is unreachable (by design). Replace or restore the host first. Per-host `scripts/nano backup` still works |
| Single `postgres` host (before NAN-5214) | Logins, rules and alerting stop while it is down; ingest keeps accepting for up to 300 s, then senders get 503 |

## Proof

The kill-any-node chaos gate (`NANO_LIVE_SCENARIO=ha-chaos
scripts/tests/sovereign-role-installer.live.sh`, 14 emulated hosts): every
host SIGKILLed for 3 minutes in turn under a steady mixed workload. See the
NAN-5215 PR for the per-node results table.
