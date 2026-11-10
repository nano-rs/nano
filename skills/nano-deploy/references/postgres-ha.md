# PostgreSQL + Valkey failover (Compose role split)

Since NAN-5214, two or three `postgres` hosts in the inventory turn on
automatic failover for PostgreSQL (Patroni + etcd) and, with two or more app
hosts, for the shared Valkey (Sentinel). One `postgres` host renders exactly
as before. The authority is the **Multi-node Self-run** guide, section
"PostgreSQL and Valkey failover". This page is the agent procedure.

## Recommend

- **Three postgres hosts** (`roles: [postgres]`, they may also carry
  `keeper` or `clickhouse`). etcd and Sentinel run on them.
- Two postgres hosts only when the inventory already has **three Keeper
  hosts**: etcd and Sentinel then run on the Keeper hosts as witnesses.
- Keep the default `cluster.postgres_ha.synchronous_mode: on`. Say why: a
  failover loses no acknowledged write; the cost is one LAN round trip per
  commit. Offer `strict` (stop writes rather than risk loss) or `off` only on
  request.
- Private TLS is required. The cluster certificate must be valid for every
  postgres (and witness Keeper) address, be usable as a client certificate
  (`serverAuth,clientAuth`), and carry an Authority Key Identifier. Check it
  before installing: `openssl x509 -in server.crt -noout -ext subjectAltName,extendedKeyUsage,authorityKeyIdentifier`.

## What survives (tell the operator)

- Loss of any one postgres host: PostgreSQL fails over with a write gap of
  about 10-15 s (raise `cluster.postgres_ha.ttl` on slow networks to avoid
  false failovers),
  Valkey in about 10 s. Logins, rules, alerting and search continue; in-flight
  requests during the window fail and are retried by the UI and agents.
- Loss of two postgres hosts: etcd loses quorum and no automatic failover
  is possible. Treat it as an outage and escalate.
- No acknowledged commit is lost in synchronous mode.

## Install order

1. Generate the shared `.env` on the first app host as usual. It now also
   holds `NANO_PG_REPLICATION_PASSWORD` and `NANO_PATRONI_API_PASSWORD`.
   Copy it to every host.
2. Install the postgres hosts (any order, close together). The first postgres
   host in inventory order initialises; the others clone it.
3. Check: `exec postgres-ha patronictl -c /run/patroni/patroni.yml list` shows
   one `Leader`, one `Sync Standby`, one `Replica`, zero lag.
4. Keeper, ClickHouse, app and ingest hosts as in [multi-node-ha.md](multi-node-ha.md).

## Converting an existing single-postgres install

1. `scripts/nano backup` first.
2. Add the new postgres hosts **after** the existing one. It must stay first.
3. Re-run `install.sh` on the first app host (generates the two new secrets)
   and copy `.env` everywhere. The identity changes: every host needs
   `--accept-topology-migration <recorded sha>` (see [operate.md](operate.md)).
4. Install the existing postgres host, then immediately the two new ones
   (writes pause until etcd has quorum). The existing data directory is
   adopted in place; nothing is restored or promoted.
5. Re-run `install.sh` on every app host.

## Firewall additions

| Port | On | Allow from |
|---|---|---|
| 5432 PostgreSQL, 8008 Patroni REST | postgres hosts | the other postgres hosts and every app host |
| 2379, 2380 etcd | DCS hosts | the other DCS hosts and the postgres hosts |
| 6379 Valkey, 26379 Sentinel | postgres / DCS hosts | each other and every app host |

All are Docker-published: restrict them in `DOCKER-USER`.

## Operations

- Backup and restore run on the **leader's** host (`patronictl list`); a
  replica refuses and names the leader.
- Upgrades: `scripts/nano upgrade` rolls replicas, switches over, then rolls
  the old leader. Never recreate a leader by hand: use
  `patronictl switchover --leader <m> --candidate <m> --force` first.
- A PostgreSQL major-version change is refused. Escalate; it is a planned
  maintenance window.
- Never start the standalone `postgres` service on an HA host (it is scaled to
  zero and would share Patroni's data volume).
- A first postgres host that logs `refusing to initialise a NEW PostgreSQL
  cluster` lost its data volume while etcd lost the cluster. **Do not** set
  `NANO_PATRONI_ALLOW_REINIT`. Follow "Recovering after losing the bootstrap
  host and etcd" in the Multi-node guide: adopt the surviving member with the
  newest data (`NANO_PATRONI_ADOPT_EXISTING=true`, once), then re-run
  `install.sh` there.
- Replacing an etcd member and changing a postgres host's address (Sentinel
  state reset) are runbook steps in the same guide; ask before each command.
