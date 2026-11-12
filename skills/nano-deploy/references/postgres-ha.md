# PostgreSQL + Valkey failover (Compose role split)

From nano 2.0.7, two or three `postgres` hosts in the inventory turn on
automatic failover for PostgreSQL (Patroni + etcd) and, with two or more app
hosts, for the shared Valkey (Sentinel). One `postgres` host renders exactly
as before. The authority is the **Multi-node Self-run** guide, section
"PostgreSQL and Valkey failover". This page is the agent procedure.

## Recommend

- **Three postgres hosts** (`roles: [postgres]`, they may also carry
  `keeper` or `clickhouse`). etcd and Sentinel run on them. A NEW install
  with three Keeper hosts that are not all postgres hosts may set
  `cluster.postgres_ha.dcs_hosts: keeper` to run them on the Keeper hosts
  instead (about 3-4 s faster failover). Never add it to an existing
  install: it is a topology change (empty etcd) that the installer refuses.
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

- Loss of the leader's postgres host: writes, sign-ins and searches fail for
  about 20-25 s (measured 20-24 s on 7-host hard-kill tests: Patroni waits for
  the dead leader's lock to expire, 20 s, its minimum `ttl`, then promotes the
  synchronous standby).
  Sign-in can return 500 rather than 503 during that window; clients should
  retry. Losing a standby, or a planned switchover, pauses writes for a few
  seconds at most. Raising
  `cluster.postgres_ha.ttl` on a slow network avoids false failovers but makes
  the pause longer. Valkey fails over in about 10 s. Logins, rules, alerting and search continue; in-flight
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
4. Record the cluster identity on the **first** postgres host. It cannot do
   so during its own install: etcd has no quorum until the second postgres
   host joins, so the cluster bootstraps only then, and its install says so.
   After the last postgres host:

   ```bash
   ssh $PG1 'cd ~/nano && ./install.sh --record-pg-ha-identity'
   ```

   It reads the identity from that host's member and writes
   `NANO_PG_HA_SYSTEM_ID` to its `.env`. It renders, pulls and restarts
   nothing, so it never recreates the leader. It prints "The shared .env
   changed on this host (NANO_PG_HA_SYSTEM_ID)". The other postgres hosts may
   already have recorded the same line in the same place; they print that the
   first postgres host records it with this command.
5. Stream **the first postgres host's** `.env` to every other host, the first
   app host included ([multi-node-ha.md](multi-node-ha.md) Step 5, with that
   host as the source), before any other installer run, and check the digests
   match. From then on, the first app host's copy is current again.
   `plan.py --install-order` prints steps 4 and 5 in place.
6. Keeper, ClickHouse, app and ingest hosts as in [multi-node-ha.md](multi-node-ha.md).

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

All are Docker-published, so UFW does not see them: restrict them in
`DOCKER-USER` before the first install
([multi-node-ha.md](multi-node-ha.md#firewall); `plan.py --firewall-script`
prints the rules).

## Operations

- Backup and restore run on the **leader's** host (`patronictl list`); a
  replica refuses and names the leader.
- Upgrades: `scripts/nano upgrade` rolls replicas, switches over, then rolls
  the old leader ([upgrade.md](upgrade.md)). From v2.0.11, an `install.sh`
  rerun on the leader's host switches over to the synchronous standby before
  recreating it, and stops (recreating nothing) if leadership does not move
  within 90 s. With no healthy streaming standby (`alone`, it warns), it
  recreates the leader without a switchover: Patroni fails over to another
  member if one is eligible (about 20-25 s of failed writes), otherwise
  writes pause until the member is back. Fix the standbys first. A rerun also restarts that host's Valkey and Sentinel: move
  the Valkey master off it first. Never recreate a leader by hand: switch
  over first, run
  **on the leader's host**, inside the container, with the Patroni config:

  ```bash
  ssh $PG 'cd ~/nano && docker compose --env-file .env --env-file .nano-role.env \
    -f deploy/compose/docker-compose.enterprise.yml exec -T postgres-ha \
    patronictl -c /run/patroni/patroni.yml list'
  # candidate = the member whose Role is "Sync Standby" (synchronous mode is on
  # by default); any other replica is refused with
  # "412, candidate name does not match with sync_standby"
  ssh $PG 'cd ~/nano && docker compose --env-file .env --env-file .nano-role.env \
    -f deploy/compose/docker-compose.enterprise.yml exec -T postgres-ha \
    patronictl -c /run/patroni/patroni.yml switchover --leader <leader> --candidate <sync standby> --force'
  ```

  `patronictl` exits 0 even when it refuses the switchover, so never chain the
  recreate on its exit code. Run `list` again and recreate the old leader only
  once the candidate shows `Leader` / `running`. Without `-c` it fails with
  "Can not find suitable configuration of distributed configuration store". A
  planned switchover pauses writes for a few seconds; an unplanned leader loss
  (hard kill) takes about 20-25 s before a new leader serves writes.
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
