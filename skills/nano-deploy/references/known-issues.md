# Known issues by release

Check this before installing. Prefer the newest release. If an issue below
applies, tell the operator and use the documented handling. Never patch the
product's files.

## All 2.0.x releases

- **Sign-in rate limit.** nano allows 100 sign-in requests per client
  address in a 5-minute window, successful or not; after that
  `POST /api/auth/login` answers `429 Too many login attempts` with
  `Retry-After` (up to 300 s). A probe that signed in every second hit it.
  Synthetic sign-in monitors and failover probes must stay below it (one
  sign-in every 10 s is fine), or authenticate with an API key instead.

- **OTLP/HTTP is binary protobuf only.** `/otlp/v1/{logs,traces,metrics}`
  answers `415` ("protobuf only") to OTLP/JSON. Senders must use
  `http/protobuf` (the OpenTelemetry SDK and Collector default); a sender set
  to `http/json` needs changing, not a nano fix.

- **TLS overlay during first install.** With `docker-compose.tls.yml` active,
  plain-HTTP `localhost` calls get a 301 redirect, and the installer's health
  and admin-creation calls can treat it as success. Install first without the
  overlay, confirm the admin exists (`smoke-test.py` login passes), then
  enable the overlay ([single-node.md](single-node.md#step-9-public-tls)).
- **The installer needs the admin variables on every app-role run until setup
  is complete.** The prepare step writes `.env`, so the following install is a
  re-run. Pass `NANO_ADMIN_EMAIL`, `NANO_ADMIN_NAME` and `NANO_ADMIN_PASSWORD`
  again (the skill sources `~/.nano-admin-credentials`). Once setup is
  initialized, later runs skip admin creation.
- **From 2.0.8, first-admin setup needs the setup token.** `install.sh`
  generates `NANO_SETUP_TOKEN` into `.env` (on the app host; it travels with
  the shared `.env`) and sends it itself. Helm generates `setup_token` in the
  chart secret. Only the web setup page after an interrupted install asks for
  it. Installs that already have an admin are unaffected.
- **Role split: `cluster.deployment_id` becomes `NANO_DEPLOYMENT_ID`.** The
  renderer writes the inventory's `deployment_id` into `.nano-role.env`,
  which overrides `.env`. Set it to the app.nano.rs deployment ID, or license
  check-in uses the wrong ID.
- **Upgrade dry run and online licenses.** In 2.0.x, `scripts/nano upgrade
  --dry-run` can refuse an install licensed online and report `C05 license
  state is missing or expired`. Contact nano support before you upgrade. Do
  not bypass the check.
- **Role split: log-source deploy reports failure although it worked.** The
  app host has no local Vector, so `POST /api/log-sources/{id}/deploy` can
  answer `success=false` with "No reload was delivered to Vector", while the
  new configuration generation is still delivered to every ingest host (the
  ingest hosts' `vector-config-consumer` logs `Installed Vector config
  generation N`). Judge it by ingest followed by search, as `smoke-test.py`
  does. Do not "fix" it by adding ingest to the app host.
- **Small role-split hosts can saturate ClickHouse.** On 4 GB lab hosts the
  replica that serves the app hit `TOO_MANY_SIMULTANEOUS_QUERIES` (code 202),
  and `system.replicas` stopped answering. Size the hosts properly. The
  recovery is to re-run that host's role command, which recreates its
  containers.
- **Ingest stops when the app host is down (role split).** The ingest nodes'
  `/healthz` returns 503 about 15 seconds after the app API is unreachable.
  Make sure senders buffer and retry. With several app hosts, each ingest
  host's `app-api-proxy` fails over to another app host, so losing one app
  host no longer stops ingest; losing all of them still does.
- **Docker-published ports bypass UFW.** Role-split hosts publish app,
  ingest, PostgreSQL, Patroni, etcd, Valkey and Sentinel ports through Docker.
  On a host with a public address and only UFW, they are reachable from the
  internet. Apply the `DOCKER-USER` rules before the first install
  ([multi-node-ha.md](multi-node-ha.md#firewall)) and prove it with
  `preflight.sh --exposure-probe`. Don't use the inventory's `bind_address`
  as the fix: the installer health-checks the edges on `localhost`.
- **Docker in LXC containers** (Proxmox CT and similar) needs `nesting=1`
  (and usually `keyctl=1`) on the container. It is fine for labs. Use VMs in
  production.

## 2.0.23 and earlier, single node (fixed after 2.0.23)

- **`scripts/nano upgrade` always fails preflight on a single-node install**
  (open or enterprise), dry run and real run alike: `FAIL single
  runtime-config command failed (exit 78): docker compose exec`, then
  `nano: preflight failed; no installation state was changed`. The check
  validated Vector's config without the interpolation flag the running
  Vector uses, so the shipped `${VAR:-default}` values read as a TOML error.
  Nothing is wrong with the install or the new config. Role splits are not
  affected. The upgrader that runs is the one in the extracted target
  bundle, so a target release with the fix upgrades normally with Path A.
  **Handling** for a target of 2.0.23 or earlier: take a backup
  (`scripts/nano backup --key-file ... --output ...`), then upgrade with the
  installer rerun from the extracted bundle (Path B, single node:
  `cd ~/nano && NANO_IMAGES_LOCK=images.enterprise.customer.lock ./install.sh`;
  open installs drop `NANO_IMAGES_LOCK`). Do not skip or edit the check.

## 2.0.13 (fixed in 2.0.14)

- **The upgrade's backup fails on a postgres host without the
  `--backup-output` folder**, after a passing dry run: `host vm-7 backup
  failed: mkdir: cannot create directory '/mnt/nano-backups': Permission
  denied` at `backup:consistent-set`. **Handling:** create the folder, owned
  by the install user, on every postgres host (and every ClickHouse host with
  `--include-clickhouse-data`) (see
  [upgrade.md](upgrade.md) Path A step 3), then `scripts/nano upgrade
  --resume`.
- **The dry run prints nothing for 2.5 to 4.5 minutes** over plain ssh (the
  preflight result table arrives at the end). The upgrade steps themselves
  stream. **Handling:** wait, or follow the journal. From 2.0.14 every
  preflight phase prints a `==> … preflight checks on <host>: started` /
  `done in Ns (P/T PASS)` line as it happens.
- **The upgrade moves `NANO_VERSION` to the end of `.env`** and drops an
  operator's duplicate key line (keeping the value in effect) without saying
  so. Nothing breaks. From 2.0.14 keys stay on their line and collapsed keys
  are named.

## 2.0.12 (fixed in 2.0.13)

- **`scripts/nano upgrade` keeps every host's old rendered configuration**
  on a role split. `~/nano/.nano-generated/` keeps the earlier install's
  files, and containers whose image did not change are not recreated. So
  fixes that live only in templates never apply: after a 2.0.11 → 2.0.12
  upgrade the ingest edge still answers OTLP **500** (not 503) during a
  PostgreSQL failover, and the 2.0.12 monitoring exporters may lack their
  config. **Handling:** after the upgrade, rerun each host's install command
  in the planner's order, as in
  [upgrade.md](upgrade.md#path-b-compose-from-v209-or-earlier-installer-rerun-host-by-host)
  step 6 (complete role list, drain app and ingest hosts first). Each rerun
  re-renders and recreates. Later upgraders re-render each host from the
  bundle themselves and recreate every container whose mounted config
  changed.
- **After an app host reboots, its `app-internal-edge` can proxy to the wrong
  container.** nginx resolved `nano-api` once at start, so it keeps the old
  container IP. The ingest hosts' `app-api-proxy` then marks that app host
  DOWN, and OTLP auth and ingest admission run on the other app hosts only.
  Nothing user-facing shows it (`/readyz` 200, nano-api healthy), and SIEM
  Health cannot see it (it has no container view). **Handling:** after any
  app host reboot, run `scripts/nano cluster-health` (or
  [cluster-health.py](../scripts/cluster-health.py)) on each ingest host; if
  `gw:app-api-proxy` fails for that app host, run
  `docker restart <project>-app-internal-edge-1` on the app host
  (`docker ps --filter name=app-internal-edge`). Later releases resolve
  container names through Docker's DNS at request time, and cluster-health
  has an `edge:internal` row on app hosts that FAILs with the restart command.
- **The load-balancer hook's forced-command advice does not work.** The
  2.0.12 hook and docs say to restrict the LB key with a forced command
  running `sudo socat`. A forced command replaces the hook's command and gets
  no stdin, so socat reads nothing and the drain silently does nothing.
  **Handling:** use the `nano-lb-haproxy` wrapper as the forced command, with
  the matching hook ([upgrade.md](upgrade.md#path-a-compose-from-v2010-or-later-scriptsnano-upgrade)
  prerequisites), and test a drain by hand.
- **The dry run's `lb-hooks` row covers ingest hosts only**, and only checks
  that the hooks are executable. The upgrade also drains app hosts. Test the
  hooks by hand on every app and ingest host. Later dry runs check every
  drained host with a live round trip.
- **The post-upgrade SIEM Health gate can compare the old report with
  itself** (no new report runs until about 5 minutes after the API leader
  starts). Read SIEM Health yourself about 10 minutes after the upgrade.
- **`scripts/nano upgrade` prints nothing until it exits** over a plain
  `ssh host '...'` (no TTY). Use `ssh -t`, or follow
  `~/nano/upgrade-journal/*.jsonl` on the coordinator.

## 2.0.11 (fixed in 2.0.12)

- **`scripts/nano upgrade` from v2.0.10 to v2.0.11 fails its dry run** on
  every role-split cluster, with two false positives (nothing is wrong with the
  cluster, and nothing was changed):
  - `registry-login ... not logged in to ghcr.io` on every host. The check
    treated any image under `nano-rs` as private, including the public
    `ghcr.io/nano-rs/vector`, which pulls anonymously; the license only issues
    a credential for the customer registry, so there is no ghcr.io login to
    give.
  - `ledger-clickhouse ... not in target ocsf/193,ocsf/194` on OCSF installs.
    The 2.0.11 upgrader's list of OCSF ClickHouse migrations stopped at
    `ocsf/190`, while 2.0.10 applies 193 and 194. The 2.0.11 migrator itself
    accepts the database.

  **Handling for v2.0.10 → v2.0.11:** upgrade with Path B instead (rerun each
  host's install command from the 2.0.11 package, host by host, with the
  load-balancer drain and rejoin by hand) ([upgrade.md](upgrade.md#path-b-compose-from-v209-or-earlier-installer-rerun-host-by-host)).
  Never bypass a preflight row or edit `scripts/nano-upgrade.py`. Or skip
  2.0.11: 2.0.12 upgrades a v2.0.10 or v2.0.11 cluster with Path A (extract
  the 2.0.12 package over `~/nano` first, as Path A says; its own upgrader
  runs). A v2.0.11 cluster upgrading to 2.0.12 with Path A is not affected.
- **First app host's migrator can hang on a fresh install** at "Applying
  open-init snapshot" (no CPU, PostgreSQL sessions idle, no tables), holding
  the installer at "clickhouse-migrate Waiting". Seen once, about two minutes
  after the PostgreSQL HA cluster formed; a rerun applied the snapshot in
  seconds. Interrupt the install after 5 minutes without progress (Ctrl-C;
  the snapshot is one transaction, so nothing is half-applied), check
  `patronictl list` on a postgres host (one Leader, one streaming Sync
  Standby), and rerun the same install command on that host. 2.0.12 bounds
  the snapshot (`NANO_PG_SNAPSHOT_TIMEOUT_SECS`, default 600 s), refuses it up
  front while no synchronous standby is streaming, ends a stuck session, and
  bounds the installer's wait for the services (`NANO_COMPOSE_UP_TIMEOUT`,
  default 3600 s).
- **The installer does not install the data-disk self-heal timer.** Install it
  per host as in [cloud-vm.md](cloud-vm.md) step 5. From 2.0.12 the installer
  installs it on a host whose Docker data is on a separate `nofail` disk
  (with passwordless sudo; otherwise it prints the one command to run).
- **The `--record-pg-ha-identity` message says `sudo ./install.sh`.** Run it
  as the install user, without sudo: `cd ~/nano && ./install.sh --record-pg-ha-identity`.
- **`support-bundle` reports `install_id: null`** although the install has
  one (it read psql's "(1 row)" footer). Read it with `GET /api/license`
  or from PostgreSQL if support asks. It also collects only the local host
  unless the host it runs on can SSH to every other host (see
  [operate.md](operate.md)).
- **OTLP senders saw a 500 or a stall while an app host was upgraded** (HEC
  did not): the ingest edge's OTLP auth check asks an app host and was not
  retried on another one. Make OTLP senders retry on 5xx and timeouts. 2.0.12
  retries that read-only check on another app host.
- **Helm: OTLP writes failed with HTTP 500 during a PostgreSQL failover.** On
  AKS, a forced failover of zone-redundant Azure flexible server made both api
  pods unready for about 48 s. The ingest edge's OTLP auth check then failed,
  and nginx answered OTLP requests with 500 (which OTLP exporters drop, unlike
  503) or a 15 s stall. HEC and `/ingest` were not affected (their admission
  check admits when the API is unreachable). Tell the operator to buffer OTLP
  in a collector with retry on all 5xx. From 2.0.12 every edge answers 503 with
  `Retry-After: 5` when the check can't be made, and the Helm edge bounds the
  check (1 s connect, 4 s read) and retries it once, so senders get an answer
  within 10 s. OTLP still pauses for the failover; nothing accepted is lost.
- **Azure flexible server, PostgreSQL 15+: the first migration fails with
  `permission denied for schema public`** although `pg-preflight.py` printed
  `POSTGRES-READY` and the migrator's preflight passed. In new databases there,
  schema `public` is owned by `azure_pg_admin`, so the database owner can't
  create tables in it. Fix, as the server admin, connected to the nano
  database: `ALTER SCHEMA public OWNER TO nanosiem;` (or `GRANT ALL ON SCHEMA
  public TO nanosiem;`), then delete the failed migrate pods and rerun the same
  `helm upgrade --install` (the snapshot is one transaction; nothing to clean
  up). The bootstrap SQL in [cloud-azure.md](cloud-azure.md#managed-postgresql-azure-flexible-server)
  does it up front. From 2.0.12 both preflights check `CREATE` on `public` and
  print this fix.
- **Helm: `k8s-health.py` stays UNHEALTHY with `distributed DDL entries
  pending > 10 min` after a ClickHouse pod restart.** An `ON CLUSTER`
  statement issued while a replica restarted can stay `Inactive` on that
  replica for good, although the replica runs every later entry and nothing
  diverged. Tell stuck from stale: `SELECT entry, host, status, query FROM
  system.distributed_ddl_queue WHERE status != 'Finished'`. If that host shows
  a later entry `Finished`, the old one is stale and harmless; ClickHouse
  removes it after `distributed_ddl.task_max_lifetime` (7 days). Don't delete
  Keeper nodes by hand. From 2.0.12 `k8s-health.py` and `cluster-health.py`
  only warn on stale entries and still fail on a stuck one.
- **Events written in the second a ClickHouse replica is deleted can be stored
  twice.** In an AKS drill, 150 HEC and 150 OTLP events sent during a pod
  delete were all accepted, and 10 of each were stored twice (same
  `metadata.uid`). Delivery from the ingest buffer to ClickHouse is
  at-least-once: a batch whose acknowledgement was lost is retried. Counts and
  detections over that minute can be inflated; `dc(metadata.uid)` gives the
  true count. Tell the operator; no repair is needed.

## External PostgreSQL, 2.0.10 and earlier (fixed in 2.0.11)

Found on Cloud SQL and Azure flexible server with the Helm chart; applies to
any external PostgreSQL. Run `scripts/pg-preflight.py` before installing.

- **PostgreSQL 16 fails the first migration** (`unrecognized configuration
  parameter "transaction_timeout"`; every app pod stays in `Init:Error`). Cloud
  SQL and RDS may default to 16, depending on when and how the instance was
  created; check the version (`SHOW server_version`). On 2.0.10 and earlier use
  PostgreSQL 17+. 2.0.11 supports 16 and up.
- **`NANOSIEM_MIGRATION_MODE=legacy` on a fresh PostgreSQL 16 still fails** with
  the same `transaction_timeout` error, in every release: the legacy path
  replays `001_init_postgres.sql`, whose bare `SET` cannot change (its checksum
  is recorded on existing installs). Never set legacy mode for a fresh install;
  the default (auto) uses the fixed snapshot.
- **Upgrading an install that runs on PostgreSQL 15 (or older) to 2.0.11.**
  The 2.0.11 migrator refuses PostgreSQL below 16 before it changes anything,
  so the upgrade's migration fails and the previous version keeps running.
  Upgrade the database to 16+ first (RDS / Cloud SQL / Azure major-version
  upgrade, after a snapshot), then upgrade nano. Check before the upgrade with
  `scripts/pg-preflight.py`.
- **Azure flexible server: `extension "pg_trgm" is not allow-listed`** (then
  `pgcrypto`). Set the `azure.extensions` server parameter to include
  `pg_trgm,pgcrypto,uuid-ossp` ([cloud-azure.md](cloud-azure.md#managed-postgresql-azure-flexible-server)),
  then rerun the same `helm upgrade --install`. The failed snapshot is rolled
  back as a whole, so no database cleanup is needed. 2.0.11 checks this first
  and names every missing extension with the fix.

## 2.0.10 and earlier (fixed in 2.0.11)

- **PostgreSQL HA identity recorded on the wrong host.** On a fresh install
  with three postgres hosts, `NANO_PG_HA_SYSTEM_ID` was recorded by a later
  postgres host (usually the third) while its message said to copy the first
  host's `.env`, which lacked the value. Copying that `.env` would have dropped
  the identity everywhere. 2.0.11 adds `./install.sh --record-pg-ha-identity`
  for the first postgres host ([postgres-ha.md](postgres-ha.md)). On 2.0.10,
  copy the `.env` of the host that printed "Recorded the PostgreSQL cluster
  identity", and never rerun the first postgres host's full install to record
  it: that recreates the leader.
- **Data disk not mounted after a hard reset.** The by-UUID link can be
  missing at boot; Docker then stays stopped (correctly) until someone mounts
  the disk. Add the self-heal timer ([cloud-vm.md](cloud-vm.md), step 5).
- **`cluster-health.py` printed PASS with Docker stopped** (two `WARN` rows)
  and reported one etcd member down as "healthy 0/0". Use the 2.0.11 skill.
- **`plan.py --firewall-script` opened 443 to every source** on HAProxy hosts.
  Regenerate it with `--edge-source-cidr` and run it again on the HAProxy
  hosts. The regenerated script first removes the old rule
  (`sudo ufw delete allow 443/tcp`, which drops its IPv4 and IPv6 forms);
  check that `sudo ufw status | grep 443` lists only the scoped sources and
  no `Anywhere` or `Anywhere (v6)` row (remove a leftover with
  `sudo ufw status numbered` and `sudo ufw delete <number>`).
- **A v2.0.8 `.env` can hold two `NANO_LICENSE_MODE` lines.** The 2.0.11
  installer and `scripts/nano upgrade` collapse them to the value in effect.

## Helm chart 2.0.10 (fixed in 2.0.11)

- **`helm install --wait` fails with "Progress deadline exceeded"** on
  `nano-api` or `nano-vector` when the first migration takes ~10 minutes
  (remote or slow managed PostgreSQL, extension retries). The pods become Ready
  later; nothing is lost. Wait for `job/nano-migrate-r1` to complete, then run
  the same `helm upgrade --install` again. If that reports the same error on
  `nano-vector` although its pods are Ready, run
  `kubectl -n nano rollout restart deployment/nano-vector` and the upgrade once
  more. 2.0.11 raises the deadline to 30 minutes
  (`migrations.dependentProgressDeadlineSeconds`) and re-rolls a Deployment
  stuck on it by itself.
- **Cloud presets pin the ingest edge to 1 replica**: with `values-aws.yaml`,
  `values-azure.yaml`, `values-gke.yaml` or `values-sovereign.yaml` layered
  AFTER the HA file, the HA file's `ingest.edge.replicas: 2` is lost. Layer the
  HA file after the cloud preset. 2.0.11 presets no longer set replica counts.
- **`nano-api` logs "Failed to deploy Vector pipeline configs ... docker
  unavailable"** on Kubernetes while ingest works: misleading, ignore it.
  2.0.11 sets `NANO_VECTOR_LOCAL_RELOAD=off` and no longer tries.
- **`GET /api/license` reports `mode: hosted` on a Self-run install.** That
  field is how the license is verified (online against nano's license
  service), not the deployment type; the operator is `entitlement.operator`.
- **Vector's internal OTLP and native ports accept unauthenticated traffic
  from any pod** when the CNI does not enforce NetworkPolicy (GKE Standard
  without Dataplane V2, EKS VPC CNI without its network policy agent, AKS
  without `--network-policy`). Enable NetworkPolicy enforcement.

## Helm chart 2.0.9 and earlier (fixed in 2.0.10)

Found on EKS (AL2023, AWS Load Balancer Controller). Install 2.0.10 or later;
on an older chart use the handling here and report it to the operator.

- **`values-small.yaml` crash-loops ClickHouse 26.10** (exit 36,
  `number_of_free_entries_in_pool_to_execute_mutation ... > 8*2`). Add
  `clickhouse.server.background_pool_size: "16"`. If ClickHouse is already
  crash-looping, `helm upgrade` cannot deliver the fix (the migration hook
  waits for ClickHouse first): patch the ClickHouseCluster
  (`kubectl -n nano patch clickhousecluster nano --type merge -p
  '{"spec":{"settings":{"extraConfig":{"background_pool_size":"16"}}}}'`), wait
  for the pods, then rerun the upgrade. 2.0.10 refuses such values at render
  time and heals a down ClickHouse from a pre-upgrade hook.
- **`clickhouse.replicas: 2` never finishes migrating** ("database visible on
  2/4 nodes", blaming a replica that is up). The ClickHouse operator's database
  sync makes database `default` a Replicated database, which lists the
  `default` cluster twice. No values workaround; use 2.0.10 (its migrator
  counts only the configured cluster).
- **Vector never becomes ready** (Permission denied on
  `/etc/vector/runtime/current/...`, exit 78, the config consumer rolls back).
  Vector ran as root without capabilities and cannot read the consumer's
  0600 files. Use 2.0.10 (both run as uid 100).
- **AWS: "TargetGroup port is empty".** Install the AWS Load Balancer
  Controller with `--set defaultTargetType=ip`. 2.0.10 renders ip-target
  TargetGroupConfigurations.
- **`smoke-test.py` fails `ingest-hz`** (`/healthz` 404 on the ingest host):
  the ingest Gateway did not route it. Treat it as a WARN when every ingest
  check passes; 2.0.10 routes it.
- **Pods rescheduled after an hour fail with ImagePullBackOff.** The pull
  credential expired. Recreate `nano-registry` with a fresh credential; 2.0.10
  refreshes it with a CronJob.

## 2.0.0

- **Role split: `ingest` on the `app` host deadlocks the install.** On a host
  with both roles, the ingest Vector service re-owned the shared
  `vector-dynamic` volume that `nano-api` writes, so the API never published a
  Vector configuration and the install aborted before admin creation. Fixed in
  2.0.1: the API now has its own volume. On 2.0.4 and later both roles may
  share a host, although the standard layouts keep them apart.
- **Single node: the license never checks in.** The 2.0.0 single-node compose
  does not pass `LICENSE_URL` and `LICENSE_TOKEN` to `nano-api` and
  `nano-jobs`, so the enrollment values in `.env` have no effect. Fixed after
  2.0.0. Use 2.0.4 or newer for a licensed single node. If the operator must
  run 2.0.0, install it, report "license not active (2.0.0 single-node
  issue)", and plan the upgrade. Do not hand-edit compose files.
- **"Active" without a license.** With no `LICENSE_URL` reaching the API,
  2.0.0 logs `License enforcement not configured (LICENSE_URL not set)` and
  `/api/license` reports `state=active valid=true` with no entitlement,
  expiry or license ID. That is not a license. `smoke-test.py` reports it as
  `WARN ... NO LICENSE BOUND`. Report it as unlicensed.
- **Fresh installs run under `umask 077`.** The 2.0.0 installer sets a
  restrictive umask before it generates non-secret configuration. Installs
  from a root-owned clone or checkout can leave ClickHouse restarting with
  exit code 233 (cannot read its config). The path in this skill (a non-root
  user, an extracted bundle) was validated on 2.0.0 without hitting it. It is
  fixed after 2.0.0. If it happens, stop and report it with `docker logs` of
  the ClickHouse container. Do not `chmod` product directories to work around
  it without nano support's guidance.
- **Enrichment memory on small hosts.** On a 12 GiB host, 2.0.0 sized
  ClickHouse to `6084M`, just under the 6 GB the enrichment dictionaries need.
  Ask the operator whether to set `CLICKHOUSE_MEM_LIMIT=6G` in `.env` and
  re-run the installer, or to turn the feeds off
  (`PLATFORM_FEEDS_AUTO_UPDATE=false`).
- **Kubernetes chart 2.0.0** takes the deployment ID through
  `nano.extraEnv` (`NANO_DEPLOYMENT_ID`), not `nano.deploymentId`.
  `scripts/helm-values.py` detects this from `helm show values`.

## Reporting a new issue

Collect a support bundle ([operate.md](operate.md#support-bundle)). Note the
exact command, its last 40 lines of output, the release and the time with
timezone, and stop. Add nothing to this file from guesswork. Only issues nano
has confirmed belong here.
