# Known issues by release

Check this before installing. Prefer the newest release. If an issue below
applies, tell the operator and use the documented handling. Never patch the
product's files.

## All 2.0.x releases

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
