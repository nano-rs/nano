# Upgrade (guided)

Use this for "update nano", "upgrade to 2.0.x", "is there a new version?".
The public [Upgrade a self-hosted deployment](https://nano.rs/docs/releases/upgrading)
guide and the multi-server sections of
[High availability](https://nano.rs/docs/getting-started/high-availability#upgrade)
are the authority.

Upgrades are high-risk. Every path below is: **precheck → backup → dry run →
upgrade → verify**, and you ask before the backup, before the dry run and
before the upgrade. Never bypass a failed gate.

## 0. Plan (read-only)

```bash
# Compose role split: every host in the inventory, over SSH
python3 -I scripts/upgrade-plan.py compose --inventory ./nano-deploy-work/inventory.yaml \
  --ssh-user <user> [--ssh-config <file>] [--ssh-target name] \
  [--policy <extracted target package>/deploy/release/upgrade-policy.json]
# Compose single node
python3 -I scripts/upgrade-plan.py compose --host <user>@<host>
# Helm
python3 -I scripts/upgrade-plan.py helm --namespace nano [--release nano] [--context <ctx>]
```

It changes nothing and prints no secret (only `NANO_VERSION` and a digest of
each host's `.env`). It reads:

- the install type (single node, multi-node HA, Helm) and the version on every
  host or workload;
- the latest release (`GET https://api.nano.rs/api/releases/latest`: version,
  summary, release notes link, security flag); `--target X.Y.Z` plans for
  another release;
- the upgrade policy of the target package (`--policy`): the minimum source
  version and any required stops;
- the license state from PostgreSQL, including the "upgrade required" lock;
- health (Docker up, no restarting, failed or unhealthy containers; Helm:
  every workload ready) and free disk on Docker's data root;
- whether `.env` is byte-identical on every host;
- on HA, which host holds the PostgreSQL leader and the Valkey master.

Open the conversation with its first lines, for example: "You're on 2.0.9;
the latest is 2.0.11. What changes: <summary>. Release notes: <link>." Then
show its findings table. Any `FAIL` (exit 1, `UPGRADE-PLAN BLOCKED`) is a
blocker: fix it first (cluster-health.py names the cause; copy the newest
`.env` everywhere; free disk). Then walk through its numbered steps, which are
the ones below filled in for this install.

### The "upgrade required" lock

A v2 release before v2.0.10 sends no install ID. At its next license check-in
(once a day, and at startup) the license server answers with a locked license
that asks for an upgrade, so a v2.0.9 install can look fine for up to a day.
The lock is the license hard stop. Tell the operator exactly what it means:

- **Keeps running:** push ingest (HTTP, HEC, OTLP), search over data
  already stored, and scheduled detection rules. Local (password) admins can
  still sign in and manage the license.
- **Stops** (licensed API routes answer `403 LICENSE_REQUIRED` and licensed
  workers pause): SSO sign-in (OIDC) and identity-provider sync; pull
  collectors and agent enrichments; cases, notebooks and case grouping;
  SOAR playbook runs; AI (meloD, pivt, shadow investigation, AI provider
  settings); risk, prevalence and entity views (risk decoration also leaves
  search results); custom enrichments, integration instances, threat-intel
  and IOC lists, the marketplace preview and air-gapped imports.

The upgrade is the fix: the upgraded API checks in when it starts, and the
lock clears with that check-in.

### Rebuilding instead of upgrading

A rebuilt install (new hosts, new PostgreSQL) gets a **new install ID**. The
old ID still counts towards the license's two installs for 7 days after its
last check-in, unless support retires it sooner. Tell the operator before a
rebuild, and offer to ask support to retire the old ID.

## Path A: Compose, from v2.0.10 or later (`scripts/nano upgrade`)

> **v2.0.10 → v2.0.11:** the 2.0.11 dry run fails on every role-split cluster
> (`registry-login ... ghcr.io` and, on OCSF, `ledger-clickhouse ... not in
> target ocsf/193,ocsf/194`). Both are false positives fixed in 2.0.12. Use
> Path B for that one upgrade, or go straight to 2.0.12 with Path A
> ([known-issues.md](known-issues.md#2011-fixed-in-2012)).

**Prerequisites on a role split** (check them before the dry run; the
fresh-install flow does not set them up):

- SSH from the first app host (the coordinator) to every other host, as the
  install user, non-interactively (`ssh -o BatchMode=yes $h true`).
- Executable drain and rejoin hooks at the same absolute path on every app
  and ingest host (mandatory with more than one ingest host). The upgrade runs
  them on the host it is upgrading with that host's **inventory** name; the
  load balancer knows it as `app-1`, `ingest-1`, ... (the planner's names).
  Start from the bundle's `deploy/compose/examples/load-balancer/nano-lb-hook`
  (one file installed as `nano-lb-drain` and `nano-lb-rejoin`; edit its
  `SERVERS` map and `LBS`).
- On every HAProxy host, the runtime socket at `level admin`
  (`stats socket /run/haproxy/admin.sock mode 600 level admin`, as in the
  bundled `haproxy.cfg` from 2.0.12; `level operator` cannot drain), and an
  SSH key from each app and ingest host that may run only the drain/rejoin
  command there.

1. **Precheck:** `upgrade-plan.py` READY; `cluster-health.py` PASS on every
   role-split host; `smoke-test.py` PASS; read the release notes and
   [known-issues.md](known-issues.md).
2. **Package:** `bash scripts/fetch-bundle.sh --enrollment ./nano-deploy-work/enrollment.env --version <v>`
   must print `VERIFIED`. Put `nano-compose-enterprise-<v>.tar.gz`, `.sha256`
   and `.sha256.sig` at the same path on every host (`/srv/nano/releases/`).
   On every host, extract it over the install directory (it carries no `.env`,
   `.nano-role.env` or generated state; nothing restarts):
   `ssh $h 'tar -xzf /srv/nano/releases/nano-compose-enterprise-<v>.tar.gz --strip-components=1 -C ~/nano'`.
   Log in to the registry on every host with a fresh pull credential (about
   one hour) right before the dry run.
3. **Backup:** the upgrade takes a mandatory backup itself
   (`--backup-key-file`, and `--backup-output` on a role split). Make sure the
   key exists and the output has room (the planner's disk row).
4. **Dry run** from the first app host (single node: drop `--inventory`,
   `--remote-*` and `--backup-output`):

   ```bash
   ssh $H1 'cd ~/nano && scripts/nano upgrade --inventory /etc/nano/inventory.yaml \
     --bundle /srv/nano/releases/nano-compose-enterprise-<v>.tar.gz \
     --remote-bundle /srv/nano/releases/nano-compose-enterprise-<v>.tar.gz \
     --remote-install-dir ~/nano --backup-key-file /secure/nano-backup/operator.pem \
     --backup-output /mnt/nano-backups/upgrade-<v> --dry-run'
   ```

   With more than one ingest host behind a load balancer, add
   `--lb-drain-command` and `--lb-rejoin-command` (absolute paths on every
   ingest host). It verifies the package signature, reads the image digests,
   migration ledger and upgrade policy from inside it, and checks each host's
   control tree, registry login and image pulls (by digest), disk, NTP,
   replica lag and license. It changes nothing that runs. Every row must
   pass.
5. **Upgrade:** ask, then run the same command without `--dry-run`. It takes
   the backup and rolls Keeper → ClickHouse → PostgreSQL (replicas first, then
   a switchover, then the old leader; the Valkey master is moved off each
   PostgreSQL host before its Valkey and Sentinel restart) → migrations →
   app → ingest, one host at a time. If it stops, fix the cause (usually an
   expired registry login) and re-run with `--resume` and the same package.
   Never delete `~/nano/upgrade-journal/`. Log out of the registry after.
6. **Verify:** see [Verify every path](#verify-every-path).

## Path B: Compose, from v2.0.9 or earlier (installer rerun, host by host)

The installed `scripts/nano upgrade` predates registry upgrades, so re-run
each host's install command from the target package (v2.0.10 or later). The
target's own `scripts/nano upgrade` is used from then on.

1. **Precheck** as in Path A.
2. **Backup** first:
   single node `scripts/nano backup --key-file ... --output ...`; role split
   `scripts/nano backup-set --inventory /etc/nano/inventory.yaml --backup-key-file ... --backup-output ...`
   on the first app host ([operate.md](operate.md#backup)).
3. **Package** on every host and registry login, as in Path A.
4. **Dry run:** there is none for a rerun. `NANO_CHECK_ONLY=1 ./install.sh`
   on one host validates the inputs, edition, release and image source
   without writing or starting anything; run it on the first host.
5. **Upgrade, single node:** `cd ~/nano && NANO_IMAGES_LOCK=images.enterprise.customer.lock ./install.sh`.
6. **Upgrade, role split**, in the order the planner prints, one host at a
   time, each with its **complete** role list (the planner's layout puts
   Keeper on the PostgreSQL hosts and ingest on the ClickHouse hosts: a
   narrower `--role` leaves a service on the old release):
   1. ClickHouse hosts (with ingest: take each out of the load balancer and
      wait for the drain; put it back after `cluster-health.py` passes).
   2. **After the first host's rerun, copy its `.env` to every other host.**
      The rerun records the new `NANO_VERSION` (it prints "The shared .env
      changed on this host (NANO_VERSION)"). Stream that host's `.env`
      everywhere ([multi-node-ha.md](multi-node-ha.md) Step 5) and check that
      `sha256sum .env` matches before the next host.
   3. PostgreSQL hosts: the replicas first, the leader's host last. **A rerun
      restarts that host's Valkey and Sentinel too**, so before each one,
      check whether its Valkey is the master (the planner marks it) and move
      the master off it first:

      ```bash
      ssh $PG 'cd ~/nano && docker compose --env-file .env --env-file .nano-role.env \
        -f deploy/compose/docker-compose.enterprise.yml exec -T valkey-sentinel \
        valkey-cli --tls --insecure --cert /etc/nano/tls/server.crt --key /etc/nano/tls/server.key \
        -p 26379 SENTINEL failover nano'
      # then until it names another host:
      ...  -p 26379 SENTINEL get-master-addr-by-name nano
      ```

      From v2.0.11, the installer switches the PostgreSQL leader over to the
      synchronous standby before recreating it, and stops (recreating
      nothing) if leadership does not move within 90 s. With an older target
      installer, switch over by hand first ([postgres-ha.md](postgres-ha.md)).
   4. App hosts one at a time (drain, rerun, `cluster-health.py`, rejoin).
   5. Any remaining ingest-only hosts the same way.
7. **Verify:** see below.

## Path C: Helm

1. **Precheck:** `upgrade-plan.py helm ...` READY,
   `python3 -I scripts/k8s-health.py --namespace nano` PASS, smoke test
   against both hostnames. Read the release notes (new ClickHouse operator
   CRDs?).
2. **Backup:** `helm get values nano -n nano -o yaml` and the chart version;
   the `nano-secrets` Secret (out of band, encrypted); PostgreSQL (managed
   snapshot, or `pg_dump` from `nano-postgres-0` when bundled); ClickHouse
   (`BACKUP ... TO S3` per shard, or PVC snapshots).
3. **Pull the new chart into a fresh directory:**
   `rm -rf nano && helm pull "$CHART" --version <v> --untar`. The old
   `./nano`'s `values-customer-images.yaml` pins the old image digests.
4. **Dry run:** `helm upgrade nano ./nano -n nano -f <the SAME value files, in the SAME order> --dry-run=server`
   and review the changes. Apply new CRDs first if the release says so
   (`kubectl apply --server-side -f nano/crds/...`).
5. **Upgrade:** ask, then
   `helm upgrade nano ./nano -n nano -f <same files, same order> --wait --timeout 20m`.
   Migrations run as a pre-upgrade hook; if it fails, the previous version
   keeps serving ([helm.md](helm.md)).
6. **Verify:** below.

## Verify every path

- `upgrade-plan.py` again: every host or workload on the target version and
  "UP TO DATE"; on Compose role splits, `.env` identical on every host.
- `cluster-health.py` on every role-split host (Helm: `k8s-health.py`):
  `CLUSTER-HEALTH PASS`.
- `smoke-test.py` through the load balancer: login, license, ingest, search.
- The license row is active. A lock reading "upgrade required" clears at the
  check-in the upgraded API makes when it starts; if it is still there after
  a few minutes, restart the API once and check outbound access to
  `https://api.nano.rs`.

## What is reversible

- **Reversible:** the image swap. `scripts/nano rollback` (Compose) restores
  the previous images while the schema is unchanged; a failed `helm upgrade`
  keeps the previous version serving.
- **Not reversible:** database migrations are forward-only. Once they have
  run, `scripts/nano rollback` refuses and prints the restore commands, and
  `helm rollback` across a schema change is not supported. Going back means
  restoring the pre-upgrade backup (data written since is lost). Say this
  before the upgrade, not after.
