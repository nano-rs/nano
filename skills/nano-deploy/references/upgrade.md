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
# Helm with an external PostgreSQL (RDS, Cloud SQL, Azure): the license comes from the API
python3 -I scripts/upgrade-plan.py helm --namespace nano --creds ./admin-creds.env \
  [--app-url https://<app host>] [--ca-file <ca.crt> --resolve <app host>:<IP>]
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
- the license state from PostgreSQL, including the "upgrade required" lock
  (Helm with an external PostgreSQL: `GET /api/license` as the admin from
  `--creds`, at `--app-url` or the app HTTPRoute's hostname);
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

> **Upgrading to 2.0.12 with Path A on a role split:** the 2.0.12 upgrader
> keeps every host's old rendered configuration (`~/nano/.nano-generated/`),
> so template-only fixes (the ingest edge's OTLP 503 during a PostgreSQL
> failover, among others) never apply. After it completes, rerun each host's
> install command in the planner's order, as in Path B step 6 (full role
> list, drain app and ingest hosts first). Later upgraders re-render
> ([known-issues.md](known-issues.md#2012-fixed-after-2012)).

**Prerequisites on a role split** (check them before the dry run; the
fresh-install flow does not set them up):

- SSH from the first app host (the coordinator) to every other host, as the
  install user, non-interactively (`ssh -o BatchMode=yes $h true`).
- Executable drain and rejoin hooks at the same absolute path on every app
  and ingest host (mandatory with more than one ingest host; used on app
  hosts too when there are two or more). The upgrade runs them on the host it
  is upgrading with that host's **inventory** name; the load balancer knows it
  as `app-1`, `ingest-1`, ... (the planner's names). Start from the bundle's
  `deploy/compose/examples/load-balancer/nano-lb-hook` (one file installed as
  `nano-lb-drain` and `nano-lb-rejoin`; edit its `SERVERS` map and `LBS`). It
  runs `ssh nano-lb@<lb> /usr/local/sbin/nano-lb-haproxy set <backend>/<server> drain|ready`
  on every LB and fails unless the reply confirms the state.
- On every HAProxy host: the runtime socket at `level admin`
  (`stats socket /run/haproxy/admin.sock mode 600 level admin`, as in the
  bundled `haproxy.cfg` from 2.0.12; `level operator` cannot drain), and the
  LB side, `deploy/compose/examples/load-balancer/nano-lb-haproxy` (its
  header has the steps; ask before each, they need sudo on the LB):

  ```bash
  sudo useradd --system --create-home --shell /bin/sh nano-lb
  sudo install -m 0755 nano-lb-haproxy /usr/local/sbin/nano-lb-haproxy
  echo 'nano-lb ALL=(root) NOPASSWD: /usr/bin/socat stdio /run/haproxy/admin.sock' \
    | sudo tee /etc/sudoers.d/nano-lb && sudo chmod 0440 /etc/sudoers.d/nano-lb
  sudo visudo -cf /etc/sudoers.d/nano-lb
  ```

  Then each app and ingest host's upgrade-user key goes in
  `~nano-lb/.ssh/authorized_keys` restricted to the wrapper:
  `command="/usr/local/sbin/nano-lb-haproxy",restrict ssh-ed25519 AAAA... nano@app-1`.
  **Never make `sudo socat` the forced command** (the advice up to 2.0.12): a
  forced command replaces the hook's command and gets no stdin, so socat reads
  nothing, exits 0, and the drain silently does nothing. The wrapper accepts
  only `set <backend>/<server> drain|ready` and `state <backend>/<server>`,
  reads the state back with `show servers state`, and fails unless HAProxy
  confirms it. 2.0.12 bundles lack the wrapper and ship the old hook: take
  both files from a later bundle.
- Test the hooks by hand before the dry run, on each app and ingest host:
  `/usr/local/sbin/nano-lb-drain <inventory-name>`, then
  `ssh nano-lb@<lb> /usr/local/sbin/nano-lb-haproxy state <backend>/<server>`
  (must print `drain`), then `/usr/local/sbin/nano-lb-rejoin <inventory-name>`
  and the same `state` (must print `ready`).

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
   key exists and the output has room (the planner's disk row). On a role
   split, create the `--backup-output` folder, owned by the install user, on
   the coordinator **and on every postgres host** (and every ClickHouse host
   with `--include-clickhouse-data`):
   each component's archive is written on the host that owns it, and the
   PostgreSQL dump on whichever postgres host leads at backup time. For
   example `ssh $h 'sudo install -d -o $(id -un) -g $(id -gn) -m 0700 /mnt/nano-backups/upgrade-<v>'`
   on each of them. The dry run's `backup-output` row checks it on every
   host that writes a backup component and on the coordinator (from 2.0.14).
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
   app and ingest host). It verifies the package signature, reads the image
   digests, migration ledger and upgrade policy from inside it, and checks
   each host's control tree, registry login and image pulls (by digest), disk,
   NTP, replica lag and license. It changes nothing that runs. Every row must
   pass. From 2.0.13 it also:
   - adds a `config-render` row per host and prints a unified diff of each
     host's re-rendered configuration (key contents are never shown). Show the
     operator the diff. A refusal naming `NANO_DEPLOYMENT_ID`/`NANO_HOST_ID`
     means the inventory's identity changed: that is the installer's
     `--accept-topology-migration` runbook, not an upgrade;
   - checks the hooks (`lb-hooks` row) on every host it drains: ingest hosts
     when there are 2+, app hosts when there are 2+. With hooks configured it
     runs a real drain → rejoin round trip, one host at a time
     (`NANO_UPGRADE_LB_HOOK_TEST=0` skips it); after a failed round trip it
     drains no further host and names the one that may still be drained. An
     app host without hooks
     passes with a note that the drain relies on the LB checking `/readyz`.
5. **Upgrade:** ask, then run the same command without `--dry-run`. It takes
   the backup and rolls Keeper → ClickHouse → PostgreSQL (replicas first, then
   a switchover, then the old leader; the Valkey master is moved off each
   PostgreSQL host before its Valkey and Sentinel restart) → migrations →
   app → ingest, one host at a time, draining each app and ingest host first.
   If it stops, fix the cause (usually an expired registry login) and re-run
   with `--resume` and the same package. Never delete `~/nano/upgrade-journal/`.
   Log out of the registry after. From 2.0.13 the upgrader also:
   - re-renders each host's configuration from the bundle right after that
     host's `prepare` step (journal step `render-config:<host>`), keeps the
     old render as `~/nano/.nano-generated.previous`, and recreates every
     container whose mounted config differs from what it runs (it prints
     `note: <host>: <service> reads an outdated <path>; recreating it`);
     `scripts/nano rollback` puts the previous render back;
   - waits up to `NANO_UPGRADE_SIEM_HEALTH_WAIT_SECONDS` (600) for a SIEM
     Health report made after the rollout started (the first one runs about
     5 minutes after the API leader starts). Without one it prints a WARNING
     and records the gate as not evaluated: then read SIEM Health yourself
     a few minutes later;
   - streams its output over a plain `ssh host 'scripts/nano upgrade ...'`:
     one `==> <time> <step>: started` and `done in Ns` line per step. With
     2.0.12 and earlier it prints nothing until it exits unless run with
     `ssh -t`; follow `~/nano/upgrade-journal/*.jsonl` instead.
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
   Never `--reuse-values`: it renders with the previous chart's values and
   ignores the new chart's defaults (charts <= 2.0.12 also kept the old images;
   fixed in 2.0.13). Without the original `-f` files, use
   `--reset-then-reuse-values -f nano/values-customer-images.yaml`.
4. **Dry run:** `helm upgrade nano ./nano -n nano -f <the SAME value files, in the SAME order> --dry-run=server`
   and review the changes: every nano image must be the new version. Apply new CRDs first if the release says so
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
  the previous images (and, from 2.0.13, each host's previous rendered
  configuration) while the schema is unchanged; a failed `helm upgrade`
  keeps the previous version serving.
- **Not reversible:** database migrations are forward-only. Once they have
  run, `scripts/nano rollback` refuses and prints the restore commands, and
  `helm rollback` across a schema change is not supported. Going back means
  restoring the pre-upgrade backup (data written since is lost). Say this
  before the upgrade, not after.
