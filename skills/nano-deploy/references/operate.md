# Operate (day 2)

Every operation here starts with a read-only check, shows the plan, and asks.
Upgrades and restores are high-risk. Back up first, and dry-run first.

The tool for Compose installs is `scripts/nano` inside the installed bundle
(`~/nano/scripts/nano`). Run it as the install owner, never with `sudo`. Its
key and `.env` checks require files owned by the current user with mode `0600`.

## Backup operator key (once)

The backup key encrypts and signs every backup. It lives **off** the nano hosts
and away from the backup destination. Anyone holding it can decrypt the
backups, and losing it makes them unrecoverable.

```bash
ssh $H 'sudo install -d -m 0700 -o "$(id -un)" -g "$(id -gn)" /secure/nano-backup &&
  ~/nano/scripts/nano backup-keygen --output /secure/nano-backup/operator.pem'
```

Then ask the operator to copy it to their secret manager, for example with
`scp` from the host to a path they choose. A role-split backup needs the key
at the same absolute path on the app host, the PostgreSQL host and replica 1
of every shard.

## Backup

Single node:

```bash
ssh $H 'cd ~/nano && scripts/nano backup --key-file /secure/nano-backup/operator.pem \
  --output /mnt/backup/nano-$(date -u +%Y%m%dT%H%M%SZ) --keep 14'
```

Role split (run on the app host; does not stop ingest):

```bash
ssh $H1 'cd ~/nano && scripts/nano backup-set --inventory /etc/nano/inventory.yaml \
  --backup-key-file /secure/nano-backup/operator.pem \
  --backup-output /mnt/backup/nano-$(date -u +%Y%m%dT%H%M%SZ)'
```

Tell the operator what a role-split backup pauses (by design, for one
consistent PostgreSQL + ClickHouse recovery set): ingest, search, dashboards
and sign-in keep working, but `nano-jobs` (scheduled and real-time detections,
alerting) and `connector-runner` stop on every app host, and API writes
(acknowledging an alert, editing a case or rule) return 503 "temporarily
paused for a consistent backup". The output reports the pause as
`writers_down_ms`; a 7-host test measured about 86 s. It grows with the number
of app hosts and the size of lookup tables, not with event volume. Nothing is
lost: scheduled rules resume from their last completed window and scan the
paused interval (a rule with a custom lookback shorter than its interval plus
the pause rescans only that lookback), and real-time signals become alerts from their saved
position, so alerts are delayed. Schedule backups for a quiet period, and have
API automation retry on 503.

A backup left on the same host is not disaster recovery. Copy it off-host.
Offer to schedule it (systemd timer or cron as the install owner) and to alert
on a non-zero exit. Never wrap backup automation in `set -x`.

## Restore drill

Only on a **fresh, isolated** install of the same or a newer release and the
same edition, never over production. A restore onto a fresh install needs
`--force` because the bootstrap admin exists. Explain this before asking.

```bash
scripts/nano restore --key-file /secure/nano-backup/operator.pem --from /mnt/backup/<dir> --force
```

For role split: start a fresh Keeper quorum and the data roles only. Restore
PostgreSQL first, then replica 1 of each shard, each with the same
`--recovery-set <dir>/recovery-set`. Then start the app and ingest roles. Verify
behaviour afterwards: search known events, sign in as a restored user, and use
a stored credential. A health check alone is not enough.

## Upgrade

Moved to [upgrade.md](upgrade.md): the guided flow starts read-only with
`scripts/upgrade-plan.py` (current and latest version, blockers, the ordered
steps for this install) and covers the three paths: Compose from v2.0.10 or
later (`scripts/nano upgrade`), Compose from v2.0.9 or earlier (installer
rerun host by host), and Helm.

`scripts/nano rollback` works only while the schema is unchanged. Otherwise it
refuses and prints the exact restore commands. Explain that before anyone
runs a restore.

## Add a node

- **Add an ingest host:** no data moves, but every host `id`/`name` is part
  of the recorded durable-topology identity (`NANO_DEPLOYMENT_IDENTITY_SHA256`
  in `.env`, computed by `render-inventory.py --identity-only`), so the first
  rerun after the change is refused until it is acknowledged. Order matters:
  1. Add a `hosts[]` entry with a new `name`, `id` and `address` and
     `roles: [ingest]`. Install the updated inventory at
     `/etc/nano/inventory.yaml` on every host, including the new one. The
     private TLS cert must cover the new address (reissue from the same CA and
     stage it on every host first if it does not).
  2. Rerun the app host with its full role list. It refuses with
     `Inventory durable topology identity changed. Existing identity is <old>;
     candidate identity is <new>. ... --accept-topology-migration <old>` and
     changes nothing. Read back the recorded value
     (`ssh $H1 'grep ^NANO_DEPLOYMENT_IDENTITY_SHA256= ~/nano/.env'`), confirm
     it equals `<old>`, tell the operator this acknowledges an ingest-only
     change, get their "yes" (SKILL.md rule 4), then rerun with that exact
     `<old>` SHA (lowercase, 64 hex, the *existing* identity, not the
     candidate):
     ```bash
     ssh $H1 'cd ~/nano && NANO_HOST_NAME=nano-1 NANO_IMAGES_LOCK=images.enterprise.customer.lock \
       ./install.sh --role app,postgres,keeper --inventory /etc/nano/inventory.yaml \
       --accept-topology-migration <old>'
     ```
     This records `<new>` in nano-1's `.env` and regenerates the app's ingest
     gateway to include the new host.
  3. Redistribute nano-1's `~/nano/.env` to every host, including the new one,
     exactly as in Step 5 of [multi-node-ha.md](multi-node-ha.md). Do this
     before any other host reruns: a host still holding `<old>` is refused the
     same way.
  4. On the new host: unpack the bundle, registry login, stage TLS, then
     `NANO_HOST_NAME=<new name> NANO_IMAGES_LOCK=images.enterprise.customer.lock ./install.sh --role ingest --inventory /etc/nano/inventory.yaml`
     **without** the flag (its `.env` already records `<new>`; passing the
     flag when nothing changed fails with "Remove the stale acknowledgement
     flag"). Other existing hosts rerun without the flag too.
  5. Open the ingest ports and add it to the load balancer after `/healthz`
     returns 200.
- **Add a ClickHouse replica or shard, or change Keeper membership:** this
  changes the durable topology. The installer refuses until
  `--accept-topology-migration <current sha>` is given, and that flag only
  acknowledges a data-movement runbook. It does not move data. Stop and ask
  nano support for the runbook. Do not improvise.
- **Single node to 3-node HA:** this is a migration, not an "add". Use a backup
  and restore into a new role-split deployment with nano support.

## Rotate certificates

**Public TLS, bundled nginx (single node):** replace
`~/nano/config/nginx/ssl/fullchain.pem` and `privkey.pem` (key `0600`), then
`docker compose -f docker-compose.opensource.yml -f docker-compose.tls.yml up -d --force-recreate nginx`.
Check the new expiry with
`openssl s_client -connect APP_FQDN:443 -servername APP_FQDN </dev/null 2>/dev/null | openssl x509 -noout -enddate`.

**Public TLS at the load balancer:** rotate it there. nano is unaffected.

**Private cluster TLS (role split):** issue the new server certificate from the
**same CA**, with the same SANs and serverAuth + clientAuth. Then, host by host
in the upgrade order (Keeper/ClickHouse hosts, then app, then ingest): put the
files in `/root/nano-pki/`, re-run `sudo scripts/nano-tls-stage ...` with the
same `--output`, and re-run that host's `install.sh` role command. That
republishes the generated TLS tree and recreates the host's containers. Run
`cluster-health.py` after each host. Changing the **CA** is a coordinated
change that briefly breaks trust between hosts. Plan it with nano support.

## Support bundle

Every install ships `scripts/nano support-bundle` (v2.0.11 and later). Run it
on any one host; on a role split it collects every inventory host over SSH.
That needs SSH trust from the host it runs on to every other host (the
install user's key, non-interactive: `ssh -o BatchMode=yes <address> true`),
which a fresh install does not set up. Without it the archive holds only the
local host and `MANIFEST.json` lists each other host with `Permission denied
(publickey)`; run it from the first app host after the
[upgrade prerequisites](upgrade.md#path-a-compose-from-v2010-or-later-scriptsnano-upgrade)
are in place, or use the per-host fallback below:

```bash
ssh $H 'cd ~/nano && scripts/nano support-bundle --since 24h'      # prints the archive path
scp $H:'~/nano/support/nano-support-*.tar.gz' ./nano-deploy-work/
```

Options: `--since 90m|24h|3d`, `--max-log-mb N` (per host, default 20),
`--inventory FILE` (default `/etc/nano/inventory.yaml`), `--local-only`,
`--out-dir DIR`. The archive holds a `README.md`, a `MANIFEST.json`, a
`GETTING-HELP.md`, `hosts/<host>/...` and `cluster/clock-skew.txt`.

Older installs (no `scripts/nano-support-bundle`), or a host the coordinator
could not reach: run the skill's identical copy on each host and send every
archive:

```bash
for h in $HOSTS; do ssh $h 'python3 -I - --install-dir ~/nano --local-only --out-dir ~' < scripts/support-bundle.py; done
```

Kubernetes: `python3 nano/scripts/nano-support-bundle --kubernetes --namespace nano --release nano`
(the script is in the pulled chart, and identical to `scripts/support-bundle.py` here).

It never collects event data, customer logs or query results, and redacts
secrets, but review it before sending (`tar -tzf`, then spot-check `env.txt`
and a log or two). Send it with the deployment ID, the failing command, and
the time with timezone.

## Offline license

Air-gapped installs import a signed offline license instead of the online
enrollment. Upload it in the UI, or with
`POST /api/license/import` as the admin. Follow the air-gapped guide on
nano.rs/docs.

## Kubernetes

- Upgrade: [upgrade.md](upgrade.md), Path C (`helm pull --untar` of the new
  chart, `helm upgrade` with the same value files in the same order and
  `--wait --timeout 20m`). `helm rollback` across a schema change is not
  supported. Roll forward.
- Back up before upgrading: the values and chart version, the `nano-secrets`
  Secret (out of band, encrypted), PostgreSQL (managed snapshots, or `pg_dump`
  from `nano-postgres-0` when bundled), and ClickHouse (`BACKUP ... TO S3`
  per shard, or PVC snapshots).
- `scripts/nano` is not a Kubernetes tool. For health use
  `python3 -I scripts/k8s-health.py --namespace nano` (pods with their failure
  reason, workloads, Vector generations, ClickHouse replicas / Keeper / DDL
  queue through `kubectl exec`, the registry credential refresh), then
  `smoke-test.py` against both hostnames. `helm test` alone misses a Vector
  that never starts.
- After a drain or node loss: a ClickHouse or Keeper pod that stays Pending
  with "volume node affinity conflict" waits for a node in its volume's zone.
  Plan at least two nodes per zone (cloud-aws.md, Amazon EKS).
- Recovery when it fails is in the product
  guide (nano.rs/docs/getting-started/kubernetes#upgrade-recovery).
