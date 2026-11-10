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

1. Read the release notes and [known-issues.md](known-issues.md). Get the
   signed release tar `nano-<version>-enterprise.tar` (the upgrade artifact)
   and verify its digest. Do not unpack or repack it.
2. Make sure the backup key exists.
3. **Dry run** (read-only), single node:

   ```bash
   ssh $H 'cd ~/nano && scripts/nano upgrade --bundle /srv/nano/releases/nano-<v>-enterprise.tar \
     --backup-key-file /secure/nano-backup/operator.pem --dry-run'
   ```

   Role split, from the app host. The bundle, install directory and key must
   exist at the same paths on every host, and the backup output must be a
   shared directory:

   ```bash
   ssh $H1 'cd ~/nano && scripts/nano upgrade --inventory /etc/nano/inventory.yaml \
     --bundle /srv/nano/releases/nano-<v>-enterprise.tar --remote-bundle /srv/nano/releases/nano-<v>-enterprise.tar \
     --remote-install-dir ~/nano --backup-key-file /secure/nano-backup/operator.pem \
     --backup-output /mnt/nano-backups/upgrade-<v> --dry-run'
   ```

   With more than one ingest host behind a load balancer, add
   `--lb-drain-command` and `--lb-rejoin-command` (absolute paths on every
   ingest host).
4. Every dry-run row must pass. A failed row is a hard refusal. Fix the cause
   (disk, NTP, replica lag, licence) and repeat. Never bypass a gate.
5. Ask, then run the same command without `--dry-run`. The tool takes the
   mandatory backup and rolls Keeper → ClickHouse → PostgreSQL → migrations →
   app → ingest, one host at a time.
6. If it stops: fix the cause and re-run with `--resume` and the same bundle.
   Never delete the journal (`~/nano/upgrade-journal/`).
7. Verify ([verify.md](verify.md)).

`scripts/nano rollback` works only while the schema is unchanged. Otherwise it
refuses and prints the exact restore commands. Explain that before anyone
runs a restore.

If the signed release tar is not available for the target version, the
documented fallback is to replace the extracted bundle and re-run each host's
`install.sh` command in the same role order (Keeper/ClickHouse hosts, then
PostgreSQL, app, ingest). Take a backup first.

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

```bash
for h in $HOSTS; do ssh $h 'python3 -I - --install-dir ~/nano' < scripts/support-bundle.py; done
scp $H:'~/nano-support-*.tar.gz' ./nano-deploy-work/
```

It is redacted, but review it before sending (`tar -tzf`, then spot-check
`env-keys.txt` and a log or two). Send it with the deployment ID, the failing
command, and the time with timezone.

## Offline licence

Air-gapped installs import a signed offline licence instead of the online
enrollment. Upload it in the UI, or with
`POST /api/license/import` as the admin. Follow the air-gapped guide on
nano.rs/docs.

## Kubernetes

- Upgrade: `helm upgrade` with the same value files and the new `--version`.
  Migrations run as a pre-upgrade hook. Apply new ClickHouse operator CRDs
  first if the release says so (`kubectl apply --server-side -f crds/...`).
  `helm rollback` across a schema change is not supported. Roll forward.
- Back up before upgrading: the values and chart version, the `nano-secrets`
  Secret (out of band, encrypted), PostgreSQL (managed snapshots, or `pg_dump`
  from `nano-postgres-0` when bundled), and ClickHouse (`BACKUP ... TO S3`
  per shard, or PVC snapshots).
- `scripts/nano` is not a Kubernetes tool.
