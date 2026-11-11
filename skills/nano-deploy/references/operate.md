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

Enterprise releases are published as the signed installer package only
(`nano-compose-enterprise-<version>.tar.gz` with `.sha256` and `.sha256.sig`).
The images come from the registry. There is no offline image bundle
(`nano-<version>-enterprise.tar`) for registry installs; the Downloads page and
the licence API do not list one. Two procedures, by target version:

### From v2.0.10 or later: `scripts/nano upgrade` with the package

The cluster already runs v2.0.10 or later.

1. Read the release notes and [known-issues.md](known-issues.md). Download the
   package for the target version with its `.sha256` and `.sha256.sig`
   (`scripts/fetch-bundle.sh`, it must print `VERIFIED`) and put all three at
   the same path on every host, for example `/srv/nano/releases/`.
2. On **every** host, extract the package over the install directory. It
   carries no `.env`, `.nano-role.env` or generated state, so those are kept:
   `ssh $h 'tar -xzf /srv/nano/releases/nano-compose-enterprise-<v>.tar.gz --strip-components=1 -C ~/nano'`.
   The running containers are unaffected until the upgrade restarts them.
3. Log in to the registry on every host with a fresh pull credential (it
   lasts about an hour, so do this right before the run) and make sure the
   backup key exists.
4. **Dry run** (read-only), from the first app host (single node: drop
   `--inventory`, `--remote-*` and `--backup-output`):

   ```bash
   ssh $H1 'cd ~/nano && scripts/nano upgrade --inventory /etc/nano/inventory.yaml \
     --bundle /srv/nano/releases/nano-compose-enterprise-<v>.tar.gz \
     --remote-bundle /srv/nano/releases/nano-compose-enterprise-<v>.tar.gz \
     --remote-install-dir ~/nano --backup-key-file /secure/nano-backup/operator.pem \
     --backup-output /mnt/nano-backups/upgrade-<v> --dry-run'
   ```

   With more than one ingest host behind a load balancer, add
   `--lb-drain-command` and `--lb-rejoin-command` (absolute paths on every
   ingest host). The tool verifies the package signature, reads the image
   digests, migration ledger and upgrade policy from inside it, and checks
   each host's `control-tree` (the package is extracted there),
   `registry-login`, and `registry-pull`: the registry must accept the
   host's credential, and every image the host needs is pulled and its digest
   checked now, before the backup or any restart. The dry run therefore fills
   each host's image cache; it changes nothing that runs.
5. Every dry-run row must pass. A failed row is a hard refusal. Fix the cause
   (disk, NTP, replica lag, licence, registry login) and repeat. Never bypass
   a gate.
6. Ask, then run the same command without `--dry-run`. The tool takes the
   mandatory backup, pulls each host's images by signed digest, and rolls
   Keeper → ClickHouse → PostgreSQL → migrations → app → ingest, one host at
   a time.
7. If it stops: fix the cause (an expired registry login is the usual one:
   log in again) and re-run with `--resume` and the same package. Never delete
   the journal (`~/nano/upgrade-journal/`).
8. Log out of the registry on every host, then verify ([verify.md](verify.md)).

### From v2.0.9 or earlier: re-run the installer, host by host, to v2.0.10

The installed `scripts/nano upgrade` predates registry upgrades. Upgrade to
v2.0.10 by re-running each host's install command from the v2.0.10 package,
in order (the path a 7-host customer test completed with no lost events).
Every later upgrade uses the section above:

1. Take a backup first (`scripts/nano backup-set`, see Back up above).
2. Download and verify the package, then on each host in turn: extract it
   over `~/nano` as above, log in to the registry, take the host out of the
   load balancer if it is an app or ingest host (wait for the drain), re-run
   its exact `install.sh` command with the full role list, wait for
   `cluster-health.py` to pass, and put it back in the load balancer.
3. Order: Keeper/ClickHouse hosts, then PostgreSQL (replicas first, then the
   leader after a switchover, see [postgres-ha.md](postgres-ha.md)), then the
   app hosts one at a time, then ingest.

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

- Upgrade: pull the new chart first (`rm -rf nano && helm pull "$CHART"
  --version <new> --untar`: the old `./nano`'s `values-customer-images.yaml`
  pins the old image digests), then `helm upgrade nano ./nano` with exactly the
  install's value files, in the same order, and `--wait --timeout 20m`
  ([helm.md](helm.md)).
  Migrations run as a pre-upgrade hook. Apply new ClickHouse operator CRDs
  first if the release says so (`kubectl apply --server-side -f crds/...`).
  `helm rollback` across a schema change is not supported. Roll forward.
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
