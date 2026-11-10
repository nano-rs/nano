# Intake

Ask these questions in groups. Do not ask for anything the operator already
told you. Never ask for the content of a secret. Ask for a **path** to a file
that holds it.

## A. Topology and scale

1. Which topology?
   - **Single node**: one Linux host, Docker Compose. Not highly available.
   - **3-node HA**: three Linux hosts plus a load balancer, Compose role split.
     ClickHouse has two replicas, Keeper a 3-member quorum, and two hosts
     accept ingest. The app and PostgreSQL run on one host, so they are not
     HA, and ingest also pauses while that host is down.
   - **Kubernetes (Helm)**: an existing cluster the operator runs.
2. Expected volume: events per second (EPS) and/or GB per day of raw logs.
   If they know only one, `scripts/size.py` estimates the other (1 KB/event by
   default; ask about the average event size if they know it).
3. Retention: how many days events stay searchable. The default is 365.
4. Growth: the expected volume in 12 months. Size the disk for it.

## B. Hosts (Compose topologies)

For each host:

- name (short, stable, for example `nano-1`) and private IP address;
- SSH: user, port, and key path, or "use my ssh-agent". The user must not be
  root. It needs `sudo` (for Docker installation, firewall and TLS staging)
  and will be added to the `docker` group. The installer itself runs as this
  user, never with `sudo`;
- OS and version, if known;
- data disk: where Docker's data root lives (`/var/lib/docker` by default)
  and its size.

Ask for the SSH host key fingerprints if the operator has them. Otherwise
show the fingerprints from the first connection and ask the operator to
confirm them. Never disable host key checking.

## C. Network, DNS and TLS

1. App hostname that users open (for example `nano.example.com`).
2. Ingest hostname that log senders use (for example `ingest.nano.example.com`).
   For 3-node HA, the two must differ. On a single node they can be the same
   host.
3. TLS:
   - **public TLS**: a certificate and key the operator provides (paths), or a
     TLS-terminating load balancer / reverse proxy in front of nano. On a
     single node, the bundled nginx can serve the certificate (TLS overlay);
   - **private cluster TLS (3-node HA)**: a private CA plus one server
     certificate valid for every node IP and a private name. Ask whether they
     have their own PKI. Otherwise offer `scripts/make-private-ca.sh`.
4. Load balancer in front of the app and ingest hosts (3-node HA): yes or no,
   its private source CIDR, and who configures it.
5. Firewall: who manages it. The installer never changes the firewall.
6. Outbound access from the hosts: the registry, `api.nano.rs` for the licence
   check, and the platform feeds. Or is this an air-gapped site?

## D. Release, licence and credentials

All of these come from **app.nano.rs → Deployments → your Self-run deployment**,
or from your nano contact while the portal delivery is rolling out.

1. Release version (for example `2.0.4`). Use the newest release unless the
   operator pins one. Check [known-issues.md](known-issues.md).
2. Enterprise compose bundle: where the operator saved
   `nano-compose-enterprise-<version>.tar.gz` (a local path or a download URL)
   and its published SHA-256.
3. Registry pull credential: the path of a file holding the credential, and
   the username nano gave with it. You log in with `--password-stdin`.
4. Enrollment values: the path of a file (mode `0600`) holding exactly these
   three lines from the deployment page. The token is shown only once:

   ```dotenv
   LICENSE_URL=https://api.nano.rs/api/license/status
   LICENSE_TOKEN=<one-time enrollment token>
   NANO_DEPLOYMENT_ID=<deployment id>
   ```

   Air-gapped sites get an offline licence file instead. See
   [operate.md](operate.md#offline-licence).
5. Admin account: email and display name. The password is generated on the
   host into a `0600` file unless the operator wants to supply one, as a file
   path.
6. Backup: where the backup operator key will live (off the nano hosts) and
   the backup destination.

## Intake record

Write this to `./nano-deploy-work/intake.md`. It holds no secret values, only
paths to them:

```markdown
# nano Self-run intake: <deployment name>
- topology: single | ha3 | helm
- version: 2.0.x   bundle: <path or url>   sha256: <hex>
- volume: <eps> EPS, <gb> GB/day, retention <days> d, 12-month growth <x>
- hosts:
  | name | address | ssh | roles |
  |---|---|---|---|
- app hostname: ...   ingest hostname: ...
- public TLS: overlay | load balancer | reverse proxy | none (lab only)
- private TLS (HA): own PKI | scripts/make-private-ca.sh
- registry credential file: <path>   username: <user>
- enrollment file: <path>
- admin: <email>, <name>; password file on the app host: ~/.nano-admin-credentials
- backup key path: <path>   backup destination: <path>
- firewall owner: ...   LB owner: ...
```
