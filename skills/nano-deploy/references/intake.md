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
   - **N VMs, full HA** ("deploy to 8 VMs", "…in AWS / Azure / GCP"): losing
     any one VM takes nothing down (nano 2.0.7+). With existing VMs the planner
     lays the roles out on them; in a cloud it can also pick the VMs. Ask
     section E too, then follow [cloud-vm.md](cloud-vm.md).
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
6. Outbound access from the hosts: the registry, `api.nano.rs` for the license
   check, and the platform feeds. Or is this an air-gapped site?

## D. Release, license and credentials

All of these come from **app.nano.rs → Deployments → your Self-run
deployment**. Only an owner or admin of the organization can open the
downloads. If the page says bundle downloads are being enabled, the operator
emails support@nano.rs.

1. Release version (for example `2.0.7`). Use the newest release unless the
   operator pins one. Check [known-issues.md](known-issues.md).
2. Enterprise compose bundle: normally nothing to ask. With the enrollment
   values (item 4) you download and verify it yourself with
   `scripts/fetch-bundle.sh`. Ask only if the operator already downloaded
   `nano-compose-enterprise-<version>.tar.gz` with its `.sha256` and
   `.sha256.sig`; verify those the same way before use.
3. Registry pull credential: normally nothing to ask. `scripts/fetch-bundle.sh
   --registry-cred FILE` writes one (user `oauth2accesstoken`, one hour). Or
   the path of a credential file the operator got from the deployment's page.
   You log in with `--password-stdin`.
4. Enrollment values: the path of a file (mode `0600`) holding exactly these
   three lines from the deployment page. The token is shown only once:

   ```dotenv
   LICENSE_URL=https://api.nano.rs/api/license/status
   LICENSE_TOKEN=<one-time enrollment token>
   NANO_DEPLOYMENT_ID=<deployment id>
   ```

   Only `LICENSE_TOKEN` is a secret. The deployment ID is an identifier: the
   inventory, the installer's output and `render-inventory.py --identity-only`
   print it, and that is fine.
   Air-gapped sites get an offline license file instead. See
   [operate.md](operate.md#offline-license).
5. Admin account: email and display name. The password is generated on the
   host into a `0600` file unless the operator wants to supply one, as a file
   path.
6. Backup: where the backup operator key will live (off the nano hosts) and
   the backup destination.

## E. N VMs, full HA

1. Do the VMs exist already? If so, for each one: name, private address,
   vCPU, RAM, the size of the filesystem for `/var/lib/docker`, and what fails
   with it (zone, rack or hypervisor host). Spot or preemptible VMs: say so.
   If they are to be created: the cloud and region (AWS, Azure or GCP; three
   availability zones are needed).
2. How users and log senders reach nano (High availability guide, "Load
   balancer options"):
   - a managed cloud load balancer (recommended on any cloud);
   - two HAProxy hosts with keepalived and a floating address (needs VRRP and
     one L2 network; most public clouds block VRRP);
   - two HAProxy hosts, both addresses in DNS with the DNS provider's
     health-checked failover (no floating address; failover takes the TTL plus
     the check interval, roughly 1-2 minutes; senders must retry and re-resolve
     DNS);
   - one HAProxy host: a single point of failure at the edge.
   The LB hosts' private addresses. A small spare VM (2 vCPU / 2 GB) per
   HAProxy host keeps it off the PostgreSQL hosts.
3. Average event size, if known (EDR JSON is often ~2.3 KB; the default is
   1 KB). Ask which sources dominate the volume.
4. Retention split: how many days must be fast to search (hot, on local
   disk), and how many may live in object storage (cold). Default: the planner
   keeps as much hot as fits.
5. How many analysts search at the same time of day.
6. Limits: a maximum VM count, a monthly budget, or instance families their
   organisation has approved or reserved. A limit never removes HA: if it is
   too tight, the planner refuses and you explain why.
7. Who creates cloud resources: you, with the operator's logged-in CLI
   (`aws` / `az` / `gcloud`), or their own team or Terraform. Never ask for
   cloud keys.
8. Existing network: a VPC/VNet to reuse and its CIDR (default plan
   `10.40.0.0/16`), DNS zone for the two hostnames, TLS certificates (ACM, Key
   Vault or Google-managed for the public names), a management CIDR for SSH.
9. Object storage for the cold tier and backups: the cloud's S3-compatible
   store (S3, Cloud Storage), RustFS, or none (all retention local). On Azure,
   Blob has no S3 API: RustFS or an external S3-compatible store.
10. The nano release they will install. Full HA needs 2.0.7 or newer
    ([known-issues.md](known-issues.md)).

## Intake record

Write this to `./nano-deploy-work/intake.md`. It holds no secret values, only
paths to them:

```markdown
# nano Self-run intake: <deployment name>
- topology: single | ha3 | helm | n-vm (existing hosts.txt | aws | azure | gcp; region, max VMs, budget, LB)
- version: 2.0.x   bundle: <path to the 3 files, or link file>   sha256: <hex>   signature: verified | not yet
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
