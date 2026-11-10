# N VMs, full HA: plan, provision, install, verify

Use this when the operator says something like *"deploy nano to 8 VMs"*,
*"…in AWS"*, *"…on Azure"* or *"…on GCP"*: a cluster where losing any one VM
takes nothing down. Two starting points:

- **The VMs already exist** (any hypervisor or cloud, spot VMs included): the
  operator gives you a list of VMs and the data volume, and `scripts/plan.py
  --hosts` works out which roles go where.
- **The VMs are to be created in AWS, Azure or GCP:** `scripts/plan.py --cloud`
  picks the VM count, instance and disk types, then you provision them with the
  cloud file: [cloud-aws.md](cloud-aws.md), [cloud-azure.md](cloud-azure.md) or
  [cloud-gcp.md](cloud-gcp.md).

Both end in the same Compose role-split install. Full HA needs **nano 2.0.7 or
newer**: several app hosts behind the load balancer, and three PostgreSQL hosts
with automatic failover (Patroni + etcd for PostgreSQL, Sentinel for Valkey).
The authorities are the Multi-node Self-run guide and
[full-ha.md](full-ha.md) / [postgres-ha.md](postgres-ha.md); this page is the
agent procedure from "here are my VMs" to a verified cluster.

Hard rules on top of the [safety rules](../SKILL.md#safety-rules-always-apply):

- **Nothing is created, changed or installed before the operator has
  confirmed the plan, and then each step.** One "yes" covers one step. Cloud
  resources cost money from the first minute: say so.
- Cloud work uses only the operator's own logged-in CLI (`aws`, `az`,
  `gcloud`). Never ask for, print or store cloud keys, licence tokens,
  registry credentials or passwords. Never put a secret on a command line.
- Read-only first: `aws sts get-caller-identity`, `az account show`,
  `gcloud config list` show who you act as. Show it and ask.
- Tag every cloud resource `nano-deployment=<cluster name>` and list what you
  create in `./nano-deploy-work/cloud-resources.md`.

## 1. Intake

Ask [intake.md](intake.md) sections A–D and section E. For existing VMs you
need, per VM: a name, its private address, vCPU, RAM (GiB), the size of the
filesystem that will hold `/var/lib/docker` (GiB), and what fails together
with it (availability zone, rack or hypervisor host), if anything. Write them
to `./nano-deploy-work/hosts.txt`:

```text
name   address     vcpu mem_gib data_disk_gib zone
vm-1   10.20.0.11  8    32      1600          rack-a
vm-2   10.20.0.12  8    32      1600          rack-b
```

Also ask **how users and log senders will reach nano**: a managed cloud load
balancer, two small HAProxy hosts with a floating address (keepalived, needs
VRRP on the network), or one HAProxy host (see [load balancer](#7-load-balancer)).

## 2. Plan the layout

```bash
# Existing VMs: roles laid out on them
python3 scripts/plan.py --hosts ./nano-deploy-work/hosts.txt --gb-per-day <GB> [--eps <EPS>] \
  --avg-event-bytes <B> --retention-days <D> [--hot-days <D>] --growth <x> --analysts <N> \
  --lb cloud|haproxy-pair|haproxy-single [--lb-address <ip>]... [--lb-vip <ip>] \
  [--trusted-proxy-cidr <managed LB source range>] > ./nano-deploy-work/plan.txt

# New cloud VMs: the planner picks them
python3 scripts/plan.py --cloud aws|azure|gcp [--region <r>] --gb-per-day <GB> ... \
  [--max-nodes <N>] [--budget-usd-month <USD>] > ./nano-deploy-work/plan.txt

python3 scripts/plan.py <same flags> --json > ./nano-deploy-work/plan.json
```

The plan is deterministic and offline. It contains:

- one row per VM: name, failure domain, roles (with ClickHouse shard/replica
  and Keeper id), size, disks, private address; unused VMs are listed as spare;
- ClickHouse shards × replicas, the hot days on local disk and the cold days in
  object storage (on existing VMs the hot window shrinks to fit their disks);
- the Vector disk-buffer budget per ingest host and the minutes of peak
  ingest it rides out;
- the HA reasoning, checked: losing any one VM (and any one failure domain,
  when you gave them) keeps every quorum and at least one replica of everything;
- the load balancer: backends, health checks, and whether it is a single
  point of failure;
- tuned settings for the volume (inventory `resources.overrides` where the
  installer accepts them; otherwise the NAN issue that will);
- for cloud plans, a dated monthly cost estimate, with anything unverified listed.

**How roles are placed on existing VMs.** The planner tries the least-stacked
full-HA layout that fits, then stacks roles only as far as needed:

| VMs (at small volume) | Layout |
|---|---|
| 7 or more | 2 app, 3 PostgreSQL + Keeper, 2 ClickHouse (+ ingest), extra ingest hosts at volume |
| 5-6 | PostgreSQL + Keeper also on the 2 app hosts, plus 1 more PostgreSQL + Keeper host |
| 4 | as above, with the third PostgreSQL + Keeper on a ClickHouse host |
| 3 or fewer | refused: full HA is not possible; offer [multi-node-ha.md](multi-node-ha.md) and say what it loses |

Every stacked host must carry the sum of its roles; the planner refuses a VM
that is too small and names the shortfall. Ingest never shares a host with the
app. Spare VMs are listed: one can carry a single HAProxy, or become another
ingest host for headroom.

How it sizes: [sizing.md](sizing.md#cloud-planner-model).

## 3. Review the plan with the operator (gate)

Present `plan.txt` and say plainly:

- the VM count, and why fewer VMs would not be HA. If they offered 8 VMs and
  the plan needs 7, say the 8th is spare (or carries HAProxy);
- **the release:** full HA needs nano 2.0.7 or newer. On an older release use
  `--inventory-schema pre-2.0.7` (one app host and one PostgreSQL host) and
  say that the UI, alerting and PostgreSQL are then single points of failure;
- the load balancer, and **if it is one HAProxy host, that the edge is a single
  point of failure**: everything behind it survives any one VM, but while that
  host is down nobody can log in and senders cannot deliver (they must buffer);
- every `EXTRAPOLATED` warning: above ~5,300 EPS the ratios come from an
  external estate, not from nano measurements;
- the cost range (cloud plans), its date, and that it is not a quote;
- the settings that cannot be applied yet at this volume, with their issues.

Write the confirmed plan to `./nano-deploy-work/plan.md`. **Do not continue
without an explicit "yes".**

## 4. Provision (new cloud VMs only)

Follow the cloud file step by step, asking before each step: network across
three zones, firewall rules from its port table, object storage, VMs (the
plan's types, zones, addresses and disks), load balancers, DNS. The loops read
the plan: `python3 scripts/plan.py <same flags> --nodes-tsv`.

For existing VMs, check instead that they match the plan (`lsblk`, `nproc`,
`free -g` over SSH, read-only) and apply the same firewall flows with the
operator's tooling: `python3 scripts/plan.py --firewall-tsv` prints every rule
(port, target group, source group). A VM joins the group of every role it runs;
`lb-app` and `lb-ingest` are the load balancer's source addresses (the HAProxy
host or hosts, when you use HAProxy).

## 5. Prepare each VM (mutating, per host)

- **OS:** Ubuntu 24.04 LTS (x86-64, AVX2). Preflight checks it.
- **Data disk first, Docker second.** Mount the data disk at
  `/var/lib/docker` *before* installing Docker, so ClickHouse, PostgreSQL,
  Keeper, etcd and the Vector buffers land on it. Use ext4 with `noatime`
  (ClickHouse's recommended filesystem). Mount by UUID with `nofail`.
- **Local NVMe (ClickHouse `local-nvme` cloud plans):** RAID 0 the devices
  with `mdadm`, ext4, at `/var/lib/docker`. It is ephemeral: a stop, resize or
  host failure wipes it, and the other replica re-seeds it. Never stop both
  replicas of a shard. Never use local NVMe for PostgreSQL or ingest.
- **Spot / preemptible VMs:** at most one VM of each role group may be
  reclaimed at a time without an outage. Two at once (for example two
  PostgreSQL hosts) is a two-host failure. Say so if the operator uses them.
- **Time sync:** chrony on the cloud's or site's time source.
  `scripts/nano upgrade` refuses unsynchronized clocks.
- **Docker Engine** from Docker's apt repository, Compose 2.24.4 or newer.
- **SSH user:** a non-root sudo user; its key from the operator's agent.

```bash
ssh $H 'set -e; lsblk -o NAME,SIZE,TYPE,MOUNTPOINT'
# after the operator confirms DEV (mkfs destroys what is on it: its own explicit "yes", new volumes only):
ssh $H "set -e; DEV=/dev/nvme1n1
  sudo mkfs.ext4 -L nano-data \$DEV
  sudo mkdir -p /var/lib/docker
  echo \"UUID=\$(sudo blkid -s UUID -o value \$DEV) /var/lib/docker ext4 defaults,noatime,nofail 0 2\" | sudo tee -a /etc/fstab
  sudo mount /var/lib/docker && df -h /var/lib/docker"
```

Then preflight every host ([preflight.md](preflight.md)) with its roles from
the plan, `--peers` the other addresses and the plan's minimums. Zero `FAIL`.

## 6. Licence, download, verify, install

1. **Licence and download (operator, in app.nano.rs → Deployments → the
   Self-run deployment):** the three enrollment values (`LICENSE_URL`,
   `LICENSE_TOKEN`, `NANO_DEPLOYMENT_ID`) saved to a `0600` file whose path
   they give you; the enterprise compose bundle **and its `.sha256`** (the
   links last 15 minutes); a registry pull credential (lasts one hour, so get
   it just before installing) saved to a file.
2. **Verify before anything is extracted:** `sha256sum -c
   nano-compose-enterprise-<V>.tar.gz.sha256` must print `OK`; on a mismatch
   stop. If nano published a signature for the checksum, verify it with nano's
   bootstrap verifier and the release key fingerprint nano gave you, never with
   a key taken from inside the archive. The installer then verifies every image
   against the digest lock (`NANO_IMAGES_LOCK=images.enterprise.customer.lock`;
   never set `NANO_SKIP_IMAGE_VERIFY`). For an air-gapped site, the signed image
   bundle is checked with `scripts/nano bundle verify <bundle>` before it is
   loaded.
3. **Stage the bundle on every host** ([multi-node-ha.md](multi-node-ha.md)
   Step 1) and log in to the registry with `--password-stdin`.
4. **Inventory** from the confirmed plan (the same flags as step 2):

   ```bash
   python3 scripts/plan.py <same flags> --cluster-name <name> \
     --deployment-id <NANO_DEPLOYMENT_ID> --app-hostname <app fqdn> \
     --ingest-hostname <ingest fqdn> --tls-server-name <private name> \
     --inventory-out ./nano-deploy-work/inventory.yaml
   ```

   It sets `cluster.postgres_ha.synchronous_mode: on` (a failover loses no
   acknowledged write) and `trusted_proxy_cidrs` to the load balancer's
   source addresses. Install it on every host and check that every host prints
   the same identity (multi-node-ha.md Step 2).
5. **Private TLS:** one certificate valid for the private server name **and
   every host address** (PostgreSQL hosts included), with `serverAuth` and
   `clientAuth` and an Authority Key Identifier: `scripts/make-private-ca.sh
   --server-name <name> --ip <each address>...` makes one. Stage it on every
   host (multi-node-ha.md Step 3).
6. **Shared `.env`:** prepare it on the **first app host in the inventory**
   only (it also creates the PostgreSQL replication and Patroni secrets), add
   the enrollment values, and stream it to every other host (multi-node-ha.md
   Steps 4-5). Other app hosts refuse to create their own.
7. **Install, one host at a time, in this order** (each command waits for
   success; re-run the same command after a fix):

   ```bash
   python3 scripts/plan.py <same flags> --install-order
   ```

   prints the exact sequence: the three PostgreSQL hosts first (the first one
   in the inventory initialises the database, the others clone it; check
   `docker compose exec postgres-ha patronictl -c /run/patroni/patroni.yml list`
   shows one `Leader`, one `Sync Standby`, one `Replica`), then the ClickHouse
   hosts, then the app hosts one by one (first app host first: migrations and
   the admin), then ingest. A host that runs several roles is always re-run
   with its complete role list.

## 7. Load balancer

Users open the app hostname; log senders use the ingest hostname. Both go
through the load balancer, which terminates public TLS and sends HTTP to port
80 on the hosts:

- app backend: every app host, health check `GET /readyz` (200 only while
  that host's API and search are ready, 503 while an upgrade drains it);
- ingest backend: every ingest host, `GET /healthz`, and HEC requests hashed on
  their request channel (header, then `?channel=`) so an event batch and its
  acknowledgement poll reach the same host;
- retry a request on another host **only when its connection failed**
  (`retries 3`, `option redispatch`, `retry-on conn-failure`). Never retry on a
  timeout or a 5xx: the host may already have applied it;
- replace `X-Forwarded-For` with the client address. The LB's own source
  addresses are in `cluster.trusted_proxy_cidrs` (the plan writes them).

Pick one:

| Option | When | HA |
|---|---|---|
| Managed cloud LB (`--lb cloud`) | AWS, Azure, GCP | survives a zone loss; see the cloud file |
| Two HAProxy hosts + keepalived (`--lb haproxy-pair --lb-vip <ip>`) | your own network with VRRP (IP protocol 112) allowed and L2 adjacency | survives either HAProxy host (~3 s failover) |
| One HAProxy host (`--lb haproxy-single`) | no managed LB and no VRRP, for example spot VMs in a cloud without one | **single point of failure at the edge** |

For HAProxy, copy `deploy/compose/examples/load-balancer/haproxy.cfg` (and
`keepalived.conf` for a pair) from the installed bundle onto the LB host(s),
replace the certificate paths, hostnames and the `server` lines with the ones
in the plan, install HAProxy 3.2+ from the OS packages, and validate with
`haproxy -c -f /etc/haproxy/haproxy.cfg` before starting it. With
`--lb haproxy-single` and no `--lb-address`, the planner puts HAProxy on a
spare VM. HAProxy may share only a PostgreSQL host (it binds 443; app and
ingest edges own port 80), and then losing that host also takes the edge down.

Tell the operator, for the single-HAProxy option: the cluster behind it keeps
running through any one VM loss, but while the HAProxy host is down nobody can
log in and senders cannot deliver, so senders must buffer and retry. Moving to
a managed LB or an HAProxy pair later only changes `trusted_proxy_cidrs` (a
re-run of every host's install) and DNS.

Point both DNS names at the LB (or the floating address). Add hosts to the
backends only after their install has succeeded.

## 8. Verify and prove failover

Follow [verify.md](verify.md), HA section, then from outside through the load
balancer:

```bash
curl -fsS https://<app fqdn>/api/health
for h in <each app host>; do ssh $h 'curl -fsS http://localhost/readyz'; done
for h in <each ingest host>; do ssh $h 'curl -fsS http://localhost/healthz'; done
ssh <first app host> "python3 -I - --app-url http://localhost --ingest-url https://<ingest fqdn>" < scripts/smoke-test.py
for h in <every host>; do ssh $h 'python3 -I - --install-dir ~/nano' < scripts/cluster-health.py; done
```

Expect one Keeper leader and two followers, every ClickHouse replica active,
Patroni with one `Leader` and one `Sync Standby`, and exactly one jobs leader
(`docker logs` of `nano-jobs` on the app hosts: one `Jobs leader elected`).

**Failover check (with the operator's approval, one VM at a time):** for one
VM of each role group (an app host, the Patroni leader, a ClickHouse replica,
an ingest host, and one HAProxy host of a pair) stop it with
`ssh $H 'sudo systemctl stop docker.socket docker'`, re-run the smoke test
through the load balancer, show it passes, then `sudo systemctl start docker`
and wait for `cluster-health.py` to return to `PASS` before the next one.
Record each result (error window, smoke test, recovery time) in the work
log. Expect a PostgreSQL leader loss to fail in-flight requests for about
15-20 s. Never stop two VMs at once, and never stop a single HAProxy host
during the check: that outage is expected and already stated.

## Teardown

Only on an explicit request, after the operator confirms they have what they
need from the data. Delete cloud resources by the `nano-deployment` tag and the
resource list in the work log, never by name pattern. Buckets with backups are
deleted last, with their own "yes".
