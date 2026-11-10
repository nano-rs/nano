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
VRRP on the network), two HAProxy hosts behind health-checked DNS, or one
HAProxy host (see [load balancer](#7-load-balancer)).

## 2. Plan the layout

```bash
# Existing VMs: roles laid out on them
python3 scripts/plan.py --hosts ./nano-deploy-work/hosts.txt --gb-per-day <GB> [--eps <EPS>] \
  --avg-event-bytes <B> --retention-days <D> [--hot-days <D>] --growth <x> --analysts <N> \
  --lb cloud|haproxy-pair|haproxy-dns|haproxy-single [--lb-address <ip>]... [--lb-vip <ip>] \
  [--trusted-proxy-cidr <managed LB source range>] [--lab] > ./nano-deploy-work/plan.txt

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
  installer accepts them; otherwise marked "not settable from the inventory
  yet");
- for cloud plans, a dated monthly cost estimate, with anything unverified listed.

**How roles are placed on existing VMs.** The planner tries the least-stacked
full-HA layout that fits, then stacks roles only as far as needed:

| VMs (at small volume) | Layout |
|---|---|
| 7 or more | 2 app, 3 PostgreSQL + Keeper, 2 ClickHouse (+ ingest), extra ingest hosts at volume |
| 5-6 | PostgreSQL + Keeper also on the 2 app hosts, plus 1 more PostgreSQL + Keeper host |
| 4 | as above, with the third PostgreSQL + Keeper on a ClickHouse host |
| 3 or fewer | refused: full HA is not possible; offer [multi-node-ha.md](multi-node-ha.md) and say what it loses |

Every stacked host must carry the sum of its roles. The production sizes per
role are the High availability guide's
[Server sizing](https://nano.rs/docs/getting-started/high-availability#server-sizing)
table; the planner computes the same numbers and raises them with volume. A
VM sold as 16 GB reports about 15 GiB and counts as 16 GB.

**When the hosts are too small**, the planner refuses and names the binding
constraint and the fix, for example:

```text
plan: these 7 hosts cannot carry a production full-HA layout at 12.5 GB/day. Binding constraint(s) for the ClickHouse hosts:
  - RAM: the largest host has 15 GiB; a ClickHouse host needs 32 GB ...
  - data disk: ... needs 100 GiB fixed (Docker images, logs, system tables) plus hot data ...
    No --hot-days value fixes this: the fixed 100 GiB alone is more than the disk
```

Quote it to the operator. `--hot-days` helps only when the message says hot
data is what does not fit. For an **evaluation or test cluster** the operator
names as one, re-run with `--lab` (alias `--allow-undersized`). The plan, the
inventory and the firewall script then carry a `LAB PLAN - NOT FOR
PRODUCTION` banner and list every shortfall, and the plan estimates how many
days of events the ClickHouse disks hold. Record the lab exception in the
work log. Never use `--lab` for production.

The planner keeps ingest off the app hosts: that is supported (2.0.4 and
later), but sender load would then compete with the UI. Spare VMs are listed:
use them for HAProxy, or as more ingest hosts for headroom.

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
- the settings that cannot be applied yet at this volume;
- with `--lab`: that the plan is **NOT FOR PRODUCTION**, every shortfall it
  lists, and how many days of events fit locally.

Write the confirmed plan to `./nano-deploy-work/plan.md`. **Do not continue
without an explicit "yes".**

## 4. Provision (new cloud VMs only)

Follow the cloud file step by step, asking before each step: network across
three zones, firewall rules from its port table, object storage, VMs (the
plan's types, zones, addresses and disks), load balancers, DNS. The loops read
the plan: `python3 scripts/plan.py <same flags> --nodes-tsv`.

For existing VMs, check instead that they match the plan (`lsblk`, `nproc`,
`free -g` over SSH, read-only). Firewall flows: `python3 scripts/plan.py
--firewall-tsv` prints every rule (port, target group, source group) for the
operator's tooling. A VM joins the group of every role it runs; `lb-app` and
`lb-ingest` are the load balancer's source addresses (the HAProxy host or
hosts, when you use HAProxy). For the host firewall itself, see step 5.

## 5. Prepare each VM (mutating, per host)

- **OS:** Ubuntu 24.04 LTS (x86-64, AVX2). Preflight checks it.
- **Data disk first, Docker second.** Mount the data disk at
  `/var/lib/docker` *before* installing Docker, so the Docker volumes
  (ClickHouse, PostgreSQL, Keeper, etcd and the Vector buffers) land on it. Use
  ext4 with `noatime` (ClickHouse's recommended filesystem). Mount by UUID
  with `nofail`. Docker 29 keeps **images** in the containerd image store at
  `/var/lib/containerd`, on the root disk: leave ~30 GB free there for images
  (or bind-mount `/var/lib/containerd` from the data disk too).
- **Local NVMe (ClickHouse `local-nvme` cloud plans):** RAID 0 the devices
  with `mdadm`, ext4, at `/var/lib/docker`. It is ephemeral: a stop, resize or
  host failure wipes it, and the other replica re-seeds it. Never stop both
  replicas of a shard. Never use local NVMe for PostgreSQL or ingest.
- **Spot / preemptible VMs:** at most one VM of each role group may be
  reclaimed at a time without an outage. Two at once (for example two
  PostgreSQL hosts) is a two-host failure. Say so if the operator uses them.
- **Time sync:** chrony on the cloud's or site's time source.
  `scripts/nano upgrade` refuses unsynchronized clocks.
- **Docker Engine 24 or newer with Compose 2.24.4 or newer.** Docker's own
  apt repository is the tested path. A distribution package (for example
  Ubuntu's `docker.io` with `docker-compose-v2`) is fine when it meets those
  versions; preflight checks them.
- **SSH user:** a non-root sudo user; its key from the operator's agent.
- **Host firewall, before the first install** (security, required on any host
  with a public address). Docker-published ports (app and ingest 80, 3000,
  8687, PostgreSQL 5432, Patroni 8008, etcd 2379/2380, Valkey 6379, Sentinel
  26379) **bypass UFW**: with only UFW, they are reachable from the internet.
  ClickHouse and Keeper (8123, 9000, 9009, 9363, 9181, 9234) use host
  networking, so UFW covers them. With the operator's approval, apply the
  DOCKER-USER and UFW rules for this plan's addresses on every host. The
  planner prints them; review them with the operator first:

     ```bash
     python3 scripts/plan.py <same flags> --firewall-script > ./nano-deploy-work/firewall.sh
     ssh $H 'MGMT_CIDR=<where the operator SSHes from> bash -s' < ./nano-deploy-work/firewall.sh
     ```

  The script refuses to run without `MGMT_CIDR`, so it can't lock the
  operator out of SSH. It installs `/usr/local/sbin/nano-docker-firewall`
  and `nano-docker-firewall.service`, which re-apply the `DOCKER-USER` rules
  at boot (before Docker) and after every Docker start. The rules drop only
  NEW connections to a published port that arrive from outside the host and
  from outside the cluster. This host's containers, talking to each other or
  connecting out on the same ports, are never filtered. Run the same script
  on the HAProxy hosts: it opens 443 there (and VRRP from the keepalived
  peer). Do **not** install `iptables-persistent`: on Ubuntu/Debian it
  uninstalls `ufw`. Do not try to
  close the ports with the inventory's `bind_address` instead: the installer
  health-checks the app and ingest edges on `localhost`, so a private-only
  bind fails the install. The public guide's
  [Host firewall](https://nano.rs/docs/getting-started/high-availability#host-firewall)
  section is the authority.

```bash
ssh $H 'set -e; lsblk -o NAME,SIZE,TYPE,MOUNTPOINT'
# after the operator confirms DEV (mkfs destroys what is on it: its own explicit "yes", new volumes only):
ssh $H "set -e; DEV=/dev/nvme1n1
  sudo mkfs.ext4 -L nano-data \$DEV
  sudo mkdir -p /var/lib/docker
  echo \"UUID=\$(sudo blkid -s UUID -o value \$DEV) /var/lib/docker ext4 defaults,noatime,nofail 0 2\" | sudo tee -a /etc/fstab
  sudo mount /var/lib/docker && df -h /var/lib/docker"
```

Then preflight every host ([preflight.md](preflight.md)) with the flags
`python3 scripts/plan.py <same flags> --preflight-args` prints for it: its
roles (with `lb` on an HAProxy host), the other addresses and its exact
requirement in this plan (`--lab` is added for a lab plan). Zero `FAIL`, and
no `exposure` WARN left unexplained.

## 6. Licence, download, verify, install

1. **Licence (operator, in app.nano.rs → Deployments → the Self-run
   deployment):** the three enrollment values (`LICENSE_URL`, `LICENSE_TOKEN`,
   `NANO_DEPLOYMENT_ID`) saved to a `0600` file whose path they give you.
   Nothing else is needed from the portal.
2. **Download and verify before anything is extracted:**
   `bash scripts/fetch-bundle.sh --enrollment <file> --version <V> --out
   ./nano-deploy-work/bundle` downloads the bundle, `.sha256` and `.sha256.sig`
   with the licence values and must print `VERIFIED`. It checks the pinned
   release-signing-v1 key, the signature, that the signed `.sha256` names
   exactly this bundle, and the bundle's hash; on any failure it keeps nothing.
   Never use `sha256sum -c` or a key taken from inside the archive. Just before
   installing, get the one-hour registry credential the same way with
   `--registry-cred <file>`. The installer then verifies every image
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
| Managed cloud LB (`--lb cloud`) | any cloud (recommended) | survives a zone loss; see the cloud file |
| Two HAProxy hosts + keepalived (`--lb haproxy-pair --lb-vip <ip>`) | your own network with VRRP (IP protocol 112) allowed and L2 adjacency | survives either HAProxy host (~3 s failover) |
| Two HAProxy hosts + health-checked DNS (`--lb haproxy-dns`) | no managed LB and no VRRP; a DNS provider with health checks, TTL 60 s or less | survives either HAProxy host once DNS drops it (TTL + check interval, roughly 1-2 min; not measured by nano). Senders must retry and re-resolve DNS; clients that cache DNS forever do not fail over |
| One HAProxy host (`--lb haproxy-single`) | nothing above is possible | **single point of failure at the edge** |

For HAProxy, copy `deploy/compose/examples/load-balancer/haproxy.cfg` (and
`keepalived.conf` for a pair) from the installed bundle onto the LB host(s),
replace the certificate paths, hostnames and the `server` lines with the ones
in the plan, install HAProxy 2.6 or later from the OS packages (Debian 12 ships
2.6, Ubuntu 24.04 ships 2.8), and validate with
`haproxy -c -f /etc/haproxy/haproxy.cfg` before starting it. For
`haproxy-dns`, give both HAProxy hosts the same `haproxy.cfg` and put both
addresses in DNS for both hostnames, with the provider's health check on
`https://<name>/healthz` through each address.

Where HAProxy goes: with no `--lb-address`, the planner puts it on spare VMs.
With no spare, it puts it on PostgreSQL-only hosts and says so: they are the
lightest-loaded role, while app, ingest and ClickHouse hosts carry the request
path (and the app and ingest edges own port 80). Losing such a host then also
costs a PostgreSQL member (a short write pause: seconds, up to about 30 s). Recommend a small
spare VM (2 vCPU / 2 GB) per HAProxy host instead. With one HAProxy host,
losing it takes the edge down whatever it shares.

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
`cluster-health.py` must print `PASS` for every `gw:` row on every host: each
row is one of the host's own HAProxy gateways (clickhouse-proxy, app-api-proxy,
ingest-proxy, postgres-router, valkey-router), read from its runtime socket.
A `gw:clickhouse-proxy` FAIL that names **this host's own replica** means the
host's containers cannot reach the host's own address (a host firewall
blocking Docker bridges): with it, losing the other replica stops every
write. Fix it (step 5: allow `docker0`/`br-+`) before go-live. On PostgreSQL
hosts the `pg-patroni`, `pg-etcd` and `pg-sentinel` rows check the failover
stack. The smoke test's `latency` row must show the write landing within its
bound (default 60 s).

After the install, log every host out of the registry: the pull credential is
stored unencrypted in `~/.docker/config.json`
(`ssh $H 'docker logout us-central1-docker.pkg.dev'`). Log in again for every
installer re-run or upgrade.

From the workstation (outside the cluster), prove nothing but the load
balancer answers from outside. Use the public addresses, if the hosts have
them:

```bash
bash scripts/preflight.sh --exposure-probe <every host address, comma-separated>
```

Every row must be `PASS`. A `WARN` on a database or cluster port is a go-live
blocker: fix the firewall (step 5) and probe again.

**Failover check (with the operator's approval, one VM at a time):** first
run `cluster-health.py` on every host: every `gw:` row must be `PASS` (a check
that starts with a gateway already DOWN proves nothing). Then, for one VM of
each role group (an app host, the Patroni leader, a ClickHouse replica, an
ingest host, and one HAProxy host of a pair), stop it. A hard power-off from
the hypervisor or cloud console is the real test; if the operator has none,
`ssh $H 'sudo systemctl stop docker.socket docker'` is a softer substitute:
say which you used. During the outage:

- run the smoke test through the load balancer from a surviving app host. It
  must PASS **including its `latency` row**: it fails when the test event takes
  longer than `--write-sla` (default 60 s) to become searchable, even if it
  lands later. Never pass `--redeploy` during a drill (a redeploy pushes a new
  Vector configuration to every ingest host mid-outage);
- run `cluster-health.py` on the surviving hosts: only gateway backends that
  point at the stopped VM may be DOWN;
- for the most honest result, also send a numbered event every second from
  outside through the LB and count them in search afterwards (the HA guide's
  "Test failover").

Then start the VM and wait for `cluster-health.py` to return to `PASS` on every
host before the next one. Record each result (error window, write latency,
recovery time) in the work log. What must hold, per the High availability
guide's full-HA failover test:

| VM stopped | Must keep working |
|---|---|
| an app host | UI, search and ingest, once the LB's `/readyz` checks drop it |
| the Patroni leader | writes, sign-ins and searches see a short pause, typically a few seconds and up to about 30 s, while a standby is promoted (a 7-host test measured ~3 s of failed sign-ins), then resume; nothing acknowledged is lost; HEC/HTTP ingest continues |
| a ClickHouse replica | search and ingest on the other replica |
| an ingest host | ingest on the others |
| one HAProxy host | keepalived pair: about 3 s; DNS pair: after the TTL and health check (about 1-2 min) |

Never stop two VMs at once, and never stop a single HAProxy host during the
check: that outage is expected and already stated.

## Teardown

Only on an explicit request, after the operator confirms they have what they
need from the data. Delete cloud resources by the `nano-deployment` tag and the
resource list in the work log, never by name pattern. Buckets with backups are
deleted last, with their own "yes".
