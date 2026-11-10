# 3-node HA (Compose role split)

> For N VMs with no single point of failure (nano 2.0.7+: several app hosts,
> three PostgreSQL members, replicas in different failure domains), lay out the
> roles with `scripts/plan.py` and follow [cloud-vm.md](cloud-vm.md). It reuses
> Steps 1–5 below for the bundle, inventory, TLS and `.env`.

Every host runs the same enterprise bundle, the same `inventory.yaml` and the
same shared `.env`, but starts only its own roles. The authorities are the
public guides at nano.rs/docs: **High availability** (the load balancer and
the failure matrix) and **Multi-node Self-run** (every inventory field and
installer flag). This page is the agent procedure for this layout:

| Host | Roles | ClickHouse | Keeper | Ingest |
|---|---|---|---|---|
| `nano-1` | `app, postgres, keeper` | (none) | id 1 | (none) |
| `nano-2` | `clickhouse, keeper, ingest` | shard 1, replica 1 | id 2 | port 80 |
| `nano-3` | `clickhouse, keeper, ingest` | shard 1, replica 2 | id 3 | port 80 |

**Keep `ingest` off the app host** in this layout. Running both on one host
is supported from 2.0.4 (2.0.0 deadlocked on it; see
[known-issues.md](known-issues.md)), but sender load would then compete with
the UI. Two ingest hosts give ingest redundancy.

Plus a TLS-terminating load balancer for both hostnames. The installer allows
any number of `app` hosts and one, two or three `postgres` hosts. ClickHouse
replicas, the 3-member Keeper quorum, several ingest hosts, several app hosts
and three postgres hosts (both nano 2.0.7+) are the HA mechanisms. See
[Several app hosts](#several-app-hosts) to keep the UI, search and alerting up
when an app host is lost, and [postgres-ha.md](postgres-ha.md) for automatic
PostgreSQL and Valkey failover.
Before you start, tell the operator what survives (see
[sizing.md](sizing.md#what-ha-means-here)):

- **Loss of `nano-2` or `nano-3`:** ingest continues on the other ingest
  host, and search on the other replica.
- **Loss of `nano-1`:** the UI, search, detections and PostgreSQL go down,
  **and ingest stops at the load balancer**. The ingest nodes' `/healthz`
  needs the app API, so senders must buffer and retry.
- **Loss of two hosts:** Keeper loses its quorum and ClickHouse goes
  read-only.

`H1`, `H2`, `H3` are `user@host` for `nano-1` to `nano-3`, and `V` is the
release. Ask before each step.

## Rules specific to role split

- Run `install.sh` as the SSH user, **never with sudo**. `.env` and
  `/etc/nano/inventory.yaml` must be owned by that user, mode `0600`, on
  every host.
- Private TLS is **on by default** and required for production. Plaintext is
  only for a disposable isolated lab the operator names as such: it needs
  `allow_plaintext_private_network: true` in the inventory **and**
  `NANO_LAB_ONLY_PLAINTEXT=1` on every installer run.
- `cluster.deployment_id` must be the app.nano.rs deployment ID
  (`NANO_DEPLOYMENT_ID`) exactly. The renderer writes it into each host's
  `.nano-role.env`, which overrides `.env`, and the licence check uses it. In
  a lab with no enrollment yet, use a clear placeholder such as
  `lab-<name>`. It cannot be changed later, so a lab inventory is never
  reused for production.
- `deployment_id`, host `name`/`id`, roles and shard/replica numbers are
  permanent identity. Never change them to get past an error.
- Every invocation names the host and its roles:
  `NANO_HOST_NAME=<hosts[].name> NANO_IMAGES_LOCK=images.enterprise.customer.lock ./install.sh --role <roles> --inventory /etc/nano/inventory.yaml`.
  Every invocation also sets `NANO_IMAGES_LOCK=images.enterprise.customer.lock`
  so images come from the customer repository your registry credential can pull.
  Once a host is fully installed, always run it with its **complete** role
  list, including on upgrades.
- Do not copy `.nano-role.env` or `.nano-generated/` between hosts. They are
  host-specific and regenerated on every run.

## Step 0: preflight all three hosts

Run preflight with `--topology ha --roles <that host's roles> --peers <the
other two addresses>`. Its defaults are the planner's floors for those roles
(`nano-1` 8 vCPU / 26 GiB, `nano-2` and `nano-3` 6 vCPU / 28 GiB, as the OS
reports RAM); add `--min-*` for the 8 vCPU / 32 GB the guide recommends and
the disk your retention needs ([preflight.md](preflight.md)).
All three hosts need zero `FAIL`, a synchronized clock and Compose 2.24.4 or
newer. The load balancer is the operator's. Ask who provides it, or note that
a lab runs without one.

## Step 1: stage the bundle on every host

Same as Steps 0–3 in [single-node.md](single-node.md): fetch and verify the
bundle once with `scripts/fetch-bundle.sh` (it must print `VERIFIED`), copy and
extract it to `~/nano`, and log in to the registry. Do this on
**all three** hosts.

## Step 2: inventory

Generate it on the workstation and review it with the operator:

```bash
python3 scripts/ha3-inventory.py --cluster-name <name> --deployment-id <NANO_DEPLOYMENT_ID> \
  --app-hostname <app fqdn> --ingest-hostname <ingest fqdn> \
  --node nano-1=<ip1> --node nano-2=<ip2> --node nano-3=<ip3> \
  --tls-server-name <private name> --trusted-proxy-cidr <lb private /32> \
  --out ./nano-deploy-work/inventory.yaml
```

Without a load balancer (a lab), leave out `--trusted-proxy-cidr`. Senders
then post straight to an ingest host, `nano-2:80` or `nano-3:80`.

Install it on every host (the same bytes):

```bash
for h in $H1 $H2 $H3; do
  scp ./nano-deploy-work/inventory.yaml $h:~/inventory.yaml
  ssh $h 'sudo install -d -m 0755 /etc/nano &&
    sudo install -m 0600 -o "$(id -un)" -g "$(id -gn)" ~/inventory.yaml /etc/nano/inventory.yaml && rm ~/inventory.yaml &&
    sha256sum /etc/nano/inventory.yaml'
done
```

The three digests must match. Validate with the product's renderer before
anything starts. This is read-only; run it with each host's own name and
roles:

```bash
ssh $H1 'cd ~/nano && python3 -I deploy/compose/render-inventory.py --inventory /etc/nano/inventory.yaml \
  --roles app,postgres,keeper --host nano-1 --identity-only'
ssh $H2 'cd ~/nano && python3 -I deploy/compose/render-inventory.py --inventory /etc/nano/inventory.yaml \
  --roles clickhouse,keeper,ingest --host nano-2 --identity-only'
```

All three print the same `sha256`.

## Step 3: private TLS material (privileged, secret)

Use the operator's PKI, or create a CA and certificate with
`scripts/make-private-ca.sh`. The certificate must cover the private server
name and every node IP, with both serverAuth and clientAuth (Keeper uses it
as a client certificate too):

```bash
scripts/make-private-ca.sh --out ./nano-pki --server-name <private name> \
  --ip <ip1> --ip <ip2> --ip <ip3>
```

`ca.key` never leaves the workstation. On each host, put the three files
where only root can read them, then stage them with the product helper:

```bash
for h in $H1 $H2 $H3; do
  scp -p ./nano-pki/server.crt ./nano-pki/server.key ./nano-pki/ca.crt $h:~/
  ssh $h 'set -e; sudo install -d -m 0700 -o root -g root /root/nano-pki
    for f in server.crt server.key ca.crt; do sudo install -m 0600 -o root -g root ~/$f /root/nano-pki/$f; rm -f ~/$f; done
    sudo ~/nano/scripts/nano-tls-stage --cert /root/nano-pki/server.crt --key /root/nano-pki/server.key \
      --ca /root/nano-pki/ca.crt --output /var/lib/nano/tls/staged --installer-user "$(id -un)"'
done
```

The helper adds the user to the `nano-tls` group. **Open a new SSH session**
afterwards, which a fresh `ssh` command does, and check with
`id -nG | grep -w nano-tls`. The installer refuses to run until the group
membership is active.

## Step 4: prepare the shared .env on nano-1

```bash
ssh $H1 "bash -s -- --email ADMIN_EMAIL --name 'ADMIN NAME'" < scripts/admin-credentials.sh
ssh $H1 'cd ~/nano && set -a && . ~/.nano-admin-credentials && set +a &&
  NANO_HOST_NAME=nano-1 NANO_BASE_URL=<https://app fqdn> NANO_PREPARE_ONLY=1 \
  NANO_IMAGES_LOCK=images.enterprise.customer.lock ./install.sh --role app,postgres,keeper --inventory /etc/nano/inventory.yaml'
```

Then add the enrollment values on nano-1 with `apply-enrollment.sh` (Step 7 of
[single-node.md](single-node.md)). Its `NANO_DEPLOYMENT_ID` must equal the
inventory's `deployment_id`. If they differ, stop.

## Step 5: distribute .env (secret)

One rule, every time: after any installer run that changed `.env` (the first
app host's prepare or a topology change, or the postgres host that prints
"The shared .env changed" when it records `NANO_PG_HA_SYSTEM_ID`), stream
**that host's** `.env` to every other host, the first app host included,
before the next installer run anywhere. Never stream the first app host's
older copy over a newer one: it would drop `NANO_PG_HA_SYSTEM_ID`. Below,
`$H1` is the host whose run changed it.

Stream it host to host. It is never written to the workstation and never
printed:

```bash
for h in $H2 $H3; do
  ssh $H1 'cat ~/nano/.env' | ssh $h 'umask 077 && cat > ~/nano/.env.tmp && chmod 600 ~/nano/.env.tmp && mv ~/nano/.env.tmp ~/nano/.env'
done
for h in $H1 $H2 $H3; do ssh $h 'stat -c "%U %a" ~/nano/.env; sha256sum ~/nano/.env | cut -c1-16'; done
```

The owner must be the installer user, the mode `600`, and the digest prefixes
must match.

## Step 6: ClickHouse and Keeper first, then the app, then ingest

Run one host at a time and wait for each to succeed before the next:

```bash
# 1. Data roles on nano-2 and nano-3 (two Keepers already form a quorum)
ssh $H2 'cd ~/nano && NANO_HOST_NAME=nano-2 NANO_IMAGES_LOCK=images.enterprise.customer.lock ./install.sh --role clickhouse,keeper --inventory /etc/nano/inventory.yaml'
ssh $H3 'cd ~/nano && NANO_HOST_NAME=nano-3 NANO_IMAGES_LOCK=images.enterprise.customer.lock ./install.sh --role clickhouse,keeper --inventory /etc/nano/inventory.yaml'

# 2. nano-1 with its complete role list: PostgreSQL, Keeper 1, migrations on both
#    replicas, dictionary readiness, Keeper root ACL, app start and admin creation
ssh $H1 'cd ~/nano && set -a && . ~/.nano-admin-credentials && set +a &&
  NANO_HOST_NAME=nano-1 NANO_IMAGES_LOCK=images.enterprise.customer.lock ./install.sh --role app,postgres,keeper --inventory /etc/nano/inventory.yaml'

# 3. Ingest on nano-2 and nano-3: complete role lists (they fetch parsers and tokens from the app)
ssh $H2 'cd ~/nano && NANO_HOST_NAME=nano-2 NANO_IMAGES_LOCK=images.enterprise.customer.lock ./install.sh --role clickhouse,keeper,ingest --inventory /etc/nano/inventory.yaml'
ssh $H3 'cd ~/nano && NANO_HOST_NAME=nano-3 NANO_IMAGES_LOCK=images.enterprise.customer.lock ./install.sh --role clickhouse,keeper,ingest --inventory /etc/nano/inventory.yaml'
```

If a run fails, read its last 40 lines, fix the cause, and re-run **that same
command**. Each run republishes the host's generated tree and recreates only
its own containers, keeping the named volumes. Never `docker restart` Vector
alone on an ingest host. Re-run the host's install command instead.

If nano-1's run stops before the admin exists, re-run it. The operator can
also finish in the browser: the setup page asks for the setup token,
`NANO_SETUP_TOKEN` in the shared `.env` (generated by the prepare step). The
operator reads it on the host; never print it yourself.

## Several app hosts

Offer this when the operator needs the UI, API, search, detections and
alerting to survive the loss of an app host. Requirements and rules:

- Two or more hosts with the `app` role; keep `postgres` on a host of its own
  if the app must survive it. Default private TLS is mandatory (plaintext lab
  mode is refused).
- The cluster's shared Valkey runs on the `postgres` host, published on
  `ports.valkey` (default 6379) behind mutual TLS. Allow it from the app
  hosts only.
- Create `.env` on the FIRST app host in the inventory and copy it to every
  host, the other app hosts included. Other app hosts refuse to create one.
- `NANO_SETUP_TOKEN` (first-admin setup token) is generated once, with the
  rest of `.env`, on the first app host. It must be the same on every app
  host, so copy that `.env`; never regenerate it per host. The first app host
  creates the admin; a later app host that finds setup already done logs
  "already initialized" and skips admin creation.
- Install order: data roles, then the app hosts one at a time (first app host
  first, never in parallel while debugging), then ingest.
- LB app backend: every app host on port 80, health check `GET /readyz`
  (200 while that host's own api and search processes are alive; 503 while an
  upgrade drains it; shared PG/Valkey/ClickHouse outages never fail it, so a
  PG failover cannot de-pool every app host), `retries 3`, `option redispatch`,
  `retry-on conn-failure` (never L7 retry-on: it resends a POST the API may already have applied). No affinity needed.
- `scripts/nano upgrade` migrates once from the first app host and drains
  each app host before restarting it: `/readyz` 503, then wait until the edge
  logs no client request for `NANO_LB_DRAIN_QUIET_SECONDS` (5, at most
  `NANO_LB_DRAIN_SECONDS` 30). Rejoin needs `NANO_LB_REJOIN_CHECKS` (3)
  consecutive `/readyz` 200s, then holds `NANO_LB_REJOIN_SECONDS` (60; at
  least the LB's check interval x rise + one interval) before the next host.
- Adding an app host to a running cluster: rerun postgres host, existing app
  host, new app host, ingest hosts, each with `--accept-topology-migration`.
  Going from one to two app hosts moves Valkey to the postgres host; JWT
  revocations are carried over, running searches are lost.
- Verify: `curl -fsS http://<app-host>/readyz` on each app host; exactly one
  jobs leader (`grep 'Jobs leader elected'` in nano-jobs logs, or one granted
  advisory lock `classid=20051 objid=1279607108` in `pg_locks`).

## Load balancer (operator-owned)

Point the app hostname at `nano-1:80` (or every app host, health-checked on
`GET /readyz`, with several app hosts), and the ingest hostname at
`nano-2:80` and `nano-3:80`. Health-check ingest on `GET /healthz`. The load balancer must replace `X-Forwarded-For` with the client
address and must not use the PROXY protocol. Use the HAProxy example in the
High availability guide (HAProxy 2.6 or later from the OS packages). Its
source address goes in `cluster.trusted_proxy_cidrs`. The load balancer
itself should be redundant: a managed load balancer, a keepalived pair, or two
HAProxy hosts behind health-checked DNS. One load balancer is a single point
of failure: say so ([cloud-vm.md](cloud-vm.md#7-load-balancer)).

## Firewall

The installer never changes the firewall. Propose rules and apply them only on
request, **before the first install** on any host with a public address.
ClickHouse and Keeper use host networking, so normal host rules (UFW
`INPUT`) cover their ports. The app, ingest and PostgreSQL ports (and, with
full HA, Patroni 8008, etcd 2379/2380, Valkey 6379 and Sentinel 26379) are
Docker-published and **bypass `INPUT`/UFW**, so restrict them in
`DOCKER-USER`:

| Port | On | Allow from |
|---|---|---|
| 80 (app) | nano-1 | load balancer |
| 80 (ingest) | nano-2, nano-3 | load balancer |
| 3000 private API | nano-1 | nano-2, nano-3 |
| 8687 tap relay | nano-2, nano-3 | nano-1 |
| 5432 PostgreSQL | nano-1 | nano-2, nano-3 (ClickHouse dictionaries) |
| 8123, 9000, 9009 ClickHouse | nano-2, nano-3 | all three hosts |
| 9181, 9234 Keeper | all | all three hosts |
| 22 SSH | all | management network, and nano-1 to the others for `scripts/nano upgrade` |

The `DOCKER-USER` rules drop only NEW connections to a published port that
arrive from outside the host (not `lo`, `docker0` or `br-*`) and from outside
the cluster; the load balancer may reach 80. Replies, this host's containers
(to each other, and outbound on the same port numbers: Patroni replication,
etcd peering) and every cluster host pass. UFW also needs allows **in on
`docker0` and `br-+`**: this host's containers reach the host-networked
ClickHouse/Keeper ports, and their own host's published ports, from a bridge
address. Persistence is a systemd unit (`nano-docker-firewall.service`), not
`iptables-persistent`, which uninstalls `ufw` on Ubuntu/Debian. The planner
prints the whole set for your addresses; run it on every nano host and every
HAProxy host:

```bash
python3 scripts/plan.py --hosts ./nano-deploy-work/hosts.txt <plan flags> --firewall-script > ./nano-deploy-work/firewall.sh
ssh $H 'MGMT_CIDR=<where the operator SSHes from> bash -s' < ./nano-deploy-work/firewall.sh
```

For a hand-made 3-node layout, the public guide's
[Host firewall](https://nano.rs/docs/getting-started/high-availability#host-firewall)
section has the same rules with variables to fill in. Re-run the script after
any address change, and test from outside with
`bash scripts/preflight.sh --exposure-probe <every host address>` (every row
`PASS`) and from one allowed source.

## Next

[verify.md](verify.md), including the HA checks.
