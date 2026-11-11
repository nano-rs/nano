---
name: nano-deploy
description: Deploy, size, verify, upgrade and operate nano Self-run (the licensed, self-hosted enterprise edition of the nano SIEM) on the operator's own Linux hosts over SSH, as a single node, a 3-node HA Docker Compose cluster, a fully highly available cluster of N VMs (existing VMs, or new ones on AWS, Azure or GCP, laid out from the data volume), or on Kubernetes with Helm. Use when asked to install, deploy, set up, size, plan, upgrade, update, back up, restore, add a node to, rotate certificates on, troubleshoot or collect a support bundle for nano / nano SIEM / nano Self-run, including requests like "deploy nano to 8 VMs", "…to 8 VMs in AWS", "update nano", "upgrade to 2.0.x" or "is there a new version of nano?".
license: AGPL-3.0-or-later
compatibility: Runs from the operator's workstation. Needs ssh, scp, python3 and bash locally; targets are Linux hosts reachable over SSH (or a Kubernetes cluster via kubectl and helm). Cloud VM deployments also use the operator's own logged-in aws, az or gcloud CLI.
metadata:
  product: nano Self-run
  tested-with: nano 2.0.x enterprise compose bundle
---

# nano Self-run deployment

You are deploying a security product on hosts that belong to the operator. Work
like a careful SRE: plan first, read before you write, ask before every change,
and never trade security for a green check.

The public guides at nano.rs/docs (Self-run install, High availability,
Custom multi-node layouts, Upgrade) are the authority. This skill follows them.
If the two ever differ, follow the guide and tell the operator about the
difference.

## Safety rules (always apply)

1. **Secrets never appear in your output, in files you commit, or on a command
   line.** That covers private keys, `.env`, the admin password, the license
   (enrollment) token, registry credentials, ingest tokens and backup keys.
   Move them as files (`scp`, mode `0600`) and read them on the host
   (`"$(cat file)"`, `set -a; . file`). Do not `cat`, `grep` or `echo` a secret
   file. To show `.env`, print key names only: `cut -d= -f1 .env`.
   Never ask the operator to paste a private key or token into the chat. Use
   their SSH agent or key path, and ask them to save other secrets to a file
   whose path they give you.
2. **Read-only first.** Preflight changes nothing. If any preflight row is
   `FAIL`, stop, report the gap, and wait. Do not continue past a failed check.
3. **Show the plan, then ask, before each mutating step.** Name the exact
   commands and the hosts they run on. One confirmation covers one step. It
   does not cover the rest of the deployment.
4. **Destructive commands need their own explicit "yes":** `docker compose
   down -v`, `docker volume rm`, `rm -rf` of an install or data directory,
   `pct destroy`, `scripts/nano restore --force`, `helm uninstall`, deleting
   PVCs, reformatting disks, `--accept-topology-migration`. Say what data is
   lost before you ask.
5. **Never weaken security to make something pass.** Do not run `install.sh`
   with `sudo`, `chmod 777`, disable TLS on a production inventory, set
   `NANO_SKIP_IMAGE_VERIFY=1`, set `NANO_LAB_ONLY_PLAINTEXT=1` outside a
   disposable lab the operator has named as one, use `--skip-backup-I-understand`
   or `--allow-siem-health-regression`, open the firewall wider than the port
   table, or edit the product's scripts. If the product refuses, report the
   exact error and the documented fix.
6. **Idempotent and resumable.** Every step can be re-run. Before acting, check
   what already exists (`~/nano/.env`, running containers, the
   `.nano-role.env` on a role host). Re-running `install.sh` keeps secrets and
   data. Never delete state to "start clean" without rule 4.
7. **Cloud resources cost money and are created only after the operator
   confirms the plan, then each provisioning step.** Use the operator's own
   logged-in cloud CLI. Never ask for, print or store cloud credentials or
   object-storage keys; the operator enters those in nano or in a file they
   name. Tag everything you create and list it in the work log.
8. Keep a local work log: `./nano-deploy-work/` on the operator's machine,
   created at mode `0700`. Write the intake record, the plan, preflight output
   and step results there. It holds no secrets; the secret files it points to
   live elsewhere. Do not commit it.

## Workflow

Follow the phases in order. Each phase ends at a gate where you report and wait.

### 1. Intake

Read [references/intake.md](references/intake.md) and ask its questions. Group
them, and skip what the operator has already told you. Record the answers in
`./nano-deploy-work/intake.md`. You need at least:

- target topology: single node, 3-node HA (Compose role split), or Kubernetes (Helm);
- hosts: address, SSH user, SSH key path or "use my agent"; the SSH user must be
  a non-root user with `sudo`;
- expected volume: EPS and/or GB/day, retention days;
- public hostnames, TLS approach and DNS;
- enrollment (license) values file (`LICENSE_URL`, `LICENSE_TOKEN`,
  `NANO_DEPLOYMENT_ID`), from app.nano.rs (Deployments, then your Self-run
  deployment). With it you download and verify the bundle and get a registry
  credential yourself ([scripts/fetch-bundle.sh](scripts/fetch-bundle.sh)); ask
  for a release version only if the operator pins one.

Size the deployment with `python3 scripts/size.py` (see
[references/sizing.md](references/sizing.md)) and show the result.

**N VMs, full HA** ("deploy nano to 8 VMs", "…in AWS / Azure / GCP"): do
not use `size.py`. Follow [references/cloud-vm.md](references/cloud-vm.md)
from start to end, in this order:

1. **Intake**, including section E: the list of VMs (name, address, vCPU, RAM,
   data disk, failure domain) or the cloud and region, the data volume, and how
   users and senders reach nano: a managed LB, an HAProxy pair with a floating
   IP, two HAProxy hosts behind health-checked DNS, or one HAProxy (a single
   point of failure).
2. **Layout:** `python3 scripts/plan.py --hosts hosts.txt ...` places the roles
   on the operator's VMs (stacking only as far as needed), or `--cloud ...`
   picks new VMs. It checks that losing any one VM keeps every quorum and a
   replica of everything. If the hosts are too small, it names the binding
   constraint (RAM, vCPU or disk) and refuses. `--lab` plans them anyway for an
   evaluation or test cluster, labelled NOT FOR PRODUCTION. Use it only when
   the operator names the cluster as one.
3. **Review the plan** with the operator: VM count and spares, the nano 2.0.7
   requirement, any `EXTRAPOLATED` figure, the load balancer, and, with one
   HAProxy host, that **the edge is a single point of failure**.
4. **Provision** (new cloud VMs only), **prepare** each VM (data disk at
   `/var/lib/docker`, time sync, Docker, and the **host firewall before the
   first install**: `plan.py ... --firewall-script`), **preflight** every host.
5. **License and download:** the enrollment values file from app.nano.rs, then
   `scripts/fetch-bundle.sh` downloads the bundle with them and verifies the
   release signature and checksum before anything is extracted; images are
   verified by digest at install.
6. **Install** in the order `plan.py --install-order` prints (PostgreSQL hosts,
   ClickHouse, app hosts one by one, ingest) with the plan's inventory, one
   private certificate for every address, and one shared `.env`.
7. **Load balancer:** both hostnames to the app and ingest backends with the
   plan's health checks.
8. **Verify:** smoke test through the load balancer, cluster health on every
   host, `preflight.sh --exposure-probe` from a machine outside the cluster
   (no database or cluster port may answer), then the **failover check**: one
   VM of each role stopped in turn while the smoke test still passes.

**Gate:** confirm the intake summary and sizing (or the N-VM plan) with the
operator. For N VMs, nothing is created or installed before this "yes".

### 2. Preflight (read-only)

Run [scripts/preflight.sh](scripts/preflight.sh) on every host, as described in
[references/preflight.md](references/preflight.md):

```bash
ssh -o BatchMode=yes USER@HOST 'bash -s' -- --topology single \
  --min-cpu 8 --min-mem-gib 30 --min-disk-gib 1500 < scripts/preflight.sh
```

It checks the OS, CPU and AVX2, RAM, disk, Docker and Compose versions, tools,
sudo, time sync, busy ports, peer reachability, registry egress and, on a role
split (`--topology ha`), whether Docker-published ports would be exposed on a
public address. It prints one `PASS`/`WARN`/`FAIL` row per check. Collect all
hosts into one table. After the install, run it once more from the
workstation with `--exposure-probe <every host address>`.

**Gate:** any `FAIL` means stop. Propose fixes (for example, install Docker
Engine from Docker's apt repository), and apply them only after the operator
approves each one. Then re-run preflight. Continue only on zero `FAIL`.

### 3. Deploy

Pick the path, then follow that reference step by step:

| Topology | Reference |
|---|---|
| Single node (Compose) | [references/single-node.md](references/single-node.md) |
| 3-node HA (Compose role split) | [references/multi-node-ha.md](references/multi-node-ha.md) |
| No single point of failure (6+ hosts, any one may die) | [references/full-ha.md](references/full-ha.md) |
| PostgreSQL + Valkey failover (2-3 postgres hosts) | [references/postgres-ha.md](references/postgres-ha.md) |
| Kubernetes (Helm) | [references/helm.md](references/helm.md) |
| N VMs, full HA (existing VMs, or AWS, Azure, GCP) | [references/cloud-vm.md](references/cloud-vm.md); new cloud VMs also [cloud-aws.md](references/cloud-aws.md), [cloud-azure.md](references/cloud-azure.md) or [cloud-gcp.md](references/cloud-gcp.md) |

Check [references/known-issues.md](references/known-issues.md) for the release
you are installing before you start.

Each reference lists its steps with the gate before each mutating step. The
Self-run order is always: **fetch and verify the bundle → stage it → prepare
(no services start) → add enrollment values → install → verify.**
**Kubernetes (Helm) does not use the compose bundle**: skip the bundle fetch,
get only the registry credential from
`GET https://api.nano.rs/api/license/self-run/registry-token?deploymentId=<id>`
with `Authorization: Bearer <license token>` read from the enrollment file
(the JSON `password` is the one-hour pull password; never print it), and follow
[references/helm.md](references/helm.md), which pulls the chart (presets and
digest-pinned image values inside) from the customer registry. With an
external (managed) PostgreSQL, run
[scripts/pg-preflight.py](scripts/pg-preflight.py) before `helm install`:
PostgreSQL 16+, `CREATE` on schema `public` for the nano user (on Azure
flexible server, `ALTER SCHEMA public OWNER TO nanosiem` as the admin), and the
extensions `pg_trgm`, `pgcrypto`, `uuid-ossp` (on Azure flexible server they
must be in `azure.extensions`).

**Get the bundle with the license values.** Run
[scripts/fetch-bundle.sh](scripts/fetch-bundle.sh) on the workstation (it needs
curl, python3 and OpenSSL 3; on macOS `brew install openssl@3`):

```bash
bash scripts/fetch-bundle.sh --enrollment ./nano-deploy-work/enrollment.env \
  --out ./nano-deploy-work/bundle [--version <V>] [--registry-cred ./nano-deploy-work/registry.cred]
```

It downloads `nano-compose-enterprise-<V>.tar.gz`, `.sha256` and `.sha256.sig`
through `GET /api/license/self-run/bundle` with the license token (never in
argv, never sent to the download host), then checks the pinned
release-signing-v1 key fingerprint, the signature on the `.sha256`, that the
signed `.sha256` is one line naming this bundle, and that line against the
bundle's own hash. It prints `VERIFIED` or exits non-zero and keeps nothing.
Never install a bundle it did not print `VERIFIED` for, and never substitute
`sha256sum -c`: it checks whichever file the `.sha256` names. With
`--registry-cred` it also writes a one-hour pull credential (password only,
`0600`); fetch it just before installing. A `401` means the license values are
wrong or the token was regenerated; a `402` names the billing reason (cancelled,
unpaid, trial over). A `404` on every request means the license API does not
offer this route yet: ask the operator for the three files. Without the license values, the operator downloads the
three files from the deployment's page instead; verify them the same way
(see the Self-run docs, "Get the bundle").

### 4. Verify

Follow [references/verify.md](references/verify.md). Done means all of these
are proven with real output, not assumed:

- the app and ingest health endpoints return 200;
- the admin can log in;
- the license is active (or you report exactly why not);
- a unique test event is ingested and then found by search
  ([scripts/smoke-test.py](scripts/smoke-test.py));
- on HA, Keeper has a quorum and every ClickHouse replica is healthy
  ([scripts/cluster-health.py](scripts/cluster-health.py)).

Report a table of the checks with their results. A failed check is reported as
failed, with the evidence.

### 5. Operate

For day-2 work, read [references/operate.md](references/operate.md):
backup and restore drills, adding a node, certificate rotation, and support
bundles (`scripts/nano support-bundle`, redacted; see
[When something goes wrong](#when-something-goes-wrong)). Upgrades: see below.

### Upgrade ("update nano", "upgrade to 2.0.x", "is there a new version?")

Follow [references/upgrade.md](references/upgrade.md). Start read-only with
[scripts/upgrade-plan.py](scripts/upgrade-plan.py): it reads every host (over
SSH, from the inventory) or every Helm workload (kubectl), the latest release
from `GET https://api.nano.rs/api/releases/latest`, and the license, health,
free disk and `.env` digests, then prints the ordered steps for this install.
Open with what it found, in this shape: "You're on 2.0.9, the latest is
2.0.11. What changes: <the release summary>. Release notes: <link>." Then
show its findings (any `FAIL` is a blocker), the path (from v2.0.10 or later:
`scripts/nano upgrade`; from v2.0.9 or earlier: an installer rerun per host;
Helm: `helm pull --untar` and `helm upgrade` with the same value files), and
ask before the backup, the dry run and the upgrade, one at a time.

### When something goes wrong

When a check fails, a command errors, or the operator reports a problem you
cannot resolve from [references/known-issues.md](references/known-issues.md):

1. Collect a support bundle right away, before restarting anything (restarts
   lose the evidence). On any one host of the install:
   `ssh $H 'cd ~/nano && scripts/nano support-bundle --since 24h'`. On a role
   split it reaches every host in `/etc/nano/inventory.yaml` over SSH (pass
   `--inventory FILE` if it lives elsewhere). Installs older than v2.0.11
   lack the command: stream the skill's copy per host instead
   (`ssh $H 'python3 -I - --install-dir ~/nano --local-only --out-dir ~' < scripts/support-bundle.py`).
   Helm: `python3 nano/scripts/nano-support-bundle --kubernetes --namespace NS --release REL`
   from the pulled chart (or this skill's `scripts/support-bundle.py`).
2. Copy the archive it prints to `./nano-deploy-work/` (`scp`). It is mode
   0600, redacted, and holds no event data or query results. Never open or
   send `.env`, credentials files or backup keys instead.
3. Read it yourself first: `MANIFEST.json` (hosts reached, collection
   errors), each host's `containers.txt` (restarts, OOM kills, unhealthy),
   `disk.txt`, `cluster-health.txt`, `clickhouse.txt` (`errors-recent`,
   `replicas-readonly`, `replication-queue`) and the ERROR lines in `logs/`.
4. Give the operator a short summary to send to nano support with the
   archive: the deployment ID and version (`release.txt`), the install ID
   (`MANIFEST.json`), what failed (the exact command and its last lines), when
   (with timezone) and whether it is still happening, what the bundle shows
   (for example "ch-2 is read-only since 14:02 UTC; Keeper lost quorum"), and
   what you already tried. Tell them to review the archive before sending
   (`tar -xzf FILE -O | less`) and to send it to support@nano.rs or their
   app.nano.rs ticket. In the UI, Help > Report a bug formats the browser
   side (failed request IDs, page, version) the same way.

To give the operator dashboards and alerts (optional, off by default), follow
[references/monitoring.md](references/monitoring.md): "Monitor your Self-run
install" for single node, role split and Helm.

## Stop and escalate

Stop and tell the operator, quoting the exact error, when:

- the product refuses an input (inventory validation, image digest mismatch,
  topology fingerprint, license refused);
- a step fails twice for the same reason;
- you would need to change product files, weaken a security setting, or delete
  data to proceed;
- the hosts differ from the intake (a different OS, missing disks, other
  services on required ports);
- a cloud call fails on permissions or quota: report it, never widen IAM
  yourself;
- `plan.py` refuses the VMs or a limit because full HA does not fit: quote the
  binding constraint it names (RAM, vCPU, disk or host count) and what would
  fix it. Never drop a replica or a quorum member to fit. Offer `--lab` only
  for a cluster the operator names as evaluation or test;
- you have no bundle: only someone with an app.nano.rs owner or admin login
  can fetch it;
- `preflight.sh --exposure-probe` shows a database or cluster port reachable
  from outside: stop the go-live until the firewall is fixed.

Suggest contacting nano support (nano.rs/docs/support) with the deployment ID,
the failing command, the time with timezone, and a redacted support bundle
([When something goes wrong](#when-something-goes-wrong)).
