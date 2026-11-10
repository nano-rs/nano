---
name: nano-deploy
description: Deploy, size, verify, upgrade and operate nano Self-run (the licensed, self-hosted enterprise edition of the nano SIEM) on the operator's own Linux hosts over SSH, as a single node, a 3-node HA Docker Compose cluster, or on Kubernetes with Helm. Use when asked to install, deploy, set up, size, upgrade, back up, restore, add a node to, rotate certificates on, troubleshoot or collect a support bundle for nano / nano SIEM / nano Self-run.
license: AGPL-3.0-or-later
compatibility: Runs from the operator's workstation. Needs ssh, scp, python3 and bash locally; targets are Linux hosts reachable over SSH (or a Kubernetes cluster via kubectl and helm).
metadata:
  product: nano Self-run
  tested-with: nano 2.0.x enterprise compose bundle
---

# nano Self-run deployment

You are deploying a security product on hosts that belong to the operator. Work
like a careful SRE: plan first, read before you write, ask before every change,
and never trade security for a green check.

## Safety rules (always apply)

1. **Secrets never appear in your output, in files you commit, or on a command
   line.** That covers private keys, `.env`, the admin password, the licence
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
7. Keep a local work log: `./nano-deploy-work/` on the operator's machine,
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
- release version, bundle location and its SHA-256, registry credential file,
  enrollment (licence) values file. All of these come from app.nano.rs
  (Deployments, then your Self-run deployment) or your nano contact.

Size the deployment with `python3 scripts/size.py` (see
[references/sizing.md](references/sizing.md)) and show the result.

**Gate:** confirm the intake summary and sizing with the operator.

### 2. Preflight (read-only)

Run [scripts/preflight.sh](scripts/preflight.sh) on every host, as described in
[references/preflight.md](references/preflight.md):

```bash
ssh -o BatchMode=yes USER@HOST 'bash -s' -- --topology single \
  --min-cpu 8 --min-mem-gib 30 --min-disk-gib 1500 < scripts/preflight.sh
```

It checks the OS, CPU and AVX2, RAM, disk, Docker and Compose versions, tools,
sudo, time sync, busy ports and peer reachability, and prints one
`PASS`/`WARN`/`FAIL` row per check. Collect all hosts into one table.

**Gate:** any `FAIL` means stop. Propose fixes (for example, install Docker
Engine from Docker's apt repository), and apply them only after the operator
approves each one. Then re-run preflight. Continue only on zero `FAIL`.

### 3. Deploy

Pick the path, then follow that reference step by step:

| Topology | Reference |
|---|---|
| Single node (Compose) | [references/single-node.md](references/single-node.md) |
| 3-node HA (Compose role split) | [references/multi-node-ha.md](references/multi-node-ha.md) |
| Kubernetes (Helm) | [references/helm.md](references/helm.md) |

Check [references/known-issues.md](references/known-issues.md) for the release
you are installing before you start.

Each reference lists its steps with the gate before each mutating step. The
Self-run order is always: **stage the bundle → prepare (no services start) →
add enrollment values → install → verify.**

### 4. Verify

Follow [references/verify.md](references/verify.md). Done means all of these
are proven with real output, not assumed:

- the app and ingest health endpoints return 200;
- the admin can log in;
- the licence is active (or you report exactly why not);
- a unique test event is ingested and then found by search
  ([scripts/smoke-test.py](scripts/smoke-test.py));
- on HA, Keeper has a quorum and every ClickHouse replica is healthy
  ([scripts/cluster-health.py](scripts/cluster-health.py)).

Report a table of the checks with their results. A failed check is reported as
failed, with the evidence.

### 5. Operate

For day-2 work, read [references/operate.md](references/operate.md):
upgrade (dry run and backup first), backup and restore drills, adding a node,
certificate rotation, and support bundles
([scripts/support-bundle.py](scripts/support-bundle.py), redacted).

## Stop and escalate

Stop and tell the operator, quoting the exact error, when:

- the product refuses an input (inventory validation, image digest mismatch,
  topology fingerprint, licence refused);
- a step fails twice for the same reason;
- you would need to change product files, weaken a security setting, or delete
  data to proceed;
- the hosts differ from the intake (a different OS, missing disks, other
  services on required ports).

Suggest contacting nano support (nano.rs/docs/support) with the deployment ID,
the failing command, the time with timezone, and a redacted support bundle.
