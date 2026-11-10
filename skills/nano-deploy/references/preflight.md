# Preflight

Preflight is read-only and runs on every host before anything changes.

```bash
# single node
ssh -o BatchMode=yes $H 'bash -s' -- --topology single \
  --min-cpu 8 --min-mem-gib 30 --min-disk-gib 1500 < scripts/preflight.sh

# N VMs from plan.py: each host's exact flags (its requirement in this plan)
python3 scripts/plan.py <plan flags> --preflight-args > ./nano-deploy-work/preflight-args.tsv
tail -n +2 ./nano-deploy-work/preflight-args.tsv | while IFS=$'\t' read -r name addr flags; do
  ssh -o BatchMode=yes "<ssh user>@$addr" "bash -s -- $flags" < scripts/preflight.sh
done

# hand-made role split (per host: its roles and the other addresses)
ssh -o BatchMode=yes $H1 'bash -s' -- --topology ha --roles app,postgres,keeper \
  --peers <ip2>,<ip3> < scripts/preflight.sh

# after the install, from the workstation (a machine OUTSIDE the cluster)
bash scripts/preflight.sh --exposure-probe <every host address, comma-separated>
```

The thresholds have one source, the planner:

- With a plan, use `plan.py --preflight-args`. Each host gets its own
  requirement at your volume and retention, so a host the planner accepted
  passes, and one it would refuse fails.
- Without one, the role-split defaults are the planner's volume-independent
  floors, added up per role as the planner stacks them (a test keeps
  `preflight.sh` and `plan.py` equal). They are lower bounds, not the
  recommended sizes in the High availability guide's
  [Server sizing](https://nano.rs/docs/getting-started/high-availability#server-sizing)
  table.

| Roles | vCPU | RAM (GiB as reported) | Docker filesystem size (GiB) |
|---|---|---|---|
| `clickhouse` | 4 | 28 | 100 |
| `clickhouse` + `ingest` | 6 | 28 | 100 |
| `postgres` (+ `keeper`, and HAProxy beside it) | 4 | 12 | 100 |
| `app` | 4 | 14 | 50 |
| `app` + `postgres` + `keeper` | 8 | 26 | 150 |
| `ingest` only | 4 | 14 | 128 |
| `lb` only (HAProxy host) | 2 | 1 | 10 |

RAM is 87.5 % of the nominal GB, as the OS reports it (a 16 GB VM shows about
15 GiB). On a role split the disk check is the size of the filesystem that
holds the Docker data, the same figure the planner compares; `--min-disk-gib`
adds a free-space minimum. `--print-minimums` shows what a set of flags
resolves to. Single node keeps 4 vCPU / 14 GiB / 50 GiB free; pass
`size.py`'s numbers. For a lab
the operator names as one, `--lab` turns a below-minimum size into a `WARN`
marked "lab exception" (and `plan.py --lab` plans it). Record that exception
in the work log. Never lower the minimums silently. `--topology ha3` is still
accepted and means the same as `ha`.

## First connection

Use `ssh -o BatchMode=yes` so a missing key fails instead of prompting. On a
new host, show the host key fingerprint
(`ssh-keyscan -t ed25519 HOST | ssh-keygen -lf -`) and ask the operator to
confirm it before you accept it. Never use `StrictHostKeyChecking=no`.

## Reading the result

| Check | FAIL means | Typical fix (only with approval) |
|---|---|---|
| user | connected as root | create or use a non-root sudo user |
| cpu / memory / disk | below the size | resize the VM, add a data disk, or re-size the plan |
| avx2 | no AVX2 on x86-64 | VM CPU type `host` or `x86-64-v3` |
| tools | missing `curl`, `openssl`, `tar`, `python3`, `ss` (and `git` for single node) | `sudo apt-get install -y ...` |
| docker / compose | missing, daemon down, user not in `docker` group, Compose < 2.24.4 for role split | Docker's official repository; `usermod -aG docker`; new SSH session |
| peer | nodes cannot reach each other | private network or security group |

| Check | WARN means |
|---|---|
| virt=lxc | Docker in a container. Fine for labs; prefer VMs in production |
| time | clock sync not proven. `scripts/nano upgrade` refuses unsynchronized clocks, so fix it now |
| ports | something already listens. Fine only when it is this host's existing nano |
| existing | an install exists. Switch to the upgrade/re-run path and do not reinstall over it |
| enrichment | ClickHouse would get less than 6 GB. Geo/ASN enrichment will not load |
| egress | registry or licence endpoint unreachable. Fine only for air-gapped installs |
| exposure | the host has a public address and `DOCKER-USER` has no nano rules (or can't be read without sudo). Docker-published ports bypass UFW. Apply `plan.py --firewall-script` before installing |
| ufw | UFW denies incoming by default with no allow for `docker0`/`br-+` (or can't be read without sudo). This host's own containers then can't reach its ClickHouse, Keeper or etcd ports, the local replica is silently DOWN in clickhouse-proxy, and losing the other replica stops all writes. Apply `plan.py --firewall-script` |
| firewall-pattern | `DOCKER-USER` holds an earlier nano firewall pattern whose drops aren't limited to NEW inbound connections from outside (the first version also blocked this host's containers connecting out on those ports). Re-apply `plan.py --firewall-script` |
| firewall-persist | the `DOCKER-USER` rules are not installed as `nano-docker-firewall.service`, so they are lost at the next reboot. Re-apply `plan.py --firewall-script` |
| firewall-ufw | `iptables-persistent` is installed and `ufw` is not: installing it removed `ufw` and with it the ClickHouse/Keeper rules. Remove it, reinstall `ufw`, re-apply the script |
| cpu / memory / disk (`--lab`) | below the production size, accepted as a named lab exception |

| Probe row (`--exposure-probe`) | Meaning |
|---|---|
| `exposed:<addr> PASS` | no database, cluster or edge port answers from this machine |
| `exposed:<addr> WARN` | listed ports answer from outside the cluster. A go-live blocker for anything but 80 on a load balancer address: fix `DOCKER-USER` / UFW and probe again |

Present one table for all hosts. Stop on any `FAIL`.
