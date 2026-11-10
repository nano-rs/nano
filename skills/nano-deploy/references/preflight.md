# Preflight

Preflight is read-only and runs on every host before anything changes.

```bash
# single node
ssh -o BatchMode=yes $H 'bash -s' -- --topology single \
  --min-cpu 8 --min-mem-gib 30 --min-disk-gib 1500 < scripts/preflight.sh

# 3-node HA (per host: its roles and the other two addresses)
ssh -o BatchMode=yes $H1 'bash -s' -- --topology ha3 --roles app,postgres,keeper \
  --peers <ip2>,<ip3> --min-cpu 8 --min-mem-gib 30 --min-disk-gib 250 < scripts/preflight.sh
```

Use the minimums `size.py` printed. For a lab, the operator may accept
smaller hosts. Record that as an explicit, named exception in the work log.
Never lower the minimums silently.

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

Present one table for all hosts. Stop on any `FAIL`.
