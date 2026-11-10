# Known issues by release

Check this before installing. Prefer the newest release. If an issue below
applies, tell the operator and use the documented handling. Never patch the
product's files.

## All 2.0.x releases

- **TLS overlay during first install.** With `docker-compose.tls.yml` active,
  plain-HTTP `localhost` calls get a 301 redirect, and the installer's health
  and admin-creation calls can treat it as success. Install first without the
  overlay, confirm the admin exists (`smoke-test.py` login passes), then
  enable the overlay ([single-node.md](single-node.md#step-9-public-tls)).
- **The installer needs the admin variables on every app-role run until setup
  is complete.** The prepare step writes `.env`, so the following install is a
  re-run. Pass `NANO_ADMIN_EMAIL`, `NANO_ADMIN_NAME` and `NANO_ADMIN_PASSWORD`
  again (the skill sources `~/.nano-admin-credentials`). Once setup is
  initialized, later runs skip admin creation.
- **Role split: `cluster.deployment_id` becomes `NANO_DEPLOYMENT_ID`.** The
  renderer writes the inventory's `deployment_id` into `.nano-role.env`,
  which overrides `.env`. Set it to the app.nano.rs deployment ID, or licence
  check-in uses the wrong ID.
- **Upgrade dry run and online licences.** In 2.0.x, `scripts/nano upgrade
  --dry-run` can refuse an install licensed online and report `C05 licence
  state is missing or expired`. Contact nano support before you upgrade. Do
  not bypass the check.
- **Role split: never put `ingest` on the `app` host.** On a host with both
  roles, the ingest Vector service re-owns the shared `vector-dynamic`
  volume (`chown 100:101`) that `nano-api` (uid 999) writes. The API logs
  `Vector configuration reconciliation failed ... Permission denied`, never
  publishes a config generation, the local `vector-config-consumer` stays
  unhealthy (HTTP 404, "no generation published"), and the install aborts
  before admin creation. Re-running does not help. Validated on 2.0.0; the
  same compose lines are on main. Keep ingest on dedicated or ClickHouse
  hosts. If an install already has app+ingest on one host, stop and contact
  nano support: removing a role changes the durable topology.
- **Role split: log-source deploy reports failure although it worked.** The
  app host has no local Vector, so `POST /api/log-sources/{id}/deploy` can
  answer `success=false` with "No reload was delivered to Vector", while the
  new configuration generation is still delivered to every ingest host (the
  ingest hosts' `vector-config-consumer` logs `Installed Vector config
  generation N`). Judge it by ingest followed by search, as `smoke-test.py`
  does. Do not "fix" it by adding ingest to the app host.
- **Small role-split hosts can saturate ClickHouse.** On 4 GB lab hosts the
  replica that serves the app hit `TOO_MANY_SIMULTANEOUS_QUERIES` (code 202),
  and `system.replicas` stopped answering. Size the hosts properly. The
  recovery is to re-run that host's role command, which recreates its
  containers.
- **Ingest stops when the app host is down (role split).** The ingest nodes'
  `/healthz` returns 503 about 15 seconds after the app API is unreachable.
  Make sure senders buffer and retry.
- **Docker in LXC containers** (Proxmox CT and similar) needs `nesting=1`
  (and usually `keyctl=1`) on the container. It is fine for labs. Use VMs in
  production.

## 2.0.0

- **Single node: the licence never checks in.** The 2.0.0 single-node compose
  does not pass `LICENSE_URL` and `LICENSE_TOKEN` to `nano-api` and
  `nano-jobs`, so the enrollment values in `.env` have no effect. Fixed after
  2.0.0. Use 2.0.4 or newer for a licensed single node. If the operator must
  run 2.0.0, install it, report "licence not active (2.0.0 single-node
  issue)", and plan the upgrade. Do not hand-edit compose files.
- **"Active" without a licence.** With no `LICENSE_URL` reaching the API,
  2.0.0 logs `License enforcement not configured (LICENSE_URL not set)` and
  `/api/license` reports `state=active valid=true` with no entitlement,
  expiry or licence ID. That is not a licence. `smoke-test.py` reports it as
  `WARN ... NO LICENCE BOUND`. Report it as unlicensed.
- **Fresh installs run under `umask 077`.** The 2.0.0 installer sets a
  restrictive umask before it generates non-secret configuration. Installs
  from a root-owned clone or checkout can leave ClickHouse restarting with
  exit code 233 (cannot read its config). The path in this skill (a non-root
  user, an extracted bundle) was validated on 2.0.0 without hitting it. It is
  fixed after 2.0.0. If it happens, stop and report it with `docker logs` of
  the ClickHouse container. Do not `chmod` product directories to work around
  it without nano support's guidance.
- **Enrichment memory on small hosts.** On a 12 GiB host, 2.0.0 sized
  ClickHouse to `6084M`, just under the 6 GB the enrichment dictionaries need.
  Ask the operator whether to set `CLICKHOUSE_MEM_LIMIT=6G` in `.env` and
  re-run the installer, or to turn the feeds off
  (`PLATFORM_FEEDS_AUTO_UPDATE=false`).
- **Kubernetes chart 2.0.0** takes the deployment ID through
  `nano.extraEnv` (`NANO_DEPLOYMENT_ID`), not `nano.deploymentId`.
  `scripts/helm-values.py` detects this from `helm show values`.

## Reporting a new issue

Collect a support bundle ([operate.md](operate.md#support-bundle)). Note the
exact command, its last 40 lines of output, the release and the time with
timezone, and stop. Add nothing to this file from guesswork. Only issues nano
has confirmed belong here.
