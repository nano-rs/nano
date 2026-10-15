# Open-core lean installation

The default open-core profile is `lean`: PostgreSQL, Dragonfly, RustFS, one
single-tenant cell, persistent local OTLP telemetry, lean enrichment, and
Redis-fenced cell jobs. No gen1 catalog, generation, or query worker runs.
Hosted manifests are independent.

Release prerequisite: identity/routing, detection/audit, trusted-local GC,
OTel, durable jobs, and the cell image ship together in one release. The
release publishes `ghcr.io/nano-rs/nano-lake-cell` and records its actual
manifest digest in `images.lock`. A compose profile alone does not prove parity
or installation.

```sh
NANO_NONINTERACTIVE=1 NANO_ADMIN_EMAIL=admin@example.com \
NANO_ADMIN_NAME=Administrator NANO_BASE_URL=http://localhost \
./install.sh --non-interactive
```

Use environment configuration for an operator-supplied admin password.
Unattended output omits bootstrap passwords and ingestion tokens. Docker Compose
2.24+ and Python 3 are required. `lean-init` calls lane A's `nanosiem-lake-cell
trusted-local init`; shell code generates no tenant ID or cell keys. Reruns
reuse identity. The initializer sizes cell budgets from host capacity. Back up
`.nano-lean` alongside PostgreSQL, RustFS, `nano-lean-cell`, and `nano-lean-otel`.

The installer probes isolation with the runtime capability set, read-only root,
and writable `/run`. Missing Landlock warns only on dedicated trusted-local;
hosted checks stay strict. Other UID/capability/seccomp/isolation failures refuse
startup. SYS_ADMIN supports a private cgroup mount; no privileged container is
requested.

## Ingest modes: Vector, Tenzir-direct, or both

| Run | Ingest | `.env` |
|---|---|---|
| `./install.sh` (default) | Vector (HTTP `/ingest`, HEC, OTLP, pull connectors) **and** the OCSF bucket drop | `NANO_VECTOR_PROFILE=lean` |
| `./install.sh --tenzir` | Tenzir-direct: the bucket drop only, no Vector | `NANO_VECTOR_PROFILE=none` |
| `./install.sh --add-vector` | back to the default, on a Tenzir-direct install | `NANO_VECTOR_PROFILE=lean` |

A re-run without either flag keeps the recorded mode (re-runs are upgrades and
must not change the topology). Both side by side is the default, because
`lean-landing` runs in every lean install: Tenzir can drop OCSF files into any
of them.

`--tenzir` leaves the `vector` and `connector-runner` services out of the lean
stack (their compose profile is `${NANO_VECTOR_PROFILE:-lean}`) and removes
their containers on a switch; their volumes stay, so `--add-vector` restores
them. Without Vector:

- **Not offered:** HTTP `/ingest`, HEC (`:8088`), OTLP (`/otlp`, `:4317/4318`),
  Vector native (`:6000`), fluent (`:24224`); nginx answers 502 on `/ingest`
  and `/otlp`. Pull connectors and directory (identity) sync deliver through
  Vector and are not available. Parser deploys have no Vector to render into.
  Synthetic checks report over Vector's OTLP and do not run.
- **In the app:** `/api/capabilities` reports `ingestMode: "tenzir_only"`.
  The web UI leads Log sources with the bucket drop key flow and disables the
  surfaces above with the note "This install ingests via Tenzir; re-run
  install.sh --add-vector to enable". The API refuses their mutations with
  `409 VECTOR_NOT_INSTALLED` (reads, deletes, revokes, pauses and undeploys
  stay open for cleanup).
- **Kept:** the lake cell, `lean-landing`, the enrichment coordinator (IPinfo,
  tenant IOCs, prevalence), `lean-otel`, and the platform audit lane, which
  has its own private Vector (`lean-audit-vector`).
- **Unchanged:** `VECTOR_AUTH_TOKEN` is still generated and kept in `.env`
  (nginx's OTLP map reads it, and `--add-vector` reuses it); the installer
  does not print it in this mode.

Next step after a `--tenzir` install (the installer prints it):

```sh
docker compose -f docker-compose.opensource.yml run --rm lean-landing-admin add --name tenzir-sysmon
```

It prints the source's write-only key and a ready-to-paste Tenzir `to_s3`
sink once. Run Tenzir on the host's compose network, or use the bundled node
(`.nano-tenzir/pipeline.tql`, seeded from `tenzir/lean/sysmon-bucket.tql`;
`docker compose -f docker-compose.opensource.yml --profile tenzir up -d
tenzir`, pinned `tenzir/tenzir:v6.19.1`). See `tenzir/AGENTS.md`.

The former `NANO_SCHEMA_PROFILE=ocsf+tenzir` (a bundled Tenzir writing to
ClickHouse) is refused: ClickHouse is gone.

## Existing ClickHouse installs: fresh install only

The ClickHouse edition is retired and cannot be upgraded in place.
On a ClickHouse install (`.env` with `NANO_LOG_QUERY_BACKEND=clickhouse`, the
`legacy` compose profile or ClickHouse credentials and no lean settings, or a
ClickHouse container or `nano-clickhouse-data` volume in the compose project),
`install.sh` stops before it updates the checkout, pulls, migrates, or restarts
anything, explains why, and exits non-zero. There is no override, and
`NANO_FRESH_LEAN_CUTOVER` does not apply to it. New installs cannot select
ClickHouse either (`NANO_ENABLE_LAKE_CONTROL_PLANE=0` and
`NANO_SCHEMA_PROFILE=udm` are refused).

To move to the lake edition:

1. Back up what you want to keep: copy out the detection rules, saved
   searches, and results you need from the web UI, and keep a copy of `.env`.
2. Stop the old stack with `docker compose -f docker-compose.opensource.yml
   down`. Its volumes (ClickHouse events, PostgreSQL) are kept; `down -v`
   would delete them.
3. Install into a new directory so the new stack gets its own volumes:
   `curl -fsSL https://get.nano.rs | NANO_INSTALL_DIR=$HOME/nano-lake bash`.
   To reuse the old directory, delete it and its volumes first.

Nothing is migrated: the new install starts empty, and the old data stays in
the old volumes until you remove them. The last ClickHouse source is the
`legacy/clickhouse` branch and its last images are tagged `0.1.703`; it is
unsupported and gets no fixes.

## Fresh gen1 lake cutover

This applies only to a gen1 lake install (`COMPOSE_PROFILES=lake`). Back up
checkout, `.env`, PostgreSQL and data volumes. In a maintenance window:

```sh
NANO_FRESH_LEAN_CUTOVER=1 ./install.sh --non-interactive
```

A gen1 install on PostgreSQL 17 stops at the PostgreSQL major-version guard
before anything changes. Upgrade the data offline first, then re-run the same
command (the cutover resumes):

```sh
docker compose -f docker-compose.opensource.yml --profile '*' down
scripts/upgrade-postgres-major.sh -f docker-compose.opensource.yml --yes
NANO_FRESH_LEAN_CUTOVER=1 ./install.sh --non-interactive
```

The installer saves `.env.pre-lean.<UTC timestamp>` with its private mode, stops
prior compose services of every profile (including Tenzir) without deleting
volumes, and selects lean. Its first
initializer run creates a UUID tenant. Gen1 bronze, Iceberg, generations and
ClickHouse history are not adopted. Metadata remains in PostgreSQL; verify
rules/sources/dashboards before resuming producers. Keep old volumes until
search, telemetry, jobs, detection and audit checks pass. Rollback requires the
old release/compose and saved environment; stop lean before restoring them.

OTLP logs use Vector's OCSF bronze path and the listing queue. Metrics/traces
use persistent native Parquet and existing UI query APIs. Full storage applies
retryable backpressure rather than evicting acknowledged records. Vector buffers
retries durably. Batch receipts (about 65 bytes each) dedupe Vector retries
and expire after a 7-day retry window.

Retention reads the open UI's system settings. Part GC requires a complete log,
removal grace, immutable content identity and local prepare/receipt protocol.
Bronze deletion additionally requires the queue's durable consumed-and-settled
watermark. Unreadable settings/cursors retain bytes. Job results use the UUID's
canonical RustFS result bucket and Redis claim/lease/fence checks, without gen1.

For acceptance, use an isolated checkout, unique `COMPOSE_PROJECT_NAME`, and
unused public ports. Keep image verification enabled. Clean up only that scratch
project with `docker compose ... down --volumes --remove-orphans`; never apply
that command to the installed project's data.

Lean object bootstrap suspends bronze and durable-result bucket versioning so
ordinary retention deletes reclaim the fresh tenant's data. This also handles
a gen1 `nano-lake` bucket created with versioning enabled. Suspension preserves
old numbered versions for rollback; it does not remove previous history. See
[RustFS versioning](https://github.com/rustfs/docs.rustfs.com/blob/main/content/en/administration/data/object/versioning.md).

The initializer UUID also selects a new Dragonfly metadata volume. Fresh gen1
cutover never reloads legacy durable-job snapshots into the lean runner. Reruns
with the same UUID reuse its durable queue; the old snapshot volume is retained
for rollback. `NANO_DRAGONFLY_DATA_VOLUME` is installer-owned after bootstrap.

## Release notes: changes operators must act on

- **OTLP ports 4317/4318 bind to 127.0.0.1.** Vector's OTLP source has no
  authentication, so the raw gRPC and HTTP ports now listen on loopback only.
  Remote senders use OTLP/HTTP through nginx at `<base>/otlp` with the ingest
  token (`Authorization: Bearer <VECTOR_AUTH_TOKEN>`); a missing or wrong token
  gets 401. To re-expose the raw ports on a network where unauthenticated OTLP
  (including gRPC) is acceptable, set `NANO_OTLP_BIND_ADDRESS=0.0.0.0` (or one
  interface address) and re-run `./install.sh` or `docker compose up -d`; the
  installer persists the value in `.env`.
- **Vector native :6000 and Fluent Forward :24224 bind to 127.0.0.1.** Neither
  checks the ingest token. On-prem Vector aggregators should ship
  with an `http` sink to `<base>/ingest` (or HEC) and the token. To re-expose a
  raw port on a trusted network, set `NANO_VECTOR_NATIVE_BIND_ADDRESS` or
  `NANO_FLUENT_BIND_ADDRESS` to `0.0.0.0` (or one interface address) and re-run
  `./install.sh` or `docker compose up -d`; the installer persists the values.
- **Containers are no longer named `nano-<service>`.** Address them through
  compose, for example `docker compose -f docker-compose.opensource.yml logs
  nano-api` or `... exec nginx nginx -s reload`. Several installs can share a
  host with distinct `COMPOSE_PROJECT_NAME` values.
- **Image pins.** `NANO_VERSION` is pinned from `images.lock` (never `latest`);
  `latest` stays on the frozen ClickHouse 0.1.703 release.

## Pull feeds

The `connector-runner` service ships the declarative Rust connector engine in
both the `lean` and `lake` profiles. Open the **Ingestion → Pull feeds** page to
create an Okta System Log or Slack access-log feed. First add an exact
`source_type` routing rule for the spec lane to the HEC source configuration
and deploy it. Then deploy an enabled OCSF HEC parser with match values containing the spec's lane (`okta` or
`slack_access_log`) in Log Sources. Creation
and resume refuse an undeployed lane so a feed never starts into the router's
drop path. Supply the vendor credential
and the local HEC ingest token configured as `VECTOR_AUTH_TOKEN`. Tokens are
sealed with the deployment encryption key in PostgreSQL and are never returned
by feed reads. Back up PostgreSQL and keep the encryption key unchanged on upgrades.

New feeds start point-forward with the engine's five-minute overlap; they have
no historical backfill setting. Per-stream cursors are persisted after Vector's
HEC acknowledgement confirms delivery, so restarting the worker resumes the
saved cursor. Pause prevents new runs; a run already in flight finishes. Delete
removes the feed and its saved cursor. Creating another feed starts a new cursor.

`CONNECTOR_POLL_INTERVAL_SECS` defaults to 30; `CONNECTOR_MEM_LIMIT` defaults to
2G. The installer starts the runner and waits for its heartbeat health check.
The standard release workflow builds both architectures and adds
`ghcr.io/nano-rs/nano-connector-runner` to the generated `images.lock`.

For isolated lab validation only, a dedicated runner can set
`CONNECTOR_TEST_MODE=1` and `CONNECTOR_TEST_MOCK_URL=http://127.0.0.1:<port>`.
This reuses the preview tool's loopback mock transport while retaining each
spec's vendor host policy. Only loopback IPs are accepted, and shared mode
refuses this transport. Use synthetic vendor credentials in that test mode.
