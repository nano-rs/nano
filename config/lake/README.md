# Nano open-core lake control plane

This directory contains the singleton control-plane configuration for a fresh
open-core deployment of Nano's OCSF 1.9 object lake:

- one RustFS object-store process;
- one Hydra OAuth2 workload-identity process;
- one OpenFGA authorization process;
- one Lakekeeper catalog process; and
- separate databases and roles on Nano's existing PostgreSQL server.

This is intentionally **not HA**. It is the durable single-host installation
shape for open-core users. Restart policies and persistent volumes recover
process failures, but a host, PostgreSQL, or RustFS failure interrupts service.

Nano's paid production deployment uses the same protocol and data contracts but
runs replicated stateless catalog/auth APIs behind load balancers, HA
PostgreSQL, and distributed RustFS or a managed cloud object store. Do not add
multiple same-host replicas here and call that high availability.

The forward product contract is OCSF 1.9 + Iceberg/Parquet + embedded chDB. chDB
embeds the ClickHouse query engine; no ClickHouse server or ClickHouse database
cluster is required. Existing UDM/ClickHouse installations remain a separate
security-maintenance line and are not upgraded in place. Moving to this model
requires a fresh installation and log repoint.

`warehouse.json` deliberately contains no credentials. The Rust bootstrap reads
RustFS credentials from named environment variables and injects them only into
the Lakekeeper management request. Hydra's admin API and OpenFGA are internal
services and must never be exposed through the public reverse proxy.

`install.sh` makes the `lake` profile the default for new installs
(`NANO_ENABLE_LAKE_CONTROL_PLANE=1`, `COMPOSE_PROFILES=lake`). That default
only works once the three lake images it deploys, `ghcr.io/nano-rs/nano-lake-control`,
`nano-lake-query` (the native chDB worker) and `nano-lake-maintenance`, are
published to GHCR as anonymously pullable multi-arch images and recorded in
`images.lock`. Until then the installer fails closed: `compose pull` cannot
fetch them, and the digest check refuses any first-party image that
`images.lock` does not cover. `build-and-push.yml` (`merge-manifests`) publishes
all three and writes their lock lines on an open-core release, alongside
`nano-api`, `nano-search`, `nano-jobs` and `nano-web`;
`scripts/check-opensource-pins.sh` fails if the compose file deploys a
first-party image that release job does not publish.

## Object-store upgrades

The `lake-object-store` service pins RustFS by digest (`images.lock` mirrors
the pin). Older installs ran `rustfs/rustfs:1.0.0-rc.1`; current
installs run stable `1.0.1` (the same musl image variant).

The upgrade from rc.1 is in place, with no migration step. RustFS 1.0.1 opens
an rc.1 `nano-lake-object-data` volume as-is: existing objects, object versions
and the bucket's versioning setting are kept, and new writes work at once. The
environment contract (`RUSTFS_VOLUMES`, `RUSTFS_ADDRESS`,
`RUSTFS_CONSOLE_ENABLE`, `RUSTFS_CONSOLE_ADDRESS`, access and secret key) and
`GET /health` (HTTP 200 when serving) are unchanged. 1.0.1 drops the `ready`
field from the health body, and nothing in Nano reads it.

To upgrade, re-run `install.sh` (or `git pull` and
`docker compose -f docker-compose.opensource.yml up -d`). Compose recreates
only the containers whose image changed. Lake writers retry while the object
store restarts. Events that Vector has already accepted wait in its disk
buffer, so nothing is lost. Search fails while the object store is down and
answers again within seconds of it coming back, without restarting the query
worker. A recreated container gets a new bridge IP, and embedded chDB caches
DNS answers with no TTL, so the worker drops that cache every 5 s
(`NANO_CHDB_DNS_REFRESH_SECONDS`, `0` disables) and after any failed object
read. Before that fix, a stale address held the worker's single
native lane for about two minutes until its watchdog restarted the worker.
Verified on a lab install: data written under rc.1 stayed
searchable after the upgrade, and new writes landed at once. Do not run
`docker compose down -v`, because it deletes the lake volume.

## Query-worker capacity contract

Every generated tenant worker configuration must set `tenant.max_memory_bytes`
deliberately. The Rust worker accepts 64 MiB through 64 GiB and retains a 4 GiB
compatibility default for older generated configs, but that default is not a
deployment sizing decision. The open-core development profile starts at 2 GiB
per query lane through `NANO_LAKE_MAX_MEMORY_BYTES`; the generation manager
copies that operator value into every signed activation. Provisioned memory
must exceed:

`executor connections * max_memory_bytes + measured resident footprint + headroom`

The local two-lane validation reached a 7.5 GB physical-memory peak and settled
near 1.9--2.2 GB RSS with the 4 GiB-per-query default. Shared deployments should
use a smaller per-query ceiling and horizontal workers; dedicated workers may
use a larger ceiling only with matching pod limits. `NANO_LAKE_EXECUTOR_CONNECTIONS`
and `NANO_LAKE_MAX_MEMORY_BYTES` must therefore be sized together. The
worker rejects an invalid ceiling at startup and reports the active value in
both `/health` and `/ready`.

Every long-lived query and maintenance container also has a Compose memory and
PID ceiling. These ceilings are intentionally overrideable through the
`NANO_LAKE_*_MEM_LIMIT` and `NANO_LAKE_*_PIDS_LIMIT` values documented in
`.env.opensource.example`, but they are never disabled. An OOM is a visible,
restartable failure; unconstrained native growth that consumes the host is not
an acceptable recovery strategy. Container ceilings are not reservations, so
the isolated durable runner can retain a large maximum without consuming that
memory while idle.

## Hot-tail packing contract

Near-real-time Search reads the signed tail before a serving-generation
checkpoint exists, so object count matters independently of bytes. The tail
packer treats transient packs as immutable size-tiered merge runs. Four raw
writer objects become a level-zero pack by default, four same-level packs merge
into the next level, and a raw remainder also packs when its oldest object
reaches `NANO_LAKE_TAIL_PACK_MAX_AGE_SECS` (60 seconds by default). A pack is
never merged with every later raw batch. This keeps event-hour rollover from
exposing dozens of tiny remote objects while bounding rewrite amplification to
logarithmic levels rather than repeatedly rewriting the full active hour. The
Iceberg compactor registers exact packs, and generation activation later
removes their source rows from the signed tail.

Do not tune the pack age and count independently of the writer flush interval,
Iceberg compaction age, and generation cadence. Readiness should alert when the
signed tail exceeds its configured object/byte bound or its oldest staged
object exceeds compaction age plus build grace. Enterprise and shared-tier
capacity tests must include selective IOC queries during an hour rollover, not
only after a clean generation activation.

The open-core startup defaults to a one-second Bronze discovery poll behind
Vector's five-second durable flush and a 500 ms signed-tail publication poll.
The validated steady-state freshness envelope is therefore seconds, not the
15-minute generation cadence. Larger deployments should replace discovery
polling with their provider notification queue while preserving the same exact
object-version admission contract.
