# Nano lake worker

This crate is the production Rust boundary around the native chDB engine. It
does not install or operate a ClickHouse server. The worker will remain a
separate process or pod so native crashes, memory limits, cancellation, and
tenant-pinned lifecycle do not compromise the Search/API processes.

`native::NativeChdb` loads a configured `libchdb` only after verifying its
exact SHA-256 digest. Startup also requires the stable C ABI symbols used by
Nano, including `chdb_query_with_params`; this prevents an older or substituted
artifact from silently falling back to SQL interpolation. The native artifact
is a versioned build input and must not be downloaded implicitly at runtime.

The default tests require no native library. Two ignored integration tests can
be run explicitly with a locally pinned artifact. The Iceberg test additionally
expects an isolated test snapshot and object-store credentials in the named
environment variables. Tests never log credential or source values.

### Search freshness notice

`NANO_LAKE_FRESHNESS_NOTICE_MIN_LAG_MS` configures the worker's display-only
`freshness_notice_min_lag_ms` threshold (default `300000`, five minutes).
Nonnegative integer milliseconds are accepted; invalid or negative values use
the default. Set `0` to show every consumer-lag warning. Restart the worker to
apply a change. Both interactive and isolated worker startup read this setting.

Served `publication_consumer_lag` below the threshold carries the watermark and
reason plus `completeness.freshness_notice_required: false`; at or above it the
flag is `true` and Search retains the existing warning text. Other degradation
reasons stay visible. This setting never changes serving verdicts, identity
checks, or `NANO_LAKE_TAIL_STALENESS_BUDGET_MS` (the hard serving budget).
There is no existing search-service publication-health settings path: Search
uses the worker's decision, including for SSE metadata, rather than maintaining
a second threshold. Roll out the worker, Search, and web images together; older
workers omit the flag and retain the previous warning behavior with new Search.

### Durable runner queue-namespace contract

`lake_job_runner` must poll the same Redis namespace the product search
service enqueues into. For a hosted shared tenant that namespace is
assignment-versioned (`search:{jobs:<tenant>:assignment:<rev>}:lake:queue:v2`),
so the runner requires `--assignment-revision`. A runner built from the
retained scope alone polls `search:{jobs:<tenant>:retention:<rev>:floor:<n>}:…`,
which nothing writes to, and never claims a job.

The contract is pinned by an ignored integration test in `nanosiem-core` that
needs only a throwaway Redis-compatible server (the local dev Dragonfly on
127.0.0.1:6379 works; so does `docker run --rm -d -p 6379:6379 redis:7-alpine`):

```sh
NANO_TEST_REDIS_URL=redis://127.0.0.1:6379 cargo test -p nanosiem-core \
  --test durable_queue_assignment_namespace_integration -- --ignored
```

It builds the store exactly as the search service does, enqueues a durable
job, proves the fixed runner construction claims it, and proves the pre-fix
construction (and a rotated assignment revision) never sees it. Each run uses
a fresh tenant id and purges its own keys.

The current production slice serves strict OCSF 1.9 broad nPL, field-name, and
typed `fetch_log` requests. It owns a bounded pool of persistent native
connections, each behind a bounded queue, enforces tenant and source-scope
fences, binds native parameters without SQL interpolation, and verifies the
immutable event manifest plus every serving artifact before accepting traffic.
The worker defaults to two connections so Nano's result and histogram
companions do not serialize. Deployments may set `--executor-connections` from
1 through 16; admission, CPU, memory, and S3 byte budgets still bound useful
concurrency.

## Query byte budgets

`tenant.max_query_bytes` is a per-query guardrail, not an ingest-volume or
retention cap. It must be provisioned per tenant/tier alongside admission,
worker memory, and query concurrency. Increasing it is appropriate when a
dedicated deployment intentionally permits larger analytical scans, but it is
not a substitute for partitioning or candidate indexes.

The planner applies the trusted query time range to `event_hour=<unix-hour>`
partitions before estimating base-generation and staged-tail bytes. Only
overlapping immutable objects count toward the preflight budget. Paths without
that partition remain conservative and count toward every window. chDB's
`max_bytes_to_read` remains set to the full configured guardrail, so the engine
still stops an execution whose real read exceeds the estimate.

Compiler-proven newest-first event retrieval through 24 hours does not reject
merely because the complete requested range exceeds this per-execution limit.
The worker reports the full estimate, then runs disjoint newest-to-oldest
windows: ten minutes first, followed by windows of at most one hour, stopping
as soon as the requested page is full. Every window is planned again with the
normal budget rejection and the same chDB hard limit. Nano also distributes a
compiler-proven terminal `stats/chart count(...) [by ...]` across disjoint
time ranges: it tries the complete range first, bisects only a range rejected
by the worker's scan planner, and exactly sums matching partial groups. The
page offset/limit is applied only after the complete merge. Other
aggregations, explicit re-sorts, and large transformed result sets keep the
single-plan contract and fail closed when over budget until they have an
explicit merge-state or rollup implementation.

This ordering is load-bearing for continuously growing tails: charging the
entire generation plus every tail object before applying the time fence causes
ordinary one-minute and one-hour searches to fail as soon as aggregate stored
bytes cross the guardrail. Deployers should alert on rejected estimated bytes,
actual bytes read, and the ratio between them; repeated large divergence is a
partition-metadata or planner bug, not a reason to disable the guardrail.

At production scale this must remain two separate controls. The hard
`max_query_bytes` value protects one worker execution and must be at least as
large as the largest physical time partition a worker is expected to read.
Interactive hunt/session cost needs a separate cumulative tenant policy across
all progressive slices. Broad transformations belong in an admission-gated
analytics lane with a deliberately larger limit or a generation-pinned rollup;
silently raising the interactive worker cap as retention grows is not the
deployment model.

`fetch_log` accepts only an event ID, an optional paired RFC3339 time range, an
optional canonical `metadata.log_source`, and Nano's denied-source set. It does
not accept nPL, SQL, object locations, or credentials. Internal native
diagnostics redact every bound value before logging.

Entity lookups use the generation-matched HMAC sidecar. Bare keywords use the
generation-matched Tantivy block postings, while `contains` and compiler-proven
regex literals use the distinct-term trigram accelerator. These are candidate
supersets only: the complete compiler-owned predicate always runs against the
original OCSF rows. Ambiguous, optional, alternated, or negated regex guards
fall back to the bounded source path. Complete negative index lookups produce
a zero-object/zero-byte plan.

The Python `lake_query_mvp.py` service remains the executable reference for
typed routes that have not yet moved here. It is not the intended product
runtime.

The first state route moved to Rust is Identity resolution. Its tenant-assigned
by-IP Parquet artifact is SHA-256 verified before startup, then size/mtime
fenced on every request. Single and batch request values remain native
parameters. Remote production publication must replace this trusted-local-file
stamp with the coordinator's exact object version; callers still never supply
the storage location.

## Publication bounds and high-rate deployments

The bronze admission limits are per-publication safety bounds, not tenant or
daily-ingest limits. One publication accepts at most 500 source files, 250,000
rows, and 1 GiB. `lake_bronze_publish --max-files` may select a lower file
target; it cannot exceed the reviewed absolute ceiling. The row and byte
ceilings deliberately remain fail-closed in the admission library.

Do not increase these bounds to provision a larger customer. Larger batches
increase peak memory, retry work, catalog-conflict cost, and the amount of data
held behind one failed commit. Capacity comes from:

- buffering writers into approximately 128-512 MiB serving Parquet objects;
- deterministic tenant/time/event-class or hash shards with exclusive input
  ownership;
- multiple admission, enrichment, compaction, and derivative workers sized by
  queue depth and publication lag;
- a coordinator that commits immutable results and exposes a generation only
  after its Iceberg snapshot and mandatory derivatives agree; and
- per-tenant fairness, byte budgets, backpressure, and a durable reconciliation
  path in addition to provider notification wakeups.

A 50 TB/day tenant averages roughly 580 MB/s before bursts. It therefore needs
horizontal writer and worker capacity. It must not depend on one publisher with
an enlarged in-memory batch. Dedicated Tenzir deployments may produce sized
Parquet and commit the shared Iceberg contract directly; Nano's Vector path
uses the same contract through the bronze admission lane.

The current `lake_bronze_publish` process intentionally serializes one
tenant/store pair with a PostgreSQL advisory lock. Deterministic same-tenant
shard ownership and its concurrent Iceberg commit/conflict tests are still a
deployment gate. Until that gate closes, do not claim that one bronze store can
serve 50 TB/day merely because the downstream stages are horizontally shaped.

## Freshness contract

Iceberg does not require minute-scale visibility. The current local validation
loop is serial and polling-based, so its observed freshness includes writer
flush, publisher polling, Iceberg publication, complete derivative rebuilding,
and worker activation. Those development polling values are not an acceptable
production Search SLA.

Production Search and seconds-cadence detections use two immutable inputs:

1. the latest fully indexed composite generation; and
2. a bounded, exact-version post-generation tail of admitted staged objects.

The worker scans the small tail as a signed exact-object Parquet list, unions it
inside the same compiled query with the indexed generation, and never exposes
the distinction to nPL or API callers. Tail objects and base objects are
disjoint, so stable event UIDs retain normal replay semantics without a second
UI/API mode. Bronze does not create one Iceberg snapshot per writer flush: it
publishes under a tenant-hashed table prefix and records each object's exact
version, digest, size, and row count in the durable ledger. The tail manager
signs that ledger view. A generation activation atomically moves covered tail
objects behind the indexed fence. The coordinator accepts an older generation
only while it remains an append-only ancestor and every base object is still in
the head; deletes, rewrites, or row-level delete files fail closed and require
a complete generation.

The tail signature key is the exact HMAC artifact installed with the indexed
generation. The generation builder and activation coordinator must never carry
independent key paths. Exact candidate objects and tail objects are read
directly rather than reopening Iceberg metadata for each selective query. The
active Iceberg snapshot authorizes base objects; the staged publication ledger
authorizes tail objects. One composite activation fence binds both sets and all
mandatory derivatives.

The intended normal target is a 2-10 second writer flush and 5-30 second
search/detection visibility. A hard event-by-event or sub-two-second SLA needs
a durable streaming log/runtime and is not provided by the object-microbatch
lane.

Nano's SSE contract remains storage-neutral. For ordinary event searches, the
primary-lake path emits the result page as soon as that scan completes while
the full-window histogram/count companion continues on the second native
connection. Field discovery remains a separate asynchronous request. The
histogram's summed buckets replace the page-bound `limit + 1` sentinel with an
exact base-predicate hit count before metadata is emitted; no lake tier or tail
state is exposed to the browser.

The local 50 EPS soak proved 15-second event visibility while the indexed base
was behind, including the active one-minute histogram bucket. After setting the
writer flush to five seconds and the local publisher poll to two seconds, six
steady-state probes observed 7.56-13.75 second event lag (10.69 second median)
and 0.41-0.54 second newest-row query time while six to ten tail objects were
merged. Moving selective base candidates and the tail to exact-object reads
reduced the measured warm IP lookup from about 1.15 seconds to 0.37-0.38
seconds on this corpus. A two-connection executor also reduced an exact
result-plus-histogram pair from 1.27 seconds serialized to a 0.99 second warm
median. This is development evidence, not the remote-cloud SLA. Provider
notification wakeups, deployment supervision, and the
compaction/delete/replay drill remain required before the freshness lane is
production-complete.

The Search field rail preserves the established two-stage interaction. Slim
table rows paint `Selected` immediately. `Show all fields` explicitly requests
a bounded full-shape sample, flattens nested OCSF objects and arrays into
canonical paths, and places populated mapped leaves under `Available`.
`Unmapped` contains only actual `unmapped.<key>` spill fields; it is never an
overflow label for hidden mapped fields. Expanding any individual field still
runs the exact full-window value query.

## Serving-file compaction

Do not commit few-second Bronze microbatches directly as long-lived serving
files. An Iceberg commit closes its Parquet file, so a 256 MiB rolling target
does not coalesce later commits. Nano keeps recent exact-version objects in the
signed hot tail. A transient tail packer physically merges already-admitted
same-hour Parquet after verifying exact versions, digests, sizes, row counts,
and the current Iceberg Arrow schema. It swaps the visible object set in one
PostgreSQL transaction without creating an Iceberg snapshot. The slower
compactor then registers a verified canonical pack directly with Iceberg, or
uses the decode/revalidate/rewrite fallback for legacy micro-object inputs.
Sized or age-bounded appends publish the Iceberg snapshot plus mandatory
derivatives behind one composite-generation fence.

Compaction is partition-bounded. It must not replay a tenant's full history,
infer a tenant-wide schema, or enlarge the 500-file/250,000-row/1-GiB admission
bounds. Use the pinned OCSF 1.9 physical contract, deterministic hour/shard
ownership, hard memory and byte budgets, and observable queue age. Schema
changes create a separately fenced generation; they are not routine
compaction.

The local v16 snapshot is a negative fixture for this rule: about 180 MiB was
spread across 663 data files with 1,984 Iceberg metadata objects behind one day
partition. Authenticated cache-bypassed Search API medians were 1.216 seconds
for one hour and 1.980 seconds for four hours. Result-only medians were 1.021
and 1.726 seconds, proving the physical result scan, not API routing or the
histogram, was the dominant latency.

The bounded v17 replacement committed the same serving generation as 13 hourly
files (110,849,124 bytes) and four Iceberg metadata objects. With result rows
given worker priority before the exact histogram companion, authenticated
cache-bypassed medians were 192 ms to first rows for one hour and 565 ms for
four hours. Exact histogram/count metadata followed at 441 ms and 1.030 seconds
respectively. Preserve this row-first SSE contract: the UI must not wait for
histogram/count or field discovery before painting the result page.

The generation manager promotes only snapshots whose summary contains
`nano.generation-ready=true`. Bronze and product-outbox appends omit that
property and therefore remain in the bounded signed hot tail even while the
Iceberg head advances. A closed-hour compaction/rewrite commit sets the fence;
the manager selects that newest marked ancestor, hydrates that exact snapshot,
builds every derivative, and activates the composite generation. Never promote
each live append: doing so recreates the small-file layout and rebuilds all
sidecars continuously.

## Object-store portability

RustFS is the local and open-core S3-compatible implementation, not a runtime
dependency of the query architecture. AWS S3 and a conforming S3-compatible
store use the current adapter directly, including immutable VersionId reads.
The Iceberg, Parquet, signed-generation, sidecar, pack, and compaction contracts
are provider-neutral.

Native Google Cloud Storage and Azure Blob support still require explicit
adapters. GCS generations and Azure blob version IDs are not interchangeable
with S3 `versionId`, and their credential, URL, notification, and conditional
write APIs differ. Do not label the current S3 implementation as drop-in
multi-cloud support. A storage-provider boundary must map exact object
identity, immutable read/write, HEAD/stat, notifications, and delete/retention
semantics, followed by the same overwrite/replay/compaction/activation drills
on each provider. An S3-compatibility facade may be used for experiments but is
not the native production portability claim.
