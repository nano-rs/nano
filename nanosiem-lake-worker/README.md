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

## Ingest stage diagnostics

The existing tenant ingest heartbeat's `ingest_diagnostics` includes default-on,
process-local timings. It adds no configuration, route or provider operation.
The original buffered/oldest-stage gauges and native started/completed counters
retain their meaning. A fresh production `Ingestor::open` initializes occupancy;
short stage transitions remain visible after the next heartbeat.

| Field | Meaning |
| --- | --- |
| `oldest_flush` | Current oldest flush's stage, input `rows`/`arrow_bytes`, built part count/rows/file bytes and bounded transition history |
| `last_completed_flush` | Most recently ACKed flush's completed history, retained until another flush completes |
| `flush_stage_timings` | Cumulative stage residence, including any wait/retry residence before a transition |
| `operation_timings` | Part-file upload, signature-payload staging, signature batch, provenance/cache publication, Add append and actual prevalence-apply scopes |
| `native_writer.timings` | Per-attempt authorize/complete/PUT scopes plus separate pacer wait (lock and sleep) |
| `occupancy` | Configured/effective flush depth, queue range capacity, filling/flight rows and bytes, reservations/budget, held notices and structural/resource constraints |
| `queue_sample` | Count/limit from the existing bounded pending-notice read; `may_be_truncated` does not claim a total backlog count |

All times are monotonic. Each timing has `in_flight`, `finished_total`,
`elapsed_us_total`, `max_us`, `last_us`, `bucket_upper_us` and `bucket_counts`.
Buckets are disjoint (1/10/50/100/500ms,1/5s,overflow); `null` is the open-ended
last upper bound. Histograms count terminated scopes, including failure and
cancellation, with in-flight elapsed excluded until termination. Native legacy
completion counts still distinguish successful parsed replies/PUT200s. Request
latency includes response-body/JSON handling for owner calls; PUT ends at response
headers, before its separate owner completion call. Pacer wait includes time
waiting for the pacing mutex and timer and is excluded from request latency.
Retry backoff is outside each native HTTP scope.

Stage history keeps the last32 transitions with a dropped count, never an
unbounded trace. Rows/Arrow bytes describe the sealed input; part-file bytes
exclude signed provenance generated later. Foreground and background flights
retain independent histories; younger work cannot relabel the oldest. Stage
residence and nested operations overlap and must not be summed as independent
wall time. Native timings include other writes sharing that writer (e.g. merges)
and are not automatically attributable to the oldest flush. Missing timing labels
mean the operation has not run in this process. Counters reset on process restart;
compare deltas only within one PID/epoch. Atomic timing snapshots are diagnostic,
not a transactional ledger. Occupancy/queue sample ages continue increasing when
an ingest tick stalls; they are sampled state, not fresh provider reads.

Only numeric counts/times, booleans and static code-defined stage/operation labels
are emitted. No tenant, source/object/part IDs, event values, URLs, keys, signatures
or raw errors enter these timings. Each production constructor owns its handles;
no process-global telemetry shares one tenant's measurements with another.
Heartbeat reads never take the mutable ingest lock or hold timing locks across IO.

The diagnostics themselves only observe the pipeline: they add no object-store
reads/writes and do not change batching, ordering, ACKs, fences or owner pacing.
Histories are bounded and cumulative metrics have a fixed set of code labels;
existing heartbeat payloads grow slightly. The flush depth they report is set by
the bounded overlap described in the next section.

The default library tests share one process and CPU allocation. Timed prevalence
admission scenarios take an exclusive test-only workload guard; large analytical,
heap and wide-part component fixtures use shared guards. This preserves the full
five-second/3,500-row admission-plus-flush assertion without charging another
fixture's million-row CPU experiment to that bound. Unrelated tests remain
parallel; there is no deployment setting or change to production scheduling.
GC read-ahead tests use a controlled Tokio clock to exercise entry-cap and early
time-cut paths independently, with cancellation-safe fixture occupancy. The
production two-second, byte and entry bounds are unchanged.

## Bounded flush overlap

Catch-up ingest keeps at most **two** sealed flushes in flight per tenant
(`MAX_FLUSH_DEPTH`), plus the memory-budgeted filling buffer. This is the coded
production path: the constructor defaults are `flush_depth = 2` and
`commit_when_ready = true`, and the retired rollout switches are no
longer read or forwarded (the supervisor drift test guards both names). There is
no environment switch or default-off rollout.

The effective depth is derived per tick, never configured by hand. It is one
(the serial contract) unless all of these hold: the cell supplied the background
store and signer; the queue allows two outstanding ranges (the cell opens the
edge source with `edge_source_config(MAX_FLUSH_DEPTH)`, whose pulled-bytes
allowance stays the single-flight 64 MiB); admission is not paused by the
over-commit hold; the catalog attachment is not degraded; and no erasure order or
step is active. A second seal additionally needs rows, no rejections/skips/
replays, no pending schema growth, no partially committed buffer, and its full
minimum build/writer reservation must fit beside the earlier flights and merges.
The one-object progress escape stays on the serial path.

Order is unchanged: only the oldest flight appends its `add` and ACKs, so seal
order is `add`, edge-range and ACK order; a younger flight that finished first
waits. A finished publication wakes the single part-log owner immediately.
Prevalence still applies in part-log cursor order inside the oldest commit.

Native writes share one 32-permit envelope per production writer
(`NativePartWriter::write_guard`), across overlapping publications, merges and
part-log appends. A permit is taken per write (never a partial group), released
on success, failure or cancellation, and waited on under the fixed timing label
`write_slot_wait`. Owner pacing and its EPS-derived interval are unchanged.

Cancellation: the oldest flight stays at the front of the in-flight queue across
every await (its task is awaited by reference, its immutable output and memory
reservation stay owned) and leaves only after its ACKs land. Serial flushes keep
their built output the same way. If an `add` committed under a dropped call, the
retry finds every part already in the log and adopts it instead of appending a
second `add` (which would double-consume its sources); its prevalence apply is
left to the exactly-once cursor replay.

### Modeled convergence suite

`tests/nan4539_flush_convergence.rs` drives the production constructor and tick
loop on Tokio's paused clock with real admission, Parquet builds, signatures and
part log; only IO and time are modeled. IO delays are **MODELED**, calibrated from
the T84 read-only RCA occupancy/residency estimates (not measured latencies): 3.65 s
per native object write (7.3 s publication residency over two write rounds), 2.72 s
build charged on each L0 data PUT, 2.47 s part-log append plus 3.49 s prevalence
folded into each `add` append, an assumed 100 ms per read. `3x` multiplies every delay as a
p95 **stand-in**, not a percentile. CPU costs zero modeled time. Each PUT holds one
permit of a 32-permit FIFO pool like the native envelope, and pays two owner calls
(authorize before, complete after) through one process-wide 50 ms pacer shared by
both publications, merges and appends, as `NativePartWriter` paces them at 300 EPS.
Catch-up, lag and drain are measured after each tick, so the committing tick counts. Rows are real (40 per
object, 300 EPS offered). Backlog durations are scaled per case: the throughput gates use
a 1h backlog at scale 4 and a 3h backlog at scale 12 (270,000 backlog rows each since
Step 3a cut larger flushes; Step 2 used scales 6/18, 180,000 rows; the
zero-cost 3h case uses scale 10), so at least ten flushes commit before catch-up; the
deadline is 5,400 s or 1,800 s divided by the scale. The gated rate is committed rows per
modeled second over the steady-state window (first backlog commit to the commit at
catch-up, at least ten flushes), which keeps the first flush's fill and commit latency out
of it. A 60x smoke run (1h = 18,000 rows, two or three flushes) checks only the deadline,
catch-up and drain no later than serial, and exactly-once; it is too short to measure a
rate. `CAUGHT_UP_LAG_MS` (60 s) is not scaled: with every backlog notice acked it is
effectively "the frontier passed the outage". The suite compares a serial baseline and the
bounded default on identical sources, and checks exactly-once rows, one `add` per
source, in-order ACKs, at most two flights and 32 concurrent writes, ingest-path
requests per committed row, a tight-memory serial fallback (a 533 MiB cell: the working
budget and the merge decode window derive from the cap as in the cell constructor) and
bounded replay cost after transient publication failures. It prints one
`NAN4539-MODELED` line per run. These are scheduling and request-cost bounds, not
physical or live EPS.

Modeled results at Step 2 (run10; serial vs bounded, steady-state rate over at least ten
flushes). Step 3a's results on the rescaled gates are in the next section:

| Case | Serial | Bounded | Gate |
| --- | --- | --- | --- |
| 1h at estimate, scale 6 (deadline 300 s) | 815 s, 387 rows/s | 170 s, 1,442 rows/s, 2 flights | passes |
| 3h at estimate, scale 18 (deadline 300 s) | 817 s, 386 rows/s | 173 s, 1,414 rows/s, 2 flights | passes |
| 3h at zero cost, scale 10 (deadline 540 s) | 257 s, 1,512 rows/s | 132 s, 2,649 rows/s | passes |
| 1h and 3h at 3x, scales 6/18 (deadline 300 s) | 2,117-2,135 s, 148 rows/s | 680 s, 466 rows/s | **misses the deadline**, reported only |
| 3h at estimate, scale 60 (deadline 90 s) | 283 s | 73 s, 915 rows/s (1.7% over 900) | smoke reference |
| same with three transient 503s | 283 s | 104 s, 686 rows/s | **misses the deadline**; bounded replay cost |
| 1h smoke, scale 60, estimate (deadline 30 s) | 53 s | 29 s | deadline only |
| tight 533 MiB cell, 3h at estimate, scale 60 | 261 s | 89 s, 1 flight, drained 161 s | fallback |

The 1h-at-scale-6 and 3h-at-scale-18 cases are the same 180,000-row workload (each a
600 modeled second backlog); the scale was chosen so that both span ten flushes. Bounded
ingest-path requests per committed row are at or below serial in every case.

Overlap applies only to edge-input tenants: the effective depth is 2 only when the
queue allows two outstanding ranges, which today only the edge source does. Bronze/spool
tenants keep depth 1.

**Card acceptance is not met by Step 2.** The serial commit stage (the oldest flight's
part-log append plus prevalence apply, about 6 s per flush at the estimate and 18 s at
3x) caps throughput at rows-per-flush divided by that time, whatever the depth. At 3x it
stays below 900 rows/s, and the scale-60 3h estimate case clears with a 1.7% margin
(915 rows/s). Step 3 addresses the commit stage (`nan4539-step3-design.md`, design only).

Pacing gaps in the model: owner sign RPCs (`HttpPartSigner`) are not charged, owner
503/504 retry windows and journal replay are not modeled, and non-native checkpoint keys
are paced here but not in production (a slight overcharge).

What the suite does **not** prove: prevalence under overlap (disabled; its apply
estimate is folded into the append delay), build and admission CPU contention (CPU
costs zero time), the real `EdgeLogSource` (a spool queue stands in; the edge tests
cover order), the cell loop (the cell constructor test covers its wiring), and
physical or live EPS. Calibrate the native pacer against live `pacer_wait` timings
before any live qualification.

Recalibration: after a coordinator train carries Step 1, read the tenant's
`ingest_diagnostics` (`native_writer.timings` authorize/complete/PUT and
`pacer_wait`, `operation_timings` part-log append and prevalence apply, stage
residence for `build_parts`) over one process epoch, take the bucket containing the
median and the 95th percentile of each, and replace the `ESTIMATE` constants with
those bucket bounds (label them measured only then, with sample sizes and epoch).

The offline physical benchmark is an explicitly invoked, ignored test on the real
clock and local disk (no modeled delay, real CPU):

```bash
cargo test --release -p nanosiem-lake-worker --test nan4539_flush_convergence \
  physical_wall_clock_benchmark -- --ignored --nocapture
```

Run serial and bounded on the same host and CPU allocation; it reports wall-clock
committed rows per second for both and is not a live EPS claim.


## Catch-up flush size and seal order

Step 2's overlap stayed near serial in large-tenant-shaped catch-up. The 3x probe
(728-row segments, ~4.5 KB Arrow rows, the large tenant's 5.63 GB ingest cap) ran at 287 rows/s.
The cause was not memory. The single ingest task stopped admitting while it
waited on a flight, so flushes stayed small (~9-10k rows) while the working
budget sat half empty. Step 3a keeps the task admitting and lets the next build
overlap the inline commit. All of these are coded defaults, with no switch:

- **Age-due seals defer beside a building flight.** Behind, a seal that only its
  age made due, and that would wait on an unfinished flight, is skipped for this
  tick. Admission keeps filling the buffer under every cap and the budget. Hard
  caps still seal or wait exactly as before: rows, bytes, objects, hours,
  rejections, budget spent, a buffer-bound admission deferral, and the crash seal.
- **A group's transient decode peak no longer seals the buffer.** Admission
  bounds one call by its objects' JSON peak. The buffer now seals only
  when the next object would not fit beside the buffer, flights and merges on
  its own. A partial admission ticks again at once (the finished-flight wake)
  instead of after the cell loop's idle second.
- **Published flights hold only their retained rows.** Once a flight's
  background task has published, its build copies and writers are freed, so it
  is charged `buffer.bytes`, not `flight_bytes`.
- **Seal before commit.** Before a published flight commits inline (its
  part-log append and prevalence apply hold the task), a catch-up buffer seals
  first if both of these hold: it fits beside the flights, and it is due or holds
  at least one full L0 part (`SEAL_FIRST_MIN_ROWS` = 16,384). Its build and upload
  then overlap that commit. A seal that only the budget blocks (a slot is free)
  waits for the oldest flight's **publication**, not its commit, and seals first
  if it then fits.
- **Writers are reserved for the parts the plan writes**:
  min(fitting, `l0_chunks` per hour). A sub-16k-row flush no longer reserves
  4 × 48 MiB.

Order and exactly-once are unchanged. The new seal passes the same
`may_seal_beside_flights` barrier: no part-log op ahead of an earlier `add`, and no
skips, rejections or schema growth. Only the oldest flight appends and ACKs. The
serial comparison policy (`commit_when_ready = false`) keeps every old wait.

Prevalence stays inline and was not deferred (option 3b was rejected). The T84
per-flush fit shows apply nearly fixed per flush (39 µs/row, r = 0.11). Stamping at
admission also needs prevalence not to be pending, so a deferred apply would
unstamp catch-up rows.

### Step 3 modeled gate (release; `cargo test --release ... -- --ignored step3_`)

All three runs use large-tenant-shaped sources in a large-tenant-sized cell (working budget 1,690 MB)
on the fitted `ROW_THREE_X` costs, which are 3x of:

| Cost | Fixed | Per row |
| --- | --- | --- |
| PUT | 3,650 ms | |
| build | | 271 µs |
| append | 2,470 ms | |
| prevalence | 2,548 ms | 94 µs |

| Case | Serial | Bounded (Step 3a) | Gate |
| --- | --- | --- | --- |
| 3h backlog, scale 4 (810k rows; deadline 1,350 s) | 1,460 s, 839 rows/s | **1,286 s, 917 rows/s over 22 flushes**, peak L0 28, 9 merges | **passes** |
| same, prevalence fully linear (1,041 µs/row at 3x) | 2,604 s, 543 rows/s | 2,186 s, 645 rows/s | reported, misses |
| 3h backlog, scale 12 probe (4-5 flushes; deadline 450 s) | 644 s | 495 s, 810 rows/s | reported, misses |

The same probe before Step 3a: serial 2,204 s at 214 rows/s; bounded 1,633 s at
287 rows/s.

Step 2 suite with Step 3a, rescaled gates (`ONE_HOUR_SCALE` 4, `THREE_HOUR_SCALE` 12;
deadline 450 s):

| Case | Serial | Bounded |
| --- | --- | --- |
| 1h at estimate | 1,243 s, 380 rows/s | 226 s, 1,444 rows/s over 14, ~13.9k rows per add |
| 3h at estimate | 1,244 s, 380 rows/s | 224 s, 1,464 rows/s over 14 |
| 3h at zero cost, scale 10 | 256 s | 14 s |
| 1h and 3h at 3x (`THREE_X`, fixed per flush) | ~3,175 s, ~149 rows/s | ~963 s, 491 rows/s; reported (misses) |
| tight 533 MiB cell, 3h at estimate, scale 60 | 261 s | 48 s, 2 flights, within depth |

`THREE_X` keeps Step 2's flush-fixed costs (no per-row term) on 40-row objects. Its
flushes stop at `MAX_FLUSH_OBJECTS` (512 objects, 20,480 rows), so each pays the
~18 s fixed commit (append and prevalence) for at most 20k rows. That is a 40-row
test-object artifact: large-tenant segments are ~728 rows, so the object cap is not
binding there. The large-tenant-shaped `ROW_THREE_X` gate above is the per-row-fitted 3x
case.

Scale 4 is the smallest scale whose backlog spans ten ~65k-row flushes. At scale 12,
the first flush's fill and commit latency (~80 s) and the 60 s lag tail dominate the
450 s deadline. The margin at scale 4 is thin: 1.9% on rate, 4.7% on the deadline. The
fully linear prevalence case misses. That makes the live FP catch-up measurement after
the train the deciding evidence, and 3b stays the fallback if live prevalence is
row-linear. In this model prevalence is disabled and charged as delay, so "no unstamped
batches" is vacuous here.
