# SlateDB 0.15.0 — idle polling patch

Vendored from the Cargo registry package, SHA-256
`35ca56b01922b15aa69fe3abb62cadc985d86032c9647e4606e211c4da751a76`.
Upstream license: Apache-2.0. The root Cargo.lock remains the production lock.
The nested workspace declaration only permits running upstream unit tests independently.

Opt-in settings (unset by default): `idle_manifest_poll_interval`,
`CompactorOptions::idle_poll_interval`, and
`CompactionWorkerOptions::idle_compactions_poll_interval`.
The Bronze UID ledger sets these to 300/60/60 seconds, retains active 30/5/5-second
tickers, and configures all six GC task intervals to 600 seconds.

* `idle_poll.rs`: bounded doubling of idle remote reads; active work bypasses the wait.
* `compactor.rs`: back off only without active jobs or a change to `last_l0_seq`;
  wake the embedded worker on observed L0/job activity. Signal manifest changes
  (including fast commits) to the writer so completed compactions are adopted at
  the original active cadence even when ingest has stopped.
* `compaction_worker.rs`: back off only with no locally owned or remotely observed
  active jobs. Embedded coordinator activity bypasses the wait. Opt-in mode uses
  fixed local ticks so jitter cannot extend the idle cap; default workers retain
  upstream jitter. Heartbeats, claims, failure reclamation, completion and cleanup
  retain their original paths.
* `memtable_flusher/manifest_writer.rs`: skip periodic remote refresh until durable
  sequence/embedded-compactor activity changes or the idle ceiling elapses.
  Explicit refreshes, manifest writes/CAS, flush acknowledgements, WAL durability
  and checkpoint creation are never gated.
* `config.rs`, `lib.rs`: configuration/module wiring. `db.rs` and
  `db_transaction.rs` only add the disabled field to exhaustive test settings.

No persisted data formats, GC age/reference rules, write paths, or exactly-once
claim protocol changes. Slow discovery may delay compaction scheduling by up to
60 seconds plus the embedded worker's next 5-second tick (excluding I/O/runtime
scheduling). Caller errors retain existing fail-closed behavior.

Tests: from the repository root, run
`cargo test --manifest-path vendor/slatedb/Cargo.toml --features test-util --lib idle_`,
then the `compactor::tests`, `compaction_worker::tests`,
`memtable_flusher::manifest_writer::tests`, `garbage_collector`, and `config::tests`
filters. Standalone dev dependencies may need a writable CARGO_HOME; production
builds use the root workspace and lockfile.
