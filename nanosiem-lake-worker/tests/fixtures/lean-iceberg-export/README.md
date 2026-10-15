# Local Iceberg export integration

From a worktree with an isolated, seeded `target/`:

```sh
python3 nanosiem-lake-worker/tests/fixtures/lean-iceberg-export/run-local.py
```

Requires Docker, Git, Go (compatible with MinIO's pinned source) and Rust.
`NANO_CARGO` replaces `cargo` and `NANO_BUILD_GATE` prefixes the MinIO
`go build`, for hosts that throttle builds through a wrapper. The runner
builds MinIO from upstream commit `07c3a429bfed433e49018cb0f78a52145d4bedeb`
(RELEASE.2025-09-07T16-13-09Z): upstream prebuilt images/binaries are unavailable.
`MINIO_BINARY=/absolute/path/to/a/local/minio` skips that source build.
The REST fixture image is pinned by digest. Fixture containers share a temporary
per-run Docker network, ports publish on loopback only, credentials are random
and never echoed. The Rust test reads a temporary mode-0600 fixture auth file
under `target/`, removed on exit, because the cargo sandbox strips credential
environment variables. Containers/network/image are removed even on test failure.
No live provider/catalog/bucket endpoints are accepted by the test.

The Rust integration uses real REST metadata commits, real S3 object writes and
iceberg-rust reads. It proves append, lost-success response recovery, idempotent
replay, conflict retry, hour-to-day overwrite, additive evolution/name mapping,
partial/full erasure, stale-replay safety, tenant rejection, fresh OAuth sessions
and frozen/breaking-version table isolation. The customer adapter test copies owner-signed Parquet/provenance into MinIO,
removes the source and replays, then checks day overwrite and erasure. A local
PostgreSQL 18 container also checks durable pending-plan recovery, exclusive
leases, stale-worker/other-tenant rejection and health counters. Hosted reference tests use a second tenant-named bucket and PostgreSQL registry.
They cover no-copy signed readback, queued pins/restart, concurrent locks, hour/day
replacement and grace, additive schema evolution, shared v1/v2 references, frozen
partial/full erasure, retirement fences, no dangling references, staged credential sealing,
revocation and read-only cross-tenant negatives. Hosted activation is DB-gated
until PR4. The fixture deliberately has no automatic catalog maintenance.
Unit tests validate manifest/state recovery and schema/tenant fences separately.

The hosted fixture also mounts the otherwise-inactive object gateway on a
loopback listener, using a test-only activation-constraint removal in its
throwaway database. It verifies signed multi-chunk Parquet HTTP readback, HEAD,
closed/open/suffix ranges, exact byte/request charges, provider failure refunds,
100% suspension/UTC reset, cross-tenant/proof/write denial, a privacy barrier
installed during a provider read, and a completed rewrite invalidating an
in-flight scope. It then erases that contract and proves immediate retirement.
Production activation remains blocked; no listener or migration is enabled.
