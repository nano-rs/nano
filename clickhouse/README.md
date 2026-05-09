# ClickHouse schema for nano

This directory contains the ClickHouse schema definitions and migrations for nano's log storage and analysis system.

## How migrations are applied

Migrations execute out-of-process via the `clickhouse_migrator` binary, not inside `nanosiem-api`:

- **Kubernetes (Pulumi)**: a pre-deploy `Job` runs the migrator, and the api/search/jobs `Deployment`s `dependsOn` it.
- **docker-compose**: the `clickhouse-migrate` service runs to completion and the app services gate on it via `service_completed_successfully`.
- The api startup performs a read-only check against `_migrations` and refuses to serve traffic on a stale schema.

This split exists because long migrations (e.g. `INSERT SELECT` backfill across tens of millions of rows) need an unbounded runtime budget. Running them inside the api means competing with the startup-probe budget, which can wedge a deploy when an aggregate-column re-INSERT inflates `SimpleAggregateFunction(sum, ...)` columns past their consistent state.

### Authoring conventions

**Migration files are DDL only.** New `NNN_*.sql` files contain `CREATE TABLE`, `CREATE MATERIALIZED VIEW`, `CREATE DICTIONARY`, `ALTER TABLE` (schema), and `DROP` statements. Each must be:

- **Fast** — no row-by-row work that scales with data volume. > 30 s on a real tenant is a red flag.
- **Idempotent** — re-running after a partial-failure recovery converges to the same end state without duplicate rows or inflated aggregates.
- **Retry-safe** — if the migrator is killed mid-execution and re-run, it must complete without manual intervention. Use `IF NOT EXISTS`, `CREATE OR REPLACE`.

**Backfills do not belong in migrations.** Any `INSERT INTO summary SELECT FROM source_agg` style work goes into a `nanosiem-jobs` task gated on a sentinel row in a `_backfills` table. Backfills are observable, resumable, and decoupled from deploy timing — guarantees migrations deliberately don't try to provide.

**Aggregating columns deserve scrutiny.** `SimpleAggregateFunction(sum, …)` columns add across duplicate inserts; only `AggregateFunction(uniq, …)` and friends merge correctly. A migration that re-INSERTs into an AggregatingMergeTree will inflate sum-typed columns even though uniq-typed ones converge.

### Numbering

Pick the next number from `ls clickhouse/ | sort | tail` — not "the next one I saw in code." Concurrent branches collide otherwise. Sub-migrations may use a letter suffix (`075a_…`, `075b_…`). The migrator's filename regex is `^\d+[a-z]*_.+\.sql$`; non-matching files (`init.sql`, `README.md`, `config.d/*`) are ignored.

### Baseline

`init.sql` represents the post-state of every numbered migration up through some version. The list of versions baked in lives in `BASELINE_MIGRATIONS` (`nanosiem-core/src/db/clickhouse_migrate/tracking.rs`); the migrator seeds those rows into `_migrations` on a fresh deploy so the runner doesn't re-apply files whose work is already in `init.sql`. When you fold a numbered migration into `init.sql`, add its version to `BASELINE_MIGRATIONS`.

---

## Schema Files

### init.sql
The base schema that creates the main `logs` table with all UDM (Unified Data Model) fields. This file is automatically executed when ClickHouse starts for the first time via docker-entrypoint-initdb.d.

### 046_direct_ingestion_schema.sql
Schema updates for direct Vector ingestion support. This migration adds:

1. **Watermark tracking** - `_inserted_at` column on logs table
2. **Real-time signals** - New `signals` table for detection outputs
3. **Error logging** - New `ingestion_errors` table for failed ingestions

## Tables

### logs
The main log storage table with:
- **Partitioning**: Daily partitions by timestamp
- **Ordering**: (timestamp, src_ip, dest_ip)
- **TTL**: 90 days
- **Indexes**: Bloom filters on IPs, users; set indexes on categorical fields
- **New**: `_inserted_at` column for watermark-based processing

### signals
Stores detection signals from real-time and near real-time detection engines:
- **Partitioning**: Daily partitions by timestamp
- **Ordering**: (timestamp, rule_id, risk_entity)
- **TTL**: 90 days
- **Indexes**: Bloom filters on rule_id, risk_entity, matched_log_id; set index on severity

Fields:
- `id` - Unique signal identifier
- `timestamp` - When the detection occurred
- `rule_id` - Detection rule that triggered
- `rule_name` - Human-readable rule name
- `severity` - Alert severity (low, medium, high, critical)
- `risk_score` - Numeric risk score (0-100)
- `risk_entity` - Entity being scored (IP, user, host)
- `matched_log_id` - Link to the log that triggered the detection
- `metadata` - Additional context as JSON
- `_inserted_at` - When the signal was created

### ingestion_errors
Captures logs that failed to ingest for troubleshooting:
- **Partitioning**: Daily partitions by timestamp
- **Ordering**: (timestamp, error_type)
- **TTL**: 30 days
- **Indexes**: Set index on error_type; token bloom filter on error_message

Fields:
- `id` - Unique error identifier
- `timestamp` - When the error occurred
- `error_type` - Classification of the error
- `error_message` - Detailed error message
- `raw_content` - The content that failed to ingest
- `source_info` - Information about the source (e.g., Vector source name)
- `_inserted_at` - When the error was logged

## Applying Migrations

### For Running Systems
Use the provided script to apply migrations to a running ClickHouse instance:

```bash
./scripts/apply-direct-ingestion-schema.sh
```

This script will:
1. Check ClickHouse connectivity
2. Apply the migration
3. Verify all changes were successful

### For New Deployments
The migration files are automatically applied when ClickHouse starts via docker-entrypoint-initdb.d. Ensure the migration files are mounted in the correct order.

## Verifying Schema

To verify the schema is correctly applied:

```bash
./scripts/verify-direct-ingestion-schema.sh
```

This will check:
- logs table has `_inserted_at` column and index
- signals table exists with all columns and indexes
- ingestion_errors table exists with all columns and indexes

## Direct Ingestion Architecture

The schema supports a triple-tier detection architecture:

1. **Real-Time (10-30s)**: Materialized views write directly to signals table
2. **Near Real-Time (1-5min)**: NRT engine uses `_inserted_at` watermarks to process micro-batches
3. **Scheduled (hourly/daily)**: Existing scheduler for complex analytics

### Watermark-Based Processing

The `_inserted_at` column enables reliable micro-batch processing:

```sql
-- Fetch logs for NRT processing
SELECT * FROM logs
WHERE _inserted_at > :last_watermark
  AND _inserted_at <= (now64(6) - INTERVAL 60 SECOND)
ORDER BY _inserted_at ASC
LIMIT 100000
```

The 60-second lag buffer accounts for late-arriving logs and clock skew.

### Real-Time Detection Example

Materialized views can write signals automatically:

```sql
CREATE MATERIALIZED VIEW mv_malicious_ip_detection TO signals AS
SELECT
    generateUUIDv4() AS id,
    timestamp,
    '550e8400-e29b-41d4-a716-446655440000'::UUID AS rule_id,
    'Malicious IP Connection' AS rule_name,
    'high' AS severity,
    75 AS risk_score,
    src_ip AS risk_entity,
    id AS matched_log_id,
    toJSONString(map('dest_ip', dest_ip)) AS metadata,
    now64(6) AS _inserted_at
FROM logs
WHERE dest_ip IN ('192.0.2.1', '198.51.100.1');
```

## Performance Considerations

### Indexes
- **Bloom filters**: Fast membership tests for high-cardinality fields (IPs, UUIDs)
- **Set indexes**: Efficient for low-cardinality categorical fields (severity, status)
- **Token bloom filters**: Full-text search on raw content and error messages
- **Minmax indexes**: Range queries on timestamps

### Partitioning
Daily partitions enable:
- Efficient TTL enforcement
- Fast partition pruning for time-range queries
- Parallel query execution

### Batch Inserts
For optimal performance, insert logs in batches:
- Vector: 10k events per batch
- NRT engine: 100 signals per batch
- Reduces write amplification and improves throughput

## Monitoring

Key metrics to monitor:

1. **Ingestion rate**: `SELECT count() FROM logs WHERE _inserted_at > now() - INTERVAL 1 MINUTE`
2. **Signal rate**: `SELECT count() FROM signals WHERE _inserted_at > now() - INTERVAL 1 MINUTE`
3. **Error rate**: `SELECT count() FROM ingestion_errors WHERE _inserted_at > now() - INTERVAL 1 MINUTE`
4. **Watermark lag**: `SELECT max(_inserted_at) FROM logs` vs current time

## Troubleshooting

### Missing _inserted_at values
If logs are missing `_inserted_at` values, they were inserted before the migration. The column has a default of `now64(6)`, so new inserts will automatically populate it.

### Signals not appearing
Check:
1. Materialized views are created: `SHOW TABLES LIKE 'mv_%'`
2. NRT engine is running and processing batches
3. Detection rules are enabled and have correct mode

### High ingestion_errors count
Query the errors table to identify patterns:
```sql
SELECT error_type, count() as cnt
FROM ingestion_errors
WHERE timestamp > now() - INTERVAL 1 HOUR
GROUP BY error_type
ORDER BY cnt DESC
```

## References

- [ClickHouse MergeTree Documentation](https://clickhouse.com/docs/en/engines/table-engines/mergetree-family/mergetree)
- [ClickHouse Materialized Views](https://clickhouse.com/docs/en/guides/developer/cascading-materialized-views)
- [Direct Ingestion Design Document](../.kiro/specs/direct-clickhouse-ingestion/design.md)
