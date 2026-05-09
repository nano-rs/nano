# Vector Sinks Configuration

This directory contains optional sink configurations for NanoSIEM Vector.

## Available Sinks

### Direct ClickHouse Ingestion

**File:** `clickhouse.toml`

**Purpose:** Enables direct log ingestion from Vector to ClickHouse, bypassing the nanosiem-ingest service for improved throughput and reduced latency.

**Architecture:**
```
Vector → ClickHouse (direct write with _inserted_at timestamp)
```

This is part of the two-tier detection architecture:
- **Real-Time (10-30s):** ClickHouse materialized views for atomic IOC detections
- **Scheduled (continuous or custom):** Scheduler with 15-second checks for all other detection types

The scheduler checks every 15 seconds and fires rules based on their cron schedule.
Use `*/1 * * * *` for continuous (1-minute) detection.

**When to Use:**
- High-volume log ingestion (>10k events/sec)
- Need for lower latency detection
- Stable log formats with minimal validation needs

**Trade-offs:**
- ✅ Higher throughput (~10k events/sec vs ~1k events/sec)
- ✅ Lower latency (direct write vs API hop)
- ✅ Simpler architecture (fewer services)
- ❌ Bypasses API validation and enrichment
- ❌ Requires ClickHouse schema knowledge

## Enabling Direct ClickHouse Ingestion

### Prerequisites

1. ClickHouse must be running and accessible
2. The direct ingestion schema must be applied:
   ```bash
   ./scripts/apply-direct-ingestion-schema.sh
   ```

### Configuration Steps

1. **Enable the ClickHouse sink:**
   
   The `clickhouse.toml` file is already active in this directory. Vector will automatically load it.

2. **Enable the schema mapping transform:**
   
   The `transforms/clickhouse_mapping.toml` file is already active. Vector will automatically load it.

3. **Enable error handling:**
   
   The `transforms/error_handling.toml` file is already active. Vector will automatically load it.

4. **Set environment variables:**
   
   Add to your `.env` file:
   ```bash
   # ClickHouse connection (required)
   CLICKHOUSE_URL=http://clickhouse:8123
   CLICKHOUSE_DATABASE=nanosiem
   CLICKHOUSE_USER=nanosiem
   CLICKHOUSE_PASSWORD=nanosiem
   ```

5. **Disable the API sink (optional):**
   
   If you want to use ONLY direct ClickHouse ingestion:
   - Edit `config/vector/90-sinks.toml`
   - Comment out or remove the `[sinks.nanosiem_api]` section
   
   **Note:** You can run both sinks in parallel during migration to validate data consistency.

6. **Restart Vector:**
   ```bash
   docker-compose restart vector
   ```

### Verification

1. **Check Vector logs:**
   ```bash
   docker-compose logs -f vector
   ```
   Look for: `Healthcheck passed for sink 'clickhouse_logs'`

2. **Verify logs in ClickHouse:**
   ```bash
   ./scripts/verify-direct-ingestion-schema.sh
   ```

3. **Check the _inserted_at timestamp:**
   ```sql
   SELECT id, timestamp, _inserted_at, source_type, raw_content
   FROM logs
   ORDER BY _inserted_at DESC
   LIMIT 10;
   ```

4. **Monitor ingestion errors:**
   ```sql
   SELECT timestamp, error_type, error_message, source_info
   FROM ingestion_errors
   ORDER BY timestamp DESC
   LIMIT 10;
   ```

## Parallel Operation (Migration Strategy)

During migration, you can run both ingestion paths in parallel:

1. Keep `nanosiem_api` sink enabled in `90-sinks.toml`
2. Enable `clickhouse_logs` sink in `sinks/clickhouse.toml`
3. Both sinks will receive the same logs
4. Compare data in Postgres vs ClickHouse to validate consistency
5. Once validated, disable the API sink

**Validation Query (Postgres):**
```sql
SELECT COUNT(*), source_type
FROM logs
WHERE ingest_time > NOW() - INTERVAL '1 hour'
GROUP BY source_type;
```

**Validation Query (ClickHouse):**
```sql
SELECT COUNT(*), source_type
FROM logs
WHERE ingest_time > now() - INTERVAL 1 HOUR
GROUP BY source_type;
```

## Rollback

To revert to API-based ingestion:

1. Comment out the `[sinks.clickhouse_logs]` section in `sinks/clickhouse.toml`
2. Ensure `[sinks.nanosiem_api]` is enabled in `90-sinks.toml`
3. Restart Vector: `docker-compose restart vector`

## Monitoring

### Vector Metrics

Vector exposes metrics on port 9598:
```bash
curl http://localhost:9598/metrics | grep clickhouse
```

Key metrics:
- `component_sent_events_total{component_id="clickhouse_logs"}` - Total events sent
- `component_sent_event_bytes_total{component_id="clickhouse_logs"}` - Total bytes sent
- `component_errors_total{component_id="clickhouse_logs"}` - Total errors

### ClickHouse Metrics

Monitor ingestion rate:
```sql
SELECT
    toStartOfMinute(timestamp) AS minute,
    COUNT(*) AS events_per_minute
FROM logs
WHERE timestamp > now() - INTERVAL 1 HOUR
GROUP BY minute
ORDER BY minute DESC;
```

Monitor watermark lag (for NRT engine):
```sql
SELECT
    now() - MAX(_inserted_at) AS lag_seconds
FROM logs;
```

## Troubleshooting

### Logs not appearing in ClickHouse

1. Check Vector logs: `docker-compose logs vector`
2. Verify ClickHouse is accessible: `curl http://localhost:8123/ping`
3. Check authentication: Verify `CLICKHOUSE_USER` and `CLICKHOUSE_PASSWORD`
4. Check disk buffer: `docker exec vector ls -lh /var/lib/vector/`

### High error rate

1. Check ingestion_errors table:
   ```sql
   SELECT error_type, COUNT(*) as count
   FROM ingestion_errors
   WHERE timestamp > now() - INTERVAL 1 HOUR
   GROUP BY error_type;
   ```

2. Check Vector error logs:
   ```bash
   docker-compose logs vector | grep ERROR
   ```

3. Verify schema compatibility:
   ```bash
   ./scripts/verify-direct-ingestion-schema.sh
   ```

### Performance issues

1. Check batch size: Increase `max_events` in `sinks/clickhouse.toml`
2. Check concurrency: Increase `concurrency` in request settings
3. Monitor ClickHouse CPU/memory: `docker stats clickhouse`
4. Check disk buffer usage: `docker exec vector du -sh /var/lib/vector/`

## Related Documentation

- Design Document: `.kiro/specs/direct-clickhouse-ingestion/design.md`
- Requirements: `.kiro/specs/direct-clickhouse-ingestion/requirements.md`
- Tasks: `.kiro/specs/direct-clickhouse-ingestion/tasks.md`
- ClickHouse Schema: `clickhouse/046_direct_ingestion_schema.sql`
- Verification Script: `scripts/verify-direct-ingestion-schema.sh`

