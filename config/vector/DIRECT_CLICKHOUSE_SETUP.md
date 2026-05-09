# Direct ClickHouse Ingestion Setup Guide

This guide explains how to enable direct ClickHouse ingestion in NanoSIEM, which bypasses the nanosiem-ingest service for improved throughput and enables the two-tier detection architecture.

## Overview

**Current Architecture (Default):**
```
Vector → nanosiem-ingest → ClickHouse
                ↓
            Postgres (rules, alerts)
```

**New Architecture (Direct Ingestion):**
```
Vector → ClickHouse (direct write with _inserted_at)
            ↓
    ┌───────┴───────┐
    ↓               ↓
Materialized    Scheduler
Views (RT)      (15s checks)
    ↓               ↓
    └───────┬───────┘
            ↓
    Postgres (rules, alerts, signals)
```

## Benefits

1. **Higher Throughput:** ~10k events/sec vs ~1k events/sec
2. **Lower Latency:** Direct write eliminates API hop
3. **Two-Tier Detection:**
   - Real-Time (10-30s): Materialized views for atomic IOC detections
   - Scheduled (continuous or custom): Scheduler with 15-second checks for all other detection types
4. **Insertion Tracking:** `_inserted_at` timestamp enables efficient time-based queries
5. **Error Handling:** Dead letter queue captures failed logs

The scheduler checks every 15 seconds and fires rules based on their cron schedule.
Use `*/1 * * * *` for continuous (1-minute) detection.

## Configuration Files

The following files have been created for direct ClickHouse ingestion:

### 1. ClickHouse Sink (`config/vector/sinks/clickhouse.toml`)

Configures Vector to write directly to ClickHouse with:
- HTTP endpoint configuration
- Basic authentication
- Disk buffering (1GB) for reliability
- Batching (10MB/10k events) for performance
- Retry logic with exponential backoff
- Health checks

### 2. Schema Mapping Transform (`config/vector/transforms/clickhouse_mapping.toml`)

Maps all UDM fields to the ClickHouse logs table schema:
- Primary identifiers (id, timestamp)
- Raw content and metadata (JSON encoding)
- UDM entity fields (src_ip, dest_ip, src_host, dest_host)
- UDM network fields (ports, protocol, bytes)
- UDM user/action fields (user, action, status)
- UDM authentication fields (auth_type, auth_result, session_id)
- UDM process fields (process_name, process_id, command_line)
- UDM file fields (file_path, file_name, file_hash)
- HTTP fields (user_agent)
- Enrichment fields (GeoIP, ASN - populated post-ingestion)
- Processing timestamps (ingest_time, _inserted_at)

### 3. Error Handling (`config/vector/transforms/error_handling.toml`)

Implements dead letter queue pattern:
- Captures logs that fail to ingest
- Writes errors to `ingestion_errors` table
- Includes error type, message, and raw content
- Fallback to console logging for critical errors

## Setup Instructions

### Prerequisites

1. ClickHouse must be running
2. Direct ingestion schema must be applied

### Step 1: Apply ClickHouse Schema

Run the schema migration script:

```bash
./scripts/apply-direct-ingestion-schema.sh
```

This creates:
- `_inserted_at` column in logs table (for watermark tracking)
- `signals` table (for real-time detection outputs)
- `ingestion_errors` table (for error logging)
- Indexes for efficient queries

### Step 2: Configure Environment Variables

Add to your `.env` file:

```bash
# ClickHouse connection (required)
CLICKHOUSE_URL=http://clickhouse:8123
CLICKHOUSE_DATABASE=nanosiem
CLICKHOUSE_USER=nanosiem
CLICKHOUSE_PASSWORD=nanosiem
```

### Step 3: Verify Configuration

Run the verification script:

```bash
./scripts/verify-vector-clickhouse.sh
```

This checks:
- Configuration files exist
- Environment variables are set
- ClickHouse is accessible
- Schema is applied correctly
- Vector configuration is valid

### Step 4: Restart Vector

Restart Vector to load the new configuration:

```bash
docker-compose restart vector
```

### Step 5: Test Ingestion

Send a test log:

```bash
curl -X POST http://localhost:8080/ \
  -H "Authorization: Bearer ${VECTOR_AUTH_TOKEN}" \
  -H "X-Source-Type: test" \
  -H "Content-Type: text/plain" \
  -d 'Test log message for direct ClickHouse ingestion'
```

Verify the log appears in ClickHouse:

```bash
./scripts/verify-direct-ingestion-schema.sh
```

Or query directly:

```sql
SELECT id, timestamp, _inserted_at, source_type, raw_content
FROM logs
ORDER BY _inserted_at DESC
LIMIT 10;
```

## Parallel Operation (Migration Strategy)

During migration, you can run both ingestion paths in parallel:

1. **Keep API sink enabled** in `config/vector/90-sinks.toml`
2. **Enable ClickHouse sink** (already configured)
3. Both sinks receive the same logs
4. Compare data to validate consistency
5. Once validated, disable the API sink

### Validation Queries

**Count logs by source type (last hour):**

```sql
-- ClickHouse
SELECT COUNT(*), source_type
FROM logs
WHERE ingest_time > now() - INTERVAL 1 HOUR
GROUP BY source_type;
```

```sql
-- Postgres (if using API sink)
SELECT COUNT(*), source_type
FROM logs
WHERE ingest_time > NOW() - INTERVAL '1 hour'
GROUP BY source_type;
```

### Disabling API Sink

Once validated, disable the API sink:

1. Edit `config/vector/90-sinks.toml`
2. Comment out the `[sinks.nanosiem_api]` section
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

**Ingestion rate:**

```sql
SELECT
    toStartOfMinute(timestamp) AS minute,
    COUNT(*) AS events_per_minute
FROM logs
WHERE timestamp > now() - INTERVAL 1 HOUR
GROUP BY minute
ORDER BY minute DESC;
```

**Watermark lag (for NRT engine):**

```sql
SELECT
    now() - MAX(_inserted_at) AS lag_seconds
FROM logs;
```

**Recent logs:**

```sql
SELECT
    timestamp,
    _inserted_at,
    source_type,
    src_ip,
    dest_ip,
    raw_content
FROM logs
ORDER BY _inserted_at DESC
LIMIT 10;
```

### Error Monitoring

**Check ingestion errors:**

```sql
SELECT
    timestamp,
    error_type,
    error_message,
    source_info
FROM ingestion_errors
ORDER BY timestamp DESC
LIMIT 10;
```

**Error rate:**

```sql
SELECT
    error_type,
    COUNT(*) as count
FROM ingestion_errors
WHERE timestamp > now() - INTERVAL 1 HOUR
GROUP BY error_type;
```

## Troubleshooting

### Logs not appearing in ClickHouse

1. **Check Vector logs:**
   ```bash
   docker-compose logs -f vector
   ```
   Look for: `Healthcheck passed for sink 'clickhouse_logs'`

2. **Verify ClickHouse is accessible:**
   ```bash
   curl http://localhost:8123/ping
   ```

3. **Check authentication:**
   Verify `CLICKHOUSE_USER` and `CLICKHOUSE_PASSWORD` in `.env`

4. **Check disk buffer:**
   ```bash
   docker exec vector ls -lh /var/lib/vector/
   ```

### High error rate

1. **Check ingestion_errors table:**
   ```sql
   SELECT error_type, COUNT(*) as count
   FROM ingestion_errors
   WHERE timestamp > now() - INTERVAL 1 HOUR
   GROUP BY error_type;
   ```

2. **Check Vector error logs:**
   ```bash
   docker-compose logs vector | grep ERROR
   ```

3. **Verify schema compatibility:**
   ```bash
   ./scripts/verify-direct-ingestion-schema.sh
   ```

### Performance issues

1. **Check batch size:** Increase `max_events` in `sinks/clickhouse.toml`
2. **Check concurrency:** Increase `concurrency` in request settings
3. **Monitor ClickHouse resources:**
   ```bash
   docker stats clickhouse
   ```
4. **Check disk buffer usage:**
   ```bash
   docker exec vector du -sh /var/lib/vector/
   ```

## Rollback

To revert to API-based ingestion:

1. Comment out the ClickHouse sink in `config/vector/sinks/clickhouse.toml`
2. Ensure API sink is enabled in `config/vector/90-sinks.toml`
3. Restart Vector: `docker-compose restart vector`

## Next Steps

After enabling direct ClickHouse ingestion:

1. **Deploy NRT Engine:** Implement near real-time detection with watermark-based micro-batching
2. **Create Materialized Views:** Enable real-time detection for atomic IOC rules
3. **Migrate Detection Rules:** Classify existing rules into real-time, near real-time, or scheduled tiers
4. **Monitor Performance:** Track ingestion rate, watermark lag, and error rate
5. **Deprecate Ingest Service:** Once validated, remove nanosiem-ingest service

## Related Documentation

- **Design Document:** `.kiro/specs/direct-clickhouse-ingestion/design.md`
- **Requirements:** `.kiro/specs/direct-clickhouse-ingestion/requirements.md`
- **Tasks:** `.kiro/specs/direct-clickhouse-ingestion/tasks.md`
- **ClickHouse Schema:** `clickhouse/046_direct_ingestion_schema.sql`
- **Sinks README:** `config/vector/sinks/README.md`
- **Vector README:** `config/vector/README.md`

