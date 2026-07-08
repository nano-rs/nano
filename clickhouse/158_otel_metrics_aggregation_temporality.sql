-- Migration: carry OTLP metric aggregationTemporality into otel_metrics so the
-- sum/rate consumers can delta-decode CUMULATIVE counters (NAN-1734, O26 consumer).
--
-- WHY
-- ---
-- Standard OTel SDKs export SUM metrics as CUMULATIVE by default — each data
-- point is a monotonically increasing RUNNING TOTAL, not the increment for its
-- interval. NAN-1721 (03-otlp-source.toml, O26 producer half) already stamps the
-- OTLP `aggregationTemporality` (2 = CUMULATIVE, 1 = DELTA, 0 = UNSPECIFIED) onto
-- the sum/histogram `event` JSON, BUT nothing consumed it: `otel_metrics` had no
-- temporality column and the sum/rate consumers treated every value as a raw
-- magnitude. So a "requests over window" panel `sum(value)`-ed running totals →
-- wildly inflated counts, silently (measured: a cumulative 100→150→250 series
-- summed to 500 instead of the true window delta of 150).
--
-- FIX (this migration — the storage/MV plumbing half)
-- ---------------------------------------------------
-- 1. Append a trailing `aggregation_temporality Int8 DEFAULT 0` column to
--    `otel_metrics` (0 = unspecified — the SAFE default so every ALREADY-INGESTED
--    row and every gauge keeps its current raw-sum behavior; only rows the fixed
--    MV populates with 2 get delta-decoded). Appended LAST so the MV → target
--    positional/name mapping of every existing column is untouched.
-- 2. `ALTER TABLE otel_metrics_raw_mv MODIFY QUERY` to populate it from
--    `JSONExtractInt(event, 'aggregationTemporality')`. The SELECT is byte-
--    identical to migration 156's `otel_metrics_raw_mv` block with ONLY the new
--    `aggregation_temporality` column APPENDED at the end (matching the ADD COLUMN
--    position). MODIFY QUERY (NOT DROP+CREATE) so there is no window where the MV
--    is absent and inserts go underived; it takes the SELECT directly — no `AS`
--    (NAN-1727). The cluster transform adds `ON CLUSTER`. Migration 156 last
--    modified this MV; 157 only touched `otel_spans_raw_mv`, so 156 is the
--    byte-source. Do NOT modify 140 or 156.
--
-- ClickHouse maps a TO-table materialized view's SELECT output to the target
-- table BY NAME (verified on a throwaway clone: the trailing SELECT column
-- `aggregation_temporality` lands in the like-named target column at position 14,
-- while the target's position-13 `ingest_time` still receives its `now64(6)`
-- DEFAULT — NOT the temporality value). So appending the column at the end is
-- correct even though `ingest_time` sits before it in the table.
--
-- The `otel_metrics_distributed` wrapper (cluster mode) picks up the new column
-- automatically: `otel_metrics` is in DISTRIBUTED_TABLES (distributed.rs, O1) and
-- `reconcile_distributed_columns` ADDs each source column the wrapper lacks with
-- its exact `system.columns` spec (`aggregation_temporality Int8 DEFAULT 0`). No
-- hand-written distributed ALTER needed; no-op on single-node.
--
-- The consumer-side delta-decode (temporality-aware `sum`/`rate` in
-- clickhouse_sql_gen/otel.rs) is the other half of NAN-1734 and ships with this.
-- =============================================================================

ALTER TABLE nanosiem.otel_metrics
    ADD COLUMN IF NOT EXISTS aggregation_temporality Int8 DEFAULT 0;

ALTER TABLE nanosiem.otel_metrics_raw_mv
MODIFY QUERY SELECT
    JSONExtractString(event, 'name') AS `metric_name`,
    multiIf(
        JSONExtractString(event, 'type') != '', JSONExtractString(event, 'type'),
        length(JSONExtractArrayRaw(JSONExtractRaw(event, 'bucketCounts'))) > 0, 'histogram',
        'gauge'
    ) AS `metric_type`,
    JSONExtractString(event, 'unit') AS `unit`,
    -- O2/O23: clamp 0/unparseable/absurd-future timeUnixNano to ingest time.
    multiIf(
        toUInt64OrZero(JSONExtractString(event, 'timeUnixNano')) = 0, now64(9, 'UTC'),
        fromUnixTimestamp64Nano(toUInt64OrZero(JSONExtractString(event, 'timeUnixNano')), 'UTC') > now64(9, 'UTC') + toIntervalDay(1), now64(9, 'UTC'),
        fromUnixTimestamp64Nano(toUInt64OrZero(JSONExtractString(event, 'timeUnixNano')), 'UTC')
    ) AS `timestamp`,
    if(
        JSONExtractRaw(event, 'asInt') != '',
        toFloat64OrZero(JSONExtractString(event, 'asInt')),
        toFloat64OrZero(JSONExtractString(event, 'asDouble'))
    ) AS `value`,
    JSONExtractUInt(event, 'count') AS `count`,
    toFloat64OrZero(JSONExtractString(event, 'sum')) AS `sum`,
    JSONExtract(event, 'bucketCounts', 'Array(UInt64)') AS `bucket_counts`,
    JSONExtract(event, 'explicitBounds', 'Array(Float64)') AS `explicit_bounds`,
    CAST(
        (
            arrayMap(
                kv -> JSONExtractString(kv, 'key'),
                JSONExtractArrayRaw(JSONExtractRaw(event, 'attributes'))
            ),
            arrayMap(
                kv -> multiIf(
                    JSONExtractRaw(kv, 'value', 'stringValue') != '', JSONExtractString(kv, 'value', 'stringValue'),
                    JSONExtractRaw(kv, 'value', 'intValue') != '', JSONExtractString(kv, 'value', 'intValue'),
                    JSONExtractRaw(kv, 'value', 'doubleValue') != '', JSONExtractString(kv, 'value', 'doubleValue'),
                    JSONExtractRaw(kv, 'value', 'boolValue') != '', JSONExtractString(kv, 'value', 'boolValue'),
                    ''
                ),
                JSONExtractArrayRaw(JSONExtractRaw(event, 'attributes'))
            )
        ),
        'Map(String, String)'
    ) AS `attributes`,
    CAST(
        (
            arrayMap(
                kv -> JSONExtractString(kv, 'key'),
                JSONExtractArrayRaw(JSONExtractRaw(event, 'resource', 'attributes'))
            ),
            arrayMap(
                kv -> multiIf(
                    JSONExtractRaw(kv, 'value', 'stringValue') != '', JSONExtractString(kv, 'value', 'stringValue'),
                    JSONExtractRaw(kv, 'value', 'intValue') != '', JSONExtractString(kv, 'value', 'intValue'),
                    JSONExtractRaw(kv, 'value', 'doubleValue') != '', JSONExtractString(kv, 'value', 'doubleValue'),
                    JSONExtractRaw(kv, 'value', 'boolValue') != '', JSONExtractString(kv, 'value', 'boolValue'),
                    ''
                ),
                JSONExtractArrayRaw(JSONExtractRaw(event, 'resource', 'attributes'))
            )
        ),
        'Map(String, String)'
    ) AS `resource_attributes`,
    JSONExtractString(
        arrayFirst(
            kv -> JSONExtractString(kv, 'key') = 'service.name',
            JSONExtractArrayRaw(JSONExtractRaw(event, 'resource', 'attributes'))
        ),
        'value', 'stringValue'
    ) AS `service_name`,
    -- O26/NAN-1734: OTLP aggregationTemporality (2 CUMULATIVE / 1 DELTA / 0
    -- UNSPECIFIED) stamped by the Vector prep (03-otlp-source.toml). Absent →
    -- JSONExtractInt returns 0 (unspecified) → raw-sum path, matching DEFAULT 0.
    toInt8(JSONExtractInt(event, 'aggregationTemporality')) AS `aggregation_temporality`
FROM nanosiem.otel_metrics_raw
;
