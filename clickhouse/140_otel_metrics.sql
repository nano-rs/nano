-- Migration: OTLP metric ingestion lane (NAN-1528).
--
-- WHAT THIS IS
-- ------------
-- OpenTelemetry metric data points land here via the SAME Null-table + MV
-- derivation idiom as OCSF logs and otel_spans (138). A producer flattens ONE
-- metric DATA POINT into ONE row and writes the full OTLP/JSON object into the
-- single `event` column on the Null staging table `nanosiem.otel_metrics_raw`;
-- the MV `nanosiem.otel_metrics_raw_mv` derives the promoted/indexed columns
-- via JSONExtract* into the MergeTree storage table `nanosiem.otel_metrics`.
--
-- ONE ROW = ONE DATA POINT (one NumberDataPoint or HistogramDataPoint). The OTLP
-- metric nesting is ResourceMetrics -> ScopeMetrics -> Metric{name,unit,<type>}
-- -> <type>.dataPoints[]. Producers MUST flatten this, hoisting the parent
-- Metric's `name`/`unit`, the type discriminator, and the owning resource's
-- attributes ALONGSIDE the single data point. This is a pragmatic SINGLE-table
-- rendition: gauge/sum number points and histogram points share one table; the
-- type-specific columns (value vs count/sum/bucketCounts/explicitBounds) are
-- populated per discriminator and left at their DEFAULT for the other shape.
-- Metrics are stored RAW/NATIVE — NOT re-normalized into UDM.
--
-- ASSUMED FLATTENED `event` SHAPE  (documented contract — see ONE ROW above)
-- -------------------------------------------------------------------------
--   {
--     "name":  "<metric name>",            -- the parent Metric.name
--     "unit":  "<unit>",                   -- the parent Metric.unit (optional)
--     "type":  "gauge"|"sum"|"histogram",  -- discriminator the producer sets
--                                          --   from which Metric.<oneof> was present
--     "timeUnixNano":  "<epoch ns>",       -- the data point's timeUnixNano
--     "asInt":    <int>   | "asDouble": <double>,  -- NumberDataPoint value (one of)
--     "count":    <uint>,                  -- HistogramDataPoint.count
--     "sum":      <double>,                -- HistogramDataPoint.sum (also Sum metric? no — Sum uses asInt/asDouble)
--     "bucketCounts":   [<uint>, ...],     -- HistogramDataPoint.bucketCounts
--     "explicitBounds": [<double>, ...],   -- HistogramDataPoint.explicitBounds
--     "attributes":     [ {key,value:{...}}, ... ],   -- data point attributes
--     "resource": { "attributes": [ {key,value:{...}}, ... ] }
--   }
--   NOTE on `type`: if the producer cannot set the discriminator, downstream
--   queries can still distinguish histograms by `count != 0 OR notEmpty(bucket_counts)`.
--   We default metric_type from the presence of bucket data when `type` is absent.
--   value: NumberDataPoint carries EITHER asInt (string-encoded int) OR asDouble.
--   OTLP/JSON encodes 64-bit ints as strings — toFloat64OrZero(JSONExtractString)
--   tolerates both numeric and string encodings.
--
-- OTLP attribute arrays flatten into Map(String,String) exactly as in
-- migration 138's otel_spans_raw_mv (key -> first present scalar AnyValue).
-- =============================================================================

CREATE DATABASE IF NOT EXISTS nanosiem;

CREATE TABLE IF NOT EXISTS nanosiem.otel_metrics_raw
(
    `event` String DEFAULT '{}' CODEC(ZSTD(3)),
    `timestamp` DateTime64(9, 'UTC')
        DEFAULT fromUnixTimestamp64Nano(
            toUInt64OrZero(JSONExtractString(event, 'timeUnixNano')), 'UTC'
        ),
    `source_type` LowCardinality(String) DEFAULT 'otlp_metric'
)
ENGINE = Null
;

-- =============================================================================
-- STORAGE TABLE  (nanosiem.otel_metrics — MergeTree; MV-populated)
-- =============================================================================
-- ORDER BY (metric_name, service_name, timestamp): the dominant access is
-- "timeseries of metric M for service S over a window". DoubleDelta+ZSTD on the
-- monotonic-ish timestamp and Gorilla+ZSTD on `value` are the canonical
-- ClickHouse codecs for metric storage. Daily partitions; 90d TTL.
CREATE TABLE IF NOT EXISTS nanosiem.otel_metrics
(
    `metric_name` LowCardinality(String) CODEC(ZSTD(1)),
    `metric_type` LowCardinality(String) CODEC(ZSTD(1)),
    `unit` LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
    -- Data-point time leads neither partition nor sort prefix? It IS in the sort
    -- key (trailing) and the partition key, so it is a plain MV-written column.
    `timestamp` DateTime64(9, 'UTC') CODEC(DoubleDelta, ZSTD(1)),
    -- NumberDataPoint scalar value (gauge / sum). Histogram rows leave this 0.
    `value` Float64 CODEC(Gorilla, ZSTD(1)),
    -- HistogramDataPoint aggregates. Number rows leave these at DEFAULT.
    `count` UInt64 DEFAULT 0 CODEC(T64, ZSTD(1)),
    `sum` Float64 DEFAULT 0 CODEC(Gorilla, ZSTD(1)),
    `bucket_counts` Array(UInt64) DEFAULT [] CODEC(ZSTD(1)),
    `explicit_bounds` Array(Float64) DEFAULT [] CODEC(ZSTD(1)),
    -- RAW/NATIVE OTLP attributes (data point + resource).
    `attributes` Map(LowCardinality(String), String) CODEC(ZSTD(1)),
    `resource_attributes` Map(LowCardinality(String), String) CODEC(ZSTD(1)),
    `service_name` LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
    `ingest_time` DateTime64(6, 'UTC') DEFAULT now64(6) CODEC(Delta(8), ZSTD(3)),
    -- metric_name discrimination: set index prunes parts that lack the metric.
    INDEX idx_metric_name metric_name TYPE set(0) GRANULARITY 4
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (metric_name, service_name, timestamp)
TTL toDateTime(timestamp) + toIntervalDay(90)
SETTINGS index_granularity = 8192
;

-- =============================================================================
-- DERIVATION MATERIALIZED VIEW  (nanosiem.otel_metrics_raw_mv — Null -> MergeTree)
-- =============================================================================
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.otel_metrics_raw_mv
TO nanosiem.otel_metrics
AS SELECT
    JSONExtractString(event, 'name') AS `metric_name`,
    -- metric_type: prefer the producer-set discriminator; else infer histogram
    -- from the presence of bucket data, otherwise treat as a generic gauge.
    multiIf(
        JSONExtractString(event, 'type') != '', JSONExtractString(event, 'type'),
        length(JSONExtractArrayRaw(JSONExtractRaw(event, 'bucketCounts'))) > 0, 'histogram',
        'gauge'
    ) AS `metric_type`,
    JSONExtractString(event, 'unit') AS `unit`,
    fromUnixTimestamp64Nano(toUInt64OrZero(JSONExtractString(event, 'timeUnixNano')), 'UTC') AS `timestamp`,
    -- value: NumberDataPoint asInt OR asDouble (one of). '' -> 0.
    if(
        JSONExtractRaw(event, 'asInt') != '',
        toFloat64OrZero(JSONExtractString(event, 'asInt')),
        toFloat64OrZero(JSONExtractString(event, 'asDouble'))
    ) AS `value`,
    JSONExtractUInt(event, 'count') AS `count`,
    toFloat64OrZero(JSONExtractString(event, 'sum')) AS `sum`,
    JSONExtract(event, 'bucketCounts', 'Array(UInt64)') AS `bucket_counts`,
    JSONExtract(event, 'explicitBounds', 'Array(Float64)') AS `explicit_bounds`,
    -- attributes Map: key -> first present scalar AnyValue rendered as String
    -- (identical flattening to otel_spans_raw_mv, migration 138).
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
    -- service_name from resource.attributes 'service.name'.
    JSONExtractString(
        arrayFirst(
            kv -> JSONExtractString(kv, 'key') = 'service.name',
            JSONExtractArrayRaw(JSONExtractRaw(event, 'resource', 'attributes'))
        ),
        'value', 'stringValue'
    ) AS `service_name`
FROM nanosiem.otel_metrics_raw
;
