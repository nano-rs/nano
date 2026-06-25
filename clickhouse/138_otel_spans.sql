-- Migration: OTLP trace/span ingestion lane (NAN-1528).
--
-- WHAT THIS IS
-- ------------
-- OpenTelemetry spans land here via the SAME Null-table + MATERIALIZED-VIEW
-- derivation idiom the canonical OCSF schema uses (clickhouse/ocsf/init.sql:
-- ocsf_logs_raw -> ocsf_logs_raw_mv -> ocsf_logs). A producer (Vector's
-- opentelemetry source, or a direct OTLP/Tenzir/Cribl writer) flattens ONE OTLP
-- span into ONE row and writes the full OTLP/JSON span object into the single
-- `event` column on the Null staging table `nanosiem.otel_spans_raw`; the MV
-- `nanosiem.otel_spans_raw_mv` derives every promoted/indexed column from it via
-- JSONExtract* and writes the result to the MergeTree storage table
-- `nanosiem.otel_spans`. The OTLP->column mapping lives ONCE, in the MV (SQL).
--
-- ONE ROW = ONE SPAN. Producers MUST flatten the OTLP ResourceSpans ->
-- ScopeSpans -> Span nesting before writing, hoisting the owning resource's
-- attributes alongside the span (the span object the producer emits carries a
-- `resource` sub-object with its `attributes`, matching the OCSF `event`
-- mental model). This makes Vector AND direct producers write the identical
-- row shape — the `event` blob is the only contract.
--
-- TRACES ARE STORED RAW / NATIVE (NOT re-normalized into UDM). The full OTLP
-- semantic-convention attribute set is preserved losslessly in the
-- `attributes` / `resource_attributes` Map columns. We ADD a thin entity
-- overlay (src_ip / dest_ip / user / host) promoted to indexed columns purely
-- for security correlation — we do NOT discard the raw maps.
--
-- THE INGESTION CONTRACT  (what a producer writes to otel_spans_raw)
-- ------------------------------------------------------------------
--   1. `event`       — the full OTLP/JSON span object for ONE span, WITH its
--                      owning `resource` sub-object (so resource.attributes is
--                      reachable). Normal (non-ephemeral) column so CH's
--                      implicit no-column-list INSERT (Vector clickhouse sink)
--                      populates it; explicit `(event, ...)` inserts also work.
--   2. `timestamp`   — the row's event time. Optional; the MV derives
--                      start_time from the span's startTimeUnixNano regardless.
--   3. `source_type` — ingest-routing identity; DEFAULT 'otlp_trace'.
--
-- OTLP/JSON SPAN FIELD NAMES  (OTLP 1.x JSON encoding — camelCase)
-- ----------------------------------------------------------------
--   traceId / spanId / parentSpanId  — HEX strings in the JSON encoding (the
--     protobuf bytes are hex-encoded by the OTLP/JSON exporter). We lower() them
--     to match nano's lower(col) id convention. NOTE: if a producer instead
--     emits raw bytes / base64, the values land verbatim and still index; the
--     JSON encoding's hex form is the assumed/common shape.
--   name                              — span name.
--   kind                              — INT enum 0..5; mapped to the OTLP
--     SpanKind string (0 UNSPECIFIED -> INTERNAL per spec default, 1 INTERNAL,
--     2 SERVER, 3 CLIENT, 4 PRODUCER, 5 CONSUMER).
--   startTimeUnixNano / endTimeUnixNano — epoch NANOSECONDS as a (possibly
--     string-encoded) integer; OTLP/JSON encodes 64-bit ints as strings, so we
--     parse with toUInt64OrZero(JSONExtractString(...)) to tolerate both forms.
--   status.code                       — INT enum 0/1/2 -> UNSET/OK/ERROR.
--   status.message                    — free-text status description.
--   attributes / resource.attributes  — OTLP KeyValue ARRAYS of
--     {key, value:{stringValue|intValue|doubleValue|boolValue|...}}. Flattened
--     into Map(String,String): each entry's key -> the first present scalar
--     value rendered as a String (see the attr-flattening helper comment in the
--     MV). Nested array/kvlist values are not flattened (rare for security use);
--     they fall out as '' — the raw tail is recoverable from the producer if
--     needed (we do not persist `event` here, mirroring OCSF's promoted-only
--     storage; security-relevant attrs are promoted via the overlay below).
--   duration_ns = endTimeUnixNano - startTimeUnixNano (0 if either missing).
--
-- ENTITY OVERLAY (security correlation; extracted from OTLP semconv attrs):
--   src_ip  <- attributes 'client.address' else 'network.peer.address'
--   dest_ip <- attributes 'server.address'
--   user    <- attributes 'enduser.id' else 'user.name'
--   host    <- attributes 'host.name' (resource attr) else span attr 'host.name'
--   service_name <- resource.attributes 'service.name'
--   These are extracted directly from the OTLP attribute arrays (NOT from the
--   flattened Map, which is produced in the same SELECT and cannot be
--   self-referenced), via the same arrayFirst(... key = '<k>' ...) idiom.
--   lower()'d like the UDM entity columns so the lower(col) fast-path applies.
-- =============================================================================

CREATE DATABASE IF NOT EXISTS nanosiem;

-- Null staging table: the implicit-insertable derivation source. ENGINE = Null
-- stores nothing; otel_spans_raw_mv reads each inserted block and writes derived
-- rows to nanosiem.otel_spans. `event` is a NORMAL column so the no-column-list
-- Vector INSERT populates it (mirrors nanosiem.ocsf_logs_raw, NAN-1443).
CREATE TABLE IF NOT EXISTS nanosiem.otel_spans_raw
(
    `event` String DEFAULT '{}' CODEC(ZSTD(3)),
    `timestamp` DateTime64(9, 'UTC')
        DEFAULT fromUnixTimestamp64Nano(
            toUInt64OrZero(JSONExtractString(event, 'startTimeUnixNano')), 'UTC'
        ),
    `source_type` LowCardinality(String) DEFAULT 'otlp_trace'
)
ENGINE = Null
;

-- =============================================================================
-- STORAGE TABLE  (nanosiem.otel_spans — MergeTree; MV-populated)
-- =============================================================================
-- ORDER BY (service_name, span_name, start_time, trace_id) clusters spans by
-- service/operation/time for the common "slow SERVER spans for service X" hunt;
-- trace_id trails the key and is also bloom-indexed for trace-assembly lookups
-- (the otel_spans_trace_id_ts AggregatingMergeTree in migration 139 makes the
-- [min,max] window resolution cheap). Daily partitions on start_time; 30d TTL.
CREATE TABLE IF NOT EXISTS nanosiem.otel_spans
(
    -- W3C trace context ids, lowercased-hex (lower(col) convention).
    `trace_id` String CODEC(ZSTD(1)),
    `span_id` String CODEC(ZSTD(1)),
    `parent_span_id` String DEFAULT '' CODEC(ZSTD(1)),

    -- Span timing. nanos precision (OTLP carries ns); Delta+ZSTD like UDM/OCSF
    -- timestamps. start_time leads partition/sort key so it is a plain column
    -- the MV writes directly (CH forbids MATERIALIZED in the sort key).
    `start_time` DateTime64(9, 'UTC') CODEC(Delta(8), ZSTD(3)),
    `end_time`   DateTime64(9, 'UTC') CODEC(Delta(8), ZSTD(3)),
    `duration_ns` UInt64 CODEC(T64, ZSTD(1)),

    -- Span identity / classification (LowCardinality: bounded sets).
    `service_name` LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
    `span_name` LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
    `span_kind` LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
    `status_code` LowCardinality(String) DEFAULT '' CODEC(ZSTD(1)),
    `status_message` String DEFAULT '' CODEC(ZSTD(1)),

    -- RAW/NATIVE OTLP attributes preserved losslessly (semantic conventions).
    `attributes` Map(LowCardinality(String), String) CODEC(ZSTD(1)),
    `resource_attributes` Map(LowCardinality(String), String) CODEC(ZSTD(1)),

    -- The span's events[] array, kept as the raw OTLP/JSON tail (rare-access).
    `events` String DEFAULT '' CODEC(ZSTD(3)),

    -- Thin security-correlation entity overlay (from OTLP semconv attrs).
    `src_ip` String DEFAULT '' CODEC(ZSTD(1)),
    `dest_ip` String DEFAULT '' CODEC(ZSTD(1)),
    `user` String DEFAULT '' CODEC(ZSTD(1)),
    `host` String DEFAULT '' CODEC(ZSTD(1)),

    -- Insert clock (parity with UDM/OCSF bookkeeping).
    `ingest_time` DateTime64(6, 'UTC') DEFAULT now64(6) CODEC(Delta(8), ZSTD(3)),

    -- trace_id equality bloom for trace-assembly lookups.
    INDEX idx_trace_id trace_id TYPE bloom_filter(0.001) GRANULARITY 1,
    -- Case-insensitive span-name fragment hunts (lower(col) text-index convention).
    INDEX idx_span_words lower(span_name) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1,
    -- Slow-span hunts (duration_ns > threshold) prune granules.
    INDEX idx_duration duration_ns TYPE minmax GRANULARITY 4
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(start_time)
ORDER BY (service_name, span_name, start_time, trace_id)
TTL toDateTime(start_time) + toIntervalDay(30)
SETTINGS index_granularity = 8192
;

-- =============================================================================
-- DERIVATION MATERIALIZED VIEW  (nanosiem.otel_spans_raw_mv — Null -> MergeTree)
-- =============================================================================
-- Reads each block inserted into nanosiem.otel_spans_raw, derives every promoted
-- column from `event` (the OTLP/JSON span object), and writes to
-- nanosiem.otel_spans. Works for BOTH implicit (Vector clickhouse sink) and
-- explicit (Tenzir `(event, source_type)`) inserts.
--
-- ATTRIBUTE-ARRAY -> Map FLATTENING
-- ---------------------------------
-- OTLP attributes are arrays of {key, value:{stringValue|intValue|...}}. For each
-- KeyValue we render the FIRST present scalar value as a String and build a Map:
--     CAST(
--       (arrayMap(kv -> JSONExtractString(kv, 'key'),         <attr_array>),
--        arrayMap(kv -> <scalar-value-of(kv)>,                <attr_array>)),
--       'Map(String, String)'
--     )
-- where <attr_array> = JSONExtractArrayRaw(JSONExtractRaw(event, ...)) and the
-- scalar-value extractor coalesces stringValue / intValue / doubleValue /
-- boolValue (the common scalar OTLP AnyValue shapes; intValue/doubleValue are
-- JSON-encoded as strings/numbers — JSONExtractString reads either as text).
-- =============================================================================
CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.otel_spans_raw_mv
TO nanosiem.otel_spans
AS SELECT
    lower(JSONExtractString(event, 'traceId')) AS `trace_id`,
    lower(JSONExtractString(event, 'spanId')) AS `span_id`,
    lower(JSONExtractString(event, 'parentSpanId')) AS `parent_span_id`,
    fromUnixTimestamp64Nano(toUInt64OrZero(JSONExtractString(event, 'startTimeUnixNano')), 'UTC') AS `start_time`,
    fromUnixTimestamp64Nano(toUInt64OrZero(JSONExtractString(event, 'endTimeUnixNano')), 'UTC') AS `end_time`,
    -- duration: end - start in ns (0 when either bound is missing/<= the other).
    -- Compute the delta in Int64 (UInt64-UInt64 promotes to Int64 anyway), clamp
    -- negatives to 0 with greatest(), then toUInt64. Doing it on a single Int64
    -- value avoids the Variant(Int64,UInt64) that an if()-with-mixed-branches
    -- produces (which silently fails the UInt64 column insert).
    toUInt64(greatest(
        toInt64(toUInt64OrZero(JSONExtractString(event, 'endTimeUnixNano'))) - toInt64(toUInt64OrZero(JSONExtractString(event, 'startTimeUnixNano'))),
        toInt64(0)
    )) AS `duration_ns`,
    -- service_name from resource.attributes 'service.name'.
    JSONExtractString(
        arrayFirst(
            kv -> JSONExtractString(kv, 'key') = 'service.name',
            JSONExtractArrayRaw(JSONExtractRaw(event, 'resource', 'attributes'))
        ),
        'value', 'stringValue'
    ) AS `service_name`,
    JSONExtractString(event, 'name') AS `span_name`,
    -- OTLP SpanKind int -> string (0 UNSPECIFIED defaults to INTERNAL).
    multiIf(
        JSONExtractInt(event, 'kind') = 2, 'SERVER',
        JSONExtractInt(event, 'kind') = 3, 'CLIENT',
        JSONExtractInt(event, 'kind') = 4, 'PRODUCER',
        JSONExtractInt(event, 'kind') = 5, 'CONSUMER',
        'INTERNAL'
    ) AS `span_kind`,
    -- OTLP StatusCode int -> string (0 UNSET, 1 OK, 2 ERROR).
    multiIf(
        JSONExtractInt(event, 'status', 'code') = 1, 'OK',
        JSONExtractInt(event, 'status', 'code') = 2, 'ERROR',
        'UNSET'
    ) AS `status_code`,
    JSONExtractString(event, 'status', 'message') AS `status_message`,
    -- attributes Map: key -> first present scalar AnyValue rendered as String.
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
    -- Raw events[] tail preserved verbatim for span-event drill-in.
    JSONExtractRaw(event, 'events') AS `events`,
    -- Entity overlay: extracted from the OTLP attribute arrays (NOT the Map
    -- aliases above, which cannot be self-referenced in the same SELECT).
    -- src_ip: prefer client.address, else network.peer.address.
    lower(if(
        JSONExtractString(arrayFirst(kv -> JSONExtractString(kv, 'key') = 'client.address', JSONExtractArrayRaw(JSONExtractRaw(event, 'attributes'))), 'value', 'stringValue') != '',
        JSONExtractString(arrayFirst(kv -> JSONExtractString(kv, 'key') = 'client.address', JSONExtractArrayRaw(JSONExtractRaw(event, 'attributes'))), 'value', 'stringValue'),
        JSONExtractString(arrayFirst(kv -> JSONExtractString(kv, 'key') = 'network.peer.address', JSONExtractArrayRaw(JSONExtractRaw(event, 'attributes'))), 'value', 'stringValue')
    )) AS `src_ip`,
    -- dest_ip: server.address.
    lower(JSONExtractString(arrayFirst(kv -> JSONExtractString(kv, 'key') = 'server.address', JSONExtractArrayRaw(JSONExtractRaw(event, 'attributes'))), 'value', 'stringValue')) AS `dest_ip`,
    -- user: prefer enduser.id, else user.name.
    lower(if(
        JSONExtractString(arrayFirst(kv -> JSONExtractString(kv, 'key') = 'enduser.id', JSONExtractArrayRaw(JSONExtractRaw(event, 'attributes'))), 'value', 'stringValue') != '',
        JSONExtractString(arrayFirst(kv -> JSONExtractString(kv, 'key') = 'enduser.id', JSONExtractArrayRaw(JSONExtractRaw(event, 'attributes'))), 'value', 'stringValue'),
        JSONExtractString(arrayFirst(kv -> JSONExtractString(kv, 'key') = 'user.name', JSONExtractArrayRaw(JSONExtractRaw(event, 'attributes'))), 'value', 'stringValue')
    )) AS `user`,
    -- host: prefer resource attr host.name, else span attr host.name.
    lower(if(
        JSONExtractString(arrayFirst(kv -> JSONExtractString(kv, 'key') = 'host.name', JSONExtractArrayRaw(JSONExtractRaw(event, 'resource', 'attributes'))), 'value', 'stringValue') != '',
        JSONExtractString(arrayFirst(kv -> JSONExtractString(kv, 'key') = 'host.name', JSONExtractArrayRaw(JSONExtractRaw(event, 'resource', 'attributes'))), 'value', 'stringValue'),
        JSONExtractString(arrayFirst(kv -> JSONExtractString(kv, 'key') = 'host.name', JSONExtractArrayRaw(JSONExtractRaw(event, 'attributes'))), 'value', 'stringValue')
    )) AS `host`
FROM nanosiem.otel_spans_raw
;
