-- Migration: clamp OTLP span/metric event timestamps in the derivation MVs (NAN-1721, O2/O23).
--
-- WHY
-- ---
-- The otel_spans / otel_metrics derivation MVs (138/140) compute the partition &
-- TTL key straight from the producer's `startTimeUnixNano` / `timeUnixNano` via
-- `fromUnixTimestamp64Nano(toUInt64OrZero(...))`. Any missing / unparseable /
-- out-of-range value parses to 0 -> `1970-01-01`, which:
--   * lands in partition 19700101, and
--   * is already 55 years past the 30d/90d TTL, so the row is reaped at the first
--     TTL merge with NO error and NO dead-letter (O2 — silent data loss;
--     empirically confirmed ttl_expired=1 on local CH).
-- A single batch whose timestamps scatter across many bogus partitions can also
-- trip max_partitions_per_insert_block and abort the WHOLE block, dropping good
-- spans alongside the poison ones (O23).
--
-- The Vector lane's producer-side fallback is fixed separately (03-otlp-source.toml,
-- O2); this MV clamp is the robust backstop that also covers DIRECT producers
-- (Tenzir/Cribl/raw OTLP) which bypass Vector and write to *_raw directly.
--
-- FIX
-- ---
-- Wrap the event-time expressions so that a 0 (missing/unparseable) or an absurd
-- future value (clock-skewed / unit-confused / >2106 wrap) degrades to ingest
-- time `now64(9)` instead of 1970 / a partition-exploding date. Legitimate past
-- timestamps (including in-retention backfill) pass through unchanged; anything
-- genuinely older than the TTL still expires, as intended.
--
-- Implemented as `ALTER TABLE <mv> MODIFY QUERY` (NOT DROP+CREATE) so there is no
-- window where the MV is absent and inserts go underived. The column list & order
-- are byte-identical to 138/140 except the wrapped time expressions, preserving
-- the MV->target positional mapping. The cluster transform adds ON CLUSTER.
-- =============================================================================

ALTER TABLE nanosiem.otel_spans_raw_mv
MODIFY QUERY SELECT
    lower(JSONExtractString(event, 'traceId')) AS `trace_id`,
    lower(JSONExtractString(event, 'spanId')) AS `span_id`,
    lower(JSONExtractString(event, 'parentSpanId')) AS `parent_span_id`,
    -- O2/O23: clamp 0/unparseable/absurd-future startTimeUnixNano to ingest time.
    multiIf(
        toUInt64OrZero(JSONExtractString(event, 'startTimeUnixNano')) = 0, now64(9, 'UTC'),
        fromUnixTimestamp64Nano(toUInt64OrZero(JSONExtractString(event, 'startTimeUnixNano')), 'UTC') > now64(9, 'UTC') + toIntervalDay(1), now64(9, 'UTC'),
        fromUnixTimestamp64Nano(toUInt64OrZero(JSONExtractString(event, 'startTimeUnixNano')), 'UTC')
    ) AS `start_time`,
    multiIf(
        toUInt64OrZero(JSONExtractString(event, 'endTimeUnixNano')) = 0, now64(9, 'UTC'),
        fromUnixTimestamp64Nano(toUInt64OrZero(JSONExtractString(event, 'endTimeUnixNano')), 'UTC') > now64(9, 'UTC') + toIntervalDay(1), now64(9, 'UTC'),
        fromUnixTimestamp64Nano(toUInt64OrZero(JSONExtractString(event, 'endTimeUnixNano')), 'UTC')
    ) AS `end_time`,
    toUInt64(greatest(
        toInt64(toUInt64OrZero(JSONExtractString(event, 'endTimeUnixNano'))) - toInt64(toUInt64OrZero(JSONExtractString(event, 'startTimeUnixNano'))),
        toInt64(0)
    )) AS `duration_ns`,
    JSONExtractString(
        arrayFirst(
            kv -> JSONExtractString(kv, 'key') = 'service.name',
            JSONExtractArrayRaw(JSONExtractRaw(event, 'resource', 'attributes'))
        ),
        'value', 'stringValue'
    ) AS `service_name`,
    JSONExtractString(event, 'name') AS `span_name`,
    multiIf(
        JSONExtractInt(event, 'kind') = 2, 'SERVER',
        JSONExtractInt(event, 'kind') = 3, 'CLIENT',
        JSONExtractInt(event, 'kind') = 4, 'PRODUCER',
        JSONExtractInt(event, 'kind') = 5, 'CONSUMER',
        'INTERNAL'
    ) AS `span_kind`,
    multiIf(
        JSONExtractInt(event, 'status', 'code') = 1, 'OK',
        JSONExtractInt(event, 'status', 'code') = 2, 'ERROR',
        'UNSET'
    ) AS `status_code`,
    JSONExtractString(event, 'status', 'message') AS `status_message`,
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
    JSONExtractRaw(event, 'events') AS `events`,
    lower(if(
        JSONExtractString(arrayFirst(kv -> JSONExtractString(kv, 'key') = 'client.address', JSONExtractArrayRaw(JSONExtractRaw(event, 'attributes'))), 'value', 'stringValue') != '',
        JSONExtractString(arrayFirst(kv -> JSONExtractString(kv, 'key') = 'client.address', JSONExtractArrayRaw(JSONExtractRaw(event, 'attributes'))), 'value', 'stringValue'),
        JSONExtractString(arrayFirst(kv -> JSONExtractString(kv, 'key') = 'network.peer.address', JSONExtractArrayRaw(JSONExtractRaw(event, 'attributes'))), 'value', 'stringValue')
    )) AS `src_ip`,
    lower(JSONExtractString(arrayFirst(kv -> JSONExtractString(kv, 'key') = 'server.address', JSONExtractArrayRaw(JSONExtractRaw(event, 'attributes'))), 'value', 'stringValue')) AS `dest_ip`,
    lower(if(
        JSONExtractString(arrayFirst(kv -> JSONExtractString(kv, 'key') = 'enduser.id', JSONExtractArrayRaw(JSONExtractRaw(event, 'attributes'))), 'value', 'stringValue') != '',
        JSONExtractString(arrayFirst(kv -> JSONExtractString(kv, 'key') = 'enduser.id', JSONExtractArrayRaw(JSONExtractRaw(event, 'attributes'))), 'value', 'stringValue'),
        JSONExtractString(arrayFirst(kv -> JSONExtractString(kv, 'key') = 'user.name', JSONExtractArrayRaw(JSONExtractRaw(event, 'attributes'))), 'value', 'stringValue')
    )) AS `user`,
    lower(if(
        JSONExtractString(arrayFirst(kv -> JSONExtractString(kv, 'key') = 'host.name', JSONExtractArrayRaw(JSONExtractRaw(event, 'resource', 'attributes'))), 'value', 'stringValue') != '',
        JSONExtractString(arrayFirst(kv -> JSONExtractString(kv, 'key') = 'host.name', JSONExtractArrayRaw(JSONExtractRaw(event, 'resource', 'attributes'))), 'value', 'stringValue'),
        JSONExtractString(arrayFirst(kv -> JSONExtractString(kv, 'key') = 'host.name', JSONExtractArrayRaw(JSONExtractRaw(event, 'attributes'))), 'value', 'stringValue')
    )) AS `host`
FROM nanosiem.otel_spans_raw
;

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
    ) AS `service_name`
FROM nanosiem.otel_metrics_raw
;
