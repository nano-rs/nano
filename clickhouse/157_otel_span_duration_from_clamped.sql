-- Migration: derive OTLP span duration_ns from the CLAMPED start/end times (NAN-1731, O2/156).
--
-- WHY
-- ---
-- Migration 156 (NAN-1721, O2/O23) clamps a missing / unparseable / absurd-future
-- `startTimeUnixNano` / `endTimeUnixNano` so the `start_time` / `end_time` columns
-- land at ingest time `now64(9)` instead of 1970 (silent TTL data loss). But the
-- SAME MV still computed `duration_ns` from the RAW, UNCLAMPED nano timestamps:
--   toUInt64(greatest(
--     toInt64(toUInt64OrZero(endTimeUnixNano)) - toInt64(toUInt64OrZero(startTimeUnixNano)),
--     toInt64(0)))
-- So a span with raw start=0 but end≈now gets duration_ns ≈ 1.78e18 ns ≈ 56.6 years,
-- while start_time / end_time are both ≈now. That single poison span poisons the
-- p95 / p99 latency and the RED `duration_state` rollup for its service (measured:
-- affected-service p95 = 56.6 years).
--
-- FIX
-- ---
-- Compute duration from the CLAMPED `start_time` / `end_time` aliases (defined
-- earlier in the same SELECT — 156 defines them BEFORE duration_ns, and ClickHouse
-- lets a later SELECT-list expression reference an earlier alias):
--   toUInt64(greatest(toInt64(dateDiff('nanosecond', start_time, end_time)), toInt64(0)))
-- A clamped-start span then has start_time≈end_time≈now -> duration≈0 (sane);
-- legitimate spans keep their true duration (dateDiff('nanosecond', ...) is
-- full-precision on DateTime64(9) — verified byte-exact vs the raw-nano diff).
--
-- Implemented as `ALTER TABLE <mv> MODIFY QUERY` (NOT DROP+CREATE) so there is no
-- window where the MV is absent and inserts go underived. The column list & order
-- are byte-identical to 156 except the duration_ns expression, preserving the
-- MV->target positional mapping. Only otel_spans_raw_mv carries a duration; the
-- metrics MV is unaffected and is left untouched. The cluster transform adds
-- ON CLUSTER. (MODIFY QUERY takes the SELECT directly — no AS; see NAN-1727.)
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
    -- NAN-1731: duration from the CLAMPED start/end aliases, not the raw nanos, so a
    -- clamped-start span is ~0 instead of ~56.6 years poisoning p95/p99 & RED rollups.
    toUInt64(greatest(toInt64(dateDiff('nanosecond', start_time, end_time)), toInt64(0))) AS `duration_ns`,
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
