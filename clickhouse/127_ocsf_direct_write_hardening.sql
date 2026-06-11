-- =============================================================================
-- 127: OCSF direct-write hardening (NAN-1384, G17)
-- =============================================================================
-- Direct INSERTs into nanosiem.ocsf_logs with a bad `time` (missing / RFC3339 /
-- epoch-seconds) derived a 1970 `timestamp` from the old DEFAULT, and the 365d
-- row TTL then annihilated the row at part-write while the INSERT returned
-- HTTP 200 — silent data loss with no dead-letter. The Vector lane is immune
-- (it always writes `timestamp` explicitly), so both statements below only
-- change behavior for the direct-write path.
--
-- 1. `timestamp` DEFAULT: never yields 1970. Epoch-ms (the OCSF timestamp_t
--    spec shape) passes through unchanged; epoch-µs and epoch-seconds are
--    repaired; RFC3339 strings parse best-effort; everything else falls back
--    to now64(3). Thresholds: >=1e14 µs, >=1e10 ms (2001-09-09), >0 seconds.
-- 2. TTL guard: only sane (post-2000) timestamps are subject to retention, so
--    a client-written garbage `timestamp` survives visibly instead of being
--    deleted at part-write. Normal rows expire exactly as before.
--
-- Keep in lockstep with clickhouse/ocsf/init.sql (fresh bootstraps).
--
-- The `nano:skip-if-unknown-table` marker tells the migration runner to skip
-- the statement when the target table does not exist: `nanosiem.ocsf_logs` is
-- only created on NANO_SCHEMA_PROFILE=ocsf deployments, and ClickHouse has no
-- `ALTER TABLE IF EXISTS`. UDM-only deployments must not fail this migration.

ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */
    MODIFY COLUMN `timestamp` DateTime64(3, 'UTC')
        DEFAULT multiIf(
            toInt64OrZero(JSONExtractString(event, 'time')) >= 100000000000000,
                fromUnixTimestamp64Milli(intDiv(toInt64OrZero(JSONExtractString(event, 'time')), 1000), 'UTC'),
            toInt64OrZero(JSONExtractString(event, 'time')) >= 10000000000,
                fromUnixTimestamp64Milli(toInt64OrZero(JSONExtractString(event, 'time')), 'UTC'),
            toInt64OrZero(JSONExtractString(event, 'time')) > 0,
                fromUnixTimestamp64Milli(toInt64OrZero(JSONExtractString(event, 'time')) * 1000, 'UTC'),
            parseDateTime64BestEffortOrZero(JSONExtractString(event, 'time'), 3, 'UTC') != toDateTime64(0, 3, 'UTC'),
                parseDateTime64BestEffortOrZero(JSONExtractString(event, 'time'), 3, 'UTC'),
            now64(3, 'UTC')
        )
        CODEC(Delta(8), ZSTD(3));

ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */
    MODIFY TTL timestamp + toIntervalDay(365) DELETE WHERE timestamp > toDateTime64('2000-01-01 00:00:00', 3, 'UTC');
