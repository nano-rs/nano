-- =============================================================================
-- OCSF/190: direct-writer future timestamp guard (NAN-4939)
-- =============================================================================
-- Runs after ocsf/init.sql under the ocsf/ migration namespace, so fresh and
-- upgraded OCSF installations use the same numbered migration path.
--
-- Vector sends a clamped timestamp and this per-row skew value. Direct writers
-- (Tenzir, audit, findings) send {event, source_type}; their omitted timestamp
-- follows this DEFAULT. The original OCSF time remains in event.time, which is
-- stored in the target event JSON for audit and repair. Metadata-only ALTERs;
-- no boot-time rewrite.

ALTER TABLE nanosiem.ocsf_logs_raw
    ADD COLUMN IF NOT EXISTS `future_timestamp_skew_seconds` UInt64 DEFAULT 86400
    AFTER `event`;

ALTER TABLE nanosiem.ocsf_logs_raw
    MODIFY COLUMN `timestamp` DateTime64(3, 'UTC') DEFAULT
        if(
            if(
                ifNull(accurateCastOrNull(event.time, 'Int64'), 0) > 0,
                -- Compare numeric epoch values before constructing DateTime64.
                -- This safely catches values such as year-9999 milliseconds,
                -- which lie beyond ClickHouse's DateTime64 range.
                multiIf(
                    accurateCastOrNull(event.time, 'Int64') >= 1000000000000000,
                        intDiv(accurateCastOrNull(event.time, 'Int64'), 1000),
                    accurateCastOrNull(event.time, 'Int64') >= 10000000000,
                        accurateCastOrNull(event.time, 'Int64'),
                    accurateCastOrNull(event.time, 'Int64') * 1000)
                    > toUnixTimestamp64Milli(now64(3, 'UTC'))
                        + toInt64(future_timestamp_skew_seconds) * 1000,
                parseDateTime64BestEffortOrZero(ifNull(toString(event.time), ''), 3, 'UTC')
                    > now64(3, 'UTC') + toIntervalSecond(future_timestamp_skew_seconds)),
            now64(3, 'UTC'),
            multiIf(
                ifNull(accurateCastOrNull(event.time, 'Int64'), 0) >= 1000000000000000,
                    fromUnixTimestamp64Milli(intDiv(accurateCastOrNull(event.time, 'Int64'), 1000), 'UTC'),
                ifNull(accurateCastOrNull(event.time, 'Int64'), 0) >= 10000000000,
                    fromUnixTimestamp64Milli(accurateCastOrNull(event.time, 'Int64'), 'UTC'),
                ifNull(accurateCastOrNull(event.time, 'Int64'), 0) > 0,
                    fromUnixTimestamp64Milli(accurateCastOrNull(event.time, 'Int64') * 1000, 'UTC'),
                parseDateTime64BestEffortOrZero(ifNull(toString(event.time), ''), 3, 'UTC') != toDateTime64(0, 3, 'UTC'),
                    parseDateTime64BestEffortOrZero(ifNull(toString(event.time), ''), 3, 'UTC'),
                now64(3, 'UTC')));
