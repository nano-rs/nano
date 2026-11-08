-- NAN-4988: repair restricted Vector writes through the OTLP raw landing MVs.
--
-- Migration 189 made the OCSF raw bridge execute as its migration owner, but
-- the span and metric bridges remained invoker-owned. Their downstream rollup
-- MVs read the stored OTLP tables, which made an INSERT by nanosiem_vector fail
-- with ACCESS_DENIED after partially writing the primary row. Keep the Vector
-- identity write-only and execute both complete MV cascades as the migration
-- owner. The guards keep UDM-only or otherwise partial schemas upgrade-safe.

ALTER TABLE nanosiem.otel_spans_raw_mv /* nano:skip-if-unknown-table */
MODIFY SQL SECURITY DEFINER DEFINER = CURRENT_USER;

ALTER TABLE nanosiem.otel_metrics_raw_mv /* nano:skip-if-unknown-table */
MODIFY SQL SECURITY DEFINER DEFINER = CURRENT_USER;
