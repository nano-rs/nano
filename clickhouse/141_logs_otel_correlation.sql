-- Migration: trace/span correlation columns on the logs lanes (NAN-1528).
--
-- WHY
-- ---
-- OTLP LogRecords ARE logs, so they ride the existing UDM/OCSF logs lane (not a
-- separate table). To pivot a log row into its distributed trace (the
-- nanosiem.otel_spans waterfall), the row needs the W3C trace context that the
-- LogRecord carried: trace_id + span_id. These are the ONLY OTLP-specific
-- additions to `logs` — everything else about an OTLP log normalizes through the
-- normal UDM parse. A `View trace` pivot in the event inspector keys on
-- `trace_id`; the bloom makes the equality lookup selective.
--
-- IDs are lowercased-hex to match the lower(col) convention used by
-- nanosiem.otel_spans.trace_id/span_id (so a logs.trace_id value joins the spans
-- table's value byte-for-byte). The Vector OTLP-log path lower()s them at the
-- edge; direct writers must supply lowercase (same contract as other id columns).
--
-- `logs` is a plain Vector/direct-written MergeTree, so ADD COLUMN is fully
-- functional immediately. `ocsf_logs` is the Null+MV-derived table (NAN-1443):
-- the columns are added for query-shape parity and accept producer/direct
-- writes, but the ocsf_logs_raw_mv is NOT rewritten here to derive them — OTLP
-- logs flow through the UDM `logs` lane, so OCSF-side MV population is
-- intentionally deferred (TODO NAN-1528: derive from a future OCSF trace-context
-- object if OCSF-native OTLP logs are added). Guarded with the
-- nano:skip-if-unknown-table marker because ocsf_logs only exists on
-- NANO_SCHEMA_PROFILE=ocsf deployments.

-- --- UDM logs lane -----------------------------------------------------------
ALTER TABLE nanosiem.logs
    ADD COLUMN IF NOT EXISTS `trace_id` String DEFAULT '' CODEC(ZSTD(1)) AFTER `session_id`;
ALTER TABLE nanosiem.logs
    ADD COLUMN IF NOT EXISTS `span_id` String DEFAULT '' CODEC(ZSTD(1)) AFTER `trace_id`;
-- trace_id equality bloom: the log->trace pivot is a whole-value lookup. IDs are
-- already lowercased at ingest, so index the raw column (raw-column bloom prunes
-- on `trace_id = '<lowered>'`, mirroring the src_ip/hash raw-compare convention).
ALTER TABLE nanosiem.logs
    ADD INDEX IF NOT EXISTS idx_trace_id trace_id TYPE bloom_filter(0.001) GRANULARITY 4;
ALTER TABLE nanosiem.logs MATERIALIZE INDEX idx_trace_id;

-- --- OCSF logs lane (profile-gated; query-shape parity) ----------------------
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */
    ADD COLUMN IF NOT EXISTS `trace_id` String DEFAULT '' CODEC(ZSTD(1));
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */
    ADD COLUMN IF NOT EXISTS `span_id` String DEFAULT '' CODEC(ZSTD(1));
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */
    ADD INDEX IF NOT EXISTS idx_trace_id trace_id TYPE bloom_filter(0.001) GRANULARITY 4;
