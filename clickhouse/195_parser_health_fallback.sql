-- Migration: count degraded (fallback) parses and ignored source claims in
-- the per-parser health rollup (NAN-5264).
--
-- Source health reported `parse_success_rate_24h = 1.0` while 16 of 17 Apache
-- events fell back to an OCSF Base Event and Sysmon records landed as
-- activity 99 with no event time. A fallback is not a runtime failure (the
-- record still lands, with its raw body), so `parse_failure` stayed 0. The
-- generated `_ocsf_prepare` now stamps `_nano_parser_fallback` (the parser's
-- `unmapped.parse_fallback` marker only; a correctly parsed Base
-- Event is not a fallback) and the `db_parser_health` reducer ships it as
-- `parse_fallback`.
--
-- `source_claim_ignored` counts events whose sender declared a source
-- (X-Source-Type, a body `source_type`) other than the one its ingest token is
-- bound to. The token decides the source; this makes the ignored claim
-- visible on the source's health instead of only in `claimed_source_type`.
--
-- Plain ADD COLUMN IF NOT EXISTS with DEFAULT 0, so rows written before this
-- migration read as "no fallbacks". MODIFY QUERY (not DROP + CREATE) so there
-- is no window in which Vector inserts land nowhere; it takes the SELECT
-- directly, no `AS` (NAN-1727). Fresh installs get the 168 bodies from
-- init.sql and this migration upgrades them, so both paths end identical.
-- The `_distributed` wrapper over `parser_health_5m` is converged by the
-- migrator's column reconcile. No backfill: counting starts with this release.
-- Vector's sink sets `skip_unknown_fields`, so a pipeline rendered before this
-- migration ran keeps inserting.

ALTER TABLE nanosiem.parser_health_ingest ADD COLUMN IF NOT EXISTS `parse_fallback` UInt8 DEFAULT 0;

ALTER TABLE nanosiem.parser_health_ingest ADD COLUMN IF NOT EXISTS `source_claim_ignored` UInt8 DEFAULT 0;

ALTER TABLE nanosiem.parser_health_5m ADD COLUMN IF NOT EXISTS `parse_fallbacks` SimpleAggregateFunction(sum, UInt64) DEFAULT 0;

ALTER TABLE nanosiem.parser_health_5m ADD COLUMN IF NOT EXISTS `source_claims_ignored` SimpleAggregateFunction(sum, UInt64) DEFAULT 0;

ALTER TABLE nanosiem.parser_health_5m_mv
MODIFY QUERY SELECT
    parser_id,
    lower(source_type) AS source_type,
    toStartOfFiveMinute(observed_at) AS bucket_start,
    count() AS events,
    countIf(parse_failure != 0) AS parse_errors,
    countIf(parse_failure = 0 AND parse_fallback != 0) AS parse_fallbacks,
    countIf(source_claim_ignored != 0) AS source_claims_ignored
FROM nanosiem.parser_health_ingest
WHERE parser_id != ''
GROUP BY parser_id, source_type, bucket_start;
