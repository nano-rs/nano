-- NAN-569: extend SIEM Health reports with enrichment + alerting dimension scores
-- The Wave 23 redesign reframed the page around 5 pipeline stages
-- (Ingestion → Parsing → Enrichment → Detection → Alerting). The collector now
-- measures all 5; this migration adds the two new score columns.
--
-- Both columns are nullable so old reports (pre-NAN-569) still load — the
-- frontend renders "not yet measured" for null scores.

ALTER TABLE siem_health_reports
    ADD COLUMN IF NOT EXISTS enrichment_score INTEGER,
    ADD COLUMN IF NOT EXISTS alerting_score INTEGER;
