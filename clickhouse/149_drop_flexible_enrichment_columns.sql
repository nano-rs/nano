-- Migration: drop the dead flexible-enrichment columns from the logs lane (NAN-1624).
--
-- WHY
-- ---
-- The ten `enrichment_label_1..5` / `enrichment_value_1..5` columns (plus the
-- three `idx_enrichment_value_1..3` bloom indexes) were added by archive
-- migration 103 as generic "flexible enrichment output" label/value slots for
-- custom enrichments. They turned out to be vestigial:
--   * NEVER populated — no ingest path (Vector / Tenzir / API) ever writes them;
--     migration 132's own comment records "enrichment_value_1..5: zero populated
--     rows" (still 0 of ~4M rows on real data).
--   * NEVER query-wired — absent from `EXPLICIT_COLUMNS`, so an nPL filter like
--     `enrichment_value_1="x"` is routed to the `ext` JSON path, never the
--     physical column, so the bloom indexes never engage either.
-- They were only ever *advertised* (udmfields.csv / generated UDM docs / web
-- autocomplete), presenting dead, unqueryable columns to users.
--
-- These slots are UNRELATED to live enrichment: GeoIP rides `enriched_*`
-- (ip_enrichment_dict) and custom/IOC enrichment rides `ioc_*`
-- (ioc_enrichment_dict / custom_ioc_enrichment_dict). This is a separate dead
-- family, so dropping it is safe. Decision (NAN-1624): DROP.
--
-- Only `nanosiem.logs` carries these columns. The OCSF lane (`ocsf_logs`) never
-- had them — its custom-enrichment footprint lives in the `enrichments.*` nested
-- objects — so no ocsf_logs statement is needed here.

-- Drop the three value bloom indexes first (they reference the columns).
ALTER TABLE nanosiem.logs DROP INDEX IF EXISTS idx_enrichment_value_1;
ALTER TABLE nanosiem.logs DROP INDEX IF EXISTS idx_enrichment_value_2;
ALTER TABLE nanosiem.logs DROP INDEX IF EXISTS idx_enrichment_value_3;

-- Drop the ten label/value slot columns.
ALTER TABLE nanosiem.logs DROP COLUMN IF EXISTS enrichment_label_1;
ALTER TABLE nanosiem.logs DROP COLUMN IF EXISTS enrichment_value_1;
ALTER TABLE nanosiem.logs DROP COLUMN IF EXISTS enrichment_label_2;
ALTER TABLE nanosiem.logs DROP COLUMN IF EXISTS enrichment_value_2;
ALTER TABLE nanosiem.logs DROP COLUMN IF EXISTS enrichment_label_3;
ALTER TABLE nanosiem.logs DROP COLUMN IF EXISTS enrichment_value_3;
ALTER TABLE nanosiem.logs DROP COLUMN IF EXISTS enrichment_label_4;
ALTER TABLE nanosiem.logs DROP COLUMN IF EXISTS enrichment_value_4;
ALTER TABLE nanosiem.logs DROP COLUMN IF EXISTS enrichment_label_5;
ALTER TABLE nanosiem.logs DROP COLUMN IF EXISTS enrichment_value_5;
