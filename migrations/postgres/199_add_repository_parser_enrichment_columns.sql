-- NAN-1149 (P1 sync layer): enrichment-parser flavor in the repo catalog.
--
-- repository_parsers caches parser.yaml files synced from the parsers GitHub
-- repo. Enrichment parsers (synced from `enrichments/<enrich_kind>/<enrich_source>/`)
-- carry a normalize VRL + target table instead of a log `parser_vrl`. All
-- columns are nullable / defaulted so existing rows and the log-parser sync path
-- are unaffected; `SELECT *` / `RETURNING *` (RepositoryParser is FromRow) pick
-- the new columns up automatically.
ALTER TABLE repository_parsers
    ADD COLUMN IF NOT EXISTS kind          TEXT NOT NULL DEFAULT 'parser',
    ADD COLUMN IF NOT EXISTS enrich_kind   TEXT,
    ADD COLUMN IF NOT EXISTS enrich_source TEXT,
    ADD COLUMN IF NOT EXISTS target_table  TEXT,
    ADD COLUMN IF NOT EXISTS normalize_vrl TEXT;
