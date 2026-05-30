-- NAN-1149 (P1 of NAN-1148): enrichment-parser flavor on log_sources.
--
-- A row is an "enrichment parser" when kind = 'enrichment'. Such rows do NOT
-- describe a log source_type; instead they carry a per-source normalize VRL
-- that the Vector config generator emits as
--   [transforms.enrichment_normalize_<enrich_source>]
-- consuming enrichment_router.<enrich_source> and feeding the sink for
-- target_table. kind = 'log' (the default) is a normal log-source parser and is
-- completely unaffected. All columns are nullable / defaulted so existing rows
-- and the parser CRUD path keep working unchanged.
ALTER TABLE log_sources
    ADD COLUMN IF NOT EXISTS kind          TEXT NOT NULL DEFAULT 'log',
    ADD COLUMN IF NOT EXISTS enrich_kind   TEXT,
    ADD COLUMN IF NOT EXISTS enrich_source TEXT,
    ADD COLUMN IF NOT EXISTS target_table  TEXT,
    ADD COLUMN IF NOT EXISTS normalize_vrl TEXT;

-- Fast path for the deploy split (load only enrichment parsers).
CREATE INDEX IF NOT EXISTS idx_log_sources_kind ON log_sources (kind);
