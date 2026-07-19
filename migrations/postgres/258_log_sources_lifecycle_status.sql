-- NAN-1920: first-class draft lifecycle for feeds. A feed created via the
-- AddFeed wizard before a parser exists persists as 'draft' so it survives
-- navigation; it flips to 'active' on deploy. Distinct from the parser
-- working-copy "draft" (log_source_versions).
ALTER TABLE log_sources
    ADD COLUMN IF NOT EXISTS lifecycle_status TEXT NOT NULL DEFAULT 'active'
        CHECK (lifecycle_status IN ('draft', 'active'));
