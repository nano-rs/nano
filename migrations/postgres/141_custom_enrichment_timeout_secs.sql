-- Add configurable sandbox timeout per enrichment (default 600s = 10 minutes)
ALTER TABLE custom_enrichments ADD COLUMN IF NOT EXISTS timeout_secs INT NOT NULL DEFAULT 600;
