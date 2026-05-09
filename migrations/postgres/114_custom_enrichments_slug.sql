-- Add slug column to custom_enrichments for marketplace-installed enrichments
ALTER TABLE custom_enrichments ADD COLUMN IF NOT EXISTS slug VARCHAR(100);
CREATE UNIQUE INDEX IF NOT EXISTS idx_ce_namespace_slug ON custom_enrichments(namespace_id, slug) WHERE slug IS NOT NULL;
