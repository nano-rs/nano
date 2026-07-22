-- NAN-1998 — Retire the `security` marketplace category.
--
-- Reverses NAN-572 (migration 167). `security` classified marketplace entries
-- by *topic* (threat-intel) while data/agent/identity classify by *mechanism*
-- (how the enrichment runs) — a second axis that never fit next to the others
-- and actively caused NAN-1585 (the installer derived enrichment_type from the
-- category and mislabeled the bulk feeds as agent). The threat-intel browse
-- experience survives via the `threat-intel` tags these rows already carry and
-- the curated "Security tools" section on the marketplace landing page.
--
-- The 5 former-security rows are reclassified by their real mechanism using the
-- same config-marker signal as `infer_enrichment_type` / migration 9000022:
-- `artifact_types` => on-demand agent lookup, `key_field` => bulk data feed.
-- Validated against the live Saturn catalog:
--   malwarebazaar, shodan, urlhaus  -> agent  (config carries artifact_types)
--   threatfox, tor-exit-nodes       -> data   (config carries key_field)

-- 1. Drop the CHECK so the reclassification can run.
ALTER TABLE marketplace_catalog
    DROP CONSTRAINT IF EXISTS marketplace_catalog_category_check;

-- 2. Reclassify every remaining `security` row by its config markers. Idempotent:
--    matches nothing on re-run or on fresh installs (rows arrive as data/agent
--    from repo-sync and this migration is a no-op there).
UPDATE marketplace_catalog
   SET category = CASE
           WHEN config ->> 'artifact_types' IS NOT NULL THEN 'agent'
           WHEN config ->> 'key_field'      IS NOT NULL THEN 'data'
           ELSE 'agent'
       END,
       updated_at = NOW()
 WHERE category = 'security';

-- 3. Re-add the CHECK without `security`.
ALTER TABLE marketplace_catalog
    ADD CONSTRAINT marketplace_catalog_category_check
    CHECK (category IN ('data', 'agent', 'identity'));

COMMENT ON COLUMN marketplace_catalog.category IS
    'Category: data (bulk feeds), agent (on-demand lookups), identity (user sync)';
