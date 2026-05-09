-- NAN-572 — Marketplace Phase 2: add `security` 4th category.
--
-- The original 101 migration constrained `marketplace_catalog.category` to
-- ('data', 'agent', 'identity'). This widens the CHECK to add 'security' and
-- reclassifies the 5 threat-intel-feed entries that surface there.
--
-- The repo-sync UPSERT in `nanosiem-core/src/marketplace/repository.rs`
-- intentionally does NOT include `category` in its DO UPDATE SET clause, so
-- the reclassification below is sticky against subsequent repo syncs.

-- 1. Drop the old CHECK constraint (auto-named by Postgres in 101 since the
--    constraint was inlined on the column without an explicit name).
ALTER TABLE marketplace_catalog
    DROP CONSTRAINT IF EXISTS marketplace_catalog_category_check;

-- 2. Reclassify the 5 security-themed entries while no CHECK is in force.
--    Rows may not exist yet (the upstream nano-enrichments repo-sync inserts
--    them at runtime), so the WHERE clause is a no-op until they land.
UPDATE marketplace_catalog
   SET category = 'security'
 WHERE slug IN ('tor-exit-nodes', 'malwarebazaar', 'shodan', 'urlhaus', 'threatfox');

-- 3. Add the widened CHECK.
ALTER TABLE marketplace_catalog
    ADD CONSTRAINT marketplace_catalog_category_check
    CHECK (category IN ('data', 'agent', 'identity', 'security'));

COMMENT ON COLUMN marketplace_catalog.category IS
    'Category: data (bulk feeds), agent (on-demand lookups), identity (user sync), security (threat-intel feeds)';
