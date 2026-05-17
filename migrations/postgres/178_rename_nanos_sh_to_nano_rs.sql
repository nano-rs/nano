-- NAN-834: migrate seeded repo URLs and namespaced slugs from the legacy
-- GitHub org `nanos-sh` to the current `nano-rs` (renamed 2026-05-12).
--
-- Per feedback_no_modify_init_migration.md we don't edit applied migrations,
-- so the seeded URLs/slugs from 101_marketplace_catalog.sql, 110_model_catalog_sync.sql,
-- 157_playbooks.sql, and 177_seed_open_baseline.sql stay as-is. Fresh installs
-- run those migrations followed by this one, ending up at nano-rs URLs.
--
-- All updates are gated on the legacy pattern so the migration is idempotent
-- (safe to re-run) and leaves user-added rows pointing at unrelated orgs alone.

-- ----------------------------------------------------------------------------
-- enrichment_marketplace_repos — seeded "nano Enrichments" row
-- ----------------------------------------------------------------------------
UPDATE enrichment_marketplace_repos
SET url = replace(url, 'github.com/nanos-sh/', 'github.com/nano-rs/')
WHERE url LIKE 'https://github.com/nanos-sh/%';

-- ----------------------------------------------------------------------------
-- playbook_repositories — seeded "nanos-sh/playbooks" row carries an
-- org-namespaced slug, so update both columns. Guard the slug rewrite with
-- NOT EXISTS so a tenant that already added the new-slug row (rare) doesn't
-- hit a unique-violation and abort the boot-time migration.
-- ----------------------------------------------------------------------------
UPDATE playbook_repositories
SET url = replace(url, 'github.com/nanos-sh/', 'github.com/nano-rs/'),
    slug = replace(slug, 'nanos-sh/', 'nano-rs/')
WHERE url LIKE 'https://github.com/nanos-sh/%'
  AND NOT EXISTS (
    SELECT 1 FROM playbook_repositories t
    WHERE t.slug = replace(playbook_repositories.slug, 'nanos-sh/', 'nano-rs/')
  );

-- ----------------------------------------------------------------------------
-- rule_repositories — no seeded rows, but user-added entries that referenced
-- the old org keep their old URL/slug until rewritten. Same NOT EXISTS guard
-- to avoid unique-slug collisions if both legacy and new rows coexist.
-- ----------------------------------------------------------------------------
UPDATE rule_repositories
SET url = replace(url, 'github.com/nanos-sh/', 'github.com/nano-rs/'),
    slug = replace(slug, 'nanos-sh/', 'nano-rs/')
WHERE url LIKE 'https://github.com/nanos-sh/%'
  AND NOT EXISTS (
    SELECT 1 FROM rule_repositories t
    WHERE t.slug = replace(rule_repositories.slug, 'nanos-sh/', 'nano-rs/')
  );

-- ----------------------------------------------------------------------------
-- parser_repositories — same pattern as rule_repositories.
-- ----------------------------------------------------------------------------
UPDATE parser_repositories
SET url = replace(url, 'github.com/nanos-sh/', 'github.com/nano-rs/'),
    slug = replace(slug, 'nanos-sh/', 'nano-rs/')
WHERE url LIKE 'https://github.com/nanos-sh/%'
  AND NOT EXISTS (
    SELECT 1 FROM parser_repositories t
    WHERE t.slug = replace(parser_repositories.slug, 'nanos-sh/', 'nano-rs/')
  );

-- ----------------------------------------------------------------------------
-- detection_settings.model_catalog_url — flip the column DEFAULT (for any
-- future inserts) and rewrite existing rows that still hold the legacy default.
-- ----------------------------------------------------------------------------
ALTER TABLE detection_settings
    ALTER COLUMN model_catalog_url SET DEFAULT 'https://github.com/nano-rs/models';

UPDATE detection_settings
SET model_catalog_url = replace(model_catalog_url, 'github.com/nanos-sh/', 'github.com/nano-rs/')
WHERE model_catalog_url LIKE 'https://github.com/nanos-sh/%';
