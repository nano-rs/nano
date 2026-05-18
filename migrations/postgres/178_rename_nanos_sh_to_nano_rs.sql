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
--
-- NAN-838: every table touch is wrapped in `IF EXISTS (pg_class)` because
-- migration ordering means this file can run before the enterprise overlay
-- has created enterprise-only tables. Boot order on a fresh install is:
--   1. open-init snapshot      (creates open-core baseline)
--   2. backfill rows 1–175 in _sqlx_migrations
--   3. numbered migrations 176+ (this file runs here)
--   4. enterprise overlay      (creates playbook_repositories etc.)
-- Without these guards, fresh open-core installs fail at step 3 because
-- playbook_repositories doesn't exist yet — and the failed UPDATE aborts
-- the whole migration transaction, blocking everything.

-- ----------------------------------------------------------------------------
-- enrichment_marketplace_repos — seeded "nano Enrichments" row
-- ----------------------------------------------------------------------------
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'enrichment_marketplace_repos' AND relnamespace = 'public'::regnamespace) THEN
        UPDATE enrichment_marketplace_repos
        SET url = replace(url, 'github.com/nanos-sh/', 'github.com/nano-rs/')
        WHERE url LIKE 'https://github.com/nanos-sh/%';
    END IF;
END $$;

-- ----------------------------------------------------------------------------
-- playbook_repositories — seeded "nanos-sh/playbooks" row carries an
-- org-namespaced slug, so update both columns. Guard the slug rewrite with
-- NOT EXISTS so a tenant that already added the new-slug row (rare) doesn't
-- hit a unique-violation and abort the boot-time migration.
--
-- Enterprise-only table: not in the open-core init snapshot, so the outer
-- pg_class guard skips this entirely on fresh open-core installs.
-- ----------------------------------------------------------------------------
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'playbook_repositories' AND relnamespace = 'public'::regnamespace) THEN
        UPDATE playbook_repositories
        SET url = replace(url, 'github.com/nanos-sh/', 'github.com/nano-rs/'),
            slug = replace(slug, 'nanos-sh/', 'nano-rs/')
        WHERE url LIKE 'https://github.com/nanos-sh/%'
          AND NOT EXISTS (
            SELECT 1 FROM playbook_repositories t
            WHERE t.slug = replace(playbook_repositories.slug, 'nanos-sh/', 'nano-rs/')
          );
    END IF;
END $$;

-- ----------------------------------------------------------------------------
-- rule_repositories — no seeded rows, but user-added entries that referenced
-- the old org keep their old URL/slug until rewritten. Same NOT EXISTS guard
-- to avoid unique-slug collisions if both legacy and new rows coexist.
-- ----------------------------------------------------------------------------
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'rule_repositories' AND relnamespace = 'public'::regnamespace) THEN
        UPDATE rule_repositories
        SET url = replace(url, 'github.com/nanos-sh/', 'github.com/nano-rs/'),
            slug = replace(slug, 'nanos-sh/', 'nano-rs/')
        WHERE url LIKE 'https://github.com/nanos-sh/%'
          AND NOT EXISTS (
            SELECT 1 FROM rule_repositories t
            WHERE t.slug = replace(rule_repositories.slug, 'nanos-sh/', 'nano-rs/')
          );
    END IF;
END $$;

-- ----------------------------------------------------------------------------
-- parser_repositories — same pattern as rule_repositories.
-- ----------------------------------------------------------------------------
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'parser_repositories' AND relnamespace = 'public'::regnamespace) THEN
        UPDATE parser_repositories
        SET url = replace(url, 'github.com/nanos-sh/', 'github.com/nano-rs/'),
            slug = replace(slug, 'nanos-sh/', 'nano-rs/')
        WHERE url LIKE 'https://github.com/nanos-sh/%'
          AND NOT EXISTS (
            SELECT 1 FROM parser_repositories t
            WHERE t.slug = replace(parser_repositories.slug, 'nanos-sh/', 'nano-rs/')
          );
    END IF;
END $$;

-- ----------------------------------------------------------------------------
-- system_settings.model_catalog_url — flip the column DEFAULT (for any
-- future inserts) and rewrite existing rows that still hold the legacy default.
-- (Originally written as `detection_settings` — that table never existed; the
-- column was added to system_settings by 110_model_catalog_sync.sql.)
-- ----------------------------------------------------------------------------
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'system_settings' AND relnamespace = 'public'::regnamespace) THEN
        ALTER TABLE system_settings
            ALTER COLUMN model_catalog_url SET DEFAULT 'https://github.com/nano-rs/models';

        UPDATE system_settings
        SET model_catalog_url = replace(model_catalog_url, 'github.com/nanos-sh/', 'github.com/nano-rs/')
        WHERE model_catalog_url LIKE 'https://github.com/nanos-sh/%';
    END IF;
END $$;
