-- NAN-5954: the pre-rename GitHub org `nanos-sh` is no longer first-party.
--
-- nano's old org name `nanos-sh` is unregistered on GitHub, so anyone could
-- claim it and publish repositories. The application no longer lists it as a
-- first-party owner (marketplace::first_party, content_bundle::channels and
-- the web client), so a `nanos-sh` URL is now third-party: refused, never
-- fetched.
--
-- So that upgrades keep working, this migration moves every stored legacy
-- `github.com/nanos-sh/<repo>` URL (and org-namespaced slug) to the same
-- repository under `nano-rs`. Trust comes from the migrated URL, never from a
-- `nanos-sh` trust entry. Migration 178 did the same once, but only for the
-- exact lower-case `https://github.com/nanos-sh/` spelling and only for rows
-- that existed then; this re-runs it for any spelling the old checks accepted
-- (case, `www.`, explicit `:443`, http, no scheme) and for rows added since.
--
-- Per table, a legacy row is rewritten only when that cannot collide:
--   * no non-legacy row already names the same repository (a `nano-rs` twin);
--   * no other row already holds the target slug (case-sensitive UNIQUE);
--   * it is the first legacy row (enabled first, then lowest id) for its
--     repository AND for its target slug.
-- Every other legacy row is a duplicate: it is disabled (enabled and
-- auto-sync off, never deleted), and on the marketplace its uninstalled
-- catalog entries are hidden, as migration 307 does for third-party repos.
-- If a table's rewrite still hits a unique violation, that table falls back
-- to disabling all of its legacy rows: this migration never aborts boot on a
-- uniqueness conflict.
--
-- Forward-only and idempotent: a second run finds nothing to change. Every
-- table is guarded with to_regclass because enterprise-only tables
-- (playbook_repositories) do not exist yet on a fresh open-core install.

-- Row updates and the default change take locks on tables live instances
-- read; never queue behind a long transaction during a rolling upgrade.
SET LOCAL lock_timeout = '5s';

DO $nan5954$
DECLARE
    -- Leading part of a legacy URL: optional scheme, optional www., optional
    -- explicit :443, the org.
    legacy CONSTANT TEXT := '^(https?://)?(www[.])?github[.]com(:443)?/nanos-sh/';
    -- Comparable repository key of a GitHub URL: "<owner>/<repo>" lower-cased,
    -- without scheme, www., :443, .git or trailing slash; a legacy owner maps
    -- to nano-rs so a legacy row and its twin share one key.
    key_sql CONSTANT TEXT :=
        'regexp_replace(lower(regexp_replace(regexp_replace(btrim(%1$s.url), '
        '''^(https?://)?(www[.])?github[.]com(:443)?/'', '''', ''i''), ''([.]git)?/?$'', '''', ''i'')), '
        '''^nanos-sh/'', ''nano-rs/'')';
    tbl TEXT;
    namespaced_slug BOOLEAN;
    has_auto_sync BOOLEAN;
    rewritten BIGINT;
    disabled BIGINT;
    hidden BIGINT;
BEGIN
    FOREACH tbl IN ARRAY ARRAY[
        'enrichment_marketplace_repos', 'rule_repositories', 'parser_repositories', 'playbook_repositories'
    ] LOOP
        CONTINUE WHEN to_regclass('public.' || tbl) IS NULL;

        -- Slugs are org-namespaced ("nanos-sh/parsers") only on rule, parser
        -- and playbook repositories; the marketplace slug is a plain name and
        -- is left alone.
        namespaced_slug := tbl <> 'enrichment_marketplace_repos' AND EXISTS (
            SELECT 1 FROM information_schema.columns
             WHERE table_schema = 'public' AND table_name = tbl AND column_name = 'slug');
        has_auto_sync := EXISTS (
            SELECT 1 FROM information_schema.columns
             WHERE table_schema = 'public' AND table_name = tbl AND column_name = 'auto_sync_enabled');

        -- 1. Rewrite the one collision-free legacy row per repository/slug.
        BEGIN
            EXECUTE format($sql$
                WITH cand AS (
                    SELECT s.id,
                           COALESCE(s.enabled, TRUE) AS active,
                           %3$s AS repo_key,
                           %4$s AS new_slug,
                           %5$s AS slug_changes
                      FROM public.%1$I s
                     WHERE btrim(s.url) ~* %2$L
                ), ranked AS (
                    SELECT c.*,
                           row_number() OVER (PARTITION BY c.repo_key ORDER BY c.active DESC, c.id) AS key_rank,
                           row_number() OVER (PARTITION BY c.new_slug ORDER BY c.active DESC, c.id) AS slug_rank
                      FROM cand c
                ), winners AS (
                    SELECT k.* FROM ranked k
                     WHERE k.key_rank = 1
                       AND (NOT k.slug_changes OR k.slug_rank = 1)
                       -- a non-legacy row already names this repository
                       AND NOT EXISTS (SELECT 1 FROM public.%1$I t
                                        WHERE NOT btrim(t.url) ~* %2$L AND %6$s = k.repo_key)
                       -- another row already holds the target slug
                       AND NOT (k.slug_changes AND EXISTS (SELECT 1 FROM public.%1$I t
                                        WHERE t.id <> k.id AND t.slug = k.new_slug))
                )
                UPDATE public.%1$I u
                   SET url = regexp_replace(btrim(u.url), %2$L, 'https://github.com/nano-rs/', 'i')%7$s
                  FROM winners w
                 WHERE u.id = w.id
                $sql$,
                tbl, legacy,
                format(key_sql, 's'),
                CASE WHEN namespaced_slug THEN 'regexp_replace(s.slug, ''^nanos-sh/'', ''nano-rs/'', ''i'')'
                     ELSE 'NULL::text' END,
                CASE WHEN namespaced_slug THEN '(s.slug ~* ''^nanos-sh/'')' ELSE 'false' END,
                format(key_sql, 't'),
                CASE WHEN namespaced_slug THEN ', slug = w.new_slug' ELSE '' END);
            GET DIAGNOSTICS rewritten = ROW_COUNT;
        EXCEPTION WHEN unique_violation THEN
            RAISE WARNING 'NAN-5954 %: rewriting legacy nanos-sh rows hit a unique conflict (%); disabling them all instead',
                tbl, SQLERRM;
            rewritten := 0;
        END;

        -- 2. Whatever still names nanos-sh is a duplicate: disable it,
        --    including rows with enabled NULL or auto-sync still on.
        EXECUTE format(
            'UPDATE public.%1$I SET enabled = false%2$s '
            'WHERE btrim(url) ~* %3$L AND (COALESCE(enabled, TRUE)%4$s)',
            tbl,
            CASE WHEN has_auto_sync THEN ', auto_sync_enabled = false' ELSE '' END,
            legacy,
            CASE WHEN has_auto_sync THEN ' OR COALESCE(auto_sync_enabled, FALSE)' ELSE '' END);
        GET DIAGNOSTICS disabled = ROW_COUNT;

        -- 3. Marketplace: hide the uninstalled catalog entries of those
        --    duplicates (same rule as migration 307 for third-party repos).
        hidden := 0;
        IF tbl = 'enrichment_marketplace_repos'
           AND to_regclass('public.marketplace_catalog') IS NOT NULL
           AND EXISTS (SELECT 1 FROM information_schema.columns
                        WHERE table_schema = 'public' AND table_name = 'marketplace_catalog'
                          AND column_name = 'hidden_reason') THEN
            UPDATE public.marketplace_catalog c
               SET hidden_reason = 'third_party_repository'
              FROM public.enrichment_marketplace_repos r
             WHERE c.repository_id = r.id
               AND c.installed = false
               AND c.hidden_reason IS NULL
               AND btrim(r.url) ~* legacy;
            GET DIAGNOSTICS hidden = ROW_COUNT;
        END IF;

        RAISE NOTICE 'NAN-5954 %: % legacy nanos-sh row(s) moved to nano-rs, % duplicate row(s) disabled, % catalog entries hidden',
            tbl, rewritten, disabled, hidden;
    END LOOP;

    -- system_settings.model_catalog_url: same rewrite. The nano-rs column
    -- default is set only when it is still wrong (178 already set it on most
    -- installs), so the ALTER's ACCESS EXCLUSIVE lock is normally skipped.
    IF to_regclass('public.system_settings') IS NOT NULL AND EXISTS (
        SELECT 1 FROM information_schema.columns
         WHERE table_schema = 'public' AND table_name = 'system_settings' AND column_name = 'model_catalog_url'
    ) THEN
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
             WHERE table_schema = 'public' AND table_name = 'system_settings' AND column_name = 'model_catalog_url'
               AND COALESCE(column_default, '') NOT LIKE '''https://github.com/nano-rs/models''%'
        ) THEN
            ALTER TABLE public.system_settings
                ALTER COLUMN model_catalog_url SET DEFAULT 'https://github.com/nano-rs/models';
        END IF;
        UPDATE public.system_settings
           SET model_catalog_url = regexp_replace(btrim(model_catalog_url), legacy, 'https://github.com/nano-rs/', 'i')
         WHERE btrim(model_catalog_url) ~* legacy;
        GET DIAGNOSTICS rewritten = ROW_COUNT;
        RAISE NOTICE 'NAN-5954 system_settings: % legacy nanos-sh model catalog URL(s) moved to nano-rs', rewritten;
    END IF;
END
$nan5954$;
