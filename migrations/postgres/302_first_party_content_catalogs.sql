-- SPDX-License-Identifier: AGPL-3.0-or-later
-- NAN-4940: first-party content catalogs (nano-rs/parsers, nano-rs/rules).
--
-- 1. Adoption marker. The leader's repository sync schedulers register both
--    catalogs on every start (nanosiem-core `content_catalog_defaults`, ported
--    from main's NAN-3758 / NAN-3897). One row here per catalog records that
--    the reconcile has registered or adopted it on this install. From then on
--    the operator owns the catalog: a deleted catalog is not re-created and
--    auto-sync turned off is not turned back on. Before adoption (a fresh
--    install, or an upgrade from a build without the reconcile) a missing
--    catalog is registered and an enabled one is switched to auto-sync.
--
-- 2. One row per first-party catalog per table. A partial unique index on the
--    normalized URL (`nano-rs/parsers` / `nano-rs/rules`; scheme, `www.`,
--    case, `.git` and a trailing slash ignored, matching
--    `schema::is_first_party_content_url`) stops a concurrent API create and
--    the boot reconcile from both registering the catalog. The application
--    also serializes both paths on one advisory lock, so this is the backstop.
--    An install that already holds duplicates keeps them: the index is then
--    skipped with a WARNING rather than failing the migration, and the
--    advisory lock still prevents new ones.
--
-- Profile-aware branch selection (OCSF -> `main`, UDM -> `legacy/clickhouse`)
-- needs NANO_SCHEMA_PROFILE, which SQL cannot see, so every row change is made
-- by the boot reconcile, not here. Forward-only and idempotent.
CREATE TABLE IF NOT EXISTS first_party_content_catalogs (
    catalog TEXT PRIMARY KEY CHECK (catalog IN ('parsers', 'rules')),
    repository_id UUID,
    adopted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE first_party_content_catalogs IS
    'NAN-4940: first-party catalogs (nano-rs/parsers, nano-rs/rules) the boot reconcile has registered or adopted; after adoption a removal or auto-sync opt-out is the operator''s choice and is kept';

DO $first_party_url_unique$
DECLARE
    first_party CONSTANT TEXT := '^(https?://)?(www[.])?github[.]com/(nano-rs/(parsers|rules))([.]git)?/?$';
    tbl TEXT;
    idx TEXT;
    dupes BIGINT;
BEGIN
    FOREACH tbl IN ARRAY ARRAY['parser_repositories', 'rule_repositories'] LOOP
        idx := tbl || '_first_party_url_key';
        CONTINUE WHEN to_regclass(idx) IS NOT NULL;
        EXECUTE format(
            'SELECT count(*) FROM (SELECT 1 FROM %I WHERE btrim(url) ~* %L '
            'GROUP BY lower(regexp_replace(btrim(url), %L, ''\3'', ''i'')) HAVING count(*) > 1) d',
            tbl, first_party, first_party)
        INTO dupes;
        IF dupes > 0 THEN
            RAISE WARNING 'NAN-4940: % holds % duplicated first-party catalog URL(s); % not created (the application lock still prevents new duplicates)',
                tbl, dupes, idx;
            CONTINUE;
        END IF;
        EXECUTE format(
            'CREATE UNIQUE INDEX IF NOT EXISTS %I ON %I ((lower(regexp_replace(btrim(url), %L, ''\3'', ''i'')))) '
            'WHERE btrim(url) ~* %L',
            idx, tbl, first_party, first_party);
    END LOOP;
END
$first_party_url_unique$;
