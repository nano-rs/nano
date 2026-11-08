-- SPDX-License-Identifier: AGPL-3.0-or-later
-- NAN-4947 (11-03 decision): all parser and rule content comes from nano
-- first-party sources. Third-party repositories (SigmaHQ, forks, customer
-- repositories) can no longer be added, and the services refuse to sync,
-- browse, import from or re-enable one (`content_catalog_defaults::
-- is_allowed_repository`).
--
-- This migration disables every existing non-first-party row so the
-- schedulers stop syncing it and it drops out of the repository listings.
-- Nothing is deleted: the rows, their cached catalog entries and the
-- provenance of anything already imported from them stay as they are (an
-- imported rule or parser is the operator's own content and keeps working).
-- The number of rows disabled per table is logged as a WARNING.
--
-- First-party rows are also rewritten to the canonical stored spelling
-- `https://github.com/nano-rs/<repo>`, so what is stored is exactly what the
-- sync parses (an older `www.` / `.git` / mixed-case row would otherwise be
-- admitted but parsed differently).
--
-- First-party = `github.com/nano-rs/parsers` / `github.com/nano-rs/rules`
-- (scheme, `www.`, case, `.git` and a trailing slash ignored: exactly what
-- `schema::github_owner_repo`, the one parser admission, reconcile and sync
-- share, accepts) or the synthetic repository
-- signed air-gap bundles are applied to (`airgap://parsers` /
-- `airgap://rules`). The playbook table is enterprise-only and is handled by
-- enterprise migration 9000085. Forward-only and idempotent.
DO $first_party_content_only$
DECLARE
    tbl TEXT;
    repo TEXT;
    disabled BIGINT;
    canonicalized BIGINT;
BEGIN
    FOR tbl, repo IN VALUES ('parser_repositories', 'parsers'), ('rule_repositories', 'rules') LOOP
        CONTINUE WHEN to_regclass(tbl) IS NULL;
        EXECUTE format(
            'UPDATE %I SET url = %L, updated_at = now() WHERE btrim(url) ~* %L AND url <> %L',
            tbl,
            'https://github.com/nano-rs/' || repo,
            '^(https?://)?(www[.])?github[.]com/nano-rs/' || repo || '([.]git)?/?$',
            'https://github.com/nano-rs/' || repo);
        GET DIAGNOSTICS canonicalized = ROW_COUNT;
        IF canonicalized > 0 THEN
            RAISE NOTICE 'NAN-4947: canonicalized % first-party URL(s) in %', canonicalized, tbl;
        END IF;
        EXECUTE format(
            'UPDATE %I SET enabled = FALSE, auto_sync_enabled = FALSE, updated_at = now() '
            'WHERE NOT (btrim(url) ~* %L OR btrim(url) = %L) '
            '  AND (COALESCE(enabled, TRUE) OR COALESCE(auto_sync_enabled, FALSE))',
            tbl,
            '^(https?://)?(www[.])?github[.]com/nano-rs/' || repo || '([.]git)?/?$',
            'airgap://' || repo);
        GET DIAGNOSTICS disabled = ROW_COUNT;
        IF disabled > 0 THEN
            RAISE WARNING 'NAN-4947: disabled % non-first-party row(s) in % (third-party content sources are no longer supported)',
                disabled, tbl;
        ELSE
            RAISE NOTICE 'NAN-4947: no non-first-party rows in %', tbl;
        END IF;
    END LOOP;
END
$first_party_content_only$;
