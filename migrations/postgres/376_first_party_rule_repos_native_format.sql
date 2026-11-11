-- Numbered 376: core migrations skip 328-374 (the retired lake line used that range).
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- NAN-5272: Sigma -> nPL conversion was retired. Any repository row still
-- stored as `rule_format = 'sigma'` is refused on sync, preview, import and
-- upstream diff.
--
-- A first-party rules repository can carry `sigma` even though its content is
-- native nPL. Two older defaults put it there: the column default (071) and
-- the create API, which both fell back to `sigma` when `rule_format` was
-- omitted. The boot reconcile (NAN-4940) adopts an existing row without
-- touching its format. Without this migration, first-party rule sync would
-- stop on those installs.
--
-- This migration:
--   * sets `rule_format = 'nanosiem'` on first-party rows only, using the
--     same allowlist as migration 308 (NAN-4947): `github.com/nano-rs/rules`
--     (scheme, `www.`, case, `.git` and a trailing slash ignored) or the
--     synthetic air-gap repository `airgap://rules`. Third-party Sigma rows
--     are left as they are and keep getting the 400.
--   * changes the column default to `nanosiem`, matching the API default, so
--     a raw INSERT that omits the format no longer creates a row that is
--     refused.
--
-- Forward-only and idempotent.
DO $first_party_rule_repos_native_format$
DECLARE
    fixed BIGINT;
BEGIN
    IF to_regclass('rule_repositories') IS NULL THEN
        RETURN;
    END IF;

    UPDATE rule_repositories
       SET rule_format = 'nanosiem',
           updated_at = now()
     WHERE rule_format IS DISTINCT FROM 'nanosiem'
       AND (btrim(url) ~* '^(https?://)?(www[.])?github[.]com/nano-rs/rules([.]git)?/?$'
            OR btrim(url) = 'airgap://rules');
    GET DIAGNOSTICS fixed = ROW_COUNT;
    IF fixed > 0 THEN
        RAISE WARNING 'NAN-5272: switched % first-party rule repository row(s) from sigma to native nPL format', fixed;
    ELSE
        RAISE NOTICE 'NAN-5272: no first-party rule repository rows needed a format fix';
    END IF;

    ALTER TABLE rule_repositories ALTER COLUMN rule_format SET DEFAULT 'nanosiem';
END
$first_party_rule_repos_native_format$;
