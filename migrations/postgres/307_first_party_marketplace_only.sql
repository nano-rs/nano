-- NAN-4946: marketplace content comes only from nano's first-party catalogs.
--
-- Dan, 2026-11-03: there is no way to add a third-party repository for any
-- content type. The API now refuses to create, edit, sync or install from a
-- marketplace repository whose URL is not https://github.com/<nano-rs |
-- nanos-sh>/<repo> (exact host and owner, no embedded credentials); this
-- migration retires rows created before that rule:
--
--   * third-party enrichment_marketplace_repos rows are disabled (auto-sync
--     off), not deleted;
--   * their UNINSTALLED catalog entries are hidden via the new
--     marketplace_catalog.hidden_reason column, not deleted. Installed
--     entries stay visible so an operator can review and uninstall them.
--
-- Forward-only and idempotent: re-running changes nothing. Counts are logged.

ALTER TABLE marketplace_catalog ADD COLUMN IF NOT EXISTS hidden_reason TEXT;

DO $$
DECLARE
    -- Same rule as nanosiem_core::marketplace::first_party (exact host, owner,
    -- one repository path segment, optional .git / trailing slash, no
    -- userinfo, port, query or fragment).
    first_party CONSTANT TEXT := '^https://github\.com(:443)?/(nano-rs|nanos-sh)/[A-Za-z0-9._-]+?(\.git)?/?$';
    repos_disabled INTEGER;
    entries_hidden INTEGER;
BEGIN
    UPDATE enrichment_marketplace_repos
       SET enabled = false, auto_sync_enabled = false, updated_at = NOW()
     WHERE (enabled OR auto_sync_enabled)
       AND NOT (lower(trim(url)) ~ first_party);
    GET DIAGNOSTICS repos_disabled = ROW_COUNT;

    UPDATE marketplace_catalog c
       SET hidden_reason = 'third_party_repository'
      FROM enrichment_marketplace_repos r
     WHERE c.repository_id = r.id
       AND c.installed = false
       AND c.hidden_reason IS NULL
       AND NOT (lower(trim(r.url)) ~ first_party);
    GET DIAGNOSTICS entries_hidden = ROW_COUNT;

    RAISE NOTICE 'NAN-4946 first-party marketplace: % third-party repositories disabled, % catalog entries hidden', repos_disabled, entries_hidden;
END $$;
