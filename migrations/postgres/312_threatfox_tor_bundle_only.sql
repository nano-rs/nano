-- NAN-4959 (IOC parity): ThreatFox and the Tor exit list come only from
-- nano's signed platform feed bundle (app.nano.rs), like IPinfo Lite (311).
--
-- Before this, the marketplace `threatfox` / `tor-exit-nodes` entries could
-- install a Deno data enrichment (enterprise) that fetched abuse.ch / the Tor
-- list directly and wrote marketplace IOC rows (platform_feed = 0, 30-day
-- expiry) next to the bundle's generation: two sources for one feed, with
-- duplicate or conflicting verdicts and no signature or rollback fence. The
-- API now refuses install / sync / enable / credentials for these slugs and
-- the Deno runtime refuses to run an enrichment installed for one; this
-- migration retires installs made before that:
--
--   * the catalog entries are switched off (marketplace_catalog.enabled);
--   * the linked custom_enrichments rows are disabled, so the scheduler stops
--     fetching. Nothing is deleted: installed flag, config and credentials
--     stay as written; an uninstall still removes the credentials.
--
-- CH migration 187 stops serving the rows those installs already wrote once
-- the bundle has committed its ThreatFox / Tor generation.
--
-- custom_enrichments may be absent on an open-core fresh install (snapshot),
-- so it is guarded. Forward-only and idempotent; counts are logged.

DO $$
DECLARE
    feed_slugs CONSTANT TEXT[] := ARRAY['threatfox', 'tor-exit-nodes', 'tor_exit_nodes', 'tor'];
    entries_off INTEGER := 0;
    enrichments_off INTEGER := 0;
BEGIN
    UPDATE marketplace_catalog
       SET enabled = false, updated_at = NOW()
     WHERE slug = ANY(feed_slugs)
       AND enabled;
    GET DIAGNOSTICS entries_off = ROW_COUNT;

    IF to_regclass('public.custom_enrichments') IS NOT NULL THEN
        EXECUTE
            'UPDATE custom_enrichments SET enabled = false
              WHERE enabled
                AND id IN (SELECT custom_enrichment_id FROM marketplace_catalog
                            WHERE slug = ANY($1) AND custom_enrichment_id IS NOT NULL)'
            USING feed_slugs;
        GET DIAGNOSTICS enrichments_off = ROW_COUNT;
    END IF;

    RAISE NOTICE 'NAN-4959 ThreatFox/Tor bundle-only: % catalog entries and % custom enrichments switched off', entries_off, enrichments_off;
END $$;
