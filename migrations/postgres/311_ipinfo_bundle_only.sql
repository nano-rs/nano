-- NAN-4959: IPinfo Lite is served only from nano's signed platform feed bundle.
--
-- Dan, 2026-11-04: IPinfo Lite is upstream-managed. It comes only from the
-- signed app.nano.rs platform feed bundle (platform_enrichment::consumer,
-- NAN-4948). There is no bring-your-own download URL or token anywhere in the
-- enrichment marketplace. The native IPinfo download job, its configure / sync
-- endpoints and the consumer's "your own IPinfo token is configured" skip
-- branch are removed in the same change; this migration retires the rows that
-- path left behind:
--
--   * native `ipinfo_lite` enrichment_sources rows are disabled, not deleted.
--     `download_url` is kept as written (no data deletion in a boot
--     migration); nothing reads it any more.
--   * the `download_url` credential field is removed from the IPinfo Lite
--     catalog entry's credential_fields (requires_credential -> 'none'), so the
--     marketplace drawer renders no credential input. The description now says
--     where the data comes from. Stored catalog ciphertext is left alone.
--
-- IP rows a previous native sync wrote to ClickHouse `ip_enrichments` stay as
-- they are; the bundle's rows are newer, so `ip_enrichment_dict_refresh`'s
-- argMax(updated_at) serves the bundle wherever both cover a network.
--
-- Forward-only and idempotent: re-running changes nothing. Counts are logged.

DO $$
DECLARE
    sources_disabled INTEGER;
    entries_updated INTEGER;
BEGIN
    UPDATE enrichment_sources
       SET enabled = false, updated_at = NOW()
     WHERE source_type = 'ipinfo_lite'
       AND enabled;
    GET DIAGNOSTICS sources_disabled = ROW_COUNT;

    UPDATE marketplace_catalog
       SET credential_fields = COALESCE((
               SELECT jsonb_agg(field ORDER BY ordinality)
                 FROM jsonb_array_elements(credential_fields) WITH ORDINALITY AS t(field, ordinality)
                WHERE field->>'name' IS DISTINCT FROM 'download_url'
           ), '[]'::jsonb),
           requires_credential = 'none',
           description = 'IP geolocation and ASN from IPinfo Lite, provided by nano''s signed platform feed bundle and stamped at ingest.',
           updated_at = NOW()
     WHERE native_source_id = 'ipinfo_lite'
       AND (credential_fields @> '[{"name": "download_url"}]' OR requires_credential <> 'none');
    GET DIAGNOSTICS entries_updated = ROW_COUNT;

    RAISE NOTICE 'NAN-4959 IPinfo bundle-only: % native ipinfo_lite sources disabled, % catalog entries without a download URL field', sources_disabled, entries_updated;
END $$;
