CREATE OR REPLACE FUNCTION nano_shared.bronze_platform_pin_object(p_tenant UUID,p_object TEXT,p_legacy JSONB,p_mode TEXT) RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE c JSONB; v JSONB; a JSONB; r JSONB; f RECORD; id UUID := gen_random_uuid();
    at_time TIMESTAMPTZ := statement_timestamp(); reason TEXT; epoch BIGINT; feeds JSONB := '[]'; times JSONB := '{}'; catalog BIGINT := 1;
BEGIN
    IF p_mode IS NULL OR p_mode NOT IN ('shadow','live') THEN RAISE EXCEPTION 'invalid stamping mode'; END IF;
    PERFORM nano_shared.bronze_platform_assert(p_tenant);
    IF p_object IS NULL OR p_object !~ '^[0-9a-f]{64}$' OR p_legacy IS NULL
      OR jsonb_typeof(p_legacy)<>'array' OR jsonb_array_length(p_legacy)<>3
      OR EXISTS(SELECT FROM jsonb_array_elements_text(p_legacy) x WHERE x IS NOT NULL AND x !~ '^[0-9a-f]{64}$')
    THEN RAISE EXCEPTION 'invalid object pin'; END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant::text || ':object:' || p_object,246904));
    IF EXISTS(SELECT FROM nano_shared.bronze_platform_objects WHERE tenant_id=p_tenant AND object_sha256=p_object) THEN RETURN; END IF;
    -- One snapshot pins active revision, right, deny, freshness and DB time.
    FOR f IN SELECT x.feed_id,x.registry_revision,x.redistribution_approved,x.status,x.freshness_seconds,x.terms_revision,
      v.revision,v.digest,v.mapping_revision,v.upstream_at,v.valid_until,v.license_revision,
      g.license_revision AS grant_license,
      e.tier,e.grant_revision,e.revision AS entitlement_revision,e.state,e.enabled,
      e.effective_at,e.expires_at,g.effective_at AS grant_effective_at,g.expires_at AS grant_expires_at,
      g.max_validity_seconds,p.enabled AS publication_enabled,
      (SELECT COALESCE(max(d.epoch),0) FROM nano_shared.platform_enrichment_deny_state d WHERE d.feed_id=x.feed_id) + COALESCE(e.deny_epoch,0) AS deny_epoch,
      EXISTS(SELECT FROM nano_shared.platform_enrichment_deny_state d WHERE d.feed_id=x.feed_id
        AND (d.feed_revision=v.revision OR (d.tier=e.tier AND d.grant_revision=e.grant_revision))) AS revoked,
      statement_timestamp() AS admitted_at
    FROM nano_shared.platform_enrichment_feeds x
    LEFT JOIN nano_shared.platform_feed_publications p ON p.feed_id=x.feed_id
    LEFT JOIN nano_shared.platform_enrichment_feed_versions v ON v.feed_id=x.feed_id AND v.revision=p.active_revision
    LEFT JOIN public.tenant_platform_enrichment_entitlements e ON e.tenant_id=p_tenant AND e.feed_id=x.feed_id
    LEFT JOIN nano_shared.platform_enrichment_grant_revisions g ON (g.feed_id,g.tier,g.revision)=(e.feed_id,e.tier,e.grant_revision)
    WHERE x.feed_id IN ('ipinfo_lite','synthient','threatfox','tor_exit_nodes') ORDER BY x.feed_id LOOP
    a := NULL; r := NULL;
    catalog := GREATEST(catalog,f.registry_revision);
    at_time := f.admitted_at;
    epoch := f.deny_epoch;
    IF f.revision IS NOT NULL THEN a := jsonb_build_object('revision',f.revision,'digest',f.digest,'mapping_revision',f.mapping_revision); END IF;
    IF f.entitlement_revision IS NOT NULL THEN r := jsonb_build_object('tier',f.tier,'grant_revision',f.grant_revision,'entitlement_revision',f.entitlement_revision); END IF;
    reason := CASE
      WHEN f.revoked OR f.state='revoked' THEN 'revoked'
      WHEN f.state='expired' OR f.valid_until<=at_time OR f.expires_at<=at_time OR f.grant_expires_at<=at_time THEN 'expired'
      WHEN NOT COALESCE(f.enabled,false) THEN 'disabled'
      WHEN f.state IS DISTINCT FROM 'active' OR f.effective_at>at_time OR f.grant_effective_at>at_time OR a IS NULL OR r IS NULL THEN 'missing'
      WHEN NOT f.redistribution_approved OR f.status<>'ready' OR NOT COALESCE(f.publication_enabled,false) THEN 'unavailable'
      WHEN f.feed_id='synthient' AND (f.terms_revision='pending-review' OR f.license_revision IS DISTINCT FROM f.terms_revision) THEN 'unavailable'
      WHEN f.tier='sandbox' AND f.license_revision IS DISTINCT FROM f.grant_license THEN 'unavailable'
      WHEN f.upstream_at IS NULL OR f.upstream_at>at_time THEN 'unavailable' ELSE NULL END;
    feeds := feeds || jsonb_build_array(jsonb_build_object('feed_id',f.feed_id,'deny_epoch',epoch,'decision',CASE WHEN reason IS NULL
      THEN jsonb_build_object('status','selected','artifact',a,'right',r)
      ELSE jsonb_build_object('status','unknown','reason',reason,'artifact',a,'right',r) END));
    times := times || jsonb_build_object(f.feed_id,jsonb_build_object('upstream_at',f.upstream_at,
      'valid_until',LEAST(f.valid_until,f.expires_at,f.grant_expires_at,at_time+make_interval(secs=>f.max_validity_seconds),
        CASE WHEN f.feed_id<>'ipinfo_lite' THEN f.upstream_at+interval '24 hours' ELSE f.valid_until END),
      'freshness',CASE WHEN reason IS NOT NULL THEN 'unknown'
        WHEN f.upstream_at+make_interval(secs=>f.freshness_seconds)>at_time THEN 'fresh' ELSE 'stale' END));
    END LOOP;
    IF jsonb_array_length(feeds)<>4 THEN RAISE EXCEPTION 'platform registry incomplete'; END IF;
    v := jsonb_build_object('contract_version',1,'tenant_id',p_tenant,'admission_id',id,'source_identity_sha256',p_object,
      'admitted_at',at_time,'catalog_revision',catalog,'feeds',feeds);
    c := jsonb_build_object('mode',p_mode,'vector',v,'legacy',p_legacy,'observation','{}'::jsonb,'feed_times',times,
      'upstream_at',times->'ipinfo_lite'->'upstream_at','valid_until',times->'ipinfo_lite'->'valid_until',
      'freshness',times->'ipinfo_lite'->'freshness','decision',NULL,'output',NULL);
    INSERT INTO nano_shared.bronze_platform_objects VALUES(p_tenant,p_object,c);
END $$;
