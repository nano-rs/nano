SELECT nano_shared.bronze_platform_pin_object('b464ceb9-28a6-4249-8e29-3489627ac5f6',repeat('b',64),'[null,null,null]','live');
DO $$ BEGIN
 IF (SELECT count(*) FROM nano_shared.bronze_platform_objects o,jsonb_array_elements(o.claim->'vector'->'feeds') f WHERE o.object_sha256=repeat('b',64) AND f->'decision'->>'status'='selected')<>3 THEN RAISE EXCEPTION 'new live pin did not select published baselines'; END IF;
 IF (SELECT count(*) FROM nano_shared.bronze_platform_objects o,jsonb_array_elements(o.claim->'vector'->'feeds') f WHERE o.object_sha256=repeat('a',64) AND f->'decision'->>'reason'='unavailable')<>3 THEN RAISE EXCEPTION 'immutable prior pin was rewritten'; END IF;
END $$;
UPDATE nano_shared.platform_enrichment_feeds SET status='unavailable' WHERE feed_id='tor_exit_nodes';
SELECT nano_shared.bronze_platform_pin_object('b464ceb9-28a6-4249-8e29-3489627ac5f6',repeat('c',64),'[null,null,null]');
DO $$ BEGIN
 IF (SELECT claim->'refusal_details'->>'tor_exit_nodes' FROM nano_shared.bronze_platform_objects WHERE object_sha256=repeat('c',64)) IS DISTINCT FROM 'registry_status_unavailable' THEN RAISE EXCEPTION 'missing exact diagnostic'; END IF;
END $$;
UPDATE nano_shared.platform_enrichment_feeds SET status='inactive' WHERE feed_id='ipinfo_lite';
SELECT nano_shared.platform_feed_activate(1,now(),'{"feed_id":"ipinfo_lite"}','');
DO $$ BEGIN
 IF (SELECT status FROM nano_shared.platform_enrichment_feeds WHERE feed_id='ipinfo_lite')<>'ready' THEN RAISE EXCEPTION 'publication failed to promote readiness'; END IF;
END $$;
