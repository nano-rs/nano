SELECT nano_shared.bronze_platform_pin_object('b464ceb9-28a6-4249-8e29-3489627ac5f6',repeat('a',64),'[null,null,null]','shadow');
DO $$ BEGIN
 IF (SELECT count(*) FROM nano_shared.bronze_platform_objects o,jsonb_array_elements(o.claim->'vector'->'feeds') f WHERE f->'decision'->>'reason'='unavailable')<>3 THEN RAISE EXCEPTION 'did not reproduce live refusal'; END IF;
END $$;
