-- NAN-4169: retro IOC hunt over platform feed deltas.
--
-- An auto retro-hunt rule now also hunts the platform baseline IOC feeds
-- (ThreatFox incl. ip:port, Tor exit nodes...) a tenant is granted. Each feed
-- carries a revision; the rule records the revision it last finished per feed
-- (feed id -> revision). A changed revision is enumerated and anti-joined
-- against retro_hunt_hunted_indicators, so only the newly added indicators are
-- hunted. A feed absent from this map is baselined on first sight (its current
-- values are recorded as hunted without a scan), never hunted whole.
--
-- NAN-4265: on an activated enterprise_shared database, 9000084 moved
-- retro_hunt_rule_state to the data owner, so the migrator can no longer ALTER
-- it ("must be owner of table retro_hunt_rule_state" stopped the futureprod
-- T68 control migrate). This file then leaves the column to
-- `9014295_retro_hunt_platform_revisions.sql`, which applies the SAME body
-- under the managed-owner bootstrap (a no-op where this file already applied
-- it). Open core, dedicated and fresh databases still get the column here.
-- (No live database ever applied the earlier unguarded body: the only
-- attempt, futureprod T68, rolled back.)

SET LOCAL lock_timeout = '5s';

DO $nan4169_platform_revisions$
DECLARE
    v_owner OID;
BEGIN
    SELECT relowner INTO v_owner FROM pg_catalog.pg_class WHERE oid = 'public.retro_hunt_rule_state'::regclass;
    IF NOT pg_catalog.pg_has_role(current_user, v_owner, 'USAGE') THEN
        RAISE NOTICE 'retro_hunt_rule_state is owned by %; 9014295 applies platform_revisions', v_owner::regrole;
        RETURN;
    END IF;
-- BEGIN retro_hunt_platform_revisions body
    ALTER TABLE public.retro_hunt_rule_state
        ADD COLUMN IF NOT EXISTS platform_revisions JSONB;
-- END retro_hunt_platform_revisions body
END
$nan4169_platform_revisions$;
