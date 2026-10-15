-- NAN-3783: pulled sources poll every 5 min by default, not every 10.
--
-- A connector feed pins its spec (spec_yaml + spec_sha256) at install, and a
-- catalog update never changes a running feed. Google Workspace was the only
-- catalog spec that pinned the old ~10 min cadence (`schedule: "*/10 * * * *"`),
-- so every Google Workspace audit feed installed before this release would
-- keep polling every 10 min. This rewrites exactly those rows:
--
--   * connector = 'google_workspace' (the audit feeds; the directory component
--     pins "0 */6 * * *" and is not matched);
--   * no per-feed override (schedule IS NULL): an operator-set cadence stays;
--   * the pinned spec carries the old default as its top-level `schedule:`
--     line (either quote style; serde_yaml re-serializes the hosted
--     per-stream specs).
--
-- The rewrite swaps only that line and recomputes spec_sha256 the way the
-- runner checks it (sha256 hex of the UTF-8 YAML), bumping revision so a
-- stale editor gets a conflict. next_run_at is untouched: the next run is due
-- within the old 10 min, and its successor lands on the 5 min grid.
-- Idempotent: a second pass matches nothing.
--
-- On an activated enterprise_shared database connector_feeds is owned by the
-- NOLOGIN data owner and is FORCE RLS; the UPDATE runs inside the 9000140
-- managed-owner bootstrap window (the tenant RESTRICTIVE policy applies only
-- to the runtime role, so the window sees every tenant's rows). Open core and
-- dedicated own the table and update it directly.
DO $connector_feed_gws_five_minute_default$
DECLARE
    owner_role NAME;
    owner_token INTEGER := 0;
    old_line CONSTANT TEXT := '^schedule:([ \t]*)([''"]?)\*/10 \* \* \* \*\2([ \t]*)$';
BEGIN
    IF to_regproc('nano_shared.begin_managed_owner_bootstrap') IS NOT NULL THEN
        SELECT contract.owner_role INTO owner_role
          FROM nano_shared.rls_role_contract contract WHERE singleton AND enabled;
        IF owner_role IS NOT NULL
           AND pg_catalog.pg_get_userbyid((SELECT relowner FROM pg_catalog.pg_class
                                           WHERE oid = 'public.connector_feeds'::regclass)) = owner_role THEN
            owner_token := nano_shared.begin_managed_owner_bootstrap(owner_role);
        END IF;
    END IF;

    WITH rewritten AS (
        SELECT f.tenant_id, f.id,
               regexp_replace(f.spec_yaml, old_line, 'schedule:\1\2*/5 * * * *\2\3', 'n') AS spec_yaml
          FROM public.connector_feeds f
         WHERE f.connector = 'google_workspace'
           AND f.schedule IS NULL
           AND f.spec_yaml ~ ('(?n)' || old_line)
    )
    UPDATE public.connector_feeds f
       SET spec_yaml = r.spec_yaml,
           spec_sha256 = encode(sha256(convert_to(r.spec_yaml, 'UTF8')), 'hex'),
           revision = f.revision + 1,
           updated_at = now()
      FROM rewritten r
     WHERE f.tenant_id = r.tenant_id AND f.id = r.id;

    IF owner_token <> 0 THEN
        PERFORM nano_shared.end_managed_owner_bootstrap(owner_role, owner_token);
    END IF;
END
$connector_feed_gws_five_minute_default$;
