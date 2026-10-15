-- NAN-3232: `risk:watchlists` -- risk watchlists become their own grant.
--
-- Watchlists (NAN-3228, migration 334) were readable with `risk:view` and
-- writable with `risk:configure`. A watchlist's name and members say who the
-- organization is watching (executives, insider-threat subjects), so viewing
-- and managing them is now one dedicated permission. Without it a caller still
-- gets the effective (weighted) risk score -- the weight is tenant scoring
-- policy -- but no watchlist endpoint and no watch field on risk reads.
--
-- Who holds it
-- ------------
-- The built-in Admin role only. Editor and ReadOnly (the analyst-style
-- built-ins; ReadOnly is bound to the auto-joined Everyone group, so a grant
-- there would reach every principal) do not. Custom roles and API keys are
-- deliberately NOT backfilled from `risk:view` / `risk:configure`: unlike
-- `credentials:use` (280), which preserved long-standing workflows, this
-- narrows a feature that shipped the same day, and the point of the grant is
-- that an operator opts a role or key in.
--
-- Enterprise databases
-- --------------------
-- On a database that already carries the enterprise role-grant
-- classification trigger (9001080), a platform `role_permissions` write is an
-- UNCLASSIFIED grant revision that retires every hosted-shared tenant's
-- detection worker assignment. There the Admin grant is left to enterprise
-- 9011450, which writes it without that revision. Fresh installs (core runs
-- before the overlay) and open-core databases grant it here.

INSERT INTO permissions (id, name, description, category) VALUES
    (
        'risk:watchlists',
        'Risk Watchlists',
        'View and manage risk watchlists (who is being watched, list weights) and see base scores and watchlist weights on risk reads. Also requires risk:view.',
        'risk'
    )
ON CONFLICT (id) DO NOTHING;

DO $grant_admin$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_trigger
         WHERE tgrelid = 'public.role_permissions'::regclass
           AND tgname = 'detection_role_grant_insert'
           AND NOT tgisinternal
    ) THEN
        RETURN;
    END IF;
    INSERT INTO role_permissions (role_id, permission_id)
    SELECT r.id, 'risk:watchlists'
    FROM roles r
    WHERE r.id = '00000000-0000-0000-0000-000000000001'::uuid -- Admin
    ON CONFLICT DO NOTHING;
END
$grant_admin$;
