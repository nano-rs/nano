-- NAN-2221: re-apply 058's ReadOnly restrictions, which 177 silently undid.
--
-- 058_readonly_restrict_permissions.sql deliberately revoked six permissions
-- from the ReadOnly role, with the rationale: "ReadOnly users are analysts who
-- view security data (search, alerts, dashboards). They should not see
-- configuration pages for ingestion, enrichments, or data management."
--
-- 177_seed_open_baseline.sql re-inserts all six (lines 373, 375, 376, 380,
-- 381, 382). Because 177 > OPEN_INIT_BASELINE_VERSION (175) it runs as an
-- ordinary pending migration on LEGACY tenants too, so `ON CONFLICT DO
-- NOTHING` cleanly re-added the rows 058 had deleted. Both fresh and legacy
-- installs are therefore over-granted. Nothing since undoes it — the only
-- post-177 deletes from role_permissions are 180 (zombie perms) and 194
-- (feeds).
--
-- Why this reaches every user, not just "ReadOnly analysts"
-- --------------------------------------------------------
-- 177:396-398 binds the `Everyone` group to the ReadOnly role, and every new
-- user is auto-joined to Everyone by the `trigger_add_user_to_everyone` DB
-- trigger. So these six permissions are effectively held by EVERY
-- authenticated principal.
--
-- The exposure that matters is `credentials:view`: GET /api/credentials gates
-- on it alone and returns the cloud-credential inventory including
-- `external_id` — the sts:ExternalId, whose own doc comment records that it is
-- "Stored and returned UNENCRYPTED". Secret payloads are NOT exposed, and
-- ExternalId is a confused-deputy control rather than a bearer secret (it does
-- not permit assuming the customer's role without our AWS principal), so this
-- is authenticated disclosure of security-configuration metadata rather than a
-- credential leak. It is nonetheless a real server-side authorization
-- over-grant, not a navigation-visibility issue.
--
-- Why a migration is required
-- ---------------------------
-- NAN-2121 made every in-product path back impossible: ReadOnly is a system
-- role (`CannotModifySystemRole`), Everyone is a system group
-- (`CannotModifySystemGroup`), and users cannot be removed from Everyone. An
-- administrator has no way to re-restrict this themselves.
--
-- Forward-cleanup rather than editing 177, matching the established pattern
-- (195 for 047's routing rules, 186 for the 185 collision, 180 for 150's
-- renames). 177 is applied and sqlx checksums it.
--
-- Idempotent: deleting rows that are already absent affects zero rows, so this
-- is a no-op on any tenant already in the intended state.

DELETE FROM public.role_permissions
WHERE role_id = '00000000-0000-0000-0000-000000000003'  -- ReadOnly
  AND permission_id IN (
    -- Settings
    'enrichments:view',
    -- Ingestion
    'log_sources:view',
    'source_configs:view',
    'credentials:view',
    -- Data
    'parsers:view',
    'lookup:view'
  );

-- Deliberately scoped to the seeded ReadOnly role id only. Custom roles that
-- an operator explicitly granted these permissions are their own decision and
-- are left untouched — 058 targeted the same single role id.
--
-- Operational note: permissions ride in the session token, so a currently
-- signed-in ReadOnly user keeps the old set until their session refreshes.
