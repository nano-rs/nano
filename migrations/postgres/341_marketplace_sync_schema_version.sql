-- NAN-3514: marketplace sync must re-parse when the sync CODE changes.
--
-- Enrichment marketplace sync skipped a repository whose HEAD commit equalled
-- `last_sync_commit` after a successful sync. That keys only on repository
-- content: when sync learns to record a new manifest field (NAN-3490 added
-- `runtime` / `connector_spec` / `connector_spec_sha256`), repos at an
-- unchanged commit never got it. Sync now records the version of its
-- parse/record logic (`SYNC_SCHEMA_VERSION` in
-- nanosiem-core/src/marketplace/sync_service.rs) next to the commit, and a
-- stored version that differs from the running one forces a full sync.
--
-- Existing rows default to 0 ("synced by code that did not record a
-- version"), so every repository re-syncs once after this lands.
--
-- Additive and idempotent. On an activated shared lake the table is owned by
-- the managed app owner, so the migrator alters it inside the 9000140 owner
-- window when it exists (as 329 does); dedicated installs alter directly.
DO $sync_schema_version$
DECLARE
    owner_role NAME;
    owner_token INTEGER := 0;
BEGIN
    IF to_regclass('public.enrichment_marketplace_repos') IS NULL THEN
        RETURN;
    END IF;
    IF to_regproc('nano_shared.begin_managed_owner_bootstrap') IS NOT NULL THEN
        SELECT contract.owner_role INTO owner_role
          FROM nano_shared.rls_role_contract contract WHERE singleton AND enabled;
        IF owner_role IS NOT NULL THEN
            owner_token := nano_shared.begin_managed_owner_bootstrap(owner_role);
        END IF;
    END IF;
    ALTER TABLE public.enrichment_marketplace_repos
        ADD COLUMN IF NOT EXISTS last_sync_schema_version INTEGER NOT NULL DEFAULT 0;
    IF owner_role IS NOT NULL THEN
        PERFORM nano_shared.end_managed_owner_bootstrap(owner_role, owner_token);
    END IF;
END
$sync_schema_version$;
