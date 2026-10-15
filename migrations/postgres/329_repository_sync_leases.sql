-- NAN-2411: abandoned repository syncs must be recoverable independently of edits.
-- On an activated shared lake these tables are owned by the managed app owner;
-- the migrator alters them inside the 9000140 owner window when it exists
-- (dedicated installs have no nano_shared schema and alter directly).
DO $sync_leases$
DECLARE
    owner_role NAME;
    owner_token INTEGER := 0;
    t TEXT;
BEGIN
    IF to_regproc('nano_shared.begin_managed_owner_bootstrap') IS NOT NULL THEN
        SELECT contract.owner_role INTO owner_role
          FROM nano_shared.rls_role_contract contract WHERE singleton AND enabled;
        IF owner_role IS NOT NULL THEN
            owner_token := nano_shared.begin_managed_owner_bootstrap(owner_role);
        END IF;
    END IF;
    FOREACH t IN ARRAY ARRAY['rule_repositories', 'parser_repositories', 'enrichment_marketplace_repos'] LOOP
        IF to_regclass(format('public.%I', t)) IS NULL THEN CONTINUE; END IF;
        EXECUTE format('ALTER TABLE public.%I ADD COLUMN IF NOT EXISTS sync_started_at TIMESTAMPTZ', t);
        EXECUTE format('ALTER TABLE public.%I ADD COLUMN IF NOT EXISTS sync_lease_expires_at TIMESTAMPTZ', t);
        EXECUTE format('ALTER TABLE public.%I ADD COLUMN IF NOT EXISTS sync_lease_token UUID', t);
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = t || '_sync_lease_check') THEN
            EXECUTE format('ALTER TABLE public.%I ADD CONSTRAINT %I CHECK ('
                '(sync_started_at IS NULL AND sync_lease_expires_at IS NULL AND sync_lease_token IS NULL) OR '
                '(sync_started_at IS NOT NULL AND sync_lease_expires_at IS NOT NULL AND sync_lease_expires_at > sync_started_at AND sync_lease_token IS NOT NULL))',
                t, t || '_sync_lease_check');
        END IF;
        EXECUTE format('UPDATE public.%I SET last_sync_status = %L, last_sync_error = %L WHERE last_sync_status = %L',
            t, 'failed', 'Sync interrupted before lease tracking was enabled', 'syncing');
    END LOOP;
    IF owner_role IS NOT NULL THEN
        PERFORM nano_shared.end_managed_owner_bootstrap(owner_role, owner_token);
    END IF;
END
$sync_leases$;

CREATE TABLE platform_repository_sync_audit (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id UUID NOT NULL,
    lease_token UUID NOT NULL,
    phase TEXT NOT NULL CHECK (phase IN ('started', 'success', 'failed')),
    error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX platform_repository_sync_audit_repository_time
    ON platform_repository_sync_audit (repository_id, created_at DESC);
