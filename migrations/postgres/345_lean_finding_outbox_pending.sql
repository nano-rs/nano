-- NAN-3492: the trusted-local lean drain acknowledges immutable finding parts
-- through ingest's part log. It consumes the open outbox from 286/291/336.
-- Keep gen1 composite acknowledgement semantics and hosted RLS unchanged.
--
-- NAN-3499 (r30 fix-forward): this body first shipped as 342, which created
-- the index directly. On an activated enterprise_shared database 9000084 moved
-- `detection_finding_lake_outbox` to the managed data owner, so the migrator
-- could not index it ("must be owner of table detection_finding_lake_outbox")
-- and the futureprod r30 migrate step failed. 342 is retired (removed, not
-- edited: a database that already applied it keeps its row, which the open
-- migrator's ignore_missing tolerates, and this file is then a no-op). The
-- index is created here inside the 9000140 managed-owner bootstrap window
-- when one exists, as 341 does; open and dedicated installs index directly.
DO $lean_finding_pending$
DECLARE
    owner_role NAME;
    owner_token INTEGER := 0;
BEGIN
    IF to_regproc('nano_shared.begin_managed_owner_bootstrap') IS NOT NULL THEN
        SELECT contract.owner_role INTO owner_role
          FROM nano_shared.rls_role_contract contract WHERE singleton AND enabled;
        IF owner_role IS NOT NULL THEN
            owner_token := nano_shared.begin_managed_owner_bootstrap(owner_role);
        END IF;
    END IF;
    CREATE INDEX IF NOT EXISTS idx_detection_finding_lean_pending
        ON detection_finding_lake_outbox (security_tenant_id, tenant_id, created_at, finding_id)
        WHERE event_published_at IS NULL OR risk_published_at IS NULL;
    IF owner_role IS NOT NULL THEN
        PERFORM nano_shared.end_managed_owner_bootstrap(owner_role, owner_token);
    END IF;
END
$lean_finding_pending$;
