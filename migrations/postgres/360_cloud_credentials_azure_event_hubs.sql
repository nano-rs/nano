-- NAN-3764: Azure Event Hubs pull sources keep their SAS / storage connection
-- strings or Entra service principal in a sealed `azure_event_hubs` credential.
--
-- NAN-3782 fix-forward: this body first shipped as 354, which altered
-- `cloud_credentials` with plain DDL. On an activated enterprise_shared
-- database that table is owned by the managed data owner, so the migrator was
-- refused there ("must be owner of table cloud_credentials", r49 futureprod).
-- 354 is retired (removed, not edited, as 344 was: a database that already
-- applied it keeps its row, which the open migrator's ignore_missing
-- tolerates, and this file re-applies the same idempotent DDL). The DDL runs
-- inside the 9000140 managed-owner bootstrap window when one exists, as 341
-- and 346 do; open and dedicated installs alter directly.
SET LOCAL lock_timeout = '5s';

DO $cloud_credentials_event_hubs$
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

    ALTER TABLE public.cloud_credentials
        DROP CONSTRAINT IF EXISTS cloud_credentials_provider_check;
    ALTER TABLE public.cloud_credentials
        ADD CONSTRAINT cloud_credentials_provider_check
        CHECK (provider IN ('aws_s3', 'azure_blob', 'gcp_pubsub', 'kafka', 'splunk_hec', 'azure_event_hubs'));
    COMMENT ON COLUMN public.cloud_credentials.provider IS
        'Cloud provider type: aws_s3, azure_blob, gcp_pubsub, kafka, splunk_hec, or azure_event_hubs';

    IF owner_role IS NOT NULL THEN
        PERFORM nano_shared.end_managed_owner_bootstrap(owner_role, owner_token);
    END IF;
END
$cloud_credentials_event_hubs$;
