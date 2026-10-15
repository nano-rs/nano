-- NAN-2542: nullable observations preserve old producers' INSERT contracts.
-- For populated deployments FIRST run scripts/lake-tail-flow-indexes.sql
-- with psql (autocommit): CREATE INDEX CONCURRENTLY cannot execute in sqlx's
-- multi-statement migration transaction. IF NOT EXISTS below adopts those
-- prebuilt indexes; empty installations build them normally.
SET LOCAL lock_timeout = '2s';
ALTER TABLE lake_pipeline_health
    ADD COLUMN IF NOT EXISTS fill_objects_per_hour double precision,
    ADD COLUMN IF NOT EXISTS drain_objects_per_hour double precision,
    ADD COLUMN IF NOT EXISTS serving_bound_objects bigint,
    ADD COLUMN IF NOT EXISTS seconds_to_serving_bound double precision,
    ADD COLUMN IF NOT EXISTS seconds_since_last_commit double precision;

-- Physical size fails closed even for populated, never-analyzed tables (reltuples=-1).
-- Only a physically empty ledger is safe for an inline build. The analogous
-- reltuples guard in 9001450_bronze_ledger_egress.sql needs a separate fix.
ALTER TABLE lake_tail_compaction_batches
    ADD COLUMN IF NOT EXISTS decode_solo_rows_max bigint;

DO $indexes$
BEGIN
    -- The fill window includes activated and compaction-superseded objects,
    -- which migration 297's staged/visible partial indexes cannot cover.
    IF to_regclass('public.idx_lake_tail_flow_arrivals') IS NULL
        AND pg_relation_size('public.lake_hot_tail_objects') > 0 THEN
        RAISE EXCEPTION 'run scripts/lake-tail-flow-indexes.sql (CONCURRENTLY) first';
    END IF;
    CREATE INDEX IF NOT EXISTS idx_lake_tail_flow_arrivals
        ON public.lake_hot_tail_objects (tenant_id, table_location_prefix, staged_at);

    IF to_regclass('public.idx_lake_tail_pack_commits') IS NULL
        AND pg_relation_size('public.lake_hot_tail_objects') > 0 THEN
        RAISE EXCEPTION 'run scripts/lake-tail-flow-indexes.sql (CONCURRENTLY) first';
    END IF;
    CREATE INDEX IF NOT EXISTS idx_lake_tail_pack_commits
        ON public.lake_hot_tail_objects (tenant_id, table_location_prefix, superseded_at)
        WHERE status='superseded' AND compaction_batch_id IS NULL;

    IF EXISTS (SELECT 1 FROM pg_index WHERE indexrelid IN (
        'public.idx_lake_tail_flow_arrivals'::regclass,
        'public.idx_lake_tail_pack_commits'::regclass) AND NOT (indisvalid AND indisready)) THEN
        RAISE EXCEPTION 'invalid prebuilt tail flow index: drop it concurrently and rerun the prebuild';
    END IF;
END
$indexes$;

-- PostgreSQL cannot CREATE OR REPLACE a changed RETURNS TABLE shape.
-- Replace atomically, preserving owner and explicit EXECUTE grants; never
-- CASCADE away dependencies. Reapplying this migration preserves the same ACL.
DO $migration$
DECLARE
    grants text[];
    grant_sql text;
    owner_name name;
    owner_token integer := 0;
    switched_role boolean;
BEGIN
    SELECT pg_get_userbyid(p.proowner),
           ARRAY(SELECT format('GRANT EXECUTE ON FUNCTION lake_pipeline_health_read(text) TO %s%s',
                      CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE quote_ident(pg_get_userbyid(a.grantee)) END,
                      CASE WHEN a.is_grantable THEN ' WITH GRANT OPTION' ELSE '' END)
                 FROM aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) a
                 WHERE a.privilege_type='EXECUTE')
    INTO STRICT owner_name, grants
    FROM pg_proc p WHERE p.oid='lake_pipeline_health_read(text)'::regprocedure;
    switched_role := owner_name <> current_user;
    IF switched_role THEN
        -- Open-core installations have no nano_shared schema or bootstrap.
        IF to_regprocedure('nano_shared.begin_managed_owner_bootstrap(name)') IS NOT NULL THEN
            owner_token := nano_shared.begin_managed_owner_bootstrap(owner_name);
        END IF;
        IF owner_token = 0 AND NOT pg_has_role(current_user, owner_name, 'SET') THEN
            RAISE EXCEPTION 'tail flow health owner bootstrap did not open';
        END IF;
    END IF;
    -- Keep the bootstrap outside this subtransaction so error cleanup can
    -- close its token after DROP/CREATE and SET ROLE have rolled back.
    BEGIN
        IF switched_role THEN
            EXECUTE format('SET ROLE %I', owner_name);
        END IF;
        DROP FUNCTION lake_pipeline_health_read(text);
        EXECUTE $definition$
CREATE OR REPLACE FUNCTION lake_pipeline_health_read(requested_tenant text)
RETURNS TABLE (
    table_location_prefix text, stage text, producer text,
    backlog_rows bigint, backlog_objects bigint, backlog_scope text,
    lag_seconds double precision, heartbeat_age_seconds double precision,
    last_success timestamptz, last_commit timestamptz, last_error text,
    fill_objects_per_hour double precision, drain_objects_per_hour double precision,
    serving_bound_objects bigint, seconds_to_serving_bound double precision,
    seconds_since_last_commit double precision
)
LANGUAGE sql STABLE SECURITY INVOKER AS $$
    SELECT h.table_location_prefix, h.stage, h.producer,
           h.backlog_rows, h.backlog_objects, h.backlog_scope,
           CASE WHEN h.oldest_pending_at IS NULL THEN 0::double precision
                ELSE GREATEST(0, EXTRACT(EPOCH FROM (statement_timestamp() - h.oldest_pending_at)))::double precision END,
           GREATEST(0, EXTRACT(EPOCH FROM (statement_timestamp() - h.observed_at)))::double precision,
           h.last_success, h.last_commit, h.last_error,
           h.fill_objects_per_hour, h.drain_objects_per_hour,
           h.serving_bound_objects, h.seconds_to_serving_bound, h.seconds_since_last_commit
    FROM lake_pipeline_health h WHERE h.tenant_id = requested_tenant
    ORDER BY h.table_location_prefix, h.stage, h.producer
$$;
$definition$;
        -- Clear any current default-privilege grants before restoring the old ACL.
        FOR grant_sql IN
            SELECT format('REVOKE ALL ON FUNCTION lake_pipeline_health_read(text) FROM %s',
                   CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE quote_ident(pg_get_userbyid(a.grantee)) END)
            FROM pg_proc p, LATERAL aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) a
            WHERE p.oid='lake_pipeline_health_read(text)'::regprocedure AND a.grantee<>p.proowner
        LOOP
            EXECUTE grant_sql;
        END LOOP;
        FOREACH grant_sql IN ARRAY grants LOOP
            EXECUTE grant_sql;
        END LOOP;
    EXCEPTION WHEN OTHERS THEN
        IF switched_role THEN
            RESET ROLE;
            IF owner_token <> 0 THEN
                PERFORM nano_shared.end_managed_owner_bootstrap(owner_name, owner_token);
            END IF;
        END IF;
        RAISE;
    END;
    IF switched_role THEN
        RESET ROLE;
        IF owner_token <> 0 THEN
            PERFORM nano_shared.end_managed_owner_bootstrap(owner_name, owner_token);
        END IF;
    END IF;
END
$migration$;
