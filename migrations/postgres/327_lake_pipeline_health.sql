-- NAN-2404: stage liveness and measured ledger backlog. Payloads and arbitrary
-- error text are deliberately excluded. Producers retain independent rows.
CREATE TABLE IF NOT EXISTS lake_pipeline_health (
    tenant_id text NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 256),
    table_location_prefix text NOT NULL CHECK (length(table_location_prefix) BETWEEN 6 AND 2048),
    stage text NOT NULL CHECK (stage IN ('bronze', 'staged_tail', 'pack', 'compact', 'generation')),
    producer text NOT NULL CHECK (length(producer) BETWEEN 1 AND 256),
    backlog_rows bigint NOT NULL CHECK (backlog_rows >= 0),
    backlog_objects bigint NOT NULL CHECK (backlog_objects >= 0),
    backlog_scope text NOT NULL CHECK (backlog_scope IN ('reserved_bronze', 'staged', 'unsigned_tail', 'unactivated')),
    oldest_pending_at timestamptz,
    last_success timestamptz,
    last_commit timestamptz,
    last_error text CHECK (last_error ~ '^[a-z0-9_]{1,80}$'),
    observed_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, table_location_prefix, stage, producer)
);

CREATE OR REPLACE FUNCTION lake_pipeline_health_read(requested_tenant text)
RETURNS TABLE (
    table_location_prefix text, stage text, producer text,
    backlog_rows bigint, backlog_objects bigint, backlog_scope text,
    lag_seconds double precision, heartbeat_age_seconds double precision,
    last_success timestamptz, last_commit timestamptz, last_error text
)
LANGUAGE sql STABLE SECURITY INVOKER AS $$
    SELECT h.table_location_prefix, h.stage, h.producer,
           h.backlog_rows, h.backlog_objects, h.backlog_scope,
           CASE WHEN h.oldest_pending_at IS NULL THEN 0::double precision
                ELSE GREATEST(0, EXTRACT(EPOCH FROM (statement_timestamp() - h.oldest_pending_at)))::double precision END,
           GREATEST(0, EXTRACT(EPOCH FROM (statement_timestamp() - h.observed_at)))::double precision,
           h.last_success, h.last_commit, h.last_error
    FROM lake_pipeline_health h WHERE h.tenant_id = requested_tenant
    ORDER BY h.table_location_prefix, h.stage, h.producer
$$;
REVOKE ALL ON FUNCTION lake_pipeline_health_read(text) FROM PUBLIC;

-- Retries must keep their publication mode when cadence is enabled or rolled
-- back after an ambiguous Iceberg commit. NULL identifies legacy reservations.
ALTER TABLE lake_tail_compaction_batches ADD COLUMN IF NOT EXISTS publication_mode text
    CHECK (publication_mode IN ('register', 'rewrite'));
CREATE INDEX IF NOT EXISTS idx_lake_tail_compaction_last_completed
    ON lake_tail_compaction_batches (tenant_id, table_location_prefix, completed_at DESC)
    WHERE completed_at IS NOT NULL;
