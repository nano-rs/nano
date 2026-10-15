-- NAN-2361: park an intrinsically unprocessable, exactly reserved tail
-- compaction without hiding or deleting its source rows.  The source objects
-- remain `staged` in lake_hot_tail_objects (and therefore query-visible) while
-- this ledger removes only the poisoned batch from automatic compaction
-- selection.  An operator replay must revalidate the same tenant/table/input
-- identity before returning the batch to service.

CREATE TABLE IF NOT EXISTS lake_tail_compaction_batches (
    tenant_id TEXT NOT NULL,
    table_location_prefix TEXT NOT NULL,
    compaction_batch_id UUID NOT NULL,
    input_sha256 TEXT NOT NULL CHECK (input_sha256 ~ '^[0-9a-f]{64}$'),
    input_objects INTEGER NOT NULL CHECK (input_objects BETWEEN 1 AND 4096),
    status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'quarantined', 'completed')),
    attempt_count BIGINT NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    consecutive_poison_failures INTEGER NOT NULL DEFAULT 0
        CHECK (consecutive_poison_failures BETWEEN 0 AND 3),
    replay_count INTEGER NOT NULL DEFAULT 0 CHECK (replay_count >= 0),
    reserved_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    last_attempted_at TIMESTAMPTZ,
    last_error_code TEXT,
    last_error_sha256 TEXT,
    quarantined_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, table_location_prefix, compaction_batch_id),
    CHECK (length(tenant_id) BETWEEN 1 AND 256),
    CHECK (
        table_location_prefix LIKE 's3://%/'
        AND length(table_location_prefix) BETWEEN 6 AND 2048
    ),
    CHECK (
        (last_error_code IS NULL AND last_error_sha256 IS NULL)
        OR (
            last_error_code ~ '^[a-z0-9_]{1,80}$'
            AND last_error_sha256 ~ '^[0-9a-f]{64}$'
            AND last_attempted_at IS NOT NULL
        )
    ),
    CHECK (
        (status = 'active' AND quarantined_at IS NULL AND completed_at IS NULL)
        OR (
            status = 'quarantined'
            AND quarantined_at IS NOT NULL
            AND completed_at IS NULL
            AND consecutive_poison_failures = 3
        )
        OR (
            status = 'completed'
            AND quarantined_at IS NULL
            AND completed_at IS NOT NULL
        )
    )
);

CREATE INDEX IF NOT EXISTS idx_lake_tail_compaction_batches_active
    ON lake_tail_compaction_batches
        (tenant_id, table_location_prefix, reserved_at, compaction_batch_id)
    WHERE status = 'active';

CREATE UNIQUE INDEX IF NOT EXISTS idx_lake_tail_compaction_one_active_table
    ON lake_tail_compaction_batches (tenant_id, table_location_prefix)
    WHERE status = 'active';

CREATE INDEX IF NOT EXISTS idx_lake_tail_compaction_batches_quarantined
    ON lake_tail_compaction_batches
        (quarantined_at, tenant_id, table_location_prefix, compaction_batch_id)
    WHERE status = 'quarantined';

CREATE TABLE IF NOT EXISTS lake_tail_compaction_poison_failures (
    tenant_id TEXT NOT NULL,
    table_location_prefix TEXT NOT NULL,
    compaction_batch_id UUID NOT NULL,
    attempt_number BIGINT NOT NULL CHECK (attempt_number > 0),
    replay_number INTEGER NOT NULL CHECK (replay_number >= 0),
    error_code TEXT NOT NULL CHECK (error_code ~ '^[a-z0-9_]{1,80}$'),
    error_evidence_sha256 TEXT NOT NULL
        CHECK (error_evidence_sha256 ~ '^[0-9a-f]{64}$'),
    failed_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (
        tenant_id,
        table_location_prefix,
        compaction_batch_id,
        attempt_number
    ),
    FOREIGN KEY (tenant_id, table_location_prefix, compaction_batch_id)
        REFERENCES lake_tail_compaction_batches
            (tenant_id, table_location_prefix, compaction_batch_id)
        ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS lake_tail_compaction_replays (
    tenant_id TEXT NOT NULL,
    table_location_prefix TEXT NOT NULL,
    compaction_batch_id UUID NOT NULL,
    replay_number INTEGER NOT NULL CHECK (replay_number > 0),
    input_sha256 TEXT NOT NULL CHECK (input_sha256 ~ '^[0-9a-f]{64}$'),
    operator_id TEXT NOT NULL CHECK (length(operator_id) BETWEEN 1 AND 200),
    reason TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 500),
    replayed_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (
        tenant_id,
        table_location_prefix,
        compaction_batch_id,
        replay_number
    ),
    FOREIGN KEY (tenant_id, table_location_prefix, compaction_batch_id)
        REFERENCES lake_tail_compaction_batches
            (tenant_id, table_location_prefix, compaction_batch_id)
        ON DELETE RESTRICT
);

CREATE OR REPLACE FUNCTION lake_tail_compaction_audit_is_append_only()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'tail compaction audit evidence is append-only';
END;
$$;

DROP TRIGGER IF EXISTS lake_tail_compaction_poison_failures_append_only
    ON lake_tail_compaction_poison_failures;
CREATE TRIGGER lake_tail_compaction_poison_failures_append_only
    BEFORE UPDATE OR DELETE ON lake_tail_compaction_poison_failures
    FOR EACH ROW EXECUTE FUNCTION lake_tail_compaction_audit_is_append_only();

DROP TRIGGER IF EXISTS lake_tail_compaction_replays_append_only
    ON lake_tail_compaction_replays;
CREATE TRIGGER lake_tail_compaction_replays_append_only
    BEFORE UPDATE OR DELETE ON lake_tail_compaction_replays
    FOR EACH ROW EXECUTE FUNCTION lake_tail_compaction_audit_is_append_only();

-- An open quarantine is itself an operational alert.  Keeping the view
-- query-visible lets health collectors page without parsing process logs.
CREATE OR REPLACE VIEW lake_tail_compaction_quarantine_alerts AS
SELECT
    tenant_id,
    table_location_prefix,
    compaction_batch_id,
    input_sha256,
    input_objects,
    attempt_count,
    replay_count,
    last_error_code,
    last_error_sha256,
    reserved_at,
    last_attempted_at,
    quarantined_at
FROM lake_tail_compaction_batches
WHERE status = 'quarantined';

-- Exact object/version evidence for an open quarantine.  The underlying rows
-- deliberately remain staged and continue to participate in the signed hot
-- tail until a successful replay reaches normal compaction acknowledgement.
CREATE OR REPLACE VIEW lake_tail_compaction_quarantine_objects AS
SELECT
    batch.tenant_id,
    batch.table_location_prefix,
    batch.compaction_batch_id,
    batch.input_sha256,
    object.bronze_store_id,
    object.batch_sha256,
    object.event_hour,
    object.object_uri,
    object.version_id,
    object.object_etag,
    object.object_bytes,
    object.object_sha256,
    object.rows,
    object.min_time_ms,
    object.max_time_ms,
    object.staged_at,
    batch.quarantined_at
FROM lake_tail_compaction_batches AS batch
JOIN lake_hot_tail_objects AS object
  ON object.tenant_id = batch.tenant_id
 AND object.table_location_prefix = batch.table_location_prefix
 AND object.compaction_batch_id = batch.compaction_batch_id
WHERE batch.status = 'quarantined'
  AND object.status = 'staged';

COMMENT ON TABLE lake_tail_compaction_batches IS
    'Tenant/table-scoped durable tail-compaction state. Quarantine parks work only; exact staged source rows remain query-visible.';
COMMENT ON TABLE lake_tail_compaction_poison_failures IS
    'Append-only typed evidence for deterministic tail-compaction failures. The evidence digest binds batch UUID, exact input digest, and error code; raw error text is deliberately excluded.';
COMMENT ON TABLE lake_tail_compaction_replays IS
    'Append-only operator audit trail for exact-identity quarantine replay.';
COMMENT ON VIEW lake_tail_compaction_quarantine_alerts IS
    'Open, query-visible tail-compaction quarantine alerts requiring operator action.';
COMMENT ON VIEW lake_tail_compaction_quarantine_objects IS
    'Exact immutable object/version identities retained in each open tail-compaction quarantine.';
