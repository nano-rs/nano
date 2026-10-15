-- NAN-2361: synthetic probe results are asynchronously committed through the
-- OTLP/Vector/Iceberg path. Result visibility therefore cannot be the authority
-- for deciding whether the next 15-second scheduler tick should fire again.
-- Keep only the scheduling watermark in PostgreSQL and claim it atomically;
-- probe measurements remain in the observability data store.

ALTER TABLE observability_synthetic_checks
    ADD COLUMN IF NOT EXISTS next_run_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE INDEX IF NOT EXISTS idx_observability_synthetic_checks_due
    ON observability_synthetic_checks (next_run_at, id)
    WHERE enabled = TRUE;

COMMENT ON COLUMN observability_synthetic_checks.next_run_at IS
    'Control-plane scheduler watermark atomically claimed by nanosiem-jobs; probe measurements are not stored in PostgreSQL.';
