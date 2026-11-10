-- NAN-5204: status of the optional automatic backups.
--
-- The `nano-backup` compose sidecar reports every scheduled attempt to
-- nano-api (POST /api/internal/backup-status). This single-row table keeps
-- the latest state for the admin card / banner (GET /api/system/backup-status)
-- and the SIEM Health "no successful backup in 36 hours" finding.
--
-- Forward-only, idempotent, no backfill: no row means "never configured".

CREATE TABLE IF NOT EXISTS backup_status (
    id                       SMALLINT PRIMARY KEY CHECK (id = 1),
    enabled                  BOOLEAN NOT NULL DEFAULT false,
    enabled_since            TIMESTAMPTZ,
    last_attempt_at          TIMESTAMPTZ,
    last_outcome             TEXT CHECK (last_outcome IN ('success', 'partial', 'failure')),
    last_success_at          TIMESTAMPTZ,
    last_success_backup_id   TEXT,
    last_success_size_bytes  BIGINT CHECK (last_success_size_bytes >= 0),
    last_failure_at          TIMESTAMPTZ,
    last_failure_error       TEXT,
    consecutive_failures     INTEGER NOT NULL DEFAULT 0,
    destination_kind         TEXT CHECK (destination_kind IN ('path', 's3')),
    destination              TEXT,
    clickhouse_data          TEXT CHECK (clickhouse_data IN ('included', 'excluded')),
    schedule                 TEXT,
    keep                     INTEGER,
    next_run_at              TIMESTAMPTZ,
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE backup_status IS
    'NAN-5204: latest automatic-backup state reported by the nano-backup sidecar (single row, id = 1).';
