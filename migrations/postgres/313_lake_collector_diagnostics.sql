-- NAN-2361: bounded control-plane diagnostics for ClickHouse-free collectors.
-- This stores Vector WARN/ERROR metadata only, never customer log payloads.

CREATE TABLE IF NOT EXISTS lake_collector_errors (
    id bigserial PRIMARY KEY,
    tenant_id text NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 256),
    occurred_at timestamptz NOT NULL,
    level text NOT NULL CHECK (level IN ('WARN', 'ERROR')),
    message text NOT NULL CHECK (length(message) <= 8192),
    error_code text NOT NULL DEFAULT '' CHECK (length(error_code) <= 512),
    error_type text NOT NULL DEFAULT '' CHECK (length(error_type) <= 512),
    stage text NOT NULL DEFAULT '' CHECK (length(stage) <= 512),
    component_id text NOT NULL DEFAULT '' CHECK (length(component_id) <= 512),
    component_kind text NOT NULL DEFAULT '' CHECK (length(component_kind) <= 512),
    component_type text NOT NULL DEFAULT '' CHECK (length(component_type) <= 512),
    collector_host text NOT NULL DEFAULT '' CHECK (length(collector_host) <= 1024),
    received_at timestamptz NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_lake_collector_errors_source_recent
    ON lake_collector_errors (tenant_id, component_id, occurred_at DESC);

CREATE INDEX IF NOT EXISTS idx_lake_collector_errors_retention
    ON lake_collector_errors (received_at);

COMMENT ON TABLE lake_collector_errors IS
    'Fourteen-day bounded Vector WARN/ERROR control-plane metadata for source health; contains no customer events.';
