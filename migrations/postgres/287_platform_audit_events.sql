-- NAN-2361: durable control-plane audit ledger for primary-lake deployments.
--
-- Platform audit is application state, not customer log data. Keeping it in
-- PostgreSQL removes the legacy ClickHouse insert from the detection/case
-- critical path while preserving the existing searchable Audit product. The
-- legacy ClickHouse audit lane remains available while old deployments migrate.

CREATE TABLE IF NOT EXISTS platform_audit_events (
    event_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    occurred_at timestamptz NOT NULL DEFAULT now(),
    actor_id uuid,
    actor_name text,
    api_key_id uuid,
    api_key_name text,
    action text NOT NULL,
    source text NOT NULL,
    resource_type text,
    resource_id uuid,
    resource_name text,
    ip_address text,
    user_agent text,
    success boolean NOT NULL,
    status text NOT NULL,
    message text NOT NULL,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_platform_audit_events_time
    ON platform_audit_events (occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_platform_audit_events_action_time
    ON platform_audit_events (action, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_platform_audit_events_source_time
    ON platform_audit_events (source, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_platform_audit_events_actor_time
    ON platform_audit_events (actor_id, occurred_at DESC)
    WHERE actor_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_platform_audit_events_api_key_time
    ON platform_audit_events (api_key_id, occurred_at DESC)
    WHERE api_key_id IS NOT NULL;

