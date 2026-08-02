-- NAN-2282: durable system-health event bus and outbound delivery outbox.
--
-- Nano is deployed as one security tenant per control-plane database today.
-- `tenant_id` is still explicit on every row and every uniqueness boundary so
-- a future shared control plane cannot accidentally turn health state into a
-- cross-tenant singleton. The application currently publishes as `default`.

CREATE TABLE IF NOT EXISTS system_health_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id TEXT NOT NULL DEFAULT 'default',
    dedup_key TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT,
    resource_name TEXT,
    diagnostic_context JSONB NOT NULL DEFAULT '{}'::jsonb,
    remediation TEXT,
    source TEXT NOT NULL,
    occurrence_count BIGINT NOT NULL DEFAULT 1,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_notified_at TIMESTAMPTZ,
    acknowledged_at TIMESTAMPTZ,
    acknowledged_by UUID REFERENCES users(id) ON DELETE SET NULL,
    resolved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT system_health_category_valid CHECK (
        category IN ('integration', 'enrichment', 'log_source', 'ingestion',
                     'parser', 'storage', 'query', 'credential', 'service')
    ),
    CONSTRAINT system_health_severity_valid CHECK (
        severity IN ('critical', 'high', 'medium', 'low', 'informational')
    ),
    CONSTRAINT system_health_status_valid CHECK (status IN ('active', 'resolved')),
    CONSTRAINT system_health_dedup_key_nonempty CHECK (length(trim(dedup_key)) > 0),
    CONSTRAINT system_health_source_nonempty CHECK (length(trim(source)) > 0)
);

-- One active lifecycle per stable producer key. A resolved lifecycle remains
-- historical; the same condition can later open a fresh active lifecycle.
CREATE UNIQUE INDEX IF NOT EXISTS idx_system_health_events_active_dedup
    ON system_health_events (tenant_id, dedup_key)
    WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_system_health_events_status_seen
    ON system_health_events (tenant_id, status, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_system_health_events_category_seen
    ON system_health_events (tenant_id, category, last_seen_at DESC);

-- Add health-event subscriptions and routing dimensions to the existing
-- notification-channel store. Severity routing reuses `severity_filter`.
ALTER TABLE webhooks
    ADD COLUMN IF NOT EXISTS health_category_filter TEXT[];
ALTER TABLE webhooks
    ADD COLUMN IF NOT EXISTS health_resource_filter TEXT[];

COMMENT ON COLUMN webhooks.health_category_filter IS
    'System-health routing filter by category. NULL/empty = all categories.';
COMMENT ON COLUMN webhooks.health_resource_filter IS
    'System-health routing filter by resource_type. NULL/empty = all resource types.';

-- One durable logical delivery per event lifecycle transition and destination.
-- The row itself is the delivery history/dead-letter record after completion.
CREATE TABLE IF NOT EXISTS system_health_outbox (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id TEXT NOT NULL DEFAULT 'default',
    event_id UUID NOT NULL REFERENCES system_health_events(id) ON DELETE CASCADE,
    webhook_id UUID NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
    event_action TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    attempt_count INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    locked_at TIMESTAMPTZ,
    locked_by TEXT,
    delivered_at TIMESTAMPTZ,
    last_status_code INTEGER,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT system_health_outbox_action_valid CHECK (
        event_action IN ('triggered', 'reminder', 'resolved')
    ),
    CONSTRAINT system_health_outbox_status_valid CHECK (
        status IN ('pending', 'delivering', 'retry', 'delivered', 'dead')
    ),
    UNIQUE (tenant_id, event_id, webhook_id, event_action)
);

CREATE INDEX IF NOT EXISTS idx_system_health_outbox_due
    ON system_health_outbox (next_attempt_at, created_at)
    WHERE status IN ('pending', 'retry', 'delivering');
CREATE INDEX IF NOT EXISTS idx_system_health_outbox_event
    ON system_health_outbox (tenant_id, event_id, created_at DESC);

INSERT INTO permissions (id, name, category, description)
VALUES
    ('system_health:view', 'View System Health Events', 'system_health',
     'View active and historical system health degradation events'),
    ('system_health:manage', 'Manage System Health Events', 'system_health',
     'Acknowledge and resolve system health events and manage their delivery')
ON CONFLICT (id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT rp.role_id, 'system_health:view'
FROM role_permissions rp
WHERE rp.permission_id = 'settings:view'
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT rp.role_id, 'system_health:manage'
FROM role_permissions rp
WHERE rp.permission_id = 'settings:system'
ON CONFLICT DO NOTHING;

-- Defense in depth for deployments with heavily customized legacy roles.
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'Admin'
  AND p.id IN ('system_health:view', 'system_health:manage')
ON CONFLICT DO NOTHING;
