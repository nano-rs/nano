-- Webhook notification endpoints for alert creation events
-- Supports fire-and-forget HTTP POST delivery with HMAC signing and severity filtering

-- Webhook configuration table
CREATE TABLE IF NOT EXISTS webhooks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    -- Headers encrypted with AES-256-GCM via EncryptionService (JSON: {"ciphertext":"...","nonce":"..."})
    headers_encrypted BYTEA,
    -- HMAC-SHA256 secret for X-NanoSIEM-Signature header (encrypted same as headers)
    secret_encrypted BYTEA,
    -- Optional severity filter: only fire for these severities (NULL = all)
    severity_filter TEXT[],
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Delivery log for debugging and monitoring
CREATE TABLE IF NOT EXISTS webhook_delivery_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    webhook_id UUID NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
    alert_id UUID,
    event_type TEXT NOT NULL DEFAULT 'alert.created',
    status_code INTEGER,
    -- Truncated to 1KB to avoid storing large response bodies
    response_body TEXT,
    success BOOLEAN NOT NULL DEFAULT false,
    error_message TEXT,
    duration_ms INTEGER,
    delivered_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for delivery log queries
CREATE INDEX IF NOT EXISTS idx_webhook_delivery_log_webhook_id ON webhook_delivery_log(webhook_id);
CREATE INDEX IF NOT EXISTS idx_webhook_delivery_log_alert_id ON webhook_delivery_log(alert_id);
CREATE INDEX IF NOT EXISTS idx_webhook_delivery_log_delivered_at ON webhook_delivery_log(delivered_at DESC);

-- Grant webhook management permission to admin role
INSERT INTO permissions (id, name, category, description)
VALUES ('settings:webhooks', 'Manage Webhooks', 'settings', 'Manage webhook notification endpoints')
ON CONFLICT (id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, 'settings:webhooks'
FROM roles r
WHERE r.name = 'Admin'
ON CONFLICT DO NOTHING;
