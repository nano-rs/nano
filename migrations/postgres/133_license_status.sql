-- License status cache for BYOC deployments
-- Caches the last known license status from nano-main to avoid
-- flapping on network blips and to survive restarts.

CREATE TABLE IF NOT EXISTS license_status (
    -- Singleton row (only one license per deployment)
    id          BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
    -- State machine: active, grace_period, locked
    status      TEXT NOT NULL DEFAULT 'active',
    -- Whether the license is currently valid
    valid       BOOLEAN NOT NULL DEFAULT TRUE,
    -- Organization tier from nano-main
    tier        TEXT,
    -- If locked, reason from nano-main
    locked_reason TEXT,
    -- Grace period end timestamp (NULL if not in grace)
    grace_ends_at TIMESTAMPTZ,
    -- When the license expires
    expires_at  TIMESTAMPTZ,
    -- Last successful check timestamp
    last_checked_at TIMESTAMPTZ,
    -- Last successful heartbeat timestamp
    last_heartbeat_at TIMESTAMPTZ,
    -- Raw JSON response from last license check (for debugging)
    raw_response JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed with default active status (self-hosted deployments start unlocked)
INSERT INTO license_status (status, valid)
VALUES ('active', TRUE)
ON CONFLICT (id) DO NOTHING;
