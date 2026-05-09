-- IP Allowlist for restricting access by client IP address
-- Supports scoped allowlisting: global, api, search, frontend

CREATE TABLE IF NOT EXISTS ip_allowlists (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scope       TEXT NOT NULL CHECK (scope IN ('global', 'api', 'search', 'frontend')),
    cidr        TEXT NOT NULL,
    description TEXT,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for fast scope-based lookups (the hot path for middleware)
CREATE INDEX idx_ip_allowlists_scope_enabled ON ip_allowlists (scope) WHERE enabled = TRUE;

-- Prevent duplicate CIDR entries within the same scope
CREATE UNIQUE INDEX idx_ip_allowlists_scope_cidr ON ip_allowlists (scope, cidr);

-- Trigger to auto-update updated_at
CREATE OR REPLACE FUNCTION update_ip_allowlists_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER ip_allowlists_updated_at
    BEFORE UPDATE ON ip_allowlists
    FOR EACH ROW
    EXECUTE FUNCTION update_ip_allowlists_updated_at();
