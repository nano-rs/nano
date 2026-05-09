-- Dashboards Table
-- Requirements: 17.1, 17.4, 17.5

CREATE TABLE IF NOT EXISTS dashboards (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    description TEXT,
    layout JSONB NOT NULL DEFAULT '{}',  -- Panel positions and sizes
    panels JSONB NOT NULL DEFAULT '[]',  -- Panel configurations
    refresh_interval INTEGER,  -- Seconds, NULL for no auto-refresh
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for dashboards
CREATE INDEX IF NOT EXISTS idx_dashboards_name ON dashboards (name);
CREATE INDEX IF NOT EXISTS idx_dashboards_created_at ON dashboards (created_at DESC);

-- Trigger to update updated_at timestamp
CREATE TRIGGER update_dashboards_updated_at
    BEFORE UPDATE ON dashboards
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
