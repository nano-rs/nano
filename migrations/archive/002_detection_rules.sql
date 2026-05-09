-- Detection Rules Table
-- Requirements: 12.1, 12.7, 12.8

CREATE TABLE IF NOT EXISTS detection_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    description TEXT,
    query TEXT NOT NULL,  -- Piped query syntax
    severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'informational')),
    mitre_tactics TEXT[] DEFAULT '{}',
    mitre_techniques TEXT[] DEFAULT '{}',
    schedule_cron TEXT,  -- NULL for real-time only
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    last_run_at TIMESTAMPTZ,
    match_count BIGINT DEFAULT 0
);

-- Indexes for detection rules
CREATE INDEX IF NOT EXISTS idx_detection_rules_name ON detection_rules (name);
CREATE INDEX IF NOT EXISTS idx_detection_rules_severity ON detection_rules (severity);
CREATE INDEX IF NOT EXISTS idx_detection_rules_enabled ON detection_rules (enabled);
CREATE INDEX IF NOT EXISTS idx_detection_rules_mitre_tactics ON detection_rules USING GIN (mitre_tactics);
CREATE INDEX IF NOT EXISTS idx_detection_rules_mitre_techniques ON detection_rules USING GIN (mitre_techniques);

-- Trigger to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_detection_rules_updated_at
    BEFORE UPDATE ON detection_rules
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
