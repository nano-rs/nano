-- Alerts Table
-- Requirements: 14.1, 14.2, 14.3, 14.4, 14.5

CREATE TABLE IF NOT EXISTS alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    rule_id UUID REFERENCES detection_rules(id) ON DELETE SET NULL,
    severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'informational')),
    status TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'acknowledged', 'closed')),
    disposition TEXT CHECK (disposition IN ('true_positive', 'false_positive', 'benign')),
    matched_events JSONB NOT NULL DEFAULT '[]',
    assigned_to TEXT,
    acknowledged_by TEXT,
    acknowledged_at TIMESTAMPTZ,
    closed_by TEXT,
    closed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for alerts
CREATE INDEX IF NOT EXISTS idx_alerts_rule_id ON alerts (rule_id);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts (status);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_assigned_to ON alerts (assigned_to);

-- Composite index for common query: open alerts sorted by severity and time
CREATE INDEX IF NOT EXISTS idx_alerts_open_priority ON alerts (severity, created_at DESC) 
    WHERE status IN ('new', 'acknowledged');
