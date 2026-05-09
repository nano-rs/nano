-- SIEM Health Check reports — AI-driven analysis of ingestion, parsing, and detection quality
-- Reports are generated every 12 hours by a leader-only scheduler

CREATE TABLE IF NOT EXISTS siem_health_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Overall score (0-100)
    overall_score INTEGER NOT NULL,
    overall_status VARCHAR(20) NOT NULL, -- 'healthy', 'warning', 'critical'
    -- Dimension scores (0-100)
    ingestion_score INTEGER NOT NULL,
    parsing_score INTEGER NOT NULL,
    detection_score INTEGER NOT NULL,
    -- AI-generated analysis (markdown)
    summary TEXT NOT NULL,
    -- Raw metrics snapshot (JSON) used to generate the report
    metrics JSONB NOT NULL DEFAULT '{}',
    -- AI-generated recommendations (JSON array of {title, description, priority})
    recommendations JSONB NOT NULL DEFAULT '[]',
    -- Dimension details (JSON with per-dimension findings)
    dimension_details JSONB NOT NULL DEFAULT '{}',
    -- Whether this was manually triggered or scheduled
    triggered_by UUID REFERENCES users(id),
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Analysis duration in milliseconds
    duration_ms INTEGER
);

-- Index for listing reports (newest first) and finding latest
CREATE INDEX idx_siem_health_reports_created_at ON siem_health_reports (created_at DESC);
