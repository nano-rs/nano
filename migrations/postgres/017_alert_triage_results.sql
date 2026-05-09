-- Alert Triage Results Table
-- Stores AI-generated triage results for alerts
-- Used by the AI Alert Agent to persist analysis results

CREATE TABLE IF NOT EXISTS alert_triage_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id UUID NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    session_id VARCHAR(100) NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    status VARCHAR(20) DEFAULT 'running',  -- running, completed, failed, cancelled
    
    -- Agent results (JSONB for flexibility)
    initial_triage JSONB,
    correlation JSONB,
    enrichment JSONB,
    context JSONB,
    risk_assessment JSONB,
    verdict JSONB,
    
    -- Summary fields for quick access
    verdict_type VARCHAR(50),  -- true_positive, false_positive, benign, needs_investigation, inconclusive
    confidence FLOAT,
    
    -- Error tracking
    error_message TEXT,
    
    -- Audit
    triggered_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Index for finding triage results by alert
CREATE INDEX IF NOT EXISTS idx_triage_alert 
ON alert_triage_results(alert_id);

-- Index for finding triage results by session
CREATE INDEX IF NOT EXISTS idx_triage_session 
ON alert_triage_results(session_id);

-- Index for finding running triage sessions
CREATE INDEX IF NOT EXISTS idx_triage_status 
ON alert_triage_results(status) 
WHERE status = 'running';

-- Index for finding latest triage per alert
CREATE INDEX IF NOT EXISTS idx_triage_alert_created 
ON alert_triage_results(alert_id, created_at DESC);

-- Index for user's triage history
CREATE INDEX IF NOT EXISTS idx_triage_user 
ON alert_triage_results(triggered_by, created_at DESC);

-- Comments for documentation
COMMENT ON TABLE alert_triage_results IS 'Stores AI-generated triage analysis results for alerts';
COMMENT ON COLUMN alert_triage_results.session_id IS 'Unique session identifier for tracking progress via SSE';
COMMENT ON COLUMN alert_triage_results.status IS 'Triage status: running, completed, failed, cancelled';
COMMENT ON COLUMN alert_triage_results.initial_triage IS 'Results from initial triage agent (entity extraction, hypothesis)';
COMMENT ON COLUMN alert_triage_results.correlation IS 'Results from correlation agent (related alerts, patterns)';
COMMENT ON COLUMN alert_triage_results.enrichment IS 'Results from enrichment agent (VT, threat intel)';
COMMENT ON COLUMN alert_triage_results.context IS 'Results from context agent (surrounding events, timeline)';
COMMENT ON COLUMN alert_triage_results.risk_assessment IS 'Results from risk agent (entity risk scores, signals)';
COMMENT ON COLUMN alert_triage_results.verdict IS 'Final verdict from verdict agent (classification, recommendations)';
COMMENT ON COLUMN alert_triage_results.verdict_type IS 'Quick access to verdict classification';
COMMENT ON COLUMN alert_triage_results.confidence IS 'Confidence score for the verdict (0.0 - 1.0)';
