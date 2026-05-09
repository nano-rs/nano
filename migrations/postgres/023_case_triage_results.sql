-- Case Triage Results Table
-- Stores AI-generated triage results for cases (multi-alert analysis)
-- Used by the AI Alert Agent to persist case-level analysis results

CREATE TABLE IF NOT EXISTS case_triage_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    session_id VARCHAR(100) NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    status VARCHAR(20) DEFAULT 'running',  -- running, completed, failed, cancelled

    -- Case triage specific fields
    alert_count INTEGER NOT NULL DEFAULT 0,
    time_span_hours FLOAT,

    -- Agent results (JSONB for flexibility)
    initial_triage JSONB,      -- CaseInitialTriageResult
    correlation JSONB,          -- CorrelationResult
    enrichment JSONB,           -- EnrichmentResult
    context JSONB,              -- ContextResult
    attack_progression JSONB,   -- AttackProgressionResult
    verdict JSONB,              -- CaseVerdictResult

    -- Summary fields for quick access
    verdict_type VARCHAR(50),  -- true_positive, false_positive, benign, needs_investigation, inconclusive
    confidence FLOAT,
    executive_summary TEXT,

    -- Error tracking
    error_message TEXT,

    -- Audit
    triggered_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Index for finding triage results by case
CREATE INDEX IF NOT EXISTS idx_case_triage_case
ON case_triage_results(case_id);

-- Index for finding triage results by session
CREATE INDEX IF NOT EXISTS idx_case_triage_session
ON case_triage_results(session_id);

-- Index for finding running triage sessions
CREATE INDEX IF NOT EXISTS idx_case_triage_status
ON case_triage_results(status)
WHERE status = 'running';

-- Index for finding latest triage per case
CREATE INDEX IF NOT EXISTS idx_case_triage_case_created
ON case_triage_results(case_id, created_at DESC);

-- Index for user's triage history
CREATE INDEX IF NOT EXISTS idx_case_triage_user
ON case_triage_results(triggered_by, created_at DESC);

-- Comments for documentation
COMMENT ON TABLE case_triage_results IS 'Stores AI-generated triage analysis results for cases (multi-alert)';
COMMENT ON COLUMN case_triage_results.session_id IS 'Unique session identifier for tracking progress via SSE';
COMMENT ON COLUMN case_triage_results.status IS 'Triage status: running, completed, failed, cancelled';
COMMENT ON COLUMN case_triage_results.alert_count IS 'Number of alerts analyzed in this case triage';
COMMENT ON COLUMN case_triage_results.time_span_hours IS 'Time span of alerts in hours';
COMMENT ON COLUMN case_triage_results.initial_triage IS 'Case-level initial triage (aggregated entities, timeline)';
COMMENT ON COLUMN case_triage_results.attack_progression IS 'Attack chain/phase detection results';
COMMENT ON COLUMN case_triage_results.verdict IS 'Case-level verdict with bulk recommendations';
COMMENT ON COLUMN case_triage_results.executive_summary IS 'Quick access to case summary';
