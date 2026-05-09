CREATE TABLE IF NOT EXISTS wizard_sessions (
    session_id TEXT PRIMARY KEY,
    user_id UUID NOT NULL,
    current_step JSONB NOT NULL,
    log_source_draft JSONB NOT NULL,
    sample_logs JSONB NOT NULL DEFAULT '[]',
    validation_result JSONB,
    test_results JSONB NOT NULL DEFAULT '[]',
    ai_suggestions JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_wizard_sessions_user ON wizard_sessions(user_id);
CREATE INDEX idx_wizard_sessions_cleanup ON wizard_sessions(updated_at);
