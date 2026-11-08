-- AI Detection Auto-Tuning Schema
-- Requirements: 1.1, 1.2, 2.1, 6.1, 8.1, 12.1

-- ============================================================================
-- Rule Versioning
-- ============================================================================

-- Detection rule versions table
-- Tracks all versions of detection rules for audit and revert capabilities
CREATE TABLE IF NOT EXISTS detection_rule_versions (
    id SERIAL PRIMARY KEY,
    rule_id UUID NOT NULL REFERENCES detection_rules(id) ON DELETE CASCADE,
    version_number INTEGER NOT NULL,
    query TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'informational')),
    mitre_tactics TEXT[] DEFAULT '{}',
    mitre_techniques TEXT[] DEFAULT '{}',
    enabled BOOLEAN NOT NULL DEFAULT true,
    is_active BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID REFERENCES users(id),
    change_reason TEXT NOT NULL,
    tuning_proposal_id UUID,
    reverted_from_version INTEGER REFERENCES detection_rule_versions(id),
    UNIQUE(rule_id, version_number)
);

-- Indexes for rule versions
CREATE INDEX idx_rule_versions_rule ON detection_rule_versions(rule_id, version_number DESC);
CREATE INDEX idx_rule_versions_active ON detection_rule_versions(rule_id, is_active) WHERE is_active = true;
CREATE INDEX idx_rule_versions_created ON detection_rule_versions(created_at DESC);

-- ============================================================================
-- Baseline Tracking
-- ============================================================================

-- Detection rule baselines table
-- Stores statistical baselines for each detection rule
CREATE TABLE IF NOT EXISTS detection_rule_baselines (
    rule_id UUID PRIMARY KEY REFERENCES detection_rules(id) ON DELETE CASCADE,
    established_at TIMESTAMPTZ NOT NULL,
    last_updated TIMESTAMPTZ NOT NULL,
    mean_alerts_per_hour DOUBLE PRECISION NOT NULL,
    std_dev_alerts_per_hour DOUBLE PRECISION NOT NULL,
    percentile_95 DOUBLE PRECISION NOT NULL,
    percentile_99 DOUBLE PRECISION NOT NULL,
    threshold_breach_level DOUBLE PRECISION NOT NULL,
    data_points INTEGER NOT NULL,
    baseline_data JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX idx_baselines_last_updated ON detection_rule_baselines(last_updated DESC);

-- ============================================================================
-- Metrics History
-- ============================================================================

-- Detection rule metrics table
-- Stores time-series metrics for each detection rule
CREATE TABLE IF NOT EXISTS detection_rule_metrics (
    id BIGSERIAL PRIMARY KEY,
    rule_id UUID NOT NULL REFERENCES detection_rules(id) ON DELETE CASCADE,
    timestamp TIMESTAMPTZ NOT NULL,
    alert_count_1h BIGINT NOT NULL,
    alert_count_24h BIGINT NOT NULL,
    alert_count_7d BIGINT NOT NULL,
    unique_users BIGINT NOT NULL DEFAULT 0,
    unique_hosts BIGINT NOT NULL DEFAULT 0,
    unique_ips BIGINT NOT NULL DEFAULT 0,
    avg_severity DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    execution_time_ms BIGINT NOT NULL DEFAULT 0,
    patterns JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX idx_metrics_rule_time ON detection_rule_metrics(rule_id, timestamp DESC);
CREATE INDEX idx_metrics_timestamp ON detection_rule_metrics(timestamp DESC);

-- ============================================================================
-- Threshold Breaches
-- ============================================================================

-- Detection threshold breaches table
-- Records when detection rules exceed their baseline thresholds
CREATE TABLE IF NOT EXISTS detection_threshold_breaches (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id UUID NOT NULL REFERENCES detection_rules(id) ON DELETE CASCADE,
    detected_at TIMESTAMPTZ NOT NULL,
    current_value DOUBLE PRECISION NOT NULL,
    baseline_mean DOUBLE PRECISION NOT NULL,
    baseline_threshold DOUBLE PRECISION NOT NULL,
    deviation_magnitude DOUBLE PRECISION NOT NULL,
    consecutive_periods INTEGER NOT NULL,
    tuning_triggered BOOLEAN NOT NULL DEFAULT false,
    tuning_proposal_id UUID
);

CREATE INDEX idx_breaches_rule ON detection_threshold_breaches(rule_id, detected_at DESC);
CREATE INDEX idx_breaches_detected ON detection_threshold_breaches(detected_at DESC);
CREATE INDEX idx_breaches_triggered ON detection_threshold_breaches(tuning_triggered, detected_at DESC);

-- ============================================================================
-- Tuning Proposals
-- ============================================================================

-- Tuning proposals table
-- Stores AI-generated tuning proposals for detection rules
CREATE TABLE IF NOT EXISTS tuning_proposals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id UUID NOT NULL REFERENCES detection_rules(id) ON DELETE CASCADE,
    breach_id UUID REFERENCES detection_threshold_breaches(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    original_query TEXT NOT NULL,
    proposed_query TEXT NOT NULL,
    rationale TEXT NOT NULL,
    confidence_score DOUBLE PRECISION NOT NULL CHECK (confidence_score >= 0.0 AND confidence_score <= 1.0),
    changes_summary JSONB NOT NULL DEFAULT '[]'::jsonb,
    affected_patterns JSONB NOT NULL DEFAULT '[]'::jsonb,
    safety_validation JSONB NOT NULL DEFAULT '{}'::jsonb,
    status TEXT NOT NULL DEFAULT 'proposed' CHECK (status IN ('proposed', 'testing', 'test_passed', 'test_failed', 'staging', 'promoted', 'reverted', 'manually_approved', 'rejected'))
);

CREATE INDEX idx_proposals_rule ON tuning_proposals(rule_id, created_at DESC);
CREATE INDEX idx_proposals_status ON tuning_proposals(status, created_at DESC);
CREATE INDEX idx_proposals_created ON tuning_proposals(created_at DESC);

-- Add foreign key constraint from breaches to proposals
ALTER TABLE detection_threshold_breaches 
    ADD CONSTRAINT fk_breach_proposal 
    FOREIGN KEY (tuning_proposal_id) 
    REFERENCES tuning_proposals(id);

-- ============================================================================
-- Tuning Test Results
-- ============================================================================

-- Tuning test results table
-- Stores validation test results for tuning proposals
CREATE TABLE IF NOT EXISTS tuning_test_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    proposal_id UUID NOT NULL REFERENCES tuning_proposals(id) ON DELETE CASCADE,
    tested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    original_alert_count BIGINT NOT NULL,
    tuned_alert_count BIGINT NOT NULL,
    reduction_percentage DOUBLE PRECISION NOT NULL,
    true_positives_preserved BOOLEAN NOT NULL,
    validation_passed BOOLEAN NOT NULL,
    comparison_metrics JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX idx_test_results_proposal ON tuning_test_results(proposal_id);
CREATE INDEX idx_test_results_tested ON tuning_test_results(tested_at DESC);

-- ============================================================================
-- Tuning Logs (Audit Trail)
-- ============================================================================

-- Tuning logs table
-- Comprehensive audit trail of all auto-tuning activities
CREATE TABLE IF NOT EXISTS tuning_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id UUID NOT NULL REFERENCES detection_rules(id) ON DELETE CASCADE,
    rule_name TEXT NOT NULL,
    triggered_at TIMESTAMPTZ NOT NULL,
    trigger_reason TEXT NOT NULL,
    proposal_id UUID REFERENCES tuning_proposals(id),
    test_results_id UUID REFERENCES tuning_test_results(id),
    applied_version_id INTEGER REFERENCES detection_rule_versions(id),
    status TEXT NOT NULL CHECK (status IN ('proposed', 'testing', 'test_passed', 'test_failed', 'staging', 'promoted', 'reverted', 'manually_approved', 'rejected')),
    reverted_at TIMESTAMPTZ,
    reverted_by UUID REFERENCES users(id),
    reverted_to_version_id INTEGER REFERENCES detection_rule_versions(id),
    revert_reason TEXT
);

CREATE INDEX idx_tuning_logs_rule ON tuning_logs(rule_id, triggered_at DESC);
CREATE INDEX idx_tuning_logs_status ON tuning_logs(status, triggered_at DESC);
CREATE INDEX idx_tuning_logs_triggered ON tuning_logs(triggered_at DESC);

-- ============================================================================
-- Tuning Notifications
-- ============================================================================

-- Tuning notifications table
-- Stores notifications for admins and detection engineers
CREATE TABLE IF NOT EXISTS tuning_notifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    notification_type TEXT NOT NULL CHECK (notification_type IN ('tuning_triggered', 'validation_complete', 'staging_deployed', 'promoted', 'reverted')),
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    link TEXT,
    tuning_log_id UUID REFERENCES tuning_logs(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    read_at TIMESTAMPTZ
);

CREATE INDEX idx_notifications_user ON tuning_notifications(user_id, created_at DESC);
CREATE INDEX idx_notifications_unread ON tuning_notifications(user_id, read_at) WHERE read_at IS NULL;
CREATE INDEX idx_notifications_type ON tuning_notifications(notification_type, created_at DESC);

-- ============================================================================
-- Rule-Specific Tuning Settings
-- ============================================================================

-- Add auto-tuning configuration columns to detection_rules table
ALTER TABLE detection_rules 
    ADD COLUMN IF NOT EXISTS auto_tuning_enabled BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN IF NOT EXISTS auto_tuning_min_confidence DOUBLE PRECISION NOT NULL DEFAULT 0.8 CHECK (auto_tuning_min_confidence >= 0.0 AND auto_tuning_min_confidence <= 1.0),
    ADD COLUMN IF NOT EXISTS auto_tuning_critical BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS auto_tuning_disabled_until TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_detection_rules_auto_tuning ON detection_rules(auto_tuning_enabled) WHERE auto_tuning_enabled = true;

-- ============================================================================
-- Comments for Documentation
-- ============================================================================

COMMENT ON TABLE detection_rule_versions IS 'Version history for detection rules, enabling audit trails and reverts';
COMMENT ON TABLE detection_rule_baselines IS 'Statistical baselines for detection rules to identify anomalous behavior';
COMMENT ON TABLE detection_rule_metrics IS 'Time-series metrics for detection rule performance monitoring';
COMMENT ON TABLE detection_threshold_breaches IS 'Records of when detection rules exceed their baseline thresholds';
COMMENT ON TABLE tuning_proposals IS 'AI-generated proposals for tuning detection rules';
COMMENT ON TABLE tuning_test_results IS 'Validation test results for tuning proposals';
COMMENT ON TABLE tuning_logs IS 'Comprehensive audit trail of all auto-tuning activities';
COMMENT ON TABLE tuning_notifications IS 'Notifications for admins and detection engineers about tuning activities';

COMMENT ON COLUMN detection_rule_versions.is_active IS 'Only one version per rule should be active at a time';
COMMENT ON COLUMN detection_rule_versions.change_reason IS 'Reason for version creation: manual_edit, auto_tuning, revert, initial_creation';
COMMENT ON COLUMN detection_rule_baselines.threshold_breach_level IS 'Calculated as mean + 2 * std_dev';
COMMENT ON COLUMN detection_threshold_breaches.consecutive_periods IS 'Number of consecutive evaluation periods the breach has persisted';
COMMENT ON COLUMN tuning_proposals.confidence_score IS 'AI confidence score from 0.0 to 1.0';
COMMENT ON COLUMN tuning_proposals.safety_validation IS 'JSON object containing safety validation results';
COMMENT ON COLUMN tuning_test_results.reduction_percentage IS 'Percentage reduction in alert volume (positive = reduction, negative = increase)';
COMMENT ON COLUMN detection_rules.auto_tuning_disabled_until IS 'Timestamp until which auto-tuning is disabled (e.g., 7 days after revert)';
