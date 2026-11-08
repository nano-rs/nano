-- Performance Optimization for AI Detection Auto-Tuning
-- Task 23.1: Optimize database queries
-- Requirements: 1.1, 1.4

-- ============================================================================
-- Additional Indexes for Metrics Collection
-- ============================================================================

-- Composite index for metrics collection queries (rule + time range)
CREATE INDEX IF NOT EXISTS idx_metrics_rule_time_composite 
    ON detection_rule_metrics(rule_id, timestamp DESC, alert_count_1h);

-- Index for time-based queries across all rules
CREATE INDEX IF NOT EXISTS idx_metrics_timestamp_rule 
    ON detection_rule_metrics(timestamp DESC, rule_id);

-- ============================================================================
-- Indexes for Baseline Calculations
-- ============================================================================

-- Index for baseline calculation window queries
CREATE INDEX IF NOT EXISTS idx_metrics_baseline_window 
    ON detection_rule_metrics(rule_id, timestamp) 
    WHERE timestamp >= NOW() - INTERVAL '30 days';

-- Index for baseline establishment checks
CREATE INDEX IF NOT EXISTS idx_metrics_oldest_timestamp 
    ON detection_rule_metrics(rule_id, timestamp ASC);

-- ============================================================================
-- Indexes for Threshold Detection
-- ============================================================================

-- Composite index for breach detection queries
CREATE INDEX IF NOT EXISTS idx_breaches_rule_triggered 
    ON detection_threshold_breaches(rule_id, tuning_triggered, detected_at DESC);

-- Index for finding recent breaches
CREATE INDEX IF NOT EXISTS idx_breaches_recent 
    ON detection_threshold_breaches(detected_at DESC) 
    WHERE tuning_triggered = false;

-- ============================================================================
-- Indexes for Proposal and Test Results
-- ============================================================================

-- Index for finding pending proposals
CREATE INDEX IF NOT EXISTS idx_proposals_pending 
    ON tuning_proposals(status, created_at DESC) 
    WHERE status IN ('proposed', 'testing');

-- Index for proposal confidence filtering
CREATE INDEX IF NOT EXISTS idx_proposals_confidence 
    ON tuning_proposals(rule_id, confidence_score DESC, created_at DESC);

-- Composite index for test results queries
CREATE INDEX IF NOT EXISTS idx_test_results_validation 
    ON tuning_test_results(proposal_id, validation_passed, tested_at DESC);

-- ============================================================================
-- Indexes for Notification Queries
-- ============================================================================

-- Composite index for user notifications
CREATE INDEX IF NOT EXISTS idx_notifications_user_unread 
    ON tuning_notifications(user_id, created_at DESC) 
    WHERE read_at IS NULL;

-- Index for notification type filtering
CREATE INDEX IF NOT EXISTS idx_notifications_type_unread 
    ON tuning_notifications(notification_type, user_id, created_at DESC) 
    WHERE read_at IS NULL;

-- ============================================================================
-- Indexes for Version Management
-- ============================================================================

-- Index for finding active versions quickly
CREATE INDEX IF NOT EXISTS idx_versions_active_lookup 
    ON detection_rule_versions(rule_id) 
    WHERE is_active = true;

-- Index for version history queries
CREATE INDEX IF NOT EXISTS idx_versions_history 
    ON detection_rule_versions(rule_id, created_at DESC, version_number DESC);

-- ============================================================================
-- Indexes for Audit Log Queries
-- ============================================================================

-- Composite index for rule-specific log queries
CREATE INDEX IF NOT EXISTS idx_tuning_logs_rule_status 
    ON tuning_logs(rule_id, status, triggered_at DESC);

-- Index for dashboard queries (recent activity)
CREATE INDEX IF NOT EXISTS idx_tuning_logs_recent_activity 
    ON tuning_logs(triggered_at DESC, status);

-- Index for finding logs by proposal
CREATE INDEX IF NOT EXISTS idx_tuning_logs_proposal 
    ON tuning_logs(proposal_id, triggered_at DESC);

-- ============================================================================
-- Indexes for Rule Configuration
-- ============================================================================

-- Index for finding auto-tuning enabled rules
CREATE INDEX IF NOT EXISTS idx_detection_rules_tuning_enabled 
    ON detection_rules(id, auto_tuning_enabled, auto_tuning_disabled_until) 
    WHERE auto_tuning_enabled = true AND enabled = true;

-- Index for critical rules
CREATE INDEX IF NOT EXISTS idx_detection_rules_critical 
    ON detection_rules(id) 
    WHERE auto_tuning_critical = true;

-- ============================================================================
-- Partial Indexes for Common Filters
-- ============================================================================

-- Index for rules with active auto-tuning
CREATE INDEX IF NOT EXISTS idx_detection_rules_active_tuning 
    ON detection_rules(id, auto_tuning_min_confidence) 
    WHERE auto_tuning_enabled = true 
      AND enabled = true 
      AND (auto_tuning_disabled_until IS NULL OR auto_tuning_disabled_until < NOW());

-- Index for high-confidence proposals
CREATE INDEX IF NOT EXISTS idx_proposals_high_confidence 
    ON tuning_proposals(rule_id, created_at DESC) 
    WHERE confidence_score >= 0.9 AND status = 'proposed';

-- ============================================================================
-- Statistics Updates
-- ============================================================================

-- Update table statistics for better query planning
ANALYZE detection_rule_metrics;
ANALYZE detection_rule_baselines;
ANALYZE detection_threshold_breaches;
ANALYZE tuning_proposals;
ANALYZE tuning_test_results;
ANALYZE tuning_logs;
ANALYZE tuning_notifications;
ANALYZE detection_rule_versions;

-- ============================================================================
-- Comments
-- ============================================================================

COMMENT ON INDEX idx_metrics_rule_time_composite IS 'Optimizes metrics collection queries by rule and time range';
COMMENT ON INDEX idx_metrics_baseline_window IS 'Optimizes baseline calculation queries using 30-day rolling window';
COMMENT ON INDEX idx_breaches_rule_triggered IS 'Optimizes breach detection and tuning trigger queries';
COMMENT ON INDEX idx_proposals_pending IS 'Optimizes queries for pending proposals requiring review';
COMMENT ON INDEX idx_notifications_user_unread IS 'Optimizes unread notification queries for users';
COMMENT ON INDEX idx_versions_active_lookup IS 'Optimizes active version lookups for rules';
COMMENT ON INDEX idx_tuning_logs_recent_activity IS 'Optimizes dashboard queries for recent tuning activity';
COMMENT ON INDEX idx_detection_rules_active_tuning IS 'Optimizes queries for rules eligible for auto-tuning';

