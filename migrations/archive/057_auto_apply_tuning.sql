-- Auto-Apply Tuning Configuration
-- Adds support for fully automatic tuning proposal application

-- Add auto-apply configuration to detection_rules table
-- When enabled, high-confidence proposals are automatically applied without manual review
ALTER TABLE detection_rules
    ADD COLUMN IF NOT EXISTS auto_apply_enabled BOOLEAN NOT NULL DEFAULT false;

-- Index for rules with auto-apply enabled
CREATE INDEX IF NOT EXISTS idx_detection_rules_auto_apply ON detection_rules(auto_apply_enabled)
WHERE auto_apply_enabled = true;

-- Comments for documentation
COMMENT ON COLUMN detection_rules.auto_apply_enabled IS
'When true, tuning proposals meeting the min_confidence threshold are automatically applied without manual review. Requires auto_tuning_enabled to also be true. Use with caution.';
