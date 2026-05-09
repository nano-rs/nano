-- Add lookback_minutes field to detection_rules table
-- This allows each rule to specify its own lookback period for scheduled execution
-- Especially useful for prevalence-based detections that need longer lookback windows

ALTER TABLE detection_rules 
ADD COLUMN lookback_minutes INTEGER;

-- Add comment explaining the field
COMMENT ON COLUMN detection_rules.lookback_minutes IS 'Custom lookback period in minutes for this rule. If NULL, uses the default from scheduler config. Useful for prevalence-based detections that need longer lookback windows (e.g., 1440 for 24 hours).';

-- Update existing rules to NULL (will use default)
-- No need to set values as NULL is the default
