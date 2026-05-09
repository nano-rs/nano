-- Case Management Global Settings
-- Adds configurable settings for case auto-grouping behavior

-- =============================================================================
-- ADD CASE SETTINGS TO SYSTEM_SETTINGS TABLE
-- =============================================================================

-- Global default for max alerts per case (1-1000)
ALTER TABLE public.system_settings
ADD COLUMN IF NOT EXISTS case_max_alerts_per_case integer DEFAULT 100 NOT NULL;

ALTER TABLE public.system_settings
ADD CONSTRAINT system_settings_case_max_alerts_check
CHECK (case_max_alerts_per_case >= 1 AND case_max_alerts_per_case <= 1000);

-- Global default time window for grouping in minutes (1-4320, i.e., up to 3 days)
ALTER TABLE public.system_settings
ADD COLUMN IF NOT EXISTS case_default_time_window_minutes integer DEFAULT 60 NOT NULL;

ALTER TABLE public.system_settings
ADD CONSTRAINT system_settings_case_time_window_check
CHECK (case_default_time_window_minutes >= 1 AND case_default_time_window_minutes <= 4320);

-- Whether auto-grouping is enabled globally
ALTER TABLE public.system_settings
ADD COLUMN IF NOT EXISTS case_auto_grouping_enabled boolean DEFAULT true NOT NULL;

-- Update case_grouping_rules max_alerts constraint to allow up to 1000
ALTER TABLE public.case_grouping_rules
DROP CONSTRAINT IF EXISTS case_grouping_rules_max_alerts_check;

ALTER TABLE public.case_grouping_rules
ADD CONSTRAINT case_grouping_rules_max_alerts_check
CHECK (max_alerts >= 1 AND max_alerts <= 1000);

-- Update case_grouping_rules time_window_minutes constraint to allow up to 3 days (4320 minutes)
ALTER TABLE public.case_grouping_rules
DROP CONSTRAINT IF EXISTS case_grouping_rules_time_window_check;

ALTER TABLE public.case_grouping_rules
ADD CONSTRAINT case_grouping_rules_time_window_check
CHECK (time_window_minutes >= 1 AND time_window_minutes <= 4320);

-- =============================================================================
-- COMMENTS
-- =============================================================================
COMMENT ON COLUMN public.system_settings.case_max_alerts_per_case IS 'Global default for maximum alerts per case before creating a new case (1-1000)';
COMMENT ON COLUMN public.system_settings.case_default_time_window_minutes IS 'Global default time window for grouping alerts into cases in minutes (1-4320, up to 3 days)';
COMMENT ON COLUMN public.system_settings.case_auto_grouping_enabled IS 'Whether automatic alert-to-case grouping is enabled globally';
