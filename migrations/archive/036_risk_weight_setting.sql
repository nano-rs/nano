-- Migration: Risk-Based Alerting - Global Risk Weight Setting
-- Requirements: 9.1
--
-- Adds global risk_weight multiplier to system_settings
-- This allows system-wide tuning of risk scores (0.0-1.0)
-- When set to 0.0, effectively disables risk scoring
-- When set to 1.0 (default), risk scores are used as-is

-- Add risk_weight column to system_settings
ALTER TABLE system_settings 
ADD COLUMN IF NOT EXISTS risk_weight NUMERIC(3,2) NOT NULL DEFAULT 1.0
CHECK (risk_weight >= 0.0 AND risk_weight <= 1.0);

-- Add comment explaining the risk_weight setting
COMMENT ON COLUMN system_settings.risk_weight IS 'Global risk score multiplier (0.0-1.0). Applied to all risk scores. Default 1.0 = no change, 0.0 = disable risk scoring';
