-- Migration: Risk-Based Alerting - Detection Rule Risk Fields
-- Requirements: 1.1, 1.4, 8.1
--
-- Adds risk scoring configuration to detection rules:
-- - risk_score: Base risk score (0-100) for the rule
-- - risk_entity_field: UDM field to extract entity from (e.g., src_ip, user, src_host)
-- - risk_modifiers: Conditional score adjustments based on field conditions

-- Add risk_score column (0-100, nullable - defaults based on severity if not set)
ALTER TABLE detection_rules 
ADD COLUMN IF NOT EXISTS risk_score INTEGER 
CHECK (risk_score >= 0 AND risk_score <= 100);

-- Add risk_entity_field column (UDM field name for entity extraction)
-- Common values: src_ip, user, src_host, dest_ip, dest_host
-- If NULL, system will infer from src_ip -> user -> src_host in order
ALTER TABLE detection_rules 
ADD COLUMN IF NOT EXISTS risk_entity_field TEXT;

-- Add risk_modifiers column (JSONB array of conditional score adjustments)
-- Format: [{"condition": "count > 10", "score": 75}, ...]
ALTER TABLE detection_rules 
ADD COLUMN IF NOT EXISTS risk_modifiers JSONB DEFAULT '[]';

-- Add comment explaining the risk fields
COMMENT ON COLUMN detection_rules.risk_score IS 'Base risk score (0-100). If NULL, defaults based on severity: Critical=90, High=70, Medium=50, Low=30, Informational=10';
COMMENT ON COLUMN detection_rules.risk_entity_field IS 'UDM field to extract risk entity from (e.g., src_ip, user, src_host). If NULL, infers from src_ip -> user -> src_host';
COMMENT ON COLUMN detection_rules.risk_modifiers IS 'JSON array of conditional score modifiers: [{"condition": "expr", "score": N}, ...]';
