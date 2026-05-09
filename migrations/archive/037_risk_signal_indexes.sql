-- Migration: Risk-Based Alerting - Signal Risk Indexes
-- Requirements: 3.4, 4.2
--
-- Adds indexes for efficient risk score queries on signals:
-- - Index on risk_score for filtering by score ranges (e.g., risk_score > 50)
-- - Index on risk_entity for grouping/aggregating by entity
--
-- These enable fast cumulative risk queries like:
--   source_type=signals | stats sum(risk_score) by risk_entity | where total > 100

-- Index for risk_score filtering on signals (as text, cast at query time)
-- Enables queries like: source_type=signals risk_score > 50
CREATE INDEX IF NOT EXISTS idx_logs_signals_risk_score 
ON logs ((metadata->>'risk_score'), timestamp DESC) 
WHERE source_type = 'signals';

-- Index for risk_entity grouping on signals
-- Enables queries like: source_type=signals | stats sum(risk_score) by risk_entity
CREATE INDEX IF NOT EXISTS idx_logs_signals_risk_entity 
ON logs ((metadata->>'risk_entity'), timestamp DESC) 
WHERE source_type = 'signals';
