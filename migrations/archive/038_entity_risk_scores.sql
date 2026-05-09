-- Migration: Entity Risk Scores Table
-- Stores aggregated risk scores per entity for analytics
--
-- This table maintains running totals of risk scores for entities,
-- enabling fast queries for the Risk Analytics dashboard.

-- Entity risk scores table
CREATE TABLE IF NOT EXISTS entity_risk_scores (
    id SERIAL PRIMARY KEY,
    entity TEXT NOT NULL,
    entity_type TEXT NOT NULL DEFAULT 'unknown', -- src_ip, user, hostname, etc.
    risk_score INTEGER NOT NULL DEFAULT 0,
    signal_count INTEGER NOT NULL DEFAULT 0,
    last_signal_at TIMESTAMPTZ,
    first_signal_at TIMESTAMPTZ,
    last_rule_name TEXT,
    last_severity TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(entity, entity_type)
);

-- Index for fast lookups by entity
CREATE INDEX IF NOT EXISTS idx_entity_risk_scores_entity ON entity_risk_scores(entity);

-- Index for sorting by risk score
CREATE INDEX IF NOT EXISTS idx_entity_risk_scores_score ON entity_risk_scores(risk_score DESC);

-- Index for time-based queries
CREATE INDEX IF NOT EXISTS idx_entity_risk_scores_updated ON entity_risk_scores(updated_at DESC);

-- Index for entity type filtering
CREATE INDEX IF NOT EXISTS idx_entity_risk_scores_type ON entity_risk_scores(entity_type);

-- Comments
COMMENT ON TABLE entity_risk_scores IS 'Aggregated risk scores per entity for risk analytics dashboard';
COMMENT ON COLUMN entity_risk_scores.entity IS 'The entity identifier (IP, username, hostname, etc.)';
COMMENT ON COLUMN entity_risk_scores.entity_type IS 'Type of entity: src_ip, user, hostname, etc.';
COMMENT ON COLUMN entity_risk_scores.risk_score IS 'Cumulative risk score for this entity';
COMMENT ON COLUMN entity_risk_scores.signal_count IS 'Number of signals contributing to the score';
COMMENT ON COLUMN entity_risk_scores.last_signal_at IS 'Timestamp of the most recent signal';
COMMENT ON COLUMN entity_risk_scores.first_signal_at IS 'Timestamp of the first signal';
COMMENT ON COLUMN entity_risk_scores.last_rule_name IS 'Name of the most recent detection rule that fired';
COMMENT ON COLUMN entity_risk_scores.last_severity IS 'Severity of the most recent detection';
