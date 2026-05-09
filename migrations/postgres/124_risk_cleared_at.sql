-- Add cleared_at to entity_risk_scores so clearing an entity's risk
-- excludes it from time-windowed ClickHouse queries until new findings arrive.
ALTER TABLE entity_risk_scores ADD COLUMN IF NOT EXISTS cleared_at TIMESTAMPTZ;
