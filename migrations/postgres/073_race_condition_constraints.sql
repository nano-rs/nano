-- Migration: Add unique constraints to prevent race conditions
-- This migration adds unique constraints that enable atomic ON CONFLICT operations,
-- eliminating check-then-insert race conditions.

-- Add unique constraint on alerts(rule_id, event_hash) for deduplication
-- This enables atomic INSERT ON CONFLICT for alert deduplication
-- Note: We use a partial unique index to handle NULL event_hash values
CREATE UNIQUE INDEX IF NOT EXISTS alerts_rule_event_hash_unique
ON alerts (rule_id, event_hash)
WHERE event_hash IS NOT NULL;

-- Add a comment explaining the constraint
COMMENT ON INDEX alerts_rule_event_hash_unique IS
    'Unique constraint for alert deduplication - enables atomic ON CONFLICT for race-condition-safe inserts';
