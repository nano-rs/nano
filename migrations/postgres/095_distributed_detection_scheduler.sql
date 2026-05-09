-- Distributed detection scheduler: add scheduling columns for SKIP LOCKED claiming
--
-- Moves detection rule scheduling from in-memory (single leader) to database-driven
-- (all nodes compete via SELECT FOR UPDATE SKIP LOCKED).

-- Persists the next execution time (was previously in-memory only)
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS next_run_at TIMESTAMPTZ;

-- Node ID currently executing this rule (NULL = available for claiming)
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS claimed_by TEXT;

-- When the rule was claimed (for stale claim recovery)
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS claimed_at TIMESTAMPTZ;

-- Partial index for the hot-path claiming query (SKIP LOCKED)
-- Only indexes unclaimed, enabled, non-staging scheduled rules with a due time
CREATE INDEX IF NOT EXISTS idx_detection_rules_skip_locked
  ON detection_rules (next_run_at ASC)
  WHERE enabled = true AND archived = false
    AND detection_mode = 'scheduled' AND mode != 'staging'
    AND claimed_by IS NULL AND next_run_at IS NOT NULL;

-- Index for stale claim recovery (find rules stuck in claimed state)
CREATE INDEX IF NOT EXISTS idx_detection_rules_stale_claims
  ON detection_rules (claimed_at ASC)
  WHERE claimed_by IS NOT NULL AND claimed_at IS NOT NULL;

-- Backfill next_run_at for existing enabled scheduled rules
-- Uses last_run_at + 60s as approximation, or NOW() for rules that haven't run yet
UPDATE detection_rules
SET next_run_at = COALESCE(last_run_at + INTERVAL '60 seconds', NOW())
WHERE enabled = true AND archived = false
  AND detection_mode = 'scheduled' AND mode != 'staging'
  AND schedule_cron IS NOT NULL AND next_run_at IS NULL;
