-- Distributed scheduled jobs: add claiming columns for SKIP LOCKED
--
-- Moves scheduled job execution from single-leader to distributed claiming.

-- Node ID currently executing this job (NULL = available for claiming)
ALTER TABLE scheduled_jobs ADD COLUMN IF NOT EXISTS claimed_by TEXT;

-- When the job was claimed (for stale claim recovery)
ALTER TABLE scheduled_jobs ADD COLUMN IF NOT EXISTS claimed_at TIMESTAMPTZ;

-- Partial index for the hot-path claiming query (SKIP LOCKED)
CREATE INDEX IF NOT EXISTS idx_scheduled_jobs_skip_locked
  ON scheduled_jobs (next_run_at ASC)
  WHERE enabled = true AND claimed_by IS NULL
    AND next_run_at IS NOT NULL;
