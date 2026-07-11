-- NAN-1781: fence distributed scheduled-job execution across reclaim/failover.
--
-- A run id survives stale-lease reclaims so append ingestion can derive stable
-- row identities. The monotonically increasing generation fences stale workers
-- at lease-renewal, side-effect, and completion boundaries.

ALTER TABLE scheduled_jobs
    ADD COLUMN IF NOT EXISTS claim_generation BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS claim_run_id UUID;

CREATE INDEX IF NOT EXISTS idx_scheduled_jobs_claim_owner_generation
    ON scheduled_jobs (id, claimed_by, claim_generation)
    WHERE claimed_by IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_scheduled_jobs_stale_claim
    ON scheduled_jobs (claimed_at)
    WHERE claimed_by IS NOT NULL;
