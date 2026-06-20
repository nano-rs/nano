-- Shadow Investigation Checkpointing (NAN-1490)
--
-- Phase 2 of agent-runtime hardening: make the shadow-investigation pipeline
-- resumable across a pod restart / mid-pipeline LLM timeout. Each completed
-- durable step writes a checkpoint row carrying the in-memory accumulators
-- (findings, counters, derived context) needed to rehydrate and skip already-
-- written steps on resume. The composite PK (investigation_id, step) is the
-- idempotency key — re-running a completed step is a no-op via
-- ON CONFLICT DO NOTHING.

-- `step_ordinal` (NAN-1488) is the deterministic execution-order rank (0..=13)
-- of `step`. `load_latest_checkpoint` orders by it FIRST (then created_at) so a
-- pair of fast step commits sharing the same microsecond `created_at` can't
-- surface an older payload — ordering by timestamp alone was non-deterministic
-- on a tie. Mirrors `Step::ordinal()` in checkpoint.rs.
CREATE TABLE IF NOT EXISTS shadow_investigation_checkpoints (
  investigation_id UUID NOT NULL REFERENCES shadow_investigations(id) ON DELETE CASCADE,
  step TEXT NOT NULL,
  step_ordinal INTEGER NOT NULL DEFAULT 0,
  payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (investigation_id, step)
);

CREATE INDEX IF NOT EXISTS idx_shadow_inv_ckpt_inv
  ON shadow_investigation_checkpoints(investigation_id, created_at);

-- Add 'interrupted' to the shadow_investigations status CHECK so the startup
-- reaper can mark orphaned 'running' rows (whose owning tokio task died with
-- the process) as interruption-rather-than-failure. A CHECK cannot be ALTERed
-- in place — drop and re-add. The constraint is auto-named
-- `shadow_investigations_status_check` (created inline in 078); guard the DROP
-- so the migration is idempotent if the constraint is absent for any reason.
DO $$
BEGIN
  ALTER TABLE shadow_investigations DROP CONSTRAINT shadow_investigations_status_check;
EXCEPTION
  WHEN undefined_object THEN NULL;
END $$;

-- Guard the ADD too (NAN-1488): if a prior partial run already re-added the
-- constraint (the DROP above succeeded but a later statement failed), a re-run
-- would otherwise abort with duplicate_object. Catch it so the migration is
-- idempotent end-to-end.
DO $$
BEGIN
  ALTER TABLE shadow_investigations
    ADD CONSTRAINT shadow_investigations_status_check
    CHECK (status IN ('pending','running','completed','failed','throttled','interrupted'));
EXCEPTION
  WHEN duplicate_object THEN NULL;
END $$;

-- Resume-attempt counter (NAN-1488). The boot resume sweep re-attempts both
-- freshly-reaped AND pre-existing `interrupted` rows; this bounds retries on a
-- deterministically-crashing step. The atomic claim (`claim_for_resume`)
-- increments it on each `interrupted -> running` transition and promotes a row
-- to `failed` ('exceeded resume attempts') once it exceeds the cap (3) instead
-- of resuming again.
ALTER TABLE shadow_investigations
  ADD COLUMN IF NOT EXISTS resume_attempts INTEGER NOT NULL DEFAULT 0;

-- Covering index for `find_resumable_investigation` (NAN-1488). The existing
-- partial `idx_shadow_inv_status` is scoped WHERE status IN ('pending','running')
-- and does not cover the `status = 'interrupted'` lookup keyed by
-- (case_id, alert_id). This index serves both that lookup and the boot sweep's
-- interrupted scan.
CREATE INDEX IF NOT EXISTS idx_shadow_inv_resumable
  ON shadow_investigations(case_id, alert_id, status, created_at);
