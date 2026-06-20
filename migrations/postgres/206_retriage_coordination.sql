-- Cross-pod re-triage debounce coordination (NAN-1492)
--
-- Phase 4 of agent-runtime hardening moves the per-pod
-- Arc<Mutex<HashMap<Uuid, PendingRetriage>>> debounce in the shadow
-- investigation service into a Postgres coordination row — one row per case —
-- so a multi-replica deployment coalesces a burst of alert-adds into exactly
-- ONE re-triage instead of one per pod that happens to receive an add.
--
-- The row carries:
--   * next_eligible_at  — the moving "fire_at" instant (30s coalesce window,
--                          extended on each add but never past window_deadline)
--   * window_deadline   — the 300s ceiling set on the first add and never moved
--   * pending_alert_ids — accumulated triggering alert ids (breadcrumb only,
--                          clamped to 500 in the register UPSERT)
--   * pending_count     — running count of alerts folded into this window
--
-- The firer-claim is claim-BY-DELETE: a single `DELETE ... WHERE
-- next_eligible_at <= NOW() ... FOR UPDATE SKIP LOCKED RETURNING ...` statement
-- both wins the window and removes the row, so exactly one pod runs the
-- coalesced re-triage with NO separate "claimed" state to track (NAN-1488). The
-- earlier design carried `claimed_by`/`claimed_at` stale-claim columns for a
-- claim-then-delete flow; those were never written by any code path and are
-- omitted here.
--
-- The actual register/extend (UPSERT) and claim-when-due DML lives in Rust
-- (coordination.rs) with bound parameters; this migration only provisions the
-- table + poll index. ON DELETE CASCADE on case_id means a deleted case
-- auto-cleans its coordination row (matches the shadow_investigations FK).
CREATE TABLE IF NOT EXISTS retriage_coordination (
  case_id           UUID PRIMARY KEY REFERENCES cases(id) ON DELETE CASCADE,
  next_eligible_at  TIMESTAMPTZ NOT NULL,
  window_deadline   TIMESTAMPTZ NOT NULL,
  pending_alert_ids UUID[]      NOT NULL DEFAULT '{}',
  pending_count     INTEGER     NOT NULL DEFAULT 0,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Poll index for the firer claim: rows fire in next_eligible_at order.
CREATE INDEX IF NOT EXISTS idx_retriage_coord_due
  ON retriage_coordination (next_eligible_at);
