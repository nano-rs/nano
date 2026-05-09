-- NAN-462 — Playbook run_context snapshot
--
-- Adds a JSONB column to `playbook_runs` that captures a frozen snapshot of
-- the triggering case/alert/rule/entities/top_matched_event at the moment
-- the playbook attached. The templating engine in `nanosiem-core/src/
-- playbooks/runtime.rs` resolves `{{...}}` tokens in the stored playbook
-- doc against this snapshot at read time (so re-runs on a different case
-- resolve independently and late-run re-evaluations don't drift as the
-- live case picks up more entities).
--
-- Null for rows created before this migration, or from manual-attach paths
-- that don't have alert context. Resolution degrades gracefully: missing
-- tokens render as the empty string rather than aborting the render.

ALTER TABLE playbook_runs
    ADD COLUMN IF NOT EXISTS run_context JSONB;

COMMENT ON COLUMN playbook_runs.run_context IS
    'Frozen snapshot of {case, alert, rule, source_type, top_matched_event, entities} captured at create_run time. Templating engine resolves {{...}} tokens against this.';
