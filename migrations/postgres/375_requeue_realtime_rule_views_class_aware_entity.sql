-- NAN-5271 C: re-render existing real-time rule views with the class-aware
-- OCSF entity.
--
-- A real-time rule's materialized view bakes its `risk_entity` expression into
-- the view body. Views created before NAN-5271 C use the old expression (on OCSF,
-- `src_endpoint.ip`, which is empty on every Sysmon endpoint class). They keep
-- it until the view is rendered again.
--
-- This migration changes no data and runs no DDL. It only queues one runtime
-- sync job per real-time rule that currently has a view. After the upgrade, the
-- normal per-rule sync worker (`start_rule_runtime_sync_reconciler`) claims the
-- jobs one at a time per API node (FOR UPDATE SKIP LOCKED, LIMIT 1) and runs
-- DROP then CREATE for each view. Each rule therefore has a short gap between
-- its DROP and its CREATE, during which rows inserted for that rule are not
-- matched. The gap is per rule, never for all rules at once.
--
-- Scope: real-time, not archived, with a deployed view. That matches the
-- worker's own invariant (an unarchived real-time rule has a view). Archived
-- rules are left alone: the worker would drop their view.
--
-- Idempotent and forward-only: ON CONFLICT DO NOTHING keeps any job already
-- queued (it renders with the new code anyway), and re-running inserts nothing
-- new for rules whose job is still pending. `desired_version_id` is the rule's
-- active version, or 0 when it has none (the same token
-- `enqueue_runtime_sync(rule_id, 0)` uses).
INSERT INTO detection_rule_runtime_sync_jobs (
    rule_id, desired_version_id, status, attempts,
    claimed_by, claimed_at, last_error
)
SELECT
    rule.id,
    COALESCE(
        (SELECT version.id
           FROM detection_rule_versions version
          WHERE version.rule_id = rule.id AND version.is_active = TRUE
          LIMIT 1),
        0
    ),
    'pending', 0, NULL, NULL, NULL
FROM detection_rules rule
WHERE rule.detection_mode = 'real-time'
  AND rule.archived = FALSE
  AND rule.materialized_view_name IS NOT NULL
ON CONFLICT (rule_id) DO NOTHING;
