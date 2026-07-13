-- NAN-1793: allow the `report_ready` in-app notification type.
--
-- A completed scheduled report notifies its owner via the in-app bell (a
-- notifications row) in addition to the outbound `report_ready` webhook. The
-- notifications table gates `notification_type` with a CHECK constraint (last
-- set in migration 094), so the new value must be admitted here.
--
-- This re-adds the constraint as a strict SUPERSET of the current allowed set:
-- it also folds in `model_deprecated` and `case_escalated`, which are inserted
-- by enterprise code (model catalog scheduler / case escalation) but were never
-- added to the CHECK — a latent gap that would reject those inserts. Widening is
-- always safe (it only admits more values), and matches the DROP/ADD pattern
-- migration 094 itself used.

ALTER TABLE notifications DROP CONSTRAINT IF EXISTS notifications_type_check;
ALTER TABLE notifications ADD CONSTRAINT notifications_type_check CHECK (
    notification_type = ANY (ARRAY[
        'case_mention'::text,
        'case_assigned'::text,
        'case_status_change'::text,
        'case_shared'::text,
        'alert_assigned'::text,
        'search_access_removed'::text,
        'case_access_removed'::text,
        'ai_provider_down'::text,
        'data_feed_stale'::text,
        'search_completed'::text,
        'search_failed'::text,
        'notebook_mention'::text,
        'tuning_triggered'::text,
        'tuning_validation_complete'::text,
        'tuning_staging_deployed'::text,
        'tuning_promoted'::text,
        'tuning_reverted'::text,
        'disk_pressure_warning'::text,
        'disk_pressure_partition_dropped'::text,
        'model_deprecated'::text,
        'case_escalated'::text,
        'report_ready'::text,
        'system'::text
    ])
);
