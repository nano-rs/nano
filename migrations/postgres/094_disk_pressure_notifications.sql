-- Migration: 094_disk_pressure_notifications
-- Description: Add disk pressure notification types to constraint

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
        'system'::text
    ])
);
