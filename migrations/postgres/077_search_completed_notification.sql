-- Migration: 077_search_completed_notification
-- Description: Add search_completed to notification type constraint

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
        'system'::text
    ])
);
