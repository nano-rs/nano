-- Migration: 080_notebook_mention_notification
-- Description: Add user_mention to notebook_entries and notebook_mention to notifications

-- Add user_mention to notebook entry types
ALTER TABLE public.notebook_entries
DROP CONSTRAINT IF EXISTS notebook_entries_type_check;

ALTER TABLE public.notebook_entries
ADD CONSTRAINT notebook_entries_type_check CHECK (entry_type = ANY (ARRAY[
    'manual_note'::text,
    'search_executed'::text,
    'search_refined'::text,
    'alert_viewed'::text,
    'alert_actioned'::text,
    'detection_viewed'::text,
    'detection_modified'::text,
    'ai_suggestion'::text,
    'ai_summary'::text,
    'entity_reference'::text,
    'ioc_marker'::text,
    'timeline_marker'::text,
    'linked_alert'::text,
    'linked_detection'::text,
    'ai_query'::text,
    'pivot_suggestions'::text,
    'user_mention'::text
]));

-- Add notebook_mention to notification types
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
        'system'::text
    ])
);
