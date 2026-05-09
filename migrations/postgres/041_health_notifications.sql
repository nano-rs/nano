-- Migration: 041_health_notifications
-- Description: Add health monitoring notification types and feed staleness config

-- Add new notification types to constraint
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
        'system'::text
    ])
);

-- Feed staleness config columns
ALTER TABLE feeds ADD COLUMN IF NOT EXISTS stale_alert_enabled BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE feeds ADD COLUMN IF NOT EXISTS stale_threshold_minutes INTEGER NOT NULL DEFAULT 15;

-- Track active health issues (prevents duplicate notifications)
CREATE TABLE IF NOT EXISTS health_issue_tracker (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    issue_type VARCHAR(50) NOT NULL,  -- 'ai_provider' or 'data_feed'
    issue_key VARCHAR(255) NOT NULL,  -- provider name or feed_id
    first_detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,
    notification_sent BOOLEAN DEFAULT false,
    UNIQUE(issue_type, issue_key)
);

-- Index for finding active (unresolved) issues
CREATE INDEX IF NOT EXISTS idx_health_issue_active
ON health_issue_tracker(issue_type, issue_key)
WHERE resolved_at IS NULL;
