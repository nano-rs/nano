-- Add AI chat entry types to notebook_entries
-- These enable interactive AI conversations within notebooks

-- Drop and recreate the entry type check constraint to include new AI chat types
ALTER TABLE notebook_entries DROP CONSTRAINT IF EXISTS notebook_entries_type_check;

ALTER TABLE notebook_entries ADD CONSTRAINT notebook_entries_type_check CHECK (
    entry_type IN (
        -- Existing types
        'manual_note',
        'search_executed',
        'search_refined',
        'alert_viewed',
        'alert_actioned',
        'detection_viewed',
        'detection_modified',
        'ai_suggestion',
        'ai_summary',
        'entity_reference',
        'ioc_marker',
        'timeline_marker',
        'linked_alert',
        'linked_detection',
        'ai_query',
        'pivot_suggestions',
        'user_mention',
        'case_event',
        -- New AI chat types (NAN-48)
        'ai_chat_message',
        'ai_chat_response',
        'ai_search_result'
    )
);
