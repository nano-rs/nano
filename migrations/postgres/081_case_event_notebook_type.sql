-- Migration: 081_case_event_notebook_type
-- Description: Add case_event to notebook entry types for mirroring case lifecycle events

-- Add case_event to notebook entry types
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
    'user_mention'::text,
    'case_event'::text
]));
