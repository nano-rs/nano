-- Add new notebook entry types for @ commands
-- Drop the old constraint and add a new one with extended types

ALTER TABLE public.notebook_entries
DROP CONSTRAINT notebook_entries_type_check;

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
    -- @ command entry types
    'entity_reference'::text,
    'ioc_marker'::text,
    'timeline_marker'::text,
    'linked_alert'::text,
    'linked_detection'::text,
    'ai_query'::text,
    'pivot_suggestions'::text
]));

COMMENT ON COLUMN public.notebook_entries.entry_type IS 'Type of entry: manual_note, search_*, alert_*, detection_*, ai_*, entity_reference, ioc_marker, timeline_marker, linked_*, pivot_suggestions';
