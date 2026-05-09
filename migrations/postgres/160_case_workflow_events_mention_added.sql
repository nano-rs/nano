-- NAN-479: First-class @mention thread events.
--
-- The Thread composer (notebook entries on case-bound notebooks) writes
-- mentions as plain text today. To surface a "Sam joined · via @mention by
-- Lia" system row in the thread, we add a new workflow-event kind
-- 'mention_added' and a partial unique index so the first mention of a given
-- user on a given case wins (subsequent mentions still notify, but don't
-- re-emit the system row).

BEGIN;

-- Allow 'mention_added' as a valid event_kind.
ALTER TABLE public.case_workflow_events
    DROP CONSTRAINT IF EXISTS case_workflow_events_kind_check;

ALTER TABLE public.case_workflow_events
    ADD CONSTRAINT case_workflow_events_kind_check
    CHECK (event_kind = ANY (ARRAY[
        'status_changed'::text,
        'pending_set'::text,
        'pending_cleared'::text,
        'escalated'::text,
        'closed'::text,
        'reopened'::text,
        'handoff_sent'::text,
        'handoff_accepted'::text,
        'handoff_bounced'::text,
        'handoff_canceled'::text,
        'mention_added'::text
    ]));

-- Idempotency guard: at most one 'mention_added' row per (case, mentioned user).
-- Mentions land via INSERT ... ON CONFLICT DO NOTHING in the repo; this index
-- is the conflict target.
CREATE UNIQUE INDEX IF NOT EXISTS idx_case_workflow_events_mention_unique
    ON public.case_workflow_events(case_id, ((metadata->>'mentioned_user_id')))
    WHERE event_kind = 'mention_added';

COMMIT;
