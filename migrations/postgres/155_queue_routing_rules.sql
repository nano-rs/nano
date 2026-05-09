-- NAN-427: Queue routing rules — auto-route newly-created cases to a queue.
--
-- On case create, when the case has no explicit `assigned_group`, we walk
-- enabled rules in ascending `priority` order and pick the first whose
-- `conditions` match the case's source_types / severity / rule_ids / tags.
-- The matched rule's `queue_id` resolves to `queues.group_id`, which is
-- stamped onto `cases.assigned_group` so the case lands in that queue.
--
-- A catch-all rule with empty conditions is seeded so unmatched cases land
-- in the Triage queue (separate from the queues table's `is_default_landing`
-- flag, which is a deployment-level fallback for when the routing rules
-- table is wiped).

BEGIN;

-- =============================================================================
-- queue_routing_rules table
-- =============================================================================

CREATE TABLE IF NOT EXISTS public.queue_routing_rules (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name text NOT NULL,
    enabled boolean NOT NULL DEFAULT true,
    priority integer NOT NULL DEFAULT 100,
    queue_id uuid NOT NULL,
    conditions jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT queue_routing_rules_pkey PRIMARY KEY (id),
    CONSTRAINT queue_routing_rules_queue_fkey FOREIGN KEY (queue_id)
        REFERENCES public.queues(id) ON DELETE CASCADE
);

-- Composite index for the hot path: evaluator walks enabled rules ordered
-- by priority ascending.
CREATE INDEX IF NOT EXISTS idx_queue_routing_rules_priority
    ON public.queue_routing_rules(enabled, priority);

-- updated_at trigger, same pattern as queues.
CREATE OR REPLACE FUNCTION public.queue_routing_rules_set_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS queue_routing_rules_set_updated_at
    ON public.queue_routing_rules;
CREATE TRIGGER queue_routing_rules_set_updated_at
    BEFORE UPDATE ON public.queue_routing_rules
    FOR EACH ROW
    EXECUTE FUNCTION public.queue_routing_rules_set_updated_at();

COMMENT ON TABLE public.queue_routing_rules IS
    'Rules evaluated on case create to auto-stamp cases.assigned_group. Ordered by priority ASC.';
COMMENT ON COLUMN public.queue_routing_rules.conditions IS
    'JSON shape: {source_type?: string[], severity?: string[], rule_id?: string[], tags?: string[], group_by_hash_prefix?: string}. AND across keys, OR within each key''s array. Empty object = fallthrough catch-all.';

-- =============================================================================
-- Seed example rules (idempotent)
-- =============================================================================

-- 1. High-severity CloudTrail events route to Tier 2 Investigation.
INSERT INTO public.queue_routing_rules (name, enabled, priority, queue_id, conditions)
SELECT
    'CloudTrail high-severity to Tier 2',
    true,
    10,
    q.id,
    jsonb_build_object(
        'source_type', jsonb_build_array('aws_cloudtrail'),
        'severity',    jsonb_build_array('high', 'critical')
    )
FROM public.queues q
WHERE q.kind = 'tier2'
  AND NOT EXISTS (
      SELECT 1 FROM public.queue_routing_rules
       WHERE name = 'CloudTrail high-severity to Tier 2'
  )
LIMIT 1;

-- 2. Catch-all fallthrough into Triage. Empty conditions = always matches.
INSERT INTO public.queue_routing_rules (name, enabled, priority, queue_id, conditions)
SELECT
    'Fallthrough to Triage',
    true,
    10000,
    q.id,
    '{}'::jsonb
FROM public.queues q
WHERE q.kind = 'triage'
  AND NOT EXISTS (
      SELECT 1 FROM public.queue_routing_rules
       WHERE name = 'Fallthrough to Triage'
  )
LIMIT 1;

-- =============================================================================
-- Extend case_workflow_events.event_kind to accept 'routed'
-- =============================================================================
--
-- The auto-routing integration in `create_case` records a `routed` workflow
-- event so the workflow audit spine captures "which rule fired + which queue
-- the case landed in." 152's CHECK constraint predates queues — widen it.

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
        'routed'::text
    ]));

COMMIT;
