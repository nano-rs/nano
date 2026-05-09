-- NAN-426: Queues — triage/tier structure for case routing.
--
-- A "queue" is a thin wrapper around an existing group: the group owns the
-- membership (who's on this queue), the queue row carries queue-specific
-- metadata (kind, SLA tier, Slack channel, routing priority, icon/color,
-- description). That lets us reuse `cases.assigned_group` as the authority
-- for "what queue is this case in" without introducing a parallel concept.
--
-- The four canonical queues (Triage, Tier 1 SOC, Tier 2 Investigation,
-- Tier 3 IR / Forensics) are seeded at migration time. Admins can add
-- Specialty queues after the fact; the backing groups for the four canonical
-- queues are `is_system=true` so they can't be deleted through the admin UI.

BEGIN;

-- =============================================================================
-- queues table
-- =============================================================================

CREATE TABLE IF NOT EXISTS public.queues (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    group_id uuid NOT NULL,
    kind text NOT NULL,
    default_sla_tier text,
    slack_channel text,
    routing_priority integer NOT NULL DEFAULT 100,
    icon text,
    color text,
    is_default_landing boolean NOT NULL DEFAULT false,
    description text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT queues_pkey PRIMARY KEY (id),
    CONSTRAINT queues_group_id_fkey FOREIGN KEY (group_id)
        REFERENCES public.groups(id) ON DELETE CASCADE,
    CONSTRAINT queues_group_id_key UNIQUE (group_id),
    CONSTRAINT queues_kind_check CHECK (kind IN (
        'triage', 'tier1', 'tier2', 'tier3', 'specialty'
    ))
);

CREATE INDEX IF NOT EXISTS idx_queues_kind
    ON public.queues(kind);

-- Partial unique: at most one queue can be the "default landing" queue that
-- new cases flow into when no routing rule matches. NULL/false rows don't
-- participate in the uniqueness check.
CREATE UNIQUE INDEX IF NOT EXISTS idx_queues_default_landing
    ON public.queues(is_default_landing)
    WHERE is_default_landing;

-- updated_at trigger: mirror the convention used by migration 152
-- (case_workflow_schema) so edits bump the timestamp automatically.
CREATE OR REPLACE FUNCTION public.queues_set_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS queues_set_updated_at ON public.queues;
CREATE TRIGGER queues_set_updated_at
    BEFORE UPDATE ON public.queues
    FOR EACH ROW
    EXECUTE FUNCTION public.queues_set_updated_at();

COMMENT ON TABLE public.queues IS
    'SOC work queues (Triage, Tier 1, Tier 2, Tier 3, Specialty). Thin wrapper over groups — membership lives on user_groups.';
COMMENT ON COLUMN public.queues.group_id IS
    'The group whose members are "on" this queue. 1:1 with queues.id.';
COMMENT ON COLUMN public.queues.is_default_landing IS
    'True on the single queue that catches unrouted cases. Partial unique index enforces singleton.';

-- =============================================================================
-- Seed the four canonical queues
-- =============================================================================
--
-- Each queue is backed by a system group. Running this migration twice is a
-- no-op: the groups + queues are matched by name / kind respectively.

-- 1. Triage queue (also the default landing)
WITH triage_group AS (
    INSERT INTO public.groups (name, description, is_system)
    VALUES (
        'Triage',
        'Unassigned cases awaiting tier-1 review',
        true
    )
    ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description
    RETURNING id
)
INSERT INTO public.queues (
    group_id, kind, default_sla_tier, routing_priority,
    icon, color, is_default_landing, description
)
SELECT
    id, 'triage', 'low', 100,
    'inbox', 'slate', true,
    'Default landing queue for unrouted cases.'
FROM triage_group
ON CONFLICT (group_id) DO NOTHING;

-- 2. Tier 1 SOC
WITH tier1_group AS (
    INSERT INTO public.groups (name, description, is_system)
    VALUES (
        'Tier 1 SOC',
        'Front-line SOC analysts handling day-to-day alert triage',
        true
    )
    ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description
    RETURNING id
)
INSERT INTO public.queues (
    group_id, kind, default_sla_tier, routing_priority,
    icon, color, is_default_landing, description
)
SELECT
    id, 'tier1', 'standard', 80,
    'shield', 'blue', false,
    'Front-line triage and initial investigation.'
FROM tier1_group
ON CONFLICT (group_id) DO NOTHING;

-- 3. Tier 2 Investigation
WITH tier2_group AS (
    INSERT INTO public.groups (name, description, is_system)
    VALUES (
        'Tier 2 Investigation',
        'Senior analysts handling escalated investigations',
        true
    )
    ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description
    RETURNING id
)
INSERT INTO public.queues (
    group_id, kind, default_sla_tier, routing_priority,
    icon, color, is_default_landing, description
)
SELECT
    id, 'tier2', 'high', 60,
    'search', 'amber', false,
    'Deeper investigation for high-severity and escalated cases.'
FROM tier2_group
ON CONFLICT (group_id) DO NOTHING;

-- 4. Tier 3 IR / Forensics
WITH tier3_group AS (
    INSERT INTO public.groups (name, description, is_system)
    VALUES (
        'Tier 3 IR / Forensics',
        'Incident response and forensic specialists',
        true
    )
    ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description
    RETURNING id
)
INSERT INTO public.queues (
    group_id, kind, default_sla_tier, routing_priority,
    icon, color, is_default_landing, description
)
SELECT
    id, 'tier3', 'critical', 40,
    'siren', 'rose', false,
    'Incident response, forensics, and major incident leadership.'
FROM tier3_group
ON CONFLICT (group_id) DO NOTHING;

COMMIT;
