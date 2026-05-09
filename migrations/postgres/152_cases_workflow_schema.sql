-- NAN-415: First-class case workflow persistence schema
--
-- Replaces the "shove everything into case_wall.metadata JSON" shim that
-- NAN-410 landed as a bridge. The wall still captures human-readable timeline
-- entries, but the structured workflow state (close reason + note, pending
-- state, escalation records, handoff records, state-transition history)
-- moves to dedicated tables so we can index, aggregate, and reference
-- foreign keys properly.

BEGIN;

-- =============================================================================
-- Columns on cases table
-- =============================================================================
--
-- close_reason is separate from disposition because the two answer different
-- questions: disposition describes the *verdict* (true_positive / benign /
-- inconclusive), close_reason describes the *resolution workflow* (fp, btp,
-- dup, esc, info, tp, inconc). A true-positive case can close as either 'tp'
-- or 'esc' depending on whether SOC handled it or handed off to IR, and both
-- paths need to be queryable independently.

ALTER TABLE public.cases
    ADD COLUMN IF NOT EXISTS close_reason text,
    ADD COLUMN IF NOT EXISTS pending_kind text,
    ADD COLUMN IF NOT EXISTS pending_target text,
    ADD COLUMN IF NOT EXISTS pending_since timestamp with time zone;

ALTER TABLE public.cases
    ADD CONSTRAINT cases_close_reason_check
    CHECK (close_reason IS NULL OR close_reason = ANY (ARRAY[
        'tp'::text, 'fp'::text, 'btp'::text, 'dup'::text,
        'esc'::text, 'info'::text, 'inconc'::text
    ]));

ALTER TABLE public.cases
    ADD CONSTRAINT cases_pending_kind_check
    CHECK (pending_kind IS NULL OR pending_kind = ANY (ARRAY[
        'await-user'::text, 'await-approval'::text, 'await-vendor'::text,
        'snoozed'::text, 'scheduled'::text, 'hold'::text
    ]));

-- "all FP closures in last 30d" is a common aggregation (tuning dashboards,
-- detector fp-rate trends) — index it.
CREATE INDEX IF NOT EXISTS idx_cases_close_reason
    ON public.cases(close_reason, closed_at DESC)
    WHERE close_reason IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_cases_pending_kind
    ON public.cases(pending_kind, pending_since DESC)
    WHERE pending_kind IS NOT NULL;

-- =============================================================================
-- case_close_notes — durable close note + sub-form state
-- =============================================================================
--
-- A case can be closed-and-reopened multiple times, so we keep a history
-- rather than a single row per case. The latest non-archived note is
-- "the current resolution."

CREATE TABLE IF NOT EXISTS public.case_close_notes (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    case_id uuid NOT NULL REFERENCES public.cases(id) ON DELETE CASCADE,
    created_by uuid REFERENCES public.users(id) ON DELETE SET NULL,
    close_reason text NOT NULL,
    title text NOT NULL,
    summary text NOT NULL,
    emits text[] DEFAULT '{}'::text[] NOT NULL,
    -- Reason-specific sub-form state. Kept narrow on purpose; anything
    -- richer belongs in its own table (e.g. case_escalations for 'esc').
    tuning_action text,               -- when close_reason='fp'
    escalation_target text,           -- when close_reason='esc'
    duplicate_primary_case_number integer, -- when close_reason='dup' (freeform)
    duplicate_primary_case_id uuid REFERENCES public.cases(id) ON DELETE SET NULL,
    ack_audit boolean DEFAULT false NOT NULL,
    audit_id text,
    superseded_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,

    CONSTRAINT case_close_notes_pkey PRIMARY KEY (id),
    CONSTRAINT case_close_notes_close_reason_check
        CHECK (close_reason = ANY (ARRAY[
            'tp'::text, 'fp'::text, 'btp'::text, 'dup'::text,
            'esc'::text, 'info'::text, 'inconc'::text
        ]))
);

CREATE INDEX IF NOT EXISTS idx_case_close_notes_case_id
    ON public.case_close_notes(case_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_case_close_notes_reason_created
    ON public.case_close_notes(close_reason, created_at DESC);
-- Partial unique so each case has at most one active close note at a time.
CREATE UNIQUE INDEX IF NOT EXISTS idx_case_close_notes_active
    ON public.case_close_notes(case_id)
    WHERE superseded_at IS NULL;

-- =============================================================================
-- case_escalations — structured escalation records
-- =============================================================================
--
-- Today NAN-410 writes escalations only into case_wall.metadata as
-- action_kind=escalation. This table promotes escalations to queryable
-- records so "show me all cases escalated to IR in the last week" is a
-- simple join instead of a JSON filter.

CREATE TABLE IF NOT EXISTS public.case_escalations (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    case_id uuid NOT NULL REFERENCES public.cases(id) ON DELETE CASCADE,
    source_user_id uuid REFERENCES public.users(id) ON DELETE SET NULL,
    target_user_id uuid REFERENCES public.users(id) ON DELETE SET NULL,
    target_group_id uuid REFERENCES public.groups(id) ON DELETE SET NULL,
    target_label text NOT NULL,
    reason text NOT NULL,
    previous_assigned_to uuid REFERENCES public.users(id) ON DELETE SET NULL,
    previous_assigned_group uuid REFERENCES public.groups(id) ON DELETE SET NULL,
    acknowledged_at timestamp with time zone,
    acknowledged_by uuid REFERENCES public.users(id) ON DELETE SET NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,

    CONSTRAINT case_escalations_pkey PRIMARY KEY (id),
    CONSTRAINT case_escalations_target_present
        CHECK (target_user_id IS NOT NULL OR target_group_id IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS idx_case_escalations_case_id
    ON public.case_escalations(case_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_case_escalations_target_user
    ON public.case_escalations(target_user_id, created_at DESC)
    WHERE target_user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_case_escalations_target_group
    ON public.case_escalations(target_group_id, created_at DESC)
    WHERE target_group_id IS NOT NULL;

-- =============================================================================
-- case_handoffs — structured analyst-to-analyst handoff records
-- =============================================================================
--
-- Distinct from escalations: escalations cross a tier boundary (SOC → IR),
-- handoffs are peer transfers of ownership (analyst A → analyst B within
-- SOC). Matches the mock's HandoffFlow component + bounce/accept semantics.

CREATE TABLE IF NOT EXISTS public.case_handoffs (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    case_id uuid NOT NULL REFERENCES public.cases(id) ON DELETE CASCADE,
    source_user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    target_user_id uuid REFERENCES public.users(id) ON DELETE SET NULL,
    target_group_id uuid REFERENCES public.groups(id) ON DELETE SET NULL,
    target_label text NOT NULL,
    reason text,
    context_payload jsonb DEFAULT '{}'::jsonb NOT NULL,
    state text DEFAULT 'pending'::text NOT NULL,
    accepted_at timestamp with time zone,
    accepted_by uuid REFERENCES public.users(id) ON DELETE SET NULL,
    bounced_at timestamp with time zone,
    bounced_by uuid REFERENCES public.users(id) ON DELETE SET NULL,
    bounce_reason text,
    canceled_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,

    CONSTRAINT case_handoffs_pkey PRIMARY KEY (id),
    CONSTRAINT case_handoffs_target_present
        CHECK (target_user_id IS NOT NULL OR target_group_id IS NOT NULL),
    CONSTRAINT case_handoffs_state_check
        CHECK (state = ANY (ARRAY['pending'::text, 'accepted'::text, 'bounced'::text, 'canceled'::text]))
);

CREATE INDEX IF NOT EXISTS idx_case_handoffs_case_id
    ON public.case_handoffs(case_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_case_handoffs_target_pending
    ON public.case_handoffs(target_user_id, state)
    WHERE state = 'pending';

-- =============================================================================
-- case_workflow_events — state transition history
-- =============================================================================
--
-- Single source of truth for "what happened and when" at the workflow layer.
-- Distinct from case_wall (which mixes comments + system events + AI turns
-- for the investigation thread UI) — this table is the audit spine for the
-- workflow bar's state transitions and links into the structured tables
-- above via foreign keys.

CREATE TABLE IF NOT EXISTS public.case_workflow_events (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    case_id uuid NOT NULL REFERENCES public.cases(id) ON DELETE CASCADE,
    actor_id uuid REFERENCES public.users(id) ON DELETE SET NULL,
    event_kind text NOT NULL,
    from_status text,
    to_status text,
    reason text,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    close_note_id uuid REFERENCES public.case_close_notes(id) ON DELETE SET NULL,
    escalation_id uuid REFERENCES public.case_escalations(id) ON DELETE SET NULL,
    handoff_id uuid REFERENCES public.case_handoffs(id) ON DELETE SET NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,

    CONSTRAINT case_workflow_events_pkey PRIMARY KEY (id),
    CONSTRAINT case_workflow_events_kind_check
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
            'handoff_canceled'::text
        ]))
);

CREATE INDEX IF NOT EXISTS idx_case_workflow_events_case_id
    ON public.case_workflow_events(case_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_case_workflow_events_kind
    ON public.case_workflow_events(event_kind, created_at DESC);

-- =============================================================================
-- Comments for future maintainers
-- =============================================================================
COMMENT ON COLUMN public.cases.close_reason IS
    'Resolution workflow key (tp/fp/btp/dup/esc/info/inconc). Separate from disposition.';
COMMENT ON COLUMN public.cases.pending_kind IS
    'Current pending-state kind when status=pending. Mirrored on case_workflow_events.';
COMMENT ON TABLE public.case_close_notes IS
    'Durable close note + sub-form state, one active row per case (supersedable on reopen).';
COMMENT ON TABLE public.case_escalations IS
    'Structured escalation records (SOC tier to IR/legal/exec). Replaces wall metadata shim.';
COMMENT ON TABLE public.case_handoffs IS
    'Peer-to-peer ownership transfers within the SOC tier with accept/bounce semantics.';
COMMENT ON TABLE public.case_workflow_events IS
    'State-transition audit spine for the workflow bar. FKs into the structured side-tables.';

COMMIT;
