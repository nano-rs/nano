-- NAN-417: Incidents as a first-class grouping primitive.
--
-- The Signal Inbox redesign (design-ref/shadcn/cases-merge.jsx) introduces
-- the `incident` concept: a parent container that groups multiple related
-- cases that belong to the same campaign (e.g. a login-spray across
-- multiple tenants). Cases remain first-class records — they're not
-- merged or destroyed on promote. An incident is a lightweight bundle.
--
-- Two shapes of incident were considered:
--   - Junction table (case_incidents many-to-many) — flexible but the
--     mocks never demonstrate a case belonging to multiple incidents.
--   - FK column on cases (incident_id, nullable, one-to-many) — simpler,
--     matches "loose vs grouped" split directly via `WHERE incident_id IS NULL`.
-- Going with the FK. If multi-parentage becomes real later, swap to the
-- junction table via a new migration.

BEGIN;

-- =============================================================================
-- incidents table
-- =============================================================================

CREATE TABLE IF NOT EXISTS public.incidents (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    incident_number SERIAL UNIQUE,
    title text NOT NULL,
    severity text NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,

    -- Provenance: who/what created this incident
    source text DEFAULT 'manual'::text NOT NULL,
    detector text,                -- agent-detection rule id when source='agent_detected'
    confidence numeric(4, 3),     -- 0.000–1.000 when source='agent_detected'
    signature text,               -- human-readable reasoning string ("same ASN + same rule + same 3-min bucket")

    tags text[] DEFAULT '{}'::text[] NOT NULL,

    -- Lifecycle timestamps
    opened_at timestamp with time zone DEFAULT now() NOT NULL,
    closed_at timestamp with time zone,
    closed_by uuid REFERENCES public.users(id) ON DELETE SET NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid REFERENCES public.users(id) ON DELETE SET NULL,

    CONSTRAINT incidents_pkey PRIMARY KEY (id),
    CONSTRAINT incidents_severity_check CHECK (severity = ANY (ARRAY[
        'critical'::text, 'high'::text, 'medium'::text, 'low'::text, 'informational'::text
    ])),
    CONSTRAINT incidents_status_check CHECK (status = ANY (ARRAY[
        'active'::text, 'resolved'::text, 'closed'::text
    ])),
    CONSTRAINT incidents_source_check CHECK (source = ANY (ARRAY[
        'manual'::text, 'agent_detected'::text
    ])),
    CONSTRAINT incidents_confidence_range CHECK (
        confidence IS NULL OR (confidence >= 0.0 AND confidence <= 1.0)
    )
);

CREATE INDEX IF NOT EXISTS idx_incidents_status
    ON public.incidents(status, opened_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_source
    ON public.incidents(source, opened_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_opened_at
    ON public.incidents(opened_at DESC);

COMMENT ON TABLE public.incidents IS
    'Parent containers that group related cases into campaigns. Cases are attached via cases.incident_id.';
COMMENT ON COLUMN public.incidents.source IS
    'Provenance: manual (analyst promoted) or agent_detected (auto-grouped by detection rule).';
COMMENT ON COLUMN public.incidents.signature IS
    'Human-readable grouping rationale. Free-form for manual, templated by detector for agent_detected.';

-- =============================================================================
-- cases.incident_id FK
-- =============================================================================

ALTER TABLE public.cases
    ADD COLUMN IF NOT EXISTS incident_id uuid REFERENCES public.incidents(id) ON DELETE SET NULL;

-- Signal Inbox query pattern: split loose (incident_id IS NULL) from grouped
-- (join on incident_id) in one scan. Partial index speeds up the hot case-list.
CREATE INDEX IF NOT EXISTS idx_cases_incident_id
    ON public.cases(incident_id)
    WHERE incident_id IS NOT NULL;

COMMENT ON COLUMN public.cases.incident_id IS
    'Optional parent incident. NULL = loose case (not grouped). See migration 153.';

COMMIT;
