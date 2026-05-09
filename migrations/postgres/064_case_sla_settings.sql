-- Case SLA (Service Level Agreement) Settings
-- Configurable response, triage, and resolution time targets by severity
-- Times are stored in minutes for flexibility

-- =============================================================================
-- SLA SETTINGS BY SEVERITY (stored in system_settings)
-- =============================================================================

-- Critical severity SLAs
ALTER TABLE public.system_settings
ADD COLUMN IF NOT EXISTS sla_critical_response_minutes integer DEFAULT 15 NOT NULL;

ALTER TABLE public.system_settings
ADD COLUMN IF NOT EXISTS sla_critical_triage_minutes integer DEFAULT 60 NOT NULL;

ALTER TABLE public.system_settings
ADD COLUMN IF NOT EXISTS sla_critical_resolution_minutes integer DEFAULT 240 NOT NULL;

-- High severity SLAs
ALTER TABLE public.system_settings
ADD COLUMN IF NOT EXISTS sla_high_response_minutes integer DEFAULT 30 NOT NULL;

ALTER TABLE public.system_settings
ADD COLUMN IF NOT EXISTS sla_high_triage_minutes integer DEFAULT 120 NOT NULL;

ALTER TABLE public.system_settings
ADD COLUMN IF NOT EXISTS sla_high_resolution_minutes integer DEFAULT 480 NOT NULL;

-- Medium severity SLAs
ALTER TABLE public.system_settings
ADD COLUMN IF NOT EXISTS sla_medium_response_minutes integer DEFAULT 120 NOT NULL;

ALTER TABLE public.system_settings
ADD COLUMN IF NOT EXISTS sla_medium_triage_minutes integer DEFAULT 480 NOT NULL;

ALTER TABLE public.system_settings
ADD COLUMN IF NOT EXISTS sla_medium_resolution_minutes integer DEFAULT 1440 NOT NULL;

-- Low severity SLAs
ALTER TABLE public.system_settings
ADD COLUMN IF NOT EXISTS sla_low_response_minutes integer DEFAULT 480 NOT NULL;

ALTER TABLE public.system_settings
ADD COLUMN IF NOT EXISTS sla_low_triage_minutes integer DEFAULT 1440 NOT NULL;

ALTER TABLE public.system_settings
ADD COLUMN IF NOT EXISTS sla_low_resolution_minutes integer DEFAULT 4320 NOT NULL;

-- Informational severity SLAs (typically longest or no strict SLA)
ALTER TABLE public.system_settings
ADD COLUMN IF NOT EXISTS sla_informational_response_minutes integer DEFAULT 1440 NOT NULL;

ALTER TABLE public.system_settings
ADD COLUMN IF NOT EXISTS sla_informational_triage_minutes integer DEFAULT 2880 NOT NULL;

ALTER TABLE public.system_settings
ADD COLUMN IF NOT EXISTS sla_informational_resolution_minutes integer DEFAULT 10080 NOT NULL;

-- Global SLA enabled flag
ALTER TABLE public.system_settings
ADD COLUMN IF NOT EXISTS sla_enabled boolean DEFAULT true NOT NULL;

-- =============================================================================
-- CASE TABLE: Track SLA timestamps
-- =============================================================================

-- When the case was first responded to (assigned or status changed from open)
ALTER TABLE public.cases
ADD COLUMN IF NOT EXISTS first_response_at timestamp with time zone;

-- When triage was completed (status changed to in_progress or beyond)
ALTER TABLE public.cases
ADD COLUMN IF NOT EXISTS triage_completed_at timestamp with time zone;

-- =============================================================================
-- INDEXES FOR SLA QUERIES
-- =============================================================================

-- Index for finding cases approaching/breaching SLAs
CREATE INDEX IF NOT EXISTS idx_cases_sla_response
ON public.cases (created_at, first_response_at)
WHERE status IN ('open');

CREATE INDEX IF NOT EXISTS idx_cases_sla_triage
ON public.cases (first_response_at, triage_completed_at)
WHERE status IN ('open', 'in_progress');

CREATE INDEX IF NOT EXISTS idx_cases_sla_resolution
ON public.cases (created_at, resolved_at)
WHERE status NOT IN ('resolved', 'closed');

-- =============================================================================
-- COMMENTS
-- =============================================================================

COMMENT ON COLUMN public.system_settings.sla_enabled IS 'Whether SLA tracking and display is enabled globally';
COMMENT ON COLUMN public.system_settings.sla_critical_response_minutes IS 'SLA target for initial response on critical cases (minutes)';
COMMENT ON COLUMN public.system_settings.sla_critical_triage_minutes IS 'SLA target for triage completion on critical cases (minutes)';
COMMENT ON COLUMN public.system_settings.sla_critical_resolution_minutes IS 'SLA target for resolution on critical cases (minutes)';

COMMENT ON COLUMN public.cases.first_response_at IS 'Timestamp when case was first responded to (assigned or status changed)';
COMMENT ON COLUMN public.cases.triage_completed_at IS 'Timestamp when triage was completed (status changed to in_progress or beyond)';
