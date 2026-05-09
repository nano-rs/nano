-- Case Management System
-- Full case-centric workflow for SOC investigations

-- =============================================================================
-- CASES TABLE
-- Core table for security investigation cases
-- =============================================================================
CREATE TABLE public.cases (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    case_number SERIAL UNIQUE,
    title text NOT NULL,
    description text,
    severity text NOT NULL,
    status text DEFAULT 'open'::text NOT NULL,
    disposition text,
    priority integer DEFAULT 0,

    -- Assignment
    assigned_to uuid REFERENCES public.users(id) ON DELETE SET NULL,
    assigned_at timestamp with time zone,

    -- AI Summary (Gemini-style)
    ai_summary text,
    ai_recommendations jsonb,
    ai_summary_generated_at timestamp with time zone,

    -- Grouping metadata
    grouping_key text,
    grouping_type text,

    -- MITRE ATT&CK mapping
    mitre_tactics text[] DEFAULT '{}',
    mitre_techniques text[] DEFAULT '{}',

    -- Timestamps
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    first_activity_at timestamp with time zone,
    last_activity_at timestamp with time zone,
    resolved_at timestamp with time zone,
    resolved_by uuid REFERENCES public.users(id) ON DELETE SET NULL,
    closed_at timestamp with time zone,
    closed_by uuid REFERENCES public.users(id) ON DELETE SET NULL,

    -- Metadata
    tags text[] DEFAULT '{}',

    CONSTRAINT cases_pkey PRIMARY KEY (id),
    CONSTRAINT cases_severity_check CHECK (severity = ANY (ARRAY['critical'::text, 'high'::text, 'medium'::text, 'low'::text, 'informational'::text])),
    CONSTRAINT cases_status_check CHECK (status = ANY (ARRAY['open'::text, 'in_progress'::text, 'pending'::text, 'resolved'::text, 'closed'::text])),
    CONSTRAINT cases_disposition_check CHECK (disposition IS NULL OR disposition = ANY (ARRAY['true_positive'::text, 'false_positive'::text, 'benign'::text, 'inconclusive'::text])),
    CONSTRAINT cases_grouping_type_check CHECK (grouping_type IS NULL OR grouping_type = ANY (ARRAY['host'::text, 'user'::text, 'rule'::text, 'ip'::text, 'manual'::text]))
);

-- Indexes for cases
CREATE INDEX idx_cases_status ON public.cases(status);
CREATE INDEX idx_cases_severity ON public.cases(severity);
CREATE INDEX idx_cases_assigned_to ON public.cases(assigned_to);
CREATE INDEX idx_cases_created_at ON public.cases(created_at DESC);
CREATE INDEX idx_cases_updated_at ON public.cases(updated_at DESC);
CREATE INDEX idx_cases_grouping_key ON public.cases(grouping_key) WHERE status NOT IN ('resolved', 'closed');
CREATE INDEX idx_cases_open_priority ON public.cases(severity, priority DESC, created_at DESC) WHERE status IN ('open', 'in_progress', 'pending');

-- =============================================================================
-- CASE_ALERTS TABLE
-- Junction table linking alerts to cases
-- =============================================================================
CREATE TABLE public.case_alerts (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    case_id uuid NOT NULL REFERENCES public.cases(id) ON DELETE CASCADE,
    alert_id uuid NOT NULL REFERENCES public.alerts(id) ON DELETE CASCADE,
    added_at timestamp with time zone DEFAULT now() NOT NULL,
    added_by uuid REFERENCES public.users(id) ON DELETE SET NULL,
    is_primary boolean DEFAULT false,

    CONSTRAINT case_alerts_pkey PRIMARY KEY (id),
    CONSTRAINT case_alerts_unique UNIQUE (case_id, alert_id)
);

-- Indexes for case_alerts
CREATE INDEX idx_case_alerts_case_id ON public.case_alerts(case_id);
CREATE INDEX idx_case_alerts_alert_id ON public.case_alerts(alert_id);

-- =============================================================================
-- CASE_ENTITIES TABLE
-- Entities extracted from alert events (IPs, users, hosts, domains, hashes)
-- =============================================================================
CREATE TABLE public.case_entities (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    case_id uuid NOT NULL REFERENCES public.cases(id) ON DELETE CASCADE,
    entity_type text NOT NULL,
    entity_value text NOT NULL,
    first_seen_at timestamp with time zone DEFAULT now(),
    last_seen_at timestamp with time zone DEFAULT now(),
    occurrence_count integer DEFAULT 1,
    risk_score integer,
    is_primary boolean DEFAULT false,
    enrichment_data jsonb,
    enrichment_updated_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,

    CONSTRAINT case_entities_pkey PRIMARY KEY (id),
    CONSTRAINT case_entities_unique UNIQUE (case_id, entity_type, entity_value),
    CONSTRAINT case_entities_type_check CHECK (entity_type = ANY (ARRAY['user'::text, 'host'::text, 'ip'::text, 'domain'::text, 'hash'::text, 'url'::text, 'file'::text, 'process'::text, 'email'::text]))
);

-- Indexes for case_entities
CREATE INDEX idx_case_entities_case_id ON public.case_entities(case_id);
CREATE INDEX idx_case_entities_type_value ON public.case_entities(entity_type, entity_value);
CREATE INDEX idx_case_entities_risk ON public.case_entities(risk_score DESC NULLS LAST) WHERE risk_score IS NOT NULL;
CREATE INDEX idx_case_entities_primary ON public.case_entities(case_id) WHERE is_primary = true;

-- =============================================================================
-- CASE_WALL TABLE
-- Activity timeline and comments for cases
-- =============================================================================
CREATE TABLE public.case_wall (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    case_id uuid NOT NULL REFERENCES public.cases(id) ON DELETE CASCADE,
    entry_type text NOT NULL,
    content text,
    metadata jsonb DEFAULT '{}'::jsonb,
    is_internal boolean DEFAULT false,
    created_by uuid REFERENCES public.users(id) ON DELETE SET NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,

    CONSTRAINT case_wall_pkey PRIMARY KEY (id),
    CONSTRAINT case_wall_type_check CHECK (entry_type = ANY (ARRAY[
        'comment'::text,
        'status_change'::text,
        'assignment_change'::text,
        'alert_added'::text,
        'alert_removed'::text,
        'entity_added'::text,
        'enrichment_result'::text,
        'ai_analysis'::text,
        'action_taken'::text,
        'attachment'::text,
        'system'::text
    ]))
);

-- Indexes for case_wall
CREATE INDEX idx_case_wall_case_id ON public.case_wall(case_id, created_at DESC);
CREATE INDEX idx_case_wall_type ON public.case_wall(case_id, entry_type);

-- =============================================================================
-- CASE_RELATIONS TABLE
-- Relationships between cases (related, parent/child, duplicate)
-- =============================================================================
CREATE TABLE public.case_relations (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    source_case_id uuid NOT NULL REFERENCES public.cases(id) ON DELETE CASCADE,
    target_case_id uuid NOT NULL REFERENCES public.cases(id) ON DELETE CASCADE,
    relation_type text NOT NULL,
    confidence float,
    reason text,
    shared_entities jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid REFERENCES public.users(id) ON DELETE SET NULL,

    CONSTRAINT case_relations_pkey PRIMARY KEY (id),
    CONSTRAINT case_relations_unique UNIQUE (source_case_id, target_case_id),
    CONSTRAINT case_relations_no_self CHECK (source_case_id != target_case_id),
    CONSTRAINT case_relations_type_check CHECK (relation_type = ANY (ARRAY['related'::text, 'parent'::text, 'child'::text, 'duplicate'::text]))
);

-- Indexes for case_relations
CREATE INDEX idx_case_relations_source ON public.case_relations(source_case_id);
CREATE INDEX idx_case_relations_target ON public.case_relations(target_case_id);

-- =============================================================================
-- CASE_GROUPING_RULES TABLE
-- Configuration for auto-grouping alerts into cases
-- =============================================================================
CREATE TABLE public.case_grouping_rules (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    name text NOT NULL,
    description text,
    enabled boolean DEFAULT true,
    priority integer DEFAULT 0,

    -- Matching criteria
    match_type text NOT NULL,
    match_conditions jsonb,

    -- Grouping behavior
    time_window_minutes integer DEFAULT 60,
    min_alerts integer DEFAULT 1,
    max_alerts integer DEFAULT 100,
    auto_create_case boolean DEFAULT true,

    -- Case template
    case_title_template text,
    case_severity_rule text DEFAULT 'highest',
    auto_assign_to uuid REFERENCES public.users(id) ON DELETE SET NULL,

    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid REFERENCES public.users(id) ON DELETE SET NULL,

    CONSTRAINT case_grouping_rules_pkey PRIMARY KEY (id),
    CONSTRAINT case_grouping_rules_match_type_check CHECK (match_type = ANY (ARRAY['host'::text, 'user'::text, 'rule'::text, 'ip'::text, 'custom'::text])),
    CONSTRAINT case_grouping_rules_severity_rule_check CHECK (case_severity_rule = ANY (ARRAY['highest'::text, 'lowest'::text, 'first'::text, 'most_common'::text]))
);

-- Index for grouping rules
CREATE INDEX idx_case_grouping_rules_enabled ON public.case_grouping_rules(enabled, priority DESC) WHERE enabled = true;

-- =============================================================================
-- MODIFY ALERTS TABLE
-- Add case_id reference for direct lookup
-- =============================================================================
ALTER TABLE public.alerts ADD COLUMN case_id uuid REFERENCES public.cases(id) ON DELETE SET NULL;
ALTER TABLE public.alerts ADD COLUMN matched_event_count integer;

-- Index for alert -> case lookup
CREATE INDEX idx_alerts_case_id ON public.alerts(case_id) WHERE case_id IS NOT NULL;

-- =============================================================================
-- COMMENTS
-- =============================================================================
COMMENT ON TABLE public.cases IS 'Security investigation cases containing grouped alerts';
COMMENT ON COLUMN public.cases.case_number IS 'Human-readable sequential case number (CASE-1234)';
COMMENT ON COLUMN public.cases.grouping_key IS 'Hash key used for auto-grouping alerts into this case';
COMMENT ON COLUMN public.cases.grouping_type IS 'Type of entity used for auto-grouping (host, user, rule, ip)';
COMMENT ON COLUMN public.cases.ai_summary IS 'AI-generated case summary with findings';
COMMENT ON COLUMN public.cases.ai_recommendations IS 'JSON array of AI remediation recommendations';

COMMENT ON TABLE public.case_alerts IS 'Junction table linking alerts to cases';
COMMENT ON COLUMN public.case_alerts.is_primary IS 'True if this alert initiated the case';

COMMENT ON TABLE public.case_entities IS 'Entities extracted from case alerts (IPs, users, hosts, domains, hashes)';
COMMENT ON COLUMN public.case_entities.entity_type IS 'Type: user, host, ip, domain, hash, url, file, process, email';
COMMENT ON COLUMN public.case_entities.occurrence_count IS 'Number of times this entity appeared across alerts';
COMMENT ON COLUMN public.case_entities.enrichment_data IS 'Cached threat intelligence enrichment data';

COMMENT ON TABLE public.case_wall IS 'Activity timeline and analyst comments for cases';
COMMENT ON COLUMN public.case_wall.entry_type IS 'Type: comment, status_change, assignment_change, alert_added, ai_analysis, etc.';
COMMENT ON COLUMN public.case_wall.is_internal IS 'True for internal analyst notes not shown to all users';

COMMENT ON TABLE public.case_relations IS 'Relationships between cases (related, parent/child, duplicate)';
COMMENT ON COLUMN public.case_relations.confidence IS 'AI confidence score for auto-detected relations (0-1)';
COMMENT ON COLUMN public.case_relations.shared_entities IS 'JSON array of entities shared between cases';

COMMENT ON TABLE public.case_grouping_rules IS 'Configuration for auto-grouping alerts into cases';
COMMENT ON COLUMN public.case_grouping_rules.time_window_minutes IS 'Time window for grouping alerts (e.g., 60 = alerts within 1 hour)';
COMMENT ON COLUMN public.case_grouping_rules.case_title_template IS 'Template for auto-generated case titles, e.g., "Multiple alerts on {{host}}"';
COMMENT ON COLUMN public.case_grouping_rules.case_severity_rule IS 'How to calculate case severity: highest, lowest, first, most_common';

-- =============================================================================
-- SEED DEFAULT GROUPING RULES
-- =============================================================================
INSERT INTO public.case_grouping_rules (id, name, description, enabled, priority, match_type, time_window_minutes, case_title_template, case_severity_rule) VALUES
    (public.uuid_generate_v4(), 'Group by Host', 'Group alerts targeting the same host within time window', true, 100, 'host', 60, 'Alerts on host: {{host}}', 'highest'),
    (public.uuid_generate_v4(), 'Group by User', 'Group alerts involving the same user within time window', true, 90, 'user', 60, 'Alerts for user: {{user}}', 'highest'),
    (public.uuid_generate_v4(), 'Group by Source IP', 'Group alerts from the same source IP within time window', true, 80, 'ip', 30, 'Alerts from IP: {{ip}}', 'highest'),
    (public.uuid_generate_v4(), 'Group by Detection Rule', 'Group alerts from the same detection rule within time window', true, 70, 'rule', 120, '{{rule_name}}', 'highest');

-- =============================================================================
-- PERMISSIONS
-- =============================================================================
INSERT INTO public.permissions (id, name, description, category) VALUES
    ('cases:view', 'cases:view', 'View cases and case details', 'cases'),
    ('cases:create', 'cases:create', 'Create new cases manually', 'cases'),
    ('cases:edit', 'cases:edit', 'Edit case details and add comments', 'cases'),
    ('cases:assign', 'cases:assign', 'Assign cases to users', 'cases'),
    ('cases:close', 'cases:close', 'Close and resolve cases', 'cases'),
    ('cases:delete', 'cases:delete', 'Delete cases', 'cases'),
    ('case_settings:view', 'case_settings:view', 'View case grouping settings', 'settings'),
    ('case_settings:edit', 'case_settings:edit', 'Edit case grouping rules', 'settings')
ON CONFLICT (id) DO NOTHING;

-- Grant case permissions to Admin role
INSERT INTO public.role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM public.roles r, public.permissions p
WHERE r.name = 'Admin' AND p.name IN ('cases:view', 'cases:create', 'cases:edit', 'cases:assign', 'cases:close', 'cases:delete', 'case_settings:view', 'case_settings:edit')
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Grant basic case permissions to Editor role
INSERT INTO public.role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM public.roles r, public.permissions p
WHERE r.name = 'Editor' AND p.name IN ('cases:view', 'cases:create', 'cases:edit', 'cases:assign', 'cases:close')
ON CONFLICT (role_id, permission_id) DO NOTHING;

-- Grant view permission to ReadOnly role
INSERT INTO public.role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM public.roles r, public.permissions p
WHERE r.name = 'ReadOnly' AND p.name = 'cases:view'
ON CONFLICT (role_id, permission_id) DO NOTHING;
