-- Add group-based case assignment (queue model)
-- Cases can be assigned to a group queue in addition to an individual user.
-- Detection rules can specify a default assigned group, with a system-wide default as fallback.

-- Cases: assigned_group for queue routing
ALTER TABLE cases
ADD COLUMN IF NOT EXISTS assigned_group UUID REFERENCES groups(id) ON DELETE SET NULL,
ADD COLUMN IF NOT EXISTS assigned_group_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_cases_assigned_group
ON cases(assigned_group) WHERE assigned_group IS NOT NULL;

-- Detection rules: per-rule assigned group override
ALTER TABLE detection_rules
ADD COLUMN IF NOT EXISTS case_assigned_group UUID REFERENCES groups(id) ON DELETE SET NULL;

-- System settings: default assigned group for all new cases
ALTER TABLE system_settings
ADD COLUMN IF NOT EXISTS default_assigned_group UUID REFERENCES groups(id) ON DELETE SET NULL;
