-- Detection Rule Case Permissions
-- Rules can specify what visibility/groups to apply to cases they create.
-- Alerts remain public; only cases get the permission inheritance.

-- Add case visibility setting to detection rules (defaults to 'public' for backwards compat)
ALTER TABLE detection_rules
ADD COLUMN IF NOT EXISTS case_visibility VARCHAR(20) DEFAULT 'public' NOT NULL;

-- Add constraint for valid visibility values
DO $$
BEGIN
    ALTER TABLE detection_rules ADD CONSTRAINT detection_rules_case_visibility_check
    CHECK (case_visibility IN ('public', 'group', 'private'));
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

-- Junction table for groups that cases should be shared with
CREATE TABLE IF NOT EXISTS detection_rule_case_groups (
    rule_id UUID NOT NULL REFERENCES detection_rules(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (rule_id, group_id)
);

-- Index for efficient lookups
CREATE INDEX IF NOT EXISTS idx_detection_rule_case_groups_group_id
ON detection_rule_case_groups(group_id);
