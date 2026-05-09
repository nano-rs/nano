-- Add visibility and creator tracking to cases
ALTER TABLE cases
ADD COLUMN IF NOT EXISTS visibility VARCHAR(20) DEFAULT 'public' NOT NULL,
ADD COLUMN IF NOT EXISTS created_by UUID REFERENCES users(id) ON DELETE SET NULL;

-- Add constraint for valid visibility values
ALTER TABLE cases ADD CONSTRAINT cases_visibility_check
CHECK (visibility IN ('public', 'group', 'private'));

-- Junction table for group sharing
CREATE TABLE IF NOT EXISTS case_groups (
    case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (case_id, group_id)
);

-- Indexes for efficient access checking
CREATE INDEX IF NOT EXISTS idx_case_groups_group_id ON case_groups(group_id);
CREATE INDEX IF NOT EXISTS idx_cases_visibility ON cases(visibility);
CREATE INDEX IF NOT EXISTS idx_cases_created_by ON cases(created_by);

-- Migrate existing cases to public visibility (maintains current behavior)
UPDATE cases SET visibility = 'public' WHERE visibility IS NULL;
