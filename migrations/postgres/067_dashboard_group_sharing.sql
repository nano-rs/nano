-- Dashboard Group Sharing
-- Adds visibility-based access control to dashboards, matching the Cases pattern.

-- Add visibility column (replaces is_private boolean)
ALTER TABLE dashboards
ADD COLUMN IF NOT EXISTS visibility VARCHAR(20) DEFAULT 'public' NOT NULL;

-- Add constraint for valid visibility values (idempotent)
DO $$
BEGIN
    ALTER TABLE dashboards ADD CONSTRAINT dashboards_visibility_check
    CHECK (visibility IN ('public', 'group', 'private'));
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

-- Junction table for group sharing (when visibility = 'group')
CREATE TABLE IF NOT EXISTS dashboard_groups (
    dashboard_id UUID NOT NULL REFERENCES dashboards(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (dashboard_id, group_id)
);

-- Index for efficient group membership lookups
CREATE INDEX IF NOT EXISTS idx_dashboard_groups_group_id ON dashboard_groups(group_id);

-- Index for visibility filtering
CREATE INDEX IF NOT EXISTS idx_dashboards_visibility ON dashboards(visibility);

-- Migrate existing data: private dashboards become 'private', public become 'public'
-- Only run if is_private column still exists
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'dashboards' AND column_name = 'is_private') THEN
        UPDATE dashboards SET visibility = 'private' WHERE is_private = true;
        UPDATE dashboards SET visibility = 'public' WHERE is_private = false;
        ALTER TABLE dashboards DROP COLUMN is_private;
    END IF;
END $$;
