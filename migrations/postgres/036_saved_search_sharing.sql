-- Add ownership and visibility to saved_searches
ALTER TABLE saved_searches
ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES users(id) ON DELETE SET NULL,
ADD COLUMN IF NOT EXISTS visibility VARCHAR(20) DEFAULT 'private'
    CHECK (visibility IN ('private', 'public', 'group')),
ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW();

-- Junction table for group sharing
CREATE TABLE IF NOT EXISTS saved_search_groups (
    saved_search_id UUID NOT NULL REFERENCES saved_searches(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    PRIMARY KEY (saved_search_id, group_id)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_saved_searches_user_id ON saved_searches(user_id);
CREATE INDEX IF NOT EXISTS idx_saved_searches_visibility ON saved_searches(visibility);
CREATE INDEX IF NOT EXISTS idx_saved_search_groups_group_id ON saved_search_groups(group_id);

-- Migrate existing searches to public (backward compatible)
UPDATE saved_searches SET visibility = 'public' WHERE visibility IS NULL;
