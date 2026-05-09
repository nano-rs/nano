-- Add folder column to detection_rules for organizing rules by data source
-- Folders: network, identity, endpoint, cloud, stash (auto-archive)

ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS folder TEXT;

-- Create index for efficient folder-based queries
CREATE INDEX IF NOT EXISTS idx_detection_rules_folder ON detection_rules(folder);

-- Note: Existing rules will have NULL folder (displayed as "Uncategorized" in UI)
