-- Add selected_paths to rule_repositories for folder filtering
ALTER TABLE rule_repositories
    ADD COLUMN IF NOT EXISTS selected_paths TEXT[] DEFAULT NULL;

-- NULL = sync all, empty array = sync nothing, array of paths = sync only those
COMMENT ON COLUMN rule_repositories.selected_paths IS 'Paths to sync. NULL means sync all under rules_path.';
