-- Prevent duplicate detection rules from the same repository.
-- NULLs are treated as distinct in Postgres UNIQUE constraints,
-- so manually created rules (source_repository_id = NULL) can share names.
CREATE UNIQUE INDEX IF NOT EXISTS idx_detection_rules_unique_name_per_repo
ON detection_rules (name, source_repository_id)
WHERE source_repository_id IS NOT NULL;
