-- NAN-3816 (ported to clickhouse/dev as NAN-4902; main's number was 365):
-- DELETE /api/rules/{id} archives the rule instead of removing the row, so
-- its detection_matches / alerts / stats keep their rule reference.
--
-- Removing a repository's imported rules ("remove all imported") goes through
-- the same delete and now leaves an archived row carrying the repository's
-- (name, source_repository_id). The per-repo name guard (migration 146) would
-- then refuse re-importing that same rule. Uniqueness only matters among
-- rules that can still run, so the guard ignores archived rows. Unarchiving a
-- rule whose name was re-imported meanwhile fails on this index, which is the
-- intended conflict.
--
-- Idempotent: re-running drops and recreates the same partial index.

SET LOCAL lock_timeout = '5s';

DROP INDEX IF EXISTS public.idx_detection_rules_unique_name_per_repo;
CREATE UNIQUE INDEX IF NOT EXISTS idx_detection_rules_unique_name_per_repo
    ON public.detection_rules (name, source_repository_id)
    WHERE source_repository_id IS NOT NULL AND archived = FALSE;
