-- NAN-3816: DELETE /api/rules/{id} archives the rule instead of removing the
-- row, so its detection_matches / alerts / stats keep their rule reference.
--
-- Removing a repository's imported rules ("remove all imported") goes through
-- the same delete and now leaves an archived row carrying the repository's
-- (name, source_repository_id). The per-repo name guard (migration 146) would
-- then refuse re-importing that same rule. Uniqueness only matters among
-- rules that can still run, so the guard ignores archived rows. Unarchiving a
-- rule whose name was re-imported meanwhile fails on this index, which is the
-- intended conflict.
--
-- Open core only. On an activated enterprise_shared database the migrator
-- does not own detection_rules (RLS data owner); hosted already archives on
-- delete (NAN-2722) and keeps its index, so this file skips there.
--
-- Idempotent: re-running drops and recreates the same partial index.

SET LOCAL lock_timeout = '5s';

DO $nan3816_archive_name_reuse$
DECLARE
    v_owner OID;
BEGIN
    SELECT relowner INTO v_owner FROM pg_catalog.pg_class WHERE oid = 'public.detection_rules'::regclass;
    IF NOT pg_catalog.pg_has_role(current_user, v_owner, 'USAGE') THEN
        RAISE NOTICE 'detection_rules is owned by %; leaving its name index unchanged', v_owner::regrole;
        RETURN;
    END IF;
    DROP INDEX IF EXISTS public.idx_detection_rules_unique_name_per_repo;
    CREATE UNIQUE INDEX IF NOT EXISTS idx_detection_rules_unique_name_per_repo
        ON public.detection_rules (name, source_repository_id)
        WHERE source_repository_id IS NOT NULL AND archived = FALSE;
END
$nan3816_archive_name_reuse$;
