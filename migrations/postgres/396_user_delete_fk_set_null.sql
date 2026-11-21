-- no-transaction
-- NAN-5721: deleting a user must neither fail nor destroy shared records.
--
-- 1) NO ACTION references made the delete FAIL (HTTP 500). For example,
--    `siem_health_reports.triggered_by` raised
--    "violates foreign key constraint siem_health_reports_triggered_by_fkey"
--    for anyone who had ever run a SIEM health check.
--
-- 2) CASCADE references made the delete DESTROY investigation evidence:
--    every case-notebook entry the user wrote, every handoff they sent, and
--    every notebook they owned (including a case notebook, with all of its
--    entries from every analyst).
--
-- These records belong to the platform or the case, not to the person who
-- wrote them, so their author column becomes ON DELETE SET NULL (nullable).
-- That matches cases, case_*, api_keys, dashboards, saved_searches and
-- detection_rule_versions (264). The audit log keeps who did what, and the
-- UI renders a NULL author as "deleted user".
--
--   was NO ACTION:
--     siem_health_reports.triggered_by
--     siem_health_finding_suppressions.created_by      (was NOT NULL)
--     siem_health_finding_suppressions.deactivated_by
--     observability_slos.created_by
--     observability_synthetic_checks.created_by
--     observability_metric_monitors.created_by
--     enrichment_marketplace_repos.created_by
--     gdpr_anonymization_requests.requested_by         (was NOT NULL)
--     custom_enrichments.created_by                    (enterprise, was NOT NULL)
--     custom_enrichment_versions.created_by            (enterprise, was NOT NULL)
--     custom_enrichment_runs.created_by                (enterprise)
--     tuning_logs.reverted_by                          (enterprise)
--   was CASCADE:
--     notebook_entries.created_by                      (enterprise, was NOT NULL)
--     case_handoffs.source_user_id                     (enterprise, was NOT NULL)
--     feedback.user_id                                 (was NOT NULL; open bug
--                                                       reports stay with admins)
--
-- notebooks.owner_id stays NOT NULL + CASCADE: ownership drives notebook
-- authorization (sharing, visibility, delete are owner-only), so it is never
-- left NULL. Instead, a BEFORE DELETE trigger on users (below) hands every
-- notebook that is not purely personal to a new owner before the cascade can
-- reach it:
--   * a CASE notebook goes to the case's assignee, or to the system AI user
--     (00000000-0000-0000-0000-000000000099) when the case is unassigned or
--     assigned to the user being deleted. This is the ownership model of
--     NAN-5690: an unassigned case's notebook is system-owned, its lifecycle
--     is governed by the case, and the next assignee takes it over.
--   * a STANDALONE notebook is kept when anyone else uses it: visibility is
--     not 'private', OR it has a share (user or group) to someone else, OR
--     another user wrote an entry in it. It goes to a person who can manage
--     it, in this order: an active user with an 'edit' share, an active user
--     with any share, the active user who most recently wrote in it, then an
--     active administrator. Standalone notebook management has no admin
--     override, so handing it to the system AI user (which cannot sign in)
--     would leave it undeletable and unshareable; a human heir keeps every
--     existing owner-only control usable.
--   * only a truly solo notebook (private, no shares, every entry by the
--     owner or the system AI) is personal scratch space and cascades.
-- When no heir exists (no system AI user row, or no active administrator for
-- a standalone notebook), the trigger RAISES foreign_key_violation and the
-- delete is refused (409 user_still_referenced): evidence is never destroyed
-- silently.
-- A trigger, not application code, because more than one path deletes users
-- (the users API and demo-session teardown) and evidence must survive all of
-- them. Demo teardown removes what demo visitors wrote before it deletes them.
--
-- CASCADE references deliberately KEPT (personal or identity data, no value
-- once the user is gone): sessions, user_groups, search_history,
-- tuning_notifications, notifications, notebook_tabs, notebook_shares
-- (grants TO the deleted user), user_recent_activity, onboarding_progress,
-- oidc_group_grant_sources, scim_users, scim_group_members,
-- case_saved_searches (a bookmarked filter for the cases list page: a query
-- string, no case data, owner-only edit rights, so an orphan could not be
-- edited or removed), report_definitions (scheduled reports execute as
-- their owner; like the user's API keys, a departed user's schedules stop),
-- and, on demo deployments only, demo.sessions.user_id (the ephemeral demo
-- user's own session).
--
-- Forward-only, idempotent and light on locks (`-- no-transaction`, with
-- explicit COMMITs between phases so no lock is held across the whole file):
--   * tables absent on this edition are skipped (several are enterprise-only;
--     the enterprise overlay re-runs the FK phases as 9000139 so tables it
--     creates on a fresh enterprise install are fixed too);
--   * DROP NOT NULL only runs on columns that are still NOT NULL;
--   * a constraint is found by (table, column) in pg_constraint, not by name,
--     and replaced under its existing name ONLY when it is not already
--     ON DELETE SET NULL. It is re-added NOT VALID (every existing value
--     already satisfied the identical reference, so no scan under the
--     exclusive lock), then validated in a separate step that takes only
--     SHARE UPDATE EXCLUSIVE and does not block reads or writes;
--   * the trigger function is CREATE OR REPLACE and checks at run time that
--     the notebook tables exist, so it is safe on the open edition.

-- Phase 1: make the author columns nullable and their references SET NULL
-- (NOT VALID: no table scan while the constraint swap holds its lock).
DO $$
DECLARE
    target RECORD;
    fk RECORD;
BEGIN
    FOR target IN
        SELECT * FROM (VALUES
            ('siem_health_reports', 'triggered_by'),
            ('siem_health_finding_suppressions', 'created_by'),
            ('siem_health_finding_suppressions', 'deactivated_by'),
            ('observability_slos', 'created_by'),
            ('observability_synthetic_checks', 'created_by'),
            ('observability_metric_monitors', 'created_by'),
            ('enrichment_marketplace_repos', 'created_by'),
            ('gdpr_anonymization_requests', 'requested_by'),
            ('custom_enrichments', 'created_by'),
            ('custom_enrichment_versions', 'created_by'),
            ('custom_enrichment_runs', 'created_by'),
            ('tuning_logs', 'reverted_by'),
            ('notebook_entries', 'created_by'),
            ('case_handoffs', 'source_user_id'),
            ('feedback', 'user_id')
        ) AS t(tbl, col)
    LOOP
        IF to_regclass(format('public.%I', target.tbl)) IS NULL THEN
            CONTINUE;
        END IF;

        IF EXISTS (
            SELECT 1 FROM pg_attribute
             WHERE attrelid = format('public.%I', target.tbl)::regclass
               AND attname = target.col
               AND NOT attisdropped
               AND attnotnull
        ) THEN
            EXECUTE format('ALTER TABLE public.%I ALTER COLUMN %I DROP NOT NULL',
                           target.tbl, target.col);
        END IF;

        FOR fk IN
            SELECT c.conname
              FROM pg_constraint c
              JOIN pg_attribute a
                ON a.attrelid = c.conrelid AND a.attnum = c.conkey[1]
             WHERE c.contype = 'f'
               AND c.conrelid = format('public.%I', target.tbl)::regclass
               AND c.confrelid = 'public.users'::regclass
               AND array_length(c.conkey, 1) = 1
               AND a.attname = target.col
               AND c.confdeltype <> 'n'
        LOOP
            EXECUTE format('ALTER TABLE public.%I DROP CONSTRAINT %I',
                           target.tbl, fk.conname);
            EXECUTE format(
                'ALTER TABLE public.%I ADD CONSTRAINT %I FOREIGN KEY (%I) '
                'REFERENCES public.users(id) ON DELETE SET NULL NOT VALID',
                target.tbl, fk.conname, target.col);
        END LOOP;
    END LOOP;
END $$;

-- A multi-statement migration runs as ONE implicit transaction even with
-- `-- no-transaction`; COMMIT ends phase 1 so its short exclusive locks are
-- released before validation scans the tables.
COMMIT;

-- Phase 2: validate the references phase 1 re-added NOT VALID (SHARE UPDATE
-- EXCLUSIVE on the child, ROW SHARE on users: reads and writes continue).
DO $$
DECLARE
    fk RECORD;
BEGIN
    FOR fk IN
        SELECT c.conrelid::regclass AS tbl, c.conname
          FROM (VALUES
            ('siem_health_reports', 'triggered_by'),
            ('siem_health_finding_suppressions', 'created_by'),
            ('siem_health_finding_suppressions', 'deactivated_by'),
            ('observability_slos', 'created_by'),
            ('observability_synthetic_checks', 'created_by'),
            ('observability_metric_monitors', 'created_by'),
            ('enrichment_marketplace_repos', 'created_by'),
            ('gdpr_anonymization_requests', 'requested_by'),
            ('custom_enrichments', 'created_by'),
            ('custom_enrichment_versions', 'created_by'),
            ('custom_enrichment_runs', 'created_by'),
            ('tuning_logs', 'reverted_by'),
            ('notebook_entries', 'created_by'),
            ('case_handoffs', 'source_user_id'),
            ('feedback', 'user_id')
        ) AS t(tbl, col)
          JOIN pg_constraint c
            ON c.conrelid = to_regclass(format('public.%I', t.tbl))
          JOIN pg_attribute a
            ON a.attrelid = c.conrelid AND a.attnum = c.conkey[1] AND a.attname = t.col
         WHERE c.contype = 'f'
           AND c.confrelid = 'public.users'::regclass
           AND NOT c.convalidated
    LOOP
        EXECUTE format('ALTER TABLE %s VALIDATE CONSTRAINT %I', fk.tbl, fk.conname);
    END LOOP;
END $$;

COMMIT;

-- Hand every notebook someone else uses to a new owner before the owner's row
-- is deleted (see the header for the rules).
CREATE OR REPLACE FUNCTION public.nanosiem_preserve_notebooks_on_user_delete()
RETURNS trigger
LANGUAGE plpgsql
AS $fn$
DECLARE
    system_ai CONSTANT uuid := '00000000-0000-0000-0000-000000000099';
    admin_role CONSTANT uuid := '00000000-0000-0000-0000-000000000001';
    nb RECORD;
    heir uuid;
BEGIN
    IF to_regclass('public.notebooks') IS NULL
       OR to_regclass('public.cases') IS NULL
       OR OLD.id = system_ai THEN
        RETURN OLD;
    END IF;

    FOR nb IN
        SELECT n.id, n.case_id
          FROM public.notebooks n
         WHERE n.owner_id = OLD.id
           AND (
                n.case_id IS NOT NULL
             OR n.visibility <> 'private'
             OR EXISTS (
                    SELECT 1 FROM public.notebook_shares ns
                     WHERE ns.notebook_id = n.id
                       AND (ns.shared_with_user_id IS NULL
                            OR ns.shared_with_user_id <> OLD.id))
             OR EXISTS (
                    SELECT 1 FROM public.notebook_entries e
                     WHERE e.notebook_id = n.id
                       AND (e.created_by IS NULL
                            OR (e.created_by <> OLD.id AND e.created_by <> system_ai)))
           )
         FOR UPDATE
    LOOP
        IF nb.case_id IS NOT NULL THEN
            SELECT COALESCE(
                       (SELECT c.assigned_to
                          FROM public.cases c
                         WHERE c.id = nb.case_id
                           AND c.assigned_to IS NOT NULL
                           AND c.assigned_to <> OLD.id),
                       (SELECT u.id FROM public.users u WHERE u.id = system_ai))
              INTO heir;
        ELSE
            SELECT COALESCE(
                       (SELECT ns.shared_with_user_id
                          FROM public.notebook_shares ns
                          JOIN public.users u ON u.id = ns.shared_with_user_id
                         WHERE ns.notebook_id = nb.id
                           AND ns.shared_with_user_id <> OLD.id
                           AND u.status = 'active'
                         ORDER BY (ns.permission = 'edit') DESC, ns.created_at, ns.id
                         LIMIT 1),
                       (SELECT e.created_by
                          FROM public.notebook_entries e
                          JOIN public.users u ON u.id = e.created_by
                         WHERE e.notebook_id = nb.id
                           AND e.created_by NOT IN (OLD.id, system_ai)
                           AND u.status = 'active'
                         ORDER BY e.created_at DESC, e.id DESC
                         LIMIT 1),
                       (SELECT u.id
                          FROM public.users u
                          JOIN public.user_groups ug ON ug.user_id = u.id
                          JOIN public.group_roles gr ON gr.group_id = ug.group_id
                         WHERE gr.role_id = admin_role
                           AND u.status = 'active'
                           AND u.id <> OLD.id
                         ORDER BY u.created_at, u.id
                         LIMIT 1))
              INTO heir;
        END IF;

        IF heir IS NULL THEN
            RAISE EXCEPTION 'cannot delete user %: notebook % is still used by others and has no one to take it over', OLD.id, nb.id
                USING ERRCODE = 'foreign_key_violation',
                      CONSTRAINT = 'preserve_notebooks_on_user_delete';
        END IF;

        UPDATE public.notebooks SET owner_id = heir WHERE id = nb.id;
    END LOOP;

    RETURN OLD;
END
$fn$;

DO $$
BEGIN
    DROP TRIGGER IF EXISTS preserve_notebooks_on_user_delete ON public.users;
    CREATE TRIGGER preserve_notebooks_on_user_delete
        BEFORE DELETE ON public.users
        FOR EACH ROW
        EXECUTE FUNCTION public.nanosiem_preserve_notebooks_on_user_delete();
END $$;
