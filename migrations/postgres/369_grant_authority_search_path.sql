-- NAN-3917: nested triggers inherit the caller function's search_path.
-- Migration 368 pins add_user_to_everyone_group to pg_catalog,pg_temp;
-- its user_groups INSERT therefore hid migration 272's unqualified singleton.
-- Pin name resolution on the trigger itself, retaining its body, owner, ACL,
-- invoker security, statement triggers and transactional row locking.
-- ALTER (rather than replacing the body) also preserves the enterprise
-- last_grant_change_version update installed by overlay migration 9000159
-- when core migrations run on an already-activated hosted database.
-- The enterprise overlay already fully qualifies this function's body and
-- pins its path in 9000077/9000159; fresh hosted databases apply that overlay
-- after the same core chain, so no separate enterprise fix is necessary.
-- Activated hosted databases can own ACL helpers through the managed owner.
SET LOCAL lock_timeout = '5s';
DO $grant_path$
DECLARE owner_role NAME; owner_token INTEGER := 0;
BEGIN
    IF to_regproc('nano_shared.begin_managed_owner_bootstrap') IS NOT NULL THEN
        SELECT contract.owner_role INTO owner_role
          FROM nano_shared.rls_role_contract contract WHERE singleton AND enabled;
        IF owner_role IS NOT NULL THEN
            owner_token := nano_shared.begin_managed_owner_bootstrap(owner_role);
        END IF;
    END IF;
ALTER FUNCTION public.bump_grant_authority_version()
    SET search_path = pg_catalog, public, pg_temp;

-- Audit of the other core grant-write trigger chains: roles invokes the
-- reserved-name guard and ACL label sync; role_permissions invokes the ACL
-- lock/assert pair. Label sync can in turn fire playbook_permissions triggers.
-- These older helpers also use unqualified relations/function calls. Pin the
-- entire reachable chain without changing its lock order or deferred checks.
ALTER FUNCTION public.normalize_reserved_role_name(text)
    SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION public.guard_reserved_role_name_write()
    SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION public.sync_playbook_acl_role_label()
    SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION public.normalize_playbook_permission_role_key()
    SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION public.lock_playbook_acl_compatibility_write()
    SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION public.assert_playbook_acl_compatibility_write()
    SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION public.lock_playbook_acl_role_permission_write()
    SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION public.assert_playbook_acl_role_permission_write()
    SET search_path = pg_catalog, public, pg_temp;

-- update_updated_at_column only assigns NEW.updated_at using pg_catalog.now.
-- Both functions installed/replaced by 368 qualify all relation references;
-- the provenance table has no user triggers. No further core helpers need DDL.

    IF owner_role IS NOT NULL THEN
        PERFORM nano_shared.end_managed_owner_bootstrap(owner_role, owner_token);
    END IF;
END $grant_path$;
