-- NAN-3917: pin search_path on the grant-authority trigger chain.
--
-- These trigger functions use unqualified relations and function calls and
-- run with the CALLER's search_path. A nested trigger also inherits the
-- calling function's path, so a caller whose path omits or shadows `public`
-- can make them resolve the wrong objects (or none). Pin name resolution on
-- each function. ALTER (rather than replacing the body) keeps each body,
-- owner, ACL, invoker security, statement triggers and row locking as-is.
--
-- Chains covered: every grant table fires bump_grant_authority_version (272);
-- roles invokes the reserved-name guard and ACL label sync, role_permissions
-- invokes the ACL lock/assert pair, and label sync can fire the
-- playbook_permissions normalizer (267/269).
--
-- Ported for the single-tenant ClickHouse product (clickhouse/dev) from main's
-- 369, without the hosted managed-owner bootstrap. The enterprise overlay
-- re-creates the 267/269 helpers (9000040/9000044), which resets their SET
-- clauses on a fresh enterprise install, so overlay 9000071 re-applies the
-- same pins.
SET LOCAL lock_timeout = '5s';

ALTER FUNCTION public.bump_grant_authority_version()
    SET search_path = pg_catalog, public, pg_temp;
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
