-- NAN-2134: make privilege-grant validation transactionally authoritative.
--
-- Grant endpoints first resolve the caller's current PostgreSQL authority and
-- the requested role/group entitlements, then perform the assignment. A
-- cached/stale check or a concurrent entitlement edit must not turn that
-- check-then-act gap into a persisted privilege grant.
--
-- This singleton generation is the common serialization point. Every table
-- that can change current grant authority or a granted entitlement advances
-- it. New writers validate against a generation and lock the singleton row in
-- the same transaction as their write. Old rolling-deployment writers still
-- advance it through these triggers.

CREATE TABLE IF NOT EXISTS grant_authority_version (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    version BIGINT NOT NULL DEFAULT 1
);

INSERT INTO grant_authority_version (singleton, version)
VALUES (TRUE, 1)
ON CONFLICT (singleton) DO NOTHING;

CREATE OR REPLACE FUNCTION bump_grant_authority_version()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE grant_authority_version
       SET version = version + 1
     WHERE singleton = TRUE;
    RETURN NULL;
END
$$;

DROP TRIGGER IF EXISTS bump_grant_authority_roles ON roles;
CREATE TRIGGER bump_grant_authority_roles
AFTER INSERT OR UPDATE OF name OR DELETE ON roles
FOR EACH STATEMENT EXECUTE FUNCTION bump_grant_authority_version();

DROP TRIGGER IF EXISTS bump_grant_authority_role_permissions ON role_permissions;
CREATE TRIGGER bump_grant_authority_role_permissions
AFTER INSERT OR UPDATE OR DELETE ON role_permissions
FOR EACH STATEMENT EXECUTE FUNCTION bump_grant_authority_version();

DROP TRIGGER IF EXISTS bump_grant_authority_group_roles ON group_roles;
CREATE TRIGGER bump_grant_authority_group_roles
AFTER INSERT OR UPDATE OR DELETE ON group_roles
FOR EACH STATEMENT EXECUTE FUNCTION bump_grant_authority_version();

DROP TRIGGER IF EXISTS bump_grant_authority_user_groups ON user_groups;
CREATE TRIGGER bump_grant_authority_user_groups
AFTER INSERT OR UPDATE OR DELETE ON user_groups
FOR EACH STATEMENT EXECUTE FUNCTION bump_grant_authority_version();

DROP TRIGGER IF EXISTS bump_grant_authority_restricted_sources ON restricted_source_types;
CREATE TRIGGER bump_grant_authority_restricted_sources
AFTER INSERT OR UPDATE OR DELETE ON restricted_source_types
FOR EACH STATEMENT EXECUTE FUNCTION bump_grant_authority_version();

DROP TRIGGER IF EXISTS bump_grant_authority_source_grants ON source_type_grants;
CREATE TRIGGER bump_grant_authority_source_grants
AFTER INSERT OR UPDATE OR DELETE ON source_type_grants
FOR EACH STATEMENT EXECUTE FUNCTION bump_grant_authority_version();

DROP TRIGGER IF EXISTS bump_grant_authority_api_keys ON api_keys;
CREATE TRIGGER bump_grant_authority_api_keys
AFTER INSERT OR UPDATE OF permissions, enabled, expires_at, created_by OR DELETE ON api_keys
FOR EACH STATEMENT EXECUTE FUNCTION bump_grant_authority_version();

DROP TRIGGER IF EXISTS bump_grant_authority_users ON users;
CREATE TRIGGER bump_grant_authority_users
AFTER INSERT OR UPDATE OF status OR DELETE ON users
FOR EACH STATEMENT EXECUTE FUNCTION bump_grant_authority_version();

COMMENT ON TABLE grant_authority_version IS
    'Monotonic serialization generation for authoritative privilege-grant checks (NAN-2134).';
