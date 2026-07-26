-- NAN-2097: complete the rolling-deployment boundary after migration 268.
--
-- Migration 268 is already deployed and hash-tracked, so later review fixes
-- live here rather than rewriting its checksum. This migration:
--
--   * normalizes every Rust-trimmable spelling of the two reserved synthetic
--     role names (268's plain btrim handled ASCII spaces only);
--   * clears any unadministrable ACL an old replica wrote in the narrow window
--     between the schema migration and this guard; and
--   * enforces the administrability invariant for legacy INSERT, UPDATE and
--     DELETE statements on both ACLs and role capabilities while old and new
--     API replicas overlap.

CREATE OR REPLACE FUNCTION normalize_reserved_role_name(candidate TEXT)
RETURNS TEXT
LANGUAGE SQL
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
    -- Rust lowercasing is locale-independent. ASCII translation avoids the
    -- Turkish-I behavior of PostgreSQL lower(); Kelvin sign is the one
    -- non-ASCII simple lowercase mapping needed to reach either reserved name.
    SELECT translate(
        replace(
            btrim(
                candidate,
                U&'\0009\000A\000B\000C\000D\0020\0085\00A0\1680\2000\2001\2002\2003\2004\2005\2006\2007\2008\2009\200A\2028\2029\202F\205F\3000'
            ),
            U&'\212A',
            'k'
        ),
        'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
        'abcdefghijklmnopqrstuvwxyz'
    )
$$;

CREATE OR REPLACE FUNCTION guard_reserved_role_name_write()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    old_reserved BOOLEAN := FALSE;
    new_reserved BOOLEAN;
BEGIN
    new_reserved :=
        normalize_reserved_role_name(NEW.name)
        IN ('api_key', 'demo_analyst');

    IF TG_OP = 'INSERT' THEN
        IF new_reserved THEN
            RAISE EXCEPTION
                'Role name % is reserved for a synthetic principal',
                NEW.name
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'roles_reserved_name_check';
        END IF;
        RETURN NEW;
    END IF;

    -- Description/timestamp edits to the deliberately retained exact legacy
    -- demo role remain valid. Renaming either into or out of the synthetic
    -- namespace does not: old replicas must observe the same boundary as new
    -- application code throughout a rolling deployment.
    IF NEW.name IS NOT DISTINCT FROM OLD.name THEN
        RETURN NEW;
    END IF;

    old_reserved :=
        normalize_reserved_role_name(OLD.name)
        IN ('api_key', 'demo_analyst');

    IF old_reserved OR new_reserved THEN
        RAISE EXCEPTION
            'Role name % is reserved for a synthetic principal',
            CASE WHEN new_reserved THEN NEW.name ELSE OLD.name END
            USING ERRCODE = 'check_violation',
                  CONSTRAINT = 'roles_reserved_name_check';
    END IF;

    RETURN NEW;
END
$$;

CREATE OR REPLACE FUNCTION lock_playbook_acl_compatibility_write()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    affected_playbook_ids UUID[] := ARRAY[]::UUID[];
    affected_role_ids     UUID[] := ARRAY[]::UUID[];
    affected_role_names   TEXT[] := ARRAY[]::TEXT[];
BEGIN
    IF TG_OP <> 'INSERT' THEN
        affected_playbook_ids :=
            array_append(affected_playbook_ids, OLD.playbook_id);
        IF OLD.role_id IS NOT NULL THEN
            affected_role_ids := array_append(affected_role_ids, OLD.role_id);
        ELSE
            affected_role_names := array_append(affected_role_names, OLD.role);
        END IF;
    END IF;
    IF TG_OP <> 'DELETE' THEN
        affected_playbook_ids :=
            array_append(affected_playbook_ids, NEW.playbook_id);
        IF NEW.role_id IS NOT NULL THEN
            affected_role_ids := array_append(affected_role_ids, NEW.role_id);
        ELSE
            affected_role_names := array_append(affected_role_names, NEW.role);
        END IF;
    END IF;

    -- Match the new repository's real-role -> playbook lock order. The name
    -- lookup covers an old binary whose INSERT has not yet passed through the
    -- role_id normalization trigger. Synthetic principals deliberately have no
    -- role row to lock.
    PERFORM 1
      FROM roles
     WHERE id = ANY(affected_role_ids)
        OR (
            name = ANY(affected_role_names)
            AND name <> ALL(ARRAY['api_key', 'demo_analyst']::TEXT[])
        )
     ORDER BY id
     FOR SHARE;

    PERFORM 1
      FROM playbooks
     WHERE id = ANY(affected_playbook_ids)
     ORDER BY id
     FOR UPDATE;

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END
$$;

CREATE OR REPLACE FUNCTION assert_playbook_acl_compatibility_write()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    affected_playbook_ids UUID[] := ARRAY[]::UUID[];
    affected_playbook_id  UUID;
    has_acl              BOOLEAN;
    has_administrator    BOOLEAN;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        affected_playbook_ids :=
            array_append(affected_playbook_ids, OLD.playbook_id);
    END IF;
    IF TG_OP <> 'DELETE' THEN
        affected_playbook_ids :=
            array_append(affected_playbook_ids, NEW.playbook_id);
    END IF;

    FOREACH affected_playbook_id IN ARRAY affected_playbook_ids
    LOOP
        SELECT
            EXISTS (
                SELECT 1
                  FROM playbook_permissions
                 WHERE playbook_id = affected_playbook_id
            ),
            EXISTS (
                SELECT 1
                  FROM playbook_permissions pp
                  JOIN role_permissions rp ON rp.role_id = pp.role_id
                 WHERE pp.playbook_id = affected_playbook_id
                   AND pp.can_view
                   AND pp.can_edit
                   AND rp.permission_id = 'playbooks:manage'
            )
          INTO has_acl, has_administrator;

        IF has_acl AND NOT has_administrator THEN
            RAISE EXCEPTION
                'Refusing to leave playbook % with an ACL nobody can administer',
                affected_playbook_id
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'playbook_permissions_administrable_check';
        END IF;
    END LOOP;

    RETURN NULL;
END
$$;

CREATE OR REPLACE FUNCTION lock_playbook_acl_role_permission_write()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    affected_role_ids UUID[] := ARRAY[]::UUID[];
    atomic_replace     BOOLEAN := FALSE;
    removes_manage     BOOLEAN := FALSE;
    would_orphan       BOOLEAN := FALSE;
BEGIN
    IF TG_OP <> 'INSERT'
       AND OLD.permission_id = 'playbooks:manage' THEN
        affected_role_ids := array_append(affected_role_ids, OLD.role_id);
    END IF;
    IF TG_OP <> 'DELETE'
       AND NEW.permission_id = 'playbooks:manage' THEN
        affected_role_ids := array_append(affected_role_ids, NEW.role_id);
    END IF;

    IF cardinality(affected_role_ids) > 0 THEN
        -- A brand-new ACL is not visible through playbook_permissions yet, so
        -- the role row is the common serialization point with ACL writers.
        PERFORM 1
          FROM roles
         WHERE id = ANY(affected_role_ids)
         ORDER BY id
         FOR UPDATE;

        PERFORM 1
          FROM playbooks p
         WHERE EXISTS (
             SELECT 1
               FROM playbook_permissions pp
              WHERE pp.playbook_id = p.id
                AND pp.role_id = ANY(affected_role_ids)
         )
         ORDER BY p.id
         FOR UPDATE;
    END IF;

    IF TG_OP = 'DELETE' THEN
        removes_manage := OLD.permission_id = 'playbooks:manage';
    ELSIF TG_OP = 'UPDATE' THEN
        removes_manage :=
            OLD.permission_id = 'playbooks:manage'
            AND (
                NEW.permission_id IS DISTINCT FROM OLD.permission_id
                OR NEW.role_id IS DISTINCT FROM OLD.role_id
            );
    END IF;

    IF removes_manage THEN
        atomic_replace :=
            COALESCE(
                current_setting(
                    'nanosiem.atomic_role_permission_replace',
                    TRUE
                ),
                ''
            ) = 'on';

        IF NOT atomic_replace THEN
            -- Shipped replicas replace a role's permissions as separate
            -- autocommit DELETE and INSERT statements. If this DELETE would
            -- orphan an ACL, retain only the manage row: a keep-and-reinsert
            -- update then succeeds via ON CONFLICT, while an intended removal
            -- fails closed and is visible in the response's permission list.
            SELECT EXISTS (
                SELECT 1
                  FROM playbook_permissions affected
                 WHERE affected.role_id = OLD.role_id
                   AND NOT EXISTS (
                       SELECT 1
                         FROM playbook_permissions administrator
                         JOIN role_permissions rp
                           ON rp.role_id = administrator.role_id
                        WHERE administrator.playbook_id = affected.playbook_id
                          AND administrator.can_view
                          AND administrator.can_edit
                          AND rp.permission_id = 'playbooks:manage'
                          AND rp.role_id <> OLD.role_id
                   )
                   AND NOT (
                       TG_OP = 'UPDATE'
                       AND NEW.permission_id = 'playbooks:manage'
                       AND NEW.role_id IS DISTINCT FROM OLD.role_id
                       AND EXISTS (
                           SELECT 1
                             FROM playbook_permissions incoming
                            WHERE incoming.playbook_id = affected.playbook_id
                              AND incoming.role_id = NEW.role_id
                              AND incoming.can_view
                              AND incoming.can_edit
                       )
                   )
            )
              INTO would_orphan;

            IF would_orphan THEN
                RAISE WARNING
                    'NAN-2097: retained playbooks:manage on role % because a legacy autocommit delete would orphan a playbook ACL',
                    OLD.role_id;
                RETURN NULL;
            END IF;
        END IF;
    END IF;

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END
$$;

CREATE OR REPLACE FUNCTION assert_playbook_acl_role_permission_write()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    affected_role_ids    UUID[] := ARRAY[]::UUID[];
    affected_playbook_id UUID;
    has_administrator    BOOLEAN;
BEGIN
    IF TG_OP <> 'INSERT'
       AND OLD.permission_id = 'playbooks:manage' THEN
        affected_role_ids := array_append(affected_role_ids, OLD.role_id);
    END IF;
    IF TG_OP <> 'DELETE'
       AND NEW.permission_id = 'playbooks:manage' THEN
        affected_role_ids := array_append(affected_role_ids, NEW.role_id);
    END IF;

    FOR affected_playbook_id IN
        SELECT DISTINCT pp.playbook_id
          FROM playbook_permissions pp
         WHERE pp.role_id = ANY(affected_role_ids)
         ORDER BY pp.playbook_id
    LOOP
        SELECT EXISTS (
            SELECT 1
              FROM playbook_permissions administrator
              JOIN role_permissions rp
                ON rp.role_id = administrator.role_id
             WHERE administrator.playbook_id = affected_playbook_id
               AND administrator.can_view
               AND administrator.can_edit
               AND rp.permission_id = 'playbooks:manage'
        )
          INTO has_administrator;

        IF NOT has_administrator THEN
            RAISE EXCEPTION
                'Refusing to leave playbook % with an ACL nobody can administer',
                affected_playbook_id
                USING ERRCODE = 'check_violation',
                      CONSTRAINT = 'playbook_permissions_administrable_check';
        END IF;
    END LOOP;

    RETURN NULL;
END
$$;

DO $$
DECLARE
    colliding_role        RECORD;
    replacement_name      TEXT;
    replacement_taken     BOOLEAN := FALSE;
    has_acl               BOOLEAN := FALSE;
    cleared_acl_entries   BIGINT := 0;
    lock_attempts         INTEGER := 0;
BEGIN
    IF to_regclass('public.roles') IS NULL THEN
        RETURN;
    END IF;

    has_acl := to_regclass('public.playbook_permissions') IS NOT NULL;

    -- Freeze every legacy write path before inspecting or normalizing state.
    -- Taking these locks before the cleanup snapshot is essential: installing
    -- the triggers after DELETE without a table lock lets a writer waiting on
    -- trigger DDL commit an invalid row that the cleanup never saw.
    IF has_acl THEN
        -- PostgreSQL takes a DML target's ROW EXCLUSIVE table lock before its
        -- row trigger can take our role -> playbook locks. Never wait while
        -- holding only the parent half: acquire the whole set with NOWAIT in a
        -- subtransaction, whose rollback releases partial locks before retry.
        LOOP
            lock_attempts := lock_attempts + 1;
            BEGIN
                LOCK TABLE roles, playbooks
                    IN EXCLUSIVE MODE NOWAIT;
                LOCK TABLE role_permissions, playbook_permissions
                    IN SHARE ROW EXCLUSIVE MODE NOWAIT;
                EXIT;
            EXCEPTION
                WHEN lock_not_available OR deadlock_detected THEN
                    IF lock_attempts >= 600 THEN
                        RAISE EXCEPTION
                            'NAN-2097: could not quiesce ACL writers after % attempts',
                            lock_attempts
                            USING ERRCODE = 'lock_not_available';
                    END IF;
                    PERFORM pg_sleep(0.05);
            END;
        END LOOP;
    ELSE
        LOCK TABLE roles IN EXCLUSIVE MODE;
    END IF;

    -- A previous application of this idempotent migration may already have
    -- installed the guard. Remove it while normalizing historical collisions,
    -- then recreate it before releasing the table lock.
    DROP TRIGGER IF EXISTS guard_reserved_role_name_write ON roles;

    -- Exact demo_analyst remains the deliberate restricted, name-derived legacy
    -- principal. Every case/Unicode-whitespace variant is an ordinary real role
    -- and must move out of the runtime-reserved namespace.
    FOR colliding_role IN
        SELECT id,
               name,
               CASE normalize_reserved_role_name(name)
                   WHEN 'api_key' THEN 'api_key'
                   ELSE 'demo_analyst'
               END AS reserved_prefix
          FROM roles
         WHERE normalize_reserved_role_name(name) = 'api_key'
            OR (
                normalize_reserved_role_name(name) = 'demo_analyst'
                AND name <> 'demo_analyst'
            )
         ORDER BY id
    LOOP
        replacement_name :=
            colliding_role.reserved_prefix || '_legacy_'
            || replace(colliding_role.id::text, '-', '');
        LOOP
            SELECT EXISTS (SELECT 1 FROM roles WHERE name = replacement_name)
              INTO replacement_taken;
            IF has_acl AND NOT replacement_taken THEN
                SELECT EXISTS (
                    SELECT 1 FROM playbook_permissions WHERE role = replacement_name
                ) INTO replacement_taken;
            END IF;
            EXIT WHEN NOT replacement_taken;
            replacement_name := replacement_name || '_';
        END LOOP;

        UPDATE roles
           SET name = replacement_name,
               updated_at = NOW()
         WHERE id = colliding_role.id;

        IF has_acl THEN
            UPDATE playbook_permissions
               SET role = replacement_name,
                   updated_at = NOW()
             WHERE role_id = colliding_role.id;
        END IF;

        RAISE NOTICE
            'NAN-2097: renamed legacy real reserved-namespace role % (%) to %',
            colliding_role.name, colliding_role.id, replacement_name;
    END LOOP;

    CREATE TRIGGER guard_reserved_role_name_write
        BEFORE INSERT OR UPDATE OF name
        ON roles
        FOR EACH ROW
        EXECUTE FUNCTION guard_reserved_role_name_write();

    IF NOT has_acl THEN
        RETURN;
    END IF;

    -- An old replica could have committed this state after 268 normalized the
    -- historical rows but before this migration installed the compatibility
    -- trigger. Restore the same safe baseline before enforcement begins.
    WITH removed AS (
        DELETE FROM playbook_permissions pp
         WHERE NOT EXISTS (
             SELECT 1
               FROM playbook_permissions administrator
               JOIN role_permissions rp ON rp.role_id = administrator.role_id
              WHERE administrator.playbook_id = pp.playbook_id
                AND administrator.can_view
                AND administrator.can_edit
                AND rp.permission_id = 'playbooks:manage'
         )
        RETURNING 1
    )
    SELECT COUNT(*) INTO cleared_acl_entries FROM removed;

    DROP TRIGGER IF EXISTS lock_playbook_acl_compatibility_write
        ON playbook_permissions;
    CREATE TRIGGER lock_playbook_acl_compatibility_write
        BEFORE INSERT OR UPDATE OR DELETE
        ON playbook_permissions
        FOR EACH ROW
        EXECUTE FUNCTION lock_playbook_acl_compatibility_write();

    DROP TRIGGER IF EXISTS assert_playbook_acl_compatibility_write
        ON playbook_permissions;
    CREATE CONSTRAINT TRIGGER assert_playbook_acl_compatibility_write
        AFTER INSERT OR UPDATE OR DELETE
        ON playbook_permissions
        DEFERRABLE INITIALLY DEFERRED
        FOR EACH ROW
        EXECUTE FUNCTION assert_playbook_acl_compatibility_write();

    DROP TRIGGER IF EXISTS lock_playbook_acl_role_permission_write
        ON role_permissions;
    CREATE TRIGGER lock_playbook_acl_role_permission_write
        BEFORE INSERT OR UPDATE OR DELETE
        ON role_permissions
        FOR EACH ROW
        EXECUTE FUNCTION lock_playbook_acl_role_permission_write();

    DROP TRIGGER IF EXISTS assert_playbook_acl_role_permission_write
        ON role_permissions;
    CREATE CONSTRAINT TRIGGER assert_playbook_acl_role_permission_write
        AFTER INSERT OR UPDATE OR DELETE
        ON role_permissions
        DEFERRABLE INITIALLY DEFERRED
        FOR EACH ROW
        EXECUTE FUNCTION assert_playbook_acl_role_permission_write();

    IF cleared_acl_entries > 0 THEN
        RAISE NOTICE
            'NAN-2097: cleared % entries written into unadministrable ACLs during rollout',
            cleared_acl_entries;
    END IF;
END
$$;
