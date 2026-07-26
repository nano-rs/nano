-- NAN-2097: expand the playbook ACL schema before migration 268 changes its
-- key semantics, so old and new API replicas can overlap during a rolling
-- deployment.
--
-- Old binaries use:
--
--   ON CONFLICT (playbook_id, role)
--
-- Migration 268 replaces that label key with a stable role_id key. Dropping
-- the old primary key before every old replica has drained makes its upsert
-- fail with PostgreSQL 42P10. More importantly, an old replica could insert a
-- post-migration row with role_id NULL; new ACL enforcement would treat that
-- unresolved row as authoritative and hide the playbook.
--
-- This expand migration deliberately sorts before 268. It retains a full
-- compatibility key, resolves role_id for legacy writes in a trigger, rejects
-- unknown labels rather than creating an unmatchable ACL, and keeps display
-- labels synchronized across role renames. The stable partial indexes added by
-- 268 remain the keys used by the new binary.

CREATE OR REPLACE FUNCTION normalize_playbook_permission_role_key()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    resolved_role_id UUID;
    resolved_name    TEXT;
BEGIN
    IF NEW.role_id IS NOT NULL THEN
        SELECT name
          INTO resolved_name
          FROM roles
         WHERE id = NEW.role_id;

        IF resolved_name IS NULL THEN
            RAISE EXCEPTION 'Unknown playbook ACL role id: %', NEW.role_id
                USING ERRCODE = 'foreign_key_violation',
                      CONSTRAINT = 'playbook_permissions_role_id_fkey';
        END IF;

        NEW.role := resolved_name;
        RETURN NEW;
    END IF;

    -- Exact demo_analyst has always been a name-derived synthetic principal,
    -- even if a legacy database also carries a real role with that name.
    IF NEW.role = 'demo_analyst' THEN
        RETURN NEW;
    END IF;

    SELECT id
      INTO resolved_role_id
      FROM roles
     WHERE name = NEW.role;

    IF resolved_role_id IS NOT NULL THEN
        NEW.role_id := resolved_role_id;
        RETURN NEW;
    END IF;

    -- api_key becomes a reserved synthetic principal once migration 268 has
    -- renamed any colliding legacy real role.
    IF NEW.role = 'api_key' THEN
        RETURN NEW;
    END IF;

    RAISE EXCEPTION 'Unknown playbook ACL role: %', NEW.role
        USING ERRCODE = 'foreign_key_violation',
              CONSTRAINT = 'playbook_permissions_role_id_fkey';
END
$$;

CREATE OR REPLACE FUNCTION sync_playbook_acl_role_label()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE playbook_permissions
       SET role = NEW.name,
           updated_at = NOW()
     WHERE role_id = NEW.id
       AND role IS DISTINCT FROM NEW.name;
    RETURN NEW;
END
$$;

DO $$
DECLARE
    lock_attempts INTEGER := 0;
BEGIN
    IF to_regclass('public.roles') IS NULL
       OR to_regclass('public.playbook_permissions') IS NULL THEN
        RETURN;
    END IF;

    -- PostgreSQL locks the DML target before its row triggers run. Acquire the
    -- parent-first DDL set with NOWAIT in a subtransaction so a busy child
    -- releases the partial parent locks before retrying instead of deadlocking.
    LOOP
        lock_attempts := lock_attempts + 1;
        BEGIN
            LOCK TABLE roles IN ACCESS EXCLUSIVE MODE NOWAIT;
            LOCK TABLE playbooks IN EXCLUSIVE MODE NOWAIT;
            LOCK TABLE playbook_permissions
                IN ACCESS EXCLUSIVE MODE NOWAIT;
            EXIT;
        EXCEPTION
            WHEN lock_not_available OR deadlock_detected THEN
                IF lock_attempts >= 600 THEN
                    RAISE EXCEPTION
                        'NAN-2097: could not quiesce legacy ACL writers after % attempts',
                        lock_attempts
                        USING ERRCODE = 'lock_not_available';
                END IF;
                PERFORM pg_sleep(0.05);
        END;
    END LOOP;

    ALTER TABLE playbook_permissions
        ADD COLUMN IF NOT EXISTS role_id UUID
            REFERENCES roles(id) ON DELETE RESTRICT;

    -- Populate the stable key before installing the write trigger. The
    -- following stable-key migration remains authoritative for legacy unknown
    -- and conflicting rows.
    UPDATE playbook_permissions pp
       SET role_id = r.id
      FROM roles r
     WHERE pp.role_id IS NULL
       AND r.name = pp.role
       AND r.name <> 'demo_analyst';

    DROP TRIGGER IF EXISTS normalize_playbook_permission_role_key
        ON playbook_permissions;
    CREATE TRIGGER normalize_playbook_permission_role_key
        BEFORE INSERT OR UPDATE OF role, role_id
        ON playbook_permissions
        FOR EACH ROW
        EXECUTE FUNCTION normalize_playbook_permission_role_key();

    DROP TRIGGER IF EXISTS sync_playbook_acl_role_label ON roles;
    CREATE TRIGGER sync_playbook_acl_role_label
        AFTER UPDATE OF name
        ON roles
        FOR EACH ROW
        WHEN (OLD.name IS DISTINCT FROM NEW.name)
        EXECUTE FUNCTION sync_playbook_acl_role_label();

    -- Retain this through the following stable-key migration. It is a
    -- compatibility arbiter for the old binary's column-list ON CONFLICT while
    -- new binaries use the role_id partial unique index.
    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint
         WHERE conrelid = 'playbook_permissions'::regclass
           AND conname = 'playbook_permissions_legacy_role_key'
    ) THEN
        ALTER TABLE playbook_permissions
            ADD CONSTRAINT playbook_permissions_legacy_role_key
            UNIQUE (playbook_id, role);
    END IF;
END
$$;
