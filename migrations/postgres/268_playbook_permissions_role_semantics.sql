-- NAN-2097: key `playbook_permissions` on a STABLE role id, normalize
-- pre-existing rows BEFORE the ACL becomes enforced, and correct the table's
-- documented semantics.
--
-- The OPEN half. Byte-identical body to
-- `migrations/postgres-enterprise/9000043_playbook_permissions_role_id.sql` —
-- see that file for why BOTH exist. Short version: `playbook_permissions` is
-- created by 157 in this directory for legacy tenants, but by the enterprise
-- overlay's 9000002 on any fresh deploy past OPEN_INIT_BASELINE_VERSION, and
-- `run_postgres_migrations` applies only the open set. So on a legacy database
-- THIS file does the work; on a fresh enterprise database the table does not
-- exist yet, this file's guard returns, and the overlay twin does it instead.
-- Both are guarded and idempotent, so whichever runs second is a no-op.
--
-- Why role_id and not the role name
-- ---------------------------------
-- The first cut matched the free-form `role` TEXT against resolved role NAMES.
-- A role name is neither stable nor reserved, which produced four independent
-- ways to break a playbook (codex rounds 5 and 6):
--
--   * `RoleRepository::update_role` permits renaming any non-system role.
--     Renaming the sole ACL editor orphaned its grant; later re-creating a role
--     with the old name TRANSFERRED those grants to a different role; and a
--     subsequent write under the CURRENT name forked a second entry whose stale
--     twin kept granting.
--   * `RESERVED_ROLE_NAMES` reserved only `demo_analyst`, so an operator could
--     create a tenant role named `api_key` whose members matched entries meant
--     exclusively for API keys. Both synthetic labels are now reserved.
--   * Deleting a role left its entries behind as permanent denials.
--
-- Real roles are therefore matched on `role_id`, with a partial unique index on
-- `(playbook_id, role_id)` so an entry can never fork. The two synthetic
-- principals keep `role_id IS NULL` and match on the `role` text. The one
-- supported legacy exception is a pre-existing real role named `demo_analyst`:
-- its name-derived demo semantics are preserved and its members deliberately
-- resolve to that same synthetic ACL principal.
--
-- Why a DATA migration and not just DDL
-- -------------------------------------
-- Until this release NOTHING read `playbook_permissions`. The rows were inert:
-- `PUT /api/playbooks/{id}/permissions/{role}` has been a live, documented,
-- public endpoint since NAN-447, accepting ANY label and ANY flag combination —
-- the API docs themselves suggested `soc-leads`, which names no role. Operators
-- could write anything and it had no effect, so nothing pushed back.
--
-- Enforcement makes those rows retroactively authoritative, and two shapes
-- become UNRECOVERABLE: an entry naming a role nobody holds, and a non-empty
-- ACL where nothing grants can_view AND can_edit to a role that ALSO holds
-- `playbooks:manage` (the capability the ACL endpoints require at the handler —
-- the seeded `Editor` role has only playbooks:view + playbooks:run). Applying a
-- policy nobody ever actually set, and had no way to test, is how a tenant loses
-- its playbook library: measured on a database carrying such rows, 61 of 118
-- ACL'd playbooks would have been permanently hidden.
--
-- So normalize to the two states that MEAN something:
--   * a coherent, administrable ACL  -> kept; somebody configured it deliberately
--   * no ACL at all                  -> unrestricted, which is the behaviour every
--                                       deployment has actually experienced to date

DO $$
DECLARE
    unresolvable_roles BIGINT := 0;
    unadministrable    BIGINT := 0;
    forked_entries     BIGINT := 0;
    colliding_role     RECORD;
    replacement_name   TEXT;
    replacement_taken  BOOLEAN := FALSE;
    has_acl             BOOLEAN := FALSE;
BEGIN
    IF to_regclass('public.roles') IS NULL THEN
        RETURN;
    END IF;

    has_acl := to_regclass('public.playbook_permissions') IS NOT NULL;
    IF has_acl THEN
        -- Stable ACL key. ON DELETE RESTRICT, not CASCADE (codex round 6): an
        -- EMPTY ACL means UNRESTRICTED, so cascading the last entry away on role
        -- deletion would silently convert a restricted playbook into a
        -- world-readable one — a fail-OPEN.
        ALTER TABLE playbook_permissions
            ADD COLUMN IF NOT EXISTS role_id UUID REFERENCES roles(id) ON DELETE RESTRICT;

        -- Resolve every label that currently names an ordinary real role before
        -- enabling the synthetic namespace. Exact `demo_analyst` is the one
        -- deliberate name-derived legacy exception.
        UPDATE playbook_permissions pp
           SET role_id = r.id
          FROM roles r
         WHERE pp.role_id IS NULL
           AND r.name = pp.role
           AND r.name <> 'demo_analyst';
    END IF;

    -- Move every real role in a newly-reserved namespace to a canonical,
    -- non-reserved name. Exact `demo_analyst` remains the deliberate restricted
    -- legacy principal described above; case/whitespace variants never had
    -- those exact-name semantics and must not become impossible to rename.
    -- This runs even on open-edition schemas where playbook_permissions does not
    -- exist.
    FOR colliding_role IN
        SELECT id,
               name,
               CASE lower(btrim(name))
                   WHEN 'api_key' THEN 'api_key'
                   ELSE 'demo_analyst'
               END AS reserved_prefix
          FROM roles
         WHERE lower(btrim(name)) = 'api_key'
            OR (
                lower(btrim(name)) = 'demo_analyst'
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

    IF NOT has_acl THEN
        RETURN;
    END IF;

    -- Collapse any pre-existing pair of entries that resolved to the SAME role
    -- under different labels (a rename before enforcement existed). Keep the
    -- most permissive, so de-duplication can only ever narrow, never widen.
    WITH ranked AS (
        SELECT ctid,
               ROW_NUMBER() OVER (
                   PARTITION BY playbook_id, role_id
                   ORDER BY (can_view::int + can_run::int + can_edit::int + can_publish::int) DESC,
                            updated_at DESC
               ) AS rn
          FROM playbook_permissions
         WHERE role_id IS NOT NULL
    ),
    removed AS (
        DELETE FROM playbook_permissions pp
         USING ranked
         WHERE pp.ctid = ranked.ctid AND ranked.rn > 1
        RETURNING 1
    )
    SELECT COUNT(*) INTO forked_entries FROM removed;

    CREATE UNIQUE INDEX IF NOT EXISTS idx_playbook_permissions_playbook_role_id
        ON playbook_permissions(playbook_id, role_id)
        WHERE role_id IS NOT NULL;

    -- `role` is only a key for synthetic principals. Keeping the legacy primary
    -- key on `(playbook_id, role)` would make a stale display label block a
    -- different role from reusing the old name after a rename.
    CREATE UNIQUE INDEX IF NOT EXISTS idx_playbook_permissions_playbook_synthetic_role
        ON playbook_permissions(playbook_id, role)
        WHERE role_id IS NULL;

    ALTER TABLE playbook_permissions
        DROP CONSTRAINT IF EXISTS playbook_permissions_pkey;

    -- All ACL predicates start by probing whether this playbook has any rows.
    -- The two uniqueness indexes above are partial, so neither can serve that
    -- unconditional lookup.
    CREATE INDEX IF NOT EXISTS idx_playbook_permissions_playbook_id
        ON playbook_permissions(playbook_id);

    CREATE INDEX IF NOT EXISTS idx_playbook_permissions_role_id
        ON playbook_permissions(role_id);

    -- Step 1: entries naming a role that can never resolve. Must run BEFORE
    -- step 2, or an unresolvable entry holding can_edit would make an otherwise
    -- unadministrable ACL look administrable and survive.
    WITH removed AS (
        DELETE FROM playbook_permissions pp
         WHERE pp.role_id IS NULL
           AND pp.role NOT IN ('api_key', 'demo_analyst')
        RETURNING 1
    )
    SELECT COUNT(*) INTO unresolvable_roles FROM removed;

    -- Step 2: clear any ACL left non-empty but with nobody able to administer it.
    -- The administrator must hold can_view AND can_edit here AND the coarse
    -- `playbooks:manage` capability, because the ACL endpoints check that at the
    -- handler — the seeded `Editor` role has only playbooks:view + playbooks:run.
    WITH removed AS (
        DELETE FROM playbook_permissions pp
         WHERE NOT EXISTS (
             SELECT 1
               FROM playbook_permissions q
               JOIN role_permissions rp ON rp.role_id = q.role_id
              WHERE q.playbook_id = pp.playbook_id
                AND q.can_view
                AND q.can_edit
                AND rp.permission_id = 'playbooks:manage'
         )
        RETURNING 1
    )
    SELECT COUNT(*) INTO unadministrable FROM removed;

    IF unresolvable_roles > 0 OR unadministrable > 0 OR forked_entries > 0 THEN
        RAISE NOTICE 'NAN-2097: normalized playbook_permissions (% unresolvable-role entries, % entries in unadministrable ACLs, % duplicate role entries collapsed)',
            unresolvable_roles, unadministrable, forked_entries;
    END IF;
END
$$;

DO $$
BEGIN
    IF to_regclass('public.playbook_permissions') IS NULL THEN
        RETURN;
    END IF;

    COMMENT ON TABLE playbook_permissions IS
        'Per-playbook ACL (NAN-2097, enforced). Semantics: a playbook with NO '
        'rows is unrestricted and governed by the tenant-wide playbooks:* '
        'capabilities alone; once ANY row exists the ACL is authoritative and '
        'the caller must hold a principal granted the requested flag. Multiple '
        'roles union across rows, but can_view and the action flag must be '
        'present on the SAME row - an action-only entry grants nothing and the '
        'halves cannot be composed from different roles. Administering these '
        'rows requires playbooks:manage AND can_edit, and a non-empty ACL must '
        'always leave at least one role holding BOTH can_view AND can_edit here '
        'AND the coarse playbooks:manage capability.';

    COMMENT ON COLUMN playbook_permissions.role IS
        'Display label for rows carrying a role_id, re-synced on every write. It '
        'is AUTHORITATIVE only for the two reserved synthetic principals, which '
        'have no roles row and are stored with role_id IS NULL: ''api_key'' (the '
        'ONLY principal an API-key caller is evaluated as - a key never inherits '
        'its owner''s roles, NAN-2043) and ''demo_analyst'' (verified live demo '
        'sessions, which carry no group role assignments, plus members of a '
        'pre-existing name-derived demo_analyst database role). Both names are '
        'reserved against new roles; the legacy demo role deliberately maps to '
        'the same restricted principal.';

    COMMENT ON COLUMN playbook_permissions.role_id IS
        'The stable ACL key for a real role (NAN-2097). Matched against the role '
        'ids resolved through user_groups -> group_roles -> roles at request '
        'time, NOT the JWT roles claim (display-only, up to one access-token TTL '
        'stale). NULL only for the reserved synthetic principals in `role`. '
        'ON DELETE RESTRICT: an empty ACL means UNRESTRICTED, so cascading the '
        'last entry away on role deletion would fail OPEN.';
END
$$;
