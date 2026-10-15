-- NAN-3374: the lake handoff tables carry the security tenant column in every
-- edition.
--
-- The shared lake publisher binds `security_tenant_id` and names it in its
-- upsert conflict target, but the column (and the tenant-first keys) used to
-- come only from enterprise overlay 9000084. A fresh open-core lake install
-- never runs that overlay, so every bronze batch failed with 42703.
--
-- This migration gives the open schema the same column and key shape for the
-- three lake handoff tables. It deliberately stops there: no foreign key to
-- tenants, no row-level security, no policy. Those remain enterprise-only
-- (9000084). Open rows land under the fixed compatibility tenant, which is the
-- value the publisher binds outside enterprise_shared.
--
-- Idempotent in both orders:
--   * existing enterprise databases already ran 9000084, so every step below
--     finds the column present and the keys already tenant-first (no-op);
--   * fresh enterprise databases run this first, then 9000084 re-derives each
--     key from its non-authority columns and recreates the identical shape.
--
-- NAN-3398: every statement is emitted ONLY when it would change something.
-- PostgreSQL checks table ownership for ALTER TABLE before it evaluates
-- IF NOT EXISTS, so even a no-op `ADD COLUMN IF NOT EXISTS` fails with
-- "must be owner of table" when the migrator is not the owner. Production
-- databases already shaped by 9000084 have these tables owned by
-- nano_shared_app_owner while migrations run as postgres, so on such a
-- database this migration must run with zero DDL/DML: it reads the catalog
-- (column, nullability, default, key order) and skips each step that is
-- already satisfied.

DO $migration$
DECLARE
    v_default_tenant CONSTANT UUID :=
        '00000000-0000-0000-0000-000000000100'::uuid;
    v_tables CONSTANT TEXT[] := ARRAY[
        'detection_finding_lake_outbox',
        'detection_late_replay_jobs',
        'lake_detection_event_publications'
    ];
    v_table TEXT;
    v_key RECORD;
    v_index RECORD;
    v_columns TEXT;
    v_definition TEXT;
    v_relid REGCLASS;
    v_attnum SMALLINT;
    v_attnotnull BOOLEAN;
    v_default_expr TEXT;
BEGIN
    FOREACH v_table IN ARRAY v_tables LOOP
        IF to_regclass(format('public.%I', v_table)) IS NULL THEN
            RAISE EXCEPTION 'lake handoff table public.% is missing', v_table;
        END IF;

        v_relid := format('public.%I', v_table)::regclass;

        -- Current shape of the authority column (NULL attnum = absent).
        v_attnum := NULL;
        v_attnotnull := NULL;
        v_default_expr := NULL;
        SELECT attribute.attnum, attribute.attnotnull,
               pg_get_expr(default_row.adbin, default_row.adrelid)
          INTO v_attnum, v_attnotnull, v_default_expr
          FROM pg_attribute attribute
          LEFT JOIN pg_attrdef default_row
            ON default_row.adrelid = attribute.attrelid
           AND default_row.adnum = attribute.attnum
         WHERE attribute.attrelid = v_relid
           AND attribute.attname = 'security_tenant_id'
           AND NOT attribute.attisdropped;

        IF v_attnum IS NULL THEN
            EXECUTE format(
                'ALTER TABLE public.%I ADD COLUMN security_tenant_id UUID',
                v_table
            );
            v_attnotnull := false;
        END IF;

        -- Backfill only while the column can still hold NULLs.
        IF NOT v_attnotnull THEN
            EXECUTE format(
                'UPDATE public.%I SET security_tenant_id = $1 WHERE security_tenant_id IS NULL',
                v_table
            ) USING v_default_tenant;
        END IF;

        IF v_default_expr IS DISTINCT FROM
               format('%L::uuid', v_default_tenant::text) THEN
            EXECUTE format(
                'ALTER TABLE public.%I ALTER COLUMN security_tenant_id SET DEFAULT %L::uuid',
                v_table, v_default_tenant::text
            );
        END IF;

        IF NOT v_attnotnull THEN
            EXECUTE format(
                'ALTER TABLE public.%I ALTER COLUMN security_tenant_id SET NOT NULL',
                v_table
            );
        END IF;

        -- Primary and unique keys that do not yet lead with the authority
        -- column are rebuilt with it first, keeping name and deferrability.
        FOR v_key IN
            SELECT constraint_row.conname::name AS constraint_name,
                   constraint_row.contype,
                   constraint_row.condeferrable,
                   constraint_row.condeferred,
                   ARRAY(
                       SELECT attribute.attname::text
                       FROM unnest(constraint_row.conkey)
                            WITH ORDINALITY key(attnum, position)
                       JOIN pg_attribute attribute
                         ON attribute.attrelid = constraint_row.conrelid
                        AND attribute.attnum = key.attnum
                       WHERE attribute.attname <> 'security_tenant_id'
                       ORDER BY key.position
                   ) AS identity_columns
            FROM pg_constraint constraint_row
            WHERE constraint_row.conrelid = format('public.%I', v_table)::regclass
              AND constraint_row.contype IN ('p', 'u')
              AND (
                  SELECT attribute.attname
                  FROM pg_attribute attribute
                  WHERE attribute.attrelid = constraint_row.conrelid
                    AND attribute.attnum = constraint_row.conkey[1]
              ) <> 'security_tenant_id'
            ORDER BY constraint_row.conname
        LOOP
            SELECT string_agg(format('%I', column_name), ', ' ORDER BY position)
              INTO v_columns
              FROM unnest(ARRAY['security_tenant_id'] || v_key.identity_columns)
                   WITH ORDINALITY columns(column_name, position);
            EXECUTE format(
                'ALTER TABLE public.%I DROP CONSTRAINT %I',
                v_table, v_key.constraint_name
            );
            EXECUTE format(
                'ALTER TABLE public.%I ADD CONSTRAINT %I %s (%s)%s%s',
                v_table,
                v_key.constraint_name,
                CASE v_key.contype WHEN 'p' THEN 'PRIMARY KEY' ELSE 'UNIQUE' END,
                v_columns,
                CASE WHEN v_key.condeferrable THEN ' DEFERRABLE' ELSE '' END,
                CASE WHEN v_key.condeferred THEN ' INITIALLY DEFERRED' ELSE '' END
            );
        END LOOP;

        -- Standalone unique indexes get the same authority prefix.
        FOR v_index IN
            SELECT index_class.relname::name AS index_name,
                   pg_get_indexdef(index_row.indexrelid) AS index_definition
            FROM pg_index index_row
            JOIN pg_class index_class ON index_class.oid = index_row.indexrelid
            WHERE index_row.indrelid = format('public.%I', v_table)::regclass
              AND index_row.indisunique
              AND NOT EXISTS (
                  SELECT 1 FROM pg_constraint constraint_row
                  WHERE constraint_row.conindid = index_row.indexrelid
                    AND constraint_row.conrelid = index_row.indrelid
                    AND constraint_row.contype IN ('p', 'u', 'x')
              )
              AND (
                  SELECT attribute.attname
                  FROM pg_attribute attribute
                  WHERE attribute.attrelid = index_row.indrelid
                    AND attribute.attnum = index_row.indkey[0]
              ) IS DISTINCT FROM 'security_tenant_id'
            ORDER BY index_class.relname
        LOOP
            v_definition := regexp_replace(
                v_index.index_definition,
                '( USING [^ ]+ \()',
                E'\\1security_tenant_id, '
            );
            IF v_definition NOT LIKE '%(security_tenant_id,%' THEN
                RAISE EXCEPTION 'cannot authority-prefix unique index %', v_index.index_name;
            END IF;
            EXECUTE format('DROP INDEX public.%I', v_index.index_name);
            EXECUTE v_definition;
        END LOOP;
    END LOOP;
END
$migration$;
