-- NAN-2361: dormant enterprise_shared PostgreSQL RLS foundation.
--
-- IMPORTANT deployment boundary:
--   * This migration creates no cluster roles and generates/persists no key.
--   * The role contract is disabled and the verifier-key table is empty.
--   * Existing dedicated/managed/demo/open-core roles retain their behavior.
--   * Activation is an explicit, transactional operator action through
--     nano_shared.activate_rls_contract after two pre-created roles and an
--     externally generated 32+ byte HMAC key are supplied.
--
-- The converted vertical slice is deliberately new and shared-only. Legacy
-- search_history and users.search_history_enabled remain untouched. Shared
-- search-history routes must stay fenced until their repositories use a
-- tenant transaction and these tables.

CREATE SCHEMA IF NOT EXISTS nano_shared;
REVOKE ALL ON SCHEMA nano_shared FROM PUBLIC;

CREATE TABLE IF NOT EXISTS nano_shared.rls_role_contract (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    runtime_role NAME,
    owner_role NAME,
    context_key_id UUID,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    activated_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (
        (NOT enabled AND runtime_role IS NULL AND owner_role IS NULL AND context_key_id IS NULL)
        OR
        (enabled AND runtime_role IS NOT NULL AND owner_role IS NOT NULL AND context_key_id IS NOT NULL)
    ),
    CHECK (runtime_role IS NULL OR runtime_role <> owner_role)
);

INSERT INTO nano_shared.rls_role_contract (singleton, enabled)
VALUES (TRUE, FALSE)
ON CONFLICT (singleton) DO NOTHING;

-- Empty after migration. The activation function stores only an explicitly
-- supplied verifier key. Migration SQL never embeds or generates one.
CREATE TABLE IF NOT EXISTS nano_shared.rls_context_keys (
    key_id UUID PRIMARY KEY,
    hmac_key BYTEA NOT NULL CHECK (octet_length(hmac_key) >= 32),
    not_before TIMESTAMPTZ NOT NULL,
    not_after TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (not_after > not_before)
);

CREATE TABLE IF NOT EXISTS nano_shared.rls_table_registry (
    schema_name NAME NOT NULL,
    table_name NAME NOT NULL,
    tenant_column NAME NOT NULL DEFAULT 'tenant_id',
    PRIMARY KEY (schema_name, table_name)
);

-- Tenant ledgers that the runtime may only SELECT are audited separately from
-- data-plane tables. They must never be fed through activate_rls_contract,
-- which intentionally grants DML to its registry.
CREATE TABLE IF NOT EXISTS nano_shared.rls_read_table_registry (
    schema_name NAME NOT NULL,
    table_name NAME NOT NULL,
    tenant_column NAME NOT NULL DEFAULT 'tenant_id',
    PRIMARY KEY (schema_name, table_name)
);

CREATE TABLE IF NOT EXISTS nano_shared.rls_entrypoint_registry (
    schema_name NAME NOT NULL,
    object_name NAME NOT NULL,
    object_kind TEXT NOT NULL CHECK (object_kind IN ('view', 'function')),
    PRIMARY KEY (schema_name, object_name, object_kind)
);

REVOKE ALL ON TABLE nano_shared.rls_role_contract FROM PUBLIC;
REVOKE ALL ON TABLE nano_shared.rls_context_keys FROM PUBLIC;
REVOKE ALL ON TABLE nano_shared.rls_table_registry FROM PUBLIC;
REVOKE ALL ON TABLE nano_shared.rls_read_table_registry FROM PUBLIC;
REVOKE ALL ON TABLE nano_shared.rls_entrypoint_registry FROM PUBLIC;

-- Search history is the first complete tenant data-plane slice. UUIDs are
-- unique inside a tenant, not globally, so a conflict cannot reveal whether
-- another tenant owns the same identifier.
CREATE TABLE IF NOT EXISTS public.tenant_search_preferences (
    tenant_id UUID NOT NULL,
    user_id UUID NOT NULL,
    history_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, user_id),
    FOREIGN KEY (tenant_id, user_id)
        REFERENCES public.tenant_members(tenant_id, user_id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS public.tenant_search_history (
    tenant_id UUID NOT NULL,
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    query TEXT NOT NULL,
    query_mode VARCHAR(10) NOT NULL DEFAULT 'piped',
    time_range_type VARCHAR(20) NOT NULL DEFAULT 'preset',
    time_range_preset VARCHAR(50),
    time_range_start TIMESTAMPTZ,
    time_range_end TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, user_id)
        REFERENCES public.tenant_members(tenant_id, user_id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_tenant_search_history_user_created
    ON public.tenant_search_history (tenant_id, user_id, created_at DESC, id);

REVOKE ALL ON TABLE public.tenant_search_preferences FROM PUBLIC;
REVOKE ALL ON TABLE public.tenant_search_history FROM PUBLIC;

INSERT INTO nano_shared.rls_table_registry (schema_name, table_name, tenant_column)
VALUES
    ('public', 'tenant_search_preferences', 'tenant_id'),
    ('public', 'tenant_search_history', 'tenant_id')
ON CONFLICT (schema_name, table_name) DO UPDATE
SET tenant_column = EXCLUDED.tenant_column;

-- Canonical payload shared with nanosiem_core::tenant_db. Database and role
-- bind a signed context to one exact deployment/runtime identity.
CREATE OR REPLACE FUNCTION nano_shared.context_payload(
    p_database NAME,
    p_role NAME,
    p_tenant_id UUID,
    p_actor_id UUID,
    p_expires_epoch BIGINT,
    p_nonce UUID,
    p_key_id UUID
) RETURNS TEXT
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
    SELECT 'v1|'
        || p_database::text || '|'
        || p_role::text || '|'
        || p_tenant_id::text || '|'
        || p_actor_id::text || '|'
        || p_expires_epoch::text || '|'
        || p_nonce::text || '|'
        || p_key_id::text
$$;

CREATE OR REPLACE FUNCTION nano_shared.constant_time_equal(p_left BYTEA, p_right BYTEA)
RETURNS BOOLEAN
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
DECLARE
    v_difference INTEGER := 0;
    v_index INTEGER;
BEGIN
    IF p_left IS NULL OR p_right IS NULL OR octet_length(p_left) <> octet_length(p_right) THEN
        RETURN FALSE;
    END IF;
    IF octet_length(p_left) = 0 THEN
        RETURN TRUE;
    END IF;
    FOR v_index IN 0..octet_length(p_left) - 1 LOOP
        v_difference := v_difference
            | (get_byte(p_left, v_index) # get_byte(p_right, v_index));
    END LOOP;
    RETURN v_difference = 0;
END
$$;

-- Returns the verified transaction-local tenant or raises 42501. Direct SET
-- of the custom GUCs cannot forge context: the proof is HMAC-bound to the
-- current PostgreSQL transaction ID and is rechecked by every RLS policy.
CREATE OR REPLACE FUNCTION nano_shared.current_tenant_id()
RETURNS UUID
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
PARALLEL RESTRICTED
SET search_path = pg_catalog, nano_shared, pg_temp
AS $$
DECLARE
    v_database NAME;
    v_role NAME;
    v_tenant_id UUID;
    v_actor_id UUID;
    v_expires_epoch BIGINT;
    v_nonce UUID;
    v_key_id UUID;
    v_proof BYTEA;
    v_expected BYTEA;
    v_key BYTEA;
    v_transaction_id TEXT;
BEGIN
    BEGIN
        v_database := current_setting('nano_shared.database', TRUE)::name;
        v_role := current_setting('nano_shared.role', TRUE)::name;
        v_tenant_id := current_setting('nano_shared.tenant_id', TRUE)::uuid;
        v_actor_id := current_setting('nano_shared.actor_id', TRUE)::uuid;
        v_expires_epoch := current_setting('nano_shared.expires_epoch', TRUE)::bigint;
        v_nonce := current_setting('nano_shared.nonce', TRUE)::uuid;
        v_key_id := current_setting('nano_shared.key_id', TRUE)::uuid;
        v_proof := decode(current_setting('nano_shared.transaction_proof', TRUE), 'hex');
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'enterprise_shared tenant context is missing or malformed'
            USING ERRCODE = '42501';
    END;

    IF v_database <> current_database()::name OR v_role <> session_user::name THEN
        RAISE EXCEPTION 'enterprise_shared tenant context identity mismatch'
            USING ERRCODE = '42501';
    END IF;
    IF v_expires_epoch <= floor(extract(epoch FROM clock_timestamp()))::bigint THEN
        RAISE EXCEPTION 'enterprise_shared tenant context expired'
            USING ERRCODE = '42501';
    END IF;

    SELECT hmac_key
    INTO v_key
    FROM nano_shared.rls_context_keys
    WHERE key_id = v_key_id
      AND revoked_at IS NULL
      AND not_before <= clock_timestamp()
      AND not_after > clock_timestamp();
    IF v_key IS NULL THEN
        RAISE EXCEPTION 'enterprise_shared tenant context key unavailable'
            USING ERRCODE = '42501';
    END IF;

    v_transaction_id := pg_current_xact_id()::text;
    v_expected := public.hmac(
        convert_to(
            'dbv1|'
            || nano_shared.context_payload(
                v_database,
                v_role,
                v_tenant_id,
                v_actor_id,
                v_expires_epoch,
                v_nonce,
                v_key_id
            )
            || '|'
            || v_transaction_id,
            'UTF8'
        ),
        v_key,
        'sha256'
    );
    IF NOT nano_shared.constant_time_equal(v_proof, v_expected) THEN
        RAISE EXCEPTION 'enterprise_shared tenant context proof invalid'
            USING ERRCODE = '42501';
    END IF;
    RETURN v_tenant_id;
END
$$;

CREATE OR REPLACE FUNCTION nano_shared.tenant_row_visible(p_tenant_id UUID)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
PARALLEL RESTRICTED
SET search_path = pg_catalog, nano_shared, pg_temp
AS $$
    SELECT p_tenant_id = nano_shared.current_tenant_id()
$$;

-- The only context setter. The caller must connect directly as the exact
-- runtime role; SET ROLE/pooler impersonation is intentionally unsupported.
-- Membership is a defense-in-depth door check, not a replacement for the
-- control-plane membership resolver that decided to sign the context.
CREATE OR REPLACE FUNCTION nano_shared.set_tenant_context(
    p_database NAME,
    p_role NAME,
    p_tenant_id UUID,
    p_actor_id UUID,
    p_expires_epoch BIGINT,
    p_nonce UUID,
    p_key_id UUID,
    p_signature_hex TEXT
) RETURNS VOID
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
PARALLEL UNSAFE
SET search_path = pg_catalog, nano_shared, pg_temp
AS $$
DECLARE
    v_runtime_role NAME;
    v_key BYTEA;
    v_signature BYTEA;
    v_expected BYTEA;
    v_transaction_proof BYTEA;
    v_payload TEXT;
    v_now_epoch BIGINT := floor(extract(epoch FROM clock_timestamp()))::bigint;
BEGIN
    SELECT runtime_role
    INTO v_runtime_role
    FROM nano_shared.rls_role_contract
    WHERE singleton AND enabled;

    IF v_runtime_role IS NULL
        OR session_user::name <> v_runtime_role
        OR p_role <> v_runtime_role
        OR p_database <> current_database()::name
    THEN
        RAISE EXCEPTION 'enterprise_shared runtime role contract mismatch'
            USING ERRCODE = '42501';
    END IF;
    IF p_expires_epoch <= v_now_epoch OR p_expires_epoch > v_now_epoch + 60 THEN
        RAISE EXCEPTION 'enterprise_shared tenant context expiry outside allowed window'
            USING ERRCODE = '42501';
    END IF;
    IF p_signature_hex !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'enterprise_shared tenant context signature malformed'
            USING ERRCODE = '42501';
    END IF;

    SELECT hmac_key
    INTO v_key
    FROM nano_shared.rls_context_keys
    WHERE key_id = p_key_id
      AND revoked_at IS NULL
      AND not_before <= clock_timestamp()
      AND not_after > clock_timestamp();
    IF v_key IS NULL THEN
        RAISE EXCEPTION 'enterprise_shared tenant context key unavailable'
            USING ERRCODE = '42501';
    END IF;

    v_payload := nano_shared.context_payload(
        p_database,
        p_role,
        p_tenant_id,
        p_actor_id,
        p_expires_epoch,
        p_nonce,
        p_key_id
    );
    v_signature := decode(p_signature_hex, 'hex');
    v_expected := public.hmac(convert_to(v_payload, 'UTF8'), v_key, 'sha256');
    IF NOT nano_shared.constant_time_equal(v_signature, v_expected) THEN
        RAISE EXCEPTION 'enterprise_shared tenant context signature invalid'
            USING ERRCODE = '42501';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM public.tenants t
        JOIN public.tenant_members tm ON tm.tenant_id = t.id
        WHERE t.id = p_tenant_id
          AND t.status = 'active'
          AND tm.user_id = p_actor_id
          AND tm.status = 'active'
    ) THEN
        RAISE EXCEPTION 'enterprise_shared tenant membership is not active'
            USING ERRCODE = '42501';
    END IF;

    v_transaction_proof := public.hmac(
        convert_to('dbv1|' || v_payload || '|' || pg_current_xact_id()::text, 'UTF8'),
        v_key,
        'sha256'
    );

    PERFORM set_config('nano_shared.database', p_database::text, TRUE);
    PERFORM set_config('nano_shared.role', p_role::text, TRUE);
    PERFORM set_config('nano_shared.tenant_id', p_tenant_id::text, TRUE);
    PERFORM set_config('nano_shared.actor_id', p_actor_id::text, TRUE);
    PERFORM set_config('nano_shared.expires_epoch', p_expires_epoch::text, TRUE);
    PERFORM set_config('nano_shared.nonce', p_nonce::text, TRUE);
    PERFORM set_config('nano_shared.key_id', p_key_id::text, TRUE);
    PERFORM set_config(
        'nano_shared.transaction_proof',
        encode(v_transaction_proof, 'hex'),
        TRUE
    );
END
$$;

REVOKE ALL ON FUNCTION nano_shared.context_payload(NAME, NAME, UUID, UUID, BIGINT, UUID, UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION nano_shared.constant_time_equal(BYTEA, BYTEA) FROM PUBLIC;
REVOKE ALL ON FUNCTION nano_shared.current_tenant_id() FROM PUBLIC;
REVOKE ALL ON FUNCTION nano_shared.tenant_row_visible(UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION nano_shared.set_tenant_context(NAME, NAME, UUID, UUID, BIGINT, UUID, UUID, TEXT) FROM PUBLIC;

-- RLS is enabled+forced immediately, but the migration installs only the
-- exact PUBLIC permissive base policy. Until explicit activation adds the
-- runtime-role restrictive policy, behavior is unchanged for existing roles.
ALTER TABLE public.tenant_search_preferences ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.tenant_search_preferences FORCE ROW LEVEL SECURITY;
ALTER TABLE public.tenant_search_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.tenant_search_history FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS nano_shared_base_allow ON public.tenant_search_preferences;
CREATE POLICY nano_shared_base_allow
ON public.tenant_search_preferences
AS PERMISSIVE
FOR ALL
TO PUBLIC
USING (TRUE)
WITH CHECK (TRUE);

DROP POLICY IF EXISTS nano_shared_base_allow ON public.tenant_search_history;
CREATE POLICY nano_shared_base_allow
ON public.tenant_search_history
AS PERMISSIVE
FOR ALL
TO PUBLIC
USING (TRUE)
WITH CHECK (TRUE);

-- Every exposed view/function is invoker-safe. The base tables remain the RLS
-- authority; these entrypoints cannot run with an owner bypass.
CREATE OR REPLACE VIEW nano_shared.tenant_search_history_visible
WITH (security_invoker = TRUE)
AS
SELECT
    tenant_id,
    id,
    user_id,
    query,
    query_mode,
    time_range_type,
    time_range_preset,
    time_range_start,
    time_range_end,
    created_at
FROM public.tenant_search_history;

CREATE OR REPLACE FUNCTION nano_shared.list_tenant_search_history(p_limit INTEGER)
RETURNS SETOF public.tenant_search_history
LANGUAGE sql
STABLE
SECURITY INVOKER
SET search_path = pg_catalog, nano_shared, pg_temp
AS $$
    SELECT *
    FROM public.tenant_search_history
    ORDER BY created_at DESC, id
    LIMIT LEAST(GREATEST(p_limit, 0), 1000)
$$;

REVOKE ALL ON TABLE nano_shared.tenant_search_history_visible FROM PUBLIC;
REVOKE ALL ON FUNCTION nano_shared.list_tenant_search_history(INTEGER) FROM PUBLIC;

INSERT INTO nano_shared.rls_entrypoint_registry (schema_name, object_name, object_kind)
VALUES
    ('nano_shared', 'tenant_search_history_visible', 'view'),
    ('nano_shared', 'list_tenant_search_history', 'function')
ON CONFLICT (schema_name, object_name, object_kind) DO NOTHING;

-- Fail-closed catalog audit. It validates the exact activation identity,
-- runtime/owner attributes, ENABLE+FORCE, tenant-first unique/FK boundaries,
-- exact policy shape (including no permissive widening), and invoker-safe
-- entrypoints. It returns rows; zero rows is the only green state.
CREATE OR REPLACE FUNCTION nano_shared.audit_rls_catalog(
    p_expected_runtime_role NAME,
    p_expected_owner_role NAME
) RETURNS TABLE (
    code TEXT,
    object_name TEXT,
    detail TEXT
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
PARALLEL RESTRICTED
SET search_path = pg_catalog, nano_shared, pg_temp
AS $$
DECLARE
    v_runtime_oid OID;
    v_owner_oid OID;
    v_table RECORD;
    v_relation_oid OID;
    v_tenant_attnum SMALLINT;
    v_policy_count INTEGER;
    v_base_count INTEGER;
    v_scope_count INTEGER;
    v_enabled BOOLEAN;
    v_contract_runtime NAME;
    v_contract_owner NAME;
BEGIN
    SELECT enabled, runtime_role, owner_role
    INTO v_enabled, v_contract_runtime, v_contract_owner
    FROM nano_shared.rls_role_contract
    WHERE singleton;

    IF NOT COALESCE(v_enabled, FALSE)
        OR v_contract_runtime IS DISTINCT FROM p_expected_runtime_role
        OR v_contract_owner IS DISTINCT FROM p_expected_owner_role
    THEN
        RETURN QUERY SELECT
            'role_contract_mismatch',
            'nano_shared.rls_role_contract',
            'enabled runtime/owner contract does not exactly match expected roles';
    END IF;

    SELECT oid INTO v_runtime_oid FROM pg_roles WHERE rolname = p_expected_runtime_role;
    SELECT oid INTO v_owner_oid FROM pg_roles WHERE rolname = p_expected_owner_role;
    IF v_runtime_oid IS NULL THEN
        RETURN QUERY SELECT 'runtime_role_missing', p_expected_runtime_role::text, 'role does not exist';
    ELSE
        IF EXISTS (
            SELECT 1 FROM pg_roles
            WHERE oid = v_runtime_oid
              AND (rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication
                   OR rolinherit OR NOT rolcanlogin)
        ) THEN
            RETURN QUERY SELECT
                'runtime_role_unsafe',
                p_expected_runtime_role::text,
                'runtime must be LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION';
        END IF;
        IF EXISTS (SELECT 1 FROM pg_auth_members WHERE member = v_runtime_oid) THEN
            RETURN QUERY SELECT
                'runtime_role_membership_unsafe',
                p_expected_runtime_role::text,
                'runtime role may not SET ROLE into any granted role';
        END IF;
    END IF;

    IF v_owner_oid IS NULL THEN
        RETURN QUERY SELECT 'owner_role_missing', p_expected_owner_role::text, 'role does not exist';
    ELSE
        IF EXISTS (
            SELECT 1 FROM pg_roles
            WHERE oid = v_owner_oid
              AND (rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication
                   OR rolinherit OR rolcanlogin)
        ) THEN
            RETURN QUERY SELECT
                'owner_role_unsafe',
                p_expected_owner_role::text,
                'owner must be NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION';
        END IF;
        IF EXISTS (
            SELECT 1
            FROM pg_auth_members
            WHERE roleid = v_owner_oid OR member = v_owner_oid
        ) THEN
            RETURN QUERY SELECT
                'owner_role_membership_unsafe',
                p_expected_owner_role::text,
                'owner role may neither inherit another role nor be granted to any role';
        END IF;
    END IF;

    IF v_runtime_oid IS NOT NULL AND v_runtime_oid = v_owner_oid THEN
        RETURN QUERY SELECT
            'role_separation_missing',
            p_expected_runtime_role::text,
            'runtime and owner roles must be distinct';
    END IF;

    FOR v_table IN SELECT * FROM nano_shared.rls_table_registry ORDER BY schema_name, table_name LOOP
        SELECT c.oid, a.attnum
        INTO v_relation_oid, v_tenant_attnum
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        LEFT JOIN pg_attribute a
          ON a.attrelid = c.oid
         AND a.attname = v_table.tenant_column
         AND NOT a.attisdropped
         AND a.atttypid = 'uuid'::regtype
         AND a.attnotnull
        WHERE n.nspname = v_table.schema_name
          AND c.relname = v_table.table_name
          AND c.relkind IN ('r', 'p');

        IF v_relation_oid IS NULL OR v_tenant_attnum IS NULL THEN
            RETURN QUERY SELECT
                'tenant_table_shape_invalid',
                format('%I.%I', v_table.schema_name, v_table.table_name),
                'registered table or NOT NULL UUID tenant column missing';
            CONTINUE;
        END IF;

        IF NOT EXISTS (
            SELECT 1 FROM pg_class
            WHERE oid = v_relation_oid AND relrowsecurity AND relforcerowsecurity
        ) THEN
            RETURN QUERY SELECT
                'rls_not_forced',
                format('%I.%I', v_table.schema_name, v_table.table_name),
                'ENABLE and FORCE ROW LEVEL SECURITY are both required';
        END IF;

        IF v_owner_oid IS NOT NULL AND NOT EXISTS (
            SELECT 1 FROM pg_class WHERE oid = v_relation_oid AND relowner = v_owner_oid
        ) THEN
            RETURN QUERY SELECT
                'table_owner_mismatch',
                format('%I.%I', v_table.schema_name, v_table.table_name),
                'registered table is not owned by the expected NOLOGIN owner';
        END IF;

        SELECT count(*) INTO v_policy_count FROM pg_policy WHERE polrelid = v_relation_oid;
        SELECT count(*) INTO v_base_count
        FROM pg_policy
        WHERE polrelid = v_relation_oid
          AND polname = 'nano_shared_base_allow'
          AND polpermissive
          AND polcmd = '*'
          AND polroles = ARRAY[0::oid]
          AND pg_get_expr(polqual, polrelid) = 'true'
          AND pg_get_expr(polwithcheck, polrelid) = 'true';
        SELECT count(*) INTO v_scope_count
        FROM pg_policy
        WHERE polrelid = v_relation_oid
          AND polname = 'nano_shared_tenant_scope'
          AND NOT polpermissive
          AND polcmd = '*'
          AND cardinality(polroles) = 1
          AND (SELECT oid FROM pg_roles WHERE rolname = p_expected_runtime_role) = ANY(polroles)
          AND pg_get_expr(polqual, polrelid) IN (
                format('nano_shared.tenant_row_visible(%I)', v_table.tenant_column),
                format('tenant_row_visible(%I)', v_table.tenant_column)
          )
          AND pg_get_expr(polwithcheck, polrelid) IN (
                format('nano_shared.tenant_row_visible(%I)', v_table.tenant_column),
                format('tenant_row_visible(%I)', v_table.tenant_column)
          );
        IF v_policy_count <> 2 OR v_base_count <> 1 OR v_scope_count <> 1 THEN
            RETURN QUERY SELECT
                'rls_policy_shape_invalid',
                format('%I.%I', v_table.schema_name, v_table.table_name),
                format(
                    'expected exactly one PUBLIC permissive base and one exact-role restrictive tenant policy (total=%s base=%s scope=%s)',
                    v_policy_count,
                    v_base_count,
                    v_scope_count
                );
        END IF;

        IF EXISTS (
            SELECT 1
            FROM pg_index i
            WHERE i.indrelid = v_relation_oid
              AND i.indisunique
              AND i.indkey[0] IS DISTINCT FROM v_tenant_attnum
        ) THEN
            RETURN QUERY SELECT
                'global_unique_side_channel',
                format('%I.%I', v_table.schema_name, v_table.table_name),
                'every unique index must lead with tenant_id';
        END IF;

        IF v_runtime_oid IS NOT NULL AND EXISTS (
            SELECT 1
            FROM pg_class relation
            CROSS JOIN LATERAL aclexplode(
                COALESCE(relation.relacl, acldefault('r', relation.relowner))
            ) acl
            WHERE relation.oid = v_relation_oid
              AND acl.privilege_type = ANY (ARRAY[
                  'SELECT',
                  'INSERT',
                  'UPDATE',
                  'DELETE',
                  'TRUNCATE',
                  'REFERENCES',
                  'TRIGGER'
              ])
              AND acl.grantee NOT IN (v_runtime_oid, v_owner_oid)
        ) THEN
            RETURN QUERY SELECT
                'tenant_table_acl_widening',
                format('%I.%I', v_table.schema_name, v_table.table_name),
                'tenant table DML may be granted only to the exact runtime and NOLOGIN owner roles';
        END IF;

        IF EXISTS (
            SELECT 1
            FROM pg_constraint fk
            JOIN pg_class parent_class ON parent_class.oid = fk.confrelid
            JOIN pg_namespace parent_namespace
              ON parent_namespace.oid = parent_class.relnamespace
            JOIN (
                SELECT * FROM nano_shared.rls_table_registry
                UNION ALL
                SELECT * FROM nano_shared.rls_read_table_registry
            ) parent_registry
              ON parent_registry.schema_name = parent_namespace.nspname
             AND parent_registry.table_name = parent_class.relname
            JOIN pg_attribute parent_tenant
              ON parent_tenant.attrelid = parent_class.oid
             AND parent_tenant.attname = parent_registry.tenant_column
             AND NOT parent_tenant.attisdropped
            WHERE fk.conrelid = v_relation_oid
              AND fk.contype = 'f'
              AND (
                  NOT (v_tenant_attnum = ANY(fk.conkey))
                  OR NOT (parent_tenant.attnum = ANY(fk.confkey))
                  OR array_position(fk.conkey, v_tenant_attnum)
                     IS DISTINCT FROM array_position(fk.confkey, parent_tenant.attnum)
              )
        ) THEN
            RETURN QUERY SELECT
                'unscoped_foreign_key',
                format('%I.%I', v_table.schema_name, v_table.table_name),
                'every foreign key between registered tenant tables must pair tenant_id';
        END IF;
    END LOOP;

    -- Read-only authority ledgers use SELECT-only policies and grants. Keep
    -- them in the same fail-closed catalog audit without allowing the DML
    -- activation path above to widen their privileges.
    FOR v_table IN
        SELECT *
        FROM nano_shared.rls_read_table_registry
        ORDER BY schema_name, table_name
    LOOP
        SELECT c.oid, a.attnum
        INTO v_relation_oid, v_tenant_attnum
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        LEFT JOIN pg_attribute a
          ON a.attrelid = c.oid
         AND a.attname = v_table.tenant_column
         AND NOT a.attisdropped
         AND a.atttypid = 'uuid'::regtype
         AND a.attnotnull
        WHERE n.nspname = v_table.schema_name
          AND c.relname = v_table.table_name
          AND c.relkind IN ('r', 'p');

        IF v_relation_oid IS NULL OR v_tenant_attnum IS NULL THEN
            RETURN QUERY SELECT
                'tenant_read_table_shape_invalid',
                format('%I.%I', v_table.schema_name, v_table.table_name),
                'registered read-only table or NOT NULL UUID tenant column missing';
            CONTINUE;
        END IF;

        IF NOT EXISTS (
            SELECT 1 FROM pg_class
            WHERE oid = v_relation_oid AND relrowsecurity AND relforcerowsecurity
        ) THEN
            RETURN QUERY SELECT
                'read_rls_not_forced',
                format('%I.%I', v_table.schema_name, v_table.table_name),
                'ENABLE and FORCE ROW LEVEL SECURITY are both required';
        END IF;

        IF v_owner_oid IS NOT NULL AND NOT EXISTS (
            SELECT 1 FROM pg_class WHERE oid = v_relation_oid AND relowner = v_owner_oid
        ) THEN
            RETURN QUERY SELECT
                'read_table_owner_mismatch',
                format('%I.%I', v_table.schema_name, v_table.table_name),
                'registered read-only table is not owned by the expected NOLOGIN owner';
        END IF;

        SELECT count(*) INTO v_policy_count FROM pg_policy WHERE polrelid = v_relation_oid;
        SELECT count(*) INTO v_base_count
        FROM pg_policy
        WHERE polrelid = v_relation_oid
          AND polname = 'nano_shared_runtime_read_allow'
          AND polpermissive
          AND polcmd = 'r'
          AND cardinality(polroles) = 1
          AND v_runtime_oid = ANY(polroles)
          AND pg_get_expr(polqual, polrelid) = 'true'
          AND polwithcheck IS NULL;
        SELECT count(*) INTO v_scope_count
        FROM pg_policy
        WHERE polrelid = v_relation_oid
          AND polname = 'nano_shared_tenant_scope'
          AND NOT polpermissive
          AND polcmd = 'r'
          AND cardinality(polroles) = 1
          AND v_runtime_oid = ANY(polroles)
          AND pg_get_expr(polqual, polrelid) IN (
                format('nano_shared.tenant_row_visible(%I)', v_table.tenant_column),
                format('tenant_row_visible(%I)', v_table.tenant_column)
          )
          AND polwithcheck IS NULL;
        IF v_policy_count <> 2 OR v_base_count <> 1 OR v_scope_count <> 1 THEN
            RETURN QUERY SELECT
                'read_rls_policy_shape_invalid',
                format('%I.%I', v_table.schema_name, v_table.table_name),
                format(
                    'expected one exact-role SELECT allow and one exact-role restrictive tenant policy (total=%s allow=%s scope=%s)',
                    v_policy_count,
                    v_base_count,
                    v_scope_count
                );
        END IF;

        IF EXISTS (
            SELECT 1
            FROM pg_index i
            WHERE i.indrelid = v_relation_oid
              AND i.indisunique
              AND i.indkey[0] IS DISTINCT FROM v_tenant_attnum
        ) THEN
            RETURN QUERY SELECT
                'read_global_unique_side_channel',
                format('%I.%I', v_table.schema_name, v_table.table_name),
                'every unique index must lead with tenant_id';
        END IF;

        IF v_runtime_oid IS NOT NULL AND EXISTS (
            SELECT 1
            FROM pg_class relation
            CROSS JOIN LATERAL aclexplode(
                COALESCE(relation.relacl, acldefault('r', relation.relowner))
            ) acl
            WHERE relation.oid = v_relation_oid
              AND acl.privilege_type = ANY (ARRAY[
                  'SELECT', 'INSERT', 'UPDATE', 'DELETE',
                  'TRUNCATE', 'REFERENCES', 'TRIGGER'
              ])
              AND (
                  acl.grantee NOT IN (v_runtime_oid, v_owner_oid)
                  OR (acl.grantee = v_runtime_oid AND acl.privilege_type <> 'SELECT')
              )
        ) THEN
            RETURN QUERY SELECT
                'read_table_acl_widening',
                format('%I.%I', v_table.schema_name, v_table.table_name),
                'runtime may receive SELECT only and no other role may receive table privileges';
        END IF;

        IF EXISTS (
            SELECT 1
            FROM pg_constraint fk
            JOIN pg_class parent_class ON parent_class.oid = fk.confrelid
            JOIN pg_namespace parent_namespace
              ON parent_namespace.oid = parent_class.relnamespace
            JOIN (
                SELECT * FROM nano_shared.rls_table_registry
                UNION ALL
                SELECT * FROM nano_shared.rls_read_table_registry
            ) parent_registry
              ON parent_registry.schema_name = parent_namespace.nspname
             AND parent_registry.table_name = parent_class.relname
            JOIN pg_attribute parent_tenant
              ON parent_tenant.attrelid = parent_class.oid
             AND parent_tenant.attname = parent_registry.tenant_column
             AND NOT parent_tenant.attisdropped
            WHERE fk.conrelid = v_relation_oid
              AND fk.contype = 'f'
              AND (
                  NOT (v_tenant_attnum = ANY(fk.conkey))
                  OR NOT (parent_tenant.attnum = ANY(fk.confkey))
                  OR array_position(fk.conkey, v_tenant_attnum)
                     IS DISTINCT FROM array_position(fk.confkey, parent_tenant.attnum)
              )
        ) THEN
            RETURN QUERY SELECT
                'read_unscoped_foreign_key',
                format('%I.%I', v_table.schema_name, v_table.table_name),
                'every foreign key between audited tenant tables must pair tenant_id';
        END IF;
    END LOOP;

    IF EXISTS (
        SELECT 1
        FROM nano_shared.rls_entrypoint_registry e
        LEFT JOIN pg_namespace n ON n.nspname = e.schema_name
        LEFT JOIN pg_class c ON c.relnamespace = n.oid AND c.relname = e.object_name
        WHERE e.object_kind = 'view'
          AND (c.oid IS NULL OR c.relkind <> 'v'
               OR NOT COALESCE(c.reloptions @> ARRAY['security_invoker=true'], FALSE))
    ) THEN
        RETURN QUERY SELECT
            'view_not_security_invoker',
            'nano_shared.rls_entrypoint_registry',
            'every registered view must use security_invoker=true';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM nano_shared.rls_entrypoint_registry e
        LEFT JOIN pg_namespace n ON n.nspname = e.schema_name
        LEFT JOIN pg_proc p ON p.pronamespace = n.oid AND p.proname = e.object_name
        WHERE e.object_kind = 'function'
          AND (p.oid IS NULL OR p.prosecdef)
    ) THEN
        RETURN QUERY SELECT
            'function_not_security_invoker',
            'nano_shared.rls_entrypoint_registry',
            'registered data entrypoint functions must not be SECURITY DEFINER';
    END IF;

    IF (
        SELECT count(*) <> 5 OR COALESCE(bool_or(
            NOT p.prosecdef
            OR NOT COALESCE(p.proconfig, ARRAY[]::text[])
                @> ARRAY['search_path=pg_catalog, nano_shared, pg_temp']
            OR EXISTS (
                SELECT 1
                FROM aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) acl
                WHERE acl.grantee = 0
                  AND acl.privilege_type = 'EXECUTE'
            )
        ), TRUE)
        FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'nano_shared'
          AND p.proname = ANY (ARRAY[
              'current_tenant_id',
              'tenant_row_visible',
              'set_tenant_context',
              'audit_rls_catalog',
              'activate_rls_contract'
          ])
    ) THEN
        RETURN QUERY SELECT
            'security_definer_hardening_invalid',
            'nano_shared',
            'critical SECURITY DEFINER functions require the exact trusted search_path and no PUBLIC execute';
    END IF;

    IF v_runtime_oid IS NOT NULL AND (
        has_table_privilege(p_expected_runtime_role, 'nano_shared.rls_context_keys', 'SELECT,INSERT,UPDATE,DELETE')
        OR has_table_privilege(p_expected_runtime_role, 'nano_shared.rls_role_contract', 'SELECT,INSERT,UPDATE,DELETE')
        OR has_schema_privilege(p_expected_runtime_role, 'nano_shared', 'CREATE')
        OR has_schema_privilege(p_expected_runtime_role, 'public', 'CREATE')
    ) THEN
        RETURN QUERY SELECT
            'runtime_control_plane_privilege',
            p_expected_runtime_role::text,
            'runtime role may not read/write RLS control tables or create objects in trusted schemas';
    END IF;
END
$$;

REVOKE ALL ON FUNCTION nano_shared.audit_rls_catalog(NAME, NAME) FROM PUBLIC;

-- Explicit activation. Roles must already exist; this function never creates
-- a cluster role or key. A different active role/key contract is rejected.
CREATE OR REPLACE FUNCTION nano_shared.activate_rls_contract(
    p_runtime_role NAME,
    p_owner_role NAME,
    p_key_id UUID,
    p_hmac_key BYTEA,
    p_key_not_after TIMESTAMPTZ
) RETURNS VOID
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
PARALLEL UNSAFE
SET search_path = pg_catalog, nano_shared, pg_temp
AS $$
DECLARE
    v_runtime RECORD;
    v_owner RECORD;
    v_existing RECORD;
    v_table RECORD;
    v_relation_owner OID;
BEGIN
    IF p_runtime_role = p_owner_role OR octet_length(p_hmac_key) < 32 THEN
        RAISE EXCEPTION 'invalid enterprise_shared RLS activation inputs';
    END IF;
    IF p_key_not_after <= clock_timestamp() + INTERVAL '1 hour' THEN
        RAISE EXCEPTION 'RLS context key expiry must be at least one hour in the future';
    END IF;

    SELECT * INTO v_runtime FROM pg_roles WHERE rolname = p_runtime_role;
    SELECT * INTO v_owner FROM pg_roles WHERE rolname = p_owner_role;
    IF v_runtime.oid IS NULL OR NOT v_runtime.rolcanlogin OR v_runtime.rolinherit
        OR v_runtime.rolsuper OR v_runtime.rolbypassrls OR v_runtime.rolcreaterole
        OR v_runtime.rolcreatedb OR v_runtime.rolreplication
    THEN
        RAISE EXCEPTION 'runtime role attributes do not satisfy the RLS contract';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_auth_members WHERE member = v_runtime.oid) THEN
        RAISE EXCEPTION 'runtime role must not be a member of another role';
    END IF;
    IF v_owner.oid IS NULL OR v_owner.rolcanlogin OR v_owner.rolinherit
        OR v_owner.rolsuper OR v_owner.rolbypassrls OR v_owner.rolcreaterole
        OR v_owner.rolcreatedb OR v_owner.rolreplication
    THEN
        RAISE EXCEPTION 'owner role attributes do not satisfy the RLS contract';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM pg_auth_members
        WHERE roleid = v_owner.oid OR member = v_owner.oid
    ) THEN
        RAISE EXCEPTION 'owner role must not participate in role membership';
    END IF;

    SELECT * INTO v_existing
    FROM nano_shared.rls_role_contract
    WHERE singleton
    FOR UPDATE;
    IF v_existing.enabled AND (
        v_existing.runtime_role <> p_runtime_role
        OR v_existing.owner_role <> p_owner_role
        OR v_existing.context_key_id <> p_key_id
    ) THEN
        RAISE EXCEPTION 'active RLS role/key contract cannot be replaced in place';
    END IF;

    IF EXISTS (
        SELECT 1 FROM nano_shared.rls_context_keys
        WHERE key_id = p_key_id AND hmac_key <> p_hmac_key
    ) THEN
        RAISE EXCEPTION 'existing RLS key id has different key material';
    END IF;
    INSERT INTO nano_shared.rls_context_keys (
        key_id, hmac_key, not_before, not_after, revoked_at
    ) VALUES (
        p_key_id, p_hmac_key, clock_timestamp() - INTERVAL '1 minute', p_key_not_after, NULL
    )
    ON CONFLICT (key_id) DO UPDATE
    SET not_after = GREATEST(nano_shared.rls_context_keys.not_after, EXCLUDED.not_after),
        revoked_at = NULL;

    FOR v_table IN SELECT * FROM nano_shared.rls_table_registry ORDER BY schema_name, table_name LOOP
        IF NOT EXISTS (
            SELECT 1
            FROM pg_policy p
            JOIN pg_class c ON c.oid = p.polrelid
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = v_table.schema_name
              AND c.relname = v_table.table_name
              AND p.polname = 'nano_shared_tenant_scope'
        ) THEN
            EXECUTE format(
                'CREATE POLICY nano_shared_tenant_scope ON %I.%I '
                'AS RESTRICTIVE FOR ALL TO %I '
                'USING (nano_shared.tenant_row_visible(%I)) '
                'WITH CHECK (nano_shared.tenant_row_visible(%I))',
                v_table.schema_name,
                v_table.table_name,
                p_runtime_role,
                v_table.tenant_column,
                v_table.tenant_column
            );
        END IF;
        SELECT c.relowner
        INTO v_relation_owner
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = v_table.schema_name
          AND c.relname = v_table.table_name
          AND c.relkind IN ('r', 'p');

        IF v_relation_owner <> v_owner.oid THEN
            -- Grant before transferring ownership. The activation definer owns
            -- a newly migrated table, but deliberately cannot become the
            -- NOLOGIN data owner later merely to repair privileges.
            EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %I.%I TO %I',
                v_table.schema_name, v_table.table_name, p_runtime_role);
            EXECUTE format('ALTER TABLE %I.%I OWNER TO %I',
                v_table.schema_name, v_table.table_name, p_owner_role);
        ELSIF NOT has_table_privilege(
            p_runtime_role,
            format('%I.%I', v_table.schema_name, v_table.table_name),
            'SELECT,INSERT,UPDATE,DELETE'
        ) THEN
            RAISE EXCEPTION
                'runtime DML grant is missing on already-owned RLS table %.%; refusing partial repair',
                v_table.schema_name,
                v_table.table_name;
        END IF;
    END LOOP;

    EXECUTE format('GRANT USAGE ON SCHEMA nano_shared TO %I', p_runtime_role);
    EXECUTE format(
        'GRANT EXECUTE ON FUNCTION nano_shared.set_tenant_context(name,name,uuid,uuid,bigint,uuid,uuid,text) TO %I',
        p_runtime_role
    );
    EXECUTE format(
        'GRANT EXECUTE ON FUNCTION nano_shared.current_tenant_id() TO %I',
        p_runtime_role
    );
    EXECUTE format(
        'GRANT EXECUTE ON FUNCTION nano_shared.tenant_row_visible(uuid) TO %I',
        p_runtime_role
    );
    EXECUTE format(
        'GRANT SELECT ON nano_shared.tenant_search_history_visible TO %I',
        p_runtime_role
    );
    EXECUTE format(
        'GRANT EXECUTE ON FUNCTION nano_shared.list_tenant_search_history(integer) TO %I',
        p_runtime_role
    );

    UPDATE nano_shared.rls_role_contract
    SET runtime_role = p_runtime_role,
        owner_role = p_owner_role,
        context_key_id = p_key_id,
        enabled = TRUE,
        activated_at = COALESCE(activated_at, clock_timestamp()),
        updated_at = clock_timestamp()
    WHERE singleton;
END
$$;

REVOKE ALL ON FUNCTION nano_shared.activate_rls_contract(NAME, NAME, UUID, BYTEA, TIMESTAMPTZ) FROM PUBLIC;

COMMENT ON SCHEMA nano_shared IS
    'Dormant enterprise_shared RLS control plane. No roles/key are created by migrations.';
COMMENT ON TABLE public.tenant_search_preferences IS
    'Shared-only tenant search preference slice; legacy users settings remain unchanged.';
COMMENT ON TABLE public.tenant_search_history IS
    'Shared-only tenant search history with tenant-first identity and forced RLS.';
COMMENT ON TABLE nano_shared.rls_context_keys IS
    'Operator-installed HMAC verifier keys; migration 320 leaves this empty.';
COMMENT ON FUNCTION nano_shared.set_tenant_context(NAME, NAME, UUID, UUID, BIGINT, UUID, UUID, TEXT) IS
    'Verifies an externally signed <=60s tenant context and installs a transaction-bound proof.';
