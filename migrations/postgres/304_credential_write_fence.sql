-- SPDX-License-Identifier: AGPL-3.0-or-later
-- NAN-4933 (L9, codex review P1): durable write fence for credential key
-- retirement.
--
-- Every service process declares the key it encrypts with on each of its
-- PostgreSQL sessions (`nano.credential_write_key`, set by the pool's
-- after_connect from the process key ring). A trigger on every secret column
-- (crypto::rotation::TARGETS) checks, in the WRITING transaction, that the
-- declared key is registered and not retired, holding FOR SHARE on its
-- credential_keys row. Retirement takes FOR UPDATE on that row before its
-- confirming scan, so:
--   * a write in flight when retirement starts commits first and is seen by
--     the scan (retirement is then refused: the key is still referenced);
--   * a write that arrives after retirement (e.g. a process paused for longer
--     than the membership TTL, then resumed) is refused, never stored under a
--     key operators are about to delete.
-- Membership heartbeats remain for observability only.
--
-- A session that declares no key (ad-hoc SQL, test fixtures) is not fenced;
-- every api/jobs pool declares one. A transaction-mode connection pooler in
-- front of PostgreSQL would share session settings across processes and must
-- not be used for the api/jobs pools.
SET LOCAL lock_timeout = '5s';

CREATE OR REPLACE FUNCTION public.credential_write_fence()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    v_column TEXT := TG_ARGV[0];
    v_key TEXT := NULLIF(current_setting('nano.credential_write_key', true), '');
    v_new BYTEA;
    v_old BYTEA;
    v_state TEXT;
BEGIN
    EXECUTE format('SELECT ($1).%I', v_column) INTO v_new USING NEW;
    IF v_new IS NULL THEN
        RETURN NEW;
    END IF;
    IF TG_OP = 'UPDATE' THEN
        EXECUTE format('SELECT ($1).%I', v_column) INTO v_old USING OLD;
        IF v_old IS NOT DISTINCT FROM v_new THEN
            RETURN NEW;
        END IF;
    END IF;
    IF v_key IS NULL THEN
        RETURN NEW;
    END IF;
    SELECT k.state INTO v_state
      FROM public.credential_keys k
     WHERE k.key_id = v_key
       FOR SHARE;
    IF v_state IS NULL THEN
        RAISE EXCEPTION 'credential key % is not registered; refusing to store %.% under it', v_key, TG_TABLE_NAME, v_column
            USING ERRCODE = 'P0001', HINT = 'restart the process so it registers its key ring';
    END IF;
    IF v_state = 'retired' THEN
        RAISE EXCEPTION 'credential key % is retired; refusing to store %.% under it', v_key, TG_TABLE_NAME, v_column
            USING ERRCODE = 'P0001', HINT = 'this process still runs a key ring whose active key was retired; restart it with the current NANOSIEM_ENCRYPTION_KEY';
    END IF;
    RETURN NEW;
END
$$;

-- Install the trigger on each secret column that exists (open schema).
CREATE OR REPLACE FUNCTION public.install_credential_write_fence(p_table TEXT, p_column TEXT)
RETURNS void
LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
         WHERE table_schema = 'public' AND table_name = p_table AND column_name = p_column
    ) THEN
        RETURN;
    END IF;
    EXECUTE format('DROP TRIGGER IF EXISTS %I ON public.%I', 'credential_write_fence_' || p_column, p_table);
    EXECUTE format(
        'CREATE TRIGGER %I BEFORE INSERT OR UPDATE OF %I ON public.%I FOR EACH ROW EXECUTE FUNCTION public.credential_write_fence(%L)',
        'credential_write_fence_' || p_column, p_column, p_table, p_column
    );
END
$$;

SELECT public.install_credential_write_fence(t, c) FROM (VALUES
    ('cloud_credentials', 'credentials_encrypted'),
    ('cloud_credential_versions', 'credentials_encrypted'),
    ('marketplace_catalog', 'credentials_encrypted'),
    ('system_settings', 'tiering_s3_credentials_encrypted'),
    ('detection_code_targets', 'token_encrypted'),
    ('users', 'totp_secret_encrypted'),
    ('users', 'backup_codes_encrypted'),
    ('oidc_providers', 'client_secret_encrypted'),
    ('oidc_providers', 'google_service_account_encrypted'),
    ('provider_credentials', 'credentials_encrypted'),
    ('agent_enrichment_providers', 'api_key_encrypted'),
    ('identity_providers', 'credentials_encrypted'),
    ('webhooks', 'url_encrypted'),
    ('webhooks', 'headers_encrypted'),
    ('webhooks', 'secret_encrypted')
) AS targets(t, c);
