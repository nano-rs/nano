-- SPDX-License-Identifier: AGPL-3.0-or-later
-- NAN-4933 (L9, codex fence review P1): the credential write fence fails
-- CLOSED for writers that do not declare their key, once enforced.
--
-- Migration 304 let a session without `nano.credential_write_key` write
-- secrets unchecked. That cannot simply become a rejection in the same
-- release: during a rolling deploy the previous api/jobs pods (which do not
-- declare a key) keep serving after this schema lands, and every secret write
-- they make would fail. So enforcement is a durable flag:
--
--   enforce = false (installed default, rollout mode)
--       Declared writers are fully fenced (registered + not retired).
--       Undeclared writers are allowed, but take FOR SHARE on this row.
--   enforce = true  (one-way)
--       A secret write from an undeclared session is refused.
--
-- The flag flips to true automatically at the FIRST key retirement (by then
-- every process has been restarted onto the rotated ring, and so declares its
-- key), or explicitly with `nanosiem-jobs credential-keys enforce`. The flip
-- is an UPDATE of this row, so it waits for every in-flight undeclared write
-- (each holds FOR SHARE) to commit; retirement's confirming scan therefore
-- sees them, and no undeclared write can land afterwards.
--
-- Sequencing: deploy this release everywhere (every api/jobs/migrator pool
-- then declares its key) -> rotate -> re-wrap -> retire (enforces).
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS public.credential_write_fence_state (
    singleton   BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    enforce     BOOLEAN NOT NULL DEFAULT FALSE,
    enforced_at TIMESTAMPTZ,
    enforced_by TEXT
);
INSERT INTO public.credential_write_fence_state (singleton) VALUES (TRUE)
ON CONFLICT (singleton) DO NOTHING;

COMMENT ON TABLE public.credential_write_fence_state IS
    'Credential write fence mode: enforce=true refuses secret writes from sessions that declare no credential key (NAN-4933)';

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
    v_enforce BOOLEAN;
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
        SELECT s.enforce INTO v_enforce
          FROM public.credential_write_fence_state s
         WHERE s.singleton
           FOR SHARE;
        -- A missing state row fails closed.
        IF COALESCE(v_enforce, TRUE) THEN
            RAISE EXCEPTION 'refusing to store %.%: this session declares no credential key (nano.credential_write_key) and the credential write fence is enforced', TG_TABLE_NAME, v_column
                USING ERRCODE = 'P0001', HINT = 'secret writes must come from an api/jobs/CLI process whose pool declares its key';
        END IF;
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
