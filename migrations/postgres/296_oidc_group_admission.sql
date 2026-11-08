-- NAN-3904 / NAN-3908 / NAN-3935 (ported to clickhouse/dev by NAN-4902 lane H;
-- main's open 368_oidc_group_admission.sql, renumbered, hosted owner-window
-- wrapper dropped): SSO admission is gated on mapped IdP groups, with no
-- default grant.
--
-- WHY
--
-- OIDC just-in-time provisioning used to create a local account for ANY user
-- the identity provider authenticated, and the Everyone trigger then gave that
-- account the baseline ReadOnly role. Group sync only ever ADDED mapped
-- groups, so removing someone from an IdP group never removed their access.
--
-- WHAT
--
-- 1. users.sso_jit marks accounts created by SSO JIT. Only those accounts are
--    admitted and re-checked against the provider's mapped groups on every
--    sign-in; any other account (created locally, by invitation, or before
--    this migration) is "invited" and keeps signing in. New SSO JIT accounts
--    are NOT auto-joined to Everyone: they receive exactly the groups their
--    mapped IdP groups grant.
-- 2. oidc_group_grant_sources remembers WHY each user_groups row exists:
--    'manual' (any writer that does not say otherwise) or
--    'sso_group:<provider_id>:<idp_group>' (set transaction-locally by the
--    sign-in reconciler via nano.sso_grant_source). Reconciliation removes a
--    membership only when no source remains, so a manual grant survives the
--    IdP dropping the same group, and an SSO grant disappears when the IdP
--    group is no longer asserted.
--
-- 3. users.authz_generation is a per-user authorization generation, bumped by a
--    trigger on every effective user_groups INSERT/DELETE (SSO reconcile,
--    mapping replacement and admin edits alike) in the writing transaction.
--    The permission, user-status and source-scope caches of every process
--    (api and search replicas) compare it on each cache hit, so a group shrink
--    takes effect on the next request everywhere, not at the cache TTL.
-- 4. sessions.previous_refresh_token_hash / rotated_at let the API tolerate
--    the immediately previous refresh token for a short grace window (two
--    browser tabs refreshing at the same moment): the loser receives an access
--    token for the same session instead of a 401 that clears the winner's
--    freshly rotated cookie. The refresh chain is never forked.
--
-- Provenance backfill: every pre-existing membership is first recorded as
-- 'manual' here (the open schema cannot see OIDC mappings on a fresh open
-- install). Enterprise migration 9000078 then re-attributes memberships that
-- the old OIDC sync created to their sso_group source (see its header for the
-- overlap policy). The provenance trigger is SECURITY DEFINER (migrator-owned,
-- like the other user_groups bookkeeping triggers) so every role that may write
-- user_groups keeps working without a provenance grant. Idempotent.
SET LOCAL lock_timeout = '5s';

ALTER TABLE public.users ADD COLUMN IF NOT EXISTS sso_jit BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE public.users ADD COLUMN IF NOT EXISTS authz_generation BIGINT NOT NULL DEFAULT 0;
ALTER TABLE public.sessions ADD COLUMN IF NOT EXISTS previous_refresh_token_hash VARCHAR(255);
ALTER TABLE public.sessions ADD COLUMN IF NOT EXISTS rotated_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS sessions_previous_refresh_token_hash_idx
    ON public.sessions (previous_refresh_token_hash)
    WHERE previous_refresh_token_hash IS NOT NULL;

CREATE TABLE IF NOT EXISTS public.oidc_group_grant_sources (
    user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES public.groups(id) ON DELETE CASCADE,
    source TEXT NOT NULL CHECK (length(source) BETWEEN 1 AND 600),
    PRIMARY KEY (user_id, group_id, source)
);
REVOKE ALL ON public.oidc_group_grant_sources FROM PUBLIC;

INSERT INTO public.oidc_group_grant_sources (user_id, group_id, source)
SELECT user_id, group_id, 'manual' FROM public.user_groups
ON CONFLICT DO NOTHING;

CREATE OR REPLACE FUNCTION public.track_oidc_group_grant_source() RETURNS TRIGGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_TABLE_SCHEMA <> 'public' OR TG_TABLE_NAME <> 'user_groups'
       OR TG_LEVEL <> 'ROW' OR TG_OP NOT IN ('INSERT', 'DELETE') THEN
        RAISE EXCEPTION 'invalid OIDC group grant source trigger' USING ERRCODE = '42501';
    END IF;
    IF TG_OP = 'INSERT' THEN
        -- BEFORE INSERT: recorded even when the membership row already exists
        -- (ON CONFLICT DO NOTHING), so a second source is never lost.
        INSERT INTO public.oidc_group_grant_sources (user_id, group_id, source)
        VALUES (NEW.user_id, NEW.group_id,
                COALESCE(NULLIF(current_setting('nano.sso_grant_source', TRUE), ''), 'manual'))
        ON CONFLICT DO NOTHING;
        RETURN NEW;
    END IF;
    DELETE FROM public.oidc_group_grant_sources
     WHERE user_id = OLD.user_id AND group_id = OLD.group_id;
    RETURN OLD;
END $$;
REVOKE ALL ON FUNCTION public.track_oidc_group_grant_source() FROM PUBLIC;

DROP TRIGGER IF EXISTS track_oidc_group_grant_insert ON public.user_groups;
CREATE TRIGGER track_oidc_group_grant_insert BEFORE INSERT ON public.user_groups
FOR EACH ROW EXECUTE FUNCTION public.track_oidc_group_grant_source();
DROP TRIGGER IF EXISTS track_oidc_group_grant_delete ON public.user_groups;
CREATE TRIGGER track_oidc_group_grant_delete AFTER DELETE ON public.user_groups
FOR EACH ROW EXECUTE FUNCTION public.track_oidc_group_grant_source();

-- No default grant for SSO JIT accounts: they are not auto-joined to Everyone
-- (which carries the baseline ReadOnly role).
CREATE OR REPLACE FUNCTION public.add_user_to_everyone_group() RETURNS TRIGGER
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NOT NEW.sso_jit THEN
        INSERT INTO public.user_groups (user_id, group_id)
        VALUES (NEW.id, '00000000-0000-0000-0000-000000000001')
        ON CONFLICT DO NOTHING;
    END IF;
    RETURN NEW;
END $$;

-- Per-user authorization generation (see 3. above). AFTER ROW so it fires only
-- for effective inserts/deletes (ON CONFLICT DO NOTHING is not a change).
CREATE OR REPLACE FUNCTION public.bump_user_authz_generation() RETURNS TRIGGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_TABLE_SCHEMA <> 'public' OR TG_TABLE_NAME <> 'user_groups'
       OR TG_LEVEL <> 'ROW' OR TG_OP NOT IN ('INSERT', 'DELETE') THEN
        RAISE EXCEPTION 'invalid authz generation trigger' USING ERRCODE = '42501';
    END IF;
    UPDATE public.users SET authz_generation = authz_generation + 1
     WHERE id = CASE WHEN TG_OP = 'INSERT' THEN NEW.user_id ELSE OLD.user_id END;
    RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION public.bump_user_authz_generation() FROM PUBLIC;
DROP TRIGGER IF EXISTS bump_user_authz_generation ON public.user_groups;
CREATE TRIGGER bump_user_authz_generation AFTER INSERT OR DELETE ON public.user_groups
FOR EACH ROW EXECUTE FUNCTION public.bump_user_authz_generation();
