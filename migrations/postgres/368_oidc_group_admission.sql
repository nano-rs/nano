-- NAN-3904: DDL on an activated tenant database needs the managed owner window.
SET LOCAL lock_timeout='5s';
DO $sso_migration$
DECLARE owner_role NAME; owner_token INTEGER:=0;
BEGIN
    IF to_regproc('nano_shared.begin_managed_owner_bootstrap') IS NOT NULL THEN
        SELECT c.owner_role INTO owner_role FROM nano_shared.rls_role_contract c WHERE singleton AND enabled;
        IF owner_role IS NOT NULL THEN owner_token:=nano_shared.begin_managed_owner_bootstrap(owner_role); END IF;
    END IF;
    EXECUTE $sso_ddl$
ALTER TABLE public.users ADD COLUMN sso_jit BOOLEAN NOT NULL DEFAULT FALSE;
-- Provenance is independent of the effective membership, so a manual insert
-- that conflicts with an SSO membership is still remembered by a BEFORE trigger.
CREATE TABLE public.oidc_group_grant_sources (
    user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES public.groups(id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    PRIMARY KEY(user_id,group_id,source)
);
REVOKE ALL ON public.oidc_group_grant_sources FROM PUBLIC;
INSERT INTO public.oidc_group_grant_sources SELECT user_id,group_id,'manual' FROM public.user_groups;
-- SECURITY DEFINER (migrator-owned, like the other user_groups bookkeeping
-- triggers): every role that may write user_groups (the provisioning owner,
-- operators, dedicated app roles) keeps working without a provenance grant
-- that only a later enterprise reconcile would supply. Trigger-only.
CREATE FUNCTION public.track_oidc_group_grant_source() RETURNS TRIGGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
    IF TG_TABLE_SCHEMA<>'public' OR TG_TABLE_NAME<>'user_groups' OR TG_LEVEL<>'ROW' OR TG_OP NOT IN ('INSERT','DELETE') THEN
        RAISE EXCEPTION 'invalid OIDC group grant source trigger' USING ERRCODE='42501';
    END IF;
    IF TG_OP='INSERT' THEN
        INSERT INTO public.oidc_group_grant_sources(user_id,group_id,source)
        VALUES(NEW.user_id,NEW.group_id,COALESCE(NULLIF(current_setting('nano.sso_grant_source',TRUE),''),'manual'))
        ON CONFLICT DO NOTHING;
        RETURN NEW;
    END IF;
    DELETE FROM public.oidc_group_grant_sources WHERE user_id=OLD.user_id AND group_id=OLD.group_id;
    RETURN OLD;
END $$;
REVOKE ALL ON FUNCTION public.track_oidc_group_grant_source() FROM PUBLIC;
CREATE TRIGGER track_oidc_group_grant_insert BEFORE INSERT ON public.user_groups
FOR EACH ROW EXECUTE FUNCTION public.track_oidc_group_grant_source();
CREATE TRIGGER track_oidc_group_grant_delete AFTER DELETE ON public.user_groups
FOR EACH ROW EXECUTE FUNCTION public.track_oidc_group_grant_source();
CREATE OR REPLACE FUNCTION public.add_user_to_everyone_group() RETURNS TRIGGER
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
    IF NOT NEW.sso_jit THEN
        INSERT INTO public.user_groups(user_id,group_id)
        VALUES(NEW.id,'00000000-0000-0000-0000-000000000001') ON CONFLICT DO NOTHING;
    END IF;
    RETURN NEW;
END $$;

$sso_ddl$;
    IF owner_role IS NOT NULL THEN PERFORM nano_shared.end_managed_owner_bootstrap(owner_role,owner_token); END IF;
END $sso_migration$;
