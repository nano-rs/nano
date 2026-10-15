-- NAN-3897: the first-party content repositories follow `main` again.
--
-- nano-rs/parsers and nano-rs/rules moved the OCSF 1.9 content onto `main`
-- (the pre-1.9 content is archived on `legacy/clickhouse`, which this app
-- never follows). NAN-3758 (361) defaulted these repositories to the
-- `ocsf-1.9` branch; that branch stays upstream for open-core v1.0.0 but is
-- retired here:
--
--   * the 361 BEFORE INSERT trigger function now supplies 'main' for every
--     omitted branch (the column default stays dropped and the triggers stay
--     attached, so no table DDL is needed);
--   * rows of nano-rs/parsers / nano-rs/rules still on 'ocsf-1.9' move to
--     'main' and are made due (last_synced_at / last_sync_commit cleared) so
--     the next scheduler pass syncs main. Any other branch (a fork or an
--     operator pin) and every third-party repository is untouched.
--
-- The app resolves a stored 'ocsf-1.9' to 'main' as well, so a row this
-- migration has not reached yet still syncs main.
--
-- The URL match is the one 361 uses and mirrors
-- `schema::is_first_party_content_url`: optional scheme and www, any case,
-- optional `.git` and trailing slash. Idempotent: a second pass matches
-- nothing.
--
-- On an activated enterprise_shared database both tables are owned by the
-- NOLOGIN data owner and are FORCE RLS; the UPDATE runs inside the 9000140
-- managed-owner bootstrap window (as 362 does), which sees every tenant's
-- rows. Open core and dedicated own the tables and update them directly.
CREATE OR REPLACE FUNCTION public.nano_content_repository_default_branch()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $function$
BEGIN
    IF NEW.branch IS NULL THEN
        NEW.branch := 'main';
    END IF;
    RETURN NEW;
END
$function$;

DO $first_party_content_follows_main$
DECLARE
    owner_role NAME;
    owner_token INTEGER := 0;
    first_party CONSTANT TEXT := '^(https?://)?(www[.])?github[.]com/nano-rs/(parsers|rules)([.]git)?/?$';
BEGIN
    IF to_regproc('nano_shared.begin_managed_owner_bootstrap') IS NOT NULL THEN
        SELECT contract.owner_role INTO owner_role
          FROM nano_shared.rls_role_contract contract WHERE singleton AND enabled;
        IF owner_role IS NOT NULL
           AND pg_catalog.pg_get_userbyid((SELECT relowner FROM pg_catalog.pg_class
                                           WHERE oid = 'public.parser_repositories'::regclass)) = owner_role THEN
            owner_token := nano_shared.begin_managed_owner_bootstrap(owner_role);
        END IF;
    END IF;

    UPDATE public.parser_repositories
       SET branch = 'main', last_synced_at = NULL, last_sync_commit = NULL, updated_at = now()
     WHERE btrim(branch) = 'ocsf-1.9'
       AND url ~* first_party;

    UPDATE public.rule_repositories
       SET branch = 'main', last_synced_at = NULL, last_sync_commit = NULL, updated_at = now()
     WHERE btrim(branch) = 'ocsf-1.9'
       AND url ~* first_party;

    IF owner_token <> 0 THEN
        PERFORM nano_shared.end_managed_owner_bootstrap(owner_role, owner_token);
    END IF;
END
$first_party_content_follows_main$;
