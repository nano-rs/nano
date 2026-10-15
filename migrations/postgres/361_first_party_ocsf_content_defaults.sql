-- NAN-3758: first-party content repositories default to the lake's OCSF 1.9
-- branch. A global 'ocsf-1.9' column default would break Sigma/third-party
-- repositories, so the column default is dropped and a BEFORE INSERT trigger
-- supplies a URL-aware default before NOT NULL validation. Explicit branches
-- (including 'main') stay caller-owned.
--
-- Existing rows are not rewritten here: the leader's first-party catalog
-- reconcile (nanosiem-core content_catalog_defaults) moves an enabled
-- nano-rs/parsers or nano-rs/rules row off 'main' on its next start and
-- audits it. This build runs only the lake/OCSF lane; the frozen ClickHouse
-- fleet runs older images and never applies this migration.
--
-- NAN-3782 fix-forward: this body first shipped as 357 with plain DDL on
-- `parser_repositories` / `rule_repositories`, which an activated
-- enterprise_shared database has moved to the managed data owner, so the
-- migrator would be refused there exactly as 354 was. 357 is retired
-- (removed, not edited, as 344 was; ignore_missing tolerates the applied row
-- and this file re-applies the same idempotent body). The trigger function
-- stays owned by the migrator; the table DDL runs inside the 9000140
-- managed-owner bootstrap window when one exists, as 329 does.
CREATE OR REPLACE FUNCTION public.nano_content_repository_default_branch()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $function$
BEGIN
    IF NEW.branch IS NULL THEN
        NEW.branch := CASE
            WHEN NEW.url ~* '^(https?://)?(www[.])?github[.]com/nano-rs/(parsers|rules)([.]git)?/?$'
                THEN 'ocsf-1.9'
            ELSE 'main'
        END;
    END IF;
    RETURN NEW;
END
$function$;

DO $content_repository_default_branch$
DECLARE
    owner_role NAME;
    owner_token INTEGER := 0;
BEGIN
    IF to_regproc('nano_shared.begin_managed_owner_bootstrap') IS NOT NULL THEN
        SELECT contract.owner_role INTO owner_role
          FROM nano_shared.rls_role_contract contract WHERE singleton AND enabled;
        IF owner_role IS NOT NULL THEN
            owner_token := nano_shared.begin_managed_owner_bootstrap(owner_role);
        END IF;
    END IF;

    ALTER TABLE public.parser_repositories ALTER COLUMN branch DROP DEFAULT;
    ALTER TABLE public.rule_repositories ALTER COLUMN branch DROP DEFAULT;

    DROP TRIGGER IF EXISTS nano_parser_repository_default_branch ON public.parser_repositories;
    CREATE TRIGGER nano_parser_repository_default_branch
        BEFORE INSERT ON public.parser_repositories FOR EACH ROW
        EXECUTE FUNCTION public.nano_content_repository_default_branch();
    DROP TRIGGER IF EXISTS nano_rule_repository_default_branch ON public.rule_repositories;
    CREATE TRIGGER nano_rule_repository_default_branch
        BEFORE INSERT ON public.rule_repositories FOR EACH ROW
        EXECUTE FUNCTION public.nano_content_repository_default_branch();

    IF owner_role IS NOT NULL THEN
        PERFORM nano_shared.end_managed_owner_bootstrap(owner_role, owner_token);
    END IF;
END
$content_repository_default_branch$;
