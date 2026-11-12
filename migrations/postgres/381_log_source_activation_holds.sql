-- SPDX-License-Identifier: AGPL-3.0-or-later
-- NAN-5132 (PR 5): two-phase activation of a log source.
--
-- Adding or removing a routed log source now takes two Vector reloads:
--
--   A. stage: the source's parser chain is rendered PARKED (its entry reads the
--      never-matching fan-in slot filter, and the source router has no route
--      for it). Every ingest host must install and acknowledge this generation.
--      Routing is unchanged, so a host that refuses it changes nothing.
--   B. activate: the router route is added (or, for a removal, the parked chain
--      is dropped). Published only after every host acknowledged A.
--
-- A row here is "this source renders parked". It must live in PostgreSQL, not
-- in the deploying process: on a role-split install every app host renders and
-- publishes the configuration from the database (the 5 s publication
-- reconciler), so a hold kept in memory would be overwritten by the full
-- render before phase A was verified. Inserting or deleting a row bumps the
-- publication source revision, like routing_rules.
--
-- A hold only exists while a deploy or undeploy runs. One left by a process
-- that died is released by the next deploy, undeploy or API start once it is
-- older than the deploy wait (see `release_stale_activation_holds`).
CREATE TABLE IF NOT EXISTS public.log_source_activation_holds (
    log_source_id UUID PRIMARY KEY REFERENCES public.log_sources(id) ON DELETE CASCADE,
    -- 'deploy' (phase A of an add) or 'undeploy' (phase A of a removal).
    purpose       TEXT NOT NULL CHECK (purpose IN ('deploy', 'undeploy')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

DROP TRIGGER IF EXISTS vector_config_activation_holds_change ON public.log_source_activation_holds;
CREATE TRIGGER vector_config_activation_holds_change
BEFORE INSERT OR UPDATE OR DELETE ON public.log_source_activation_holds
FOR EACH STATEMENT EXECUTE FUNCTION bump_vector_config_source_revision();
