-- NAN-3806: an ingest token decides the source. 100% token based.
--
-- Every named ingest token (358) and the install token (VECTOR_AUTH_TOKEN) is
-- bound to exactly one log source. nano-api renders the bound source's route
-- key into Vector's hashed tokens file, and the HEC / HTTP lanes set
-- `.source_type` from the token alone: a `sourcetype` / `X-Source-Type` the
-- sender declares no longer selects the parser (it survives only as the raw
-- `claimed_source_type` field). There is no multiplex and no fallback mode:
-- a token with no bound source is left out of the file, so Vector refuses it
-- (HTTP 401) until an admin binds it.
--
-- Existing tokens are bound here when the choice is unambiguous, looking only
-- at enabled, push-capable log sources (HTTP / HEC / Vector lanes; never
-- OTLP or a fetch transport such as Kafka or S3):
--   1. exactly one enabled push-capable source exists -> every unbound active
--      token, and the install token, is bound to it;
--   2. otherwise a named token whose name equals (case-insensitively) the
--      name or one match value of exactly one such source is bound to it.
-- Everything else stays unbound and is refused until an admin binds it in
-- Ingestion -> Credentials. Nothing is guessed from event content.
--
-- `request_count` / `vector_request_counter`: per-token request count,
-- accumulated from Vector's `hashed_token_requests_total{credential_id}`
-- (`vector_request_counter` = the last raw counter value seen, so a counter
-- reset after a Vector restart is detected and several API replicas never
-- double count).
--
-- Additive and idempotent. On an activated enterprise_shared database where
-- 9013540 already moved the tables to the data owner, the migrator can no
-- longer ALTER them; this file then leaves the columns to
-- `9013590_ingest_token_sources.sql` (hosted tenants never use these tables:
-- their tokens are bound to sources at the edge Worker).
SET LOCAL lock_timeout = '5s';

DO $nan3806_token_sources$
DECLARE
    v_owner OID;
    v_settings_owner OID;
    v_only_source UUID;
    v_candidates BIGINT;
BEGIN
    SELECT relowner INTO v_owner FROM pg_catalog.pg_class WHERE oid = 'public.ingest_tokens'::regclass;
    SELECT relowner INTO v_settings_owner FROM pg_catalog.pg_class WHERE oid = 'public.ingest_token_settings'::regclass;
    IF NOT pg_catalog.pg_has_role(current_user, v_owner, 'USAGE')
       OR NOT pg_catalog.pg_has_role(current_user, v_settings_owner, 'USAGE') THEN
        RAISE NOTICE 'ingest_tokens is owned by %; 9013590 applies the source binding columns', v_owner::regrole;
        RETURN;
    END IF;

    ALTER TABLE public.ingest_tokens
        ADD COLUMN IF NOT EXISTS source_id UUID,
        ADD COLUMN IF NOT EXISTS source_bound_at TIMESTAMPTZ,
        ADD COLUMN IF NOT EXISTS source_bound_by UUID,
        ADD COLUMN IF NOT EXISTS request_count BIGINT NOT NULL DEFAULT 0,
        ADD COLUMN IF NOT EXISTS vector_request_counter DOUBLE PRECISION;
    ALTER TABLE public.ingest_token_settings
        ADD COLUMN IF NOT EXISTS install_token_source_id UUID,
        ADD COLUMN IF NOT EXISTS install_token_source_bound_at TIMESTAMPTZ,
        ADD COLUMN IF NOT EXISTS install_token_source_bound_by UUID;

    -- Open core / dedicated only: `log_sources` is the deployment's parser
    -- registry there (no tenant column).
    IF to_regclass('public.log_sources') IS NULL THEN
        RETURN;
    END IF;

    SELECT count(*), min(ls.id::TEXT)::UUID INTO v_candidates, v_only_source
      FROM public.log_sources ls
     WHERE ls.enabled AND ls.source_type NOT IN (
           'opentelemetry', 'otlp', 'kafka', 'aws_s3', 'aws_sqs', 's3', 'gcp_pubsub', 'pubsub', 'azure_event_hubs');

    IF v_candidates = 1 THEN
        UPDATE public.ingest_tokens
           SET source_id = v_only_source, source_bound_at = now()
         WHERE source_id IS NULL AND revoked_at IS NULL;
        -- The install token: the open-core compatibility tenant (319).
        INSERT INTO public.ingest_token_settings
               (tenant_id, install_token_enabled, install_token_source_id, install_token_source_bound_at, updated_at)
        SELECT t.id, TRUE, v_only_source, now(), now()
          FROM public.tenants t
         WHERE t.id = '00000000-0000-0000-0000-000000000100'
        ON CONFLICT (tenant_id) DO UPDATE
           SET install_token_source_id = EXCLUDED.install_token_source_id,
               install_token_source_bound_at = EXCLUDED.install_token_source_bound_at
         WHERE public.ingest_token_settings.install_token_source_id IS NULL;
    ELSIF v_candidates > 1 THEN
        WITH push_sources AS (
            SELECT ls.id, lower(ls.name) AS name,
                   COALESCE((SELECT array_agg(lower(btrim(v))) FROM unnest(ls.match_values) v),
                            ARRAY[]::TEXT[]) AS match_values
              FROM public.log_sources ls
             WHERE ls.enabled AND ls.source_type NOT IN (
                   'opentelemetry', 'otlp', 'kafka', 'aws_s3', 'aws_sqs', 's3', 'gcp_pubsub', 'pubsub', 'azure_event_hubs')
        ), matches AS (
            SELECT t.tenant_id, t.id, min(s.id::TEXT)::UUID AS source_id, count(*) AS n
              FROM public.ingest_tokens t
              JOIN push_sources s
                ON s.name = lower(t.name) OR lower(t.name) = ANY (s.match_values)
             WHERE t.source_id IS NULL AND t.revoked_at IS NULL
             GROUP BY t.tenant_id, t.id
        )
        UPDATE public.ingest_tokens t
           SET source_id = m.source_id, source_bound_at = now()
          FROM matches m
         WHERE m.n = 1 AND t.tenant_id = m.tenant_id AND t.id = m.id;
    END IF;
END
$nan3806_token_sources$;
