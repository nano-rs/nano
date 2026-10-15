-- NAN-3503: identity directory-sync feeds (connector spec `kind: identity`).
--
-- An identity feed writes the tenant's identity directory through the
-- tenant's lean enrichment coordinator (staged snapshots + deltas), not the
-- tenant ingress: it has no HEC URL and no ingest credential. `sink` names
-- where a feed's rows go (`hec` = every existing feed, the default;
-- `identity`). The runner claims an identity feed without a token and the
-- credential issuance pass skips it.
--
-- Additive and idempotent. Requires 340 (credential columns). On an
-- activated enterprise_shared database where 9012400 already moved the table
-- to the data owner, the migrator can no longer ALTER it; this file then
-- leaves the change to `9013180_connector_feed_identity_sink.sql`, which
-- applies the SAME body under the managed-owner bootstrap
-- (nano-connector/tests/migration_parity.rs keeps the two bodies identical).

-- A busy connector_feeds (runner claims every poll) must not queue every
-- other writer behind this ALTER: give up after 5 s and let the migrator
-- retry.
SET LOCAL lock_timeout = '5s';

DO $nan3503_sink$
DECLARE
    v_owner OID;
BEGIN
    SELECT relowner INTO v_owner FROM pg_catalog.pg_class WHERE oid = 'public.connector_feeds'::regclass;
    IF NOT pg_catalog.pg_has_role(current_user, v_owner, 'USAGE') THEN
        RAISE NOTICE 'connector_feeds is owned by %; 9013180 applies the identity sink columns', v_owner::regrole;
        RETURN;
    END IF;
-- BEGIN connector_feed_identity_sink body
    ALTER TABLE public.connector_feeds
        ADD COLUMN IF NOT EXISTS sink TEXT NOT NULL DEFAULT 'hec',
        ALTER COLUMN ingest_url DROP NOT NULL;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint
                    WHERE conrelid = 'public.connector_feeds'::regclass
                      AND conname = 'connector_feeds_sink_kind') THEN
        ALTER TABLE public.connector_feeds ADD CONSTRAINT connector_feeds_sink_kind CHECK (
            sink IN ('hec', 'identity')
        ) NOT VALID;
    END IF;
    -- A collector feed still needs its ingress; an identity feed never has
    -- one, nor an ingest credential (issued or in flight).
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint
                    WHERE conrelid = 'public.connector_feeds'::regclass
                      AND conname = 'connector_feeds_sink_ingest') THEN
        ALTER TABLE public.connector_feeds ADD CONSTRAINT connector_feeds_sink_ingest CHECK (
            (sink = 'hec' AND ingest_url IS NOT NULL)
            OR (sink = 'identity' AND ingest_url IS NULL AND ingest_token_encrypted IS NULL
                AND ingest_credential_request_id IS NULL AND ingest_reveal_key_encrypted IS NULL)
        ) NOT VALID;
    END IF;
    -- Added NOT VALID, then validated (a no-op once valid).
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_constraint
                WHERE conrelid = 'public.connector_feeds'::regclass
                  AND conname = 'connector_feeds_sink_kind' AND NOT convalidated) THEN
        ALTER TABLE public.connector_feeds VALIDATE CONSTRAINT connector_feeds_sink_kind;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_constraint
                WHERE conrelid = 'public.connector_feeds'::regclass
                  AND conname = 'connector_feeds_sink_ingest' AND NOT convalidated) THEN
        ALTER TABLE public.connector_feeds VALIDATE CONSTRAINT connector_feeds_sink_ingest;
    END IF;
-- END connector_feed_identity_sink body
END
$nan3503_sink$;
