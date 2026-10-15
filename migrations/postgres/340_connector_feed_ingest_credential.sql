-- NAN-3490 (H3): platform-held per-feed ingest credential.
--
-- A hosted connector feed posts to its tenant's ingress with its own HEC
-- token, issued through the NAN-2590 request -> nano-main fulfilment ->
-- sealed reveal path (nano-connector/src/service/credential.rs). The runner,
-- acting as the tenant's worker member, requests the credential with an
-- X25519 reveal key whose private half is sealed (deployment cipher) onto the
-- feed row, reveals the sealed token once nano-main has issued it, and seals
-- the plaintext into `ingest_token_*` in the same transaction.
--
-- So a feed can now exist without a token (credential pending); the runner
-- never claims a run for such a feed. Open core / dedicated feeds still get
-- their token at create time (the local ingress has no issuance service).
--
-- Additive, nullable, idempotent. On an activated enterprise_shared database
-- where 9012400 already moved the table to the data owner, the migrator can
-- no longer ALTER it; this file then leaves the change to
-- `9012510_connector_feed_ingest_credential.sql`, which applies the SAME body
-- under the managed-owner bootstrap (tests/migration_parity.rs keeps the two
-- bodies identical).

DO $nan3490_h3$
DECLARE
    v_owner OID;
BEGIN
    SELECT relowner INTO v_owner FROM pg_catalog.pg_class WHERE oid = 'public.connector_feeds'::regclass;
    IF NOT pg_catalog.pg_has_role(current_user, v_owner, 'USAGE') THEN
        RAISE NOTICE 'connector_feeds is owned by %; 9012510 applies the credential columns', v_owner::regrole;
        RETURN;
    END IF;
-- BEGIN connector_feed_ingest_credential body
    ALTER TABLE public.connector_feeds
        ALTER COLUMN ingest_token_encrypted DROP NOT NULL,
        ALTER COLUMN ingest_token_nonce DROP NOT NULL,
        ADD COLUMN IF NOT EXISTS ingest_credential_request_id UUID,
        ADD COLUMN IF NOT EXISTS ingest_reveal_key_encrypted BYTEA
            CHECK (octet_length(ingest_reveal_key_encrypted) <= 4096),
        ADD COLUMN IF NOT EXISTS ingest_reveal_key_nonce TEXT
            CHECK (length(ingest_reveal_key_nonce) <= 64),
        ADD COLUMN IF NOT EXISTS ingest_credential_requested_at TIMESTAMPTZ,
        ADD COLUMN IF NOT EXISTS ingest_credential_issued_at TIMESTAMPTZ,
        ADD COLUMN IF NOT EXISTS ingest_credential_error TEXT
            CHECK (length(ingest_credential_error) <= 1100);
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint
                    WHERE conrelid = 'public.connector_feeds'::regclass
                      AND conname = 'connector_feeds_ingest_token_pair') THEN
        ALTER TABLE public.connector_feeds ADD CONSTRAINT connector_feeds_ingest_token_pair CHECK (
            (ingest_token_encrypted IS NULL) = (ingest_token_nonce IS NULL)
        );
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint
                    WHERE conrelid = 'public.connector_feeds'::regclass
                      AND conname = 'connector_feeds_reveal_key_pair') THEN
        ALTER TABLE public.connector_feeds ADD CONSTRAINT connector_feeds_reveal_key_pair CHECK (
            (ingest_reveal_key_encrypted IS NULL) = (ingest_reveal_key_nonce IS NULL)
        );
    END IF;
    -- A reveal key exists only for a request in flight, never next to a token.
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint
                    WHERE conrelid = 'public.connector_feeds'::regclass
                      AND conname = 'connector_feeds_reveal_key_in_flight') THEN
        ALTER TABLE public.connector_feeds ADD CONSTRAINT connector_feeds_reveal_key_in_flight CHECK (
            ingest_reveal_key_encrypted IS NULL
            OR (ingest_credential_request_id IS NOT NULL AND ingest_token_encrypted IS NULL)
        );
    END IF;
    -- Feeds waiting for a credential (small; the issuance pass scans it).
    CREATE INDEX IF NOT EXISTS connector_feeds_credential_pending
        ON public.connector_feeds (tenant_id, next_run_at)
        WHERE enabled AND ingest_token_encrypted IS NULL;
-- END connector_feed_ingest_credential body
END
$nan3490_h3$;
