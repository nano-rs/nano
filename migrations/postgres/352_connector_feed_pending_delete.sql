-- NAN-3503: uninstalling a connector feed is a pending delete, not a hard
-- delete.
--
-- Uninstalling a directory (identity) feed must also remove its rows from
-- the tenant's identity directory, at the tenant's lean enrichment
-- coordinator (`<feed>:users`, `<feed>:groups`). The API therefore only
-- disables the feed and sets `delete_requested_at`; the connector runner
-- (which holds the tenant's identity-writer token) claims it, removes the
-- external state and then hard-deletes the row. A failed attempt records
-- `delete_last_error`, counts `delete_attempts` and waits until
-- `delete_next_attempt_at`; the next tick retries. Nothing is dropped.
--
-- Additive and idempotent. Requires 339 (connector_feeds). On an activated
-- enterprise_shared database where 9012400 already moved the table to the
-- data owner, the migrator can no longer ALTER it; this file then leaves the
-- change to `9013220_connector_feed_pending_delete.sql`, which applies the
-- SAME body under the managed-owner bootstrap
-- (nano-connector/tests/migration_parity.rs keeps the two bodies identical).

-- A busy connector_feeds (runner claims every poll) must not queue every
-- other writer behind this ALTER: give up after 5 s and let the migrator
-- retry.
SET LOCAL lock_timeout = '5s';

DO $nan3503_pending_delete$
DECLARE
    v_owner OID;
BEGIN
    SELECT relowner INTO v_owner FROM pg_catalog.pg_class WHERE oid = 'public.connector_feeds'::regclass;
    IF NOT pg_catalog.pg_has_role(current_user, v_owner, 'USAGE') THEN
        RAISE NOTICE 'connector_feeds is owned by %; 9013220 applies the pending delete columns', v_owner::regrole;
        RETURN;
    END IF;
-- BEGIN connector_feed_pending_delete body
    ALTER TABLE public.connector_feeds
        ADD COLUMN IF NOT EXISTS delete_requested_at TIMESTAMPTZ,
        ADD COLUMN IF NOT EXISTS delete_attempts INTEGER NOT NULL DEFAULT 0,
        ADD COLUMN IF NOT EXISTS delete_next_attempt_at TIMESTAMPTZ,
        ADD COLUMN IF NOT EXISTS delete_last_error TEXT;
    -- A feed pending delete never runs again; attempts and the recorded
    -- error stay bounded.
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint
                    WHERE conrelid = 'public.connector_feeds'::regclass
                      AND conname = 'connector_feeds_pending_delete') THEN
        ALTER TABLE public.connector_feeds ADD CONSTRAINT connector_feeds_pending_delete CHECK (
            (delete_requested_at IS NULL OR NOT enabled)
            AND delete_attempts >= 0
            AND (delete_last_error IS NULL OR length(delete_last_error) <= 2048)
        ) NOT VALID;
    END IF;
    -- Added NOT VALID, then validated (a no-op once valid).
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_constraint
                WHERE conrelid = 'public.connector_feeds'::regclass
                  AND conname = 'connector_feeds_pending_delete' AND NOT convalidated) THEN
        ALTER TABLE public.connector_feeds VALIDATE CONSTRAINT connector_feeds_pending_delete;
    END IF;
    -- The runner's delete claim: one tenant's due pending deletes.
    CREATE INDEX IF NOT EXISTS connector_feeds_pending_delete_due
        ON public.connector_feeds (tenant_id, delete_next_attempt_at)
        WHERE delete_requested_at IS NOT NULL;
-- END connector_feed_pending_delete body
END
$nan3503_pending_delete$;
