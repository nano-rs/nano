-- SPDX-License-Identifier: AGPL-3.0-or-later
-- NAN-4931 (G22): identity directory feeds + honest identity sync status.
--
-- 1. NAN-3483 (main 338): a pull sync emits records onto the fire-and-forget
--    nano_enrich lane. It used to report `completed` even when the lane's
--    normalizer dead-lettered every record. The sync now runs the lane's
--    normalizer in-process first and records how many records it fetched,
--    mapped and dead-lettered; the status is `partial` when some were
--    dead-lettered and `failed` when all were. sync_status is a VARCHAR(20)
--    with no CHECK, so `partial` needs no constraint change.
--
-- 2. G22 (port of NAN-3503): a connector identity feed (`kind: identity`
--    bundled spec run by nano-connector-runner) owns exactly one
--    identity_providers row (id = the feed's `cfeed_...` typeid) and writes
--    its users into the ClickHouse user_registry under it. The binding column
--    lets the native scheduler/sync and credential paths refuse a
--    feed-managed provider, and removes the provider with its feed.
--
-- Forward-only, additive and idempotent. Runs on the enterprise and open-core
-- paths alike (both apply the numbered postgres/ migrations after their
-- baseline; connector_feeds comes from 293 on both).
SET LOCAL lock_timeout = '5s';

ALTER TABLE public.identity_providers
    ADD COLUMN IF NOT EXISTS last_sync_records_total BIGINT,
    ADD COLUMN IF NOT EXISTS last_sync_records_synced BIGINT,
    ADD COLUMN IF NOT EXISTS last_sync_records_dead_lettered BIGINT,
    ADD COLUMN IF NOT EXISTS connector_feed_id UUID;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'identity_providers_connector_feed_fk'
          AND conrelid = 'public.identity_providers'::regclass
    ) THEN
        ALTER TABLE public.identity_providers
            ADD CONSTRAINT identity_providers_connector_feed_fk
            FOREIGN KEY (connector_feed_id) REFERENCES public.connector_feeds(id) ON DELETE CASCADE;
    END IF;
END
$$;

CREATE UNIQUE INDEX IF NOT EXISTS identity_providers_connector_feed_uniq
    ON public.identity_providers (connector_feed_id)
    WHERE connector_feed_id IS NOT NULL;

COMMENT ON COLUMN public.identity_providers.connector_feed_id IS
    'G22: the connector identity feed that manages this provider (synced by nano-connector-runner; no native sync or credentials)';
