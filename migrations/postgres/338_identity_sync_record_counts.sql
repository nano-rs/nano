-- NAN-3483: identity sync status must be honest.
--
-- A pull sync emits records onto the fire-and-forget nano_enrich lane. Before
-- NAN-3483 it reported `completed` even when the lane's normalizer
-- dead-lettered every record (open core: Okta users through the AD
-- normalizer). The sync now runs the lane's normalizer in-process first and
-- records how many records it emitted and how many it dead-lettered. The
-- status is `partial` when some were dead-lettered and `failed` when all were;
-- `last_sync_error` carries the counts and the first reason. sync_status is a
-- VARCHAR(20) with no CHECK, so `partial` needs no constraint change.
--
-- Additive and idempotent; NULL until a provider's first sync after this
-- migration. Runs on the enterprise and open-core paths alike (both apply the
-- numbered postgres/ migrations after their baseline).
ALTER TABLE identity_providers
    ADD COLUMN IF NOT EXISTS last_sync_records_total BIGINT,
    ADD COLUMN IF NOT EXISTS last_sync_records_synced BIGINT,
    ADD COLUMN IF NOT EXISTS last_sync_records_dead_lettered BIGINT;

