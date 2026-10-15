-- NAN-2553. A Bronze shard holds exactly one pending batch at a time, so a
-- publication the writer plane refuses *permanently* (e.g. a 409 permit
-- conflict from the tenant writer authority) is a head-of-line block on the
-- entire shard: the poison batch is re-attempted every poll for as long as the
-- shard lives, and no other work can be discovered behind it.
--
-- The refusal counter is durable rather than in-process because a pod restart
-- must not reset the budget — on 2026-09-21 shard 2 was restarted and resumed
-- failing on the same batch, which is exactly the case an in-memory counter
-- cannot bound.
--
-- Quarantine reuses the existing `rejected` status with a new rejection code,
-- so no other reader changes: discovery already skips every object that has a
-- row, `load_pending` only reads `pending`, and Bronze reclaim only deletes
-- source objects for `published` rows. The source objects therefore stay
-- durable for an operator replay.
ALTER TABLE lake_bronze_object_publications
    ADD COLUMN IF NOT EXISTS permanent_refusals integer NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS last_permanent_refusal_at timestamptz;

ALTER TABLE lake_bronze_object_publications
    DROP CONSTRAINT IF EXISTS lake_bronze_object_publications_permanent_refusals_check;

ALTER TABLE lake_bronze_object_publications
    ADD CONSTRAINT lake_bronze_object_publications_permanent_refusals_check
    CHECK (permanent_refusals >= 0);
