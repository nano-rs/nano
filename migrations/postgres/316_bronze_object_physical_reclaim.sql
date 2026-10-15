-- NAN-2361: let bronze objects be physically reclaimed after publication.
--
-- WHY
-- ---
-- Bronze is a write-once, read-once staging area: Vector writes a Parquet
-- object, `lake_bronze_publish` reads it exactly once during admission, commits
-- the canonical rows into Iceberg, and nothing ever reads that object again.
-- Nothing deleted them either, so they accumulated forever. Measured on a
-- 4-day-old deployment ingesting only ~50 EPS: 59,178 objects / 8.3 GB, growing
-- 718 objects/hour — roughly 4x the size of the canonical table it feeds,
-- because bronze is uncompacted. At the 50-100 GB/day design target with
-- 365-day retention that is ~18-36 TB and ~6M objects per year, per tenant,
-- with no knob to stop it.
--
-- It is also a query regression, not just a storage one: per-query planning
-- cost scales with object count in this lake.
--
-- WHAT THIS ADDS
-- --------------
-- `physical_deleted_at` mirrors the column `lake_hot_tail_objects` already uses
-- for the same purpose, so the reclaim sweep can record which objects it has
-- removed and never re-attempt them. The LEDGER ROW IS DELIBERATELY RETAINED
-- after the object is gone: it is the replay/dedupe identity record
-- (`ConflictingReplay` admission checks and `late_replay` both read it), and
-- dropping it would let a re-delivered object be admitted twice.
--
-- Forward-only and idempotent. Existing rows get NULL, which the sweep reads as
-- "object still present", so the first pass after deploy reclaims the backlog.

ALTER TABLE lake_bronze_object_publications
    ADD COLUMN IF NOT EXISTS physical_deleted_at TIMESTAMPTZ;

COMMENT ON COLUMN lake_bronze_object_publications.physical_deleted_at IS
    'NAN-2361: when the bronze object was physically removed from the object store after its rows were durably published. NULL means the object is still present. The ledger row outlives the object because it is the replay/dedupe identity record.';

-- The sweep selects published rows whose object still exists, oldest first.
-- Partial index keeps that scan cheap as the ledger grows into the millions.
CREATE INDEX IF NOT EXISTS lake_bronze_publications_reclaimable
    ON lake_bronze_object_publications (published_at)
    WHERE status = 'published' AND physical_deleted_at IS NULL;
