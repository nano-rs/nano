-- NAN-714: bump search admission queue_timeout default from 120s to 300s.
--
-- Migration 076 set `search_queue_timeout_seconds` default to 120. That was
-- the admission queue wait window — how long a request waits in the queue
-- for a slot before being rejected. Misaligned with Interactive priority's
-- ClickHouse `max_execution_time = 300s`: a request could be kicked out
-- of the queue while CH would have happily run an equivalent query for
-- the full 5 minutes. Aligning the two means requests under contention
-- wait long enough for natural query completion to free up a slot.
--
-- This migration:
--   1. Updates the column default for new tenants going forward.
--   2. Bumps existing tenants whose value is still the legacy 120, but
--      LEAVES intact any tenant who has explicitly set a different value
--      (which, by definition, isn't 120). Idempotent — re-running is a
--      no-op once the column is at 300 (or any non-120 value).

ALTER TABLE system_settings
    ALTER COLUMN search_queue_timeout_seconds SET DEFAULT 300;

UPDATE system_settings
   SET search_queue_timeout_seconds = 300
 WHERE search_queue_timeout_seconds = 120;
