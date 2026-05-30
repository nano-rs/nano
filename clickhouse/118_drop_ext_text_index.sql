-- Drop `ext_text` materialized column and `idx_ext_text` text index added by
-- 117 (NAN-1022). The design was wrong for nano's Splunk-style _raw model:
-- `message` always carries the full source content, so probing `ext_text` for
-- free-text hunts adds a second index probe and storage cost for zero net-new
-- hits. User-typed `extfield=value` queries are already columnar-fast via the
-- native JSON subcolumn storage (`ext.field`) — they never touched `ext_text`.
--
-- This migration is idempotent: `IF EXISTS` makes it a no-op on fresh installs
-- where 117 never ran (e.g., a brand-new tenant that picks up main after the
-- revert lands — its init.sql doesn't declare ext_text either).
--
-- See NAN-1023 (revert PR) and memory note `feedback_splunk_raw_model` for
-- the architectural reasoning.

ALTER TABLE nanosiem.logs DROP INDEX IF EXISTS idx_ext_text;
ALTER TABLE nanosiem.logs DROP COLUMN IF EXISTS ext_text;
