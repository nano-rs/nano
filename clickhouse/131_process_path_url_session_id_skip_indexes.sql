-- NAN-1414: skip indexes missed by migration 119 — process_path / url /
-- uri_path text indexes, session_id equality bloom.
--
-- Migration 119 added `text(tokenizer = splitByNonAlpha)` indexes on 15
-- commonly-searched UDM string columns but skipped `process_path` (42%
-- populated locally — file_path got one, process_path didn't), `url`, and
-- `uri_path`. `session_id` has no index at all, so even whole-value
-- equality lookups full-scan.
--
-- Measured on local CH (2M rows, 542 granules), before → after:
--   lower(process_path) LIKE '%temp%'   542/542 → 270/542 granules
--   lower(process_path) LIKE '%xmrig%'  542/542 →   0/542
--   lower(url) LIKE '%slack%'           542/542 →  53/542
--   lower(uri_path) LIKE '%quarterly%'  542/542 →   1/542
--   lower(session_id) = '<real value>'  542/542 →   6/542
--
-- ⚠️ KNOWN LIMITATION (set expectations before tuning queries against this):
-- text(splitByNonAlpha) does NOT serve iLike/LIKE patterns whose required
-- substring contains non-alphanumeric characters. Measured: `%.tmp%` and
-- `%temp\%` still full-scan (542/542) even with the index in place, because
-- the dictionary holds only alphanumeric tokens. These indexes accelerate
-- pure-alphanumeric substrings (`%temp%`, `%powershell%`) and
-- `lower(col) = '<token>'` equality only. The session_id bloom_filter is a
-- whole-value equality index and has no such caveat.
--
-- The ADD INDEX statements are instant (metadata only). The MATERIALIZE
-- INDEX statements backfill existing parts in the background and may take
-- a while on large tenants — monitor via system.mutations. Safe to
-- interrupt and resume; ClickHouse tracks per-part progress.
--
-- Naming follows the migration-119 convention: `_words` = splitByNonAlpha
-- whole-token index; the session_id bloom gets `_lower` because it indexes
-- lower(session_id) for case-insensitive equality (codegen compares on
-- lower()).
--
-- ⚠️ Scale-sensitive (NAN-1035 rule): pruning validated on local data only;
-- Saturn-validate before assuming production benefit.

ALTER TABLE nanosiem.logs ADD INDEX IF NOT EXISTS idx_process_path_words
    lower(process_path) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1;
ALTER TABLE nanosiem.logs MATERIALIZE INDEX idx_process_path_words;

ALTER TABLE nanosiem.logs ADD INDEX IF NOT EXISTS idx_url_words
    lower(url) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1;
ALTER TABLE nanosiem.logs MATERIALIZE INDEX idx_url_words;

ALTER TABLE nanosiem.logs ADD INDEX IF NOT EXISTS idx_uri_path_words
    lower(uri_path) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1;
ALTER TABLE nanosiem.logs MATERIALIZE INDEX idx_uri_path_words;

ALTER TABLE nanosiem.logs ADD INDEX IF NOT EXISTS idx_session_id_lower
    lower(session_id) TYPE bloom_filter GRANULARITY 4;
ALTER TABLE nanosiem.logs MATERIALIZE INDEX idx_session_id_lower;
