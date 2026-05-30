-- Phase 1 of NAN-1026: schema foundation for the fragment-matching fix.
--
-- Adds / swaps `text(tokenizer = splitByNonAlpha)` indexes on the most
-- commonly searched UDM string fields, so that the Phase 2 codegen swap
-- (hasToken* → iLike) can rely on CH 26.4's LIKE-via-dictionary-scan
-- optimization to keep queries fast.
--
-- Phase 1 alone is a no-op for query *behavior*: existing codegen still
-- emits hasToken/hasTokenCaseInsensitive, which works against
-- text(splitByNonAlpha) indexes the same way it worked against
-- tokenbf_v1 / ngrams. The benefit lands when Phase 2 flips codegen to
-- iLike — which can then walk the splitByNonAlpha dictionary and match
-- substring tokens (the fix for `src_host = /dc/` not matching `srv-dc01`
-- and friends — see NAN-1026 for the full evidence).
--
-- Storage math (extrapolating from local POC measurements):
--
--   Replace `idx_message_ft` ngrams (~730 GB Saturn) with splitByNonAlpha
--     (~50 GB Saturn). Net -680 GB on the single biggest index.
--   Replace 5 existing tokenbf_v1 indexes (file_path, registry_path,
--     http_user_agent, query, subject) with splitByNonAlpha. Net +~225 GB.
--   Add 8 new splitByNonAlpha indexes on bloom-filter-only fields
--     (src_host, dest_host, user, src_user, dest_user, process_name,
--     command_line, parent_command_line). Net +~400 GB.
--   Combined: approximately -55 GB net at Saturn. Effectively
--     redistributing the message-ngrams budget to other searched fields.
--
-- The ADD/DROP INDEX statements are instant (metadata only). The
-- MATERIALIZE INDEX statements backfill existing parts in the background
-- and may take hours on large tenants — monitor via system.mutations.
-- Safe to interrupt and resume; ClickHouse tracks per-part progress.
--
-- We keep:
--   * idx_message_tokens (tokenbf_v1) — still used by current hasToken
--     codegen until Phase 2 lands. Will be retired in Phase 2.
--   * All bloom_filter indexes on UDM fields — still useful for
--     `field = 'X'` whole-value equality lookups (orthogonal to splitByNonAlpha).
--   * All other existing indexes (set, bloom_filter on other fields, etc.).
--
-- This is reversible per-index via DROP INDEX IF EXISTS in a future migration.

-- 1. REPLACE: message ngrams(3) → splitByNonAlpha
-- The big storage win. ngrams was inherited from an early-access CH text
-- index adoption (NAN-140); never served LIKE queries (EXPLAIN shows it's
-- only consulted for hasToken — same job splitByNonAlpha does at 1/15th
-- the size).
ALTER TABLE nanosiem.logs DROP INDEX IF EXISTS idx_message_ft;
ALTER TABLE nanosiem.logs ADD INDEX IF NOT EXISTS idx_message_words
    lower(message) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1;
ALTER TABLE nanosiem.logs MATERIALIZE INDEX idx_message_words;

-- 2. REPLACE: 5 existing tokenbf_v1 indexes with splitByNonAlpha.
-- tokenbf_v1 is a probabilistic bloom over alphanumeric tokens; only useful
-- for hasToken. splitByNonAlpha is an exact inverted index over the same
-- tokens; useful for hasToken AND iLike via dictionary scan.
--
-- The new indexes use the `_words` suffix to keep naming consistent with
-- the message and bloom-only-replacement indexes below — `_words` is our
-- convention for "this is the splitByNonAlpha (whole-token) index, distinct
-- from the bloom_filter (whole-value) index on the same field."
ALTER TABLE nanosiem.logs DROP INDEX IF EXISTS idx_file_path;
ALTER TABLE nanosiem.logs ADD INDEX IF NOT EXISTS idx_file_path_words
    lower(file_path) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1;
ALTER TABLE nanosiem.logs MATERIALIZE INDEX idx_file_path_words;

ALTER TABLE nanosiem.logs DROP INDEX IF EXISTS idx_registry_path;
ALTER TABLE nanosiem.logs ADD INDEX IF NOT EXISTS idx_registry_path_words
    lower(registry_path) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1;
ALTER TABLE nanosiem.logs MATERIALIZE INDEX idx_registry_path_words;

ALTER TABLE nanosiem.logs DROP INDEX IF EXISTS idx_http_user_agent;
ALTER TABLE nanosiem.logs ADD INDEX IF NOT EXISTS idx_http_user_agent_words
    lower(http_user_agent) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1;
ALTER TABLE nanosiem.logs MATERIALIZE INDEX idx_http_user_agent_words;

ALTER TABLE nanosiem.logs DROP INDEX IF EXISTS idx_query;
ALTER TABLE nanosiem.logs ADD INDEX IF NOT EXISTS idx_query_words
    lower(query) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1;
ALTER TABLE nanosiem.logs MATERIALIZE INDEX idx_query_words;

ALTER TABLE nanosiem.logs DROP INDEX IF EXISTS idx_subject;
ALTER TABLE nanosiem.logs ADD INDEX IF NOT EXISTS idx_subject_words
    lower(subject) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1;
ALTER TABLE nanosiem.logs MATERIALIZE INDEX idx_subject_words;

-- 3. ADD: splitByNonAlpha indexes on commonly-searched bloom-filter-only fields.
-- bloom_filter on the whole value is still kept for `field = 'X'` equality
-- (e.g., src_host = 'WS-MKT-088.corp.local'). The new splitByNonAlpha index
-- handles token / regex / iLike substring search (e.g., src_host = /088/).
ALTER TABLE nanosiem.logs ADD INDEX IF NOT EXISTS idx_src_host_words
    lower(src_host) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1;
ALTER TABLE nanosiem.logs MATERIALIZE INDEX idx_src_host_words;

ALTER TABLE nanosiem.logs ADD INDEX IF NOT EXISTS idx_dest_host_words
    lower(dest_host) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1;
ALTER TABLE nanosiem.logs MATERIALIZE INDEX idx_dest_host_words;

ALTER TABLE nanosiem.logs ADD INDEX IF NOT EXISTS idx_user_words
    lower(user) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1;
ALTER TABLE nanosiem.logs MATERIALIZE INDEX idx_user_words;

ALTER TABLE nanosiem.logs ADD INDEX IF NOT EXISTS idx_src_user_words
    lower(src_user) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1;
ALTER TABLE nanosiem.logs MATERIALIZE INDEX idx_src_user_words;

ALTER TABLE nanosiem.logs ADD INDEX IF NOT EXISTS idx_dest_user_words
    lower(dest_user) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1;
ALTER TABLE nanosiem.logs MATERIALIZE INDEX idx_dest_user_words;

ALTER TABLE nanosiem.logs ADD INDEX IF NOT EXISTS idx_process_name_words
    lower(process_name) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1;
ALTER TABLE nanosiem.logs MATERIALIZE INDEX idx_process_name_words;

ALTER TABLE nanosiem.logs ADD INDEX IF NOT EXISTS idx_command_line_words
    lower(command_line) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1;
ALTER TABLE nanosiem.logs MATERIALIZE INDEX idx_command_line_words;

ALTER TABLE nanosiem.logs ADD INDEX IF NOT EXISTS idx_parent_command_line_words
    lower(parent_command_line) TYPE text(tokenizer = splitByNonAlpha) GRANULARITY 1;
ALTER TABLE nanosiem.logs MATERIALIZE INDEX idx_parent_command_line_words;
