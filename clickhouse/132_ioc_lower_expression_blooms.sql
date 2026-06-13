-- NAN-1415: lower(col) expression blooms for IOC equality hunts.
--
-- ClickHouse matches skip indexes by EXPRESSION. Every string field outside
-- LOWERCASE_NORMALIZED_FIELDS gets `lower(col) = '<value>'` from the query
-- codegen, but the migration-046/119-era blooms are on the RAW columns — so
-- IOC equality hunts (hashes, GUIDs, SIDs, domains, file names, rule/signature
-- ids) full-scanned the window. Measured on local CH (2.0M rows, 26 parts),
-- query_log read_rows before → after, identical result counts:
--
--   lower(process_hash) = '<rare hash>'     1,996,256 → 28,010   (71x)
--   lower(file_hash) = 'deadbeef…' (absent) 1,996,256 → 13,456  (148x)
--   lower(file_hash) = '<rare hash>'        1,996,256 → 68,270   (29x)
--   lower(process_guid) = '<rare guid>'     1,996,256 → 26,676   (75x)
--   lower(user_id) = '<rare SID>'           1,996,256 → 29,681   (67x)
--   lower(url_domain) = '<rare domain>'     1,996,256 → 46,487   (43x)
--   lower(file_name) = '<rare name>'        1,996,256 → 41,166   (48x)
--   lower(signature_id) = '<rare id>'       1,996,256 → 186,438  (11x)
--   lower(rule_id) = '<absent uuid>'        1,996,256 → 0
--
-- Data is NOT case-normalized at ingest for these columns (594,885 uppercase
-- process_hash rows locally; user_id holds uppercase Windows SIDs), so the
-- codegen cannot simply drop the lower() wrapper — and the OR-disjunct form
-- was verifier-refuted (a granule cannot be excluded while one disjunct is
-- non-index-evaluable). Expression blooms are purely additive: they engage
-- the existing emission on historical AND new data with no correctness window
-- and no backfill mutation of row data.
--
-- The raw-column blooms (idx_process_hash, idx_file_hash, …) are deliberately
-- kept: ingest-canonicalized fields and API/dict lookups still compare raw.
--
-- rule_id also carried a correctness bug fixed alongside this migration: it
-- routed through UUID_FIELDS emitting `toString(rule_id) = '<lowered literal>'`
-- — a case-sensitive compare against a lowered literal (logs.rule_id is a
-- plain String), so uppercase-stored vendor rule ids NEVER matched. The
-- codegen now emits `lower(rule_id) = …`, which idx_rule_id_lower serves.
--
-- Audit-listed IOC columns left OUT (cve, mitre_technique_id, sender,
-- recipient, message_id, risk_entity, cloud_account_id, resource_id,
-- enrichment_value_1..5): zero populated rows on local data, so index
-- engagement could not be measured — add them in a follow-up once a dataset
-- exercises them (NAN-1035 rule: measure before shipping index changes).
--
-- The ADD INDEX statements are instant (metadata only). The MATERIALIZE
-- INDEX statements backfill existing parts in the background and may take
-- a while on large tenants — monitor via system.mutations. Safe to
-- interrupt and resume; ClickHouse tracks per-part progress.
--
-- Naming follows the migration-131 convention: `_lower` = bloom_filter over
-- lower(col) for case-insensitive whole-value equality.
--
-- ⚠️ Scale-sensitive (NAN-1035 rule): pruning validated on local data only;
-- Saturn-validate before assuming production benefit.

ALTER TABLE nanosiem.logs ADD INDEX IF NOT EXISTS idx_process_hash_lower
    lower(process_hash) TYPE bloom_filter GRANULARITY 4;
ALTER TABLE nanosiem.logs MATERIALIZE INDEX idx_process_hash_lower;

ALTER TABLE nanosiem.logs ADD INDEX IF NOT EXISTS idx_file_hash_lower
    lower(file_hash) TYPE bloom_filter GRANULARITY 4;
ALTER TABLE nanosiem.logs MATERIALIZE INDEX idx_file_hash_lower;

ALTER TABLE nanosiem.logs ADD INDEX IF NOT EXISTS idx_process_guid_lower
    lower(process_guid) TYPE bloom_filter GRANULARITY 4;
ALTER TABLE nanosiem.logs MATERIALIZE INDEX idx_process_guid_lower;

ALTER TABLE nanosiem.logs ADD INDEX IF NOT EXISTS idx_user_id_lower
    lower(user_id) TYPE bloom_filter GRANULARITY 4;
ALTER TABLE nanosiem.logs MATERIALIZE INDEX idx_user_id_lower;

ALTER TABLE nanosiem.logs ADD INDEX IF NOT EXISTS idx_url_domain_lower
    lower(url_domain) TYPE bloom_filter GRANULARITY 4;
ALTER TABLE nanosiem.logs MATERIALIZE INDEX idx_url_domain_lower;

ALTER TABLE nanosiem.logs ADD INDEX IF NOT EXISTS idx_file_name_lower
    lower(file_name) TYPE bloom_filter GRANULARITY 4;
ALTER TABLE nanosiem.logs MATERIALIZE INDEX idx_file_name_lower;

ALTER TABLE nanosiem.logs ADD INDEX IF NOT EXISTS idx_rule_id_lower
    lower(rule_id) TYPE bloom_filter GRANULARITY 4;
ALTER TABLE nanosiem.logs MATERIALIZE INDEX idx_rule_id_lower;

ALTER TABLE nanosiem.logs ADD INDEX IF NOT EXISTS idx_signature_id_lower
    lower(signature_id) TYPE bloom_filter GRANULARITY 4;
ALTER TABLE nanosiem.logs MATERIALIZE INDEX idx_signature_id_lower;
