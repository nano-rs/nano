-- NAN-1580: bloom_filter skip indexes for retro IOC hunt observable columns.
--
-- nPL IOC retro-hunt drives a value matchset (an IOC list) against the logs
-- table over a historical window. The codegen lands on the observable column
-- carrying that value (`dvc_ip = '<ip>'`, `dns_answers iLike '%<domain>%'`,
-- etc.). The migration-046/119/131/132-era blooms already cover the high-value
-- observables (src_ip/dest_ip, file/process hashes, url_domain, user_id,
-- rule/signature ids, sender/recipient, message_id, cve, mitre, risk_entity,
-- cloud_account_id, resource_id). The columns below carried NO skip index of
-- any kind (raw bloom, lower() bloom, or text index) — so a retro hunt that
-- pivoted on a device IP/host/MAC or a DNS answer full-scanned the window.
--
-- Indexed here (verified unindexed against clickhouse/init.sql logs DDL):
--   dvc_ip      device IP — IOC IP lookups against the reporting device
--   dvc         device hostname — IOC host lookups against the reporting device
--   dvc_mac     device MAC — IOC MAC lookups
--   dns_answers resolved A/AAAA/CNAME payload — IOC IP/domain co-occurrence
--
-- All four are raw `String DEFAULT ''` columns. INDEX EXPRESSION MUST EQUAL THE
-- QUERY EXPRESSION (CLAUDE.md QO rule #2) — the IOC matchset emits one of two
-- shapes per column, so the index shape follows:
--   * dvc_ip is ingest-lowercased and matched RAW (`dvc_ip = '<value>'`), so a
--     RAW bloom over the column prunes — same shape as idx_src_ip / idx_dest_ip.
--   * dvc / dvc_mac / dns_answers are matched via `lower(col) = '<value>'` (the
--     IOC_OBSERVABLE_LOWER_COLUMNS set), so they get `lower(col)` EXPRESSION
--     blooms. A RAW bloom would NOT engage for the `lower(col)='v'` predicate.
-- Note: dns_answers may hold MULTIPLE answers in one column value, so
-- `lower(dns_answers) = '<value>'` matches only when the whole column equals the
-- value (single-answer rows / exact payloads). A token / substring match across
-- a multi-answer payload is a follow-up (a text index or per-answer projection).
--
-- ADD INDEX is metadata-only (instant). MATERIALIZE INDEX backfills existing
-- parts in the background and can run long on large tenants; monitor via
-- system.mutations, safe to interrupt/resume (per-part progress is tracked).
--
-- logs is NOT in DISTRIBUTED_TABLES, so no _local rename is needed; the
-- cluster init (deploy/scripts/init-clickhouse-cluster.sh) auto-injects
-- `ON CLUSTER` into every ALTER TABLE, exactly as it does for migration 132.
--
-- ⚠️ Scale-sensitive (NAN-1035 rule): pruning is reasoned, not yet measured —
-- local data does not exercise these columns. Saturn-validate read_rows
-- before/after on a populated dataset before assuming production benefit, and
-- before any value-sorted projection follow-up for the retro matchset.

ALTER TABLE nanosiem.logs ADD INDEX IF NOT EXISTS idx_dvc_ip
    dvc_ip TYPE bloom_filter GRANULARITY 4;
ALTER TABLE nanosiem.logs MATERIALIZE INDEX idx_dvc_ip;

ALTER TABLE nanosiem.logs ADD INDEX IF NOT EXISTS idx_dvc_lower
    lower(dvc) TYPE bloom_filter GRANULARITY 4;
ALTER TABLE nanosiem.logs MATERIALIZE INDEX idx_dvc_lower;

ALTER TABLE nanosiem.logs ADD INDEX IF NOT EXISTS idx_dvc_mac_lower
    lower(dvc_mac) TYPE bloom_filter GRANULARITY 4;
ALTER TABLE nanosiem.logs MATERIALIZE INDEX idx_dvc_mac_lower;

ALTER TABLE nanosiem.logs ADD INDEX IF NOT EXISTS idx_dns_answers_lower
    lower(dns_answers) TYPE bloom_filter GRANULARITY 4;
ALTER TABLE nanosiem.logs MATERIALIZE INDEX idx_dns_answers_lower;
