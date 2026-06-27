-- NAN-1580: lower() expression bloom_filter skip indexes for the OCSF retro IOC
-- hunt observable columns.
--
-- The IOC retro-hunt matchset is now schema-profile-aware (NAN-1580): on an
-- OCSF-flagged tenant the `ioc=<v> | retro` sweep resolves each logical UDM
-- observable to its promoted OCSF column via SchemaProfile::udm_column_sql and
-- emits the SAME two compare shapes the UDM path uses:
--   * RAW equality  (`<col> = '<lowered>'`)  for ingest-lowercased ip/mac cols
--   * `lower(<col>) = '<lowered>'`           for the mixed-case-history columns
--     (hashes, email parties, cve, user uid, …).
--
-- INDEX EXPRESSION MUST EQUAL THE QUERY EXPRESSION (CLAUDE.md QO rule #2): a skip
-- index only engages when ClickHouse can match it by EXPRESSION. The OCSF DDL
-- (clickhouse/ocsf/init.sql) already covers the retro sweep's needs for:
--   * the RAW ip/mac legs        — `src_endpoint.ip`/`dst_endpoint.ip`/
--                                  `src_endpoint.mac`/`dst_endpoint.mac` carry
--                                  RAW blooms (idx_src_endpoint_ip, …).
--   * the lower() host/url/dns/process-hash legs — `src_endpoint.hostname`,
--     `dst_endpoint.hostname`, `query.hostname`, `process_hash_unified`,
--     `url_unified`, `url_domain_unified` carry `lower(col)` text indexes.
--
-- The columns below carry ONLY a RAW bloom, so the retro sweep's
-- `lower(<col>) = '<v>'` predicate orphaned every index and full-scanned the
-- window. Each gets a `lower(col)` EXPRESSION bloom that matches the emitted
-- form (a RAW bloom would NOT engage for `lower(col)='v'`), mirroring the UDM
-- migration-132/145 `idx_*_lower` blooms:
--   file.hashes.sha256          SUBJECT file SHA-256 — the primary IOC hash leg
--                               (file_hash observable; also drives the summary
--                               per-field match count).
--   user.uid                    user identifier (user_id observable).
--   email.from / email.to       email parties (sender / recipient observables).
--   vulnerabilities.cve.uid     CVE id (cve observable).
--
-- Scope note (minimal high-value subset, NAN-1035 rule): only the columns the
-- retro sweep emits as `lower(col)=` AND that had no lower()-shaped index are
-- added here. The class-split process/url hash legs (process_hash_unified,
-- url_unified, url_domain_unified) already carry lower() text indexes, and the
-- ip/mac legs compare RAW. `answers.rdata` (dns_answers parity) holds multiple
-- answers per value, so an exact `lower(col)=` whole-value bloom is low-yield;
-- a token/per-answer index is deferred (same follow-up note as migration 145).
--
-- ⚠️ Scale-sensitive (NAN-1035 rule): pruning is REASONED, not yet measured —
-- local data does not exercise these OCSF columns at volume. Saturn-validate
-- read_rows/read_bytes before vs after on a populated OCSF dataset before
-- assuming production benefit, and before any value-sorted projection follow-up.
--
-- ocsf_logs is NOT in DISTRIBUTED_TABLES (deploy/scripts/init-clickhouse-cluster.sh),
-- so no _local rename is needed; the cluster init auto-injects `ON CLUSTER` into
-- every ALTER TABLE. ocsf_logs may be ABSENT on UDM-only tenants, so each ALTER
-- carries the /* nano:skip-if-unknown-table */ marker (mirrors migration 135).
--
-- ADD INDEX is metadata-only (instant). MATERIALIZE INDEX backfills existing
-- parts in the background and can run long on large tenants; monitor via
-- system.mutations, safe to interrupt/resume (per-part progress is tracked).

ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */
    ADD INDEX IF NOT EXISTS idx_file_sha256_lower
    lower(`file.hashes.sha256`) TYPE bloom_filter GRANULARITY 4;
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */
    MATERIALIZE INDEX idx_file_sha256_lower;

ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */
    ADD INDEX IF NOT EXISTS idx_user_uid_lower
    lower(`user.uid`) TYPE bloom_filter GRANULARITY 4;
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */
    MATERIALIZE INDEX idx_user_uid_lower;

ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */
    ADD INDEX IF NOT EXISTS idx_email_from_lower
    lower(`email.from`) TYPE bloom_filter GRANULARITY 4;
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */
    MATERIALIZE INDEX idx_email_from_lower;

ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */
    ADD INDEX IF NOT EXISTS idx_email_to_lower
    lower(`email.to`) TYPE bloom_filter GRANULARITY 4;
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */
    MATERIALIZE INDEX idx_email_to_lower;

ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */
    ADD INDEX IF NOT EXISTS idx_cve_lower
    lower(`vulnerabilities.cve.uid`) TYPE bloom_filter GRANULARITY 4;
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */
    MATERIALIZE INDEX idx_cve_lower;
