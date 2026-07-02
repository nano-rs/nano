-- NAN-1637 (NAN-1632 findings 3.10 + 3.11): lower(col) expression blooms for
-- the remaining mixed-case-history columns that carry only a RAW bloom.
--
-- ClickHouse matches skip indexes by EXPRESSION (CLAUDE.md QO rule #2). These
-- columns are outside LOWERCASE_NORMALIZED_FIELDS, so the query codegen emits
-- `lower(col) = '<value>'` / `lower(col) IN (…)` for them — the correct form
-- for mixed-case stored history (CVE-… canonical casing, vendor rule names,
-- AS names; NAN-1415 dest_user precedent forbids blanket raw compares). But
-- the migration-046-era blooms on these columns are on the RAW column, so the
-- emitted form can never engage them:
--
--   * 3.11 — Saturn EXPLAIN: `lower(cve) = '<v>'` reads 8121/8121 granules;
--     the raw form prunes to 0/8121. The lower() predicate is index-blind on
--     every column below today.
--   * 3.10 — the `ioc=<v>` sweep ORs a lower() leg per observable; ONE
--     index-blind leg suppresses pruning for the WHOLE disjunction (a granule
--     cannot be excluded while one disjunct is non-index-evaluable, the same
--     verifier argument recorded in migration 132). Saturn EXPLAIN: the 4-leg
--     domain OR prunes 0/7910 granules vs 5932/7910 once the blind legs are
--     covered; the cve sweep is 100% blind. sender / recipient /
--     sender_domain / recipient_domain / cve below close the sweep's gaps.
--
-- Expression blooms are purely additive: they serve the ALREADY-emitted SQL on
-- historical and new data with no codegen change, no correctness window, and
-- no mutation of row data. The raw-column blooms (idx_cve, idx_sender, …) are
-- deliberately kept — ingest-canonicalized values and API/dict lookups still
-- compare raw (same call as migration 132).
--
-- Columns indexed (types verified against clickhouse/init.sql logs DDL — all
-- String or LowCardinality(String); the enriched_* AS columns are MATERIALIZED
-- String dictGet outputs, physically stored, so index build reads stored data):
--   cve, sender, recipient, sender_domain, recipient_domain, answer,
--   message_id, signature, mitre_technique_id, resource_id, cloud_account_id,
--   enriched_src_asn, enriched_src_as_name, enriched_src_as_domain,
--   enriched_dest_asn, enriched_dest_as_name, enriched_dest_as_domain
--
-- Deliberately EXCLUDED:
--   * signature_id — already carries idx_signature_id_lower (migration 132).
--   * enrichment_value_1..3 (the audit-listed slots; migration 149 / NAN-1624
--     dropped the whole enrichment_label/value_1..5 family) — the columns no
--     longer exist.
--
-- ADD INDEX is metadata-only (instant). MATERIALIZE INDEX backfills existing
-- parts as a BACKGROUND mutation processed part-by-part by the server — it
-- does not run inside the migration process, so the 8GiB boot-migration
-- resource rule (NAN-1398/1404) is respected; same decision as migrations
-- 132/145/147. It can run long on large tenants; monitor via
-- system.mutations, safe to interrupt/resume (per-part progress is tracked).
--
-- logs is NOT in DISTRIBUTED_TABLES, so no _local rename is needed; the
-- cluster init (deploy/scripts/init-clickhouse-cluster.sh) auto-injects
-- `ON CLUSTER` into every ALTER TABLE, exactly as it does for migrations
-- 132/145.
--
-- Naming follows the migration-131/132 convention: `_lower` = bloom_filter
-- over lower(col) for case-insensitive whole-value equality.
--
-- Local validation (CH 26.4, 4.1M rows / 31 parts / 1741 granules; every ADD +
-- MATERIALIZE below applied, EXPLAIN indexes=1, then dropped to leave the dev
-- box as found):
--   lower(cve) = 'cve-2024-1234'                      0/1741 granules
--   lower(sender_domain) = '<absent domain>'          0/1741
--   lower(mitre_technique_id) = 't1059.001'           0/1741
--   lower(enriched_src_as_name) = 'google llc'        1/1741
--   4-leg email OR (sender/recipient/±domain legs)    1286/1741 via the
--     CH 26.4 "<Combined skip indexes>" AND/OR step — confirming the 3.10
--     mechanism: the combined step can only prune when EVERY disjunct is
--     served by some index, so covering the blind legs re-enables it.
--
-- ⚠️ Scale-sensitive (NAN-1035 rule): pruning RATIO at production scale is
-- extrapolated from the Saturn raw-form EXPLAINs above — Saturn-validate
-- read_rows before/after once deployed.

ALTER TABLE nanosiem.logs ADD INDEX IF NOT EXISTS idx_cve_lower
    lower(cve) TYPE bloom_filter GRANULARITY 4;
ALTER TABLE nanosiem.logs MATERIALIZE INDEX idx_cve_lower;

ALTER TABLE nanosiem.logs ADD INDEX IF NOT EXISTS idx_sender_lower
    lower(sender) TYPE bloom_filter GRANULARITY 4;
ALTER TABLE nanosiem.logs MATERIALIZE INDEX idx_sender_lower;

ALTER TABLE nanosiem.logs ADD INDEX IF NOT EXISTS idx_recipient_lower
    lower(recipient) TYPE bloom_filter GRANULARITY 4;
ALTER TABLE nanosiem.logs MATERIALIZE INDEX idx_recipient_lower;

ALTER TABLE nanosiem.logs ADD INDEX IF NOT EXISTS idx_sender_domain_lower
    lower(sender_domain) TYPE bloom_filter GRANULARITY 4;
ALTER TABLE nanosiem.logs MATERIALIZE INDEX idx_sender_domain_lower;

ALTER TABLE nanosiem.logs ADD INDEX IF NOT EXISTS idx_recipient_domain_lower
    lower(recipient_domain) TYPE bloom_filter GRANULARITY 4;
ALTER TABLE nanosiem.logs MATERIALIZE INDEX idx_recipient_domain_lower;

ALTER TABLE nanosiem.logs ADD INDEX IF NOT EXISTS idx_answer_lower
    lower(answer) TYPE bloom_filter GRANULARITY 4;
ALTER TABLE nanosiem.logs MATERIALIZE INDEX idx_answer_lower;

ALTER TABLE nanosiem.logs ADD INDEX IF NOT EXISTS idx_message_id_lower
    lower(message_id) TYPE bloom_filter GRANULARITY 4;
ALTER TABLE nanosiem.logs MATERIALIZE INDEX idx_message_id_lower;

ALTER TABLE nanosiem.logs ADD INDEX IF NOT EXISTS idx_signature_lower
    lower(signature) TYPE bloom_filter GRANULARITY 4;
ALTER TABLE nanosiem.logs MATERIALIZE INDEX idx_signature_lower;

ALTER TABLE nanosiem.logs ADD INDEX IF NOT EXISTS idx_mitre_technique_id_lower
    lower(mitre_technique_id) TYPE bloom_filter GRANULARITY 4;
ALTER TABLE nanosiem.logs MATERIALIZE INDEX idx_mitre_technique_id_lower;

ALTER TABLE nanosiem.logs ADD INDEX IF NOT EXISTS idx_resource_id_lower
    lower(resource_id) TYPE bloom_filter GRANULARITY 4;
ALTER TABLE nanosiem.logs MATERIALIZE INDEX idx_resource_id_lower;

ALTER TABLE nanosiem.logs ADD INDEX IF NOT EXISTS idx_cloud_account_id_lower
    lower(cloud_account_id) TYPE bloom_filter GRANULARITY 4;
ALTER TABLE nanosiem.logs MATERIALIZE INDEX idx_cloud_account_id_lower;

ALTER TABLE nanosiem.logs ADD INDEX IF NOT EXISTS idx_enriched_src_asn_lower
    lower(enriched_src_asn) TYPE bloom_filter GRANULARITY 4;
ALTER TABLE nanosiem.logs MATERIALIZE INDEX idx_enriched_src_asn_lower;

ALTER TABLE nanosiem.logs ADD INDEX IF NOT EXISTS idx_enriched_src_as_name_lower
    lower(enriched_src_as_name) TYPE bloom_filter GRANULARITY 4;
ALTER TABLE nanosiem.logs MATERIALIZE INDEX idx_enriched_src_as_name_lower;

ALTER TABLE nanosiem.logs ADD INDEX IF NOT EXISTS idx_enriched_src_as_domain_lower
    lower(enriched_src_as_domain) TYPE bloom_filter GRANULARITY 4;
ALTER TABLE nanosiem.logs MATERIALIZE INDEX idx_enriched_src_as_domain_lower;

ALTER TABLE nanosiem.logs ADD INDEX IF NOT EXISTS idx_enriched_dest_asn_lower
    lower(enriched_dest_asn) TYPE bloom_filter GRANULARITY 4;
ALTER TABLE nanosiem.logs MATERIALIZE INDEX idx_enriched_dest_asn_lower;

ALTER TABLE nanosiem.logs ADD INDEX IF NOT EXISTS idx_enriched_dest_as_name_lower
    lower(enriched_dest_as_name) TYPE bloom_filter GRANULARITY 4;
ALTER TABLE nanosiem.logs MATERIALIZE INDEX idx_enriched_dest_as_name_lower;

ALTER TABLE nanosiem.logs ADD INDEX IF NOT EXISTS idx_enriched_dest_as_domain_lower
    lower(enriched_dest_as_domain) TYPE bloom_filter GRANULARITY 4;
ALTER TABLE nanosiem.logs MATERIALIZE INDEX idx_enriched_dest_as_domain_lower;
