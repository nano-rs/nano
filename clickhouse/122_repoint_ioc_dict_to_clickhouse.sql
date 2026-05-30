-- Migration: repoint ioc_enrichment_dict from PostgreSQL to ClickHouse and
-- split marketplace-provided vs user-created IOC enrichments (NAN-1114).
--
-- INCIDENT (demo, 0.1.578): ingestion silently stopped — zero new rows in
-- nanosiem.logs for ~20h — because ioc_enrichment_dict was FAILED:
--   Code: 614 POSTGRESQL_CONNECTION_FAILURE
--   "password authentication failed for user nanosiem"
-- The dict was PostgreSQL-sourced (init.sql) reading `ioc_enrichments JOIN
-- enrichment_sources`. NAN-1112 dropped the `ioc_enrichments` PG table (and the
-- native sync engine that filled it), so the dict can no longer load. The
-- nanosiem.logs `ioc_*` MATERIALIZED columns call dictGetOrDefault on it on
-- every insert, and a dict that fails to LOAD makes dictGetOrDefault THROW
-- (not return the default) — so every INSERT 500s and Vector's buffer drops
-- everything. Same failure class as migrations 115/121 (prevalence dict creds),
-- but here the PG *source table itself is gone*, so we move the dict to CH.
--
-- ROUTING MODEL (the reason for the is_marketplace split):
--   * ioc_*        = OOTB IOC feeds we provide via the marketplace (e.g.
--                    ThreatFox) -> ioc_enrichment_dict
--   * custom_ioc_* = IOC enrichments a user builds themselves ->
--                    custom_ioc_enrichment_dict
-- Both dicts read nanosiem.custom_enrichment_results. They are partitioned on
-- the new `is_marketplace` flag, written by the enrichment store path
-- (results_store::store_enrichment_records, set from marketplace_catalog).
--
-- The runner substitutes {clickhouse_self_*} placeholders for numbered
-- migrations (NAN-707). init.sql is kept in sync separately; prior migrations
-- are left untouched (editing them trips ChecksumMismatch).
--
-- Idempotent: ADD COLUMN IF NOT EXISTS + CREATE OR REPLACE DICTIONARY (atomic
-- swap). Existing rows are not backfilled — a migration can't join PG to learn
-- provenance, and `is_ioc=1 => marketplace` would mis-mark tenants that already
-- have user-created IOC enrichments. ioc_* repopulates on the next enrichment
-- sync (<=1h); ingestion itself resumes the moment the dict loads.

-- 1. Provenance marker on the shared results table.
ALTER TABLE nanosiem.custom_enrichment_results
    ADD COLUMN IF NOT EXISTS is_marketplace UInt8 DEFAULT 0;

-- 2. Repoint ioc_enrichment_dict: PostgreSQL (dead) -> ClickHouse, sourcing the
--    marketplace-provided IOC rows. Layout/attributes/key are unchanged from
--    the original PG definition so the nanosiem.logs ioc_* MATERIALIZED columns
--    (which look up by ioc_value) keep working.
CREATE OR REPLACE DICTIONARY nanosiem.ioc_enrichment_dict
(
    ioc_value String,
    ioc_type String DEFAULT '',
    source_id String DEFAULT '',
    threat_type String DEFAULT '',
    malware String DEFAULT '',
    confidence_level Int32 DEFAULT 0,
    tags String DEFAULT ''
)
PRIMARY KEY ioc_value
SOURCE(CLICKHOUSE(
    HOST '{clickhouse_self_host}'
    PORT {clickhouse_self_port}
    USER '{clickhouse_self_user}'
    PASSWORD '{clickhouse_self_password}'
    DB 'nanosiem'
    QUERY 'SELECT
        key_value AS ioc_value,
        anyLast(key_type) AS ioc_type,
        anyLast(enrichment_name) AS source_id,
        anyLast(threat_type) AS threat_type,
        anyLast(malware) AS malware,
        toInt32(anyLast(confidence)) AS confidence_level,
        arrayStringConcat(groupUniqArrayArray(tags), '','') AS tags
    FROM (
        SELECT * FROM nanosiem.custom_enrichment_results
        WHERE expires_at > now() AND is_ioc = 1 AND is_marketplace = 1
        ORDER BY confidence DESC
    )
    GROUP BY key_value'
))
LAYOUT(HASHED())
LIFETIME(MIN 60 MAX 300);

-- 3. Restrict custom_ioc_enrichment_dict to user-created enrichments so OOTB
--    marketplace feeds no longer double-populate custom_ioc_*. Query is
--    otherwise byte-for-byte identical to init.sql — only the WHERE gains
--    `AND is_marketplace = 0`.
CREATE OR REPLACE DICTIONARY nanosiem.custom_ioc_enrichment_dict
(
    key_type String,
    key_value String,
    threat_type String,
    malware String,
    confidence UInt8,
    tags Array(String),
    enrichment_names Array(String)
)
PRIMARY KEY key_type, key_value
SOURCE(CLICKHOUSE(
    HOST '{clickhouse_self_host}'
    PORT {clickhouse_self_port}
    USER '{clickhouse_self_user}'
    PASSWORD '{clickhouse_self_password}'
    DB 'nanosiem'
    QUERY 'SELECT
        key_type,
        key_value,
        anyLast(threat_type) as threat_type,
        anyLast(malware) as malware,
        anyLast(confidence) as confidence,
        groupUniqArrayArray(tags) as tags,
        groupUniqArray(enrichment_name) as enrichment_names
    FROM (
        SELECT * FROM nanosiem.custom_enrichment_results
        WHERE expires_at > now() AND is_ioc = 1 AND is_marketplace = 0
        ORDER BY confidence DESC
    )
    GROUP BY key_type, key_value'
))
LAYOUT(COMPLEX_KEY_HASHED())
LIFETIME(MIN 60 MAX 300);
