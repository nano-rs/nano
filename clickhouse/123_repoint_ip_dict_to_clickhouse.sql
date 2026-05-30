-- Migration: repoint ip_enrichment_dict (IP / GeoIP / IPinfo Lite) from
-- PostgreSQL to ClickHouse, and create the CH-side payload table it now reads
-- (NAN-1117).
--
-- WHY (exact NAN-1114 / 122 failure class): ip_enrichment_dict was
-- PostgreSQL-sourced (init.sql) reading `ip_enrichments JOIN enrichment_sources`.
-- The nanosiem.logs `enriched_src_*` / `enriched_dest_*` MATERIALIZED columns
-- (init.sql:557-570) call dictGetOrDefault on this dict on EVERY insert. A dict
-- that fails to LOAD makes dictGetOrDefault THROW (not return the default) — so
-- if the PG source disappears or auth fails, every INSERT 500s and Vector
-- (when_full=drop_newest) silently discards all logs: a total, silent ingestion
-- halt. NAN-1112 already proved the PG payload tables are migration-fragile.
-- We move the dict's payload + source to ClickHouse so ingestion no longer
-- depends on a cross-database PG read on the hot path. PG keeps only
-- enrichment_sources (config/metadata: url, enabled, sync status).
--
-- INGESTION-HALT MITIGATION: the CH payload table is CREATEd (IF NOT EXISTS)
-- in this SAME migration BEFORE the CREATE OR REPLACE DICTIONARY, so even an
-- empty-but-LOADED dict returns defaults instead of THROWing. The dict must
-- never reference a not-yet-existing table.
--
-- IP_TRIE / CIDR keying: `network` MUST stay a String holding CIDR notation
-- ('1.2.3.0/24', '2001:db8::/32'). IP_TRIE builds its trie from the CIDR
-- string; using a CH IPv4/IPv6 column type would break trie construction and
-- the toIPv4OrDefault/toIPv6OrDefault lookups in the logs columns. The IPinfo
-- Lite CSV `network` field is already canonical CIDR text and is inserted
-- verbatim by the Rust sync writer.
--
-- Attributes / PRIMARY KEY / LAYOUT(IP_TRIE()) are BYTE-FOR-BYTE identical to
-- the prior PG-sourced dict so the 14 logs enriched_* columns keep resolving
-- unchanged — do NOT rename attributes or the key.
--
-- The runner substitutes {clickhouse_self_*} placeholders for numbered
-- migrations (NAN-707). init.sql is kept in sync separately (literal env-
-- rendered creds); prior migrations are left untouched (editing them trips
-- ChecksumMismatch).
--
-- Idempotent: CREATE TABLE IF NOT EXISTS + CREATE OR REPLACE DICTIONARY.
--
-- DROP ORDERING: the PG `ip_enrichments` table is NOT dropped here. It is
-- dropped in PG migration 197, which must ship in a LATER release once this
-- repoint is live everywhere and a sync has populated CH — dropping the PG
-- table in the same release that any tenant could still run the OLD PG-sourced
-- dict against is exactly the NAN-1114 incident.

-- 1. CH payload table mirroring the PG ip_enrichments columns the dict reads.
--    ReplacingMergeTree keyed by (source_id, network) gives last-write-wins per
--    CIDR, matching the PG UNIQUE(source_id, network) + DELETE-then-INSERT swap.
--    `updated_at` is the version column; `deleted` is a tombstone for CIDRs a
--    newer feed dropped. `network` stays a CIDR String (see IP_TRIE note above).
CREATE TABLE IF NOT EXISTS nanosiem.ip_enrichments
(
    network         String,
    source_id       LowCardinality(String) DEFAULT 'ipinfo_lite',
    country         String DEFAULT '',
    country_code    String DEFAULT '',
    continent       String DEFAULT '',
    continent_code  String DEFAULT '',
    asn             String DEFAULT '',
    as_name         String DEFAULT '',
    as_domain       String DEFAULT '',
    updated_at      DateTime64(3) DEFAULT now64(3),
    deleted         UInt8 DEFAULT 0
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (source_id, network);

-- 2. Repoint ip_enrichment_dict: PostgreSQL (fragile) -> ClickHouse.
--    argMax(...) GROUP BY network + HAVING deleted=0 collapses
--    ReplacingMergeTree duplicates at dict-load time without relying on
--    background merges, and drops tombstoned CIDRs. IP_TRIE requires exactly
--    one String PRIMARY KEY holding CIDR strings.
--
--    ENABLED GATE (NAN-1117): the old PG source ended in `WHERE es.enabled =
--    true`, so disabling the ipinfo_lite source blanked the dict on next
--    reload. CH cannot join PG here, so the disable UX is preserved on the
--    write side instead: disabling the source lightweight-DELETEs its CH rows
--    (EnrichmentService::clear_ip_enrichments_for_source), so the dict reloads
--    empty exactly as before; re-enabling repopulates on the next sync.
CREATE OR REPLACE DICTIONARY nanosiem.ip_enrichment_dict
(
    network String,
    country String DEFAULT '',
    country_code String DEFAULT '',
    continent String DEFAULT '',
    continent_code String DEFAULT '',
    asn String DEFAULT '',
    as_name String DEFAULT '',
    as_domain String DEFAULT ''
)
PRIMARY KEY network
SOURCE(CLICKHOUSE(
    HOST '{clickhouse_self_host}'
    PORT {clickhouse_self_port}
    USER '{clickhouse_self_user}'
    PASSWORD '{clickhouse_self_password}'
    DB 'nanosiem'
    QUERY 'SELECT
        network,
        argMax(country, updated_at) AS country,
        argMax(country_code, updated_at) AS country_code,
        argMax(continent, updated_at) AS continent,
        argMax(continent_code, updated_at) AS continent_code,
        argMax(asn, updated_at) AS asn,
        argMax(as_name, updated_at) AS as_name,
        argMax(as_domain, updated_at) AS as_domain
    FROM nanosiem.ip_enrichments
    GROUP BY network
    HAVING argMax(deleted, updated_at) = 0'
))
LIFETIME(MIN 300 MAX 600)
LAYOUT(IP_TRIE());
