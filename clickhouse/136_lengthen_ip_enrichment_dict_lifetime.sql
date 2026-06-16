-- Migration: lengthen ip_enrichment_dict LIFETIME 5–10min → 6–12h (NAN-1473).
--
-- WHY: ip_enrichment_dict is an IP_TRIE over IPinfo Lite — ~3.6M ranges /
-- ~800 MiB resident, and each reload spikes another ~800 MiB–1 GiB build
-- transient on top of the resident dicts. Migration 133's LIFETIME(MIN 300
-- MAX 600) made ClickHouse rebuild that trie every 5–10 minutes. On
-- smaller-spec boxes (org: 3.7 GB Hetzner) that recurring transient pegged
-- the CH memory cap and caused MEMORY_LIMIT_EXCEEDED on both the rebuild and
-- concurrent interactive search queries (NAN-1404 family).
--
-- IPinfo Lite geo/ASN data changes ~weekly, so the 5–10 min rebuild was pure
-- churn. Migration 133 already decoupled FRESHNESS from the dict LIFETIME:
-- the ip_enrichment_dict_refresh MV refreshes the STAGING table every 5 min,
-- and the dict's LIFETIME only controls how often it re-reads that staging
-- table into the trie. Lengthening LIFETIME to 6–12h therefore cuts the
-- trie-rebuild churn ~100x with negligible staleness for near-static geo
-- data, and removes the recurring memory pressure on smaller boxes.
--
-- SCOPE: only the heavy IP_TRIE dict is changed here. The other four staged
-- dicts (ioc_enrichment, custom_enrichment, custom_ioc_enrichment,
-- user_registry) are far smaller HASHED dicts whose rebuilds are cheap, and
-- the IOC feeds genuinely benefit from staying fresh for threat matching —
-- they keep their migration-133 LIFETIMEs. The prevalence CACHE dicts are
-- untouched (their LIFETIME is cache-expiry semantics, not full reload).
--
-- The dict body below is byte-identical to migration 133 / clickhouse/init.sql
-- except for the LIFETIME line; clickhouse/init.sql is updated to match (fresh
-- bootstraps land directly on the new LIFETIME). The lockstep guard
-- (nanosiem-core/tests/dict_source_memory_guard.rs) now treats this migration
-- as the canonical definition for ip_enrichment_dict. The runner substitutes
-- {clickhouse_self_*} placeholders (NAN-707). Prior migrations are left
-- untouched (editing them trips ChecksumMismatch).
--
-- Idempotent: CREATE OR REPLACE DICTIONARY is an atomic swap.

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
    QUERY 'SELECT network, country, country_code, continent, continent_code, asn, as_name, as_domain FROM nanosiem.ip_enrichment_dict_staging'
))
LIFETIME(MIN 21600 MAX 43200)
LAYOUT(IP_TRIE())
SETTINGS(max_result_rows = 0, max_result_bytes = 0);
