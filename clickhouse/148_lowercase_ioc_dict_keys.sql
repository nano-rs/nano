-- Lowercase the IOC dictionary keys so ingest-time matching is case-insensitive (NAN-1588).
--
-- WHY: the `ioc_*` / `custom_ioc_*` MATERIALIZED columns on nanosiem.logs look up
-- the IOC dicts with a LOWERCASED key — `lower(file_hash)`, `lower(url_domain)`,
-- and ingest-lowercased `src_ip`/`dest_ip` (init.sql:830/834/856). But migration
-- 133 builds the dict key from the raw `key_value` the feed supplied
-- (`key_value AS ioc_value`), so an indicator that arrives in any other case — an
-- uppercase/mixed-case HASH, an IPv6 with uppercase hex (`2001:DB8::1`), an
-- uppercase DOMAIN — is keyed uppercase while every log lookup asks for the
-- lowercased form, and SILENTLY NEVER MATCHES. IPv4 is caseless, which is why IP
-- IOC matching has worked. (The search/`| retro` path already lowercases both
-- sides, so it is unaffected.)
--
-- FIX: lowercase the key in the dictionary SOURCE query — the same shape
-- `user_registry_dict` already uses (`username_lc`). This is a projection, not an
-- aggregation, so it stays off the memory-bound rule (NAN-1404). The dict reloads
-- from its existing staging on its LIFETIME cadence; the *_dict_staging tables and
-- their refresh MVs are deliberately left untouched (no rebuild, no refresh gap).
--
-- MECHANISM: CREATE OR REPLACE DICTIONARY (atomic swap — supported for dicts on
-- CH 26.4, unlike materialized views). The cluster transform fans this out
-- ON CLUSTER. This migration is the new canonical body for these two dicts;
-- clickhouse/init.sql is updated to match (guard: dict_source_memory_guard.rs,
-- DICTS_REDEFINED_BY_148). Migration 133 stays immutable history — it runs first
-- and is superseded by this CREATE OR REPLACE on every path.
--
-- Idempotent: re-running the same CREATE OR REPLACE is a harmless no-op.

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
    QUERY 'SELECT lower(ioc_value) AS ioc_value, ioc_type, source_id, threat_type, malware, confidence_level, tags FROM nanosiem.ioc_enrichment_dict_staging'
))
LIFETIME(MIN 60 MAX 300)
LAYOUT(HASHED());

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
    QUERY 'SELECT key_type, lower(key_value) AS key_value, threat_type, malware, confidence, tags, enrichment_names FROM nanosiem.custom_ioc_enrichment_dict_staging'
))
LAYOUT(COMPLEX_KEY_HASHED())
LIFETIME(MIN 60 MAX 300);
