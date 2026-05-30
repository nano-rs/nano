-- Migration: Re-apply domain_prevalence_dict and hash_prevalence_dict with
-- templated credentials. Same fix as 115_fix_ip_prevalence_dict_creds.sql
-- (NAN-707) but for the other two prevalence dicts that 115 missed.
--
-- 112 hardcoded `USER 'nanosiem' PASSWORD 'nanosiem'` in all three prevalence
-- dict definitions. 115 fixed only `ip_prevalence_dict`. Every BYOC tenant
-- (and every tenant that rotated the default password) hits
-- `Code: 516 AUTHENTICATION_FAILED` on dict load — every INSERT into
-- nanosiem.logs that triggers an MV using `dictGetOrDefault` on these dicts
-- silently aborts → the ingest pipeline drops events with no exception
-- surfaced in query_log.
--
-- Observed live on fresh GCP BYOC tenant `nano-slepe`:
--   ip_prevalence_dict     LOADED
--   domain_prevalence_dict FAILED  Code: 516. Authentication failed
--   hash_prevalence_dict   FAILED  Code: 516. Authentication failed
--
-- The migration runner substitutes `{clickhouse_self_*}` placeholders for
-- numbered migrations (NAN-707, sql_transform.rs::substitute_clickhouse_self_vars).
-- This migration reissues the two broken dict definitions using those
-- placeholders so the substituted creds get baked in on next apply.
--
-- 112 is left untouched on disk (its checksum is recorded in tenants'
-- _migrations tables; editing it would trip ChecksumMismatch in
-- check_schema_up_to_date).
--
-- Idempotent: CREATE OR REPLACE swaps atomically. Layout, lifetime, and
-- source query are byte-for-byte identical to 112 — only the SOURCE
-- credentials change.

CREATE OR REPLACE DICTIONARY nanosiem.domain_prevalence_dict
(
    domain String,
    host_count UInt16 DEFAULT 9999,
    first_seen DateTime64(6) DEFAULT '1970-01-01 00:00:00',
    last_seen DateTime64(6) DEFAULT '1970-01-01 00:00:00',
    total_occurrences UInt64 DEFAULT 0
)
PRIMARY KEY domain
SOURCE(CLICKHOUSE(
    HOST '{clickhouse_self_host}'
    PORT {clickhouse_self_port}
    USER '{clickhouse_self_user}'
    PASSWORD '{clickhouse_self_password}'
    DB 'nanosiem'
    QUERY 'SELECT domain,
                  toUInt16(least(9998, uniqMerge(source_host_count))) AS host_count,
                  min(first_seen) AS first_seen,
                  max(last_seen) AS last_seen,
                  toUInt64(sum(total_count)) AS total_occurrences
           FROM nanosiem.domain_prevalence_summary
           GROUP BY domain
           HAVING host_count < 1000
           SETTINGS max_memory_usage = 536870912'
))
LIFETIME(MIN 900 MAX 1800)
LAYOUT(COMPLEX_KEY_CACHE(SIZE_IN_CELLS 1000000));

CREATE OR REPLACE DICTIONARY nanosiem.hash_prevalence_dict
(
    file_hash String,
    host_count UInt16 DEFAULT 9999,
    first_seen DateTime64(6) DEFAULT '1970-01-01 00:00:00',
    last_seen DateTime64(6) DEFAULT '1970-01-01 00:00:00',
    total_occurrences UInt64 DEFAULT 0
)
PRIMARY KEY file_hash
SOURCE(CLICKHOUSE(
    HOST '{clickhouse_self_host}'
    PORT {clickhouse_self_port}
    USER '{clickhouse_self_user}'
    PASSWORD '{clickhouse_self_password}'
    DB 'nanosiem'
    QUERY 'SELECT file_hash,
                  toUInt16(least(9998, uniqMerge(host_count))) AS host_count,
                  min(first_seen) AS first_seen,
                  max(last_seen) AS last_seen,
                  toUInt64(sum(total_count)) AS total_occurrences
           FROM nanosiem.hash_prevalence_summary
           GROUP BY file_hash
           HAVING host_count < 1000
           SETTINGS max_memory_usage = 536870912'
))
LIFETIME(MIN 900 MAX 1800)
LAYOUT(COMPLEX_KEY_CACHE(SIZE_IN_CELLS 1000000));
