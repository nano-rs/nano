-- Migration: Re-apply ip_prevalence_dict with templated credentials (NAN-707).
--
-- NAN-706's migration 114 hardcoded `USER 'nanosiem' PASSWORD 'nanosiem'`
-- in the dict's SOURCE block. That worked on most tenants only because they
-- kept the default password. Saturn had rotated credentials, so post-migration
-- every dictGetOrDefault('nanosiem.ip_prevalence_dict', ...) failed with
-- `Code: 516 AUTHENTICATION_FAILED` — every panel using IP prevalence broken,
-- CH CPU dropped from pinned to ~200m as queries fail-fasted.
--
-- Root cause was in the migration runner, not in the migration: only init.sql
-- substituted `{clickhouse_self_*}` placeholders; numbered migrations didn't.
-- NAN-707 extends the runner so numbered migrations get the same substitution.
-- This migration re-issues the dict definition using placeholders so the
-- corrected creds get baked in on next apply.
--
-- 114 is left untouched on disk (its checksum is recorded in tenants'
-- _migrations tables; editing it would trip ChecksumMismatch in
-- check_schema_up_to_date).
--
-- Idempotent: CREATE OR REPLACE swaps atomically. SIZE_IN_CELLS stays at
-- 5,000,000 (NAN-706's intent) since 114 already applied that bump on
-- tenants where its auth happened to work; this migration's job is purely
-- to fix the credentials.

CREATE OR REPLACE DICTIONARY nanosiem.ip_prevalence_dict
(
    ip String,
    host_count UInt16 DEFAULT 9999,
    first_seen DateTime64(6) DEFAULT '1970-01-01 00:00:00',
    last_seen DateTime64(6) DEFAULT '1970-01-01 00:00:00',
    total_occurrences UInt64 DEFAULT 0
)
PRIMARY KEY ip
SOURCE(CLICKHOUSE(
    HOST '{clickhouse_self_host}'
    PORT {clickhouse_self_port}
    USER '{clickhouse_self_user}'
    PASSWORD '{clickhouse_self_password}'
    DB 'nanosiem'
    QUERY 'SELECT ip,
                  toUInt16(least(9998, uniqMerge(source_host_count))) AS host_count,
                  min(first_seen) AS first_seen,
                  max(last_seen) AS last_seen,
                  toUInt64(sum(total_count)) AS total_occurrences
           FROM nanosiem.ip_prevalence_summary
           WHERE is_private = 0
           GROUP BY ip
           HAVING host_count < 1000
           SETTINGS max_memory_usage = 536870912'
))
LIFETIME(MIN 900 MAX 1800)
LAYOUT(COMPLEX_KEY_CACHE(SIZE_IN_CELLS 5000000));
