-- Migration: Bounded layout for prevalence dictionaries (FRO-243).
--
-- ip_prevalence_dict / domain_prevalence_dict / hash_prevalence_dict were
-- defined in 110 with LAYOUT(SPARSE_HASHED()) over a source query doing
-- GROUP BY + uniqMerge across the full *_prevalence_summary table. Two
-- compounding issues made the dicts unloadable on any non-trivial tenant:
--
--   1. SPARSE_HASHED is unbounded in RAM — the full materialized result set
--      is resident for the life of the dict. At 20M+ keys this crosses the
--      6 GiB Team-tier max_server_memory_usage.
--   2. The source query's GROUP BY + uniqMerge over the whole summary table
--      allocates 3–4 GiB of HLL-merge temporaries every 5–10 min per
--      LIFETIME(MIN 300 MAX 600). Even if the layout fit, the load query
--      alone tripped the cap.
--
-- Symptom on nano-saturn: ip_prevalence_dict in FAILED_AND_RELOADING for
-- 12 days, `dictGetOrDefault` returning the 9999 fallback on every log
-- row's prevalence_min, and ExternalDictionariesLoader retry-storming the
-- cluster every 5–10 minutes.
--
-- Fix: switch to LAYOUT(COMPLEX_KEY_CACHE(SIZE_IN_CELLS 1000000)) with a
-- flat source query. On a miss, ClickHouse appends `WHERE {key} IN (...)`
-- to the source and the analyzer pushes that predicate into the GROUP BY
-- (the filter is on the grouping key), so the aggregation runs over just
-- the rows for the missed key batch rather than the full 20M-row table.
-- Cache memory is bounded to ~80 MiB (1M cells × ~80 B/row) regardless of
-- source growth. LIFETIME(MIN 900 MAX 1800) sets per-entry TTL — entries
-- stay cached 15–30 min before re-fetch on next access.
--
-- Pushdown requires CH ≥ 22.8 with the modern analyzer (default — controlled
-- by `allow_experimental_analyzer = 1`). If the legacy analyzer is forced on,
-- the predicate doesn't push and each miss degrades to a full-table GROUP BY.
-- The per-source-query `max_memory_usage = 512 MiB` cap below is a
-- belt-and-suspenders defense: in that degraded mode the query errors fast
-- and the dict returns the 9999 fallback instead of OOMing the server.
--
-- Followup if hit rate degrades on large tenants (track post-deploy): bump
-- SIZE_IN_CELLS or move to COMPLEX_KEY_SSD_CACHE. ~95% hit rate is the
-- threshold worth investigating at.
--
-- Dict names, attributes, and attribute order are identical to 110, so the
-- logs.prevalence_* ingest-time MATERIALIZED columns and the
-- `| prevalence` search command are unaffected. CREATE OR REPLACE swaps
-- atomically.

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
    HOST 'localhost'
    PORT 9000
    USER 'nanosiem'
    PASSWORD 'nanosiem'
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
    HOST 'localhost'
    PORT 9000
    USER 'nanosiem'
    PASSWORD 'nanosiem'
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
    HOST 'localhost'
    PORT 9000
    USER 'nanosiem'
    PASSWORD 'nanosiem'
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
LAYOUT(COMPLEX_KEY_CACHE(SIZE_IN_CELLS 1000000));
