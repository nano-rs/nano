-- =============================================================================
-- 162: prevalence dicts read *_prevalence_final (NAN-1732 P2-D phase 2 cutover)
-- =============================================================================
--
-- Phase 1 (migration 160) landed the pre-finalized `*_prevalence_final` tables +
-- their bounded-recency refresh MVs. This migration cuts the dict SOURCE over
-- from the summary to `final` — the point of the whole exercise.
--
-- BEFORE: SOURCE reads `*_prevalence_summary{dist_suffix}` with
--   `GROUP BY entity, uniqMerge(host_count)` on every cache-miss batch. On the
--   post-NAN-1728 distributed summary this fans a uniqMerge across shards per
--   miss — 254 GiB / 16.1B rows / 3h on Saturn, AND slow enough that per-batch
--   loads hit the 6000ms dict-source timeout → the batch falls back to the 9999
--   default → genuinely rare artifacts returned as common (NAN-1761 #2, a live
--   correctness degradation).
--
-- AFTER: SOURCE reads the LOCAL `*_prevalence_final` as a point-lookup
--   (`argMax(col, version)` GROUP BY key over the ReplacingMergeTree — the
--   CACHE dict pushes `WHERE key IN (batch)` in, so it reads only the batch's
--   rows via the entity ORDER BY). No uniqMerge, no summary scan, no cross-shard
--   fan-in, no timeout. `final` holds the byte-identical finalized value
--   (validated 0-mismatch vs the summary-sourced dict on local + Saturn), and is
--   kept complete by the refresh MV (recent set) + the one-time history backfill.
--
-- `final` is `keep-local` and complete on each node (the refresh reads the
--   distributed summary → global counts), so the SOURCE reads it LOCALLY — NO
--   {dist_suffix} (unlike the summary source in 159). New-artifact misses (an
--   entity younger than the ~10-min refresh cadence, not yet in `final`) fall to
--   the dict default and are covered by the D4b dict-blind rescue (NAN-1705).
--
-- Only the SOURCE QUERY changes; key/attributes/defaults/LAYOUT/LIFETIME are
-- byte-identical to migration 159 / init.sql. CREATE OR REPLACE is idempotent
-- and, being a CACHE (lazy) dict, does not trigger a load — the next dictGet at
-- ingest reads `final`.
-- =============================================================================

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
                  argMax(host_count, version) AS host_count,
                  argMax(first_seen, version) AS first_seen,
                  argMax(last_seen, version) AS last_seen,
                  argMax(total_occurrences, version) AS total_occurrences
           FROM nanosiem.hash_prevalence_final
           GROUP BY file_hash'
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
    HOST '{clickhouse_self_host}'
    PORT {clickhouse_self_port}
    USER '{clickhouse_self_user}'
    PASSWORD '{clickhouse_self_password}'
    DB 'nanosiem'
    QUERY 'SELECT domain,
                  argMax(host_count, version) AS host_count,
                  argMax(first_seen, version) AS first_seen,
                  argMax(last_seen, version) AS last_seen,
                  argMax(total_occurrences, version) AS total_occurrences
           FROM nanosiem.domain_prevalence_final
           GROUP BY domain'
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
    HOST '{clickhouse_self_host}'
    PORT {clickhouse_self_port}
    USER '{clickhouse_self_user}'
    PASSWORD '{clickhouse_self_password}'
    DB 'nanosiem'
    QUERY 'SELECT ip,
                  argMax(host_count, version) AS host_count,
                  argMax(first_seen, version) AS first_seen,
                  argMax(last_seen, version) AS last_seen,
                  argMax(total_occurrences, version) AS total_occurrences
           FROM nanosiem.ip_prevalence_final
           GROUP BY ip'
))
LIFETIME(MIN 900 MAX 1800)
LAYOUT(COMPLEX_KEY_CACHE(SIZE_IN_CELLS 5000000));
