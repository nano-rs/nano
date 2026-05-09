-- Migration: Bump ip_prevalence_dict cache to 5M cells (NAN-706).
--
-- Saturn observation post-NAN-701 deploy: ip_prevalence_dict at 89.85%
-- hit rate, both shards pegged at the 1M-cell cap. The miss rate kept
-- firing the dict's source query against ip_prevalence_summary
-- (~50 batched queries per 2 min, ~400 IPs each) which kept CH CPU
-- pinned. NAN-701's call-site change (panel/detection -> dictGet) is
-- working as designed — the bottleneck is just the cache being too
-- small for saturn's working set.
--
-- Migration 112 documented this exact followup: "If hit rate degrades
-- on large tenants: bump SIZE_IN_CELLS or move to COMPLEX_KEY_SSD_CACHE.
-- ~95% hit rate is the threshold worth investigating at."
--
-- 5M cells × ~80 B/cell ≈ 400 MiB resident. Well within the 8 GiB
-- max_server_memory_usage on saturn (the 89.85% hit-rate baseline
-- showed ~620 MiB headroom even with the rest of the cluster running).
-- Hash and domain dicts stay at 1M for now — no concrete pressure data
-- on those yet; revisit if their hit rates also dip below 95%.
--
-- Idempotent: CREATE OR REPLACE swaps atomically, so applying twice is
-- a no-op. Source query, attributes, and PRIMARY KEY are byte-identical
-- to migration 112; only the LAYOUT constant changes.

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
LAYOUT(COMPLEX_KEY_CACHE(SIZE_IN_CELLS 5000000));
