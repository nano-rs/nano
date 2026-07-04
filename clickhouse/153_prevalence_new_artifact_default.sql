-- =============================================================================
-- 153: ingest-time prevalence — a brand-new artifact stamps "new/rare" (1),
--      not "common" (9999)  (NAN-1662, P5 core; closes audit gap G1)
-- =============================================================================
--
-- BUG: the ingest-time MATERIALIZED prevalence_* columns did
--   dictGetOrDefault(dict, 'host_count', key, 9999)
-- A dict MISS returned 9999 ("common"), so a brand-new artifact — the single
-- most forensically-important event, its FIRST sighting — was frozen as
-- "common" forever, hidden from every `prevalence_* < N` rare filter (incl.
-- shadow-investigation's auto-hunt). The stamp is point-in-time and never
-- rewritten, so that first event stays wrong.
--
-- WHY A DICT MISS WAS AMBIGUOUS: the dict source dropped common artifacts
-- (`HAVING host_count < 1000`), so a miss meant EITHER "brand-new" OR
-- "so-common-we-dropped-it". Flipping the default alone would make every
-- common artifact read rare (a rare-hunt flood — Saturn: 780 common hashes,
-- 311 common domains + common IPs).
--
-- FIX (two coordinated halves):
--   1. Teach the dict to KEEP common artifacts, marked 9999, instead of
--      dropping them: drop `HAVING host_count < 1000`, store common as a 9999
--      cap. Now a dict miss can ONLY mean "genuinely new (not in the summary)".
--      Memory: the cache dict loads per-key (filtered), never full-scans (the
--      full-scan needs ~1.7GB > the 512MB cap, so it has always loaded lazily);
--      a per-key load with/without the HAVING is identical (~11MB, Saturn-
--      measured). No cap change needed.
--   2. Flip the ingest not-found default 9999 -> 1 on the four prevalence_*
--      columns (+ UDM prevalence_min's inline lookups). 1 is the TRUTH — a
--      just-seen artifact is on 1 host — it passes `< N`, renders as "1 host",
--      and builds up as the dict learns. The 65535 "field N/A" sentinel and the
--      9999 "common" marker are unchanged, so the frontend muting, the
--      prevalence page, and every 9999=common consumer keep working — only
--      genuinely-new flips.
--
-- ORDERING: the CREATE OR REPLACE DICTIONARY statements run first and reset the
-- (empty) cache, so on the first post-migration lookup a common key loads as
-- 9999 BEFORE the flipped column default can stamp it. No transition flood.
--
-- FORWARD-ONLY: ALTER ... MODIFY COLUMN on a MATERIALIZED expression is
-- metadata-only (verified) — it changes FUTURE inserts and does NOT rewrite
-- existing parts. Historical first-contact rows keep their old 9999 stamp
-- (backfill would be a multi-TB mutation — deliberately not done).
--
-- The dicts and both column sets (UDM logs, OCSF ocsf_logs) are kept in lockstep
-- with clickhouse/init.sql and clickhouse/ocsf/init.sql (fresh bootstraps).
-- =============================================================================

-- ----------------------------------------------------------------------------
-- 1. Dict sources: keep common (marked 9999), so a miss == genuinely new.
-- ----------------------------------------------------------------------------
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
                  if(uniqMerge(host_count) >= 1000, toUInt16(9999), toUInt16(least(9998, uniqMerge(host_count)))) AS host_count,
                  min(first_seen) AS first_seen,
                  max(last_seen) AS last_seen,
                  toUInt64(sum(total_count)) AS total_occurrences
           FROM nanosiem.hash_prevalence_summary
           GROUP BY file_hash
           SETTINGS max_memory_usage = 536870912, max_bytes_before_external_group_by = 268435456, max_threads = 2'
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
                  if(uniqMerge(source_host_count) >= 1000, toUInt16(9999), toUInt16(least(9998, uniqMerge(source_host_count)))) AS host_count,
                  min(first_seen) AS first_seen,
                  max(last_seen) AS last_seen,
                  toUInt64(sum(total_count)) AS total_occurrences
           FROM nanosiem.domain_prevalence_summary
           GROUP BY domain
           SETTINGS max_memory_usage = 536870912, max_bytes_before_external_group_by = 268435456, max_threads = 2'
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
                  if(uniqMerge(source_host_count) >= 1000, toUInt16(9999), toUInt16(least(9998, uniqMerge(source_host_count)))) AS host_count,
                  min(first_seen) AS first_seen,
                  max(last_seen) AS last_seen,
                  toUInt64(sum(total_count)) AS total_occurrences
           FROM nanosiem.ip_prevalence_summary
           WHERE is_private = 0
           GROUP BY ip
           SETTINGS max_memory_usage = 536870912, max_bytes_before_external_group_by = 268435456, max_threads = 2'
))
LIFETIME(MIN 900 MAX 1800)
LAYOUT(COMPLEX_KEY_CACHE(SIZE_IN_CELLS 5000000));

-- ----------------------------------------------------------------------------
-- 2a. UDM nanosiem.logs — flip the not-found default 9999 -> 1.
--     (65535 "field N/A" branch unchanged; empty-field prevalence_min branches
--      stay 9999 so an absent field never drags the min down.)
-- ----------------------------------------------------------------------------
ALTER TABLE nanosiem.logs
    MODIFY COLUMN `prevalence_file_hash` UInt16 MATERIALIZED if(file_hash != '', dictGetOrDefault('nanosiem.hash_prevalence_dict', 'host_count', lower(file_hash), toUInt16(1)), toUInt16(65535)) CODEC(T64, LZ4);

ALTER TABLE nanosiem.logs
    MODIFY COLUMN `prevalence_process_hash` UInt16 MATERIALIZED if(process_hash != '', dictGetOrDefault('nanosiem.hash_prevalence_dict', 'host_count', lower(process_hash), toUInt16(1)), toUInt16(65535)) CODEC(T64, LZ4);

ALTER TABLE nanosiem.logs
    MODIFY COLUMN `prevalence_dest_domain` UInt16 MATERIALIZED if(dest_host != '' AND NOT match(dest_host, '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$'), dictGetOrDefault('nanosiem.domain_prevalence_dict', 'host_count', lower(dest_host), toUInt16(1)), toUInt16(65535)) CODEC(T64, LZ4);

ALTER TABLE nanosiem.logs
    MODIFY COLUMN `prevalence_dest_ip` UInt16 MATERIALIZED if(dest_ip != '' AND NOT (match(dest_ip, '^10\\.') OR match(dest_ip, '^172\\.(1[6-9]|2[0-9]|3[0-1])\\.') OR match(dest_ip, '^192\\.168\\.') OR match(dest_ip, '^127\\.') OR match(dest_ip, '^169\\.254\\.')), dictGetOrDefault('nanosiem.ip_prevalence_dict', 'host_count', dest_ip, toUInt16(1)), toUInt16(65535)) CODEC(T64, LZ4);

ALTER TABLE nanosiem.logs
    MODIFY COLUMN `prevalence_min` UInt16 DEFAULT least(
        if(file_hash != '', dictGetOrDefault('nanosiem.hash_prevalence_dict', 'host_count', lower(file_hash), toUInt16(1)), toUInt16(9999)),
        if(process_hash != '', dictGetOrDefault('nanosiem.hash_prevalence_dict', 'host_count', lower(process_hash), toUInt16(1)), toUInt16(9999)),
        if(dest_host != '' AND NOT match(dest_host, '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$'), dictGetOrDefault('nanosiem.domain_prevalence_dict', 'host_count', lower(dest_host), toUInt16(1)), toUInt16(9999)),
        if(dest_ip != '' AND NOT (startsWith(dest_ip, '10.') OR startsWith(dest_ip, '172.16.') OR startsWith(dest_ip, '192.168.') OR startsWith(dest_ip, '127.')), dictGetOrDefault('nanosiem.ip_prevalence_dict', 'host_count', dest_ip, toUInt16(1)), toUInt16(9999))
    ) CODEC(T64, LZ4);

-- ----------------------------------------------------------------------------
-- 2b. OCSF nanosiem.ocsf_logs — same flip. Shared dicts, so no separate dict
--     change. Marked skip-if-unknown-table (ocsf_logs only exists on
--     NANO_SCHEMA_PROFILE=ocsf). OCSF prevalence_min is column-derived and
--     inherits the fix automatically — no statement needed.
-- ----------------------------------------------------------------------------
ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */
    MODIFY COLUMN `prevalence_file_hash` UInt16 MATERIALIZED if(`file.hashes.sha256` != '', dictGetOrDefault('nanosiem.hash_prevalence_dict', 'host_count', `file.hashes.sha256`, toUInt16(1)), toUInt16(65535)) CODEC(T64, LZ4);

ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */
    MODIFY COLUMN `prevalence_process_hash` UInt16 MATERIALIZED if(`process.file.hashes.sha256` != '', dictGetOrDefault('nanosiem.hash_prevalence_dict', 'host_count', `process.file.hashes.sha256`, toUInt16(1)), toUInt16(65535)) CODEC(T64, LZ4);

ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */
    MODIFY COLUMN `prevalence_dest_domain` UInt16 MATERIALIZED if(`dst_endpoint.hostname` != '' AND NOT match(`dst_endpoint.hostname`, '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$'), dictGetOrDefault('nanosiem.domain_prevalence_dict', 'host_count', lower(`dst_endpoint.hostname`), toUInt16(1)), toUInt16(65535)) CODEC(T64, LZ4);

ALTER TABLE nanosiem.ocsf_logs /* nano:skip-if-unknown-table */
    MODIFY COLUMN `prevalence_dest_ip` UInt16 MATERIALIZED if(`dst_endpoint.ip` != '' AND NOT (startsWith(`dst_endpoint.ip`, '10.') OR startsWith(`dst_endpoint.ip`, '172.16.') OR startsWith(`dst_endpoint.ip`, '192.168.') OR startsWith(`dst_endpoint.ip`, '127.')), dictGetOrDefault('nanosiem.ip_prevalence_dict', 'host_count', `dst_endpoint.ip`, toUInt16(1)), toUInt16(65535)) CODEC(T64, LZ4);
