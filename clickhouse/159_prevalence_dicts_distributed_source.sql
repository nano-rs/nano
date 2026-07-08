-- =============================================================================
-- 159: prevalence cache dicts -> DISTRIBUTED summary source (NAN-1728 — C3)
-- =============================================================================
--
-- The hash/domain/ip prevalence CACHE dicts source their host_count / first_seen
-- / last_seen / total_occurrences from the *_prevalence_summary tables. Those
-- summary tables are AggregatingMergeTree and are PER-SHARD (they are 80M+ rows
-- on Saturn — far too large to cluster-wide replicate; unlike the small C2
-- reference tables in migration 158). On the enterprise 3-shard tier a dict that
-- reads the LOCAL summary sees only ~1/3 of the hosts, so:
--   * host_count ~= 1/3 of reality -> `host_count < N` rare-artifact rules
--     false-positive on genuinely common artifacts;
--   * the NAN-1662 9999 common-mask invariant breaks (a 1,800-host artifact is
--     < 1000 per shard -> never masked -> NAN-1699 dict-mask path passes it as
--     rare);
--   * the ingest-time prevalence_* MATERIALIZED columns stamp per-landing-shard
--     values -> the same artifact stored with 3 different prevalence values, and
--     a cache MISS on a shard that never saw it stamps 1 ("brand new").
--
-- FIX: repoint each dict's SOURCE QUERY at nanosiem.<x>_prevalence_summary
-- followed by the {dist_suffix} placeholder (the three summaries
-- were added to dual_pool::DISTRIBUTED_TABLES this release, so the reconciler
-- auto-creates the *_distributed wrappers on clusters). The uniqMerge(...) GROUP
-- BY key is retained verbatim: uniqMerge over a Distributed AggregatingMergeTree
-- merges the per-shard uniq partials into one global count — the standard
-- cross-shard fan-in. This mirrors the change already made to
-- clickhouse/init.sql for fresh installs; here it is pushed to EXISTING installs
-- via CREATE OR REPLACE DICTIONARY.
--
-- The dict bodies below are byte-identical to init.sql except for the
-- {dist_suffix} placeholder on the FROM table. CACHE layout, cell
-- counts, LIFETIME, attributes and the memory-bounded SETTINGS are unchanged.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- TOPOLOGY RESOLUTION (single-shard AND multi-shard from one definition):
-- {dist_suffix} is resolved by the migrator's generalized suffix substitution
-- (clickhouse_migrate::sql_transform, the same {dist_suffix} used by the
-- dict-refresh MVs in migration 158,
-- wired into apply_migration + run_init_sql) using the SAME detect_cluster()
-- signal that gates wrapper creation:
--   * cluster (Saturn 1x2, enterprise 3x2 — detect_cluster() = Some) → suffix
--     "_distributed": reads the reconciler-created wrapper (fans uniqMerge across
--     shards). The reconciler runs AFTER migrations; CACHE dicts load lazily, so
--     the wrapper exists by the first miss.
--   * true single-node (dev / open-core install.sh, no <remote_servers> —
--     detect_cluster() = None) → suffix "" : reads the plain local
--     nanosiem.<x>_prevalence_summary, which is complete on one shard.
-- We deliberately do NOT hardcode "_distributed" and do NOT create any
-- *_distributed object on single-node (that would false-positive DualPool's
-- logs_distributed-presence cluster detection). CREATE OR REPLACE DICTIONARY is
-- idempotent, so re-runs are safe.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- WRAPPER-EXISTENCE / NO-WINDOW (P2a): on a cluster this CREATE OR REPLACE
-- DICTIONARY points at *_prevalence_summary_distributed, whose wrapper is created
-- by ensure_distributed_tables(). Boot ordering (nanosiem-api/src/bin/
-- clickhouse_migrator.rs) is: run_init_sql -> run_migrations (THIS migration) ->
-- ensure_distributed_tables -> reconcile_distributed_columns, ALL in the SAME
-- migrator process, which api/search/jobs gate on (they refuse to serve until
-- the migrator has completed / the schema is up to date). Crucially these are
-- CACHE (lazy) dictionaries — CREATE OR REPLACE only STORES the definition, it
-- does NOT trigger a load; the first dictGet happens at ingest, which resumes
-- only AFTER the migrator exits, by which point the wrapper exists. So there is
-- NO window in which a dictGet hits a not-yet-created wrapper. (A migrator that
-- crashed between this migration and ensure_distributed_tables fails the deploy;
-- apps stay down and the next migrator run reaches ensure_distributed_tables
-- before completing — fail-closed, self-healing.)
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
                  if(uniqMerge(host_count) >= 1000, toUInt16(9999), toUInt16(least(9998, uniqMerge(host_count)))) AS host_count,
                  min(first_seen) AS first_seen,
                  max(last_seen) AS last_seen,
                  toUInt64(sum(total_count)) AS total_occurrences
           FROM nanosiem.hash_prevalence_summary{dist_suffix}
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
           FROM nanosiem.domain_prevalence_summary{dist_suffix}
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
           FROM nanosiem.ip_prevalence_summary{dist_suffix}
           WHERE is_private = 0
           GROUP BY ip
           SETTINGS max_memory_usage = 536870912, max_bytes_before_external_group_by = 268435456, max_threads = 2'
))
LIFETIME(MIN 900 MAX 1800)
LAYOUT(COMPLEX_KEY_CACHE(SIZE_IN_CELLS 5000000));
