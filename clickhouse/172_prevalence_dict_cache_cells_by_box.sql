-- Migration: size the prevalence CACHE dicts' SIZE_IN_CELLS to the box
-- (NAN-2346 — 400 MiB preallocated fleet-wide to hold ~11 rows).
--
-- WHY: COMPLEX_KEY_CACHE preallocates its ENTIRE cell array at the first
-- dictGet, regardless of how many keys are ever resident, and ClickHouse rounds
-- SIZE_IN_CELLS UP to the next power of two. So `SIZE_IN_CELLS 5000000` does not
-- allocate 5M cells — it allocates 2^23 = 8,388,608. Measured on a live tenant:
--
--   ip_prevalence_dict        2 elements   320.02 MiB   (2^23 cells)
--   domain_prevalence_dict    8 elements    40.02 MiB   (2^20 cells)
--   hash_prevalence_dict      1 element     40.02 MiB   (2^20 cells)
--
-- 320.02 MiB / 2^23 = exactly 40.0 B/cell. (Migrations 112/114 and
-- docs-internal cite "~80 B/row"; that figure is wrong in both directions and
-- only coincidentally lands near the truth for the ip dict.)
--
-- This is not a hobby-only problem — it is just fatal there first. `org`, the
-- central aggregator with ~12M dictionary queries, also holds 1 element in each
-- of the three at a 99.62–99.99% found_rate. The 5M constant (NAN-706, sized for
-- Saturn's working set against the OLD source) has no measured justification on
-- any box we can observe.
--
-- IMPACT: on a 4 GB hobby box ClickHouse was capped at 1.6 GiB, so those 400 MiB
-- were a quarter of the server's entire budget. With them resident,
-- ip_enrichment_dict could not build its ~3.4M-range IP_TRIE: every load hit
-- MEMORY_LIMIT_EXCEEDED at the same row offset, the dict stayed `LOADED` with
-- `element_count 0` (CH keeps the last-good version on a failed update), and
-- dictGetOrDefault therefore returned defaults rather than throwing. IP
-- geo/ASN enrichment produced nothing at all while ingest looked perfectly
-- healthy and no alarm fired. Freeing the cache is what let the trie fit.
--
-- WHY SHRINKING IS SAFE NOW: a CACHE dict miss re-queries its SOURCE, so a small
-- cache costs miss-QPS, never correctness. The historical objections were all
-- measured against the PRE-162 source (a per-miss `uniqMerge` fan-out across
-- shards — 254 GiB / 16.1B rows / 3h on Saturn): NAN-706's CPU pinning, and
-- NAN-1761 #2 where batches blew the 6000 ms dict-source timeout and fell back
-- to the 9999 "common" default, reporting genuinely rare artifacts as common.
-- Migration 162 cut the SOURCE over to a point lookup on the local
-- `*_prevalence_final` (~326 KiB per miss, 0 rows for an absent key), which is
-- what makes a small cache cheap. Because these placeholders only ever appear in
-- ≥172 bodies, that ordering is structural rather than a deployment assumption.
--
-- MECHANISM: `{prevalence_cache_cells_ip}` / `{prevalence_cache_cells}` are
-- resolved by the migration runner (sql_transform.rs) from
-- NANO_PREVALENCE_CACHE_CELLS_IP / NANO_PREVALENCE_CACHE_CELLS. **Unset, they
-- resolve to today's literals (5000000 / 1000000)** — so k8s, BYOC, CH Cloud,
-- dev compose and open-core installs are byte-identical to current behaviour.
-- Only managed-compose tenants, whose generated .env carries the vars, get a
-- box-sized cache. Checksums are computed over the RAW pre-substitution file
-- bytes, so a placeholder never trips ChecksumMismatch.
--
-- ⚠ THE VALUE IS BAKED AT APPLY TIME. A migration runs exactly once, and
-- init.sql only replays when its own file hash changes — so setting or changing
-- NANO_PREVALENCE_CACHE_CELLS* AFTER this migration has been recorded does
-- nothing on its own; the dicts keep whatever size they were created with. The
-- platform therefore backfills both keys into a tenant's .env BEFORE the
-- compose up that recreates clickhouse-migrate (nano-main
-- provisioning-worker/update.ts), so the value is present the first time this
-- runs. An operator retuning an already-migrated box must re-issue these three
-- CREATE OR REPLACE statements by hand (or land a follow-up migration) — a
-- resize is an atomic swap, so doing so is safe at any time.
--
-- Attributes / PRIMARY KEY / SOURCE QUERY / LIFETIME are byte-for-byte identical
-- to migration 162 — ONLY the SIZE_IN_CELLS literal becomes a placeholder — so
-- every dependent nanosiem.logs MATERIALIZED column keeps resolving unchanged.
-- This SUPERSEDES 162 as the canonical body for PUSHDOWN_DICTS; 162 stays
-- immutable history exactly as 153 did (guard:
-- nanosiem-core/tests/dict_source_memory_guard.rs, and both init.sql files are
-- kept in lockstep). Prior migrations are left untouched — editing them trips
-- ChecksumMismatch.
--
-- NOTE the pushdown dicts deliberately carry NO source-memory SETTINGS: their
-- GROUP BY is exactly the dict key, so CACHE key-pushdown bounds each miss
-- query on its own (NAN-1440 / migration 130's is_key_pushdown_bounded carve-out).
--
-- Idempotent: CREATE OR REPLACE DICTIONARY is an atomic swap. DDL-only.

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
LAYOUT(COMPLEX_KEY_CACHE(SIZE_IN_CELLS {prevalence_cache_cells}));

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
LAYOUT(COMPLEX_KEY_CACHE(SIZE_IN_CELLS {prevalence_cache_cells}));

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
LAYOUT(COMPLEX_KEY_CACHE(SIZE_IN_CELLS {prevalence_cache_cells_ip}));
