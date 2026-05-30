-- Migration: repoint user_registry_dict (Identity enrichment — Entra / Google /
-- AD / Okta / Workday directory feed) from PostgreSQL to ClickHouse, and create
-- the CH-side payload table it now reads (NAN-1117).
--
-- WHY (exact NAN-1114 / 122 / 123 failure class): user_registry_dict was
-- PostgreSQL-sourced (init.sql) reading the PG `user_registry` table. The 24
-- nanosiem.logs user_identity_* / src_user_identity_* / dest_user_identity_*
-- MATERIALIZED columns (init.sql:640-663) call dictGetOrDefault on this dict on
-- EVERY insert. A dict that fails to LOAD makes dictGetOrDefault THROW (not
-- return the default) — so if the PG source disappears or auth fails, every
-- INSERT 500s and Vector (when_full=drop_newest) silently discards all logs: a
-- total, silent ingestion halt. We move the dict's payload + source to
-- ClickHouse so ingestion no longer depends on a cross-database PG read on the
-- hot path.
--
-- WHAT STAYS IN PG: this is the `user_registry` ENRICHMENT feed only — NOT the
-- `public.users` auth table (that stays PG). `identity_providers` (creds,
-- sync_status, delta_link, config) and the GDPR/audit metadata also stay PG.
-- Only the synced directory ROWS (the dict payload) move to ClickHouse.
--
-- INGESTION-HALT MITIGATION: the CH payload table is CREATEd (IF NOT EXISTS) in
-- this SAME migration BEFORE the CREATE OR REPLACE DICTIONARY, so even an
-- empty-but-LOADED dict returns defaults instead of THROWing. The dict must
-- never reference a not-yet-existing table.
--
-- Attributes / PRIMARY KEY username / LAYOUT(HASHED()) are BYTE-FOR-BYTE
-- identical to the prior PG-sourced dict (init.sql:453-482) so the 24 logs
-- user_identity_* columns keep resolving unchanged — do NOT rename attributes
-- or the key. groups stays a comma-joined String via arrayStringConcat(...,',')
-- reproducing the PG array_to_string(groups,','). account_enabled / mfa_enabled
-- stay UInt8. The key is the lowercased username (username_lc AS username) so
-- dictGetOrDefault(...,lower("user")) still hits.
--
-- REPLACINGMERGETREE DEDUP: the payload table is keyed (provider_id,
-- external_id); re-syncs append a new `version` (ms epoch) row and the latest
-- wins. Background merges are async, so the dict QUERY MUST argMax-by-version +
-- GROUP BY username_lc (not rely on FINAL) and apply the same filter the PG
-- dict used: username present + account_status != 'deleted' (via HAVING).
--
-- The runner substitutes {clickhouse_self_*} placeholders for numbered
-- migrations (NAN-707). init.sql is kept in sync separately; prior migrations
-- are left untouched (editing them trips ChecksumMismatch).
--
-- Idempotent: CREATE TABLE IF NOT EXISTS + CREATE OR REPLACE DICTIONARY.
--
-- NO BACKFILL: a migration can't pull PG rows into a CH table here. Directory
-- rows repopulate on the next provider sync (<= sync_interval_hours, default
-- 6h; AD via next push). Ingestion resumes the instant the empty-but-LOADED CH
-- dict returns defaults. Consider a manual 'Sync now' post-deploy to refill.
--
-- DROP ORDERING: the PG `user_registry` table is NOT dropped here. It is
-- dropped in a LATER PG migration once this repoint is live everywhere and a
-- sync has populated CH — dropping the PG table while any tenant could still
-- run the OLD PG-sourced dict against it is exactly the NAN-1114 incident.

-- 1. CH payload table for the identity directory feed (replaces PG
--    user_registry as the dict source). ReplacingMergeTree(version) keyed on
--    the natural sync identity (provider_id, external_id) so re-syncs collapse
--    to the latest version. account_status='deleted'/'anonymized' rows are KEPT
--    (soft state) and filtered out by the dict QUERY, exactly like the PG
--    `WHERE account_status != 'deleted'`. Lowercased lookup keys are
--    materialized so the dict QUERY + exact-match lookup never depend on a
--    runtime lower() over a scan.
CREATE TABLE IF NOT EXISTS nanosiem.user_registry
(
    provider_id        LowCardinality(String),
    external_id        String,
    username           String DEFAULT '',
    upn                String DEFAULT '',
    email              String DEFAULT '',
    display_name       String DEFAULT '',
    first_name         String DEFAULT '',
    last_name          String DEFAULT '',
    department         String DEFAULT '',
    title              String DEFAULT '',
    manager_upn        String DEFAULT '',
    manager_display_name String DEFAULT '',
    company            String DEFAULT '',
    office_location    String DEFAULT '',
    city               String DEFAULT '',
    country            String DEFAULT '',
    groups             Array(String) DEFAULT [],
    account_enabled    UInt8 DEFAULT 1,
    account_status     LowCardinality(String) DEFAULT 'active',
    mfa_enabled        UInt8 DEFAULT 0,
    last_sign_in_at    DateTime64(3) DEFAULT toDateTime64(0, 3),
    created_in_directory_at DateTime64(3) DEFAULT toDateTime64(0, 3),
    phone              String DEFAULT '',
    employee_id        String DEFAULT '',
    employee_type      LowCardinality(String) DEFAULT 'employee',
    sync_hash          String DEFAULT '',
    last_synced_at     DateTime64(3) DEFAULT now64(3),
    version            UInt64,
    username_lc        String MATERIALIZED lower(username),
    upn_lc             String MATERIALIZED lower(upn),
    email_lc           String MATERIALIZED lower(email)
)
ENGINE = ReplacingMergeTree(version)
ORDER BY (provider_id, external_id);

-- 2. Repoint user_registry_dict: PostgreSQL (fragile) -> ClickHouse, sourcing
--    the new CH payload table. argMax(..., version) GROUP BY username_lc +
--    HAVING account_status != 'deleted' collapses ReplacingMergeTree duplicates
--    at dict-load time without relying on background merges, drops deleted
--    users, and preserves the exact PG dict shape. groups is comma-joined to
--    keep user_identity_groups a String (matching PG array_to_string).
CREATE OR REPLACE DICTIONARY nanosiem.user_registry_dict
(
    username String,
    email String DEFAULT '',
    display_name String DEFAULT '',
    department String DEFAULT '',
    title String DEFAULT '',
    manager_upn String DEFAULT '',
    manager_display_name String DEFAULT '',
    company String DEFAULT '',
    groups String DEFAULT '',
    account_enabled UInt8 DEFAULT 1,
    account_status String DEFAULT '',
    mfa_enabled UInt8 DEFAULT 0,
    employee_type String DEFAULT '',
    country String DEFAULT '',
    office_location String DEFAULT ''
)
PRIMARY KEY username
SOURCE(CLICKHOUSE(
    HOST '{clickhouse_self_host}'
    PORT {clickhouse_self_port}
    USER '{clickhouse_self_user}'
    PASSWORD '{clickhouse_self_password}'
    DB 'nanosiem'
    QUERY 'SELECT
        username_lc AS username,
        argMax(email, version) AS email,
        argMax(display_name, version) AS display_name,
        argMax(department, version) AS department,
        argMax(title, version) AS title,
        argMax(manager_upn, version) AS manager_upn,
        argMax(manager_display_name, version) AS manager_display_name,
        argMax(company, version) AS company,
        argMax(arrayStringConcat(groups, '',''), version) AS groups,
        argMax(account_enabled, version) AS account_enabled,
        argMax(account_status, version) AS account_status,
        argMax(mfa_enabled, version) AS mfa_enabled,
        argMax(employee_type, version) AS employee_type,
        argMax(country, version) AS country,
        argMax(office_location, version) AS office_location
    FROM nanosiem.user_registry
    WHERE username_lc != ''''
    GROUP BY username_lc
    HAVING argMax(account_status, version) != ''deleted'''
))
LIFETIME(MIN 300 MAX 600)
LAYOUT(HASHED());
