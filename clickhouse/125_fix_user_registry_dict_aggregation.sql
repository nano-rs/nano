-- Migration: fix user_registry_dict ClickHouse source query (NAN-1120).
--
-- NAN-1117 migration 124 repointed user_registry_dict to ClickHouse but its
-- source query used `... GROUP BY username_lc HAVING argMax(account_status,
-- version) != 'deleted'`. ClickHouse re-resolves the `account_status` inside
-- the HAVING's argMax to the SELECT alias (itself `argMax(account_status,
-- version)`), producing a nested aggregate:
--   Code: 184 DB::Exception: Aggregate function argMax(account_status, version)
--   is found inside another aggregate function (ILLEGAL_AGGREGATION)
-- so the dict goes status=FAILED. `cargo check` + the migrate tests + offline
-- review don't catch it because none of them LOAD a dict against a real CH;
-- it surfaced on a live `SYSTEM RELOAD DICTIONARY`. A FAILED dict referenced by
-- the 24 nanosiem.logs user_identity_* MATERIALIZED columns makes
-- dictGetOrDefault THROW on every INSERT -> silent total ingestion halt (the
-- NAN-1114 failure class).
--
-- Fix: drop the HAVING-on-aggregate and filter the deduped result in an outer
-- WHERE (the subquery-wrap the IOC / custom dicts already use), which removes
-- the alias shadowing. Attributes / PRIMARY KEY username / LAYOUT(HASHED())
-- are unchanged from 124 (a String key is stored as COMPLEX_KEY_HASHED at
-- runtime, same as the original PG dict — single-key dictGet is unaffected).
--
-- Migration 124 is left untouched on disk (its checksum is recorded in
-- tenants' _migrations; editing it would trip ChecksumMismatch). init.sql is
-- kept in sync separately. CREATE OR REPLACE swaps atomically; the runner
-- substitutes {clickhouse_self_*}.

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
    QUERY 'SELECT * FROM (SELECT username_lc AS username, argMax(email, version) AS email, argMax(display_name, version) AS display_name, argMax(department, version) AS department, argMax(title, version) AS title, argMax(manager_upn, version) AS manager_upn, argMax(manager_display_name, version) AS manager_display_name, argMax(company, version) AS company, argMax(arrayStringConcat(groups, '',''), version) AS groups, argMax(account_enabled, version) AS account_enabled, argMax(account_status, version) AS account_status, argMax(mfa_enabled, version) AS mfa_enabled, argMax(employee_type, version) AS employee_type, argMax(country, version) AS country, argMax(office_location, version) AS office_location FROM nanosiem.user_registry WHERE username_lc != '''' GROUP BY username_lc) WHERE account_status != ''deleted'''
))
LIFETIME(MIN 300 MAX 600)
LAYOUT(HASHED());
