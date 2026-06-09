-- Migration: lift the result-row/byte caps on the ip_enrichment_dict LOAD query
-- so importing a full-size IP enrichment dataset (IPinfo Lite, ~3.9M CIDR ranges)
-- cannot stall all log ingestion.
--
-- INCIDENT CLASS (extends 123 / NAN-1117): the logs `enriched_src_*` /
-- `enriched_dest_*` MATERIALIZED columns call dictGetOrDefault on
-- ip_enrichment_dict on EVERY insert. A dict that fails to LOAD makes
-- dictGetOrDefault THROW (not return the default), so every INSERT 500s and
-- Vector (when_full=drop_newest) silently discards all logs — a total, silent
-- ingestion halt. 123 fixed the "PG source disappears / auth fails" trigger by
-- moving the dict to ClickHouse. This migration fixes a SECOND trigger of the
-- same halt that 123 did not anticipate.
--
-- ROOT CAUSE: the dict's CLICKHOUSE source runs its QUERY as the nanosiem user,
-- which resolves to the `default` profile (query_limits.xml) with
-- max_result_rows=1,000,000 and max_result_bytes=1G under result_overflow_mode=throw.
-- Those caps are correct for interactive analyst queries but are ALSO enforced on
-- the dictionary's load query. While ip_enrichments held only the airgap seed
-- (~75k rows) the load stayed under 1M and the dict loaded fine "forever". The
-- first full IPinfo Lite import (~3.9M ranges) pushes the load result past 1M, so
-- the NEXT LIFETIME(MIN 300 MAX 600) reload throws Code 396 (TOO_MANY_ROWS_OR_BYTES)
-- and the dict goes FAILED — hours after the import, on an unrelated-looking reload.
--
-- FIX: attach SETTINGS(max_result_rows = 0, max_result_bytes = 0) to the dictionary
-- so the caps are lifted for the LOAD query ONLY. The `default` analyst profile is
-- left untouched (interactive queries keep their guardrails). ALTER ... MODIFY
-- SETTINGS is not supported on dictionaries, so this is a CREATE OR REPLACE.
--
-- Everything else (attributes, PRIMARY KEY, SOURCE QUERY, LIFETIME, LAYOUT(IP_TRIE()))
-- is byte-for-byte identical to 123 so the 14 logs enriched_* columns keep resolving
-- unchanged. The runner substitutes {clickhouse_self_*} placeholders (NAN-707);
-- init.sql is kept in sync separately. Prior migrations are left untouched
-- (editing them trips ChecksumMismatch).
--
-- Idempotent: CREATE OR REPLACE DICTIONARY.

CREATE OR REPLACE DICTIONARY nanosiem.ip_enrichment_dict
(
    network String,
    country String DEFAULT '',
    country_code String DEFAULT '',
    continent String DEFAULT '',
    continent_code String DEFAULT '',
    asn String DEFAULT '',
    as_name String DEFAULT '',
    as_domain String DEFAULT ''
)
PRIMARY KEY network
SOURCE(CLICKHOUSE(
    HOST '{clickhouse_self_host}'
    PORT {clickhouse_self_port}
    USER '{clickhouse_self_user}'
    PASSWORD '{clickhouse_self_password}'
    DB 'nanosiem'
    QUERY 'SELECT
        network,
        argMax(country, updated_at) AS country,
        argMax(country_code, updated_at) AS country_code,
        argMax(continent, updated_at) AS continent,
        argMax(continent_code, updated_at) AS continent_code,
        argMax(asn, updated_at) AS asn,
        argMax(as_name, updated_at) AS as_name,
        argMax(as_domain, updated_at) AS as_domain
    FROM nanosiem.ip_enrichments
    GROUP BY network
    HAVING argMax(deleted, updated_at) = 0'
))
LIFETIME(MIN 300 MAX 600)
LAYOUT(IP_TRIE())
SETTINGS(max_result_rows = 0, max_result_bytes = 0);
