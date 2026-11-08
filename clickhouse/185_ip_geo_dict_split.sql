-- Migration 185 (NAN-4957): split the IPinfo geo/ASN dictionary so it fits a
-- small box.
--
-- WHY: ip_enrichment_dict is an IP_TRIE holding all seven String attributes
-- for every network. With the platform feed bundle (NAN-4948) every install
-- now loads IPinfo Lite: 4,376,565 networks. Measured on CH 26.10.3.7 with the
-- real feed: 1.32 GiB resident (324 B per network), and a reload builds the new
-- trie next to the old one, so a reload needs another ~1.3-1.5 GiB on top. On a
-- 4G open-core box (server limit 3.20 GiB) the first load after the feed
-- install failed with MEMORY_LIMIT_EXCEEDED (241), the dictionary stayed LOADED
-- with 0 elements, and every event was stamped with empty geo/ASN without any
-- error. On 6G boxes the reload transient pushed concurrent searches and
-- inserts into 241.
--
-- The seven attributes only take 114,342 distinct combinations across those
-- 4.38M networks. So:
--   * ip_geo_trie_dict   IP_TRIE  network -> geo_id (UInt64)      201.7 MiB
--   * ip_geo_attrs_dict  HASHED   geo_id  -> the seven attributes   50.0 MiB
-- geo_id is cityHash64 of the seven attributes, computed by both source
-- queries from the same staging table, so no id table is needed. A lookup is
-- trie -> geo_id -> attribute. A miss in either dictionary returns '' exactly
-- as the old single lookup did, and both dictionaries keep the old keying
-- (toIPv4OrDefault / toIPv6OrDefault) and staging source (133), so enrichment
-- results are identical. Proved on the real feed (CH
-- 26.10.3.7): all seven attributes compared equal for 5,876,573 addresses (1M
-- random IPv4, the base address of each of the 4,376,565 networks, 500k random
-- IPv6, edge cases), 0 mismatches. Static guards:
-- nanosiem-core/tests/ip_geo_dict_split_guard.rs; upgrade/fresh on a real
-- ClickHouse: scripts/e2e/lanes/upgrade-185.sh.
-- A 64-bit hash collision between two of the ~114k combinations is ~4e-10.
--
-- WHAT CHANGES:
-- 1. The two new dictionaries, kept as ONE GENERATION (codex review): both
--    have LIFETIME(0), so ClickHouse never reloads one half on its own; nano
--    reloads them together, attrs first (nanosiem-core enrichment::ip_geo::
--    reload_pair, after every staging refresh it triggers, and on the
--    leader's 5-minute platform feed tick when the staging refreshed after the
--    trie loaded). Before each pair reload the APPEND view
--    ip_geo_attrs_history_refresh records the staging combinations in
--    ip_geo_attrs_history (30-day TTL), and the attrs dictionary loads staging
--    UNION history. So the attrs half always covers both the trie still
--    serving and the trie being loaded: a trie reload that fails after the
--    attrs reload leaves the old trie fully resolvable, never empty geo.
-- 2. The 14 UDM `logs` enriched_* MATERIALIZED columns get the two-step
--    lookup. Same type and codec, so this is a metadata-only ALTER: existing
--    parts keep their stored values, new inserts use the new expression.
-- 3. ocsf_logs_raw_mv gets the body that scripts/gen-ocsf-ddl.py now renders
--    (its _geo helper emits the two-step lookup). MODIFY QUERY with SELECT
--    directly, no AS (NAN-1727). OCSF overlays run AFTER numbered migrations,
--    so a fresh OCSF install skips this ALTER (no view yet) and the overlay
--    creates the view with the new body; an upgraded one is converted here and
--    the overlay's CREATE ... IF NOT EXISTS is a no-op. UDM-only installs have
--    no view and skip it too.
-- 4. ip_enrichment_dict_refresh (the refreshable view that fills the staging
--    table both dictionaries load) keeps migration 184's body but spills its
--    GROUP BY at 256 MiB instead of 1 GB (max_memory_usage 2.5 GB -> 1.5 GB)
--    and writes 262,144-row insert blocks instead of squashing ~1M-row ones.
--    It runs at every feed activation, every 6 h and at server start (next to
--    the boot-time insert backlog). Measured on the real feed (4.38M networks):
--    the refresh peaked at 898-996 MiB; the same INSERT ... SELECT takes
--    530 MiB with the old settings and 286 MiB with these, in ~4.5 s, writing
--    6 parts.
-- 5. nanosiem_ingest loses dictGet on ip_enrichment_dict (the OCSF view no
--    longer needs it, and a direct writer could otherwise lazy-load the old
--    trie). Users from users.d XML are read-only to SQL, so this REVOKE soft-
--    fails there and the XML drops the grant instead; it applies to
--    SQL-created users.
-- 6. ip_enrichment_dict is re-issued identical to migration 136 apart from
--    the `nano:fatal` marker, which (like the two new dictionaries) makes a
--    failure abort the migration instead of being skipped and recorded.
--    CREATE OR REPLACE swaps in a NOT_LOADED instance (dictionaries load
--    lazily), which frees the 1.32 GiB trie now instead of at the next
--    restart. The dictionary stays defined for compatibility (raw SQL, and the
--    column snapshot of a cluster's logs_distributed wrapper, which is never
--    evaluated), but nothing in nano reads or reloads it any more, so it never
--    loads again unless someone calls dictGet on it.
--
-- init.sql is NOT edited (the migrator runs it before the numbered
-- migrations): fresh installs create the old column expressions and this
-- migration converts them, the same path as an upgrade.
--
-- The attrs source aggregates (GROUP BY over the staging table), so it
-- carries the memory-bound settings (NAN-1404 guard). The trie source is a
-- plain scan. Both lift the profile's 1M max_result_rows (NAN-1310).
-- The runner substitutes the {clickhouse_self_*} placeholders (NAN-707).
--
-- Idempotent: CREATE OR REPLACE DICTIONARY swaps atomically; MODIFY COLUMN and
-- both MODIFY QUERY statements re-set the same definitions.

CREATE TABLE IF NOT EXISTS nanosiem.ip_geo_attrs_history
(
    geo_id UInt64,
    country String,
    country_code String,
    continent String,
    continent_code String,
    asn String,
    as_name String,
    as_domain String,
    seen_at DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(seen_at) /* nano:keep-local-engine */
ORDER BY geo_id
TTL seen_at + INTERVAL 30 DAY;

CREATE MATERIALIZED VIEW IF NOT EXISTS nanosiem.ip_geo_attrs_history_refresh
REFRESH EVERY 6 HOUR APPEND TO nanosiem.ip_geo_attrs_history AS
SELECT cityHash64(country, country_code, continent, continent_code, asn, as_name, as_domain) AS geo_id, country, country_code, continent, continent_code, asn, as_name, as_domain, now() AS seen_at FROM nanosiem.ip_enrichment_dict_staging GROUP BY geo_id, country, country_code, continent, continent_code, asn, as_name, as_domain SETTINGS max_bytes_before_external_group_by = 268435456, max_memory_usage = 1000000000, max_threads = 2;

CREATE OR REPLACE DICTIONARY nanosiem.ip_geo_attrs_dict /* nano:fatal */
(
    geo_id UInt64,
    country String DEFAULT '',
    country_code String DEFAULT '',
    continent String DEFAULT '',
    continent_code String DEFAULT '',
    asn String DEFAULT '',
    as_name String DEFAULT '',
    as_domain String DEFAULT ''
)
PRIMARY KEY geo_id
SOURCE(CLICKHOUSE(
    HOST '{clickhouse_self_host}'
    PORT {clickhouse_self_port}
    USER '{clickhouse_self_user}'
    PASSWORD '{clickhouse_self_password}'
    DB 'nanosiem'
    QUERY 'SELECT geo_id, any(country) AS country, any(country_code) AS country_code, any(continent) AS continent, any(continent_code) AS continent_code, any(asn) AS asn, any(as_name) AS as_name, any(as_domain) AS as_domain FROM (SELECT cityHash64(country, country_code, continent, continent_code, asn, as_name, as_domain) AS geo_id, country, country_code, continent, continent_code, asn, as_name, as_domain FROM nanosiem.ip_enrichment_dict_staging UNION ALL SELECT geo_id, country, country_code, continent, continent_code, asn, as_name, as_domain FROM nanosiem.ip_geo_attrs_history) GROUP BY geo_id SETTINGS max_bytes_before_external_group_by = 268435456, max_memory_usage = 1000000000, max_threads = 2'
))
LIFETIME(0)
LAYOUT(HASHED())
SETTINGS(max_result_rows = 0, max_result_bytes = 0);

CREATE OR REPLACE DICTIONARY nanosiem.ip_geo_trie_dict /* nano:fatal */
(
    network String,
    geo_id UInt64 DEFAULT 0
)
PRIMARY KEY network
SOURCE(CLICKHOUSE(
    HOST '{clickhouse_self_host}'
    PORT {clickhouse_self_port}
    USER '{clickhouse_self_user}'
    PASSWORD '{clickhouse_self_password}'
    DB 'nanosiem'
    QUERY 'SELECT network, cityHash64(country, country_code, continent, continent_code, asn, as_name, as_domain) AS geo_id FROM nanosiem.ip_enrichment_dict_staging'
))
LIFETIME(0)
LAYOUT(IP_TRIE())
SETTINGS(max_result_rows = 0, max_result_bytes = 0);

ALTER TABLE nanosiem.logs
    MODIFY COLUMN `enriched_src_country` LowCardinality(String) MATERIALIZED if(src_ip != '', dictGetOrDefault('nanosiem.ip_geo_attrs_dict', 'country', if(isIPv4String(src_ip), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv4OrDefault(src_ip), toUInt64(0)), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv6OrDefault(src_ip), toUInt64(0))), ''), '') CODEC(ZSTD(1)),
    MODIFY COLUMN `enriched_src_country_code` LowCardinality(String) MATERIALIZED if(src_ip != '', dictGetOrDefault('nanosiem.ip_geo_attrs_dict', 'country_code', if(isIPv4String(src_ip), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv4OrDefault(src_ip), toUInt64(0)), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv6OrDefault(src_ip), toUInt64(0))), ''), '') CODEC(ZSTD(1)),
    MODIFY COLUMN `enriched_src_continent` LowCardinality(String) MATERIALIZED if(src_ip != '', dictGetOrDefault('nanosiem.ip_geo_attrs_dict', 'continent', if(isIPv4String(src_ip), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv4OrDefault(src_ip), toUInt64(0)), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv6OrDefault(src_ip), toUInt64(0))), ''), '') CODEC(ZSTD(1)),
    MODIFY COLUMN `enriched_src_asn` String MATERIALIZED if(src_ip != '', dictGetOrDefault('nanosiem.ip_geo_attrs_dict', 'asn', if(isIPv4String(src_ip), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv4OrDefault(src_ip), toUInt64(0)), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv6OrDefault(src_ip), toUInt64(0))), ''), '') CODEC(ZSTD(1)),
    MODIFY COLUMN `enriched_src_as_name` String MATERIALIZED if(src_ip != '', dictGetOrDefault('nanosiem.ip_geo_attrs_dict', 'as_name', if(isIPv4String(src_ip), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv4OrDefault(src_ip), toUInt64(0)), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv6OrDefault(src_ip), toUInt64(0))), ''), '') CODEC(ZSTD(1)),
    MODIFY COLUMN `enriched_dest_country` LowCardinality(String) MATERIALIZED if(dest_ip != '', dictGetOrDefault('nanosiem.ip_geo_attrs_dict', 'country', if(isIPv4String(dest_ip), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv4OrDefault(dest_ip), toUInt64(0)), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv6OrDefault(dest_ip), toUInt64(0))), ''), '') CODEC(ZSTD(1)),
    MODIFY COLUMN `enriched_dest_country_code` LowCardinality(String) MATERIALIZED if(dest_ip != '', dictGetOrDefault('nanosiem.ip_geo_attrs_dict', 'country_code', if(isIPv4String(dest_ip), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv4OrDefault(dest_ip), toUInt64(0)), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv6OrDefault(dest_ip), toUInt64(0))), ''), '') CODEC(ZSTD(1)),
    MODIFY COLUMN `enriched_dest_continent` LowCardinality(String) MATERIALIZED if(dest_ip != '', dictGetOrDefault('nanosiem.ip_geo_attrs_dict', 'continent', if(isIPv4String(dest_ip), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv4OrDefault(dest_ip), toUInt64(0)), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv6OrDefault(dest_ip), toUInt64(0))), ''), '') CODEC(ZSTD(1)),
    MODIFY COLUMN `enriched_dest_asn` String MATERIALIZED if(dest_ip != '', dictGetOrDefault('nanosiem.ip_geo_attrs_dict', 'asn', if(isIPv4String(dest_ip), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv4OrDefault(dest_ip), toUInt64(0)), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv6OrDefault(dest_ip), toUInt64(0))), ''), '') CODEC(ZSTD(1)),
    MODIFY COLUMN `enriched_dest_as_name` String MATERIALIZED if(dest_ip != '', dictGetOrDefault('nanosiem.ip_geo_attrs_dict', 'as_name', if(isIPv4String(dest_ip), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv4OrDefault(dest_ip), toUInt64(0)), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv6OrDefault(dest_ip), toUInt64(0))), ''), '') CODEC(ZSTD(1)),
    MODIFY COLUMN `enriched_src_as_domain` String MATERIALIZED if(src_ip != '', dictGetOrDefault('nanosiem.ip_geo_attrs_dict', 'as_domain', if(isIPv4String(src_ip), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv4OrDefault(src_ip), toUInt64(0)), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv6OrDefault(src_ip), toUInt64(0))), ''), '') CODEC(ZSTD(1)),
    MODIFY COLUMN `enriched_src_continent_code` LowCardinality(String) MATERIALIZED if(src_ip != '', dictGetOrDefault('nanosiem.ip_geo_attrs_dict', 'continent_code', if(isIPv4String(src_ip), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv4OrDefault(src_ip), toUInt64(0)), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv6OrDefault(src_ip), toUInt64(0))), ''), '') CODEC(ZSTD(1)),
    MODIFY COLUMN `enriched_dest_as_domain` String MATERIALIZED if(dest_ip != '', dictGetOrDefault('nanosiem.ip_geo_attrs_dict', 'as_domain', if(isIPv4String(dest_ip), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv4OrDefault(dest_ip), toUInt64(0)), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv6OrDefault(dest_ip), toUInt64(0))), ''), '') CODEC(ZSTD(1)),
    MODIFY COLUMN `enriched_dest_continent_code` LowCardinality(String) MATERIALIZED if(dest_ip != '', dictGetOrDefault('nanosiem.ip_geo_attrs_dict', 'continent_code', if(isIPv4String(dest_ip), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv4OrDefault(dest_ip), toUInt64(0)), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv6OrDefault(dest_ip), toUInt64(0))), ''), '') CODEC(ZSTD(1));

ALTER TABLE nanosiem.ocsf_logs_raw_mv /* nano:skip-if-unknown-table */
MODIFY QUERY SELECT
    timestamp,
    if(source_type IN ('', 'unknown'), lower(ifNull(toString(event.metadata.log_source), 'unknown')), lower(source_type)) AS source_type,
    id,
    ifNull(accurateCastOrNull(event.`class_uid`, 'UInt32'), 0) AS `class_uid`,
    ifNull(accurateCastOrNull(event.`category_uid`, 'UInt16'), 0) AS `category_uid`,
    ifNull(accurateCastOrNull(event.`activity_id`, 'Int32'), 0) AS `activity_id`,
    ifNull(accurateCastOrNull(event.`type_uid`, 'Int64'), 0) AS `type_uid`,
    ifNull(accurateCastOrNull(event.`severity_id`, 'Int32'), 0) AS `severity_id`,
    ifNull(accurateCastOrNull(event.`status_id`, 'Int32'), 0) AS `status_id`,
    ifNull(accurateCastOrNull(event.`disposition_id`, 'Int32'), 0) AS `disposition_id`,
    ifNull(accurateCastOrNull(event.`action_id`, 'Int32'), 0) AS `action_id`,
    ifNull(accurateCastOrNull(event.`auth_protocol_id`, 'Int32'), 0) AS `auth_protocol_id`,
    ifNull(toString(event.`class_name`), '') AS `class_name`,
    ifNull(toString(event.`category_name`), '') AS `category_name`,
    ifNull(toString(event.`activity_name`), '') AS `activity_name`,
    ifNull(toString(event.`severity`), '') AS `severity`,
    ifNull(toString(event.`status`), '') AS `status`,
    ifNull(toString(event.`metadata`.`version`), '') AS `metadata.version`,
    ifNull(toString(event.`metadata`.`uid`), '') AS `metadata.uid`,
    ifNull(toString(event.`metadata`.`event_code`), '') AS `metadata.event_code`,
    ifNull(toString(event.`metadata`.`product`.`name`), '') AS `metadata.product.name`,
    ifNull(toString(event.`metadata`.`product`.`vendor_name`), '') AS `metadata.product.vendor_name`,
    ifNull(toString(event.`metadata`.`log_name`), '') AS `metadata.log_name`,
    ifNull(toString(event.`metadata`.`log_provider`), '') AS `metadata.log_provider`,
    ifNull(toString(event.`metadata`.`correlation_uid`), '') AS `metadata.correlation_uid`,
    ifNull(toString(event.`message`), '') AS `message`,
    ifNull(toString(event.`raw_data`), '') AS `raw_data`,
    ifNull(toString(event.`actor`.`user`.`name`), '') AS `actor.user.name`,
    ifNull(toString(event.`actor`.`user`.`uid`), '') AS `actor.user.uid`,
    ifNull(toString(event.`actor`.`user`.`domain`), '') AS `actor.user.domain`,
    ifNull(toString(event.`actor`.`user`.`email_addr`), '') AS `actor.user.email_addr`,
    ifNull(toString(event.`user`.`name`), '') AS `user.name`,
    ifNull(toString(event.`user`.`uid`), '') AS `user.uid`,
    lower(ifNull(toString(event.`user`.`domain`), '')) AS `user.domain`,
    ifNull(toString(event.`user`.`email_addr`), '') AS `user.email_addr`,
    lower(ifNull(toString(event.`device`.`hostname`), '')) AS `device.hostname`,
    lower(ifNull(toString(event.`device`.`ip`), '')) AS `device.ip`,
    ifNull(toString(event.`device`.`uid`), '') AS `device.uid`,
    lower(ifNull(toString(event.`src_endpoint`.`ip`), '')) AS `src_endpoint.ip`,
    lower(ifNull(toString(event.`src_endpoint`.`hostname`), '')) AS `src_endpoint.hostname`,
    ifNull(accurateCastOrNull(event.`src_endpoint`.`port`, 'Int32'), 0) AS `src_endpoint.port`,
    lower(ifNull(toString(event.`src_endpoint`.`mac`), '')) AS `src_endpoint.mac`,
    if((ifNull(toString(event.`src_endpoint`.`location`.`country`), '')) AS `_native.src_endpoint.location.country` != '', `_native.src_endpoint.location.country`, if(`src_endpoint.ip` != '', dictGetOrDefault('nanosiem.ip_geo_attrs_dict', 'country_code', if(isIPv4String(`src_endpoint.ip`), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv4OrDefault(`src_endpoint.ip`), toUInt64(0)), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv6OrDefault(`src_endpoint.ip`), toUInt64(0))), ''), '')) AS `src_endpoint.location.country`,
    if((ifNull(accurateCastOrNull(event.`src_endpoint`.`autonomous_system`.`number`, 'Int64'), 0)) AS `_native.src_endpoint.autonomous_system.number` != 0, `_native.src_endpoint.autonomous_system.number`, toInt64OrZero(replaceRegexpAll(if(`src_endpoint.ip` != '', dictGetOrDefault('nanosiem.ip_geo_attrs_dict', 'asn', if(isIPv4String(`src_endpoint.ip`), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv4OrDefault(`src_endpoint.ip`), toUInt64(0)), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv6OrDefault(`src_endpoint.ip`), toUInt64(0))), ''), ''), '[^0-9]', ''))) AS `src_endpoint.autonomous_system.number`,
    lower(ifNull(toString(event.`dst_endpoint`.`ip`), '')) AS `dst_endpoint.ip`,
    lower(ifNull(toString(event.`dst_endpoint`.`hostname`), '')) AS `dst_endpoint.hostname`,
    ifNull(accurateCastOrNull(event.`dst_endpoint`.`port`, 'Int32'), 0) AS `dst_endpoint.port`,
    lower(ifNull(toString(event.`dst_endpoint`.`mac`), '')) AS `dst_endpoint.mac`,
    if((ifNull(toString(event.`dst_endpoint`.`location`.`country`), '')) AS `_native.dst_endpoint.location.country` != '', `_native.dst_endpoint.location.country`, if(`dst_endpoint.ip` != '', dictGetOrDefault('nanosiem.ip_geo_attrs_dict', 'country_code', if(isIPv4String(`dst_endpoint.ip`), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv4OrDefault(`dst_endpoint.ip`), toUInt64(0)), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv6OrDefault(`dst_endpoint.ip`), toUInt64(0))), ''), '')) AS `dst_endpoint.location.country`,
    if((ifNull(accurateCastOrNull(event.`dst_endpoint`.`autonomous_system`.`number`, 'Int64'), 0)) AS `_native.dst_endpoint.autonomous_system.number` != 0, `_native.dst_endpoint.autonomous_system.number`, toInt64OrZero(replaceRegexpAll(if(`dst_endpoint.ip` != '', dictGetOrDefault('nanosiem.ip_geo_attrs_dict', 'asn', if(isIPv4String(`dst_endpoint.ip`), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv4OrDefault(`dst_endpoint.ip`), toUInt64(0)), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv6OrDefault(`dst_endpoint.ip`), toUInt64(0))), ''), ''), '[^0-9]', ''))) AS `dst_endpoint.autonomous_system.number`,
    ifNull(accurateCastOrNull(event.`connection_info`.`protocol_num`, 'Int32'), 0) AS `connection_info.protocol_num`,
    ifNull(accurateCastOrNull(event.`traffic`.`bytes_in`, 'UInt64'), 0) AS `traffic.bytes_in`,
    ifNull(accurateCastOrNull(event.`traffic`.`bytes_out`, 'UInt64'), 0) AS `traffic.bytes_out`,
    ifNull(accurateCastOrNull(event.`traffic`.`packets_in`, 'UInt64'), 0) AS `traffic.packets_in`,
    ifNull(accurateCastOrNull(event.`traffic`.`packets_out`, 'UInt64'), 0) AS `traffic.packets_out`,
    ifNull(toString(event.`process`.`name`), '') AS `process.name`,
    ifNull(toString(event.`process`.`cmd_line`), '') AS `process.cmd_line`,
    ifNull(accurateCastOrNull(event.`process`.`pid`, 'Int64'), 0) AS `process.pid`,
    ifNull(toString(event.`process`.`uid`), '') AS `process.uid`,
    ifNull(toString(event.`process`.`file`.`path`), '') AS `process.file.path`,
    arrayMap(x -> lower(x), arrayMap(x -> ifNull(toString(x), ''), event.`process`.`file`.`hashes`[].`value`)) AS `process.file.hashes.value`,
    ifNull(toString(event.`process`.`parent_process`.`name`), '') AS `process.parent_process.name`,
    ifNull(toString(event.`process`.`parent_process`.`cmd_line`), '') AS `process.parent_process.cmd_line`,
    ifNull(toString(event.`actor`.`process`.`name`), '') AS `actor.process.name`,
    ifNull(toString(event.`actor`.`process`.`cmd_line`), '') AS `actor.process.cmd_line`,
    ifNull(accurateCastOrNull(event.`actor`.`process`.`pid`, 'Int64'), 0) AS `actor.process.pid`,
    ifNull(toString(event.`actor`.`process`.`uid`), '') AS `actor.process.uid`,
    ifNull(toString(event.`actor`.`process`.`file`.`path`), '') AS `actor.process.file.path`,
    arrayMap(x -> lower(x), arrayMap(x -> ifNull(toString(x), ''), event.`actor`.`process`.`file`.`hashes`[].`value`)) AS `actor.process.file.hashes.value`,
    ifNull(toString(event.`file`.`path`), '') AS `file.path`,
    ifNull(toString(event.`file`.`name`), '') AS `file.name`,
    arrayMap(x -> lower(x), arrayMap(x -> ifNull(toString(x), ''), event.`file`.`hashes`[].`value`)) AS `file.hashes.value`,
    ifNull(toString(event.`reg_key`.`path`), '') AS `reg_key.path`,
    ifNull(toString(event.`reg_value`.`path`), '') AS `reg_value.path`,
    ifNull(toString(event.`http_request`.`url`.`url_string`), '') AS `http_request.url.url_string`,
    ifNull(toString(event.`http_request`.`url`.`hostname`), '') AS `http_request.url.hostname`,
    ifNull(toString(event.`http_request`.`url`.`path`), '') AS `http_request.url.path`,
    ifNull(toString(event.`http_request`.`http_method`), '') AS `http_request.http_method`,
    ifNull(toString(event.`http_request`.`user_agent`), '') AS `http_request.user_agent`,
    ifNull(accurateCastOrNull(event.`http_response`.`code`, 'Int32'), 0) AS `http_response.code`,
    ifNull(toString(event.`url`.`url_string`), '') AS `url.url_string`,
    ifNull(toString(event.`url`.`hostname`), '') AS `url.hostname`,
    ifNull(toString(event.`query`.`hostname`), '') AS `query.hostname`,
    arrayMap(x -> ifNull(toString(x), ''), event.`answers`[].`rdata`) AS `answers.rdata`,
    ifNull(toString(event.`api`.`operation`), '') AS `api.operation`,
    ifNull(toString(event.`api`.`service`.`name`), '') AS `api.service.name`,
    ifNull(toString(event.`cloud`.`provider`), '') AS `cloud.provider`,
    ifNull(toString(event.`cloud`.`region`), '') AS `cloud.region`,
    ifNull(toString(event.`cloud`.`account`.`uid`), '') AS `cloud.account.uid`,
    ifNull(toString(event.`session`.`uid`), '') AS `session.uid`,
    lower(ifNull(toString(event.`email`.`from`), '')) AS `email.from`,
    ifNull(toString(event.`email`.`subject`), '') AS `email.subject`,
    arrayMap(x -> lower(x), arrayMap(x -> ifNull(toString(x), ''), if(dynamicType(event.`email`.`to`) LIKE 'Array(%', CAST(event.`email`.`to`, 'Array(Nullable(String))'), if(isNull(event.`email`.`to`), [], [toString(event.`email`.`to`)])))) AS `email.to`,
    ifNull(toString(event.`finding_info`.`uid`), '') AS `finding_info.uid`,
    ifNull(toString(event.`finding_info`.`title`), '') AS `finding_info.title`,
    arrayMap(x -> ifNull(toString(x), ''), event.`observables`[].`value`) AS `observables.value`,
    arrayMap(x -> toUInt16OrZero(x), arrayMap(x -> ifNull(toString(x), ''), event.`observables`[].`type_id`)) AS `observables.type_id`,
    arrayMap(x -> ifNull(toString(x), ''), event.`enrichments`[].`value`) AS `enrichments.value`,
    arrayMap(x -> ifNull(toString(x), ''), event.`enrichments`[].`name`) AS `enrichments.name`,
    arrayMap(x -> ifNull(toString(x), ''), event.`resources`[].`uid`) AS `resources.uid`,
    arrayMap(x -> ifNull(toString(x), ''), event.`vulnerabilities`[].`cve`.`uid`) AS `vulnerabilities.cve.uid`,
    ifNull(toString(event.`actor`.`user`.`type`), '') AS `actor.user.type`,
    ifNull(toString(event.`auth_protocol`), '') AS `auth_protocol`,
    ifNull(accurateCastOrNull(event.`is_mfa`, 'Bool'), false) AS `is_mfa`,
    ifNull(accurateCastOrNull(event.`logon_type_id`, 'Int32'), 0) AS `logon_type_id`,
    ifNull(toString(event.`cloud`.`account`.`name`), '') AS `cloud.account.name`,
    if((ifNull(toString(event.`src_endpoint`.`autonomous_system`.`name`), '')) AS `_native.src_endpoint.autonomous_system.name` != '', `_native.src_endpoint.autonomous_system.name`, if(`src_endpoint.ip` != '', dictGetOrDefault('nanosiem.ip_geo_attrs_dict', 'as_name', if(isIPv4String(`src_endpoint.ip`), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv4OrDefault(`src_endpoint.ip`), toUInt64(0)), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv6OrDefault(`src_endpoint.ip`), toUInt64(0))), ''), '')) AS `src_endpoint.autonomous_system.name`,
    if((ifNull(toString(event.`src_endpoint`.`location`.`continent`), '')) AS `_native.src_endpoint.location.continent` != '', `_native.src_endpoint.location.continent`, if(`src_endpoint.ip` != '', dictGetOrDefault('nanosiem.ip_geo_attrs_dict', 'continent', if(isIPv4String(`src_endpoint.ip`), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv4OrDefault(`src_endpoint.ip`), toUInt64(0)), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv6OrDefault(`src_endpoint.ip`), toUInt64(0))), ''), '')) AS `src_endpoint.location.continent`,
    if((ifNull(toString(event.`dst_endpoint`.`autonomous_system`.`name`), '')) AS `_native.dst_endpoint.autonomous_system.name` != '', `_native.dst_endpoint.autonomous_system.name`, if(`dst_endpoint.ip` != '', dictGetOrDefault('nanosiem.ip_geo_attrs_dict', 'as_name', if(isIPv4String(`dst_endpoint.ip`), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv4OrDefault(`dst_endpoint.ip`), toUInt64(0)), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv6OrDefault(`dst_endpoint.ip`), toUInt64(0))), ''), '')) AS `dst_endpoint.autonomous_system.name`,
    if((ifNull(toString(event.`dst_endpoint`.`location`.`continent`), '')) AS `_native.dst_endpoint.location.continent` != '', `_native.dst_endpoint.location.continent`, if(`dst_endpoint.ip` != '', dictGetOrDefault('nanosiem.ip_geo_attrs_dict', 'continent', if(isIPv4String(`dst_endpoint.ip`), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv4OrDefault(`dst_endpoint.ip`), toUInt64(0)), dictGetOrDefault('nanosiem.ip_geo_trie_dict', 'geo_id', toIPv6OrDefault(`dst_endpoint.ip`), toUInt64(0))), ''), '')) AS `dst_endpoint.location.continent`,
    ifNull(accurateCastOrNull(event.`duration`, 'Int64'), 0) AS `duration`,
    ifNull(toString(event.`email`.`message_uid`), '') AS `email.message_uid`,
    ifNull(toString(event.`http_request`.`referrer`), '') AS `http_request.referrer`,
    lower(ifNull(toString(event.`trace`.`uid`), '')) AS `trace.uid`,
    lower(ifNull(toString(event.`trace`.`span`.`uid`), '')) AS `trace.span.uid`,
    arrayMap(x -> ifNull(toString(x), ''), if(dynamicType(event.`http_request`.`url`.`categories`) LIKE 'Array(%', CAST(event.`http_request`.`url`.`categories`, 'Array(Nullable(String))'), if(isNull(event.`http_request`.`url`.`categories`), [], [toString(event.`http_request`.`url`.`categories`)]))) AS `http_request.url.categories`,
    ifNull(toString(event.`metadata`.`product`.`feature`.`name`), '') AS `metadata.product.feature.name`,
    ifNull(toString(event.`module`.`file`.`name`), '') AS `module.file.name`,
    ifNull(toString(event.`module`.`file`.`path`), '') AS `module.file.path`,
    ifNull(toString(event.`reg_value`.`name`), '') AS `reg_value.name`,
    ifNull(toString(event.`reg_value`.`data`), '') AS `reg_value.data`,
    arrayMap(x -> ifNull(toString(x), ''), event.`resources`[].`name`) AS `resources.name`,
    arrayMap(x -> ifNull(toString(x), ''), event.`resources`[].`type`) AS `resources.type`,
    lower(ifNull(toString(arrayFirst(h -> ifNull(accurateCastOrNull(h.algorithm_id, 'Int64'), 0) = 3, event.`process`.`file`.`hashes`[]).value), '')) AS `process.file.hashes.sha256`,
    lower(ifNull(toString(arrayFirst(h -> ifNull(accurateCastOrNull(h.algorithm_id, 'Int64'), 0) = 3, event.`actor`.`process`.`file`.`hashes`[]).value), '')) AS `actor.process.file.hashes.sha256`,
    lower(ifNull(toString(arrayFirst(h -> ifNull(accurateCastOrNull(h.algorithm_id, 'Int64'), 0) = 3, event.`file`.`hashes`[]).value), '')) AS `file.hashes.sha256`,
    if(arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'ioc_src_ip_threat_type')) != '', arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'ioc_src_ip_threat_type')), if(`src_endpoint.ip` != '', dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'threat_type', `src_endpoint.ip`, ''), '')) AS `enrichments.ioc_src_ip_threat_type`,
    if(arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'ioc_dest_ip_threat_type')) != '', arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'ioc_dest_ip_threat_type')), if(`dst_endpoint.ip` != '', dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'threat_type', `dst_endpoint.ip`, ''), '')) AS `enrichments.ioc_dest_ip_threat_type`,
    if(arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'ioc_domain_threat_type')) != '', arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'ioc_domain_threat_type')), multiIf(`url.hostname` != '' AND dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'threat_type', lower(`url.hostname`), '') != '', dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'threat_type', lower(`url.hostname`), ''), `http_request.url.hostname` != '' AND dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'threat_type', lower(`http_request.url.hostname`), '') != '', dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'threat_type', lower(`http_request.url.hostname`), ''), `query.hostname` != '' AND dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'threat_type', lower(`query.hostname`), '') != '', dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'threat_type', lower(`query.hostname`), ''), '')) AS `enrichments.ioc_domain_threat_type`,
    if(arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'ioc_hash_threat_type')) != '', arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'ioc_hash_threat_type')), multiIf(`file.hashes.sha256` != '' AND dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'threat_type', lower(`file.hashes.sha256`), '') != '', dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'threat_type', lower(`file.hashes.sha256`), ''), `process.file.hashes.sha256` != '' AND dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'threat_type', lower(`process.file.hashes.sha256`), '') != '', dictGetOrDefault('nanosiem.ioc_enrichment_dict', 'threat_type', lower(`process.file.hashes.sha256`), ''), '')) AS `enrichments.ioc_hash_threat_type`,
    if(arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'custom_src_ip_tags')) != '', arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'custom_src_ip_tags')), if(`src_endpoint.ip` != '', arrayStringConcat(dictGetOrDefault('nanosiem.custom_enrichment_dict', 'tags', tuple('ip', `src_endpoint.ip`), []), ', '), '')) AS `enrichments.custom_src_ip_tags`,
    if(arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'custom_dest_ip_tags')) != '', arrayElement(`enrichments.value`, indexOf(`enrichments.name`, 'custom_dest_ip_tags')), if(`dst_endpoint.ip` != '', arrayStringConcat(dictGetOrDefault('nanosiem.custom_enrichment_dict', 'tags', tuple('ip', `dst_endpoint.ip`), []), ', '), '')) AS `enrichments.custom_dest_ip_tags`,
    toUInt32(length(toJSONString(event))) AS `event_bytes`,
    event,
    event.^unmapped AS `unmapped`
FROM nanosiem.ocsf_logs_raw;

ALTER TABLE nanosiem.ip_enrichment_dict_refresh
MODIFY QUERY SELECT network, argMax(country, updated_at) AS country, argMax(country_code, updated_at) AS country_code, argMax(continent, updated_at) AS continent, argMax(continent_code, updated_at) AS continent_code, argMax(asn, updated_at) AS asn, argMax(as_name, updated_at) AS as_name, argMax(as_domain, updated_at) AS as_domain
FROM nanosiem.ip_enrichments
WHERE platform_feed = 0 OR source_id GLOBAL IN (SELECT argMax(storage_key, (sequence, committed_at)) FROM nanosiem.platform_feed_commits GROUP BY feed_id)
GROUP BY network
HAVING argMax(deleted, updated_at) = 0
SETTINGS max_bytes_before_external_group_by = 268435456, max_memory_usage = 1500000000, max_threads = 2, min_insert_block_size_rows = 262144, min_insert_block_size_bytes = 67108864, max_insert_block_size = 262144;

REVOKE dictGet ON nanosiem.ip_enrichment_dict FROM nanosiem_ingest;

CREATE OR REPLACE DICTIONARY nanosiem.ip_enrichment_dict /* nano:fatal */
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
    QUERY 'SELECT network, country, country_code, continent, continent_code, asn, as_name, as_domain FROM nanosiem.ip_enrichment_dict_staging'
))
LIFETIME(MIN 21600 MAX 43200)
LAYOUT(IP_TRIE())
SETTINGS(max_result_rows = 0, max_result_bytes = 0);
