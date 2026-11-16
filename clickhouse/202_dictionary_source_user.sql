-- NAN-5470: every ClickHouse-sourced dictionary reads its source as the
-- dedicated dictionary identity `nanosiem_dict` (clickhouse/users.d/
-- nanosiem-users.xml: SELECT on exactly these nine source tables, profile
-- `dict_source`, uncapped `nano_service` quota) instead of the shared app
-- user `nanosiem`. The three prevalence CACHE dictionaries query their source
-- on every insert-time cache miss, so this also takes that traffic off the
-- app user's budget and out of its system.query_log rows.
--
-- Each body is the current definition byte for byte (hash/domain/ip
-- prevalence: 172; ip_geo_attrs / ip_geo_trie / ip_enrichment: 185; ioc and
-- custom_ioc: 188; custom_enrichment and user_registry: 133) except for the
-- USER / PASSWORD placeholders.
--
-- Forward-only and safe mid-upgrade: the migrator resolves
-- {clickhouse_dict_user} / {clickhouse_dict_password} to nanosiem_dict only
-- when CLICKHOUSE_DICT_PASSWORD is set AND that login works on every
-- ClickHouse server (a remote() probe per replica, prefer_localhost_replica=0,
-- so the password is checked). Otherwise they resolve to the
-- {clickhouse_self_*} credentials, exactly what these dictionaries use today,
-- so a server that does not have the new user yet never sees a dictionary it
-- cannot load (a failing CACHE dictionary fails the insert). The migrator
-- re-applies this file on a later run once the user is ready everywhere
-- (ensure_dictionary_source_user), which is how a Helm upgrade (this
-- migration runs as a pre-upgrade hook, before ClickHouse has the new user)
-- and a role-split host upgraded out of order converge.
--
-- Each dictionary's COMMENT is a fingerprint of the login it reads with
-- ({clickhouse_dict_fingerprint}: a truncated SHA-256 of user + password,
-- never the password). The migrator re-applies this file when a fingerprint
-- no longer matches, so a changed CLICKHOUSE_DICT_PASSWORD reaches the
-- dictionaries on the next migrate instead of leaving them on the old one.
--
-- Metadata only: no data moves. HASHED / IP_TRIE dictionaries are lazy
-- (dictionaries_lazy_load), so they reload on next use with the same source
-- query they run today; CACHE dictionaries restart empty and refill on demand.
-- init.sql and ocsf/init.sql use the same placeholders, so a later re-run of
-- either keeps the dictionary user.

-- hash_prevalence_dict (current body: 172_prevalence_dict_cache_cells_by_box.sql)
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
    USER '{clickhouse_dict_user}'
    PASSWORD '{clickhouse_dict_password}'
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
LAYOUT(COMPLEX_KEY_CACHE(SIZE_IN_CELLS {prevalence_cache_cells}))
COMMENT '{clickhouse_dict_fingerprint}';

-- domain_prevalence_dict (current body: 172_prevalence_dict_cache_cells_by_box.sql)
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
    USER '{clickhouse_dict_user}'
    PASSWORD '{clickhouse_dict_password}'
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
LAYOUT(COMPLEX_KEY_CACHE(SIZE_IN_CELLS {prevalence_cache_cells}))
COMMENT '{clickhouse_dict_fingerprint}';

-- ip_prevalence_dict (current body: 172_prevalence_dict_cache_cells_by_box.sql)
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
    USER '{clickhouse_dict_user}'
    PASSWORD '{clickhouse_dict_password}'
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
LAYOUT(COMPLEX_KEY_CACHE(SIZE_IN_CELLS {prevalence_cache_cells_ip}))
COMMENT '{clickhouse_dict_fingerprint}';

-- ip_geo_attrs_dict (current body: 185_ip_geo_dict_split.sql)
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
    USER '{clickhouse_dict_user}'
    PASSWORD '{clickhouse_dict_password}'
    DB 'nanosiem'
    QUERY 'SELECT geo_id, any(country) AS country, any(country_code) AS country_code, any(continent) AS continent, any(continent_code) AS continent_code, any(asn) AS asn, any(as_name) AS as_name, any(as_domain) AS as_domain FROM (SELECT cityHash64(country, country_code, continent, continent_code, asn, as_name, as_domain) AS geo_id, country, country_code, continent, continent_code, asn, as_name, as_domain FROM nanosiem.ip_enrichment_dict_staging UNION ALL SELECT geo_id, country, country_code, continent, continent_code, asn, as_name, as_domain FROM nanosiem.ip_geo_attrs_history) GROUP BY geo_id SETTINGS max_bytes_before_external_group_by = 268435456, max_memory_usage = 1000000000, max_threads = 2'
))
LIFETIME(0)
LAYOUT(HASHED())
SETTINGS(max_result_rows = 0, max_result_bytes = 0)
COMMENT '{clickhouse_dict_fingerprint}';

-- ip_geo_trie_dict (current body: 185_ip_geo_dict_split.sql)
CREATE OR REPLACE DICTIONARY nanosiem.ip_geo_trie_dict /* nano:fatal */
(
    network String,
    geo_id UInt64 DEFAULT 0
)
PRIMARY KEY network
SOURCE(CLICKHOUSE(
    HOST '{clickhouse_self_host}'
    PORT {clickhouse_self_port}
    USER '{clickhouse_dict_user}'
    PASSWORD '{clickhouse_dict_password}'
    DB 'nanosiem'
    QUERY 'SELECT network, cityHash64(country, country_code, continent, continent_code, asn, as_name, as_domain) AS geo_id FROM nanosiem.ip_enrichment_dict_staging'
))
LIFETIME(0)
LAYOUT(IP_TRIE())
SETTINGS(max_result_rows = 0, max_result_bytes = 0)
COMMENT '{clickhouse_dict_fingerprint}';

-- ip_enrichment_dict (current body: 185_ip_geo_dict_split.sql)
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
    USER '{clickhouse_dict_user}'
    PASSWORD '{clickhouse_dict_password}'
    DB 'nanosiem'
    QUERY 'SELECT network, country, country_code, continent, continent_code, asn, as_name, as_domain FROM nanosiem.ip_enrichment_dict_staging'
))
LIFETIME(MIN 21600 MAX 43200)
LAYOUT(IP_TRIE())
SETTINGS(max_result_rows = 0, max_result_bytes = 0)
COMMENT '{clickhouse_dict_fingerprint}';

-- ioc_enrichment_dict (current body: 188_ocsf_ioc_stamping_parity.sql)
CREATE OR REPLACE DICTIONARY nanosiem.ioc_enrichment_dict
(
    ioc_value String,
    ioc_type String DEFAULT '',
    source_id String DEFAULT '',
    threat_type String DEFAULT '',
    malware String DEFAULT '',
    confidence_level Int32 DEFAULT 0,
    tags String DEFAULT ''
)
PRIMARY KEY ioc_value
SOURCE(CLICKHOUSE(
    HOST '{clickhouse_self_host}'
    PORT {clickhouse_self_port}
    USER '{clickhouse_dict_user}'
    PASSWORD '{clickhouse_dict_password}'
    DB 'nanosiem'
    QUERY 'SELECT if(ioc_type = \'url\', arrayElement(arrayMap(url_t -> if(position(url_t, \'://\') > 0, arrayElement(arrayMap(url_rest -> arrayElement(arrayMap(url_tail_pos -> arrayElement(arrayMap(url_authority -> concat(lower(substring(url_t, 1, position(url_t, \'://\') + 2)), arrayElement(arrayMap(url_at_from_end -> arrayElement(arrayMap(url_userinfo_end -> arrayElement(arrayMap(url_host_port -> arrayElement(arrayMap(url_host_end -> concat(substring(url_authority, 1, url_userinfo_end), lower(substring(url_host_port, 1, url_host_end)), substring(url_host_port, url_host_end + 1)), [if(startsWith(url_host_port, \'[\') AND position(url_host_port, \']\') > 0, position(url_host_port, \']\'), if(position(url_host_port, \':\') > 0, position(url_host_port, \':\') - 1, length(url_host_port)))]), 1), [substring(url_authority, url_userinfo_end + 1)]), 1), [if(url_at_from_end = 0, 0, length(url_authority) - url_at_from_end + 1)]), 1), [position(reverse(url_authority), \'@\')]), 1), if(url_tail_pos = 0, \'\', substring(url_rest, url_tail_pos))), [if(url_tail_pos = 0, url_rest, substring(url_rest, 1, url_tail_pos - 1))]), 1), [multiSearchFirstPosition(url_rest, [\'/\', char(63), \'#\'])]), 1), [substring(url_t, position(url_t, \'://\') + 3)]), 1), url_t), [trimBoth(ioc_value)]), 1), lower(ioc_value)) AS ioc_value, ioc_type, source_id, threat_type, malware, confidence_level, tags FROM nanosiem.ioc_enrichment_dict_staging'
))
LIFETIME(MIN 60 MAX 300)
LAYOUT(HASHED())
COMMENT '{clickhouse_dict_fingerprint}';

-- custom_ioc_enrichment_dict (current body: 188_ocsf_ioc_stamping_parity.sql)
CREATE OR REPLACE DICTIONARY nanosiem.custom_ioc_enrichment_dict
(
    key_type String,
    key_value String,
    threat_type String,
    malware String,
    confidence UInt8,
    tags Array(String),
    enrichment_names Array(String)
)
PRIMARY KEY key_type, key_value
SOURCE(CLICKHOUSE(
    HOST '{clickhouse_self_host}'
    PORT {clickhouse_self_port}
    USER '{clickhouse_dict_user}'
    PASSWORD '{clickhouse_dict_password}'
    DB 'nanosiem'
    QUERY 'SELECT key_type, if(key_type = \'url\', arrayElement(arrayMap(url_t -> if(position(url_t, \'://\') > 0, arrayElement(arrayMap(url_rest -> arrayElement(arrayMap(url_tail_pos -> arrayElement(arrayMap(url_authority -> concat(lower(substring(url_t, 1, position(url_t, \'://\') + 2)), arrayElement(arrayMap(url_at_from_end -> arrayElement(arrayMap(url_userinfo_end -> arrayElement(arrayMap(url_host_port -> arrayElement(arrayMap(url_host_end -> concat(substring(url_authority, 1, url_userinfo_end), lower(substring(url_host_port, 1, url_host_end)), substring(url_host_port, url_host_end + 1)), [if(startsWith(url_host_port, \'[\') AND position(url_host_port, \']\') > 0, position(url_host_port, \']\'), if(position(url_host_port, \':\') > 0, position(url_host_port, \':\') - 1, length(url_host_port)))]), 1), [substring(url_authority, url_userinfo_end + 1)]), 1), [if(url_at_from_end = 0, 0, length(url_authority) - url_at_from_end + 1)]), 1), [position(reverse(url_authority), \'@\')]), 1), if(url_tail_pos = 0, \'\', substring(url_rest, url_tail_pos))), [if(url_tail_pos = 0, url_rest, substring(url_rest, 1, url_tail_pos - 1))]), 1), [multiSearchFirstPosition(url_rest, [\'/\', char(63), \'#\'])]), 1), [substring(url_t, position(url_t, \'://\') + 3)]), 1), url_t), [trimBoth(key_value)]), 1), lower(key_value)) AS key_value, threat_type, malware, confidence, tags, enrichment_names FROM nanosiem.custom_ioc_enrichment_dict_staging'
))
LAYOUT(COMPLEX_KEY_HASHED())
LIFETIME(MIN 60 MAX 300)
COMMENT '{clickhouse_dict_fingerprint}';

-- custom_enrichment_dict (current body: 133_dict_staging_indirection.sql)
CREATE OR REPLACE DICTIONARY nanosiem.custom_enrichment_dict
(
    key_type String,
    key_value String,
    tags Array(String),
    risk_score UInt8,
    enrichment_names Array(String)
)
PRIMARY KEY key_type, key_value
SOURCE(CLICKHOUSE(
    HOST '{clickhouse_self_host}'
    PORT {clickhouse_self_port}
    USER '{clickhouse_dict_user}'
    PASSWORD '{clickhouse_dict_password}'
    DB 'nanosiem'
    QUERY 'SELECT key_type, key_value, tags, risk_score, enrichment_names FROM nanosiem.custom_enrichment_dict_staging'
))
LAYOUT(COMPLEX_KEY_HASHED())
LIFETIME(MIN 60 MAX 300)
COMMENT '{clickhouse_dict_fingerprint}';

-- user_registry_dict (current body: 133_dict_staging_indirection.sql)
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
    USER '{clickhouse_dict_user}'
    PASSWORD '{clickhouse_dict_password}'
    DB 'nanosiem'
    QUERY 'SELECT username, email, display_name, department, title, manager_upn, manager_display_name, company, groups, account_enabled, account_status, mfa_enabled, employee_type, country, office_location FROM nanosiem.user_registry_dict_staging'
))
LIFETIME(MIN 300 MAX 600)
LAYOUT(HASHED())
COMMENT '{clickhouse_dict_fingerprint}';

