-- NAN-366: Filter internal/non-public TLDs from domain_prevalence_mv.
-- Internal hostnames like ws-support-041.corp.local were passing the domain regex
-- and polluting domain_prevalence_dict alongside real public domains.
--
-- Rebuild the MV with the TLD exclusion. Existing polluted rows in
-- domain_prevalence_agg / domain_prevalence_summary age out naturally via the
-- 30-day TTL; no destructive cleanup needed.

DROP VIEW IF EXISTS nanosiem.domain_prevalence_mv;

CREATE MATERIALIZED VIEW nanosiem.domain_prevalence_mv TO nanosiem.domain_prevalence_agg
(
    `domain` String,
    `is_subdomain` UInt8,
    `parent_domain` String,
    `time_bucket` DateTime('UTC'),
    `source_host_count` AggregateFunction(uniq, String),
    `first_seen` DateTime64(6, 'UTC'),
    `last_seen` DateTime64(6, 'UTC'),
    `total_count` UInt64
)
AS SELECT
    lower(dest_host) AS domain,
    if(length(splitByChar('.', dest_host)) > 2, 1, 0) AS is_subdomain,
    '' AS parent_domain,
    toStartOfHour(timestamp) AS time_bucket,
    uniqState(if(src_host != '', src_host, if(src_ip != '', src_ip, 'unknown'))) AS source_host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.logs
WHERE (dest_host != '') AND (position(dest_host, '.') > 0)
    AND (NOT match(dest_host, '^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$'))
    AND (NOT (position(dest_host, ':') > 0))
    AND match(dest_host, '^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$')
    AND (length(splitByChar('.', dest_host)[-1]) >= 2)
    AND (NOT match(splitByChar('.', dest_host)[-1], '^[0-9]+$'))
    AND (length(dest_host) <= 253)
    AND (lower(splitByChar('.', dest_host)[-1]) NOT IN ('local', 'corp', 'internal', 'lan', 'home', 'localdomain', 'intranet', 'private', 'arpa'))
GROUP BY domain, is_subdomain, time_bucket
UNION ALL
SELECT
    lower(query) AS domain,
    if(length(splitByChar('.', query)) > 2, 1, 0) AS is_subdomain,
    '' AS parent_domain,
    toStartOfHour(timestamp) AS time_bucket,
    uniqState(if(src_host != '', src_host, if(src_ip != '', src_ip, 'unknown'))) AS source_host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.logs
WHERE (query != '') AND (position(query, '.') > 0)
    AND (NOT match(query, '^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$'))
    AND (NOT (position(query, ':') > 0))
    AND match(query, '^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$')
    AND (length(splitByChar('.', query)[-1]) >= 2)
    AND (NOT match(splitByChar('.', query)[-1], '^[0-9]+$'))
    AND (length(query) <= 253)
    AND ((dest_host = '') OR (lower(dest_host) != lower(query)))
    AND (lower(splitByChar('.', query)[-1]) NOT IN ('local', 'corp', 'internal', 'lan', 'home', 'localdomain', 'intranet', 'private', 'arpa'))
GROUP BY domain, is_subdomain, time_bucket
UNION ALL
SELECT
    lower(url_domain) AS domain,
    if(length(splitByChar('.', url_domain)) > 2, 1, 0) AS is_subdomain,
    '' AS parent_domain,
    toStartOfHour(timestamp) AS time_bucket,
    uniqState(if(src_host != '', src_host, if(src_ip != '', src_ip, 'unknown'))) AS source_host_count,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_count
FROM nanosiem.logs
WHERE (url_domain != '') AND (position(url_domain, '.') > 0)
    AND (NOT match(url_domain, '^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$'))
    AND match(url_domain, '^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$')
    AND (length(splitByChar('.', url_domain)[-1]) >= 2)
    AND (NOT match(splitByChar('.', url_domain)[-1], '^[0-9]+$'))
    AND (length(url_domain) <= 253)
    AND ((dest_host = '') OR (lower(dest_host) != lower(url_domain)))
    AND ((query = '') OR (lower(query) != lower(url_domain)))
    AND (lower(splitByChar('.', url_domain)[-1]) NOT IN ('local', 'corp', 'internal', 'lan', 'home', 'localdomain', 'intranet', 'private', 'arpa'))
GROUP BY domain, is_subdomain, time_bucket;
