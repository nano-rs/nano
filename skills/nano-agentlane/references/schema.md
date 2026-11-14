# Agent Lane schema reference

Tested with nano 2.0.23 (ClickHouse schema head 200, OCSF head ocsf/197). All
tables live in the `nanosiem` database. For the live list on your install,
run the `tables_available` and `columns_like` recipes, or
`DESCRIBE TABLE nanosiem.ocsf_logs`.

## Tables you can read

| Table | What it holds | Time column |
|---|---|---|
| `ocsf_logs` | Every event, normalized to OCSF. The main hunt table. | `timestamp` |
| `signals` | Detection matches: which rule fired, on which entity, for which event. | `timestamp` |
| `identity_observations` | IP to host name / user bindings over time (private source IPs). 30-day retention. | `observed_at` |
| `hash_prevalence_source_summary` | Per hash and log source: distinct hosts, first/last seen, events. Last 30 days. | none needed |
| `domain_prevalence_source_summary` | Per domain and log source: distinct source hosts, first/last seen. Last 30 days. | none needed |
| `ip_prevalence_source_summary` | Per IP, direction and log source: distinct peers, first/last seen. Last 30 days. | none needed |
| `logs` | UDM installs only: the older normalized table. Empty on OCSF installs. | `timestamp` |

Not granted: the source-less prevalence tables (`*_prevalence_summary`,
`*_prevalence_agg`), because their merged counts include audit events that
can't be filtered out. Use the `*_prevalence_source_summary` tables.

**Clusters.** On a multi-node install, each table above also exists as
`<table>_distributed`, which reads every shard. Query the `_distributed`
name: the bare name only reads the shard you're connected to.
`tables_available` shows which you have.

**`GLOBAL IN` and `GLOBAL JOIN`.** On a cluster, when both sides of an
`IN (SELECT …)` or a `JOIN` read Distributed tables, the subquery must run
once and be sent to every shard. Agent Lane pins
`distributed_product_mode = 'global'` (locked), so a plain `IN` / `JOIN` is
rewritten to `GLOBAL` for you. Still write `x GLOBAL IN (SELECT …)` and
`GLOBAL [ASOF] [LEFT] JOIN` explicitly: it reads correctly on any install and
reminds you that the subquery's whole result travels to each shard, so keep
it small and `LIMIT` it. `GLOBAL` also works on a single node.

**Hidden:** nano's own audit events (`source_type = 'audit'`) are filtered
out of every table above.

## `ocsf_logs`

One row per event, for every OCSF version. About 120 hot OCSF attributes are
typed columns. The full OCSF object is in the `event` JSON column, and vendor
fields the parser didn't map are in `unmapped`.

**Sort key:** `(class_uid, source_type, timestamp, src_endpoint.ip)`, daily
partitions. Filtering on `class_uid` and `source_type` prunes the most.

### Dotted names need backticks

Column names are OCSF paths with dots. Quote them with backticks, or
ClickHouse reads the dot as a table qualifier:

```sql
SELECT `src_endpoint.ip`, `process.cmd_line` FROM nanosiem.ocsf_logs WHERE …
```

Alias them to plain names in the SELECT list (`` `src_endpoint.ip` AS src ``),
and don't reuse a real column name as an alias: an alias shadows the column
in WHERE.

### Common columns

| Area | Columns |
|---|---|
| Taxonomy | `class_uid`, `class_name`, `category_uid`, `category_name`, `activity_id`, `activity_name`, `type_uid`, `severity_id`, `severity`, `status_id` (1 success, 2 failure), `status`, `disposition_id`, `action_id` |
| Source | `source_type` (the nano log source), `metadata.product.name`, `metadata.product.vendor_name`, `metadata.log_name`, `metadata.event_code`, `metadata.version`, `metadata.uid` |
| Time and ids | `timestamp` (UTC, ms), `_inserted_at`, `id` (UUID, the event id signals point at), `duration` |
| Text | `message`, `raw_data` |
| Users | `user.name`, `user.uid`, `user.domain`, `user.email_addr`, `actor.user.name`, `actor.user.uid`, `actor.user.domain`, `actor.user.type`, `is_mfa`, `logon_type_id`, `auth_protocol` |
| Device | `device.hostname`, `device.ip`, `device.uid` |
| Network | `src_endpoint.ip`, `src_endpoint.hostname`, `src_endpoint.port`, `src_endpoint.mac`, `src_endpoint.location.country`, `src_endpoint.autonomous_system.number` / `.name`, the same for `dst_endpoint.*`, `connection_info.protocol_num`, `traffic.bytes_in`, `traffic.bytes_out`, `traffic.packets_in`, `traffic.packets_out` |
| Process | `process.name`, `process.cmd_line`, `process.pid`, `process.uid`, `process.file.path`, `process.file.hashes.value` (array), `process.file.hashes.sha256`, `process.parent_process.name`, `process.parent_process.cmd_line`, and `actor.process.*` (the parent / initiating process in many sources) |
| File and registry | `file.path`, `file.name`, `file.hashes.value` (array), `file.hashes.sha256`, `module.file.name`, `module.file.path`, `reg_key.path`, `reg_value.path`, `reg_value.name`, `reg_value.data` |
| Web and DNS | `http_request.url.url_string`, `http_request.url.hostname`, `http_request.url.path`, `http_request.http_method`, `http_request.user_agent`, `http_request.referrer`, `http_response.code`, `url.url_string`, `url.hostname`, `query.hostname` (DNS question), `answers.rdata` (array) |
| Cloud and API | `api.operation`, `api.service.name`, `cloud.provider`, `cloud.region`, `cloud.account.uid`, `cloud.account.name`, `resources.uid` / `.name` / `.type` (arrays), `session.uid` |
| Email | `email.from`, `email.to` (array), `email.subject`, `email.message_uid` |
| Findings | `finding_info.uid`, `finding_info.title`, `vulnerabilities.cve.uid` (array) |
| Observables | `observables.value`, `observables.type_id` (parallel arrays: every IP, domain, hash, user, URL the parser tagged) |
| Threat intel | `enrichments.ioc_*` and `enrichments.custom_ioc_*` (threat type, malware, confidence per src IP / dest IP / domain / hash / URL), `enrichments.ioc_tags`, `enrichments.ioc_source`, `enrichments.value` / `.name` (arrays) |
| Prevalence | `prevalence_file_hash`, `prevalence_process_hash`, `prevalence_dest_domain`, `prevalence_dest_ip` (host counts at ingest time; 65535 = not applicable), `prevalence_min` |
| Tracing | `trace.uid`, `trace.span.uid` (aliases `trace_id`, `span_id`) |

### Unified columns

Different sources put the same fact in different OCSF places. These ALIAS
columns pick the first non-empty one, and each has its own text index:

| Column | Resolves to |
|---|---|
| `user_unified` | `user.name`, else `actor.user.name` |
| `src_host_unified` | `src_endpoint.hostname`, else `device.hostname` |
| `process_name_unified` | `process.name`, else `actor.process.name` |
| `process_path_unified` | `process.file.path`, else `actor.process.file.path` |
| `command_line_unified` | `process.cmd_line`, else `actor.process.cmd_line` |
| `process_id_unified` | `process.pid`, else `actor.process.pid` |
| `process_guid_unified` | `process.uid`, else `actor.process.uid` |
| `process_hash_unified` | `process.file.hashes.sha256`, else `actor.process.file.hashes.sha256` |
| `url_unified` | `http_request.url.url_string`, else `url.url_string` |
| `url_domain_unified` | `http_request.url.hostname`, else `url.hostname` |

### Common OCSF classes

| `class_uid` | Class |
|---|---|
| 1001 | File System Activity |
| 1006 | Scheduled Job Activity |
| 1007 | Process Activity |
| 2004 | Detection Finding |
| 3001 | Account Change |
| 3002 | Authentication |
| 4001 | Network Activity |
| 4002 | HTTP Activity |
| 4003 | DNS Activity |
| 6003 | API Activity |

Run the `source_inventory` recipe to see which classes your install has.

### The `event` and `unmapped` JSON columns

Any OCSF attribute without its own column is still in `event`. Read it with
a dotted path and convert it to a plain type:

```sql
SELECT toString(event.query.type) AS query_type, toString(event.firewall_rule.name) AS rule
FROM nanosiem.ocsf_logs
WHERE timestamp >= now() - INTERVAL 24 HOUR AND class_uid = 4003
LIMIT 20
```

Paths in `event` have no index, so pair them with an indexed or sort-key
filter. Use `unmapped.<field>` the same way for vendor fields. Don't use
`JSONExtract*` on these columns, and don't read a promoted attribute from
`event`: promoted values are stored only in their own column.

## Case-insensitive matching: use the indexed forms

ClickHouse uses a skip index only when the WHERE clause contains **the exact
expression the index was built on**. Lowercase your literal, and write the
column side as shown.

**1. Lowercased at ingest: compare the raw column.** These are stored
lowercase. `col = '…'` uses their index; `lower(col) = '…'` does not.

`src_endpoint.ip`, `src_endpoint.hostname`, `src_endpoint.mac`,
`dst_endpoint.ip`, `dst_endpoint.hostname`, `dst_endpoint.mac`, `device.ip`,
`device.hostname`, `user.domain`, `email.from`, `email.to`, `trace.uid`,
`trace.span.uid`, `file.hashes.sha256`, `process.file.hashes.sha256`,
`actor.process.file.hashes.sha256`, and the hash arrays `file.hashes.value`,
`process.file.hashes.value`, `actor.process.file.hashes.value`.

```sql
`dst_endpoint.ip` = '203.0.113.66'
`src_endpoint.hostname` IN ('ws-01.corp.example.com', 'ws-02.corp.example.com')
hasAny(`process.file.hashes.value`, ['e3b0c442…'])
```

**2. Text-indexed (`lower(col)`, word tokens): hunts in free text.**
`message`, `raw_data`, `process.cmd_line`, `actor.process.cmd_line`,
`process.parent_process.cmd_line`, `http_request.url.url_string`,
`http_request.user_agent`, `url.url_string`, `email.subject`,
`finding_info.title`, `reg_value.data`, and every `*_unified` column.

```sql
hasToken(lower(message), 'mimikatz')            -- a whole word: fastest
lower(command_line_unified) LIKE '%-enc %'      -- a fragment or punctuation
lower(user_unified) = 'corp\\alice'              -- an exact value
```

`hasToken` matches whole words only (split on anything not a letter or
digit), and its argument must be one lowercase word. Use `LIKE '%…%'` for
fragments. Prefer `lower(col) LIKE` over `ILIKE` and
`positionCaseInsensitive`, which scan far more slowly.

**3. Bloom-indexed on `lower(col)`: exact values.** `user.name`, `user.uid`,
`user.email_addr`, `actor.user.name`, `actor.user.uid`,
`actor.user.email_addr`, `device.uid`, `process.name`, `process.file.path`,
`process.parent_process.name`, `actor.process.name`,
`actor.process.file.path`, `file.path`, `file.name`, `module.file.name`,
`module.file.path`, `reg_key.path`, `reg_value.path`, `reg_value.name`,
`http_request.url.hostname`, `url.hostname`, `query.hostname`,
`api.operation`, `metadata.event_code`.

```sql
lower(`process.name`) = 'powershell.exe'
lower(`query.hostname`) IN ('c2.bad-domain.example', 'evil.example.net')
```

**4. Arrays indexed on `arrayMap(x -> lower(x), col)`.** `observables.value`,
`enrichments.value`, `resources.uid`, `vulnerabilities.cve.uid`,
`answers.rdata`.

```sql
has(arrayMap(x -> lower(x), `observables.value`), '203.0.113.66')
hasAny(arrayMap(x -> lower(x), `observables.value`), ['203.0.113.66', 'c2.bad-domain.example'])
```

**5. Exact, case-sensitive ids (bloom on the raw column).** `metadata.uid`,
`metadata.correlation_uid`, `process.uid`, `actor.process.uid`,
`cloud.account.uid`, `session.uid`, `finding_info.uid`, `email.message_uid`.
Compare as stored: `` `session.uid` = 'AbC123' ``.

**6. `source_type`.** Compare `lower(source_type) = 'windows_security'`. It
leads the sort key after `class_uid`, so it prunes well.

Numeric columns (`*_id`, ports, `http_response.code`, `prevalence_*`) have
min/max indexes: plain comparisons work.

## `signals`

| Column | Notes |
|---|---|
| `id` | signal id |
| `timestamp` | when the rule matched (UTC) |
| `rule_id` (UUID), `rule_name` | the detection rule |
| `severity` | low, medium, high, critical |
| `risk_score` | 0–100 |
| `risk_entity` | the scored entity: a host, user or IP (bloom index) |
| `matched_log_id` | the `ocsf_logs.id` of the event that matched |
| `source_type` | source of the matched event |
| `metadata` | JSON text with rule context |

Sorted by `(timestamp, rule_id, risk_entity)`. Join to events with
`ocsf_logs.id GLOBAL IN (SELECT matched_log_id FROM nanosiem.signals WHERE …)`,
both sides time-bounded (see the `signal_events` recipe).

## `identity_observations`

Written from events that carry a private source IP and a host name.

| Column | Notes |
|---|---|
| `observed_at` | when the binding was seen (time filter column) |
| `ip` | the private IP (sort key) |
| `hostname`, `fqdn`, `mac`, `user`, `domain` | what held the IP |
| `source` | the log source that showed it |
| `ip_type` | private, vpn, loopback, public |

Use it to answer "which host had 10.0.0.10 at 14:02?" with a `GLOBAL ASOF LEFT JOIN` on
`ip` and `timestamp >= observed_at` (see `identity_asof_join`). Bound the
identity side with `observed_at` as well; a window somewhat wider than the
event window catches bindings seen shortly before.

## Prevalence tables (`*_prevalence_source_summary`)

`AggregatingMergeTree` tables with one row per artifact **per log source**
(and per schema profile) after merges, possibly several before. Merge the
sources away: `GROUP BY` the artifact only and merge the states.

| Table | Key | Distinct hosts | Also |
|---|---|---|---|
| `hash_prevalence_source_summary` | `file_hash` (lowercase), `hash_type` | `uniqMerge(host_count)` | `min(first_seen)`, `max(last_seen)`, `sum(total_count)` |
| `domain_prevalence_source_summary` | `domain` (lowercase), `is_subdomain` | `uniqMerge(source_host_count)` | same |
| `ip_prevalence_source_summary` | `ip`, `direction`, `is_private` | `uniqMerge(source_host_count)` | same |

Rules:

- **Filter `schema_profile`.** `'ocsf'` on OCSF installs, `'udm'` on UDM
  installs. An install moving from UDM to OCSF can briefly hold both; mixing
  them double-counts `total_count`.
- **Drop `source_type` from `GROUP BY`** for a whole-install verdict.
  `uniqMerge` over several sources' states gives the distinct hosts across all
  of them (a host seen by two sources counts once). Keep `source_type` in the
  `GROUP BY`, or use `groupUniqArray(source_type)`, to see which sources saw it.
- **IPs: pick a `direction`.** `'dest'` rows count the distinct sources that
  connected *to* the IP; `'src'` rows count the distinct peers it connected
  to. "How many of our hosts talked to 203.0.113.66?" is `direction = 'dest'`.
- `host_count` and `source_host_count` are HyperLogLog states. `sum()` or
  `count()` on them is wrong; use `uniqMerge()`.
- The window is the last 30 days by `last_seen`. No time filter is needed.
- Attribution starts when the install upgraded to a release with these
  tables, so an artifact seen only before then is absent.

"Rare" depends on the install's size: on 50 hosts, 1 to 2 hosts is rare; on
5,000, under 5 is a reasonable start.
