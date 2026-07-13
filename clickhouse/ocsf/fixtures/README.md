# OCSF fixtures (NAN-1242, Phase 0)

Spec-compliant OCSF 1.8.0 events used to prove that the **MATERIALIZED promoted
columns and their indexes populate from a plain OCSF write into a single
`event` JSON column** — i.e. an emitter pushes raw OCSF, and ClickHouse derives
every hot/indexed UDM-parity column for free.

These fixtures are vendored against the OCSF classes captured under
`nanosiem-core/docs/ocsf/1.8.0/` and the promotion manifest
`nanosiem-core/docs/ocsf/1.8.0/udm_ocsf_mapping.json`.

## Files / classes covered

| File | Class | `class_uid` | `category_uid` | `activity_id` | `type_uid` |
|------|-------|-------------|----------------|---------------|------------|
| `authentication_3002_logon.json` | Authentication | 3002 | 3 (IAM) | 1 (Logon) | 300201 |
| `network_activity_4001_traffic.json` | Network Activity | 4001 | 4 (Network) | 6 (Traffic) | 400106 |
| `process_activity_1007_launch.json` | Process Activity | 1007 | 1 (System) | 1 (Launch) | 100701 |
| `file_activity_1001_delete.json` | File System Activity | 1001 | 1 (System) | 4 (Delete) | 100104 |
| `http_activity_4002_get.json` | HTTP Activity | 4002 | 4 (Network) | 3 (Get) | 400203 |
| `dns_activity_4003_query.json` | DNS Activity | 4003 | 4 (Network) | 2 (Response) | 400302 |

Every fixture satisfies the OCSF taxonomy invariant
`type_uid == class_uid * 100 + activity_id`, carries `metadata.version = "1.8.0"`,
and `time` is **epoch milliseconds** (13 digits, `timestamp_t`) — convert with
`fromUnixTimestamp64Milli(time)`, never compare the raw int to a `DateTime64`
(coerces as seconds → far future; cf. NAN-1123).

## What each fixture exercises (per the promotion manifest)

- **Authentication 3002** — top-level `user.{name,domain,uid}` (the subject;
  `user_name`/`user_domain`/`user_uid`), `actor.user.name` (the initiator;
  `actor_user_name`), `src_endpoint`/`dst_endpoint` (`*_ip`/`*_port`/`*_hostname`),
  `auth_protocol_id`/`auth_protocol`, `status_id`/`status`, `session.uid`,
  `severity_id`/`severity`. This is the class where the principal is *top-level*
  `user`, not `actor.user`.
- **Network Activity 4001** — `src_endpoint`/`dst_endpoint` (incl. `mac`,
  `location`, `autonomous_system` — see enrichment below),
  `connection_info.protocol_num` (IANA, indexed int), `traffic.{bytes,packets}_{in,out}`,
  the split `url.hostname` (domain entity) vs `url.url_string` (full URL — OCSF
  1.8.0 uses `url_string`, NOT `text`), and a populated `enrichments[]` (ioc +
  custom by-name entries).
- **HTTP Activity 4002** — `http_request.{http_method,user_agent,url.path}`,
  `http_response.code`, plus `src_endpoint.{location,autonomous_system}` geo/ASN
  enrichment and `enrichments[]` (ioc + custom).
- **DNS Activity 4003** — `query.hostname` (queried domain) and the `answers[]`
  array (the promoted `answers.rdata` takes the FIRST answer's rdata), plus an
  `enrichments[]` domain-IOC entry.
- **Process Activity 1007** — the class-dependent process split: `actor.process.*`
  (initiator → `actor_process_*`) **and** top-level `process.*` (target →
  `process_*`), the deepest promoted path
  `actor.process.parent_process.cmd_line`, and `*.file.hashes[]` SHA-256 selection
  (`algorithm_id = 3`). Uses `device.hostname` (Host profile) as the `src_host`
  source since there is no `src_endpoint`.
- **File System Activity 1001** — `actor.{user,process}` as the principal,
  `file.{name,path}`, `file.hashes[]` SHA-256 selection, and `file_action`
  encoded as `activity_id` scoped by `class_uid = 1001` (Delete = 4). Multi-algo
  hashes (MD5 = 1 alongside SHA-256 = 3) confirm the `arrayFilter(algorithm_id=3)`
  selector picks the right one.

`raw_data` — the producer's untouched original — IS promoted, to its own column
(NAN-1827). The auth fixture carries a syslog-framed Windows 4624 there while its
`message` stays a human summary, which is the split OCSF intends; the other five
leave it absent, which is what our own Vector lanes produce (they put the raw log
in `message` and emit no `raw_data`). `ocsf_materialization_integration` asserts
both cases round-trip byte-exactly — as hex, because the original carries tabs and
CRLFs that `FORMAT TSV` would escape.

⚠️ `observables[]` is populated on every fixture and is currently **dropped on
every ingest**. It is a standard OCSF attribute, so a conformant producer does not
put it in `unmapped`; it is not promoted; and the `event` JSON column this file
once said it "intentionally stays in" no longer exists — NAN-1443 deleted it. Same
silent-drop class as the pre-NAN-1827 `raw_data` bug, and nothing in the test suite
catches it (the assertions prove promoted columns POPULATE, never that nothing was
LOST). Tracked separately; do not assume `observables[]` survives ingest.

`enrichments[]`, by contrast, IS promoted (dual-mode): the Network/DNS/HTTP
fixtures carry named entries (`ioc_*`, `custom_*`) that materialize into the
`enrichments.<udm_name>` columns via the by-NAME `arrayFirst` selector — geo/ASN
likewise materialize from the OCSF-native `*.location.*` /
`*.autonomous_system.*` objects. This holds whether nano computed the enrichment
(open-core ingestion writes it into the standard OCSF objects) or the client
shipped pre-enriched OCSF.

> Note on JSON escaping: these files are JSON-encoded for `JSONEachRow`. Windows
> paths and the `\\` in `ACME\\jsmith` appear as `\\\\` / `\\\\\\\\` in the source
> on disk because the value itself contains a literal backslash that JSON must
> escape, then the OCSF string is embedded once more; ClickHouse decodes them
> back to single backslashes on insert.

## Loading: insert into ONLY the `event` column

The whole point of Phase 0 is that the emitter writes **just** the raw OCSF object
into the `event` column; ClickHouse fills in `class_uid`, `time_dt`,
`` `src_endpoint.ip` ``, `` `file.hashes.sha256` ``, the `.search` companions, etc.
via the MATERIALIZED expressions defined in the Phase 0 DDL (deliverable 3). Do
**not** write the promoted columns by hand.

`FORMAT JSONEachRow` reads one JSON object per line and assigns it to the named
columns; here the single named column is `event`, so each input object must be
wrapped as `{"event": <ocsf-object>}`. Two equivalent ways:

### Option A — wrap each fixture as `{"event": ...}` and stream

```bash
# CH_TABLE is the OCSF logs table created by the Phase 0 DDL, e.g. nanosiem.ocsf_logs
CH_TABLE="nanosiem.ocsf_logs"

for f in authentication_3002_logon.json \
         network_activity_4001_traffic.json \
         process_activity_1007_launch.json \
         file_activity_1001_delete.json; do
  # collapse the fixture to one line and nest it under "event"
  jq -c '{event: .}' "$f"
done | clickhouse-client --query \
  "INSERT INTO ${CH_TABLE} (event) FORMAT JSONEachRow"
```

Over HTTP (matches the local-dev pattern — POST raw body, not `query=`):

```bash
for f in *_*.json; do jq -c '{event: .}' "$f"; done \
  | curl -sS 'http://localhost:8123/' \
      --data-binary @- \
      -H 'Content-Type: application/x-ndjson' \
      -G --data-urlencode \
        "query=INSERT INTO ${CH_TABLE} (event) FORMAT JSONEachRow"
```

### Option B — treat the OCSF object itself as the row value

If the `event` column is JSON/String and you would rather not pre-wrap, insert the
raw object as a single string value:

```bash
clickhouse-client --query \
  "INSERT INTO ${CH_TABLE} (event) FORMAT JSONAsString" \
  < authentication_3002_logon.json
```

`JSONAsString` maps the entire JSON document to one String column (must be the
sole inserted column), which is the simplest way to land a verbatim OCSF event in
`event` without re-nesting.

## Verifying the promotion worked

After insert, the promoted columns should be non-empty even though only `event`
was written:

Promoted columns use LITERAL DOTTED OCSF paths and MUST be backtick-quoted:

```sql
SELECT
    class_uid,
    category_uid,
    activity_id,
    type_uid,
    time_dt,
    `src_endpoint.ip`,
    `dst_endpoint.ip`,
    `user.name`,
    `actor.user.name`,
    `actor.process.name`,
    `process.name`,
    `file.hashes.sha256`,
    `actor.process.file.hashes.sha256`,
    auth_protocol_id,
    status,
    `url.hostname`,
    `dst_endpoint.location.country`,
    `dst_endpoint.autonomous_system.number`,
    `enrichments.ioc_dest_ip_threat_type`,
    `query.hostname`,
    `answers.rdata`,
    `http_request.http_method`,
    `http_response.code`
FROM nanosiem.ocsf_logs
ORDER BY time_dt;
```

Expected, one row per fixture:

- `class_uid` ∈ {3002, 4001, 1007, 1001, 4002, 4003}; `type_uid` = `class_uid*100 + activity_id`.
- `time_dt` resolves to the fixtures' `time` epoch-ms values, proving
  `fromUnixTimestamp64Milli` is wired correctly.
- `` `src_endpoint.ip` `` = `10.20.30.40` on Auth/Network/DNS/HTTP;
  `` `dst_endpoint.ip` `` = `93.184.216.34` on Network.
- `` `user.name` `` = `jsmith` on Auth (top-level subject); `` `actor.process.name` `` /
  `` `process.name` `` populated on Process 1007 (`explorer.exe` / `powershell.exe`).
- `` `file.hashes.sha256` `` lowercased on File 1001, and
  `` `actor.process.file.hashes.sha256` `` set from the actor's SHA-256 — proving the
  `arrayFilter(algorithm_id = 3)` selector ignored the MD5 entry.
- Enrichment (dual-mode): `` `dst_endpoint.location.country` `` = `US` (ISO code),
  `` `dst_endpoint.autonomous_system.number` `` = `15133`,
  `` `enrichments.ioc_dest_ip_threat_type` `` = `c2` (selected from `enrichments[]`
  BY NAME) on Network.
- DNS 4003: `` `query.hostname` `` = `malware-c2.example.net`; `` `answers.rdata` `` =
  `203.0.113.66` (the FIRST answer).
- HTTP 4002: `` `http_request.http_method` `` = `GET`; `` `http_response.code` `` = `403`.
- `.search` companions (e.g. `` `message.search` ``, `` `file.path.search` ``,
  `` `actor.process.cmd_line.search` ``) should satisfy `hasToken(...)` lookups for the
  embedded tokens, confirming the text/bloom indexes materialized from the
  `event` write alone.

## Deferred / unmapped (UDM-indexed fields with no clean OCSF 1.8.0 home)

These UDM-indexed columns are intentionally NOT promoted because OCSF 1.8.0 has
no spec-correct scalar path for them. They remain in the `event` tail (or are
derived at the query layer); we never invent a non-standard OCSF path:

- **`enriched_src_country` / `enriched_dest_country` (country NAME).** OCSF
  `location.country` is the ISO 3166-1 Alpha-2 CODE only — it maps to UDM
  `enriched_*_country_code`. There is no country-NAME attribute on `location`, so
  the UDM name column is left to query-layer derivation (code→name).
- **`enriched_*_continent_code`.** `location.continent` is the continent NAME;
  there is no continent-code attribute.
- **`enriched_*_as_domain`.** The `autonomous_system` object has only `number`
  and `name` — no AS-domain attribute.
- **`change_type`.** No scalar OCSF analog; the closest is the class/activity
  taxonomy (`category_uid`/`activity_id`), already promoted. `change_type` itself
  stays in the tail.
- **Detection / signal-engine-internal fields** (`rule_id`, `matched_log_id`,
  `mitre_technique_id`, `signature`, `signature_id`, `risk_entity`, `risk_score`)
  and ingest artifacts (`_inserted_at` bookkeeping, regex-derived fields) are
  EXCLUDED by design — they are not part of a raw client OCSF record (they are
  produced by nano's detection/ingestion, which the OCSF read-plane does not own).
- **`url_domain` on HTTP Activity 4002** lives at `http_request.url.hostname`;
  only `http_request.url.path` is promoted today. The hostname stays in the tail
  until a hunt need justifies promoting it.
- **Multi-valued tails**: additional `file.hashes[]` algorithms (MD5/SHA1/SHA512),
  extra `answers[]`, extra `email.to[]` recipients, and extra `vulnerabilities[]`
  CVEs stay in `event` — only the canonical/first element is promoted.
