# Authoring a Tenzir → OCSF → nano pipeline

This guide is for agents writing or fixing a Tenzir pipeline that ships OCSF
events into nano. People can read it too.

nano runs on the **lean lake** now: Parquet parts in an object store, written
by the lake-cell ingestor. ClickHouse is gone. The old `to_clickhouse` path
(`pipeline.tql` and [Legacy](#legacy-clickhouse-era-direct-ingestion-retired)
below) does not work on a lean install.

Field mappings follow the parser set in the **parsers repo**
(`parsers-ocsf/<source>/parser.yaml`, `main` branch).

---

## Where Tenzir sends: the bucket drop (open core)

Tenzir already emits OCSF 1.9, so it skips Vector. It writes files straight
into the install's object store (RustFS), and the lake converts each file into
ordinary bronze:

```
Tenzir ─ to_s3 { write_parquet } ─▶ landing-ocsf-v1/tenant_id=<T>/source=<source_id>/<uuid>.parquet
   ─▶ lake_landing_ingest (lean-landing): claim once per (key, etag), run Vector's own
      ocsf_lake_storage_prepare VRL, pre-check strict OCSF 1.9, write one bronze object
   ─▶ bronze-v2/[shard=N/]tenant_id=<T>/<secs>-<uuid>.parquet
   ─▶ lake-cell part ingest: the SAME admission as Vector's files (IPinfo geo/ASN,
      tenant IOC enrichments[], identity, prevalence, platform stamps, uid window)
```

| | Status | How |
|---|---|---|
| **Bucket drop (THE path)** | Open core, lean profile | `to_s3` + `write_parquet` (or `write_ndjson`, optionally `.gz`) into the source's folder |
| HTTP through Vector (fallback) | Works on open core | `POST http://<nano-host>/ingest` with a per-sender ingest token; see [below](#fallback-http-through-vector) |
| HEC through Vector | Open core: does not work with `to_splunk` | see [below](#why-not-to_splunk-on-open-core) |
| Hosted | Out of scope for the bucket drop | hosted tenants have no install object store to drop into |

### Install modes

The pinned, tested Tenzir is **`tenzir/tenzir:v6.19.1`**
(`@sha256:6e96f962bc0a957d94d5149f840f7603c47a7b11d995e0f1fc167c141db7c06f`,
the same pin as the compose `tenzir` service and `images.lock`).

- `install.sh` (default): Vector ingest **and** the bucket drop, side by side.
  Tenzir can drop files into any lean install.
- `install.sh --tenzir`: Tenzir-direct. The lean stack **without Vector** and
  without the connector runner. What that removes:
  - HTTP `/ingest`, HEC (`:8088`), OTLP (`/otlp`, `:4317/4318`), Vector native
    (`:6000`) and fluent are not offered; nginx answers 502 on `/ingest` and
    `/otlp`.
  - Pull connectors and directory (identity) sync, which deliver through
    Vector, are not available; the connector runner is not started.
  - Parser deploys have no Vector to render into; map in Tenzir instead.
  - Synthetic checks report their metrics over Vector's OTLP and do not run.

  What stays: the lake cell, lean-landing, the enrichment coordinator
  (IPinfo, tenant IOCs, prevalence), lean-otel, and the platform audit lane,
  which has its own private Vector (`lean-audit-vector`) and is unaffected.
- `install.sh --add-vector` turns a Tenzir-direct install into the default
  (Vector plus the bucket drop). A re-run without either flag keeps the mode
  the install has (`NANO_VECTOR_PROFILE` in `.env`: `none` = no Vector).
- The bundled node: `docker compose --profile tenzir up -d tenzir` runs the
  pinned Tenzir with `.nano-tenzir/pipeline.tql` (seeded from
  `lean/sysmon-bucket.tql`; edit its source and paste your sink). It is never
  started by `up` on its own.

### Add a source

```sh
docker compose run --rm lean-landing-admin add --name tenzir-sysmon [--route <key>] [--endpoint <host:port>]
```

It creates a disabled log source (never rendered into Vector), a landing
source, and a RustFS user whose only policy is `s3:PutObject` on
`arn:aws:s3:::nano-lake/landing-ocsf-v1/tenant_id=<T>/source=<source_id>/*`.
It prints the key and a ready-to-paste `to_s3` sink **once**; the key is not
stored or logged anywhere. `list` shows sources; `revoke <source_id>` deletes
the RustFS user and its policy, which is the revocation.

The key can only put objects into its own folder: it cannot read, list or
delete, and cannot write into another source's folder or into bronze (probed
on RustFS 1.0.1). Tenzir's multipart uploads succeed with `s3:PutObject`
alone (a 71 MiB file on CT 106 with Tenzir v6.18.0 and v6.19.1), so the policy carries no
`s3:AbortMultipartUpload`.

### The pipeline: `lean/sysmon-bucket.tql`

```
to_s3 "s3://nano-lake/landing-ocsf-v1/tenant_id=<T>/source=<id>/{uuid}.parquet?endpoint_override=lake-object-store:9000&scheme=http",
  aws_iam={access_key_id: "<key>", secret_access_key: "<secret>"} {
  write_parquet
}
```

- **The folder decides the source.** Every row gets
  `metadata.log_source = <route key>`, `metadata.tenant_uid = <T>`,
  `metadata.nano_credential_id = <the source's credential id>` and
  `metadata.ingress_transport = "landing_bucket"`, whatever the file says.
- **Keep `metadata.uid` stable** (Sysmon `ProcessGuid`, `RecordID` plus host).
  It is kept as sent unless it is a bare random UUIDv4 that does not appear in
  `raw_data`. A row without a uid gets one derived from the file's SHA-256 and
  the row's ordinal. Resending the same events adds no duplicates: the lake's
  uid dedupe window drops them (a resend days later can fall outside it).
- **Formats:** `.parquet` (Tenzir's typed nested `write_parquet`), `.ndjson`,
  `.jsonl`, `.json`, each NDJSON form optionally `.gz`. A typed `time` column
  (RFC 3339 string after decoding) is read as the event time.
- **Caps:** 256 MiB per file on the store, 1 GiB decoded NDJSON, 250 000 rows.
- **Refusals never wedge.** A bad row is counted and left out. A file with
  nothing admissible (unreadable, wrong tenant or source, revoked source, over a
  cap, failing 5 times) is refused whole and moved to
  `landing-ocsf-v1-refused/...`. Status, with a value-free reason, is on
  **Ingestion → Credentials → Bucket drop sources** and
  `GET /api/landing-sources[/{id}/files]`.
- **Vector features do not apply, by design.** nano Pipe filters and sampling
  and VRL parsers run in Vector; bucket-drop rows never pass through it. Map
  and filter in Tenzir.

### Reaching RustFS

RustFS stays internal by default: run Tenzir on the nano host on the compose
network (`--network nano_default`, endpoint `lake-object-store:9000`, `scheme=http`).
For a Tenzir node on another host, put a TLS listener in front of RustFS
(for example an nginx `stream`/`server` block on a dedicated port with your
certificate, proxying to `lake-object-store:9000`), firewall it to the
sender, and pass `--endpoint <host>:<port> --scheme https` to `add` so the
printed sink uses it. Never publish RustFS's plain port 9000 beyond the host.

### Fallback: HTTP through Vector

`lean/sysmon-http.tql` POSTs NDJSON to open-core `/ingest` with a per-sender
ingest token. Proven 100/100 on CT 106 (Tenzir `v6.18.0`), but:

- **Class 0, not your class.** With no parser deployed for the source,
  Vector's generic lane wraps every event as OCSF class 0 Base Event; your
  mapping survives only inside `raw_data` and `message`. A passthrough parser
  fixes this, but keeps Vector in the loop.
- **Your `metadata` is replaced.** `metadata.uid` is re-minted, so a sender
  retry can duplicate events. `metadata.log_source` comes from the token's
  bound source or `X-Source-Type`.
- **Close a request every few seconds:** wrap `to_http` in `every 2s { … }`;
  `buffer_all=true` sends `Content-Length` and lets it retry on 5xx.

Ingest tokens: **Ingestion → Credentials**, or `POST /api/ingest-tokens` with
`{"name": "tenzir-sysmon"}` (`settings:system`). The value is shown once; keep
it in the Tenzir node's environment, never in a `.tql` file.

### Why not `to_splunk` on open core

Open-core HEC is Vector's `splunk_hec` source with indexer acknowledgements
on. It refuses any request that has no `X-Splunk-Request-Channel` header
(`{"text":"Data channel is missing","code":10}`), and `to_splunk` has no
header option. The hosted Worker synthesizes a channel itself, so this refusal
is specific to open core.

---

## OCSF mapping conventions (lean)

- Map to the released OCSF **1.9.0** schema and set `metadata.version` to
  `"1.9.0"`. Lake admission runs a strict OCSF 1.9 validator
  (`nanosiem_core::parsers::validate_ocsf_event`). It refuses unknown
  attributes, a wrong `type_uid`, and missing required objects (for example
  `device` on System Activity classes).
- `type_uid = class_uid * 100 + activity_id`.
- `time` is integer epoch **milliseconds**.
- Keep the original bytes as a **string** in `raw_data`. Lake admission
  refuses a source row without a non-empty `raw_data` and a matching
  `raw_data_size`; the storage stage fills `raw_data_size` (and `raw_data`
  from `message`) when they are missing.
  - Read input with `read_lines` and parse with `line.parse_json()` to keep
    the original line byte-exact.
  - `print_json()` re-renders the record, so it is not byte-exact.
- Put a meaningful summary in `message`; bare-keyword search targets it.
- Set `metadata.uid` from a natural record id (Sysmon `ProcessGuid`, or
  `RecordID` plus host). The bucket drop keeps a sender uid, and the lake
  dedupes on it.
- Lowercase anything nano lowercases at ingest: hostnames, IPs, hashes.
- Put anything that has no OCSF attribute in `unmapped`. Do not invent
  top-level fields; strict admission refuses them.

Representative classes (mirror `parsers-ocsf/<source>/parser.yaml` so
Tenzir rows look like Vector-parsed rows):

| Source / event | OCSF class | `class_uid` |
|---|---|---|
| Sysmon EID 1/5 (process create/terminate), 10 | Process Activity | `1007` |
| Sysmon EID 7 (image load) | Module Activity | `1005` |
| Sysmon EID 12 (registry key) | Registry Key Activity | `201001` |
| Sysmon EID 13 (registry value) | Registry Value Activity | `201002` |
| Sysmon EID 3 (network) | Network Activity | `4001` |
| Sysmon EID 11/23 (file) | File System Activity | `1001` |
| Sysmon EID 22 (DNS) | DNS Activity | `4003` |
| Proxy / Apache access (HTTP) | HTTP Activity | `4002` |
| CloudTrail API call | API Activity | `6003` |
| Unknown / unroutable | Process Activity (Other) | `1007`, `activity_id=99` |

## Validate end to end

1. Send a run with a unique marker in `message`, for example
   `cmd.exe /c echo <run>-0001`.
2. Search (`POST /api/search`, with a search-only API key in `X-API-Key`) for:
   - `<run>` (expect N rows);
   - `<run> | stats count` (expect N);
   - `<run> | stats count by metadata.uid | where count > 1` (expect no rows).
3. Check that `metadata.nano_credential_id` is your token's credential id.

Bronze objects are ingested within seconds on open core. A search 20 s after
the send already returned the full 100/100.

---

## Legacy: ClickHouse-era direct ingestion (retired)

Everything below applies only to gen1 ClickHouse installs (the `legacy`
compose profile, which the `tenzir` profile and `pipeline.tql` depend on).
`install.sh` refuses the bundled Tenzir profile in lake mode. It is kept for
installs that have not moved yet.

### The sink (copy verbatim)

```tql
to_clickhouse table="nanosiem.ocsf_logs_raw",
  host=env("NANO_CH_HOST").otherwise("clickhouse"),
  port=int(env("NANO_CH_NATIVE_PORT").otherwise("9000")),
  user=env("NANO_CH_INGEST_USER").otherwise("nanosiem_ingest"),
  password=env("CLICKHOUSE_INGEST_PASSWORD"),
  tls=false, mode="append"
```

Why each argument:

- `tls=false` — `to_clickhouse` defaults to **TLS on**; the native port on the
  internal docker network is plaintext. Without this you get
  `OpenSSL error: wrong version number`.
- `port=9000` — the **native** protocol, not the `8123` HTTP port.
- `mode="append"` — the table exists; do not create it. (The `json=` argument is
  create-mode only and **errors** with `append`.)

---

### Batch before the sink

Put this **immediately before** `to_clickhouse`:

```tql
unordered { batch 65536, timeout=2s }
```

ClickHouse wants big inserts, not a storm of 1-row parts. Real OCSF is
**maximally heterogeneous** — every class / field-set is a distinct Tenzir
schema — so the mapped stream fragments into ~1-row table slices and
`to_clickhouse` issues **one native INSERT per event**. At volume that backs up
in the node's in-memory buffer and **OOM-kills it** (measured: avg 1.4
rows/insert, ~0.5 % landed at 200 eps, node SIGKILL'd at its memory limit).

`batch` buffers **per schema** and, in the default **ordered** mode, flushes on
every schema change — so it can't coalesce an interleaved heterogeneous stream.
`unordered { batch }` accumulates same-schema events across the stream into large
inserts. Measured on the OCSF rig: **avg ~23 rows/insert (max 183), bounded
memory (no OOM), 16× more landed.** Order is irrelevant once rows are in
ClickHouse. Raise `timeout` for bigger batches at a little more ingest latency.
`unordered` alone (without `batch`) or `batch` alone (ordered) do **not** help —
you need both.

---

### Target table & the legacy entrypoint

Write directly to **`nanosiem.ocsf_logs_raw`** (Tenzir ≥ 6.6.0). It's an
`ENGINE = Null` landing table exposing `event JSON` + `source_type` +
server-derived `timestamp` + `id`. You send only `{event, source_type}`;
`ocsf_logs_raw_mv` derives every promoted / enriched / prevalence column into
`nanosiem.ocsf_logs`:

```
to_clickhouse → ocsf_logs_raw → ocsf_logs_raw_mv → ocsf_logs
```

**Why 6.6.0.** `append` mode validates **every column type on the target
table** — even DEFAULT columns it never writes — and older releases rejected two
of `ocsf_logs_raw`'s columns. 6.6.0 also learned to **omit columns absent from
the record** so their ClickHouse DEFAULTs fire (older releases dropped the event):

| `ocsf_logs_raw` column | Tenzir ≤ 6.5.x | Tenzir ≥ 6.6.0 |
|---|---|---|
| `event JSON` | OK (≥ 6.4.0) | OK |
| `source_type LowCardinality(String)` | **rejected** — wants plain `String` | OK |
| `timestamp DateTime64(3, 'UTC')` | **rejected** — the timezone arg blocks it | OK |
| absent `timestamp` / `id` (server-derived) | **event dropped** | omitted → DEFAULT fires |

**Legacy fallback (Tenzir 6.4.0–6.5.x).** If you're pinned to an older node,
target `nanosiem.ocsf_logs_native_raw` instead — a thin `ENGINE = Null` shim
exposing only `event JSON` + `source_type String` (the types those releases
accept), whose forwarding MV pushes `(event, source_type)` into `ocsf_logs_raw`:

```
to_clickhouse → ocsf_logs_native_raw → (forwarding MV) → ocsf_logs_raw → ocsf_logs_raw_mv → ocsf_logs
```

Same wire shape, same result, one extra hop. It stays supported but is
**deprecated** in favour of the direct write. No projection is duplicated either
way; `ocsf_logs_raw_mv` is the single source of truth for derivation/enrichment.
(Schema: `clickhouse/ocsf/init.sql`. The native shim came first; the direct
`ocsf_logs_raw` write became the default on Tenzir 6.6.0.)

---

### OCSF mapping conventions

Pin mappings and fixtures to the released OCSF 1.9.0 schema. Tenzir 6.10.0's
`ocsf::cast` accepts 1.9.0 and the `ai_operation` plus `record_integrity`
profiles. Do not claim a 1.8 mapping is 1.9 by changing only
`metadata.version`; update and validate its actual event-class/profile fields.

Mirror `parsers-ocsf/<source>/parser.yaml` exactly — same `class_uid`,
`activity_id`, and promoted fields as the Vector lane, so direct-ingested rows
are indistinguishable from Vector-ingested ones. Representative classes:

| Source / event | OCSF class | `class_uid` |
|---|---|---|
| Sysmon EID 1/5 (process create/terminate), 10 | Process Activity | `1007` |
| Sysmon EID 7 (image load) | Module Activity | `1005` |
| Sysmon EID 12 (registry key) | Registry Key Activity | `201001` |
| Sysmon EID 13 (registry value) | Registry Value Activity | `201002` |
| Sysmon EID 3 (network) | Network Activity | `4001` |
| Sysmon EID 11/23 (file) | File System Activity | `1001` |
| Sysmon EID 22 (DNS) | DNS Activity | `4003` |
| Proxy / Apache access (HTTP) | HTTP Activity | `4002` |
| CloudTrail API call | API Activity | `6003` |
| Unknown / unroutable | Process Activity (Other) | `1007`, `activity_id=99` |

Rules:

- `type_uid = class_uid * 100 + activity_id`.
- Set a lowercase `source_type` per feed (`windows_sysmon`, `conduit_proxy`, …).
  A missing/uppercase `source_type` lands rows as `unknown` and every
  `source_type=`-scoped detection/hunt skips them.
- Anything without an OCSF home goes in `event.unmapped` (a spill object), not a
  top-level invented field.
- Don't drop unroutable input — land a minimal debuggable record (class `1007`,
  `activity_id=99`, `message=<raw>`) like the Vector parsers do.

#### `raw_data` — keep the original

If you parse a raw log, put the **untouched original** (syslog header included) on
`event.raw_data`, and use `event.message` for the human-readable summary. nano
persists `raw_data` to its own column for the full retention window, so an OCSF
feed re-materializes by re-reading it through this same mapping — no parallel raw
archive.

- `raw_data` is OCSF `string_t` (**not** `json_t`, since OCSF 1.5) — **send a string.**
  An object is not rejected, it is stringified — and ClickHouse's JSON type
  **reorders its keys** on the way through (measured: `{"EventID":…,"Channel":…}`
  came back `{"Channel":…,"EventID":…}`). It survives, but no longer byte-for-byte,
  which defeats the point of keeping an original. Byte-exact round-trip is only
  guaranteed for a string.
- Capture it **before** you parse: `let $original = this`, then set
  `event.raw_data = $original` after mapping.
- It is **stored, not bare-keyword-searched.** A bare `foo` hunt targets `message`
  only (`keyword_search_column()`), so `message` still needs to carry something
  meaningful. Explicit `raw_data` hunts do get a text index (`idx_raw_data_words`).
- Costs nothing if you skip it (empty column), but the original is then gone — the
  Vector lanes take that route deliberately, putting the raw log in `message`
  instead. Don't do **both**: the raw log stored twice is exactly what an
  earlier cleanup deleted (it was ~46% of the table).
- `raw_data_hash` / `raw_data_size` are **not** promoted — nothing emits them yet.
  Send them and they are dropped (they are standard OCSF attributes, so they will
  not land in `unmapped` either). Ask before relying on them.

#### `time` fallback

`event.time` should be epoch ms. nano's `timestamp` derivation never silently
drops a row — it accepts ms, detects+converts seconds/microseconds, parses
RFC3339/ISO-8601 best-effort, and falls back to **insert time** for
missing/garbage values. Prefer plain integer epoch ms; if you map with
`ocsf::cast`, time-typed fields serialize as RFC3339 strings (handled, but ms is
the spec shape).

---

### Source shape

The bundled `pipeline.tql` listens with `accept_http` and expects already-OCSF
NDJSON. Swap the source for whatever you ingest (`load_tcp`, `load_kafka`,
`load_file`, syslog, …); a listener keeps the node alive when there's no input.
Envelope-style rigs (the dev `tools/log-blaster/tenzir/blaster_to_ocsf.tql`)
receive `{message, timestamp, source_type}` and route on `source_type`.

---

### Validate end-to-end (always do this)

Run the pipeline against a reachable ClickHouse, push a marked event, and read it
back out of `ocsf_logs` (not `ocsf_logs_raw` — that's `ENGINE = Null`):

```bash
# from the nano docker network (host=clickhouse), or your own CH host
MARK="probe-$(date +%s)"
curl -s -X POST --data-binary \
  "{\"class_uid\":4001,\"time\":$(($(date +%s)*1000)),\"activity_id\":1,\"message\":\"$MARK\",\"src_endpoint\":{\"ip\":\"9.9.9.9\"}}" \
  http://localhost:9095/

clickhouse-client -q "SELECT source_type, class_uid, timestamp, \`src_endpoint.ip\`, message
  FROM nanosiem.ocsf_logs WHERE message = '$MARK' FORMAT Vertical"
```

Confirm: row count increments, `timestamp` derives from `event.time`, and your
promoted fields (`src_endpoint.ip`, etc.) are populated. Validate at production
scale too — local 2M-row timing can mislead.

---

### Common failures → fix

| Symptom | Cause / fix |
|---|---|
| `OpenSSL error: wrong version number` | `to_clickhouse` defaulted to TLS. Add `tls=false`. |
| `unsupported ClickHouse type 'JSON'` | Tenzir < 6.4.0, or a clickhouse-cpp sink. Upgrade to ≥ 6.6.0. |
| `unsupported ClickHouse type 'DateTime64(...)'` / `LowCardinality` | Tenzir < 6.6.0 writing to `ocsf_logs_raw`. Upgrade to ≥ 6.6.0, or target the legacy `ocsf_logs_native_raw` entrypoint. |
| `required column missing in input` / events silently dropped | Tenzir < 6.6.0 can't omit the server-derived `timestamp`/`id`, or a **null** in a required column (nulls drop the event even with a DEFAULT). Upgrade to ≥ 6.6.0 and guard mapped values with `.otherwise(...)`. |
| `ACCESS_DENIED` on insert | `nanosiem_ingest` lacks INSERT/SELECT on the target (`ocsf_logs_raw`, or `ocsf_logs_native_raw` on the legacy path) or `SELECT` on the `*_prevalence_agg` tables the MV cascade reads. Grants ship in `clickhouse/users.d/nanosiem-users.xml`; reload with `SYSTEM RELOAD USERS` (or redeploy). |
| Rows land as `source_type='unknown'` | Set a lowercase `source_type` on each record. |
| Rows present but `timestamp` is "now" | `event.time` missing/garbage → fell back to insert time. Emit epoch ms. |
| `event` is a JSON **string**, not an object | Emit a JSON object; a stringified blob fails parsing and async inserts can drop the batch. |

---

### Connection environment

| Var | Default | Meaning |
|---|---|---|
| `CLICKHOUSE_INGEST_PASSWORD` | — (**required**) | `nanosiem_ingest` password |
| `NANO_CH_HOST` | `clickhouse` | ClickHouse host |
| `NANO_CH_NATIVE_PORT` | `9000` | native TCP port |
| `NANO_CH_INGEST_USER` | `nanosiem_ingest` | INSERT-only user |
| `NANO_TENZIR_LISTEN` | `0.0.0.0:9095` | listener address (bundled pipeline) |

> The bundled listener on `:9095` is **unauthenticated** — restrict network
> access, or replace the source with an authenticated one.
