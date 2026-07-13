# Authoring a Tenzir → OCSF → nano pipeline

Agent-facing guide for writing or fixing the Tenzir pipeline that ships OCSF
events into nano (this directory's `pipeline.tql`). Human-readable too. If you
are an AI assistant helping a user customize their bundled `nano-tenzir` node,
this is your reference — read it before editing `pipeline.tql`.

Ground truth for field mappings is the parser set in the **parsers repo**
(`parsers-ocsf/<source>/parser.yaml`). End-user docs:
<https://nano.rs/docs/ocsf/integrations/direct-ocsf>.

---

## TL;DR — the rules that bite

1. **Sink is fixed. Do not change it.** Write with the native `to_clickhouse`
   operator into `nanosiem.ocsf_logs_raw`, `tls=false`, `mode="append"`,
   native port `9000`. Editing the table name or sink will break ingestion.
2. **Requires Tenzir ≥ 6.6.0.** The first release whose `to_clickhouse` accepts
   `ocsf_logs_raw`'s column types AND omits server-derived columns it doesn't
   send. On Tenzir 6.4.0–6.5.x, target the legacy `nanosiem.ocsf_logs_native_raw`
   entrypoint instead — see
   [Target table & the legacy entrypoint](#target-table--the-legacy-entrypoint).
3. **Send only `{event, source_type}`.** `timestamp` and `id` are server-derived
   — leave them out and their ClickHouse DEFAULTs fire. A **null** in a required
   column still drops the event even with a DEFAULT (only ABSENT columns default),
   so guard mapped values like `source_type` with `.otherwise("unknown")`.
4. **Wire shape is `{event, source_type}`.** `event` is the full OCSF 1.8.0
   object; it MUST carry `class_uid` and `time` (epoch **milliseconds**).
5. **Lowercase** `source_type` and any value you write that nano lowercases at
   ingest (IPs, hostnames, hashes).
6. You own everything between source and sink: parse + map your logs to OCSF.

---

## The sink (copy verbatim)

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

## Target table & the legacy entrypoint

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
(Schema: `clickhouse/ocsf/init.sql`. Rationale: NAN-1603 added the native shim;
NAN-1788 made the direct `ocsf_logs_raw` write the default on Tenzir 6.6.0.)

---

## OCSF mapping conventions

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

### `raw_data` — keep the original (NAN-1827)

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
  instead. Don't do **both**: the raw log stored twice is exactly what NAN-1443
  deleted (it was ~46% of the table).
- `raw_data_hash` / `raw_data_size` are **not** promoted — nothing emits them yet.
  Send them and they are dropped (they are standard OCSF attributes, so they will
  not land in `unmapped` either). Ask before relying on them.

### `time` fallback

`event.time` should be epoch ms. nano's `timestamp` derivation never silently
drops a row — it accepts ms, detects+converts seconds/microseconds, parses
RFC3339/ISO-8601 best-effort, and falls back to **insert time** for
missing/garbage values. Prefer plain integer epoch ms; if you map with
`ocsf::cast`, time-typed fields serialize as RFC3339 strings (handled, but ms is
the spec shape).

---

## Source shape

The bundled `pipeline.tql` listens with `accept_http` and expects already-OCSF
NDJSON. Swap the source for whatever you ingest (`load_tcp`, `load_kafka`,
`load_file`, syslog, …); a listener keeps the node alive when there's no input.
Envelope-style rigs (the dev `tools/log-blaster/tenzir/blaster_to_ocsf.tql`)
receive `{message, timestamp, source_type}` and route on `source_type`.

---

## Validate end-to-end (always do this)

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

## Common failures → fix

| Symptom | Cause / fix |
|---|---|
| `OpenSSL error: wrong version number` | `to_clickhouse` defaulted to TLS. Add `tls=false`. |
| `unsupported ClickHouse type 'JSON'` | Tenzir < 6.4.0, or a clickhouse-cpp sink. Upgrade to ≥ 6.6.0. |
| `unsupported ClickHouse type 'DateTime64(...)'` / `LowCardinality` | Tenzir < 6.6.0 writing to `ocsf_logs_raw`. Upgrade to ≥ 6.6.0, or target the legacy `ocsf_logs_native_raw` entrypoint. |
| `required column missing in input` / events silently dropped | Tenzir < 6.6.0 can't omit the server-derived `timestamp`/`id`, or a **null** in a required column (nulls drop the event even with a DEFAULT). Upgrade to ≥ 6.6.0 and guard mapped values with `.otherwise(...)`. |
| `ACCESS_DENIED` on insert | `nanosiem_ingest` lacks INSERT/SELECT on the target (`ocsf_logs_raw`, or `ocsf_logs_native_raw` on the legacy path) or `SELECT` on the `*_prevalence_agg` tables the MV cascade reads (NAN-1787). Grants ship in `clickhouse/users.d/nanosiem-users.xml`; reload with `SYSTEM RELOAD USERS` (or redeploy). |
| Rows land as `source_type='unknown'` | Set a lowercase `source_type` on each record. |
| Rows present but `timestamp` is "now" | `event.time` missing/garbage → fell back to insert time. Emit epoch ms. |
| `event` is a JSON **string**, not an object | Emit a JSON object; a stringified blob fails parsing and async inserts can drop the batch. |

---

## Connection environment

| Var | Default | Meaning |
|---|---|---|
| `CLICKHOUSE_INGEST_PASSWORD` | — (**required**) | `nanosiem_ingest` password |
| `NANO_CH_HOST` | `clickhouse` | ClickHouse host |
| `NANO_CH_NATIVE_PORT` | `9000` | native TCP port |
| `NANO_CH_INGEST_USER` | `nanosiem_ingest` | INSERT-only user |
| `NANO_TENZIR_LISTEN` | `0.0.0.0:9095` | listener address (bundled pipeline) |

> The bundled listener on `:9095` is **unauthenticated** — restrict network
> access, or replace the source with an authenticated one.
