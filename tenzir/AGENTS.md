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
   operator into `nanosiem.ocsf_logs_native_raw`, `tls=false`, `mode="append"`,
   native port `9000`. Editing the table name or sink will break ingestion.
2. **Requires Tenzir ≥ 6.4.0.** Earlier releases' `to_clickhouse` cannot write a
   ClickHouse `JSON` column (`unsupported ClickHouse type 'JSON'`).
3. **Target `ocsf_logs_native_raw`, never `ocsf_logs_raw` directly.** See
   [Why the native entrypoint](#why-the-native-entrypoint).
4. **Wire shape is `{event, source_type}`.** `event` is the full OCSF 1.8.0
   object; it MUST carry `class_uid` and `time` (epoch **milliseconds**).
5. **Lowercase** `source_type` and any value you write that nano lowercases at
   ingest (IPs, hostnames, hashes).
6. You own everything between source and sink: parse + map your logs to OCSF.

---

## The sink (copy verbatim)

```tql
to_clickhouse table="nanosiem.ocsf_logs_native_raw",
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

## Why the native entrypoint

`to_clickhouse`'s `append` mode validates **every column type on the target
table** — even DEFAULT columns it never writes — and rejects:

| Column type | Verdict |
|---|---|
| `JSON` / `Nullable(JSON)` | OK (Tenzir ≥ 6.4.0 only) |
| `String` | OK |
| `LowCardinality(String)` | **rejected** — wants plain `String` |
| `DateTime64(3, 'UTC')` | **rejected** — wants bare `DateTime64(9)` |
| `DateTime64(9, 'UTC')` | **rejected** — the timezone arg itself is the blocker |

`nanosiem.ocsf_logs_raw` (the table the Vector lane and HTTP clients use) carries
both a `LowCardinality(String) source_type` and a `DateTime64(3, 'UTC') timestamp`,
so `to_clickhouse` cannot target it. `nanosiem.ocsf_logs_native_raw` exposes only
`event JSON` + `source_type String`; a forwarding MV pushes `(event, source_type)`
into `ocsf_logs_raw`, where the existing timestamp/id DEFAULTs and
`ocsf_logs_raw_mv` do all promotion. ClickHouse cascades MVs through the
`ENGINE = Null` entrypoint, so the full chain runs:

```
to_clickhouse → ocsf_logs_native_raw → (forwarding MV) → ocsf_logs_raw → ocsf_logs_raw_mv → ocsf_logs
```

No projection is duplicated; `ocsf_logs_raw_mv` stays the single source of truth
for derivation/enrichment. (Schema: `clickhouse/ocsf/init.sql`. Rationale:
NAN-1603.)

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
| `unsupported ClickHouse type 'JSON'` | Tenzir < 6.4.0, or a clickhouse-cpp sink. Upgrade to ≥ 6.4.0. |
| `unsupported ClickHouse type 'DateTime64(...)'` / `LowCardinality` | You targeted `ocsf_logs_raw`. Use `ocsf_logs_native_raw`. |
| `ACCESS_DENIED` on insert | `nanosiem_ingest` lacks INSERT/SELECT on the entrypoint. Grants ship in `clickhouse/users.d/nanosiem-users.xml`; reload with `SYSTEM RELOAD USERS` (or redeploy). |
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
