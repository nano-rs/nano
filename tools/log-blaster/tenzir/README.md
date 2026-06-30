# log-blaster `--tenzir`: raw logs → Tenzir → OCSF → ClickHouse

A permanent rig for the raw-log leg of direct OCSF ingestion (NAN-1402,
follow-up to the NAN-1400 validation): log-blaster ships its generators'
**raw, pre-parse payloads** to a Tenzir HTTP listener; the TQL pipeline in
this directory parses them, maps each feed to OCSF 1.8.0 (same
class/activity/promoted-field coverage as the native Vector OCSF parsers),
and INSERTs straight into `nanosiem.ocsf_logs_raw` as the INSERT-only
`nanosiem_ingest` user — Vector is bypassed entirely.

```
log-blaster --tenzir ─NDJSON {message, timestamp, source_type}→ Tenzir accept_http :9095
  → route on source_type → parse raw (JSON / Apache combined log) → OCSF 1.8.0
  → {event, source_type} → ClickHouse HTTP INSERT (nanosiem.ocsf_logs_raw)
```

Producer contract: `docs/user-guide/direct-ocsf-ingestion.md`.

## Feeds covered

| source_type | raw form | OCSF classes |
|---|---|---|
| `windows_sysmon` | Windows Event JSON | 1007 / 1005 / 1001 / 4001 / 4003 / 201001 / 201002 (per Sysmon EventID) |
| `windows_event` | Windows Security JSON | 3002 (4624/4625/4634), 3003 (4672), 1007 (4688) |
| `conduit_proxy` | proxy access JSON | 4002 HTTP Activity |
| `apache_access` | combined log **text** (grok-parsed) | 4002 HTTP Activity |
| `aws_cloudtrail` | CloudTrail JSON | 6003 API Activity |

## Run it

1. Start the Tenzir side (joins the local compose network; the password is
   `CLICKHOUSE_INGEST_PASSWORD` from your stack — local dev default lives in
   `docker-compose.yml`):

   ```bash
   docker run -d --name tenzir-blaster --network nanosiem_default \
     -p 9095:9095 \
     -e NANO_CH_INGEST_PASSWORD="$CLICKHOUSE_INGEST_PASSWORD" \
     -v "$PWD/tools/log-blaster/tenzir/blaster_to_ocsf.tql:/pipeline.tql:ro" \
     tenzir/tenzir -f /pipeline.tql
   ```

2. Blast (all rate/blast/spike modes work):

   ```bash
   cargo run -p log-blaster -- --tenzir --rate 600            # default http://localhost:9095
   cargo run -p log-blaster -- --tenzir http://host:9095 --blast --eps 5000
   ```

3. Verify and tear down:

   ```bash
   # rows per feed
   curl -s "http://localhost:8123/" --user "nanosiem_admin:$CLICKHOUSE_PASSWORD" \
     --data-binary "SELECT source_type, count() FROM nanosiem.ocsf_logs
       WHERE _inserted_at > now() - INTERVAL 10 MINUTE GROUP BY source_type"
   docker rm -f tenzir-blaster
   ```

Environment knobs on the pipeline: `NANO_CH_INGEST_USER` (default
`nanosiem_ingest`), `NANO_CH_INGEST_PASSWORD` (**required**, never committed),
`NANO_CH_HOST` (default `clickhouse`), `NANO_CH_NATIVE_PORT` (default `9000`),
`NANO_TENZIR_LISTEN` (default `0.0.0.0:9095`).

### Sink: native `to_clickhouse` (NAN-1603)

The rig streams to ClickHouse via the native `to_clickhouse` operator over the
native protocol (port 9000) into the dedicated `nanosiem.ocsf_logs_native_raw`
entrypoint. **Requires Tenzir ≥ 6.4.0** (the first release whose `to_clickhouse`
can write a ClickHouse `JSON` column). The legacy `to_http`-JSONEachRow shooter
was removed — native is the only path.

A separate entrypoint table is required because `to_clickhouse`'s append mode
rejects `ocsf_logs_raw`'s `LowCardinality` / timezone-qualified `DateTime64`
columns; `ocsf_logs_native_raw` exposes only `event JSON` + `source_type String`
and forwards into the same `ocsf_logs_raw_mv` derivation chain. Full rationale:
`docs/user-guide/direct-ocsf-ingestion.md`.

## Design notes

- **Wire format**: the blaster sends its existing `Event` serde shape —
  `{message, timestamp, source_type}` — as NDJSON. The raw payload is
  byte-identical to what the Vector lane receives in `.message`; identity is
  in-band (one listener, no per-feed ports/headers), which is what
  `accept_http` can route on.
- **One router pipeline, not five**: a single `if src == … else if …` chain
  keeps the rig to one container/one port/one file, mirroring how the Vector
  router fans out to per-feed parsers.
- **Native sink, no batching wrapper**: `to_clickhouse` streams continuously
  over the native protocol and manages its own inserts, so the pipeline drops
  the old `every 1s { to_http … }` micro-batching wrapper the HTTP shooter
  needed (NAN-1603).
- **Mapping ground truth** is the OCSF parser set in the parsers repo
  (`parsers-ocsf/*/parser.yaml`). Known benign divergence: for Sysmon /
  Windows Event, the TQL emits `metadata.uid` = the Windows `record_id` (as
  the parser.yaml intends); the deployed Vector VRL's `string()` errors on
  the integer `record_id` and falls back to `uuid_v4()`, so Vector-lane rows
  carry a random UUID there instead.
- Validated against Tenzir v6.1 (`tenzir/tenzir` image). `from_http
  server=true` was removed in v6 — `accept_http` is the listener.

For the sink rules, OCSF mapping conventions, validation recipe, and gotchas
when authoring/fixing any Tenzir → OCSF → nano pipeline, see **`tenzir/AGENTS.md`**
(repo root) — the canonical agent-facing guide.
