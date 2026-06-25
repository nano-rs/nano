# OCSF Ingestion Parser Handoff (NAN-1246)

## TL;DR — where we are
- **Query side**: PR **#1909** (branch `feat/NAN-1241-ocsf-schema-support`, ~28 commits, review-ready). Whole OCSF read path is profile-aware, UDM byte-identical, validated live.
- **NAN-1246 ingestion keystone: DONE + proven end-to-end.** The Vector-config **generator** now produces the OCSF ingestion lane **dynamically**, gated on `NANO_SCHEMA_PROFILE=ocsf`. A parser is "OCSF" **iff its VRL emits a root `.class_uid`** — the generated `{name}_ocsf_split` (route `exists(.class_uid)`) forks those → `{name}_ocsf_prepare` (builds the `ocsf_logs` row `{event, timestamp, source_type}`) → generated `_ocsf_sink.toml` (`clickhouse_ocsf_logs`). Non-OCSF events fall to `._unmatched` → `_output` → UDM `logs`. Hand-written `_ocsf.toml` is deleted by the generator. UDM deployments emit no lane (byte-identical).
- **Proven**: synthetic apache line → `:8080` → generated lane → landed in `ocsf_logs` (count +1), **0** in UDM `logs`.
- Generator code (committed `914520ac`): `nanosiem-core/src/parsers/vector_config/parser_config.rs` (`ocsf_mode`, `generate_ocsf_lane`, `OCSF_PREPARE_VRL` const + VRL-compile test, wired into `generate_parser_config`) + `deploy.rs` (`write_ocsf_sink_config`). Activates on the next parser deploy/restart.

## THE NEXT TASK (what the user asked for)
Author **OCSF versions of the log-blaster source parsers in `../parsers`**, in a **new `ocsf` folder structure** (user's decision: separate OCSF folders, NOT a `parser_vrl_ocsf` field). Mirror each existing UDM parser → an OCSF one with the same source but VRL emitting the **OCSF event root** instead of `.udm.*`.

**Sources** (log-blaster emits `windows_sysmon, windows_event, conduit_proxy, aws_cloudtrail`; user also wants `apache_access`):
| source | ../parsers path (UDM) | OCSF class(es) |
|---|---|---|
| apache (apache_access) | `parsers/apache/parser.yaml` | HTTP Activity **4002** — **TEMPLATE already exists** (deployed apache parser emits OCSF; see generated `config/vector/sources/parsers/apache.toml` + `ocsf-validation/apache/parser.vrl`) |
| conduit_proxy | `parsers/conduit_proxy/parser.yaml` | Network **4001** / HTTP **4002** |
| windows_sysmon | `parsers/sysmon/parser.yaml` | by EventID: Process **1007** / Network **4001** / File **1001** / DNS **4003** / Registry |
| windows_event | `parsers/windows_event/parser.yaml` | by EventID: Authentication **3002** (4624/4625), etc. |

**Steps:**
1. **Scope first** — read `tools/event-core/generators/*` (e.g. `proxy.rs`) to see EXACTLY which event shapes/EventIDs log-blaster actually emits per source; only map those (NOT the full sysmon/windows spec — that's 29/24+ IDs).
2. For each: read the UDM `parser.yaml` (`parser_vrl` emits `.udm`/`.ext`). Create the OCSF folder (confirm exact layout with user — likely `../parsers/parsers-ocsf/<src>/parser.yaml` or `../parsers/parsers/<src>/ocsf/parser.yaml`). Write the OCSF `parser.yaml` whose `parser_vrl` assembles the **complete OCSF record on the root** (`.class_uid`, `.category_uid`, `.activity_id`, `.type_uid = class_uid*100+activity_id`, `.time` = epoch **ms**, `.severity[_id]`, `.message`, and the entity objects: `src_endpoint`/`dst_endpoint`/`actor`/`user`/`file`/`http_request`/`http_response`/`query`/etc per class). **Mirror the apache OCSF VRL as the template.**
3. **Validate**: `../parsers/scripts/validate-vrl.sh` (run BEFORE committing — memory `feedback_validate_vrl`). VRL `parse_regex` needs **named captures** `(?P<name>...)` — numeric `."0"` no-ops on Vector 0.54+ (memory `feedback_vrl_parse_regex_named_captures`).
4. **Onboard** into the app so the generator produces the lane (the app imports `parser.yaml` → PG parser repo → `vector_config` generator). **Confirm the onboarding mechanism with the user** (UI parser editor vs import/seed). Open question: how OCSF parser defs get into the repo under OCSF mode.
5. User **restarts** (owns the dev startup script; must set `NANO_SCHEMA_PROFILE=ocsf`) → generator regenerates lanes.
6. Run **log-blaster** (`tools/log-blaster`) → Vector `:8080` → validate diverse OCSF classes land in `ocsf_logs`.

## Key facts the next session needs
- **Test-ingest one line**: `POST http://localhost:8080/` with headers `X-Source-Type: <src>` + `Authorization: Bearer nanosiem-default-token`, body = raw log line. Returns 200 on buffer-accept (NOT CH-confirm); sink batch timeout ~10s, so wait ≥12s. Verify: `SELECT count() FROM nanosiem.ocsf_logs WHERE source_type='<src>'` (CH `localhost:8123`, `nanosiem`/`nanosiem`; admin `nanosiem_admin`/`nanosiem_admin_secret` for DDL/mutations — the `nanosiem` user is DDL-prohibited).
- **`%source_type`** is stashed **globally** in `00-base.toml` `source_type_extract` (`%source_type = downcase(source_type)`, ~line 309) — survives the parser's `. = {OCSF object}` root-wipe; `_ocsf_prepare` reads it back. Works for ALL sources (verified).
- **OCSF column mappings** (`nanosiem-core/docs/ocsf/1.8.0/udm_ocsf_mapping.json`): `src_ip→src_endpoint.ip`, `dest_ip→dst_endpoint.ip`, `src_host→src_endpoint.hostname`, `dest_host→dst_endpoint.hostname`, `user→user.name`, `process_name→actor.process.name`, `command_line→actor.process.cmd_line`, `file_hash→file.hashes.sha256`, `file_name→file.name`, `file_path→file.path`, `url_domain→url.hostname`, `query→query.hostname`. INT value cols: `status_id`/`activity_id`/`severity_id`/`auth_protocol_id`.
- **OCSF classes**: 4002 HTTP Activity, 4001 Network Activity, 4003 DNS Activity, 1007 Process Activity, 1001 File System Activity, 3002 Authentication, 6003 Cloud API Activity. (2004 Detection Finding = nano's OWN findings, already done in NAN-1254.)
- **Profile check**: `GET :3000/api/schema/fields` → `{"schema":"ocsf",...}`; search `:3002/api/search/explain` → `FROM ocsf_logs`. API key for testing: `-PopdJxnG9EY1P71Vt6XTcpuWOSLg6IJ8BZTwLKzY7Y` (header `X-API-Key`).
- **Don't** `cargo build`/restart the search/api binary — the dev startup script owns it (memory `feedback_dev_startup_script_owns_search_build`). Compiling for tests is fine.
- Generated config lives in `config/vector/sources/parsers/` (auto-generated, regenerated on deploy/restart) — `apache.toml` (has `apache_ocsf_split`/`_prepare`), `_ocsf_sink.toml` (generated), `_router.toml` (generated). These are local artifacts; the committed thing is the GENERATOR.

## Branch / PR / Linear
- Branch `feat/NAN-1241-ocsf-schema-support` pushed; **PR #1909** (~28 commits) = query side + NAN-1246 generator keystone + frontend highlight/autocomplete + test hardening.
- Linear (all under epic **NAN-1241**): **NAN-1246** ingestion (In Progress — this task); **1252/1254/1256/1257/1259** In Review (on #1909); **1262** OCSF test hardening (In Progress); **1263** testing-strategy initiative (Backlog).
- Uncommitted local noise: `config/vector/*` (generated artifacts + parser dev files) + lockfiles — **leave them** (memory `feedback_ignore_vector_parser_local_files`).

## Open decisions to confirm with user
1. Exact `../parsers` OCSF folder layout (separate `parsers-ocsf/` tree vs `<src>/ocsf/` subfolder).
2. How OCSF parser defs get onboarded into the app's parser repo under OCSF mode (UI vs import/seed).
