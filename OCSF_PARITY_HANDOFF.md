# OCSF Profile-Awareness Parity — Session Handoff (NAN-1241)

Hand-off for a fresh session. Goal: OCSF (`NANO_SCHEMA_PROFILE=ocsf`) reaches **feature parity with UDM** across search/detection/UI. UDM output must stay **byte-identical** everywhere (the seam guarantees this for the UDM profile).

Branch: `feat/NAN-1241-ocsf-schema-support` · everything is **UNCOMMITTED** in the working tree.

---

## 0. FIRST THINGS (do before touching anything)

1. **The grind COMPLETED green** (workflow `wf_72acdfd5-647`, 2026-06-06). All 7 groups (prevalence-ddl → asset_dossier → asset+lateral → signal+sqlgen → handlers → frontend-entitymap → frontend-rest) reviewer-approved; final-verify + an independent check both pass: `cargo build` core/search/api PASS, `cargo test -p nanosiem-core --lib` 1361/0, `tsc -b` PASS. 48 files / ~2700 insertions, all UNCOMMITTED. NOTE: "green" = builds + EXISTING tests pass (no new coverage added — that's the §4 test-hardening pass) and NOT yet validated against live CH (subagents didn't recreate `ocsf_logs` + run queries). So: re-verify, then do the §5 CH validation + §3 gaps + §4 tests.
2. **Verify the whole tree builds + tests:**
   ```
   cargo build -p nanosiem-core -p nanosiem-search -p nanosiem-api --lib
   cargo test -p nanosiem-core --lib
   cd nanosiem-web && npx tsc -b
   ```
   Last good state mid-session: `nanosiem-core` 1361 lib tests green; web `tsc -b` + `npm run build` green.
3. **Read** `OCSF_PROFILE_AWARENESS_AUDIT.md` (full ranked fix plan, 44 sites) before starting new work.

---

## 1. The seam — USE THESE (already built + tested this session)

**Rust (`crate::schema::SchemaProfile`, on `SearchService.active_profile: Arc<dyn SchemaProfile>`):**
- `profile.udm_column_sql(udm_field) -> Option<String>` — maps a **UDM-semantic** field name (`src_host`, `process_name`, `dest_ip`, `file_hash`, …) → the **escaped OCSF column**; `None` when OCSF has no column (caller **skips** the field — never emit a dead `ext.` ref). UDM = identity. Powered by the manifest `udm_field` index.
- `profile.column_sql(field) -> String` — resolve an already-schema-correct field name → SQL expr (ExplicitColumn→escaped, JsonPath→`JSONExtractString`, else `ext.{field}`). Uses `escape_string` for path segments.
- `crate::search::classification::{event_type_sql, lane_sql, auth_predicate, file_predicate}(profile)` — profile-aware classification SQL. UDM returns the old consts byte-identical; OCSF keys off `category_uid`/`class_uid`/`status_id`.
- `Self::logs_table_key(profile)` → `"logs"`/`"ocsf_logs"`, then `self.table_names.read(key)` for the FROM table. **Never** literal `"logs"`.

**Frontend:** `api.getSchemaFields()` → `{schema:'udm'|'ocsf', fields:[{name,type,category,entity_type,…}]}`, cached via `useQuery(['schema-fields'])`. Pattern: known-field set = active-schema fields ∪ `UDM_COLUMNS`.

**Pattern for UDM-semantic raw-SQL builders (free fns):** add a `profile: &dyn crate::schema::SchemaProfile` param threaded from the caller; replace literal columns with `profile.udm_column_sql("<udm_field>")` (skip on `None`); table via `logs_table_key`; classification via the dispatch fns.

---

## 2. DONE this session (validated, uncommitted)

**User-facing fixes (each tested):**
- Source picker (`handlers/fields.rs get_source_types`) profile-aware FROM table.
- Slim `table_view` projection profile-aware (`field_analysis.rs`, OCSF → `default_table_fields`).
- OCSF **row identity**: added `id UUID DEFAULT generateUUIDv7()` to `ocsf/init.sql` + `OcsfProfile::resolve("id")`/`is_uuid_field`; `fetch_log_by_id`/`build_fetch_log_sql` profile-aware → row-expand / event inspector work.
- `build_field_values_sql`/`get_field_values` profile-aware (was 500ing on `ext.trafficbytes_out`).
- **NAN-1247** (own Linear bug): `search_expr.rs` full-text emitted `lower(toString(col))` which orphaned the `lower(col)` text index on **both UDM and OCSF** → field full-text full-scanned. Fixed: `lower(col)` for plain String columns; `.search` companion columns removed in `ocsf/init.sql` (dead index) and text indexes redefined on the expression.
- Sort/SAMPLE tiebreaker `cityHash64(toString(event))` → `cityHash64(id)` (~3000× cheaper; needs table recreate).
- Frontend: EventInspectorPanel Core/Extended categorization, SearchResults RawView key-field chips, FieldsPanel "Selected" set — all profile-aware via `getSchemaFields()`.

**Enablers (the linchpins):** classification dispatch + `udm_column_sql` semantic resolver + `column_sql` + manifest `udm_field` index. UDM byte-identical (regression tests added).

**Prevalence parity (DDL):** `ocsf/init.sql` got `prevalence_*` MATERIALIZED columns (dictGet on OCSF keys) + summary tables/dicts + OCSF summary MVs `FROM ocsf_logs`; manifest registers them. (`prevalence_` appears ~36× in `ocsf/init.sql`.)

**Grind groups (verify completion + per-group review verdicts):** asset_dossier, asset+lateral, signal+sqlgen free-fns, api handlers, frontend entity-map hook + remaining frontend.

---

## 3. KNOWN GAPS — pipe commands the grind did NOT cover (do these)

Add to NAN-1248. Each fix = thread profile + `udm_column_sql`/`logs_table_key`/classification, UDM byte-identical.

1. **`histogram` (HIGHEST PRIORITY — hits every OCSF search).** `search/service/histogram.rs:219` hardcodes `FROM logs` → the search/timechart **timeline is empty under OCSF**. Fix: `self.table_names.read(Self::logs_table_key(self.active_profile.as_ref()))`. Cheap, do first.
2. **`| cloud` (full backend surface).** `cloud.rs` + `cloud_dossier.rs` + `cloud_overview.rs` — all `FROM logs` + literal UDM cols (`cloud_service`, `resource_type/id/name`, `change_type`, `mfa_used`, …). Also the **manifest is missing** the non-core cloud mappings — only `cloud_provider/account.uid/account.name/region` are mapped. Needs: manifest + `ocsf/init.sql` promotions for `api.service.name` (cloud_service), the **`resources[]` array** (`resource_type/uid/name` → ArrayElement), `mfa`, an operation/`change_type` derivation; then thread the 3 cloud modules. Bigger sub-build.
3. **`| prevalence`.** `prevalence_join.rs` (17 UDM col refs, not profile-aware) and `prevalence_processing.rs apply_prevalence_filtering` (~:127) reference UDM field names (`file_hash`, `dest_host`) not on `ocsf_logs`. The prevalence *columns* now exist (DDL done); the *filter field names* still need `udm_column_sql`.

**Verify (low coupling, probably fine):** `tree_view.rs` (1 ref), `funnel_view.rs` (0 refs) — confirm they only touch generic/passed-in fields. `lateral_graph.rs` is OK (consumes lateral.rs's aliased structs, no raw SQL).

---

## 4. Test-hardening pass (do after gaps closed)

The grind kept *existing* tests green but added little new coverage. Add:
1. **UDM byte-identical SQL snapshots** for every rewritten path (asset timeline/facets, dossier sections, lateral edges, field-values, anomaly/argmax, histogram) — assert the `UdmProfile` output is unchanged vs the literal-column version. This is the drift net.
2. **OCSF resolution units** — `udm_column_sql`/classification/prevalence column resolution per site.
3. **CH integration** (`ocsf_query_integration` / `ocsf_materialization`) — assert **each pipe command runs under OCSF without 500** and `prevalence_*` materializes with real numbers. NOTE: `ocsf_query_integration::ocsf_npl_queries_execute_against_fixtures` is **pre-existing red on the committed baseline** (`src_endpoint.ip count=0`) — isolate before trusting it.

**Lateral correctness nuance to test:** `auth_result→status_id` and `auth_type→auth_protocol_id` are **string→int** mappings. A value predicate like `auth_result='failure'` mapped column-only → `status_id='failure'` won't match (OCSF uses `2`). Confirm lateral/auth value predicates map values too, or accept under-detection.

---

## 5. Local-CH validation recipe (correctness, not scale)

- CH: `http://nanosiem:nanosiem@localhost:8123/` (runtime, read-only — DDL is **prohibited**); admin for DDL: `http://nanosiem_admin:nanosiem_admin_secret@localhost:8123/`. Force sync reads with `&...` settings (`async_insert` defaults ON locally → read-after-write lag).
- Search API: `:3002`, header `X-API-Key: -PopdJxnG9EY1P71Vt6XTcpuWOSLg6IJ8BZTwLKzY7Y` (may be rotated — ask if 401). `/api/search/explain` returns SQL without executing.
- **To make schema changes live:** recreate `nanosiem.ocsf_logs` from the updated `ocsf/init.sql` (it has the new `id`, sort key, prevalence cols, full-text index changes) + **rebuild the search/api binaries**. The user drives restarts.
- **Prevalence validation:** after recreate + reingest apache, confirm `prevalence_*` columns populate (non-65535) and the asset rare-process card shows real numbers.

---

## 6. Commit

Large batch (~30 files). Per CLAUDE.md pre-commit: run `/code-review-expert` (done once mid-session — clean, one P2 hardened), then commit. **Do NOT push without the user.** The vector `config/vector/**.toml` + lockfile changes in `git status` are **pre-existing local noise — do not stage** (per memory: ignore uncommitted vector parser .toml).

---

## 7. Gotchas (cost me time)

- `escape_identifier` uses **double quotes** (`"src_endpoint.ip"`), not backticks.
- `ocsf/init.sql` is **NOT** a checksummed migration — freely editable; CH has **no `ALTER TABLE IF EXISTS`** so OCSF-table ALTERs can't go in the shared `clickhouse/` numbered dir.
- `udm_column_sql` returns `None` for unmapped → **skip the field**, don't fall back to the literal (would 500). The one place using `unwrap_or_else(literal)` (lateral `req()`) is only for entity cols that always map.
- Enterprise build isn't in the merge gate; if you add `SchemaProfile` trait methods, the enterprise crate's impls (if any) need them too.

## Linear
- Epic **NAN-1241** (OCSF first-class schema).
- **NAN-1247** — dead text indexes (toString) — fixed this session.
- **NAN-1248** — profile-awareness audit (44 sites); the §3 gaps above are appended to it.
