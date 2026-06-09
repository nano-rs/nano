# OCSF Schema Support — Scoping

## 1. Executive Summary

**What the client wants.** A deployment where (a) they bring their own ClickHouse, (b) Vector is removed from the path entirely, (c) they push pre-parsed, pre-enriched data into their own CH using their own tooling, and (d) nanosiem acts purely as the query / detection / abstraction layer over data that is **stored natively in OCSF**. nanosiem is no longer the ingestion or enrichment owner; it is the read/detect plane over a schema it did not write.

**Core architectural insight (LOCKED).** OCSF is not a translation target. The product decision is that **the schema itself becomes a pluggable abstraction**, with UDM and OCSF as two concrete implementations that coexist. Today the entire stack hard-codes the proposition *"schema == the UDM constants"*: a build-time-generated `UdmField` enum (`nanosiem-core/src/udm/fields.rs`, generated from `nanosiem-core/docs/udmfields.csv`), `const EXPLICIT_COLUMNS` / `MATERIALIZED_COLUMNS` / `PREWHERE_FIELDS` / `NUMERIC_UDM_FIELDS` / `LOWERCASE_NORMALIZED_FIELDS` / `UUID_FIELDS` arrays in `nanosiem-core/src/query/clickhouse_sql_gen.rs`, and a parallel hard-coded `UDM_COLUMNS` set in `nanosiem-web/src/lib/udm-fields.ts`. The work is to lift that implicit single schema into an explicit `SchemaProfile` trait/registry that the SQL generator, field-stats, detection engine, and frontend all consult — with `UdmProfile` (today's behavior, byte-for-byte) and `OcsfProfile` as the first two implementations. This is **not** a runtime field-name translation layer; OCSF data is queried and detected on *as OCSF*, its native field universe resolving to its native CH column/path layout.

**The client's contract is "emit standard OCSF" — nothing more. Our table is standard-OCSF storage, indexed server-side.** OCSF is a *logical event schema* (classes, nested objects, arrays); it does not dictate a ClickHouse physical layout. So the contract with the client is simply: **produce OCSF-compliant JSON events** (which any modern parser/pipeline can target). They insert the full OCSF record into a single `event JSON` column. We then own the *physical* schema (`clickhouse/ocsf/init.sql`): we derive it mechanically by mapping the full OCSF 1.x dictionary against our UDM field set (Appendix §5), and **every OCSF path that corresponds to an indexed UDM field is promoted to a `MATERIALIZED` scalar column extracted from `event`, with the same bloom/skip-index + PREWHERE + `_search` treatment UDM gives its hot fields.** ClickHouse computes these at insert time on *any* insert, so the client's plain OCSF write lands fully indexed with **zero extra cooperation** — they never see or populate the promoted columns (they're `MATERIALIZED`, not `DEFAULT`). The long tail of OCSF attributes stays in `event` and resolves via `JsonPath` — the OCSF analog of UDM's `ext`. We do **not** reverse-engineer an arbitrary client layout or rely on runtime introspection to decide what's fast; the promotion/indexing is our invisible implementation detail. This makes `OcsfProfile` a **static, build-time-generated profile** (like `UdmProfile`), and it guarantees OCSF queries hit indexes by construction. *If they map their logs to proper OCSF, it just comes over — correctly and fast.*

**A useful consequence: `_search` materialized columns work in OCSF mode.** `_search` columns (`lower()`/tokenized) are self-contained ClickHouse `MATERIALIZED` expressions — CH computes them at insert time regardless of *who* inserts. So if we define `cmd_line_search`, `process_path_search`, `observables_search`, etc. in the canonical OCSF DDL, the client's direct insert populates them automatically, and `hasToken()` full-text hunts work natively. This is distinct from how UDM **enrichment** is computed: UDM `enriched_*`/`ioc_*` rely on `dictGet` against dictionaries *we* provision during *our* ingestion via `MATERIALIZED` columns. **OCSF enrichment is DUAL-MODE** (refined in Phase 0 / NAN-1242 — supersedes the earlier "read-only" framing): enrichment lives in **OCSF-native fields** (`src_endpoint.location.*`, `src_endpoint.autonomous_system.*`, `cloud.*`, the `enrichments[]` array) and we promote indexed dotted columns from them *regardless of who computed them*. When nano owns ingestion (open-core + Vector) nano computes geo/ASN/IOC and writes them into those standard OCSF objects before the row lands; when the client ships pre-enriched OCSF the same native fields are already present. Either way the promoted columns materialize from native OCSF and are indexed (bloom/set/text) for parity with UDM's `enriched_*`/`ioc_*` footprint. The `enrichments[]` array is selected **by name**: each entry's `name` is the UDM column it corresponds to (e.g. an entry named `ioc_src_ip_threat_type`), pulled via `arrayFirst(e -> name = '<udm>', enrichments).value`. The profile declares which enrichment paths exist and how to read them; computation (when nano owns ingestion) is a Vector/open-core concern, not a query-layer one.

**Rough total effort: XL** (multi-quarter epic). The seam itself is mechanical but pervasive (4 backend layers + frontend, ~600+ hard-coded field references, two const-array clusters, a generated enum). The genuinely hard parts are nested-path resolution in nPL→SQL, OCSF arrays (`file.hashes[]`), the enum+sibling pattern, and detection's hard-coded entity-extraction priority lists. Frontend is L. Detection is M. Query-gen + schema-core are each XL.

---

## 2. The Schema-Abstraction Design

### 2.1 Where the "schema = UDM constants" assumption lives today

The single-schema assumption is not in one place — it is replicated as compile-time data and inlined branching across five surfaces:

| Surface | Hard-coded artifact | File |
|---|---|---|
| Field universe (build-time enum) | `UdmField` enum, `column_name()`, `category()`, `data_type()` generated from CSV | `nanosiem-core/build.rs`, `nanosiem-core/docs/udmfields.csv`, `nanosiem-core/src/udm/fields.rs` |
| Column routing (query) | `EXPLICIT_COLUMNS` (216 names), `MATERIALIZED_COLUMNS` (14), `is_explicit_column()` | `nanosiem-core/src/query/clickhouse_sql_gen.rs` (lines ~61–378) |
| Field typing / optimization | `NUMERIC_UDM_FIELDS`, `LOWERCASE_NORMALIZED_FIELDS`, `UUID_FIELDS`, `PREWHERE_FIELDS` | `nanosiem-core/src/query/clickhouse_sql_gen.rs` + `clickhouse_sql_gen/helpers.rs` |
| Field aliasing | `normalize_field_name()` 40+ alias match (`sourcetype→source_type`, `hostname→host`) | `nanosiem-core/src/query/clickhouse_sql_gen/helpers.rs` |
| Default view + analysis | hard-coded table-view summary fields; `analyze_required_fields()` | `nanosiem-core/src/query/clickhouse_sql_gen/field_analysis.rs` |
| WHERE/PREWHERE dispatch | `is_udm_field()` + `is_explicit_column()` choosing direct-column vs `ext.*`; `generate_json_extract()` (metadata-prefix only) | `nanosiem-core/src/query/clickhouse_sql_gen/search_expr.rs` |
| Identity resolve | `IDENTITY_COLUMN_FIELDS`, `IDENTITY_DICT_ONLY_FIELDS`, `resolve_identity_join_col()` | `nanosiem-core/src/query/clickhouse_sql_gen/identity.rs` |
| Detection entity extraction | identical hard-coded priority lists (`src_ip, dest_ip, src_user, user, file_hash, ...`) in three places | `nanosiem-core/src/detection/service/helpers.rs`, `nanosiem-core/src/detection/risk/calculator.rs`, `nanosiem-core/src/detection/materialized_view.rs` |
| DDL field validation | `field.parse::<UdmField>().is_ok()` allowlist | `nanosiem-core/src/detection/materialized_view.rs` (~line 49) |
| Field stats fallback | hard-coded 15-field fallback; table-view summary fields | `nanosiem-core/src/search/service/field_queries.rs`, `nanosiem-core/src/search/execution/clickhouse_executor/field_stats.rs` |
| Frontend | `UDM_COLUMNS` (518), `ENRICHED_FIELDS`/`IOC_FIELDS`/`COMPUTED_FIELDS`, prefix-regex `getFieldCategory()`, `FIELD_TO_ENTITY_TYPE` | `nanosiem-web/src/lib/udm-fields.ts`, `query-tokens.ts`, `query-autocomplete.ts`, `components/search/*`, `components/editor/{query,detection}-language.ts` |

### 2.2 The seam: `SchemaProfile`

Introduce a new crate module `nanosiem-core/src/schema/` exposing a `SchemaProfile` trait. Every const array and generated-enum lookup above is replaced by a method call against the **active profile**, which is passed (by `Arc<dyn SchemaProfile>`) into `ClickHouseSqlGenerator`, `SearchService`, `DetectionService`, and `MaterializedViewGenerator` at construction. The trait is the contract that `UdmProfile` and `OcsfProfile` both satisfy.

The profile must expose (at minimum):

```rust
pub trait SchemaProfile: Send + Sync {
    fn id(&self) -> SchemaId;                       // Udm | Ocsf

    // --- Field universe & resolution ---
    /// All queryable canonical field names (replaces UDM_COLUMNS / EXPLICIT_COLUMNS).
    fn fields(&self) -> &[FieldDef];
    /// Resolve an nPL field token to its physical CH location. THE CORE METHOD.
    fn resolve(&self, npl_field: &str) -> FieldResolution;
    /// Schema-specific aliases (sourcetype->..., user->...). Replaces normalize_field_name.
    fn canonicalize(&self, npl_field: &str) -> Cow<str>;
    /// Validate a field name is known (replaces UdmField::from_str allowlist for DDL).
    fn is_known_field(&self, name: &str) -> bool;

    // --- Typing & query optimization hints ---
    fn field_type(&self, field: &str) -> Option<FieldType>;       // string/ip/int/uuid/ts/bool
    fn is_lowercased_at_ingest(&self, field: &str) -> bool;       // skip lower() wrapper
    fn prewhere_fields(&self) -> &[String];                       // indexed/PREWHERE-eligible
    fn materialized_columns(&self) -> &[String];                  // re-add to CTE SELECTs

    // --- _search columns ---
    fn search_column_for(&self, field: &str) -> Option<String>;   // e.g. cmd_line -> cmd_line_search
    fn search_columns(&self) -> &[String];

    // --- Categorization / UX (drives both LLM context and frontend) ---
    fn category(&self, field: &str) -> FieldCategory;             // network/process/identity/enrichment/ext...
    fn entity_type(&self, field: &str) -> Option<EntityType>;     // ip/host/user/hash/domain/...
    fn default_table_fields(&self) -> &[String];                  // table-view summary
    fn priority_fields(&self) -> &[String];                       // pinned in FieldsPanel

    // --- Detection semantics ---
    /// Semantic-role -> physical field, in priority order. Replaces the 3 hard-coded lists.
    fn entity_extraction_order(&self) -> &[(EntityRole, String)];
    fn risk_entity_default(&self) -> Option<&str>;

    // --- Enrichment ownership ---
    /// In OCSF mode this returns Read (client materialized it); in UDM mode Materialized (we compute).
    fn enrichment_mode(&self) -> EnrichmentMode;
    fn enrichment_field(&self, semantic: EnrichmentKind) -> Option<FieldResolution>;

    // --- Storage binding ---
    fn table_name(&self) -> &str;                                 // nanosiem.logs vs <client>.ocsf_events
    fn timestamp_expr(&self) -> &str;                             // timestamp vs fromUnixTimestamp64Milli(time)
}
```

The pivotal type is `FieldResolution`, which is what makes OCSF's nesting tractable without translating to UDM:

```rust
pub enum FieldResolution {
    ExplicitColumn(String),            // direct CH column (UDM src_ip; OCSF if flattened to a column)
    JsonPath { col: String, path: Vec<String> },  // JSONExtract(col, 'a','b','c') for OCSF nested paths
    ArrayElement { col: String, path: Vec<String>, key_attr: String, key_val: i64, value_attr: String },
                                       // file.hashes[] where algorithm_id=3 -> value
    Alias(String),                     // action AS event_type
    Unknown,                           // falls to ext / unmapped
}
```

`UdmProfile::resolve` returns `ExplicitColumn` for the 216 known names, `Unknown→ext.*` otherwise — **identical to today's `is_explicit_column()` behavior**, so UDM regression risk is contained. `OcsfProfile::resolve` returns `ExplicitColumn` for promoted/flattened paths the client stored as columns, `JsonPath`/`ArrayElement` for fields they left nested in a CH `JSON`/`String` column, and honors the enum+sibling pattern (a query on `activity` resolves to the `_id` integer column for PREWHERE *and* its sibling string for display).

### 2.3 How the abstraction provides each thing the prompt asks about

- **Field/column universe** → `fields()` + `resolve()`. The codegen for `OcsfProfile` is data-driven: a new build-time input (`nanosiem-core/docs/ocsf/<version>/*.json`, sourced from `schema.ocsf.io` dictionary + class defs) generates an OCSF field registry the way `build.rs` generates `UdmField` from the CSV today. **Keep the UDM CSV generator intact**; add a parallel OCSF generator rather than fusing them.
- **`_search` column derivation** → `search_column_for()` / `search_columns()`. UDM keeps `message_search`, `process_path_search`, `url_search`. OCSF declares its own (`cmd_line_search`, `process_path_search`, plus an `observables_search` fed by `observables[].value`) **as `MATERIALIZED` columns in the canonical OCSF DDL** — CH computes them on the client's direct insert, so full-text hunts work without our ingestion path. Per repo memory **NAN-1155**, any new materialized `_search` column must be registered in all of: `EXPLICIT_COLUMNS`, `MATERIALIZED_COLUMNS`, table-view struct, `UDM_COLUMNS` frontend set, and the frontend identity categorizers — under the new design those five lists become *profile-derived*, which is the whole point of the seam.
- **PREWHERE / indexed-field hints** → `prewhere_fields()` + `field_type()` + `is_lowercased_at_ingest()`. `generate_settings()` and `extract_prewhere_conditions()` stop reading the `PREWHERE_FIELDS` const and instead ask the profile. OCSF's indexable set is the taxonomy ints (`class_uid`, `type_uid`, `severity_id`) + the promoted endpoint columns.
- **Field categorization / grouping** → `category()` + `entity_type()`. This single source replaces the duplicated 9-tier `getFieldCategory()` prefix-regex logic across `PaginatedTable.tsx`, `SearchResults.tsx`, `EventInspectorPanel.tsx`, `AssetView.tsx`, and the LLM `udm_context.rs` iteration over `UdmField::by_category()`.
- **Default table-view fields** → `default_table_fields()`, consumed by `field_analysis.rs` and `field_queries.rs` instead of the literal `src_host, src_ip, dest_host, …` list.
- **nPL token → physical column/path** → `resolve()`. The nPL parser (`nanosiem-core/src/query/parser.rs`) stays schema-agnostic (field names are opaque strings — good, no change). Resolution happens at SQL-gen time. For OCSF this is where `JsonPath`/`ArrayElement` get emitted as `JSONExtractString(event, 'actor','process','cmd_line')` etc. — and `generate_json_extract()` (today metadata-prefix only) must be generalized to N-level paths.

### 2.4 How a deployment selects its active schema

**Recommendation: per-deployment, single active schema, chosen at boot from configuration (env var + persisted `system_settings` row), with the CH table validated against it at startup.** Rationale:

- The client's deployment *is* an OCSF deployment end-to-end — they own one CH, one storage schema. A per-source or mixed model multiplies the surface (dual table routing, schema-version columns, "tenant A expects `src_ip` but table is OCSF" silent-correctness bugs called out in the ch-schema risks) for zero analyst benefit here.
- Selection mechanism: `NANO_SCHEMA_PROFILE=udm|ocsf` resolved at boot → constructs the `Arc<dyn SchemaProfile>` injected everywhere. Persist the choice in `system_settings` so the API/frontend can report it; **fail fast at boot** (consistent with the DualPool fail-fast philosophy, NAN-800) if the active profile's required columns/table are absent — run a `DESCRIBE TABLE` probe against the configured table and assert the profile's `prewhere_fields()` + key columns exist.
- Frontend learns the active schema from a new endpoint **`GET /api/schema/fields`** (parameterized/aware of active profile), replacing the UDM-specific `/api/udm/fields`. The frontend hydrates its field universe at app startup before rendering Search/RuleEditor/Dashboard.
- Leave a forward door for per-source later (the trait is already keyed by `SchemaId`), but **do not build it now**.

**Dotted OCSF column names + the "event-as-spill, drop-it-in" model (Phase 0 / NAN-1242, LOCKED).** Promoted ClickHouse columns use the **literal dotted OCSF field name** as the column name — `src_endpoint.ip`, `dst_endpoint.port`, `actor.process.cmd_line`, `user.name`, `cloud.account.uid` — *not* an underscore-flattened alias. ClickHouse supports dotted top-level column names when backtick-quoted; they index fine and do not collide with the `event` JSON subcolumns (verified on CH 26.4). Conventions: a real OCSF scalar → its literal dotted path; an array-derived value with no scalar OCSF path (selected from `file.hashes[]`, `answers[]`, `email.to[]`, `vulnerabilities[]`, `enrichments[]`) → `<path>.<derived>` (e.g. `file.hashes.sha256`, `answers.rdata`, `vulnerabilities.cve.uid`, `enrichments.<udm_name>`); a `_search` companion → the base path with a `.search` **suffix** (`actor.process.cmd_line.search`); enum siblings already top-level OCSF (`activity_id`/`activity`, `severity_id`/`severity`, `status_id`/`status`) stay as-is. The mental model is **drop-it-in**: a user drops a standard OCSF record into the single `event` JSON column, the matching dotted columns MATERIALIZE out of it, and the unmapped nested tail stays in `event` — the **spill**. This is the OCSF analog of UDM's `ext`, but the contrast matters: in UDM a Vector VRL pipeline *we own* parses raw logs into flat `.udm.*` fields and dumps leftovers into `ext`; in OCSF there is no per-source parse to own — the emitter (client, or nano in open-core ingestion) produces a whole standard OCSF object and the promoted columns derive mechanically from the standard shape. We still MUST materialize typed columns (not just read the JSON subcolumns) because JSON subcolumns are `Dynamic`-typed and cannot carry bloom/text skip indexes (verified: "Unexpected type Dynamic of bloom filter index").

**Storage shape (we own it; client just sends OCSF JSON).** OCSF mode targets a **canonical nanosiem-authored OCSF table** — one wide `MergeTree`: a single `event JSON` column holding the complete standard OCSF record (what the client inserts), plus ~30–45 `MATERIALIZED` scalar columns extracted from `event` (every OCSF path that maps to an indexed UDM field per Appendix §5) with bloom/skip indexes + PREWHERE eligibility on the same hot fields UDM indexes, `MATERIALIZED` `_search` columns, and the taxonomy ints (`class_uid`/`type_uid`/`severity_id`) as indexed materialized columns. (Ordering-key columns like `timestamp` are the one place a value may need to be inserted or `DEFAULT`-derived rather than `MATERIALIZED`, since CH restricts `MATERIALIZED` columns in the sort key — resolve in Phase 0.) We ship this as `clickhouse/ocsf/init.sql`; the *only* load contract is "valid OCSF into `event`." Because the layout is fixed and known, `OcsfProfile` is **statically generated at build time** (`resolve()` returns `ExplicitColumn` for promoted paths, `JsonPath`/`ArrayElement` for the tail) — no runtime `system.columns` introspection drives correctness. The boot-time `DESCRIBE TABLE` probe is then a *validation* step (assert the client's table matches our canonical DDL and fail fast on drift), not a discovery step.

---

## 3. Subsystem-by-Subsystem Impact

| Subsystem | Coupling mechanism | What changes | Effort | Key risks |
|---|---|---|---|---|
| **schema-core / UDM field defs** (`udm/fields.rs`, `build.rs`, `udmfields.csv`, `udm/validation.rs`, `udm_context.rs`) | Build-time `UdmField` enum + category/type inference; validation matches on generated `UdmDataType` | New `schema/` module + `SchemaProfile` trait; `UdmProfile` wraps existing generated data unchanged; new build-time OCSF registry generator from `docs/ocsf/*.json`; validation depends on `profile.field_type()` | **XL** | Enum baked into binary; OCSF needs parallel codegen, not a second enum fused in; validation injection risk if OCSF field names are untrusted in DDL |
| **query-langgen** (`clickhouse_sql_gen.rs` + `helpers.rs`/`search_expr.rs`/`field_analysis.rs`/`identity.rs`/`commands.rs`/`aggregation.rs`/`eval_functions.rs`) | `EXPLICIT_COLUMNS`/`MATERIALIZED_COLUMNS`/`PREWHERE_FIELDS`/`NUMERIC_UDM_FIELDS`/`LOWERCASE_NORMALIZED_FIELDS`/`UUID_FIELDS` consts; `is_explicit_column()`; `normalize_field_name()`; `generate_json_extract()` metadata-only | Thread `Arc<dyn SchemaProfile>` through generator; replace every const lookup with profile method; generalize `generate_json_extract()` to N-level OCSF paths; `expand_wildcard_pattern()` matches `profile.fields()` | **XL** | Hot-path `is_explicit_column()` called per field-ref — must stay O(1) (precompute `HashSet` in profile, `Arc`); a single missed reference silently routes an OCSF field to `ext` instead of erroring; OCSF nested-path JSONExtract loses bloom/skip-index pruning unless those paths are promoted to columns |
| **ch-schema** (`clickhouse/init.sql`, prevalence tables, dicts, 13 MVs) | 75+ explicit columns + 31 `MATERIALIZED` enrichment cols + dicts keyed on flat names + 13 MVs referencing UDM cols | OCSF mode: **separate table the client owns** (e.g. `<db>.ocsf_events`); `profile.table_name()` selects it; no nanosiem `MATERIALIZED`/dict/MV provisioning in OCSF mode (out of scope — client owns ingestion) | **XL** (mostly *removal*/non-provisioning for OCSF) | OCSF event_class multiplicity vs single search stream — solve with one wide table + JSON column for class-specific tail, **not** per-class tables; nested arrays (`hashes[]`); we do not control the client's column layout, so the profile must be *configurable* to their actual flattening |
| **ingestion** (`ingestion/parser.rs` `ParsedLog`, `ingestion/row.rs`, Vector `_pipeline.toml`) | `ParsedLog` 25 hard-coded `Option<String>` fields; VRL emits `.udm.*`; UDM mapped to CH cols | **Largely N/A for the client** — Vector skipped, client writes CH directly. nanosiem's own internal/audit writes still use UDM `ParsedLog`. No OCSF ingestion path needed in nanosiem | **S** (for OCSF) | Don't accidentally couple OCSF read-path to `ParsedLog`; confirm no detection/audit write assumes the OCSF table shape |
| **search-fieldstats** (`search/service/field_queries.rs`, `clickhouse_executor/field_stats.rs`, `types.rs`) | 15-field fallback; table-view 13-field list; `get_table_columns()` name-pattern filters; heuristic type detect; `nanosiem.logs` hard-coded | `profile.default_table_fields()` + `profile.table_name()`; fallback list from profile; column-introspection filters parameterized (OCSF may not use `prevalence_*`/`_search` naming); `get_ext_field_names` → profile's overflow column (`unmapped`/`raw_data` vs `ext`) | **L** | Fallback to UDM 15 fields on introspection failure silently degrades OCSF; `distinctJSONPaths(ext)` assumes `ext` — OCSF overflow may be `unmapped`; table name hard-coded to `nanosiem.logs` breaks all stats |
| **detection** (`service/helpers.rs`, `risk/calculator.rs`, `materialized_view.rs`, `prevalence.rs`, `signal_processor.rs`) | 3× identical hard-coded entity-priority lists; `auto_detect_risk_entity()`; `validate_ddl_field_name()` via `UdmField`; prevalence `file_hash`/`dest_host` static map | Replace 3 lists with `profile.entity_extraction_order()`; `auto_detect_risk_entity()` + `validate_ddl_field_name()` take profile; prevalence field map → `profile.enrichment_field()`/semantic lookup | **M** | Entity extraction silently falling back to `"unknown"` if OCSF names don't match → meaningless risk scores, no error surfaced; real-time MV DDL validation rejecting OCSF fields forces scheduled-mode fallback; SQL-injection allowlist must be re-derived safely from profile, not loosened |
| **enrichment** (`enrichment/service.rs`, `init.sql` `MATERIALIZED`/dicts, `enrichment/types.rs`) | `lookup_ips_bulk()` hard-codes 8 attrs; 40+ `MATERIALIZED` cols; dicts keyed on flat names | OCSF mode: **read-only enrichment** — `profile.enrichment_mode() == Read`; map `enriched_*` UX concepts onto OCSF's `enrichments[]`/`src_endpoint.location.*`/`cloud` paths via `profile.enrichment_field()`; disable IP-sync/marketplace scheduler arms for OCSF | **XL→L** (much is disablement) | If we don't own ingestion, our IP/IOC sync is a no-op — must not break boot or schedulers; reading client enrichment from arrays/nested objects loses the `MATERIALIZED` perf; prevalence indicators blind to client-side prevalence |
| **API** (`handlers/fields.rs`, `openapi.rs`) | `UdmField`-typed path parsing; `get_udm_field_values/stats` | Parameterize to active profile; new `/api/schema/fields`; OpenAPI annotations + `verify_openapi` path-count bump per CLAUDE.md | **M** | OpenAPI path-count assertion; API contract change cascades to frontend |
| **frontend** (`udm-fields.ts`, `query-tokens.ts`, `query-autocomplete.ts`, `FieldsPanel.tsx`, `PaginatedTable.tsx`, `EventInspectorPanel.tsx`, `SearchResults.tsx`, `AssetView.tsx`, editor `*-language.ts`, enterprise `CaseAlertsSheet.tsx`, `templateGrammar.ts`) | `UDM_COLUMNS`(518), prefix-regex categorizers ×5, `FIELD_TO_ENTITY_TYPE`, CodeMirror `UDM_FIELD_NAMES`, hard-coded drilldowns/fallbacks | Fetch field metadata from `/api/schema/fields` at startup into a SchemaContext; unify duplicated `getFieldCategory()` into metadata-driven lookup; categorization/entity-type/priority/color from `field.metadata`; CodeMirror tokenizers init from context; generic drilldown `(field,value)` | **L** | 5 divergent local copies of `getFieldCategory()` risk drift; blank field panels if OCSF priority fields not provided; OCSF frontend work stays open-core (SchemaContext lives in the open edition), so no new `@/enterprise/*` import / NAN-1190 stub is introduced |

---

## 4. The Hard Problems / Biggest Risks

1. **Hard-coded column lists are the load-bearing wall, and they're duplicated.** The same field universe is encoded as: the `UdmField` enum, six const arrays in `clickhouse_sql_gen.rs`, the field-stats fallback list, three detection priority lists, and the frontend `UDM_COLUMNS`. The seam only pays off if *all* of these read from one profile; any holdout silently misroutes OCSF fields to `ext`/`unmapped` with no error (memory: `ext` misses are silent — `feedback_ext_json_field_tostring_null`). Mitigation: make `resolve()` return `Unknown` loudly in a strict mode and add a "no field silently fell to ext" test against a real OCSF sample.

2. **Generated SQL + nPL field resolution against nested OCSF paths.** `generate_json_extract()` in `search_expr.rs` today only handles a `metadata_` prefix and single-dot notation. OCSF needs true N-level path extraction (`actor.process.parent_process.cmd_line`) for the long-tail attributes that live in the `event JSON` column. This is genuinely new code, error-prone, and untested (no OCSF fixtures exist in the repo). JSONExtract on the tail defeats bloom/skip-index pruning — **but this is now bounded, not open-ended**: because we own the canonical schema (§2.4) and promote every UDM-indexed-equivalent path to a real column, the hot fields analysts hunt on (IP, hash, cmd_line, user, taxonomy ints) are `ExplicitColumn` + indexed *by construction*. JSONExtract is reserved for the genuinely rare long tail, where slow is acceptable. Per repo memory, still validate the promoted-column index strategy + any `_search` path **at demo scale, not local 2M-row CH** (`feedback_local_ch_validates_correctness_not_scale`).

3. **OCSF arrays — `file.hashes[]` / `observables[]`.** A single file carries MD5+SHA1+SHA256 as array elements keyed by `algorithm_id`. There is no scalar `file_hash` in OCSF. `FieldResolution::ArrayElement` must emit `arrayFirst`/`arrayFilter` over the path picking the chosen `algorithm_id`. `observables[]` is a gift — a pre-flattened entity/IOC index — and should feed an `observables_search` materialized/`Array(String)` column so existing `hasToken()` hunts work; but materializing it depends on the client having stored it, which we don't control.

4. **Enum + sibling pattern.** Every classified OCSF field is `_id` (int, 0=Unknown, 99=Other) + sibling string. The profile must resolve a user's `activity=...` to the int column for exact/PREWHERE filtering *and* the sibling string for display and case-insensitive search, and honor `Other(99)→custom label`. nPL queries like `severity=high` need profile-driven enum-name→id resolution.

5. **Detection rule field references.** Detection rules are stored as nPL text and compiled at execution. The three identical entity-extraction priority lists (`detection/service/helpers.rs`, `risk/calculator.rs`, `materialized_view.rs`) silently default to `"unknown"` on a miss — so an OCSF deployment would produce meaningless risk scores with no error. `validate_ddl_field_name()`'s `UdmField` allowlist (the SQL-injection guard) must be re-derived from `profile.is_known_field()` *without* loosening into an injection vector. Real-time MVs in OCSF mode reference the client's table/columns — DDL generation must be fully profile-parameterized or rules silently fall back to scheduled mode.

6. **Enrichment ownership when we don't own ingestion.** This is the conceptual crux. Today enrichment is nanosiem-computed via CH `MATERIALIZED` columns + dicts at insert time. In OCSF mode the client ingests directly into their CH — nanosiem has **no insert hook**, so `MATERIALIZED` enrichment cannot run. Enrichment becomes **read-only**: the UI's `enriched_src_country`/`ioc_*` concepts must map onto OCSF's inline `enrichments[]`, `src_endpoint.location.country/asn`, `cloud` objects via `profile.enrichment_field()`. IP-sync, marketplace feeds, and prevalence aggregation are **disabled** for OCSF (and must not panic a scheduler — memory: a `nanosiem-jobs` panic aborts *all* background schedulers, `reference_workers_ai_credential_less_and_jobs_panic_blast_radius`). Prevalence indicators will be blind unless the client populated equivalents.

7. **No OCSF fixtures / test harness exists.** Everything above is untested against real OCSF. Building `OcsfProfile` requires pulling OCSF 1.8.0 class/dictionary JSON and a representative event corpus. Per memory `feedback_compile_test_generated_vrl`/NAN-667, add compile/regression tests for any static OCSF mapping templates since Rust can't see inside string literals.

---

## 5. Appendix — OCSF ⇄ UDM Field Mapping (reference for `OcsfProfile` authors)

> This is **reference material for engineers implementing `OcsfProfile`** (what UDM concept each OCSF path corresponds to, for parity in UI labels, detection semantics, and the field categorizer). It is **not** a translation feature — OCSF data is queried as OCSF. **This table is also the promotion list:** every OCSF path below becomes a *promoted explicit column* in the canonical OCSF DDL (`clickhouse/ocsf/init.sql`), indexed/PREWHERE-eligible to match its UDM counterpart; paths *not* in this table stay in the `event JSON` tail and resolve via `JsonPath`. OCSF `time` is epoch **milliseconds**; convert with `fromUnixTimestamp64Milli` and never compare a raw ms int to a `DateTime64` (coerces as seconds — NAN-1123).
>
> **NOTE (Phase 0 / NAN-1242):** the live, authoritative promotion list is now the manifest `nanosiem-core/docs/ocsf/1.8.0/udm_ocsf_mapping.json` (43 → **75 entries / 74 distinct columns: 73 promoted physical + the `time_dt` logical alias**), gated against the DDL by `tests/ocsf_manifest_ddl_consistency.rs`. The CH column name for each promoted path is the **literal dotted OCSF path** (e.g. `src_endpoint.ip`), not the underscore-flattened name shown for readability below. The table below is kept as conceptual UDM↔OCSF reference; the manifest is the source of truth and also expanded the indexed footprint to UDM parity (DNS 4003, HTTP 4002, Email 4009, cloud, MACs, geo/ASN, IOC/custom `enrichments[]`). Two corrections vs the original table: the full URL is **`url.url_string`** (OCSF 1.8.0 has no `url.text`), and `location.country` is the **ISO Alpha-2 code** (maps to `enriched_*_country_code`, not the country name).

| OCSF (native path) | UDM concept | Notes for profile impl |
|---|---|---|
| `class_uid`, `category_uid`, `activity_id`, `type_uid` (+ `*_name`/`activity`) | `source_type` + event-kind | Numeric taxonomy replaces `source_type`. Promote all to explicit int columns; `type_uid = class_uid*100 + activity_id` is most specific (`300201` = Authentication: Logon). PREWHERE/bloom-friendly. |
| `time` (timestamp_t, epoch ms) | `timestamp` | `fromUnixTimestamp64Milli(time)`. |
| `metadata.modified_time` | — | secondary time. |
| `src_endpoint.ip` | `src_ip` | initiator. |
| `dst_endpoint.ip` | `dest_ip` | responder. |
| `src_endpoint.port` / `dst_endpoint.port` | `src_port` / `dest_port` | direct. |
| `src_endpoint.hostname` / `device.hostname` | `src_host` | `device` = host context (Host profile). |
| `dst_endpoint.hostname` | `dest_host` | direct. |
| `actor.user.name` (or `user.name` in IAM) | `user` | **class-aware**: System Activity → `actor.user.name`; Authentication 3002 subject → `user.name`, initiator → `actor.user.name`. |
| `actor.process.name` | `process_name` | Process Activity 1007 target → `process.name`. |
| `actor.process.cmd_line` | `command_line` | OCSF uses `cmd_line`. |
| `actor.process.parent_process.cmd_line` | `parent_command_line` | nested parent. |
| `actor.process.file.hashes[]` (Fingerprint{`algorithm_id`,`value`}) | `process_hash` | **array**; pick `algorithm_id`=SHA-256. |
| `file.name` / `file.path` | file name / `file_path` | `file.path` ≈ `file_path`. |
| `file.hashes[]` where `algorithm_id`=SHA-256 → `.value` | `file_hash` | **array** flatten. |
| `activity_id`/`activity` on File System 1001 | `file_action` | action encoded as activity enum. |
| `connection_info.protocol_num` / `network_protocol` | `protocol` | string ≈ UDM `protocol`. |
| `traffic.bytes_in` / `traffic.bytes_out` | `bytes_in` / `bytes_out` | nested; `packets_in/out` also. |
| `auth_protocol_id`/`auth_protocol` (Auth 3002) | `auth_type` | enum+sibling (2=Kerberos, 5=SAML, 6=OAuth2.0). |
| `status_id`/`status` (1=Success,2=Failure) | `auth_result` / outcome | generic outcome. |
| `session.uid` | `session_id` | session object. |
| `message` / `raw_data` | `message` | `raw_data` = unparsed; `message` = human-readable. |
| `enrichments[]` (by name), `src_endpoint.location.{country,continent}`, `src_endpoint.autonomous_system.{number,name}`, `cloud.{provider,region,account.*}` | `enriched_src_country_code`/`enriched_src_asn`/`ioc_*`/`custom_*`/`cloud_*` | **DUAL-MODE** (NAN-1242) — lives in OCSF-native fields; promoted + indexed whether nano computed it (open-core ingestion) or the client shipped it pre-enriched. `enrichments[]` selected by `name = '<udm col>'`. `location.country` is the ISO code → `*_country_code`. |
| `observables[]` {`name`,`value`,`type_id`} | (no single col) entity/IOC index | feed `_search`/`Array(String)`; free pivot index. |
| `unmapped` + non-promoted nested attrs | `ext` | OCSF's own overflow concept = our `ext`. |

---

## 6. Phased Delivery Plan

**Epic: "OCSF as a first-class alternate schema (pluggable SchemaProfile)"** — Linear team Nanos-sh. Target effort XL / multi-quarter. Suggested issue-sized phases:

**Phase 0 — Spec, canonical DDL & fixtures (NAN-xxx, M).** Vendor the full OCSF 1.8.0 dictionary + class JSON into `nanosiem-core/docs/ocsf/1.8.0/`. **Author the canonical OCSF ClickHouse schema (`clickhouse/ocsf/init.sql`)** by mapping the OCSF dictionary against our UDM field set (Appendix §5): a single `event JSON` column for the standard OCSF record, plus a `MATERIALIZED <col> ... JSONExtract(event, ...)` promoted column for every OCSF path that maps to an indexed UDM field — with matching bloom/skip-index + PREWHERE treatment — plus `MATERIALIZED` `_search` columns and taxonomy ints. Resolve the sort-key/`timestamp` column strategy (CH can't put `MATERIALIZED` columns in ORDER BY). Assemble a representative multi-class event corpus (Auth 3002, Network 4001, Process 1007, File 1001), inserting **only `event` JSON** to prove the materialized columns + indexes populate from a plain OCSF write. The load contract is just "valid OCSF JSON" — it does not depend on the client. *Open-core* (schema data is public).

**Phase 1 — `SchemaProfile` trait + `UdmProfile` (NAN-xxx, XL).** Create `nanosiem-core/src/schema/`; define the trait + `FieldResolution`. Implement `UdmProfile` wrapping today's generated data/consts. **No behavior change** — pure extraction, gated by a full regression of existing query/detection tests. This is the riskiest-to-get-wrong, lowest-visible-value phase; do it first and prove byte-identical UDM SQL. *Open-core.*

**Phase 2 — Thread the profile through query-langgen (NAN-xxx, XL).** Inject `Arc<dyn SchemaProfile>` into `ClickHouseSqlGenerator`; replace all six const-array lookups + `normalize_field_name` + `is_explicit_column` + field-stats fallbacks with profile calls; generalize `generate_json_extract()` to N-level paths; `expand_wildcard_pattern()` over `profile.fields()`. Still UDM-only at runtime; verifies the seam carries SQL correctly. *Open-core.* **⚠️ Dotted-column escaping (deferred from Phase 0 / NAN-1242): the generator's `escape_identifier` must backtick dotted OCSF column names** — today it does not need to because UDM columns are bare `snake_case`, but OCSF promoted columns are literal dotted paths (`src_endpoint.ip`, `actor.process.cmd_line`) that ClickHouse parses as tuple/sub-column access unless backtick-quoted. Every place the generator emits a column reference (SELECT, WHERE/PREWHERE, ORDER BY, skip-index hints, `_search` companions) must quote a profile-declared dotted `ExplicitColumn`. This is data/SQL-correct in the Phase 0 DDL/tests already; the Rust generator change lands here.

**Phase 3 — Boot-time schema selection + `/api/schema/fields` (NAN-xxx, M).** `NANO_SCHEMA_PROFILE` env + `system_settings` persistence; boot-time `DESCRIBE TABLE` validation/fail-fast; parameterized `table_name()`/`timestamp_expr()`; new API endpoint with OpenAPI annotations + `verify_openapi` path-count bump. *Open-core.*

**Phase 4 — `OcsfProfile` codegen + resolution (NAN-xxx, XL).** Build-time OCSF field-registry generator (parallel to the UDM CSV generator), sourced from the Phase 0 manifest `nanosiem-core/docs/ocsf/1.8.0/udm_ocsf_mapping.json`; implement `OcsfProfile` incl. `JsonPath`/`ArrayElement`, enum+sibling resolution, taxonomy int columns, `observables[]`→`_search`. Compile/regression tests for static mapping templates (NAN-667). *Open-core* — OCSF is a first-class open-edition schema, not gated behind a license. **⚠️ `resolve()` and `canonicalize()` must accept DOTTED OCSF paths** as nPL field tokens: an analyst writes `src_endpoint.ip` or `actor.process.cmd_line` directly, so `resolve()` returns `ExplicitColumn("src_endpoint.ip")` (the dotted promoted column, which Phase 2's `escape_identifier` then backticks) for promoted paths and `JsonPath`/`ArrayElement` for the unpromoted tail — `canonicalize()` must NOT mangle the dots (no `sourcetype→source_type`-style aliasing that assumes bare snake_case). The string-keyed `enrichments[]` selector (`array_key.key_value_str`) and the array-derived `<path>.<derived>` columns are encoded in the manifest for the generator to consume.

**Phase 5 — Detection profile-awareness (NAN-xxx, M).** Replace the three entity-extraction lists with `entity_extraction_order()`; profile-parameterize `auto_detect_risk_entity()`, `validate_ddl_field_name()`, prevalence semantic map. Add a "no silent unknown entity" test. *Open-core.*

**Phase 6 — Enrichment read-only mode (NAN-xxx, L).** `enrichment_mode()==Read` for OCSF; map `enriched_*` UX onto OCSF `enrichments[]`/`location`/`cloud`; disable IP-sync/marketplace/prevalence scheduler arms for OCSF without panicking the shared jobs runner. *Open-core.*

**Phase 7 — Frontend SchemaContext (NAN-xxx, L).** Hydrate field metadata from `/api/schema/fields`; unify the 5 `getFieldCategory()` copies into one metadata-driven function; category/entity-type/priority/color/drilldown from metadata; CodeMirror tokenizers from context. *Open-core.*

**Phase 8 — Scale validation & docs (NAN-xxx, M).** Re-validate OCSF JSONExtract/`_search` paths at demo scale (not local CH); document the storage contract the client must satisfy. *Open-core.*

**Phase 9 — Schema-aware meloD / AI (NAN-xxx, L). *Enterprise* (rides on the open-core profile).** The AI wizards must generate/validate queries and rules against the *active* schema's field universe, not hardcoded UDM. Work:
- Make the LLM field-context profile-driven: `nanosiem-core/src/udm_context.rs` (`get_udm_field_context` / `get_udm_field_context_for_categories` / `get_udm_field_names_by_category`) builds from `SchemaProfile.fields()` + `category()` + `entity_type()` instead of `UdmField::by_category()`. Needs a description source — add `description` to `FieldDef` (UDM ← CSV, OCSF ← the manifest's `notes`).
- Thread the active profile into the ~10 consuming meloD agents (`query_correction_agent`, `query_best_practices_agent`, `dashboard_prompts`, `summarize_agent`, `notebook_chat_agent`, `sigma_converter/prompts`, `parser_prompts`, `cases/shadow_investigation`, …) so the context they emit matches the deployment's schema.
- `melod/udm_validation.rs` must validate generated queries against the active profile's universe (else it rejects valid OCSF).
- Audit prompt few-shots / system prompts for hardcoded UDM field names; make them schema-neutral or profile-selected so the model isn't biased back to `src_ip`.
- Result: Sigma→detection generation, dashboard generation, query correct/review, and shadow investigation all emit dotted OCSF that the (already profile-driven) generator resolves. No OCSF-specific enterprise *schema* code — just teaching the existing enterprise AI to read the active `SchemaProfile`.

**Edition policy: OCSF is fully open-core — no split.** The entire deliverable — the `SchemaProfile` abstraction, `UdmProfile`, *and* `OcsfProfile` (codegen, resolution, OCSF detection semantics, read-only enrichment mapping, frontend SchemaContext) — ships in the open edition. Gating OCSF behind the enterprise license would reproduce exactly the "open in name, proprietary in practice" lock-in perception the open-core move exists to dispel (this scoping was triggered by a prospect asking *"why no OCSF if everything else is open?"*). The answer must be: **yes, OCSF is supported natively, in the open edition.** No phase in this plan is enterprise-gated; nothing OCSF-specific lands behind the `nanosiem-core` `enterprise` feature, so no `@/enterprise/*` open-core stubs (NAN-1190) are required for this work. The enterprise pieces remain the *existing* meloD AI wizards (detection-rule/Sigma generation, query correction, dashboard generation, summarize, parser prompts, shadow investigation). **Correction (was earlier mis-stated as "free"):** these are NOT automatically schema-aware. They feed the LLM a field catalog built by `nanosiem-core/src/udm_context.rs::get_udm_field_context()`, which iterates `UdmField::by_category()` — i.e. the *UDM* field names/types/descriptions. On an OCSF deployment the model would be told the fields are `src_ip`/`process_name` (UDM) and would generate queries/rules that don't resolve against OCSF (`src_endpoint.ip`). Teaching the AI the active schema's field universe is real, bounded work — **Phase 9** below. It stays enterprise but rides entirely on the open-core `SchemaProfile` (no OCSF-specific enterprise *schema* code). Continue to build both editions locally before pushing — the enterprise build is **not** in the merge gate (`feedback_enterprise_build_not_in_merge_gate`) — but here that's only to confirm the open-core OCSF work didn't break the enterprise compile, not because any OCSF code lives there.

---

## 7. Open Questions to Confirm with the Client

1. **CH ownership & boot.** They bring their own ClickHouse — does nanosiem connect read-only with a least-privilege user, or does it still need DDL rights (for real-time detection MVs / `signals` table)? Real-time detection requires creating MVs in *their* CH.
2. **Storage layout — no longer a client dependency.** The only contract is "emit standard OCSF JSON into the `event` column"; we ship the canonical DDL (`clickhouse/ocsf/init.sql`) and materialize/index the promoted columns server-side, invisibly. The remaining ask is just confirmation that their pipeline produces *spec-compliant* OCSF (correct class_uids, nested object shapes, `time` in epoch ms) — i.e. validate their OCSF conformance, not their table layout. If their parser emits a non-standard "OCSF-ish" dialect, that conformance gap is the real work on their side, not our schema.
3. **Table name(s) and database.** What is the fully-qualified table (`profile.table_name()`)? Single table or do they expect a UNION across class tables?
4. **OCSF version & extensions.** Pin to 1.8.0? Any vendor/platform **extensions** (Windows/Linux/macOS, custom UIDs) in use — those add namespaced classes/attributes we'd need in the registry.
5. **Enum/sibling population.** Do they reliably populate both `_id` ints and sibling strings, and `Other(99)` labels? Affects whether we filter on ints (fast) or strings.
6. **Arrays.** For `file.hashes[]`/`process` hashes — which `algorithm_id` is canonical (SHA-256)? Do they ever need multi-algo? Did they pre-flatten or leave as arrays?
7. **`observables[]`.** Is it populated? If so we get a near-free entity/IOC search index.
8. **Enrichment.** Confirm enrichment is **fully client-side** (we go read-only). Where does it live — `enrichments[]`, `location`/`cloud` objects, or custom columns? Do they want any nanosiem-side enrichment at all (if so, the no-insert-hook problem resurfaces)?
9. **Detection rule authoring.** Will their analysts write rules in OCSF field names (`actor.process.cmd_line`) directly in nPL? Confirms the nested-path resolution UX is required, not optional.
10. **Real-time vs scheduled detection.** Acceptable to start OCSF as scheduled-only (no MV DDL into their CH) and add real-time later?
11. **Prevalence.** Do they have/expect prevalence signals? If they don't populate equivalents, prevalence-based FP filtering is inert for them.
12. **Mixed mode.** Is a single deployment ever both UDM and OCSF, or strictly one schema per deployment? (We're scoping single-schema-per-deployment; mixed multiplies effort and risk.)
