# Dead Code Hunt — Findings

_Adversarially-verified dead-code report for the nanosiem Rust codebase. Each "REMOVAL UNIT" below is scoped to map 1:1 to a Linear issue and a single PR._

## 1. Executive Summary

**Confirmed-dead items:** 39 distinct symbols/modules (after de-duplicating the multi-lane overlaps — the SearchService constructor family, `db_now`, and the cfg-gated test modules each appeared under more than one lane).

**Rough LOC removable:** ~4,900 lines, dominated by the two orphaned `query/tests/` directory trees (~4,327 LOC across 17 files) plus ~570 LOC of disabled `#[cfg(any())]` test modules and ~250 LOC of dead constructors/methods/fields.

**Biggest single win:** the two **orphaned `query/tests/` directories** (`parser_tests/` + `clickhouse_sql_gen_tests/`, ~4,327 LOC, 204+ `#[test]` functions). They compile-clean and never run because the parent `mod tests {}` in `query/mod.rs:46` is an empty placeholder that never declares them. This is the largest removable surface and the lowest behavioral risk (no production code references them at all). Note: this is a **judgment call** — these tests have *value if wired in* rather than deleted; see §3.

**Theme:** Almost all confirmed-dead code is the residue of three completed refactors — NAN-800 (PG-only fallback removal), NAN-1162 (PostgreSQL search backend removal), and NAN-1151/NAN-1112 (identity/IOC reroute to enrichment lane) — plus a test-suite triage (commit `23c21e5b` / `4ac6e7b2`) that disabled rotted tests via `#[cfg(any())]` instead of fixing them.

---

## 2. Removal Units

### UNIT 1 — Remove dead SearchService constructor family + `set_backend` setter

**Linear-ready title:** `chore: remove 6 unused SearchService constructors and the no-op set_backend setter (search service)`

**Member items** (all in `nanosiem-core/src/search/service/mod.rs`):
| Symbol | Location |
|---|---|
| `SearchService::with_dual_pool_and_config` | mod.rs:548 |
| `SearchService::with_dual_pool_and_lookup` | mod.rs:574 |
| `SearchService::with_dual_pool_config_and_lookup` | mod.rs:600 |
| `SearchService::with_dual_pool_and_prevalence` | mod.rs:630 |
| `SearchService::with_all_options` | mod.rs:689 |
| `SearchService::with_all_services` | mod.rs:720 |
| `SearchService::set_backend` | mod.rs:757 |

**Cascade:** none beyond the unit. These are leaf constructors/setters; removing them strands no further code.

**Shared types to PRESERVE (do NOT delete):**
- `SearchService::with_dual_pool` (still called by integration tests) and `SearchService::with_dual_pool_lookup_and_prevalence` (THE live production constructor — `nanosiem-api/src/state/constructors.rs:130`, `nanosiem-search/src/lib.rs`, and `DetectionService`).
- `set_inputlookup_service`, `set_ai_client`, `set_job_store`, `set_admission_controller` setters — these are how production wires services (the "construct lighter, then set" pattern that *replaced* the dead `with_all_*` builders).
- The `inputlookup_service` field and all other struct fields.
- The single-variant `SearchBackend` enum and its `== ClickHouse` guards. **Do NOT inline/delete the enum** — NAN-1162 deliberately kept it as low-risk scaffolding; collapsing it is a separate, riskier change. Only the `set_backend` *setter* goes here, because the backend can no longer change at runtime.

**Risk:** low. Pure pub-fn deletion; no callers anywhere.

**Verification after removal:**
```
cargo build -p nanosiem-core
cargo build -p nanosiem-api
cargo build -p nanosiem-search
cargo build -p nanosiem-api --features enterprise
cargo test -p nanosiem-core --lib search::
# These greps MUST return empty:
grep -rn "with_dual_pool_and_config\|with_dual_pool_and_lookup\|with_dual_pool_config_and_lookup\|with_dual_pool_and_prevalence\|with_all_options\|with_all_services\|\.set_backend(" --include="*.rs" --exclude-dir=".claude" .
```

---

### UNIT 2 — Remove dead PG-only / superseded Service constructors (NAN-800 fallout)

**Linear-ready title:** `chore: remove PG-only and superseded service constructors left over from NAN-800 dual-pool migration`

**Member items:**
| Symbol | Location |
|---|---|
| `FeedService::new` (PgPool-only) | nanosiem-core/src/feeds/service.rs:41 |
| `LogSourceService::new` (PgPool-only) | nanosiem-core/src/log_sources/service/mod.rs:83 |
| `LogSourceService::with_dual_pool` (no config_dir) | nanosiem-core/src/log_sources/service/mod.rs:95 |
| `LogSourceService::with_vector_config_dir` (PG-only + config) | nanosiem-core/src/log_sources/service/mod.rs:107 |
| `ParserService::with_validator` (test helper, callerless) | nanosiem-core/src/parsers/service/mod.rs:86 |
| `ParserRepositoryService::with_config` (builder, callerless) | nanosiem-core/src/parser_repository/service.rs:73 |
| `PlaybookRepositoryService::with_config` (builder, callerless) | nanosiem-core/src/playbook_repository/service/mod.rs:68 |

**Cascade:** none. Each is a leaf constructor superseded by a live sibling.

**Shared types to PRESERVE:**
- The live constructors that replaced them: `FeedService::with_dual_pool`, `LogSourceService::with_dual_pool_and_config_dir`, `ParserService::new`, `ParserRepositoryService::new`, `PlaybookRepositoryService::new`.
- `ParserRepositoryServiceConfig` and `PlaybookRepositoryServiceConfig` structs — still used by the default `new()` paths; only the `with_config` builder method is dead, not the config type.
- `TableNames` (constructed differently in the live constructors).

**Risk:** low.

**Verification after removal:**
```
cargo build -p nanosiem-core
cargo build -p nanosiem-api
cargo build -p nanosiem-api --features enterprise
# MUST be empty:
grep -rn "FeedService::new\b" --include="*.rs" --exclude-dir=".claude" .
grep -rn "LogSourceService::new\b\|LogSourceService::with_dual_pool[^_]\|LogSourceService::with_vector_config_dir" --include="*.rs" --exclude-dir=".claude" .
grep -rn "ParserService::with_validator\|ParserRepositoryService::with_config\|PlaybookRepositoryService::with_config" --include="*.rs" --exclude-dir=".claude" .
```

---

### UNIT 3 — Remove dead Repository methods (zero-caller DB accessors)

**Linear-ready title:** `chore: remove zero-caller repository methods (heartbeat, allowlist EXISTS, lookup-by-id, detection-pattern delete)`

**Member items:**
| Symbol | Location |
|---|---|
| `LicenseRepository::update_heartbeat_at` | nanosiem-core/src/license/repository.rs:62 |
| `IpAllowlistRepository::has_enabled_rules` | nanosiem-core/src/ip_allowlist/repository.rs:61 |
| `LookupRepository::get_table_by_id` | nanosiem-core/src/lookup/repository.rs:117 |
| `DetectionPatternRepository::delete_detection_pattern` | nanosiem-core/src/parsers/repository.rs:856 |

**Cascade (note for the implementer):** `delete_detection_pattern`'s only conceptual parent, `AutoDetector::load_patterns()` (`nanosiem-core/src/parsers/auto_detect.rs:124`), is **itself unreachable** per the verifier. Removing `delete_detection_pattern` alone is safe and self-contained. A *deeper* cleanup of `AutoDetector::load_patterns` + `DetectionPatternRepository` was flagged but NOT confirmed (the repo's other methods — `get_detection_patterns`, `set_pattern_enabled`, `create_detection_pattern` — were not all audited). **Keep this PR to the 4 confirmed methods**; do not chase `AutoDetector` removal without a fresh audit.

**Shared types to PRESERVE:**
- `LicenseRepository` itself (alive via `get_status`/`update_status`); the `last_heartbeat_at` column is a legacy DB field — leave the column and the struct field.
- `IpAllowlistRepository` (alive via `list`/`get`/`create`/`update`/`delete`); the service computes `has_any_rules` locally and stays untouched.
- `LookupRepository` and `LookupTable` (alive via `get_table(name)`).
- `DetectionPatternRepository` struct and its other methods (not audited — preserve).

**Risk:** low.

**Verification after removal:**
```
cargo build -p nanosiem-core
cargo build -p nanosiem-api --features enterprise
# MUST be empty:
grep -rn "\.update_heartbeat_at(\|\.has_enabled_rules(\|\.get_table_by_id(\|\.delete_detection_pattern(" --include="*.rs" --exclude-dir=".claude" .
```

---

### UNIT 4 — Remove identity sync dead code (NAN-1151 reroute fallout)

**Linear-ready title:** `chore: remove identity-sync dead code superseded by staleness reconciler (NAN-1151)`

**Member items:**
| Symbol | Location |
|---|---|
| `IdentityRepository::mark_absent_users` (set-based, superseded) | nanosiem-core/src/identity/repository.rs:423 |
| `IdentityRepository::db_now` (clock-skew helper, no callers) | nanosiem-core/src/identity/repository.rs:442 |
| `ActiveDirectoryCredentials` struct | nanosiem-core/src/identity/types.rs:470 |

**Cascade:** when `db_now` goes, the stale doc-comment at repository.rs:412–414 ("cutoff must come from db_now()") becomes misleading — update or delete it. No code cascade.

**Shared types to PRESERVE:**
- `IdentityRepository::mark_absent_users_by_sync_time` (the live replacement, called from `service.rs` → `reconcile_stale_users` → scheduler) plus its helpers `fetch_live_rows_for_provider` and `soft_delete_rows`.
- `IdentityProviderType::ActiveDirectory` **enum variant** — still matched at `service.rs:166`/`:449` for provider classification. Only the *credentials struct* is dead, not the variant.
- All live provider credential types: `EntraIdCredentials`, `GoogleWorkspaceCredentials`, `OktaCredentials`, `WorkdayCredentials`.
- The `IdentityProvider.credentials_encrypted` blob storage.

**Risk:** low-med (identity is a live data path; the staleness reconciler is the active code and is untouched — verify the scheduler still compiles and the AD enum match arms still resolve).

**Verification after removal:**
```
cargo build -p nanosiem-core
cargo build -p nanosiem-api --features enterprise
cargo test -p nanosiem-core --lib identity::
# MUST be empty:
grep -rn "\.mark_absent_users(\|\.db_now(\|ActiveDirectoryCredentials" --include="*.rs" --exclude-dir=".claude" .
```

---

### UNIT 5 — Remove unreachable `ioc_feed` dict-reload branch (NAN-1112 fallout)

**Linear-ready title:** `chore: remove unreachable ioc_feed dict-reload arm in enrichment scheduler (sunset by NAN-1112)`

**Member items:**
| Symbol | Location |
|---|---|
| `"ioc_feed" => Some("nanosiem.ioc_enrichment_dict")` arm | nanosiem-core/src/enrichment/scheduler.rs:300 |

**Why dead:** the outer match (scheduler.rs:271–285) `continue`s for every `source_type` except `ipinfo_lite`, so the inner match at line 298 only ever sees `ipinfo_lite`. The `ioc_feed` source type was deleted from the DB (migration 196 deletes what 177 seeded). Doubly unreachable.

**Cascade:** none.

**Shared types to PRESERVE:** the `ipinfo_lite` arm and the rest of the scheduler. IOC lookups now go through the CH `custom_ioc_enrichment_dict` — don't touch that path.

**Risk:** low.

**Verification after removal:**
```
cargo build -p nanosiem-core
cargo build -p nanosiem-api --features enterprise
grep -rn "ioc_enrichment_dict" --include="*.rs" --exclude-dir=".claude" nanosiem-core/src/enrichment/   # expect no scheduler hit
```

---

### UNIT 6 — Remove dead LogParser methods (Vector-direct ingestion fallout)

**Linear-ready title:** `chore: remove dead LogParser parse/detect/CEF chain left after Vector→ClickHouse direct ingestion`

**Member items** (all in `nanosiem-core/src/ingestion/parser.rs`):
| Symbol | Location |
|---|---|
| `LogParser::with_normalizer` | parser.rs:193 |
| `LogParser::parse_json` | parser.rs:209 |
| `LogParser::parse_vector_format` | parser.rs:223 |
| `LogParser::detect_and_parse` | parser.rs:323 |
| `LogParser::parse_cef` | parser.rs:377 |
| `LogParser::detect_source_type_from_json` | parser.rs:352 |

**Cascade — IMPORTANT:** the only remaining callers of `LogParser::parse()` / `parse_json()` are (a) the in-file `#[cfg(test)]` tests and (b) the fuzz target `nanosiem-core/fuzz/fuzz_targets/fuzz_log_parser.rs`. Decide explicitly:
- **Option A (recommended, conservative):** delete only `with_normalizer` (fully orphaned, zero refs) and the `parse_cef` branch (genuinely vestigial CEF path), and leave `parse`/`parse_json`/`detect_and_parse` alive for the fuzz harness. Smallest blast radius.
- **Option B (full removal):** delete the whole chain AND `fuzz_log_parser.rs` AND the in-file tests at parser.rs ~490–550. Larger, but removes the entire dead `LogParser` parsing surface.

Pick one in the PR description; don't half-remove (deleting `parse_cef` while keeping `detect_and_parse` is fine; deleting `parse_json` while keeping its tests is not).

**Shared types to PRESERVE:**
- `ParsedLog` struct and `LogParser::new()` — **still used by audit emitters** (core + enterprise) which construct `ParsedLog` directly. Do not touch.
- `DefaultFieldNormalizer::with_defaults()`.

**Risk:** med (the fuzz harness + tests reference the chain; choose Option A or B deliberately).

**Verification after removal:**
```
cargo build -p nanosiem-core
cargo build -p nanosiem-api --features enterprise
cargo test -p nanosiem-core --lib ingestion::
# If Option B, also confirm the fuzz workspace builds (separate workspace):
# (cd nanosiem-core/fuzz && cargo build) — only if you kept/edited the fuzz target
grep -rn "with_normalizer\|parse_cef\|parse_vector_format\|detect_source_type_from_json" --include="*.rs" --exclude-dir=".claude" .   # MUST be empty for whatever you removed
```

---

### UNIT 7 — Remove dead case-entity enrichment writer

**Linear-ready title:** `chore: remove unreachable CaseRepository::update_entity_enrichment + UpdateEntityEnrichment`

**Member items:**
| Symbol | Location |
|---|---|
| `CaseRepository::update_entity_enrichment` | nanosiem-core/src/db/repository/cases/entities.rs:81 |
| `UpdateEntityEnrichment` input struct | cases/entities.rs (re-exported in mod.rs) |

**Cascade:** removing the method orphans `UpdateEntityEnrichment` (never constructed) — remove it too and its re-export. The `enrichment_data` / `enrichment_updated_at` DB columns become write-never (already effectively NULL); leave the columns and the `CaseEntity` fields in place (schema change is out of scope and higher-risk).

**Shared types to PRESERVE:** `CaseEntity` struct (incl. its `enrichment_data`/`enrichment_updated_at` fields — read paths may still deserialize them), `add_or_update_entity` (the live entity writer), `CaseRepository`.

**Risk:** low.

**Verification after removal:**
```
cargo build -p nanosiem-core
cargo build -p nanosiem-api --features enterprise
grep -rn "update_entity_enrichment\|UpdateEntityEnrichment" --include="*.rs" --exclude-dir=".claude" .   # MUST be empty
```

---

### UNIT 8 — Remove dead `DetectionService::test_rule`

**Linear-ready title:** `chore: remove superseded DetectionService::test_rule (replaced by stepped analyzers)`

**Member items:**
| Symbol | Location |
|---|---|
| `DetectionService::test_rule` | nanosiem-core/src/detection/service/execution.rs:352 |

**Cascade:** none.

**Shared types to PRESERVE:** `analyze_rule_stepped`, `analyze_query_stepped`, and `evaluate_window` — the live rule-testing path used by the `/api/rules/{id}/test` and `/api/rules/test` handlers.

**Risk:** low.

**Verification after removal:**
```
cargo build -p nanosiem-core
cargo build -p nanosiem-api --features enterprise
grep -rn "\.test_rule(" --include="*.rs" --exclude-dir=".claude" .   # MUST be empty
```

---

### UNIT 9 — Remove confessed `#[allow(dead_code)]` leaf helpers + the dead post-processing wrapper

**Linear-ready title:** `chore: delete confessed dead helpers (op_str, _coerce_cat, serialize_optional_naive_date, apply_stats_post_processing wrapper)`

**Member items:**
| Symbol | Location |
|---|---|
| `op_str` (private, `#[allow(dead_code)]`) | nanosiem-api/src/handlers/detections/predicates.rs:435 |
| `_coerce_cat` (private, `#[allow(dead_code)]`) | nanosiem-core/src/playbooks/repository.rs:597 |
| `serialize_optional_naive_date` ("kept for symmetry") | nanosiem-core/src/playbooks/models.rs:497 |
| `apply_stats_post_processing` (wrapper, `#[allow(dead_code)]`) | nanosiem-core/src/search/processing/post_processing/stats.rs:49 |
| `VrlValidator::with_container` (`#[deprecated]`, Docker-era stub) | nanosiem-core/src/parsers/validator.rs:133 |

**Cascade:** when `apply_stats_post_processing` goes, also drop the misleading comment at `post_processing/mod.rs:43` that claims it's reachable. None of these have a code cascade.

**Shared types to PRESERVE:**
- `apply_stats_post_processing_with_limit` — the **live** function called from `apply_post_prevalence_commands_with_limit` (core_search.rs:821/847/941/1002). Only the no-arg wrapper is dead.
- `deserialize_optional_naive_date` — actually used (`#[serde(deserialize_with=...)]`); keep it. Only the serialize twin is dead.
- `VrlValidator::new()` (the recommended replacement) and `without_docker()` (still called by the fuzz harness).
- `Comparator::as_str()` (what `op_str` would have duplicated).

**Risk:** low.

**Verification after removal:**
```
cargo build -p nanosiem-core
cargo build -p nanosiem-api
cargo build -p nanosiem-api --features enterprise
cargo test -p nanosiem-api verify_openapi   # predicates.rs is in a handler tree
grep -rn "op_str(\|_coerce_cat\|serialize_optional_naive_date\|with_container" --include="*.rs" --exclude-dir=".claude" .   # MUST be empty
grep -rn "apply_stats_post_processing[^_]" --include="*.rs" --exclude-dir=".claude" .   # MUST be empty
```

---

### UNIT 10 — Remove confessed dead struct fields (over-deserialization + reserved-for-future)

**Linear-ready title:** `chore: drop confessed dead struct fields (VtData, StixObject, SinkInfo, AiGatewayClient, NotebookChatAgent)`

**Member items:**
| Symbol | Location |
|---|---|
| `VtData::id` (+ cascade `VtData::data_type`) | nanosiem-enterprise/src/agent_enrichment/provider/virustotal.rs:40 |
| `StixObject::id` | nanosiem-core/src/mitre/types.rs:70 |
| `SinkInfo::ty` (local helper struct) | nanosiem-core/src/parsers/vector_config/deploy.rs:62 |
| `AiGatewayClient::aws_access_key_id` (+ `aws_secret_access_key`) | nanosiem-enterprise/src/melod/ai_gateway.rs:458 |
| `NotebookChatAgent::data_access` | nanosiem-enterprise/src/melod/notebook_chat_agent.rs:174 |

**⚠️ Caveat — these are NOT all clearly worth removing:**
- `VtData::id` / `StixObject::id` mirror external API/STIX JSON schemas for serde. Deleting requires confirming serde won't fail on the incoming payload (add `#[serde(default)]` or verify the field is never sent). **Treat as med risk**, not a blind delete.
- `AiGatewayClient::aws_access_key_id`/`aws_secret_access_key` and `NotebookChatAgent::data_access` are explicitly **"reserved for future"** (Bedrock SigV4 / autonomous lookups). The enterprise lane summary recommends keeping these as intentional technical debt. **Recommendation: DEFER these two** unless the team has decided the features are dead; removing them cascades into builder methods (ai_gateway.rs:1507–1513) and constructor call sites (notebook chat handlers:302/579).
- `SinkInfo::ty` is a safe, purely-local delete.

**Shared types to PRESERVE:** `VtData::attributes` (used 4×), the live `MitreTactic`/`MitreTechnique` outputs, `SinkInfo::{blocks,acks,inputs}`, the AiGateway Debug impl and live credential paths.

**Risk:** med (serde fields + future-reserved). Split this unit: a low-risk sub-PR for `SinkInfo::ty`, a separate decision for the serde mirrors, and a defer for the reserved fields.

**Verification after removal:**
```
cargo build -p nanosiem-core
cargo build -p nanosiem-enterprise
cargo build -p nanosiem-api --features enterprise
cargo test -p nanosiem-enterprise --lib   # exercise VT/STIX deserialization if covered
```

---

### UNIT 11 — Wire-in OR delete the orphaned `query/tests/` directory trees

**Linear-ready title:** `chore: resolve orphaned query test trees (parser_tests + clickhouse_sql_gen_tests) — wire in or delete`

**Member items:**
| Symbol | Location |
|---|---|
| empty placeholder `#[cfg(test)] mod tests {}` | nanosiem-core/src/query/mod.rs:46 |
| `query/tests/parser_tests/` (mod.rs + 6 files, ~113 `#[test]`) | nanosiem-core/src/query/tests/parser_tests/ |
| `query/tests/clickhouse_sql_gen_tests/` (mod.rs + 10 files, ~101 `#[test]`) | nanosiem-core/src/query/tests/clickhouse_sql_gen_tests/ |

**This is the biggest LOC unit (~4,327 lines) but is a JUDGMENT CALL, not a pure delete.** The directories contain real, structurally-valid tests that simply were never wired into the module tree (`query/tests/` has no `mod.rs`; `query/mod.rs:46` is an empty stub). Two resolutions:
- **Option A (resurrect):** create `query/tests/mod.rs` declaring both subdirs and change `query/mod.rs:46` to `#[cfg(test)] mod tests;`. This *adds* ~204 tests to the suite — but they may have rotted (the inline tests in `clickhouse_sql_gen.rs` already cover much of this). Expect compile fixes.
- **Option B (delete):** remove both directories and the empty `mod tests {}` stub. Clean and zero-risk to production, but throws away potential coverage.

**Recommendation:** raise as its own Linear issue and let a human decide A vs B; do NOT fold into a generic cleanup PR. Inline tests in `clickhouse_sql_gen.rs` and the wired `parser.rs` `mod tests` provide the actual live coverage today.

**Shared types to PRESERVE:** nothing in production references these; `clickhouse_sql_gen.rs` inline tests and `parser.rs`-wired tests are independent and must stay.

**Risk:** low (production), but Option A has test-compile risk.

**Verification:**
```
# Option B (delete):
cargo test -p nanosiem-core --lib query::   # unchanged count vs baseline
grep -rn "parser_tests\|clickhouse_sql_gen_tests" --include="*.rs" --exclude-dir=".claude" .   # MUST be empty
# Option A (wire-in):
cargo test -p nanosiem-core --lib query::tests   # should now run ~204 tests; fix failures
```

---

### UNIT 12 — Resolve the 8 `#[cfg(any())]`-disabled test modules

**Linear-ready title:** `chore: re-enable or delete 8 #[cfg(any())]-disabled test modules (~90 tests)`

**Member items:**
| Module | Location |
|---|---|
| `query::pretty_print::tests` (32 tests) | nanosiem-core/src/query/pretty_print/mod.rs:12 |
| `detection::realtime::tests` (7 tests) | nanosiem-core/src/detection/realtime/mod.rs:20 |
| `detection::findings::tests` (6 tests) | nanosiem-core/src/detection/findings.rs:604 |
| `detection::risk::tests` (34 tests) | nanosiem-core/src/detection/risk/mod.rs:31 |
| `udm_context::tests` (3 tests) | nanosiem-core/src/udm_context.rs:255 |
| `melod::dashboard_agent::tests` (2 tests) | nanosiem-enterprise/src/melod/dashboard_agent.rs:819 |
| `melod::service::tests` (3 tests) | nanosiem-enterprise/src/melod/service/tests.rs:1 |
| `melod::sigma_converter::udm_fields::tests` | nanosiem-enterprise/src/melod/sigma_converter/udm_fields.rs:90 |

**Context:** these were flipped from `#[cfg(test)]` to `#[cfg(any())]` in commits `23c21e5b` / `4ac6e7b2` to silence ~71 compile errors from rotted fixtures (DetectionRule shape drift, etc.) — a triage shortcut, not intentional permanent removal.

**Cascade if deleting `detection::realtime::tests`:** the 7 `pub(crate)` test-helper fns in `matching.rs:379–423` (`test_search_keyword_in_value`, `test_get_field_value`, etc.) and the `pub(crate) use test_helpers::*;` re-export at matching.rs:372 become dead and must be removed in the same PR.

**Recommendation:** prefer **re-enabling** (`#[cfg(any())]` → `#[cfg(test)]`) and fixing fixtures, since these test live, exercised functions (risk scoring, findings serialization, dashboard JSON extraction, formatting handlers). Only delete if the team accepts the coverage loss. **Do per-module sub-PRs** — `detection::risk` (34 tests) alone is substantial and may need real fixture work. This is a test-health issue more than a dead-code issue; raise as its own Linear epic.

**Shared types to PRESERVE:** every function these modules test is LIVE production code (`ScoreCalculator::validate_weight` → risk settings handler, `extract_json_from_response`/`get_panel_dimensions` → dashboard agent, `format_*_response` → melod handlers, `get_udm_field_context` → query-correction agent). Do not touch production functions.

**Risk:** low (delete) / med (re-enable + fixture repair).

**Verification:**
```
cargo test -p nanosiem-core --lib detection:: query:: udm_context::
cargo build -p nanosiem-enterprise
cargo test -p nanosiem-enterprise --lib melod::
grep -rn "cfg(any())" --include="*.rs" --exclude-dir=".claude" .   # MUST be empty for resolved modules
```

---

### UNIT 13 — Drop genuinely-unused `utoipa-axum` dependency

**Linear-ready title:** `chore: remove unused utoipa-axum dependency from api + search crates`

**Member items:**
| Symbol | Location |
|---|---|
| `utoipa-axum` dep (nanosiem-api) | nanosiem-api/Cargo.toml:60 |
| `utoipa-axum` dep (nanosiem-search) | nanosiem-search/Cargo.toml:42 |
| `utoipa-axum` workspace dep entry | root Cargo.toml (~:71) |

**Cascade:** none. OpenAPI/Swagger is provided by `utoipa` + `utoipa-swagger-ui` (which carries its own axum integration via `SwaggerUi`). `utoipa-axum` is pure unused sugar.

**Shared deps to PRESERVE:** `utoipa`, `utoipa-swagger-ui`. Also **do NOT** remove the other cargo-machete flags that are false positives per the lane: `metrics-exporter-prometheus` (used via `axum_prometheus` re-export) and `thiserror` in nanosiem-api (used by sibling `nanosiem-api-lib`). The lane also flagged `tracing-subscriber`, `async-stream`, `scraper`, and dev-dep `proptest` as genuinely unused — those were NOT in the confirmed-dead list, so verify each independently before touching (not part of this unit).

**Risk:** low.

**Verification after removal:**
```
cargo build -p nanosiem-api
cargo build -p nanosiem-search
cargo build -p nanosiem-api --features enterprise
cargo test -p nanosiem-api verify_openapi
grep -rn "utoipa_axum" --include="*.rs" --exclude-dir=".claude" .   # already empty; stays empty
```

---

## 3. Unsure / Needs Human Eyes

The verifier's "STILL UNSURE" list was empty — every candidate reached a `dead` verdict. However, several confirmed-dead items carry **judgment** rather than pure-mechanical risk, and the synthesis flags them for a human decision:

| Item | What blocks a clean "just delete it" |
|---|---|
| **UNIT 11** (orphaned `query/tests/` trees) | These are *valid tests*, not garbage. Deciding delete-vs-resurrect needs a human call on whether the ~204 tests add coverage beyond the inline `clickhouse_sql_gen.rs` tests. |
| **UNIT 12** (8 `#[cfg(any())]` modules) | Same: ~90 tests of live code, disabled as triage. Re-enabling needs fixture repair; deleting loses coverage. Test-health decision. |
| **UNIT 10 — `VtData::id` / `StixObject::id`** | Serde-deserialized API/STIX schema mirrors. Removing risks deserialization failure on incoming payloads unless `#[serde(default)]` is added or the field is confirmed absent. Needs a payload check. |
| **UNIT 10 — `AiGatewayClient::aws_*` / `NotebookChatAgent::data_access`** | Explicitly "reserved for future" (Bedrock SigV4, autonomous lookups). Enterprise lane recommends keeping. Needs product decision on whether those features are abandoned. |
| **UNIT 6 — full `LogParser` chain** | `parse`/`parse_json`/`detect_and_parse` are kept alive only by the fuzz target + in-file tests. Human must choose Option A (keep for fuzzing) vs Option B (delete chain + fuzz target). |
| **UNIT 3 — `AutoDetector::load_patterns`** | Flagged as itself-unreachable but its sibling repo methods weren't fully audited. Don't expand the PR into removing `AutoDetector`/`DetectionPatternRepository` without a fresh reachability pass. |
| `SearchBackend` single-variant enum | Confirmed low-risk-keep. Do NOT inline/collapse it (NAN-1162 intentionally retained it). Only `set_backend` is removed. |

---

## 4. Ordering Recommendation

**Land first (biggest + safest, pure pub-fn / dep deletes — zero behavioral risk, fast wins):**
1. **UNIT 1** — SearchService constructor family + `set_backend`. Largest single safe-delete of production symbols, self-contained, well-proven.
2. **UNIT 2** — superseded service constructors (NAN-800 fallout). Same shape, low risk.
3. **UNIT 13** — drop `utoipa-axum`. One-line-per-crate, trivial.
4. **UNIT 3** — zero-caller repo methods.
5. **UNIT 5** — unreachable `ioc_feed` arm.
6. **UNIT 8** — `DetectionService::test_rule`.
7. **UNIT 7** — case-entity enrichment writer.
8. **UNIT 9** — confessed leaf helpers.

**Land next (needs a deliberate Option-A/B choice but still low production risk):**
9. **UNIT 4** — identity sync dead code (verify scheduler + AD enum arms compile).
10. **UNIT 6** — LogParser chain (pick Option A or B in the PR).
11. **UNIT 10** — split: `SinkInfo::ty` now; serde mirrors after a payload check.

**Defer (test-health epics + product decisions, NOT routine dead-code PRs):**
- **UNIT 11** — orphaned `query/tests/` trees (largest LOC, but resurrect-vs-delete is a coverage decision).
- **UNIT 12** — `#[cfg(any())]` test modules (fixture-repair epic).
- **UNIT 10 reserved fields** — `AiGatewayClient::aws_*`, `NotebookChatAgent::data_access` (keep until features are formally abandoned).

**Cross-cutting safety rules honored throughout:**
- Every unit's verification runs `cargo build -p nanosiem-api --features enterprise` (the enterprise crate is NOT in the merge gate — `--features enterprise` can be red on green main, so build it explicitly).
- Each unit lists shared types to PRESERVE and the post-removal greps that must be empty (cascade-then-regrep).
- No single-variant-enum inlining; `SearchBackend` stays.
- Modified handler trees (UNIT 9 `predicates.rs`, UNIT 13) run `cargo test -p nanosiem-api verify_openapi`.
