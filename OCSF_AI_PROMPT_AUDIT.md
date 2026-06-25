# OCSF AI-Prompt Awareness — Audit & Implementation Plan (NAN-1248)

Audited 2026-06-06 (3 parallel agents) — the meloD / AI surfaces for UDM-hardcoding that should become schema-aware under `NANO_SCHEMA_PROFILE=ocsf`.

## TL;DR — severity is *enhancement*, not break
The nPL alias layer (shipped this session: `OcsfProfile::resolve` maps `src_ip`→`src_endpoint.ip`, etc.) means AI prompts that teach **UDM field names still produce working queries under OCSF** — the LLM emits `src_ip`, which resolves to the OCSF column at query time. So nothing here 500s on the happy path. The real gaps:
1. The AI **can't suggest OCSF-native-only fields** (`api.operation`, `resources.type`, `is_mfa`, dotted paths) because its glossary is UDM-only → OCSF-specific detections/queries can't be AI-generated.
2. **Value-literal** suggestions (`auth_result="failure"`) carry the value-semantics mismatch (separate, partially addressed for cloud/asset).
3. Two data-layer spots read the **wrong table/columns** under OCSF (wrong context, no crash).

## Root cause (one file feeds ~10 prompts)
`nanosiem-core/src/udm_context.rs` — `get_udm_field_context()`, `get_udm_field_context_for_categories()`, `get_udm_field_names_by_category()`, `get_field_mistakes_warning()`, `get_query_syntax_reference()` all build a **hardcoded UDM glossary** (`UdmField::by_category`) with **no profile parameter**. Every meloD prompt that injects field context calls these.

**meloD has no profile seam today** (zero `SchemaProfile` refs in `nanosiem-enterprise/src/melod`).

## The mechanism (both already exist — makes this tractable)
- `SchemaProfile::fields() -> &[FieldDef]` — **both** `UdmProfile` and `OcsfProfile` expose their field list (so the glossary can be built per-schema).
- `DataAccessLayer` (the shared meloD data layer) is constructed at **`nanosiem-api/src/state/melod.rs:298`** (`with_clickhouse_clustered(...)`) — that call site has `config.schema_profile()`. Thread the profile in there → every agent that holds `DataAccessLayer` can reach it.

## Implementation plan (proposed — your review)
**Phase 1 — foundation (nanosiem-core, in merge gate, safe/additive):**
- Add profile-aware variants in `udm_context.rs`: `…(profile: &dyn SchemaProfile)`. UDM branch = current hardcoded glossary (byte-identical); OCSF branch builds from `profile.fields()` (name/category/description) so the LLM sees `src_endpoint.ip`, `api.operation`, `resources.type`, etc.
- Adjust `get_field_mistakes_warning` for OCSF (the UDM "use `process` not `command_line`" rules are UDM-specific).

**Phase 2 — thread the profile (nanosiem-enterprise + the one api site):**
- Add `profile: Arc<dyn SchemaProfile>` to `DataAccessLayer`; set it at `melod.rs:298` from `config.schema_profile()`.
- Repoint the ~10 prompt builders to call the profile-aware `udm_context` with `data_access`'s profile:
  - `melod/parser_prompts/system_prompt.rs` (⚠️ see note), `query_prompts/system_prompt.rs`, `query_correction_agent.rs`, `query_best_practices_agent.rs`, `notebook_chat_agent.rs`, `dashboard_prompts.rs`, `prompts/mod.rs` (detection gen), `sigma_converter/prompts.rs`, `tuning/agent.rs`, `cases/shadow_investigation/investigation.rs` (hunt system prompt ~897 UDM field list).

**Phase 3 — data-layer fixes:**
- `melod/data_access/field_statistics.rs` — hardcoded `FROM logs` + bare UDM columns (`src_ip`, …). Under OCSF reads the *UDM* table (wrong stats, no 500). Fix: use the active table (`logs_table_key`) + resolve columns via the profile.
- `melod/validation/mod.rs` `get_known_fields` — UDM-only allowlist; rejects OCSF dotted names in the AI-generation retry loop. Fix: profile-aware (mirror `detections/testing.rs:346`, which already uses `profile.is_known_field`).

**Already profile-aware (do NOT touch):** `detections/testing.rs` validation, risk-entity auto-detect, realtime-MV codegen (fixed this session), scheduled detection execution, SIEM-health AI (metrics-driven, schema-agnostic), the shadow entity-pivot queries (nPL → alias-resolved).

**Open question for the parser-generation prompt:** parsers currently target `.udm.*` (UDM intermediate). Under OCSF *native* ingestion (NAN-1246, separate epic) they should target OCSF structure. Out of scope here — flag for the ingestion epic.

## Verify
Both builds: `cargo build --lib` (open) **and** `cargo build -p nanosiem-api --lib --features enterprise` (enterprise is NOT in the merge gate). UDM byte-identical: `npl_compat 480/0`, `lib 1361+/0`. The UDM prompt output must be unchanged (UDM branch returns the current glossary).
