// SPDX-License-Identifier: AGPL-3.0-or-later

//! The [`SchemaProfile`] trait — the seam that lifts the implicit single-schema
//! ("schema == the UDM constants") assumption into an explicit, pluggable
//! abstraction (scoping §2.2, NAN-1244 / OCSF Phase 1).
//!
//! Phase 1 introduces the trait and the `UdmProfile` implementation only; no
//! existing call site is re-pointed at it yet (that is Phase 2). Every const
//! array and generated-enum lookup in the SQL generator, field-stats, and
//! detection engine will eventually be replaced by a method call against the
//! active profile, passed by `Arc<dyn SchemaProfile>`.

use std::borrow::Cow;

use super::types::{
    EnrichmentKind, EnrichmentMode, EntityRole, EntityType, EnumIntMapping, FieldCategory,
    FieldDef, FieldResolution, FieldType, SchemaId,
};

/// The contract that `UdmProfile` and (later) `OcsfProfile` both satisfy.
///
/// Implementations must be cheap to clone-by-`Arc` and safe to share across
/// threads (`Send + Sync`). Hot-path methods — chiefly [`resolve`] — are called
/// once per field reference during SQL generation and MUST be O(1); back them
/// with precomputed lookup structures (e.g. `OnceLock<HashSet<_>>`).
///
/// [`resolve`]: SchemaProfile::resolve
pub trait SchemaProfile: Send + Sync {
    /// Identity of this profile (`Udm` | `Ocsf`).
    fn id(&self) -> SchemaId;

    // --- Field universe & resolution ---

    /// All queryable canonical field names with their metadata
    /// (replaces `UDM_COLUMNS` / `EXPLICIT_COLUMNS`).
    fn fields(&self) -> &[FieldDef];

    /// Resolve an nPL field token to its physical ClickHouse location.
    ///
    /// THE CORE METHOD. Must be O(1). For UDM this reproduces
    /// `is_explicit_column()` exactly: [`FieldResolution::ExplicitColumn`] for
    /// known names, [`FieldResolution::Unknown`] otherwise.
    fn resolve(&self, npl_field: &str) -> FieldResolution;

    /// Map a user-typed alias to its canonical field name
    /// (`sourcetype` → `source_type`, `hostname` → `host`).
    /// Replaces `normalize_field_name`. Returns `Borrowed` when no rewrite applies.
    fn canonicalize<'a>(&self, npl_field: &'a str) -> Cow<'a, str>;

    /// Whether a field name is part of this schema's universe.
    /// Replaces the `UdmField::from_str` allowlist used for DDL validation.
    fn is_known_field(&self, name: &str) -> bool;

    // --- Typing & query optimization hints ---

    /// Value type of a field, if known.
    fn field_type(&self, field: &str) -> Option<FieldType>;

    /// Whether the field is lowercased at ingest, so queries can skip the
    /// `lower()` wrapper and use the index directly.
    fn is_lowercased_at_ingest(&self, field: &str) -> bool;

    /// Whether the field must NOT be `lower()`-wrapped because it is numeric.
    fn is_numeric_field(&self, field: &str) -> bool;

    /// Whether the field is a ClickHouse `UUID` (compared via `toString()`).
    fn is_uuid_field(&self, field: &str) -> bool;

    /// Fields eligible for PREWHERE extraction (indexed / bloom-filtered).
    fn prewhere_fields(&self) -> &[&str];

    /// Columns declared `MATERIALIZED`; a multi-stage CTE chain must re-add these
    /// because ClickHouse excludes them from `SELECT *` (NAN-1147).
    fn materialized_columns(&self) -> &[&str];

    // --- Categorization / UX ---

    /// Coarse category for a field (drives grouping, color, and LLM context).
    fn category(&self, field: &str) -> FieldCategory;

    /// The security entity a field denotes, if any.
    fn entity_type(&self, field: &str) -> Option<EntityType>;

    /// Default fields shown in the table-view summary.
    fn default_table_fields(&self) -> &[&str];

    /// Fields pinned to the top of the FieldsPanel.
    fn priority_fields(&self) -> &[&str];

    /// Default-view column rewrites applied to the `SELECT *` projection of a
    /// bare (non-aggregated) search: each `(column, alias)` pair drops `column`
    /// from the wildcard (`* EXCEPT (column)`) and re-projects it as
    /// `column AS alias` so the user-facing result header carries the canonical
    /// name.
    ///
    /// UDM returns `[("action", "event_type")]` — exactly today's
    /// `* EXCEPT (action), action AS event_type` behavior (NAN-659/671/876),
    /// which the generator reproduces byte-for-byte. OCSF returns `[]` because it
    /// has no `action` column (it carries `activity`/`activity_id`); applying the
    /// UDM rewrite would reference a nonexistent column and fail every bare/filter
    /// search. The default here is `[]` so an unrelated profile is never
    /// accidentally given a UDM-specific rewrite.
    fn default_view_renames(&self) -> &[(&str, &str)] {
        &[]
    }

    /// The JSON "tail"/overflow column holding the un-promoted record body —
    /// `ext` for UDM, `event` for OCSF. JSON extraction with no explicit,
    /// schema-mapped source column (e.g. `spath`) targets this (NAN-1343). The
    /// default reproduces UDM's `ext`; OCSF overrides it.
    fn json_tail_column(&self) -> &'static str {
        "ext"
    }

    // --- Detection semantics ---

    /// Semantic-role → physical field, in priority order. Replaces the three
    /// hard-coded entity-extraction lists in the detection engine.
    fn entity_extraction_order(&self) -> &[(EntityRole, &str)];

    /// Default field to attribute risk to when no rule-specified entity exists.
    fn risk_entity_default(&self) -> Option<&str>;

    // --- Enrichment ownership ---

    /// Whether nanosiem computes enrichment (`Materialized`, UDM) or only reads
    /// client-populated enrichment (`Read`, OCSF).
    fn enrichment_mode(&self) -> EnrichmentMode;

    /// Resolve a semantic enrichment concept to the physical field/path that
    /// carries it, if this schema exposes it.
    fn enrichment_field(&self, semantic: EnrichmentKind) -> Option<FieldResolution>;

    // --- Storage binding ---

    /// Fully-qualified table the active schema reads from
    /// (`nanosiem.logs` for UDM).
    fn table_name(&self) -> &str;

    /// SQL expression yielding the event timestamp as a `DateTime64`
    /// (`timestamp` for UDM; `fromUnixTimestamp64Milli(time)` for OCSF).
    fn timestamp_expr(&self) -> &str;

    /// Canonical SQL access expression for `field` (String-typed) — the same
    /// resolution the query generator's `field_access_expr` applies, exposed on
    /// the profile so raw-SQL builders that don't own a generator (asset dossier,
    /// lateral movement, signal matched-log fetch — NAN-1241) can resolve columns
    /// per the active schema instead of hardcoding UDM names:
    /// - [`FieldResolution::ExplicitColumn`] → escaped (possibly dotted) column
    /// - [`FieldResolution::JsonPath`] → `JSONExtractString(col, 'p1', …)` (OCSF tail)
    /// - everything else → UDM `ext.{field}` spill (byte-identical UDM behavior)
    ///
    /// Default impl is profile-agnostic; UDM and OCSF both inherit it. Pair with
    /// [`is_known_field`](Self::is_known_field) to SKIP fields a schema doesn't map
    /// (e.g. UDM `prevalence_process_hash` has no OCSF column) rather than emitting
    /// a dead `ext.` reference.
    /// SQL access expression for a UDM-SEMANTIC field name (NAN-1241). Raw-SQL
    /// builders that are written in UDM terms (`src_host`, `process_name`, …) use
    /// this so they resolve to the right physical column per schema:
    /// - UDM: `udm_field` IS the column → delegates to [`column_sql`](Self::column_sql).
    /// - OCSF: maps `udm_field` → the promoted OCSF column via the manifest's
    ///   `udm_field` correspondence; returns `None` when the schema has no column
    ///   for that UDM concept (caller SKIPS the field rather than emitting a dead
    ///   `ext.` reference / unknown-column 500).
    fn udm_column_sql(&self, udm_field: &str) -> Option<String> {
        Some(self.column_sql(udm_field))
    }

    /// The NATIVE display field name for a UDM-semantic concept under this schema
    /// — the bare key (no quoting/SQL) a result row should carry so callers and
    /// the UI see schema-native names. UDM returns the concept itself (the column
    /// IS the field). OCSF returns the promoted OCSF column name (e.g. `dest_host`
    /// → `dst_endpoint.hostname`), or the class-split primary column for split
    /// concepts. Returns `None` when the schema has no column for the concept.
    ///
    /// Pairs with [`udm_column_sql`](Self::udm_column_sql): that gives the SQL
    /// expression to SELECT, this gives the name to alias it to / read it back by,
    /// so a projection and its consumers stay in lockstep across schemas.
    fn display_field_name(&self, udm_field: &str) -> Option<String> {
        Some(udm_field.to_string())
    }

    /// The class-spanning VALUE expression for a UDM-semantic concept whose
    /// physical home is split across several columns by event class (NAN-1319).
    /// Under OCSF a "host"/"user"/"process"/"url" lives in different columns on
    /// different OCSF classes (e.g. the source host is `src_endpoint.hostname` on
    /// network events but `device.hostname` on endpoint/sysmon events), so a
    /// single-column projection drops every event of the other class. Returns
    /// `Some(if(...))` only for such split concepts; `None` for everything else
    /// (the caller then uses its normal single-column resolution).
    ///
    /// Default: `None` — UDM has no class-split (a UDM-semantic field IS one
    /// column), so projection / GROUP BY / SORT stay byte-identical. Pairs with
    /// [`udm_column_sql`](Self::udm_column_sql), which resolves the same split for
    /// raw-SQL builders; this exposes it to the `field_to_sql_expr` value/group
    /// seam so `stats count by src_host` sees the host wherever the class put it.
    fn class_split_value_sql(&self, _udm_field: &str) -> Option<String> {
        None
    }

    /// The INDEXED unified physical column that materializes the
    /// [`class_split_value_sql`](Self::class_split_value_sql) union for a class-
    /// split concept (NAN-1333). The inline `if(primary != s, primary, fallback)`
    /// value-pick is opaque to every skip index, so a filter on it full-scans;
    /// the active profile may materialize the same union into one plain column
    /// (with a words text index) and return its name here so the codegen emits the
    /// indexed column instead — restoring granule pruning while preserving the
    /// exact union semantics. Returns `Some(col)` only for split concepts that
    /// HAVE such a column.
    ///
    /// Default: `None` — UDM has no class-split, so all UDM codegen paths keep
    /// their single-column resolution byte-identical. OCSF overrides this.
    fn class_split_column(&self, _udm_field: &str) -> Option<String> {
        None
    }

    /// Enum label→int translation for a field whose RESOLVED physical column is
    /// an enum-encoded integer (NAN-1382 / parity gap G6). `field` is the nPL
    /// token (a UDM-semantic alias like `auth_result`, or the native column name
    /// like `status_id`); the implementation resolves it and returns how string
    /// verbs map onto the int — a fixed [`EnumIntMapping::Values`] table or a
    /// sibling [`EnumIntMapping::LabelColumn`]. Returns `None` when the field
    /// does not resolve to an enum-int column under this schema.
    ///
    /// Default: `None` — UDM stores verbs as strings (`auth_result` IS a String
    /// column), so every UDM codegen path is byte-identical. OCSF overrides this
    /// from the manifest's `enum_values` / `enum_label_column` metadata.
    fn enum_int_mapping(&self, _field: &str) -> Option<EnumIntMapping<'_>> {
        None
    }

    fn column_sql(&self, field: &str) -> String {
        match self.resolve(field) {
            FieldResolution::ExplicitColumn(c) => crate::query::escape_identifier(&c),
            FieldResolution::JsonPath { col, path } => {
                // Delegate to the SAME emission as `field_access_expr`'s JsonPath
                // arm (NAN-1426): native subcolumn access instead of
                // `JSONExtractString(event, …)`, which re-serialized the whole
                // `event` object per row. Keeping this seam in lockstep is what
                // the raw-SQL builders (asset dossier, lateral movement, signal
                // matched-log fetch — NAN-1241) rely on.
                crate::query::json_tail_access_sql(&col, &path, "String")
            }
            FieldResolution::ArrayElement { .. }
            | FieldResolution::Alias(_)
            | FieldResolution::Unknown => {
                // NAN-1411: a typed `ext.foo` must address the same spill key as
                // bare `foo` — the alnum filter below deletes the dot, so without
                // stripping the prefix first this emitted `ext.extfoo` (a key that
                // never exists). No live caller passes prefixed names here today
                // (callers use known UDM field names), but this default must stay
                // in lockstep with `field_access_expr`'s Unknown arm.
                let sanitize = |s: &str| -> String {
                    s.chars()
                        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
                        .collect()
                };
                let safe = match field.strip_prefix("ext.").map(sanitize) {
                    Some(key) if !key.is_empty() => key,
                    _ => sanitize(field),
                };
                format!("ext.{}", safe)
            }
        }
    }
}
