// SPDX-License-Identifier: AGPL-3.0-or-later

//! Standalone helper functions for ClickHouse SQL generation
//!
//! Contains field normalization, escaping, type detection, and other utilities
//! shared across the SQL generator submodules.

use super::ClickHouseSqlGenerator;
use super::EXPLICIT_COLUMNS_SET;

/// Generate SETTINGS clause based on context options
/// Includes max_execution_time=300 (5 minutes) for server-side query timeout
///
/// When `has_selective_indexed_eq` is true, `optimize_read_in_order` is disabled
/// so ClickHouse can parallelize granule reads instead of scanning sequentially
/// in timestamp order. This is critical for selective filters (e.g. src_host)
/// where most granules are empty — sequential scanning wastes I/O.
///
/// When `is_non_timechart_aggregation` is true, both `optimize_read_in_order` and
/// `optimize_aggregation_in_order` are disabled — GROUP BY scrambles the output
/// order anyway, so maintaining order during scan/aggregation wastes I/O and CPU.
/// Timechart keeps both enabled because temporal bucket ordering matters.
pub(crate) fn generate_settings(
    use_cache: bool,
    has_selective_indexed_eq: bool,
    is_non_timechart_aggregation: bool,
) -> String {
    let read_in_order = if has_selective_indexed_eq || is_non_timechart_aggregation { 0 } else { 1 };
    let agg_in_order = if is_non_timechart_aggregation { 0 } else { 1 };
    if use_cache {
        format!(
            "SETTINGS max_threads=16, max_execution_time=300, optimize_read_in_order={}, optimize_aggregation_in_order={}, use_query_cache=1, query_cache_ttl=300",
            read_in_order, agg_in_order
        )
    } else {
        format!(
            "SETTINGS max_threads=16, max_execution_time=300, optimize_read_in_order={}, optimize_aggregation_in_order={}",
            read_in_order, agg_in_order
        )
    }
}

/// Check if a field is a known UDM boolean column (UInt8 in ClickHouse).
/// Only applies to actual schema columns, NOT user-defined eval fields.
/// e.g. `ioc_matched` is a real UInt8 column, but `is_suspect` from an eval is a String.
pub(crate) fn is_boolean_field(field: &str) -> bool {
    use crate::udm::fields::{UdmDataType, UdmField};
    use std::str::FromStr;

    // Check if it's a known UDM field with Boolean type
    if let Ok(udm_field) = UdmField::from_str(field) {
        return udm_field.data_type() == UdmDataType::Boolean;
    }

    // ioc_matched is an explicit ClickHouse column (UInt8) but may not be in UDM enum
    field == "ioc_matched"
}

// Phase 4: the 50+ `normalize_field_name` call sites route through
// `profile.canonicalize()` then (dotted OCSF paths pass through UDM aliasing
// unchanged today, so leaving them is behavior-neutral for UDM).
pub(crate) fn normalize_field_name(field: &str) -> &str {
    match field {
        // Time field alias (PPL convention)
        "_time" => "timestamp",

        // CIM compatibility aliases
        "sourcetype" => "source_type",

        // Host aliases (common variations)
        "hostname" => "host",
        "dest_hostname" => "dest_host",
        "src_hostname" => "src_host",

        // User aliases (common variations)
        // Note: user_name is a real UDM column, don't alias it
        "username" => "user",

        // Destination shorthand (CIM)
        // Note: "source" is NOT aliased - it's a real column for audit subsystem
        "destination" => "dest",

        // IP address variations
        "source_ip" => "src_ip",
        "destination_ip" => "dest_ip",
        "src_address" => "src_ip",
        "dest_address" => "dest_ip",

        // Port variations
        "source_port" => "src_port",
        "destination_port" => "dest_port",

        // MAC address variations
        "source_mac" => "src_mac",
        "destination_mac" => "dest_mac",

        // Process variations (migration 086: process → command_line)
        "process" => "command_line",
        "parent_process" => "parent_command_line",

        // HTTP/Web aliases
        // Note: uri_path is a real UDM column, don't alias it
        "uri" => "url",
        "referer" => "http_referrer", // Common misspelling
        "referrer" => "http_referrer",
        "useragent" => "http_user_agent",
        // Note: user_agent is a real UDM column (used by audit logs), don't alias it

        // File aliases
        "filename" => "file_name",
        "filepath" => "file_path",

        // Status/Result aliases (string status like "success", "failure")
        // Note: result is a real UDM column, don't alias it
        "outcome" => "status",

        // HTTP status code aliases - map to status_code (numeric UInt16)
        // Note: status_code is a real UDM column, don't alias it
        "response_code" => "http_status_code", // Squid proxy, some web servers
        "http_status" => "http_status_code",   // CIM standard
        "http_response_code" => "http_status_code", // Another common form
        "resp_code" => "http_status_code",     // Abbreviated form

        // HTTP method aliases (map non-UDM names to UDM columns)
        // Note: http_method is a real UDM column, don't alias it
        "request_method" => "http_method", // Apache/nginx logs
        "method" => "http_method",         // Common short form

        // DNS field aliases - map common variations to actual column names
        "dns_query" => "query",
        "dns_response" => "answer",
        "dns_answer" => "answer",

        // Cloud aliases (CIM / ECS compatibility)
        "cloud.provider" => "cloud_provider",
        "cloud.account.id" => "cloud_account_id",
        "cloud.account.name" => "cloud_account_name",
        "cloud.region" => "cloud_region",
        "cloud.service.name" => "cloud_service",
        "service_name" => "cloud_service",

        // Windows Event / detection aliases
        "event_id" => "signature_id",
        "eventid" => "signature_id",

        // Add other aliases here as needed
        _ => field,
    }
}

/// Whether `table` projecting `name` as the bare `field_expr` would surface the
/// column under a name other than `name` (NAN-5306): `field_expr` is a
/// different column (`timestamp` for `time`) or an expression, whose result
/// ClickHouse names after the expression text.
pub(crate) fn table_field_renamed(field_expr: &str, name: &str) -> bool {
    field_expr != name && field_expr != escape_identifier(name)
}

/// The requested names `table` re-aliases on output because they resolve to a
/// differently named column or an expression (NAN-5306). Computed against the generator's
/// CURRENT scope, so call it for the stage being generated (before its own
/// outputs are registered). Wildcards and explicit aliases are excluded:
/// wildcard expansions project real column names, and an explicit alias is
/// already registered as a created column.
pub(crate) fn table_implicit_aliases(
    fields: &[crate::query::ast::TableField],
    gen: &ClickHouseSqlGenerator,
) -> Vec<String> {
    fields
        .iter()
        .filter(|f| f.alias.is_none() && !f.name.contains('*'))
        .filter(|f| {
            let (expr, needs_alias) = field_to_sql_expr(&f.name, gen);
            needs_alias || table_field_renamed(&expr, &f.name)
        })
        .map(|f| f.name.clone())
        .collect()
}

/// The name `table` leaves the event time column in scope under, when it is
/// not its own (NAN-5306 review): `table time, src_ip` projects
/// `timestamp AS time`, so later stages that read the event time must read
/// `time`. `None` when the time column is projected under its own name (or a
/// field is re-aliased TO it), when nothing projects it, or for a wildcard
/// list (wildcards expand to physical names). `current` is the name the time
/// column is in scope under before this `table` (a second `table time`).
pub(crate) fn table_time_alias(
    fields: &[crate::query::ast::TableField],
    current: Option<&str>,
    gen: &ClickHouseSqlGenerator,
) -> Option<String> {
    let time_col = gen.time_column();
    let in_scope = gen.time_column_in_scope();
    let mut alias = None;
    for f in fields {
        if f.name.contains('*') {
            return None;
        }
        let out = f.alias.as_deref().unwrap_or(&f.name);
        if out.eq_ignore_ascii_case(time_col) {
            return None;
        }
        let (expr, _) = field_to_sql_expr(&f.name, gen);
        let reads_time = expr == time_col
            || current.is_some_and(|c| f.name == c)
            || expr == in_scope && current.is_some();
        if reads_time && alias.is_none() {
            alias = Some(out.to_string());
        }
    }
    alias
}

/// Convert a field name to its SQL expression, handling metadata fields
/// Returns (sql_expression, needs_alias) where needs_alias indicates if the field
/// should be aliased to its original name for clean output
pub(crate) fn field_to_sql_expr(field: &str, gen: &ClickHouseSqlGenerator) -> (String, bool) {
    // A field an UPSTREAM pipeline stage created with a new value (rex capture,
    // eval assignment, rename target, …) shadows any same-named schema field or
    // UDM alias for the rest of the pipeline — checked on the PRE-normalization
    // name, BEFORE alias normalization and schema resolution. Otherwise
    // `rex "(?P<method>…)" | stats count by method` normalizes `method` →
    // `http_method`, resolves it to the schema column, and silently discards
    // the capture (NAN-1341). Plain `stats by method` (no upstream compute) is
    // untouched: stats by-field passthroughs are deliberately NOT in this set.
    if gen.is_upstream_computed_field(field) {
        return (escape_identifier(field), false);
    }

    // Normalize field name (apply aliases). NAN-1555: profile-aware so spans keep
    // `service_name` (not the UDM `cloud_service` alias); logs byte-identical.
    let field = gen.canonicalize_field(field);

    // NAN-1555: spans/metrics — a non-promoted field is an attribute `Map` lookup
    // (`MapKey`), resolved by the profile via `field_access_expr` (the
    // `attributes['key']` subscript), NOT the UDM `metadata`/`ext` JSON paths or a
    // bare column reference below. UDM/OCSF never return `MapKey` → skipped. (A
    // stats split-by on an attribute re-derives this in the GROUP BY stage, which
    // is fine: stage_0 passes the maps through; the computed-name hazard lives in
    // the `| where` path, guarded in `generate_where_condition`, not here.)
    if gen.resolves_to_map_key(field) {
        return (gen.field_access_expr(field, "String"), true);
    }

    // Fields with metadata_ prefix always go to JSON
    if field.starts_with("metadata_") {
        return (gen.generate_json_extract(field, "String"), true);
    }

    // A field the active schema resolves to a real physical column: a UDM
    // explicit column, an OCSF promoted column, or (NAN-1248) a UDM-semantic
    // alias like `src_ip` → `src_endpoint.ip`. `field_access_expr` emits the
    // resolved column. UDM byte-identical: `resolve()` returns the same name for
    // UDM explicit columns, so `field_access_expr` == `escape_identifier(field)`
    // exactly as before. Gating on `resolves_to_column` (not `is_known_field`,
    // which under OCSF only knows native dotted names) is what lets a UDM-named
    // `stats by src_ip` GROUP BY the promoted OCSF column instead of a bare
    // reference (500) or an `ext`/JSONExtract miss.
    if gen.resolves_to_column(field) {
        // NAN-1319: a UDM-semantic concept OCSF splits across columns by event
        // class (the source host is `src_endpoint.hostname` on network events but
        // `device.hostname` on endpoint/sysmon events; user/process span actor.*
        // too) must PROJECT / GROUP BY / SORT on the class-spanning value, or
        // `stats count by src_host` sees only network hosts and drops every
        // endpoint event. Mirror the raw-SQL builders (`udm_column_sql`). UDM has
        // no class-split → `None`, so this is byte-identical there; native OCSF
        // dotted names aren't UDM concepts → `None`, so they keep `field_access_expr`.
        // NAN-1333: project / GROUP BY / SORT on the INDEXED unified column when
        // the split concept has one (materializes the same union, prunes via its
        // words index); else the inline value-pick `if(...)`. UDM → both `None` →
        // byte-identical.
        if let Some(col) = gen.class_split_column(field) {
            return (escape_identifier(&col), false);
        }
        if let Some(split_expr) = gen.class_split_value_sql(field) {
            return (split_expr, false);
        }
        return (gen.field_access_expr(field, "String"), false);
    }

    // Dot notation means nested metadata access
    if field.contains('.') {
        // NAN-1644 (finding 2.6): a UDM `ext.*` path is a NATIVE ext-tail
        // field, not metadata JSON — the ingest pipeline never writes an
        // 'ext' key into `metadata`, so the old
        // `JSONExtractString(metadata, 'ext', …)` collapsed every row into
        // one '' bucket for stats/table/chart on ext fields. stage_0
        // materializes `toString(ext.<key>) AS "ext.<key>"`
        // (`analyze_ext_fields`), so reference the projected alias here —
        // re-deriving the ext expression in a later stage over a `SELECT *`
        // stage_0 defeats ClickHouse 26.4 JSON-subcolumn pruning and reads
        // the whole ext column (Saturn-measured 22.68 GiB / 65x regression).
        // OCSF never takes this branch for ext.*: its profile resolves the
        // path to the `event` tail (JsonPath), routed natively by
        // `generate_json_extract`. `metadata_`-prefixed and `metadata.*`
        // names were already returned above / keep the JSON path below.
        if field.starts_with("ext.") && !gen.resolves_to_json_path(field) {
            return (escape_identifier(field), false);
        }
        // NAN-4934: past stage_0 a tail field it projected is a plain String
        // column. No cast and no re-alias: `toString("f") AS "f"` would make a
        // `GROUP BY toString("f")` bind the alias, not stage_0's column (Code 215).
        if let Some(alias) = gen.stage_tail_alias(field, "String") {
            return (alias, false);
        }
        return (gen.generate_json_extract(field, "String"), true);
    }

    // A field produced earlier in this pipeline (eval, stats alias, risk, …) is
    // a real column in the current scope — reference it directly, even if its
    // name collides with a "known metadata" field. Without this, `risk_factors`
    // / `raw_risk_score` after a `| risk` command would be JSON-extracted from
    // the `metadata` column, which is wrong (and errors outright once a `stats`
    // upstream has dropped `metadata`). Stored-signal search, which has no such
    // pipeline command, still falls through to JSON extraction below. (NAN-1236)
    if gen.is_computed_field(field) {
        return (escape_identifier(field), false);
    }

    // `{func}_{field}` reference to an UN-aliased aggregation earlier in the
    // pipeline (NAN-1339): `… | chart avg(bytes_in) over X | sort -avg_bytes_in`
    // — the output column is literally `avg`, but the `values_`/`list_` naming
    // convention makes `avg_bytes_in` the intuitive reference. Resolve it to
    // the actual output column (aliased back for projections).
    if let Some(target) = gen.agg_reference_alias(field) {
        return (escape_identifier(&target), true);
    }

    // Known metadata fields that need JSON extraction
    // These are fields stored in the metadata JSON column but commonly queried
    if is_known_metadata_field(field) {
        let json_type = get_metadata_field_type(field);
        return (gen.generate_json_extract(field, json_type), true);
    }

    // Unknown bare field. Under OCSF an unmapped/unpromoted name is part of the
    // `event` tail → native subcolumn access ('' when absent, NAN-1426) rather
    // than a bare column reference that 500s with "Unknown identifier". Under UDM `resolve` never
    // yields JsonPath, so this is skipped and the bare reference (a computed /
    // renamed / previous-stage column) is preserved byte-identically. Computed
    // pipeline fields were already returned above (is_computed_field). (NAN-1248)
    if gen.resolves_to_json_path(field) {
        // NAN-1911: a JSON-tail field the profile types as numeric
        // (OCSF's unmapped `risk_score` / `raw_risk_score`) must extract as
        // `Float64`, not `String` — otherwise `| stats sum(risk_score)` sums a
        // `toString(...)` and CH rejects it ("Illegal type String … for sum").
        // `json_tail_access_sql` emits the numeric subcolumn extractor for
        // `"Float"`. UDM never resolves numerics to JsonPath, so this is
        // byte-identical there.
        let json_type = if gen.is_numeric_field(field) {
            "Float"
        } else {
            "String"
        };
        // NAN-4934: see the dotted branch above.
        if let Some(alias) = gen.stage_tail_alias(field, json_type) {
            return (alias, false);
        }
        return (gen.field_access_expr(field, json_type), true);
    }
    // For unknown fields without metadata_ prefix and no dots:
    // Treat as a direct column reference (could be a computed column from eval,
    // a renamed column, or a column from a previous stage)
    (escape_identifier(field), false)
}

/// Resolve a by-field / GROUP BY / PARTITION BY / dedup-key reference for the
/// multi-stage window commands (eventstats / streamstats / anomaly / funnel /
/// sequence / dedup) in a SchemaProfile-aware way.
///
/// These commands historically emitted `escape_identifier(normalize_field_name(f))`
/// directly, which under OCSF produces a bare reference to a UDM name that is not
/// an OCSF column (`src_ip` → 500 in a GROUP BY, or a silent miss). This routes a
/// field the active profile resolves to a real column (UDM explicit column, OCSF
/// promoted column, or — NAN-1248 — a UDM-semantic alias like `src_ip` →
/// `src_endpoint.ip`) through [`field_access_expr`]; everything else keeps the
/// exact legacy `escape_identifier(normalize_field_name(f))` form. UDM is therefore
/// byte-identical (under UDM `resolves_to_column` ⇔ the field is an explicit column,
/// and `field_access_expr` returns the same escaped name).
///
/// [`field_access_expr`]: ClickHouseSqlGenerator::field_access_expr
pub(crate) fn by_field_sql(field: &str, gen: &ClickHouseSqlGenerator) -> String {
    // Upstream value-computed fields shadow schema fields / UDM aliases —
    // checked on the PRE-normalization name, before alias normalization and
    // schema resolution, mirroring `field_to_sql_expr` (NAN-1341).
    if gen.is_upstream_computed_field(field) {
        return escape_identifier(field);
    }
    // NAN-1555: profile-aware canonicalization (spans keep `service_name`); logs
    // byte-identical via the free alias map.
    let field = gen.canonicalize_field(field);
    // NAN-1555: spans attribute `Map` lookup → `field_access_expr` subscript.
    if gen.resolves_to_map_key(field) {
        return gen.field_access_expr(field, "String");
    }
    if gen.resolves_to_column(field) {
        // NAN-1319: class-split UDM concepts (OCSF host/user/process/url) PARTITION
        // / GROUP / dedup on the class-spanning value, same as `field_to_sql_expr`.
        // `None` for UDM and native fields → byte-identical legacy behavior.
        // NAN-1333: prefer the indexed unified column (same union, words-index
        // prunable) over the inline value-pick. UDM → `None` → byte-identical.
        if let Some(col) = gen.class_split_column(field) {
            return escape_identifier(&col);
        }
        if let Some(split_expr) = gen.class_split_value_sql(field) {
            return split_expr;
        }
        gen.field_access_expr(field, "String")
    } else if !gen.is_computed_field(field) && gen.resolves_to_json_path(field) {
        // OCSF unmapped/tail field → native `event` subcolumn access (empty if
        // absent, NAN-1426), not a bare reference that 500s in GROUP BY /
        // PARTITION BY. Computed
        // pipeline fields are excluded — they are real in-scope columns and stay
        // bare. UDM never hits this (resolve never yields JsonPath). (NAN-1248)
        // NAN-1911: a numeric tail field (OCSF `risk_score`) partitions / dedups
        // / groups on its Float64 value so the window-command key matches the
        // Float64 projection the base scan emits; else lexicographic. UDM never
        // reaches this branch, so it stays byte-identical.
        let json_type = if gen.is_numeric_field(field) {
            "Float"
        } else {
            "String"
        };
        gen.field_access_expr(field, json_type)
    } else {
        escape_identifier(field)
    }
}

/// The OUTPUT alias for a by-field / projected field: an upstream
/// value-computed field keeps its PRE-normalization name — it shadows the
/// schema alias, and the bare raw name is exactly what `field_to_sql_expr` /
/// `by_field_sql` emit for it, so the alias must follow or downstream stages
/// reference a column that no longer exists (NAN-1341). Everything else keeps
/// the canonical `normalize_field_name` alias exactly as before.
pub(crate) fn by_field_output_name<'a>(field: &'a str, gen: &ClickHouseSqlGenerator) -> &'a str {
    if gen.is_upstream_computed_field(field) {
        field
    } else {
        // NAN-1555: profile-aware so the spans output alias matches the group/sort
        // expression (`service_name`, not the UDM `cloud_service` alias). Logs keep
        // the exact `normalize_field_name` alias (byte-identical).
        gen.canonicalize_field(field)
    }
}

/// Check if a field is a known metadata field that should be extracted from JSON
/// Note: This is only for fields that are NOT UDM fields but are commonly queried from metadata
pub(crate) fn is_known_metadata_field(field: &str) -> bool {
    matches!(
        field,
        // Signal-specific metadata fields (not in UDM schema)
        "raw_risk_score"
            | "risk_factors"
            | "signal_type"
            | "rule_query"
            | "rule_mode"
            | "alert_id"
            | "matched_event_count"
            | "realtime"
            | "detected_at"
            | "mitre_tactics"
            | "mitre_techniques"
    )
}

/// Get the appropriate JSON extraction type for a known metadata field
/// Note: ClickHouse uses JSONExtractInt (not Int64), JSONExtractUInt, JSONExtractFloat, etc.
pub(crate) fn get_metadata_field_type(field: &str) -> &'static str {
    match field {
        // Numeric fields - use Int for signed integers in ClickHouse
        "raw_risk_score" | "matched_event_count" => "Int",
        // Boolean fields
        "realtime" => "Bool",
        // Array fields (extract as string for now, can be parsed later)
        "risk_factors" | "mitre_tactics" | "mitre_techniques" => "String",
        // String fields (default)
        _ => "String",
    }
}

/// Check if a field is a UDM field (direct column or JSON) vs metadata (JSON)
///
/// In the hybrid schema:
/// - Explicit columns are stored as direct columns with bloom filters
/// - Other UDM fields are stored in the `ext` JSON column (extended fields)
/// - Non-UDM fields are stored in the `metadata` JSON column
///
/// Phase 2b re-pointed the generator-scoped callers at
/// `ClickHouseSqlGenerator::is_known_profile_field` (→ `profile.is_known_field`),
/// so the only remaining references are the free-fn classification semantics this
/// keeps as the canonical helper. `#[allow(dead_code)]` while no in-tree caller
/// remains; Phase 4 may route the free-fn analysis helpers through it.
#[allow(dead_code)]
pub(crate) fn is_udm_field(field: &str) -> bool {
    use crate::udm::fields::UdmField;
    use std::str::FromStr;

    // Check if it's an explicit column (direct column access)
    if EXPLICIT_COLUMNS_SET.contains(field) {
        return true;
    }

    // Check if it's a valid UDM field (will be stored in ext JSON column)
    if UdmField::from_str(field).is_ok() {
        return true;
    }

    // Also check common computed/result column names (from stats, timechart, etc.)
    matches!(
        field,
        "count"
            | "sum"
            | "avg"
            | "min"
            | "max"
            | "total"
            | "time_bucket"
            | "bytes"
            | "total_bytes"
            | "requests"
    )
}

/// Convert a comparator to SQL operator
pub(crate) fn comparator_to_sql(op: &crate::query::ast::Comparator) -> &'static str {
    use crate::query::ast::Comparator;
    match op {
        Comparator::Eq => "=",
        Comparator::Ne => "!=",
        Comparator::Gt => ">",
        Comparator::Lt => "<",
        Comparator::Gte => ">=",
        Comparator::Lte => "<=",
        Comparator::Regex => "LIKE", // Handled specially with match()
        Comparator::NotRegex => "NOT LIKE",
        Comparator::Like => "LIKE",
        Comparator::NotLike => "NOT LIKE",
        Comparator::Contains => "LIKE",
        Comparator::NotContains => "NOT LIKE",
        Comparator::StartsWith => "LIKE",
        Comparator::NotStartsWith => "NOT LIKE",
        Comparator::EndsWith => "LIKE",
        Comparator::NotEndsWith => "NOT LIKE",
    }
}

/// Convert a Value to SQL literal
pub(crate) fn value_to_sql(value: &crate::query::ast::Value) -> String {
    use crate::query::ast::{IntervalUnit, Value};
    match value {
        Value::String(s) => format!("'{}'", escape_string(s)),
        Value::Number(n) => {
            if n.fract() == 0.0 {
                format!("{}", *n as i64)
            } else {
                format!("{}", n)
            }
        }
        Value::Bool(b) => if *b { "1" } else { "0" }.to_string(),
        Value::Ip(ip) => format!("'{}'", ip),
        Value::Regex(pattern) => format!("'{}'", escape_regex_pattern(pattern)),
        // Intervals are converted to ClickHouse interval syntax
        Value::Interval(duration, unit) => {
            let seconds = duration.as_secs();
            match unit {
                IntervalUnit::Microsecond => {
                    format!("INTERVAL {} MICROSECOND", seconds * 1_000_000)
                }
                IntervalUnit::Millisecond => format!("INTERVAL {} MILLISECOND", seconds * 1_000),
                IntervalUnit::Second => format!("INTERVAL {} SECOND", seconds),
                IntervalUnit::Minute => format!("INTERVAL {} MINUTE", seconds / 60),
                IntervalUnit::Hour => format!("INTERVAL {} HOUR", seconds / 3600),
                IntervalUnit::Day => format!("INTERVAL {} DAY", seconds / 86400),
                IntervalUnit::Week => format!("INTERVAL {} WEEK", seconds / 604800),
                IntervalUnit::Month => format!("INTERVAL {} MONTH", seconds / 2592000),
                IntervalUnit::Year => format!("INTERVAL {} YEAR", seconds / 31536000),
            }
        }
    }
}

/// Convert a Value to SQL literal, respecting the target field's column type
/// per the ACTIVE schema profile (NAN-1241). A numeric literal compared against a
/// String column is quoted to avoid CH type-mismatch; numeric columns keep the
/// bare literal. The profile drives the String-vs-numeric decision so OCSF
/// promoted columns are typed correctly instead of falling through the UDM list.
pub(crate) fn value_to_sql_for_field(
    field: &str,
    value: &crate::query::ast::Value,
    profile: &dyn crate::schema::SchemaProfile,
) -> String {
    if is_text_column(field, profile) {
        match value {
            crate::query::ast::Value::Number(n) => {
                if n.fract() == 0.0 {
                    format!("'{}'", *n as i64)
                } else {
                    format!("'{}'", n)
                }
            }
            _ => value_to_sql(value),
        }
    } else {
        value_to_sql(value)
    }
}

/// Check if a field is stored as String/LowCardinality(String) in ClickHouse for
/// the active schema. Used by `value_to_sql_for_field` to auto-quote numeric
/// literals for String columns, preventing type mismatch errors (e.g.
/// `signature_id = 4672` → `signature_id = '4672'`).
///
/// A field is "text" when it is a known column of the active schema and the
/// profile does not classify it as numeric. For UDM this is byte-identical to the
/// previous `EXPLICIT_COLUMNS_SET.contains && !NUMERIC_COLUMNS.contains` check —
/// `UdmProfile::is_numeric_field` is backed by exactly that numeric list and
/// `is_known_field`/`resolve` by `EXPLICIT_COLUMNS_SET`.
pub(crate) fn is_text_column(field: &str, profile: &dyn crate::schema::SchemaProfile) -> bool {
    matches!(
        profile.resolve(field),
        crate::schema::FieldResolution::ExplicitColumn(_)
    ) && !profile.is_numeric_field(field)
}

/// Translate a string literal against a field whose resolved physical column is
/// an enum-encoded INT with a fixed label table (NAN-1382 / parity gap G6) into
/// the integer SQL literal to compare with:
/// - a known label (case-insensitive) → its enum id (`"failure"` → `2`)
/// - a numeric string → passed through as the id (UI drilldowns send the int as
///   a string: `status_id="2"` → `2`)
/// - anything else → a LOUD validation error listing the valid labels — never a
///   silent zero-match (`lower(toString(<int col>)) = 'verb'` matched nothing).
pub(crate) fn enum_values_literal_sql(
    field: &str,
    labels: &std::collections::HashMap<String, i64>,
    s: &str,
) -> Result<String, crate::query::sql_gen::SqlGenError> {
    let lower = s.to_lowercase();
    if let Some(id) = labels.get(lower.as_str()) {
        return Ok(id.to_string());
    }
    // Emit the PARSED value (not the raw string) so oddly-spelled-but-parseable
    // inputs ("+2", "007") become canonical integer literals.
    if let Ok(id) = lower.parse::<i64>() {
        return Ok(id.to_string());
    }
    let mut known: Vec<&str> = labels.keys().map(|k| k.as_str()).collect();
    known.sort_unstable();
    Err(crate::query::sql_gen::SqlGenError::InvalidQuery(format!(
        "'{}' is not a valid value for '{}' — expected one of: {} (or the integer enum id)",
        s,
        field,
        known.join(", ")
    )))
}

/// Escape a string for SQL (single quotes).
/// Thin alias over the canonical [`crate::sql_hygiene::escape_sql_string`]
/// (backslash escaped before quotes); kept as a local name for the many
/// SQL-gen call sites (NAN-1616).
pub(crate) fn escape_string(s: &str) -> String {
    crate::sql_hygiene::escape_sql_string(s)
}

/// Escape a regex pattern for SQL.
/// Byte-identical to [`escape_string`] — backslashes and single quotes are
/// escaped for embedding in a SQL string literal.
/// Note: `?` is NOT escaped here — the executor's `escape_question_marks_in_strings`
/// handles escaping `?` inside string literals for the clickhouse-rs crate.
/// Escaping `?` here would double-escape and break regex inline flags like `(?i)`.
pub(crate) fn escape_regex_pattern(s: &str) -> String {
    crate::sql_hygiene::escape_sql_string(s)
}

/// NAN-1426: native JSON **subcolumn** access expression for an OCSF tail path
/// (`FieldResolution::JsonPath`), replacing the `JSONExtract<T>(event, 'a', 'b')`
/// emission. `event` is a native `JSON` column, and `JSONExtract*` on it
/// re-serializes the ENTIRE event object per row — the largest column read in
/// full for every unpromoted-field filter/projection — while subcolumn access
/// (`event."a"."b"`) reads only that path's columnar substream. Measured on
/// local CH 26.4 (3M-row `ocsf_logs`): 8.06 GiB → 64 MiB (~125x read_bytes) on
/// the headline string-equality probe, identical row counts.
///
/// The naive rewrite alone CHANGES results; each typed form below carries a
/// verifier-mandated parity carve-out (all empirically validated, see NAN-1426):
///
/// - `"String"` → a `multiIf` over the subcolumn that is byte-identical to
///   `JSONExtractString(event, …)` on every value shape:
///   - **scalar / array leaf** (`isNotNull(sub)`): `toString(sub)` — numbers,
///     bools, and arrays format identically to JSONExtractString-over-the-JSON-
///     column because that function operates on the column's own CH
///     serialization (e.g. `['a','b']` with single quotes for string arrays —
///     verified equal on all 13,899 local array rows).
///   - **object-valued path** (subcolumn is NULL but subpaths exist):
///     `toJSONString(event.^"a"."b")` — the `^` prefix reads only the subtree's
///     substreams and serializes byte-identically to the old raw-JSON return
///     (verified equal on every object row locally). `toString(event.a.b)`
///     alone would return `''` here and silently break raw-JSON hunts
///     (`unmapped CONTAINS '"key":"val"'`) and `field=""` semantics.
///   - **missing key / JSON null**: `''` — same as JSONExtractString, which is
///     what keeps the NAN-1161 negation guarantee (`field != "x"` keeps
///     absent-key rows; the expression is never NULL).
/// - `"Float"` → `coalesce(accurateCastOrNull(sub, 'Float64'), 0.)`.
///   `JSONExtractFloat` returns **0** for missing keys; a bare cast returns
///   NULL — without the coalesce, `field=0` flips 2.7M→0 and `field!=7` drops
///   every absent-key row on local data. `accurateCastOrNull` matches
///   JSONExtractFloat on every edge probed: numeric strings ("42.5"→42.5),
///   non-numeric strings (→NULL→0), bools (true→1), objects/arrays (→NULL→0).
///   (Suffix nomenclature: the extractor is `Float`, NOT `Float64` — NAN-1383.)
/// - `"NullableFloat"` → `accurateCastOrNull(sub, 'Float64')`: the predicate
///   form for numeric OCSF attributes (NAN-4918). Absent / malformed values
///   stay NULL so a comparison excludes them rather than treating them as 0.
/// - anything else (`"Bool"`, raw forms) → the legacy `JSONExtract{T}` form.
///   `Bool` is deliberately NOT converted: `accurateCastOrNull('true','Bool')`
///   is `true` where `JSONExtractBool` returns `false` for string-typed values,
///   so the cast form is not parity-safe. Array access keeps its
///   `JSONExtractArrayRaw` forms untouched (emitted elsewhere).
///
/// Path segments are embedded as double-quoted identifiers, valid for CH
/// subcolumn access including reserved words and spaces (verified). CH
/// processes BOTH backslash escapes and `""`-doubling inside double-quoted
/// identifiers (verified on 26.4: `"a\\b"` addresses the key `a\b`,
/// `"se""lect"` addresses `se"lect`), so backslashes must be escaped first —
/// a raw `\` would silently escape the following character and address the
/// wrong key (or break out of the identifier on a trailing `\`). `col` is a
/// resolver-owned column name (`event` / `metadata`), embedded as-is like the
/// old emission.
///
/// Saturn note: tenants exceeding `max_dynamic_paths=1024` push overflow paths
/// into shared data, which subcolumn reads must scan — less surgical, but never
/// worse than the full-event decode this replaces.
pub(crate) fn json_tail_access_sql(col: &str, path: &[String], json_type: &str) -> String {
    if path.iter().any(|p| p == JSON_ARRAY_SEGMENT) {
        return json_array_access_sql(col, path, json_type);
    }
    let segments: Vec<String> = path
        .iter()
        .map(|p| crate::sql_hygiene::quote_identifier_always(p))
        .collect();
    let sub = format!("{}.{}", col, segments.join("."));
    // CH-2610 adoption: a JSON type hint (`json_hints.json`) stores the path as
    // a typed Nullable(String) subcolumn, and the insert cast turns any value a
    // producer sends there (number, object, array) into its text. So the typed
    // subcolumn alone answers both the scalar and the object case: reading it
    // skips the `event.^path` sub-object read, which scans the shared data and
    // dominated the cost (measured 3.3-4.3x warm on equality/presence/wildcard
    // filters over the hinted path, identical results). A NULL is an absent
    // path, as for Dynamic paths. Gated on the hint being physically present in
    // this deployment's table (`is_event_json_hint` reads the boot-detected
    // live schema): on an unhinted table an object value sits in `event.^path`
    // and only the parity form below finds it.
    if col == "event"
        && matches!(json_type, "String" | "Presence")
        && crate::schema::is_event_json_hint(&path.join("."))
    {
        let typed = format!("ifNull(toString({sub}), '')");
        return if json_type == "String" {
            typed
        } else {
            format!("({typed} NOT IN ('', '[]'))")
        };
    }
    match json_type {
        "Presence" => {
            let subtree = format!("toJSONString({}.^{})", col, segments.join("."));
            // Serialize the Dynamic value before checking emptiness: [] is
            // absent, but the string "[]", numeric zero and false are present.
            // Objects live in the subtree rather than the scalar subcolumn.
            format!(
                "(({sub} IS NOT NULL AND toJSONString({sub}) NOT IN ('\"\"', '[]')) OR {subtree} != '{{}}')"
            )
        }
        "String" => {
            let subtree = format!("toJSONString({}.^{})", col, segments.join("."));
            format!(
                "multiIf(isNotNull({sub}), toString({sub}), {subtree} != '{{}}', {subtree}, '')"
            )
        }
        "Float" => format!("coalesce(accurateCastOrNull({sub}, 'Float64'), 0.)"),
        // NAN-4918: predicate form. Absent or non-numeric stays NULL, so SQL
        // three-valued logic excludes the row from `<`, `!=`, `IN`, `NOT IN`
        // alike instead of comparing a fabricated 0.
        "NullableFloat" => format!("accurateCastOrNull({sub}, 'Float64')"),
        _ => {
            let path_args: Vec<String> = path
                .iter()
                .map(|p| format!("'{}'", escape_string(p)))
                .collect();
            format!("JSONExtract{}({}, {})", json_type, col, path_args.join(", "))
        }
    }
}

/// Path-segment marker for an OCSF array (NAN-4903). A profile puts it after a
/// segment that is an array: `["answers", "[]", "rdata"]` is `answers[].rdata`
/// (array of objects); a trailing marker (`["email", "to", "[]"]`) is a leaf
/// array of scalars. [`json_tail_access_sql`] then returns an `Array(String)`
/// (or `Array(Float64)`) expression instead of a scalar.
pub(crate) const JSON_ARRAY_SEGMENT: &str = "[]";

/// Array form of [`json_tail_access_sql`] for paths carrying
/// [`JSON_ARRAY_SEGMENT`] markers.
///
/// - Arrays of objects use ClickHouse's native `col."a"[]."b"` element access
///   (`Array(Dynamic)`, NULL where an element lacks the key); nested arrays
///   (`a[].b[].c`) come back as `Array(Array(..))` and are `arrayFlatten`ed so
///   membership (`has`) sees every value.
/// - A trailing marker is a leaf array of scalars (`email.to`): the subcolumn is
///   a `Dynamic` that normally holds an array, but a producer may send a lone
///   scalar, so the cast is guarded by `dynamicType` (a bare CAST of a String
///   value throws "Array does not start with '['" — measured on 26.10).
///
/// Elements are stringified with `ifNull(toString(x), '')`, so missing keys
/// keep their slot (positional, like the promoted array columns) and compare as
/// `''`. `toString()` of the result renders `['a','b']`, the shape rule evals
/// such as `tostring(module.file.signatures.state) CONTAINS "'valid'"` expect.
fn json_array_access_sql(col: &str, path: &[String], json_type: &str) -> String {
    let quote = |p: &str| crate::sql_hygiene::quote_identifier_always(p);
    let leaf_array = path.last().map(String::as_str) == Some(JSON_ARRAY_SEGMENT);
    let body = if leaf_array { &path[..path.len() - 1] } else { path };
    let mut expr = col.to_string();
    let mut depth = 0usize;
    for seg in body {
        if seg == JSON_ARRAY_SEGMENT {
            expr.push_str("[]");
            depth += 1;
        } else {
            expr.push('.');
            expr.push_str(&quote(seg));
        }
    }
    let elems = if depth == 0 {
        // Leaf scalar array only.
        format!(
            "if(dynamicType({expr}) LIKE 'Array(%', CAST({expr}, 'Array(Nullable(String))'), if(isNull({expr}), [], [toString({expr})]))"
        )
    } else if depth > 1 {
        format!("arrayFlatten({expr})")
    } else {
        expr
    };
    match json_type {
        "Float" | "NullableFloat" => format!("arrayMap(x -> coalesce(accurateCastOrNull(x, 'Float64'), 0.), {elems})"),
        _ => format!("arrayMap(x -> ifNull(toString(x), ''), {elems})"),
    }
}

/// NAN-1555: access a ClickHouse `Map(String, String)` attribute tail by LITERAL
/// dotted key — `attributes['http.method']` — with an optional second map column
/// tried when the key is absent in the primary (`resource_attributes` for spans).
///
/// Unlike [`json_tail_access_sql`] (which extracts from a JSON column and, on the
/// UDM `Unknown` arm, sanitizes dots out of the key) this is a native `Map`
/// subscript: the dotted OTel attribute name is preserved verbatim as the key.
/// `map[absent]` already yields `''` for `Map(_, String)`, but the explicit
/// `has()` guard keeps a real empty-string value and an absent key unambiguous and
/// makes the resource fallback exact. Mirrors `otel::tag_lookup_expr` (the
/// metrics-v2 tag resolver) so spans and metrics resolve attributes identically.
/// `key` is escaped; `col`/`fallback` are profile-supplied literals.
pub(crate) fn map_tail_access_sql(col: &str, fallback: Option<&str>, key: &str) -> String {
    let k = escape_string(key);
    match fallback {
        Some(fb) => format!(
            "if(has({col}, '{k}'), {col}['{k}'], if(has({fb}, '{k}'), {fb}['{k}'], ''))"
        ),
        None => format!("if(has({col}, '{k}'), {col}['{k}'], '')"),
    }
}

/// NAN-1416: minimum length for an index-guard token (which must also contain
/// at least one ASCII letter). Empirical (local CH 26.4, 2M-row `logs`,
/// medians of 4 runs, query-condition-cache off):
///
/// - short tokens are catastrophic when they don't prune — the per-row
///   substring scan for a short common needle costs more than the full-needle
///   scan it guards (`%cmd%` +153% CPU, `%192%` +159% CPU, zero granules
///   pruned);
/// - 5-char tokens are coin-flips (`%query%` −22% CPU on a sparse phrase, but
///   `%event%` +26% CPU on a dense one);
/// - numeric-only tokens (IP octets, ports, build numbers) are ubiquitous in
///   log text and never pruned meaningfully (`%22621%` +15% CPU);
/// - ≥6-char lettered tokens stayed within noise on every dense probe
///   (`%svchost%` +7%, `%provider%` +8%) and won big when selective
///   (`%failed%` −47% CPU / 3.0x fewer bytes, `%ycombinator%` −55% / 3.7x).
///
/// The audit (QUERY_PERF_AUDIT.md B2) proposed ≥3; measurement moved it to
/// ≥6 + letter. Needles whose tokens all fail the bar emit NO guard — the
/// safe failure mode is the unchanged pre-NAN-1416 shape, never a wrong or
/// costly guard.
pub(crate) const GUARD_TOKEN_MIN_LEN: usize = 6;

/// NAN-1416: longest index-servable token of a multi-token search needle.
///
/// CH 26.4's `text(tokenizer = splitByNonAlpha)` index serves
/// `lower(col) iLike '%needle%'` via a dictionary-substring scan ONLY when the
/// needle is a single token: any non-alphanumeric char in the needle (space,
/// `.`, `-`, `_`, `/`, …) makes the index bail and the column full-scans —
/// measured up to 307x read_bytes on `%failed login%` vs `%failed%`. The fix:
/// AND an index-servable guard `... LIKE '%<longest token>%'` after the
/// full-needle predicate (full-needle first — see the Keyword arm for the
/// ordering rationale). Every token is a contiguous substring of the needle,
/// so `full ∧ guard ≡ full` — byte-identical results by construction.
///
/// Returns `Some(token)` only when the (already-lowercased) needle splits into
/// **more than one** token and at least one token passes the
/// [`GUARD_TOKEN_MIN_LEN`]+letter bar; picks the longest qualifying token,
/// ties resolving to the first occurrence (deterministic SQL). Single-token
/// needles return `None` so their emission shape is untouched (the
/// single-token LIKE is already index-served with DIRECT READ — do not
/// disturb it). Longest-token-only is deliberate: ANDing *all* tokens was
/// measured to regress dense matches (CPU 0.90M→1.63M µs) for marginal I/O
/// gain.
///
/// Tokens are maximal runs of **ASCII** alphanumerics — a conservative subset
/// of ClickHouse's `splitByNonAlpha` (which keeps non-ASCII bytes inside
/// tokens, e.g. `splitByNonAlpha('caféteria') = ['caféteria']`). An ASCII-alnum
/// run is always a substring of whatever larger token CH indexes around it, so
/// the dictionary-substring scan still serves the guard; when a needle yields
/// no qualifying run we emit no guard (the safe failure mode). By construction
/// the token contains no LIKE metachars (`%`, `_`, `\`) and no quotes, so it
/// needs no escaping.
pub(crate) fn longest_guard_token(needle_lower: &str) -> Option<&str> {
    let (token_count, best) = guard_token_scan(needle_lower);
    if token_count >= 2 {
        best
    } else {
        None
    }
}

/// Shared scan behind [`longest_guard_token`] and [`anchored_guard_token`]:
/// splits on non-ASCII-alnum, counts the tokens, and returns the longest one
/// passing the [`GUARD_TOKEN_MIN_LEN`]+letter bar (ties → first occurrence,
/// deterministic SQL). The two callers differ only in the token-count policy.
fn guard_token_scan(needle_lower: &str) -> (usize, Option<&str>) {
    let mut token_count = 0usize;
    let mut best: Option<&str> = None;
    for t in needle_lower
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| !t.is_empty())
    {
        token_count += 1;
        if t.len() >= GUARD_TOKEN_MIN_LEN
            && t.chars().any(|c| c.is_ascii_alphabetic())
            // Strictly-greater keeps the FIRST longest qualifying token on ties.
            && best.is_none_or(|b| t.len() > b.len())
        {
            debug_assert!(t.chars().all(|c| c.is_ascii_alphanumeric()));
            best = Some(t);
        }
    }
    (token_count, best)
}

/// NAN-1640: index-servable guard token for an *anchored* prefix/suffix regex
/// literal (the `startsWith`/`endsWith` lowerings of `^lit.*` / `.*lit$`).
///
/// Same token bar and extraction as [`longest_guard_token`], with one deliberate
/// policy difference: **single-token literals DO return a guard**. The ≥2-token
/// requirement over there exists because a single-token `LIKE '%tok%'` primary
/// predicate is already text-index-served, so a guard would be redundant. Here
/// the primary predicate is `startsWith`/`endsWith`, which NO skip index serves
/// (text-index analysis yields `tokens: []` — EXPLAIN-verified), so even a
/// single-token literal like `powershell` needs the LIKE conjunct to engage the
/// `lower(col)` text index (Saturn: 19.97GiB → 25.71MiB read_bytes, 795x).
///
/// Soundness: the token is a contiguous substring of the anchored literal, so
/// `startsWith(x, lit) ⇒ x LIKE '%tok%'` (likewise `endsWith`) — ANDing the
/// guard is a pure conjunctive implication, results identical by construction.
/// Like the keyword guard, the returned token is pure ASCII-alnum: no LIKE
/// metachars, no quotes, no escaping needed.
pub(crate) fn anchored_guard_token(literal_lower: &str) -> Option<&str> {
    guard_token_scan(literal_lower).1
}

/// NAN-1515: bare free-text keyword → text-index predicate on `col` (the active
/// profile's [`keyword_search_column`] — `message` for logs, `span_name` for
/// spans, NAN-1555).
///
/// [`keyword_search_column`]: crate::schema::SchemaProfile::keyword_search_column
///
/// Drives the `lower(message)` `text(splitByNonAlpha)` index (`idx_message_words`)
/// via `hasAllTokens`, a **posting-list lookup**. At Saturn scale (152M rows)
/// this is 0.16–0.5s vs **35–206s** for the prior `lower(message) iLike '%kw%'`
/// substring form: the iLike substring extracts no index tokens (`EXPLAIN`:
/// `tokens: []`) so it degrades to a dictionary scan across every candidate
/// granule — O(table size), measured 77–250× slower while returning the
/// identical rows. (Local 2M-row POCs missed this — the dictionary scan is ~8ms
/// at 547 granules; the cost only shows at 56k granules / 79 GB index.)
///
/// Semantics: a bare keyword is a **token search** — `hasAllTokens` matches rows
/// where every token of the needle is present (token-AND), one token or many.
/// This is the one deliberate change from the pre-NAN-1515 substring default,
/// and it applies uniformly:
/// * `comsvcs` → token `comsvcs`. Bare `error` no longer matches `errors`.
/// * `update.exe` → tokens `update` AND `exe`. Matches the literal `update.exe`
///   file; does NOT match `MicrosoftEdgeUpdate.exe` (token `microsoftedgeupdate`,
///   not `update`). Substring matching that spans token boundaries can't be
///   served by a posting-list lookup — it requires the dictionary/`position`
///   full scan (77–250× slower) — so substring intent goes through the explicit
///   `*kw*` / `CONTAINS` arms (still LIKE). Splunk parity.
/// * **No token content** (`!!!`, `---`) → fall back to the substring LIKE; the
///   text index has no tokens to serve (rare).
///
/// Multi-token needles are pure token-AND — we deliberately do NOT add a
/// `position(needle) > 0` adjacency guard to mimic Splunk's compound segment.
/// Measured on Saturn: `cmd.exe` is 0.29s as bare `hasAllTokens` but **24s** with
/// the guard (80×) — `exe` is ubiquitous so the token prefilter barely prunes and
/// `position()` ends up reading the message column on nearly every row — for an
/// *identical* result set (scattered `cmd … exe` without an adjacent `cmd.exe`
/// does not occur in practice). Not worth 80× for zero rows.
///
/// The needle is passed to `hasAllTokens` as a **string** (not a Rust-split
/// array) so ClickHouse tokenizes it with the index's own `splitByNonAlpha`
/// tokenizer — alignment guaranteed, non-ASCII safe (`café` stays one CH token;
/// an ASCII split would yield `caf` → false negatives). `escape_string` (not
/// `escape_like_pattern`) is correct: `hasAllTokens` takes a literal string where
/// `%`/`_` are ordinary characters, not LIKE metacharacters.
/// NAN-1828: OR-fold the predicate across every column that can carry the event
/// body for the active profile (`keyword_search_columns()`).
///
/// Single-column profiles (UDM `message`, spans `span_name`, metrics, risk) fold
/// to exactly one term, so their SQL is byte-identical to the pre-NAN-1828 form.
///
/// OCSF has TWO body columns, because the raw log lands in a different one
/// depending on the producer: our Vector parsers put it in `message` and leave
/// `raw_data` empty, while a direct producer (Tenzir) puts the original in
/// `raw_data` and a human summary in `message`. Searching only `message` made a
/// Tenzir tenant's original log unfindable by the primary hunt path (NAN-1827
/// persisted it; nothing could reach it — the explicit `raw_data=*kw*` form emits
/// `iLike`, which extracts NO index tokens, so it degrades to the 77-250x
/// dictionary scan documented above).
///
/// The union is TIGHT, not doubled — the body lives in exactly ONE of the two, so
/// the other index contributes almost nothing: on a Vector tenant `raw_data` is
/// empty and its index prunes to zero granules; on a Tenzir tenant `message` is a
/// short summary. Measured (120k rows / 16 granules, half of each shape): a
/// needle in either column prunes to 1/15 granules via `<Combined skip indexes>`,
/// and a nonexistent token to 0/15.
///
/// Rejected alternative: a single text index on the coalesce expression
/// `lower(if(raw_data != '', raw_data, message))`. ClickHouse builds the index but
/// the planner NEVER considers it (EXPLAIN shows no `Skip` entry at all) — text
/// indexes do not match a non-trivial expression. Do not retry it.
pub(crate) fn bare_keyword_predicate(kw: &str, cols: &[&str]) -> String {
    debug_assert!(!cols.is_empty(), "keyword_search_columns() must never be empty");
    match cols {
        [col] => bare_keyword_predicate_for_column(kw, col),
        _ => {
            let folded = cols
                .iter()
                .map(|col| bare_keyword_predicate_for_column(kw, col))
                .collect::<Vec<_>>()
                .join(" OR ");
            // Parenthesized: the caller splices this into a larger AND-chain, and
            // a bare `a OR b` there would bind as `x AND a OR b` = `(x AND a) OR b`
            // — silently widening every keyword search to match on `b` alone.
            format!("({folded})")
        }
    }
}

/// The single-column predicate. Every arm below must stay index-compatible: the
/// emitted expression is matched by ClickHouse against the text index BY
/// EXPRESSION, so `lower(<col>)` here must mirror the DDL exactly.
fn bare_keyword_predicate_for_column(kw: &str, col: &str) -> String {
    // ClickHouse `lower()` semantics (ASCII only) so the literal agrees with the
    // `lower(col)` side — see [`ch_lower`].
    let lowered = ch_lower(kw);

    // Explicit wildcards (`cmd*`, `*cmd`, `c?d`, `**`) are partial-match intent →
    // a `lower(col) LIKE` pattern on the text index, NOT a token lookup. This is the
    // documented escape hatch from token search. Checked FIRST so wildcard-only
    // needles (`**`, `?`) convert to `%`/`_` rather than falling into the
    // all-separator literal branch below. (`*cmd*` is already lowered to a
    // wildcard upstream; this covers single-sided forms that reach here as a bare
    // Keyword and stops `hasAllTokens` from tokenizing a `*`/`?` needle.)
    if lowered.contains('*') || lowered.contains('?') {
        let pattern = wildcard_to_like_pattern(&lowered);
        return ci_like(&format!("lower({col})"), &pattern, false);
    }

    let escaped = escape_string(&lowered);

    // All-separator needles (`!!!`) tokenize to nothing — keep the substring match.
    if lowered.chars().all(|c| c.is_ascii() && !c.is_ascii_alphanumeric()) {
        let pattern = escape_like_pattern(&escaped);
        return ci_like(&format!("lower({col})"), &format!("%{pattern}%"), false);
    }

    format!("hasAllTokens(lower({col}), '{}')", escaped)
}

/// Add LIKE-pattern escaping on top of an already SQL-escaped string (single
/// quotes doubled, backslashes doubled by `escape_string`) so that it matches
/// as a literal substring inside an `LIKE '%X%'` body.
///
/// In ClickHouse LIKE/LIKE, `\` is the pattern escape character, so a literal
/// backslash needs `\\` *in the pattern value* — which, after the string-literal
/// layer, is `\\\\` in the SQL text. `escape_string` only produced `\\` (one
/// backslash in the pattern value), which LIKE then consumed as an escape,
/// silently matching nothing — so every `CONTAINS`/keyword over a Windows path
/// (`C:\Windows\System32\`, `\NETLOGON\`, …) failed to match. We therefore
/// double the (already-doubled) backslashes here, and escape `%`/`_` so literal
/// wildcards from user input don't act as wildcards. NAN-1157.
///
/// Use this for the codegen path that lowered to `hasToken*` pre-NAN-1026 —
/// `hasToken` is whole-token semantic and silently drops fragments like
/// `/dc/` not matching `srv-dc01`; LIKE with the splitByNonAlpha text index
/// (CH 26.4's LIKE-via-dictionary-scan) gives both correct substring
/// semantics AND granule pruning.
pub(crate) fn escape_like_pattern(escaped: &str) -> String {
    // Backslash first: each `\` (the SQL-escape layer already made them pairs)
    // becomes `\\` in the pattern value so LIKE matches it literally. The `\\`
    // we add for `%`/`_` is then NOT re-doubled (it's added after this step).
    escaped
        .replace('\\', "\\\\")
        .replace('%', "\\\\%")
        .replace('_', "\\\\_")
}

/// Lowercase a literal exactly the way ClickHouse `lower()` does: ASCII letters
/// only (`lower('ÄÉЖ') = 'ÄÉЖ'`, verified on 26.10.3.7; `lowerUTF8` is the
/// Unicode one). Every case-insensitive pattern compares `lower(<col>)` with a
/// literal lowered HERE, so both sides must use the same mapping: Rust's
/// Unicode `to_lowercase()` would turn `Äbc` into `äbc`, which `lower(col)` can
/// never produce from the stored `Äbc`, and the search would silently miss it.
pub(crate) fn ch_lower(s: &str) -> String {
    s.to_ascii_lowercase()
}

/// THE case-insensitive pattern predicate of nPL (NAN-4943). Every literal
/// `*kw*` / `kw*` / `*kw` wildcard, `CONTAINS`, `STARTSWITH`, `ENDSWITH`,
/// explicit `LIKE`, simple-regex token, keyword fallback and regex-literal
/// rewrite — and the negation of each — is emitted here and nowhere else:
///
/// ```sql
/// lower(<expr>) [NOT ]LIKE '<pattern lowered with ClickHouse lower() semantics>'
/// ```
///
/// `body` is the SQL text between the quotes: already string-escaped and
/// LIKE-escaped by the caller (`escape_like_pattern` for a user literal,
/// `wildcard_to_like_pattern` for `*`/`?` wildcards, plain `escape_string` for
/// an explicit `LIKE` whose `%`/`_` are intentional). It is ASCII-lowercased
/// again here so the invariant cannot be broken by a caller; that is safe on
/// escaped text because `escape_string` doubles every backslash, so no letter
/// ever follows a lone `\` (lowercasing `\N` into `\n` cannot happen).
///
/// `lhs` is the index expression. An expression that is already `lower(…)`
/// (the exact form of the `lower(col)` text indexes — ClickHouse matches skip
/// indexes BY EXPRESSION) is used as is; anything else (`toString(ext.x)`, a
/// CTE column) is wrapped in `lower(…)`.
///
/// **Semantics: case-insensitive = lowercase match**, the same rule as
/// `field=value` → `lower(col) = '<lowered>'`. ClickHouse `ILIKE` is no longer
/// emitted for a literal: on 26.10 the text index does not serve
/// `lower(col) ILIKE` (k-patterns like `%mimikatz%` read the whole column),
/// while `lower(col) LIKE` is served by the index dictionary scan. Consequences,
/// pinned by `ci_like_parity_integration`:
///
/// - mixed-case ASCII: identical to `ILIKE` and to `=`;
/// - non-ASCII letters match their own case only (`*Äbc*` finds `ÄBC`'s `Ä`
///   but not `äbc`; Cyrillic likewise), because `lower()` folds ASCII only;
/// - U+212A KELVIN SIGN and U+017F LONG S are distinct characters: `*kelvin*`
///   does not match `Kelvin` written with the Kelvin sign (26.10 `ILIKE` did),
///   and `*svchost*` does not match `ſvchost` (26.10 `ILIKE` did not either).
///   To every OS these are different names; detection loses nothing.
///
/// Expression-valued patterns (`CONTAINS other_field`, `STARTSWITH <expr>`)
/// do not come through here: their case and charset are only known at run time,
/// so they keep `iLike concat(…)`.
pub(crate) fn ci_like(lhs: &str, body: &str, negate: bool) -> String {
    let not = if negate { "NOT " } else { "" };
    let body = body.to_ascii_lowercase();
    if is_lower_call(lhs) {
        format!("{lhs} {not}LIKE '{body}'")
    } else {
        format!("lower({lhs}) {not}LIKE '{body}'")
    }
}

/// True when `expr` is one whole `lower( … )` call (not `lower(a) || b`).
fn is_lower_call(expr: &str) -> bool {
    let Some(inner) = expr.strip_prefix("lower(").and_then(|s| s.strip_suffix(')')) else {
        return false;
    };
    // The opening paren must close at the very end: track depth outside quotes.
    let mut depth = 0i32;
    let mut in_str = false;
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' if in_str => {
                chars.next();
            }
            '\'' => in_str = !in_str,
            '(' if !in_str => depth += 1,
            ')' if !in_str => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            _ => {}
        }
    }
    depth == 0 && !in_str
}

/// Validate a regex pattern for complexity to prevent ReDoS attacks.
///
/// Checks maximum length, nesting depth, and attempts compilation with a size limit
/// to catch catastrophic backtracking patterns before they reach ClickHouse.
pub(crate) fn validate_regex_pattern(pattern: &str) -> Result<(), String> {
    if pattern.len() > 1024 {
        return Err("Regex pattern exceeds maximum length of 1024 characters".to_string());
    }

    // Check nesting depth of groups (skip escaped parentheses)
    let mut depth = 0u32;
    let mut max_depth = 0u32;
    let mut prev_backslash = false;
    for c in pattern.chars() {
        if prev_backslash {
            prev_backslash = false;
            continue;
        }
        match c {
            '\\' => {
                prev_backslash = true;
            }
            '(' => {
                depth += 1;
                max_depth = max_depth.max(depth);
            }
            ')' => {
                depth = depth.saturating_sub(1);
            }
            _ => {}
        }
    }
    if max_depth > 5 {
        return Err("Regex pattern exceeds maximum nesting depth of 5".to_string());
    }

    // Attempt compilation with size limit to catch catastrophic patterns
    regex::RegexBuilder::new(pattern)
        .size_limit(1 << 20) // 1MB compiled size limit
        .build()
        .map_err(|e| format!("Invalid regex pattern: {}", e))?;

    Ok(())
}

/// Check if a regex pattern is "simple" - just a literal substring with no metacharacters.
/// Simple patterns like "explorer" can use hasToken() which leverages bloom filter indexes.
/// Returns Some(token) if simple, None if it contains regex metacharacters.
pub(crate) fn extract_simple_regex_token(pattern: &str) -> Option<String> {
    // Regex metacharacters that indicate a complex pattern
    const REGEX_METACHARACTERS: &[char] = &[
        '^', '$', '.', '*', '+', '?', '[', ']', '(', ')', '{', '}', '|', '\\',
    ];

    // NAN-4943: the bare `*kw*` keyword reaches here as `(?i)<regex::escape(kw)>`
    // (`*cmd.exe*` → `(?i)cmd\.exe`). A leading `(?i)` is a no-op (matching is
    // always case-insensitive) and an escaped ASCII punctuation character is a
    // literal, so such a pattern is still a plain substring.
    let pattern = pattern.strip_prefix("(?i)").unwrap_or(pattern);
    let mut literal = String::with_capacity(pattern.len());
    let mut chars = pattern.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some(e) if e.is_ascii_punctuation() => literal.push(e),
                // `\d`, `\w`, `\x41`, trailing `\` … are regex syntax.
                _ => return None,
            }
        } else if REGEX_METACHARACTERS.contains(&c) {
            return None;
        } else {
            literal.push(c);
        }
    }
    if literal.is_empty() {
        return None;
    }
    let pattern = literal.as_str();

    // NAN-4943: an ASCII literal is rewritten to the nPL lowercase match
    // (`lower(col) LIKE '%tok%'`, see `ci_like`), dropping RE2's Unicode folds
    // of `k`/`s` (Kelvin sign, long s) by design. A literal with non-ASCII
    // letters stays a real `match()`: RE2 `(?i)` folds `Ä`↔`ä`, which an
    // ASCII-only `lower()` comparison cannot express.
    if !regex_literal_rewrite_safe(pattern) {
        return None;
    }
    Some(ch_lower(pattern))
}

/// NAN-4943: what an nPL field regex (`f=/re/`) MEANS, decided once for every
/// engine. The canonical SQL generator ([`regex_predicate_sql`]), the
/// prevalence pushdown and the post-stage Rust evaluator all branch on this,
/// so a predicate never changes its answer when it moves across a pipe.
///
/// - `Contains` / `Prefix` / `Suffix` / `AnyContains`: the regex is a literal
///   (or literal alternation / anchored literal) and is evaluated as the nPL
///   lowercase match (ClickHouse `lower()`, ASCII-only fold);
/// - `Match`: everything else stays a real case-insensitive RE2 match.
///
/// [`regex_predicate_sql`]: super::regex_predicate_sql
#[derive(Debug, PartialEq)]
pub(crate) enum RegexPlan {
    Contains(String),
    Prefix(String),
    Suffix(String),
    AnyContains(Vec<String>),
    Match,
}

pub(crate) fn regex_plan(pattern: &str) -> RegexPlan {
    if let Some(token) = extract_simple_regex_token(pattern) {
        return RegexPlan::Contains(token);
    }
    match analyze_regex_for_optimization(pattern) {
        Some(RegexOptimization::Prefix(p)) => RegexPlan::Prefix(p),
        Some(RegexOptimization::Suffix(s)) => RegexPlan::Suffix(s),
        Some(RegexOptimization::LiteralAlternation(l)) => RegexPlan::AnyContains(l),
        Some(RegexOptimization::BloomGuard(_)) | None => RegexPlan::Match,
    }
}

/// Result of analyzing a regex pattern for optimization opportunities.
/// Each variant allows the SQL generator to skip or augment the expensive match() call.
#[derive(Debug, PartialEq)]
pub(crate) enum RegexOptimization {
    /// Pattern is a pure anchored prefix: `^admin.*` → startsWith(lower(field), 'admin')
    /// Eliminates regex entirely.
    Prefix(String),
    /// Pattern is a pure anchored suffix: `.*\.exe$` → endsWith(lower(field), '.exe')
    /// Eliminates regex entirely.
    Suffix(String),
    /// All branches of a top-level alternation are literals: `(error|warning|critical)`
    /// → hasToken() OR hasToken() OR hasToken(), eliminates regex entirely.
    LiteralAlternation(Vec<String>),
    /// A literal token was found that can be used as a bloom filter pre-filter
    /// before the full regex runs: hasToken(field, 'token') AND match(field, pattern)
    BloomGuard(String),
}

/// NAN-4943: may a regex literal be REWRITTEN (match() eliminated) into the
/// nPL lowercase match? Yes for ASCII: the only difference from RE2 `(?i)` is
/// its Kelvin-sign / long-s folding, which nPL case-insensitivity deliberately
/// does not do (see `ci_like`). Non-ASCII literals keep `match()`.
fn regex_literal_rewrite_safe(literal: &str) -> bool {
    literal.is_ascii()
}

/// Is `ch` folded by RE2 `(?i)` onto ASCII only? Used for BloomGuard tokens,
/// which are ANDed IN FRONT of a surviving `match()`: there the guard must be a
/// superset of what RE2 accepts, so a `k`/`s` (which RE2 folds onto U+212A /
/// U+017F) must not appear in it. Rewrites that eliminate `match()` use
/// [`regex_literal_rewrite_safe`] instead.
fn regex_char_ascii_case_safe(ch: char) -> bool {
    use regex_syntax::hir::{ClassUnicode, ClassUnicodeRange};
    static SAFE: std::sync::OnceLock<[bool; 128]> = std::sync::OnceLock::new();
    ch.is_ascii() && SAFE.get_or_init(|| std::array::from_fn(|byte| {
        let ch = byte as u8 as char;
        let mut class = ClassUnicode::new([ClassUnicodeRange::new(ch, ch)]);
        class.case_fold_simple();
        class.ranges().iter().all(|range| range.end().is_ascii())
    }))[ch as usize]
}

/// Shorthand/hex/Unicode escapes are regex syntax, never literal suffixes or alternation branches.
fn has_regex_character_escape(pattern: &str) -> bool {
    let mut chars = pattern.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' && chars.next().is_some_and(|escaped| escaped.is_ascii_alphanumeric()) { return true; }
    }
    false
}

/// Analyze a regex pattern for optimization opportunities.
///
/// Checks (in priority order):
/// 1. Anchored prefix: `^literal.*` or `^literal` → startsWith
/// 2. Anchored suffix: `.*literal$` or `literal$` with no other metacharacters → endsWith
/// 3. Pure literal alternation: `(a|b|c)` where all branches are plain text → hasToken OR chain
/// 4. Longest literal substring: extract for bloom filter pre-filtering → hasToken AND match
///
/// Returns None if no optimization is possible (e.g., pattern is too short or purely metacharacters).
pub(crate) fn analyze_regex_for_optimization(pattern: &str) -> Option<RegexOptimization> {
    // Strip leading (?i) — we always do case-insensitive matching
    let pat = pattern.strip_prefix("(?i)").unwrap_or(pattern);

    if pat.is_empty() {
        return None;
    }

    // 1. Anchored prefix: ^literal.* or ^literal (exact prefix match)
    if let Some(prefix) = extract_anchored_prefix(pat) {
        if prefix.len() >= 2 && regex_literal_rewrite_safe(&prefix) {
            return Some(RegexOptimization::Prefix(ch_lower(&prefix)));
        }
    }

    // 2. Anchored suffix: .*literal$ or just literal$
    if let Some(suffix) = extract_anchored_suffix(pat) {
        if suffix.len() >= 2 && regex_literal_rewrite_safe(&suffix) && !has_regex_character_escape(pat) {
            return Some(RegexOptimization::Suffix(ch_lower(&suffix)));
        }
    }

    // 3. Pure literal alternation: (a|b|c) or a|b|c (entire pattern)
    if let Some(literals) = extract_literal_alternation(pat) {
        if literals.len() >= 2 && !pat.contains('\\')
            && literals.iter().all(|l| l.len() >= 2 && regex_literal_rewrite_safe(l)) {
            return Some(RegexOptimization::LiteralAlternation(
                literals.into_iter().map(|l| ch_lower(&l)).collect(),
            ));
        }
    }

    // 4. Longest literal substring for bloom guard
    if let Some(token) = extract_longest_literal(pat) {
        // hasToken needs at least 3 chars for meaningful bloom filter selectivity
        if token.len() >= 3 {
            return Some(RegexOptimization::BloomGuard(ch_lower(&token)));
        }
    }

    None
}

/// Extract an anchored prefix from patterns like `^admin.*` or `^admin`
/// Returns the literal prefix if the pattern starts with ^ followed by literals,
/// then optionally ends with .* or $ or .*$
fn extract_anchored_prefix(pat: &str) -> Option<String> {
    if !pat.starts_with('^') {
        return None;
    }
    let after_caret = &pat[1..];
    let mut literal = String::new();
    let mut chars = after_caret.chars().peekable();

    while let Some(&c) = chars.peek() {
        if is_regex_metachar(c) {
            break;
        }
        if c == '\\' {
            // Escaped character — consume the backslash and take the next char literally
            chars.next();
            if let Some(escaped) = chars.next() {
                literal.push(escaped);
            }
            continue;
        }
        literal.push(c);
        chars.next();
    }

    if literal.is_empty() {
        return None;
    }

    // A plain prefix or trailing .* is exact. ^literal$ needs the final match(), not startsWith.
    let rest: String = chars.collect();
    if rest.is_empty() || rest == ".*" || rest == ".*$" {
        return Some(literal);
    }

    None
}

/// Extract an anchored suffix from patterns like `.*\.exe$` or `\.exe$`
/// Returns the literal suffix if the pattern ends with literals followed by $
fn extract_anchored_suffix(pat: &str) -> Option<String> {
    if !pat.ends_with('$') {
        return None;
    }
    let before_dollar = &pat[..pat.len() - 1];

    // Find where the literal suffix starts (scan backwards)
    let mut literal_start = before_dollar.len();
    let bytes = before_dollar.as_bytes();
    while literal_start > 0 {
        let prev = bytes[literal_start - 1];
        if is_regex_metachar_byte(prev) {
            // Check for escaped character: if preceded by backslash, it's a literal
            if literal_start >= 2 && bytes[literal_start - 2] == b'\\' {
                literal_start -= 2;
                continue;
            }
            break;
        }
        literal_start -= 1;
    }

    let suffix_raw = &before_dollar[literal_start..];
    if suffix_raw.is_empty() {
        return None;
    }

    // Unescape backslashes in the suffix
    let suffix = unescape_regex_literal(suffix_raw);
    if suffix.is_empty() {
        return None;
    }

    // Preceding part must be empty or .* or .*? (greedy prefix)
    let prefix = &before_dollar[..literal_start];
    if prefix.is_empty() || prefix == ".*" || prefix == ".*?" {
        return Some(suffix);
    }

    None
}

/// Extract all branches of a top-level alternation if every branch is a pure literal.
/// Handles both `(a|b|c)` and `a|b|c` forms.
fn extract_literal_alternation(pat: &str) -> Option<Vec<String>> {
    // Strip optional outer parens
    let inner = if pat.starts_with('(') && pat.ends_with(')') {
        &pat[1..pat.len() - 1]
    } else {
        pat
    };

    // Must contain a pipe
    if !inner.contains('|') {
        return None;
    }

    let mut literals = Vec::new();
    for branch in inner.split('|') {
        let unescaped = unescape_regex_literal(branch);
        // Check that the branch has no regex metacharacters (after unescaping)
        if branch.is_empty() || has_unescaped_metachar(branch) {
            return None;
        }
        literals.push(unescaped);
    }

    Some(literals)
}

/// Extract a mandatory literal run from the regex HIR, then its longest index-servable ASCII token.
/// The guard is a candidate filter: Unicode folds that an ASCII lower() LIKE guard cannot represent must be omitted.
/// A shorter safe token still matches the existing lower(col) text-index expression.
///
/// SOUNDNESS (NAN-2361). The returned literal becomes an ANDed `LIKE` guard in
/// front of `match()`, so it must be present in EVERY string the pattern
/// matches. The original implementation split the raw pattern on
/// metacharacters and took the longest piece, which silently harvested
/// literals out of alternation branches and optional groups:
/// `/^(ws|wks)/` produced the guard `%wks%` and therefore returned ZERO rows
/// for `ws-sales-131`, and `/admin(istrator)?/` produced `%istrator%` and lost
/// every bare `admin`. The guard is now derived from the parsed HIR and only
/// from literal runs that every match must contain.
fn extract_longest_literal(pat: &str) -> Option<String> {
    // A leading global flag is stripped by the caller; strip again so direct
    // callers behave identically and so `(?i)` does not explode the literals
    // into character classes (which would yield no guard at all).
    let pat = pat.strip_prefix("(?i)").unwrap_or(pat);
    // An unparseable pattern (lookaround, or anything regex-syntax rejects
    // that RE2/ClickHouse would accept) yields NO guard. Losing a guard costs
    // a scan; inventing one costs correctness.
    let hir = regex_syntax::Parser::new().parse(pat).ok()?;
    let mut runs = Vec::new();
    mandatory_literal_runs(&hir, &mut runs);
    let best = runs.into_iter().fold(String::new(), |accumulator, run| {
        if run.len() > accumulator.len() {
            run
        } else {
            accumulator
        }
    });

    if best.is_empty() {
        return None;
    }

    // Longest qualifying ASCII-alnum token within the winning piece
    // (strictly-greater comparison keeps the first occurrence on ties). For a
    // piece that is already a single pure-alphanumeric qualifying token this
    // is the identity when ASCII case folding is sufficient.
    let token = best
        .split(|c: char| !c.is_ascii_alphanumeric() || !regex_char_ascii_case_safe(c))
        .filter(|t| t.len() >= GUARD_TOKEN_MIN_LEN && t.chars().any(|c| c.is_ascii_alphabetic()))
        .fold("", |acc, t| if t.len() > acc.len() { t } else { acc });

    if !token.is_empty() {
        Some(token.to_string())
    } else if best.chars().all(regex_char_ascii_case_safe) {
        Some(best)
    } else {
        // A shorter mandatory ASCII fragment is still a safe row prefilter.
        // Never carry the K/S Unicode-fold mismatch into the lower() LIKE guard.
        best.split(|c: char| !c.is_ascii_alphanumeric() || !regex_char_ascii_case_safe(c))
            .filter(|run| run.len() >= 3)
            .max_by_key(|run| run.len())
            .map(str::to_owned)
    }
}

/// Walk the HIR collecting every literal run that EVERY match must contain.
///
/// A run is mandatory only when it is reachable unconditionally: literals in
/// a concatenation, inside a capture, or inside a repetition with `min >= 1`.
/// Alternation branches and zero-min repetitions contribute NOTHING — see
/// [`extract_longest_literal`] for why picking a branch literal is a silent
/// wrong answer.
fn mandatory_literal_runs(hir: &regex_syntax::hir::Hir, out: &mut Vec<String>) {
    use regex_syntax::hir::HirKind;
    match hir.kind() {
        HirKind::Literal(literal) => {
            if let Ok(text) = std::str::from_utf8(&literal.0) {
                if !text.is_empty() {
                    out.push(text.to_string());
                }
            }
        }
        HirKind::Capture(capture) => mandatory_literal_runs(&capture.sub, out),
        HirKind::Repetition(repetition) if repetition.min > 0 => {
            mandatory_literal_runs(&repetition.sub, out)
        }
        HirKind::Concat(expressions) => {
            for expression in expressions {
                mandatory_literal_runs(expression, out);
            }
        }
        // Alternation: no literal is common to every branch in the SUBSTRING
        // sense a guard needs, so contribute none. Zero-min repetition
        // (`(istrator)?`, `(foo)*`): the sub may not appear at all.
        HirKind::Alternation(_)
        | HirKind::Empty
        | HirKind::Class(_)
        | HirKind::Look(_)
        | HirKind::Repetition(_) => {}
    }
}

/// Check if a character is a regex metacharacter
fn is_regex_metachar(c: char) -> bool {
    matches!(
        c,
        '^' | '$' | '.' | '*' | '+' | '?' | '[' | ']' | '(' | ')' | '{' | '}' | '|' | '\\'
    )
}

fn is_regex_metachar_byte(b: u8) -> bool {
    matches!(
        b,
        b'^' | b'$'
            | b'.'
            | b'*'
            | b'+'
            | b'?'
            | b'['
            | b']'
            | b'('
            | b')'
            | b'{'
            | b'}'
            | b'|'
            | b'\\'
    )
}

/// Check if a string has any unescaped regex metacharacters
fn has_unescaped_metachar(s: &str) -> bool {
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            chars.next(); // skip escaped char
            continue;
        }
        if is_regex_metachar(c) {
            return true;
        }
    }
    false
}

/// Unescape a regex literal substring (remove backslashes before escaped chars)
fn unescape_regex_literal(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(escaped) = chars.next() {
                result.push(escaped);
            }
        } else {
            result.push(c);
        }
    }
    result
}

/// Extract named capture group names from a regex pattern
/// Returns a list of group names in order of appearance.
/// Accepts both PCRE/Splunk forms — `(?<name>…)` and `(?P<name>…)` — since
/// migrating users write either (NAN-1340); the optional `P` is what re2 / Python
/// syntax uses and what the corpus leans on.
/// Example: "(?<user>\w+)@(?P<domain>\w+)" -> ["user", "domain"]
pub(crate) fn extract_named_groups(pattern: &str) -> Vec<String> {
    named_capture_groups(pattern)
        .into_iter()
        .map(|(name, _)| name)
        .collect()
}

/// NAN-3327: true when `spath input=<column> path=<p>` must parse the JSON
/// TEXT held in `<column>` (`raw_data`, `message`) rather than address the
/// nested schema path `<column>.<p>` (`input=src_endpoint path=ip`).
pub(crate) fn spath_reads_column_text(
    profile: &dyn crate::schema::SchemaProfile,
    input: Option<&str>,
    path: &str,
) -> bool {
    let Some(input) = input else { return false };
    if matches!(input, "ext" | "event" | "unmapped") {
        return false;
    }
    profile.is_known_field(input) && !profile.is_known_field(&format!("{input}.{path}"))
}

/// `a.b.c` → `'a', 'b', 'c'` for `JSONExtract*` key arguments.
pub(crate) fn spath_path_args(path: &str) -> String {
    path.split('.')
        .filter(|part| !part.is_empty())
        .map(|part| format!("'{}'", escape_string(part)))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Every named capture group of `pattern` with its 1-based index among ALL
/// capturing groups, the numbering `extractGroups` uses (NAN-3327). An unnamed
/// `( … )` group counts; `(?: … )`, lookarounds, inline flags, escaped parens
/// and parens inside a `[ … ]` class do not. Assigning names by their order
/// among NAMED groups put `port` on the unnamed `(:(?<port>…))` wrapper.
pub(crate) fn named_capture_groups(pattern: &str) -> Vec<(String, usize)> {
    let bytes = pattern.as_bytes();
    let mut out = Vec::new();
    let mut index = 0usize;
    let mut in_class = false;
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                i += 2;
                continue;
            }
            b'[' if !in_class => in_class = true,
            b']' if in_class => in_class = false,
            b'(' if !in_class => {
                let rest = &pattern[i + 1..];
                let named = rest
                    .strip_prefix("?P<")
                    .or_else(|| rest.strip_prefix("?<"))
                    .filter(|r| !r.starts_with('=') && !r.starts_with('!'))
                    .and_then(|r| r.find('>').map(|end| &r[..end]));
                if let Some(name) = named {
                    index += 1;
                    out.push((name.to_string(), index));
                } else if !rest.starts_with('?') {
                    index += 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    out
}

/// Convert named capture groups to numbered groups for ClickHouse.
/// Handles both `(?<name>…)` and `(?P<name>…)` (NAN-1340).
/// Example: "(?P<user>\w+)" -> "(\w+)"
pub(crate) fn convert_named_groups_to_numbered(pattern: &str) -> String {
    let re = regex::Regex::new(r"\(\?P?<[^>]+>").unwrap();
    re.replace_all(pattern, "(").to_string()
}

/// Convert wildcard pattern (* and ?) to SQL LIKE pattern (% and _)
///
/// Output is embedded directly in the SQL text, so this single pass has to do
/// the work of BOTH `escape_string` and `escape_like_pattern` — the value
/// crosses two decoders on its way to a match:
///
/// 1. the SQL string-literal parser, which turns `\\` into `\`
/// 2. `LIKE`, which reads `\` as its own escape character
///
/// So one literal backslash needs FOUR here: `\\\\` -> `\\` after the literal
/// parser -> one literal `\` at match time. Emitting two was enough for the
/// common case only by accident — ClickHouse leaves an unrecognised escape like
/// `\w` alone, so `C:\Windows*` matched. `\\fileserver\share*` did not match
/// itself: the doubled backslash collapsed to one and `LIKE` ate it as an
/// escape (NAN-2269).
pub(crate) fn wildcard_to_like_pattern(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 2);
    for c in s.chars() {
        match c {
            '*' => result.push('%'),
            '?' => result.push('_'),
            // `\%` survives the literal parser intact (unrecognised escape) and
            // reaches LIKE as an escaped, literal `%`.
            '%' => result.push_str("\\%"),
            '_' => result.push_str("\\_"),
            '\'' => result.push_str("''"),
            '\\' => result.push_str("\\\\\\\\"),
            _ => result.push(c),
        }
    }
    result
}

/// Sanitize a field name for use in ext JSON dot-notation (e.g. `ext.field_name`).
/// Strips anything that isn't alphanumeric or underscore to prevent path injection.
pub(crate) fn sanitize_json_path(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect()
}

/// Escape an identifier (column/table name) for ClickHouse.
///
/// Thin alias over [`crate::sql_hygiene::quote_identifier`], the canonical
/// identifier sink (moved there in the 2026-11-08 security review so code
/// outside the generator can use it). Plain non-reserved barewords are emitted
/// verbatim, so generated SQL stays byte-identical; everything else is
/// double-quoted with backslash-then-quote escaping. See that function for the
/// full contract.
///
/// Generated nPL SQL is NOT parsed or validated after generation (only the raw
/// SQL surface runs `validate_sql_query`), so this escaping is the guarantee,
/// not a backstop.
pub(crate) fn escape_identifier(name: &str) -> String {
    crate::sql_hygiene::quote_identifier(name)
}

#[cfg(test)]
mod inline_tests {
    use super::*;

    #[test]
    fn extract_named_groups_handles_both_pcre_forms() {
        // NAN-1340: `(?P<name>…)` (re2/Python/Splunk-PCRE) must be recognized, not
        // just `(?<name>…)` — else the corpus's `(?P<method>…)` captures are never
        // created and the rex command silently no-ops.
        assert_eq!(
            extract_named_groups(r"(?<user>\w+)@(?P<domain>\w+)"),
            vec!["user".to_string(), "domain".to_string()]
        );
        assert_eq!(
            extract_named_groups(r"(?P<method>GET|POST)\s+(?P<path>/\S+)"),
            vec!["method".to_string(), "path".to_string()]
        );
    }

    /// NAN-3327: names map to their index among ALL capturing groups.
    #[test]
    fn named_groups_index_counts_unnamed_groups_nan3327() {
        assert_eq!(
            named_capture_groups(r"https?://(?<host>[^/:]+)(:(?<port>\d+))?(?<path>/.*)"),
            vec![("host".to_string(), 1), ("port".to_string(), 3), ("path".to_string(), 4)]
        );
        assert_eq!(
            named_capture_groups(r"(?:a)(?=b)\((?P<x>[(]y)(?<!z)(?i)(w)(?<v>.)"),
            vec![("x".to_string(), 1), ("v".to_string(), 3)]
        );
    }

    #[test]
    fn convert_named_groups_to_numbered_strips_both_pcre_forms() {
        // NAN-1340: both `(?<…>)` and `(?P<…>)` collapse to a bare `(` for the
        // numbered-group pattern ClickHouse `extractGroups` consumes.
        assert_eq!(
            convert_named_groups_to_numbered(r"(?P<method>GET|POST)\s+(?<path>/\S+)"),
            r"(GET|POST)\s+(/\S+)"
        );
    }

    #[test]
    fn test_escape_regex_pattern_question_mark() {
        // ? is NOT escaped here — executor's escape_question_marks_in_strings handles it
        assert_eq!(escape_regex_pattern("(?i)test"), "(?i)test");
        assert_eq!(escape_regex_pattern("a?b?c"), "a?b?c");
    }

    #[test]
    fn test_escape_regex_pattern_quotes() {
        // Single quotes should still be escaped
        assert_eq!(escape_regex_pattern("don't"), "don''t");
    }

    #[test]
    fn test_escape_regex_pattern_backslash() {
        // Backslashes should be escaped
        assert_eq!(escape_regex_pattern(r"\d+"), r"\\d+");
    }

    #[test]
    fn escape_identifier_leaves_plain_barewords_raw() {
        // NAN-1992 no-churn invariant: any `^[A-Za-z_][A-Za-z0-9_]*$` name that
        // is not reserved must be emitted VERBATIM — the generated SQL (and its
        // hundreds of golden-string assertions) stays byte-identical.
        for bareword in [
            "event_type",
            "total",
            "src_ip",
            "count",
            "_agg_foo",
            "COL1",
            "rex_matches",
        ] {
            assert_eq!(
                escape_identifier(bareword),
                bareword,
                "bareword `{bareword}` must stay raw"
            );
        }
    }

    #[test]
    fn escape_identifier_quotes_reserved_dotted_and_spaced() {
        // Unchanged from prior behavior — these already quoted before NAN-1992.
        assert_eq!(escape_identifier("user"), "\"user\"");
        assert_eq!(escape_identifier("order"), "\"order\"");
        assert_eq!(escape_identifier("ext.foo"), "\"ext.foo\"");
        // Legit quoted alias with a space (`eval "p95 latency" = …`) — the case
        // NAN-1354 protects by owning output-name safety at this sink.
        assert_eq!(escape_identifier("p95 latency"), "\"p95 latency\"");
    }

    #[test]
    fn escape_identifier_neutralizes_rex_alias_injection() {
        // NAN-1992: a `rex` capture-group name carrying a comma/paren (with `/**/`
        // for whitespace so it dodged the old `contains(' ')` check) must be
        // quoted into a single inert alias, never raw SQL.
        assert_eq!(escape_identifier("a,version()"), "\"a,version()\"");
        assert_eq!(
            escape_identifier("a,version()/**/v,hostName()/**/h,currentUser()/**/u"),
            "\"a,version()/**/v,hostName()/**/h,currentUser()/**/u\""
        );
        // A subquery breakout is likewise wrapped whole.
        assert_eq!(
            escape_identifier("a,(SELECT/**/count()/**/FROM/**/logs)/**/x"),
            "\"a,(SELECT/**/count()/**/FROM/**/logs)/**/x\""
        );
    }

    #[test]
    fn escape_identifier_escapes_embedded_quote_and_backslash() {
        // Embedded double-quote is doubled.
        assert_eq!(escape_identifier("a\"b"), "\"a\"\"b\"");
        // Backslash is doubled BEFORE the quote, because ClickHouse honors
        // C-style `\"` escapes inside double-quoted identifiers (verified against
        // the server) — otherwise a trailing/embedded backslash defeats the
        // closing quote and breaks out. `bs` = one literal backslash.
        let bs = "\\";
        assert_eq!(
            escape_identifier(&format!("foo{bs}")),
            format!("\"foo{bs}{bs}\"")
        );
        // Combined backslash+quote breakout attempt (`foo\",x`) collapses to a
        // single quoted identifier.
        assert_eq!(
            escape_identifier(&format!("foo{bs}\",x")),
            format!("\"foo{bs}{bs}\"\",x\"")
        );
    }

    #[test]
    fn test_escape_regex_pattern_combined() {
        // Test combination of all special characters (? left unescaped for executor)
        assert_eq!(escape_regex_pattern(r"(?i)test's\d+"), r"(?i)test''s\\d+");
    }

    // =========================================================
    // Tests for regex optimization (analyze_regex_for_optimization)
    // =========================================================

    #[test]
    fn test_regex_opt_anchored_prefix() {
        assert_eq!(
            analyze_regex_for_optimization("^admin.*"),
            Some(RegexOptimization::Prefix("admin".to_string()))
        );
        assert_eq!(
            // NAN-4943: an `s`/`k` no longer blocks the rewrite (nPL
            // case-insensitivity is a lowercase match, no Unicode folds).
            analyze_regex_for_optimization("^PowerShell.*$"),
            Some(RegexOptimization::Prefix("powershell".to_string()))
        );
        assert_eq!(
            analyze_regex_for_optimization("^admin$"),
            Some(RegexOptimization::BloomGuard("admin".to_string()))
        );
    }

    #[test]
    fn test_regex_opt_anchored_prefix_with_case_insensitive() {
        assert_eq!(
            analyze_regex_for_optimization("(?i)^admin.*"),
            Some(RegexOptimization::Prefix("admin".to_string()))
        );
    }

    #[test]
    fn test_regex_opt_anchored_suffix() {
        assert_eq!(
            analyze_regex_for_optimization(r".*\.exe$"),
            Some(RegexOptimization::Suffix(".exe".to_string()))
        );
        assert_eq!(
            analyze_regex_for_optimization(r".*\.dll$"),
            Some(RegexOptimization::Suffix(".dll".to_string()))
        );
    }

    #[test]
    fn test_regex_opt_literal_alternation() {
        assert_eq!(
            analyze_regex_for_optimization("(error|warning|critical)"),
            Some(RegexOptimization::LiteralAlternation(vec![
                "error".to_string(),
                "warning".to_string(),
                "critical".to_string(),
            ]))
        );
        // Without parens
        assert_eq!(
            analyze_regex_for_optimization("error|warning"),
            Some(RegexOptimization::LiteralAlternation(vec![
                "error".to_string(),
                "warning".to_string(),
            ]))
        );
    }

    #[test]
    fn test_regex_opt_alternation_with_metachar_rejected() {
        // One branch has .* — not pure literal
        assert_ne!(
            analyze_regex_for_optimization("(error|warn.*)"),
            Some(RegexOptimization::LiteralAlternation(vec![
                "error".to_string(),
                "warn.*".to_string(),
            ]))
        );
    }

    #[test]
    fn test_regex_opt_bloom_guard() {
        assert_eq!(
            analyze_regex_for_optimization(r"powershell.*-enc.*"),
            Some(RegexOptimization::BloomGuard("power".to_string()))
        );
        assert_eq!(
            analyze_regex_for_optimization(r".*mimikatz.*sekurlsa.*"),
            Some(RegexOptimization::BloomGuard("mimi".to_string()))
        );
    }

    #[test]
    fn test_regex_opt_short_literal_no_guard() {
        // "ab" is only 2 chars — below the 3-char minimum for bloom guard
        assert_eq!(analyze_regex_for_optimization(r"ab.*cd"), None);
    }

    #[test]
    fn test_regex_opt_no_optimization() {
        // Purely metacharacters
        assert_eq!(analyze_regex_for_optimization(r".*"), None);
        assert_eq!(analyze_regex_for_optimization(r".+"), None);
    }

    #[test]
    fn test_regex_opt_escaped_chars() {
        // Escaped dot in suffix
        assert_eq!(
            analyze_regex_for_optimization(r".*\.ps1$"),
            Some(RegexOptimization::Suffix(".ps1".to_string()))
        );
    }

    #[test]
    fn test_extract_longest_literal() {
        assert_eq!(
            extract_longest_literal("powershell.*-enc.*"),
            Some("power".to_string())
        );
        assert_eq!(extract_longest_literal(".*"), None);
        // Escaped dot is treated as literal, so foo.bar is one contiguous
        // string; neither `foo` nor `bar` passes the GUARD_TOKEN_MIN_LEN bar,
        // so the raw piece is kept (pre-NAN-1416 row-prefilter behavior).
        assert_eq!(
            extract_longest_literal(r"foo\.bar"),
            Some("foo.bar".to_string())
        );
    }

    /// NAN-1416: when a multi-token literal piece contains a qualifying
    /// (≥GUARD_TOKEN_MIN_LEN, lettered) token, the guard becomes that single
    /// token so the splitByNonAlpha text index can serve it.
    #[test]
    fn test_extract_longest_literal_tokenizes_winning_piece() {
        // The winning mandatory piece contains Unicode-folded S; use only
        // its safe ASCII fragment, retaining match() for the full expression.
        assert_eq!(
            extract_longest_literal(r"svchost\.exe (started|stopped)"),
            Some("vcho".to_string())
        );
        // The Kelvin-sign fold in K also requires a shorter safe fragment.
        assert_eq!(
            extract_longest_literal(r"mimikatz.*sekurlsa"),
            Some("mimi".to_string())
        );
        // No qualifying token → raw piece kept (regex row-prefilter intact).
        assert_eq!(
            extract_longest_literal(r"cmd\.exe (started|stopped)"),
            Some("cmd.exe ".to_string())
        );
    }

    /// NAN-1416: the regex bloom guard rides analyze_regex_for_optimization —
    /// a multi-token literal with a qualifying token yields a single-token
    /// BloomGuard; without one the old raw-piece guard survives.
    #[test]
    fn test_regex_opt_bloom_guard_single_token() {
        assert_eq!(
            analyze_regex_for_optimization(r"svchost\.exe (started|stopped)"),
            Some(RegexOptimization::BloomGuard("vcho".to_string()))
        );
        // `a.b ` has no qualifying token; the raw piece (≥3 chars) stays the
        // pre-filter exactly as before NAN-1416.
        assert_eq!(
            analyze_regex_for_optimization(r"a\.b (x|y)"),
            Some(RegexOptimization::BloomGuard("a.b ".to_string()))
        );
    }

    /// NAN-2361 CANDIDATE-SUPERSET INVARIANT.
    ///
    /// `analyze_regex_for_optimization` feeds an ANDed `LIKE '%token%'` guard
    /// in front of `match()`. The guard is a candidate filter, never the
    /// predicate — so it MUST NOT exclude any string the regex accepts.
    ///
    /// This models the emitted SQL in Rust: `match()` is the compiled regex
    /// (case-insensitive, unanchored `is_match`, exactly what ClickHouse runs
    /// for `'(?i)<pat>'`) and the guard is a case-insensitive substring test,
    /// exactly what `lower(col) LIKE '%tok%'` computes. Any sample the regex
    /// matches but the guard rejects is a silently lost row.
    ///
    /// The anchored-alternation-with-unequal-branch-lengths shape is the one
    /// that shipped broken (`/^(ws|wks)/` → guard `%wks%` → zero rows for
    /// `ws-sales-131.corp.local`), so it leads the corpus.
    #[test]
    fn regex_guard_never_excludes_a_row_the_pattern_matches() {
        // (pattern, samples). Every sample the pattern matches must survive
        // whatever guard the optimizer chooses.
        let corpus: &[(&str, &[&str])] = &[
            // Anchored alternation, unequal branch lengths — the shipped bug.
            ("^(ws|wks)", &["ws-sales-131.corp.local", "wks-eng-7"]),
            ("^(wks|ws)", &["ws-sales-131.corp.local", "wks-eng-7"]),
            ("^(ws-|wks-)", &["ws-sales-131.corp.local", "wks-eng-7"]),
            // Anchored alternation, EQUAL branch lengths >= 3: also broken
            // before the fix (the first longest piece won).
            ("^(abc|xyz)", &["abc-1", "xyz-1"]),
            ("^(corp|corporate)", &["corp-dc-01", "corporate-dc-01"]),
            // Unanchored alternations and alternations with a metachar branch.
            ("(ws|wks)", &["a-ws-1", "a-wks-1"]),
            ("(error|warn.*)", &["an error here", "warning here"]),
            ("x(y|z)", &["axy", "axz"]),
            // Optional / zero-min groups.
            ("admin(istrator)?", &["admin", "administrator"]),
            ("(mimikatz)*sekurlsa", &["sekurlsa::logonpasswords"]),
            // Suffix alternation.
            (r"\.(exe|scr)$", &["payload.exe", "payload.scr"]),
            // Mandatory literals mixed with alternation — the guard should
            // still be taken, from the mandatory part only.
            (r"svchost\.exe (started|stopped)", &["svchost.exe started", "svchost.exe stopped"]),
            ("(net|net1) user", &["net user", "net1 user"]),
            (r"foo.*(bar|bazlong)", &["foo bar", "foo bazlong"]),
            // Plain mandatory-literal patterns (guard must stay effective).
            (r"powershell.*-enc.*", &["powershell -enc AAA"]),
            (r".*mimikatz.*sekurlsa.*", &["x mimikatz y sekurlsa z"]),
            ("[ab]cdef", &["acdef", "bcdef"]),
        ];

        for (pattern, samples) in corpus {
            let compiled = regex::RegexBuilder::new(pattern)
                .case_insensitive(true)
                .build()
                .unwrap_or_else(|error| panic!("test pattern `{pattern}` is invalid: {error}"));
            let guard = match analyze_regex_for_optimization(pattern) {
                Some(RegexOptimization::BloomGuard(token)) => Some(token),
                // Prefix/Suffix/LiteralAlternation are complete rewrites, not
                // ANDed guards; this invariant covers the guard arm.
                _ => None,
            };
            for sample in *samples {
                assert!(
                    compiled.is_match(sample),
                    "test corpus is wrong: `{pattern}` does not match `{sample}`"
                );
                if let Some(token) = &guard {
                    assert!(
                        sample.to_lowercase().contains(&token.to_lowercase()),
                        "CANDIDATE-SUPERSET VIOLATION: guard `%{token}%` excludes \
                         `{sample}`, which `/{pattern}/` matches"
                    );
                }
            }
        }
    }

    /// NAN-4902: the anchored-alternation shapes used by ClickHouse rules. An
    /// alternation branch is never a mandatory literal, so no guard is taken.
    #[test]
    fn anchored_alternation_takes_no_bloom_guard() {
        for pattern in [
            "^(ws|wks)",
            "^(wks|ws)",
            "^(ws-|wks-)",
            "^(abc|xyz)",
            "^(corp|corporate)",
            "^(ws|wks)$",
            "(?i)^(ws|wks)",
        ] {
            assert_eq!(
                extract_longest_literal(pattern.strip_prefix("(?i)").unwrap_or(pattern)),
                None,
                "`{pattern}` must yield no mandatory literal"
            );
            assert_eq!(
                analyze_regex_for_optimization(pattern),
                None,
                "`{pattern}` must fall back to a bare match()"
            );
        }
    }

    /// NAN-2361: a zero-min repetition is optional, so its literal is not
    /// mandatory. `admin(istrator)?` keeps the mandatory `admin` guard and
    /// must NOT keep `istrator`.
    #[test]
    fn optional_group_literal_is_not_a_mandatory_guard() {
        assert_eq!(
            extract_longest_literal("admin(istrator)?"),
            Some("admin".to_string())
        );
        assert_eq!(extract_longest_literal("(mimikatz)*sekurlsa"), Some("url".to_string()));
        // `.` alone is the only mandatory literal and is below the 3-char bar.
        assert_eq!(analyze_regex_for_optimization(r"\.(exe|scr)$"), None);
    }

    #[test]
    fn test_longest_guard_token() {
        // Multi-token needles → longest qualifying token; ties → first.
        assert_eq!(longest_guard_token("failed login"), Some("failed"));
        assert_eq!(longest_guard_token("svchost.exe"), Some("svchost"));
        assert_eq!(
            longest_guard_token("failed_login_attempt"),
            Some("attempt")
        );
        assert_eq!(
            longest_guard_token("news.ycombinator.com"),
            Some("ycombinator")
        );
        // Tokens below GUARD_TOKEN_MIN_LEN never become guards — measured
        // catastrophic when unselective (`%cmd%` +153% CPU, `%192%` +159%).
        assert_eq!(longest_guard_token("cmd.exe"), None);
        assert_eq!(longest_guard_token("a.b.c"), None);
        // 5-char tokens are coin-flips (`%event%` +26% on dense) → excluded.
        assert_eq!(longest_guard_token("event_data"), None);
        // Numeric-only tokens (octets, ports, builds) are ubiquitous in log
        // text and never guard, regardless of length.
        assert_eq!(longest_guard_token("192.168.1.100"), None);
        assert_eq!(longest_guard_token("10.0.22621.1"), None);
        assert_eq!(longest_guard_token("10.0.0.52"), None);
        // …but a long lettered token qualifies even next to numerics.
        assert_eq!(
            longest_guard_token("update.20250612.payload"),
            Some("payload")
        );
        // Single-token needles → None (shape must stay untouched).
        assert_eq!(longest_guard_token("error"), None);
        assert_eq!(longest_guard_token("mimikatz"), None);
        // Leading/trailing separators around ONE token is still single-token.
        assert_eq!(longest_guard_token(" error "), None);
        // No alphanumeric content at all → no guard.
        assert_eq!(longest_guard_token("***"), None);
        assert_eq!(longest_guard_token("   "), None);
        assert_eq!(longest_guard_token(""), None);
        // LIKE metachars are separators, never part of a token.
        assert_eq!(
            longest_guard_token("100%_download\\complete"),
            Some("download")
        );
        // Non-ASCII chars are conservative separators (CH's splitByNonAlpha
        // keeps them inside tokens; an ASCII-alnum run is a substring of the
        // bigger CH token, so the guard stays index-servable either way).
        assert_eq!(longest_guard_token("café attachment"), Some("attachment"));
        // A needle that is one CH token but splits for us only guards when a
        // qualifying ASCII run remains — `teria` (5) does not.
        assert_eq!(longest_guard_token("caféteria"), None);
        // Tokens returned are alnum-only by construction.
        for needle in [
            "failed login!",
            "x%y_z\\w 100%_download",
            "a'b''c quoted_string",
        ] {
            if let Some(t) = longest_guard_token(needle) {
                assert!(
                    t.chars().all(|c| c.is_ascii_alphanumeric()),
                    "guard token {:?} from {:?} must be pure ASCII-alnum",
                    t,
                    needle
                );
            }
        }
    }

    /// NAN-1640: guard token for anchored prefix/suffix literals. Identical bar
    /// to `longest_guard_token`, but single-token literals DO guard — the
    /// startsWith/endsWith primary predicate is never index-served, unlike the
    /// single-token LIKE that justifies the ≥2-token policy over there.
    #[test]
    fn test_anchored_guard_token() {
        // Single-token literal ≥6 chars + lettered → guards (the 795x case).
        assert_eq!(anchored_guard_token("powershell"), Some("powershell"));
        assert_eq!(anchored_guard_token("sekurlsa"), Some("sekurlsa"));
        // Multi-token literal → longest qualifying token (ties → first), same
        // as the keyword guard.
        assert_eq!(anchored_guard_token("svchost.exe started"), Some("svchost"));
        assert_eq!(anchored_guard_token("run mimikatz64.log"), Some("mimikatz64"));
        // NAN-1416 bar still applies: short tokens never guard…
        assert_eq!(anchored_guard_token(".exe"), None);
        assert_eq!(anchored_guard_token("admin"), None);
        // …nor do unlettered (numeric-only) tokens, regardless of length.
        assert_eq!(anchored_guard_token("20250612"), None);
        assert_eq!(anchored_guard_token("192.168.1.100"), None);
        // No alphanumeric content → no guard.
        assert_eq!(anchored_guard_token("***"), None);
        assert_eq!(anchored_guard_token(""), None);
    }
}
