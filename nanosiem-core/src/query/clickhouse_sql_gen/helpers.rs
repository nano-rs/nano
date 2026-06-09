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
/// When `has_selective_prewhere` is true, `optimize_read_in_order` is disabled
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
    has_selective_prewhere: bool,
    is_non_timechart_aggregation: bool,
) -> String {
    let read_in_order = if has_selective_prewhere || is_non_timechart_aggregation { 0 } else { 1 };
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

/// Convert a field name to its SQL expression, handling metadata fields
/// Returns (sql_expression, needs_alias) where needs_alias indicates if the field
/// should be aliased to its original name for clean output
pub(crate) fn field_to_sql_expr(field: &str, gen: &ClickHouseSqlGenerator) -> (String, bool) {
    // Normalize field name (apply aliases)
    let field = normalize_field_name(field);

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
        if let Some(split_expr) = gen.class_split_value_sql(field) {
            return (split_expr, false);
        }
        return (gen.field_access_expr(field, "String"), false);
    }

    // Dot notation means nested metadata access
    if field.contains('.') {
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

    // Known metadata fields that need JSON extraction
    // These are fields stored in the metadata JSON column but commonly queried
    if is_known_metadata_field(field) {
        let json_type = get_metadata_field_type(field);
        return (gen.generate_json_extract(field, json_type), true);
    }

    // Unknown bare field. Under OCSF an unmapped/unpromoted name is part of the
    // `event` tail → JSONExtract (returns '' when absent) rather than a bare column
    // reference that 500s with "Unknown identifier". Under UDM `resolve` never
    // yields JsonPath, so this is skipped and the bare reference (a computed /
    // renamed / previous-stage column) is preserved byte-identically. Computed
    // pipeline fields were already returned above (is_computed_field). (NAN-1248)
    if gen.resolves_to_json_path(field) {
        return (gen.field_access_expr(field, "String"), true);
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
    let field = normalize_field_name(field);
    if gen.resolves_to_column(field) {
        // NAN-1319: class-split UDM concepts (OCSF host/user/process/url) PARTITION
        // / GROUP / dedup on the class-spanning value, same as `field_to_sql_expr`.
        // `None` for UDM and native fields → byte-identical legacy behavior.
        if let Some(split_expr) = gen.class_split_value_sql(field) {
            return split_expr;
        }
        gen.field_access_expr(field, "String")
    } else if !gen.is_computed_field(field) && gen.resolves_to_json_path(field) {
        // OCSF unmapped/tail field → JSONExtract from `event` (empty if absent),
        // not a bare reference that 500s in GROUP BY / PARTITION BY. Computed
        // pipeline fields are excluded — they are real in-scope columns and stay
        // bare. UDM never hits this (resolve never yields JsonPath). (NAN-1248)
        gen.field_access_expr(field, "String")
    } else {
        escape_identifier(field)
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

/// Escape a string for SQL (single quotes)
/// Note: Backslash must be escaped BEFORE quotes, otherwise `\'` becomes `''''` instead of `\\''`
pub(crate) fn escape_string(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "''")
}

/// Escape a regex pattern for SQL
/// Escapes backslashes and single quotes for embedding in SQL string literals.
/// Note: `?` is NOT escaped here — the executor's `escape_question_marks_in_strings`
/// handles escaping `?` inside string literals for the clickhouse-rs crate.
/// Escaping `?` here would double-escape and break regex inline flags like `(?i)`.
pub(crate) fn escape_regex_pattern(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "''")
}

/// Add LIKE-pattern escaping on top of an already SQL-escaped string (single
/// quotes doubled, backslashes doubled by `escape_string`) so that it matches
/// as a literal substring inside an `iLike '%X%'` body.
///
/// In ClickHouse LIKE/iLike, `\` is the pattern escape character, so a literal
/// backslash needs `\\` *in the pattern value* — which, after the string-literal
/// layer, is `\\\\` in the SQL text. `escape_string` only produced `\\` (one
/// backslash in the pattern value), which iLike then consumed as an escape,
/// silently matching nothing — so every `CONTAINS`/keyword over a Windows path
/// (`C:\Windows\System32\`, `\NETLOGON\`, …) failed to match. We therefore
/// double the (already-doubled) backslashes here, and escape `%`/`_` so literal
/// wildcards from user input don't act as wildcards. NAN-1157.
///
/// Use this for the codegen path that lowered to `hasToken*` pre-NAN-1026 —
/// `hasToken` is whole-token semantic and silently drops fragments like
/// `/dc/` not matching `srv-dc01`; iLike with the splitByNonAlpha text index
/// (CH 26.4's LIKE-via-dictionary-scan) gives both correct substring
/// semantics AND granule pruning.
pub(crate) fn escape_like_pattern(escaped: &str) -> String {
    // Backslash first: each `\` (the SQL-escape layer already made them pairs)
    // becomes `\\` in the pattern value so iLike matches it literally. The `\\`
    // we add for `%`/`_` is then NOT re-doubled (it's added after this step).
    escaped
        .replace('\\', "\\\\")
        .replace('%', "\\\\%")
        .replace('_', "\\\\_")
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

    // If pattern contains any metacharacters, it's not simple
    if pattern.chars().any(|c| REGEX_METACHARACTERS.contains(&c)) {
        return None;
    }

    // Pattern is simple - just a literal token
    // Convert to lowercase for case-insensitive hasToken matching
    Some(pattern.to_lowercase())
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

/// Analyze a regex pattern for optimization opportunities.
///
/// Checks (in priority order):
/// 1. Anchored prefix: `^literal.*` or `^literal$` → startsWith
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
        if prefix.len() >= 2 {
            return Some(RegexOptimization::Prefix(prefix.to_lowercase()));
        }
    }

    // 2. Anchored suffix: .*literal$ or just literal$
    if let Some(suffix) = extract_anchored_suffix(pat) {
        if suffix.len() >= 2 {
            return Some(RegexOptimization::Suffix(suffix.to_lowercase()));
        }
    }

    // 3. Pure literal alternation: (a|b|c) or a|b|c (entire pattern)
    if let Some(literals) = extract_literal_alternation(pat) {
        if literals.len() >= 2 && literals.iter().all(|l| l.len() >= 2) {
            return Some(RegexOptimization::LiteralAlternation(
                literals.into_iter().map(|l| l.to_lowercase()).collect(),
            ));
        }
    }

    // 4. Longest literal substring for bloom guard
    if let Some(token) = extract_longest_literal(pat) {
        // hasToken needs at least 3 chars for meaningful bloom filter selectivity
        if token.len() >= 3 {
            return Some(RegexOptimization::BloomGuard(token.to_lowercase()));
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

    // Remaining must be empty, .*, $, or .*$
    let rest: String = chars.collect();
    if rest.is_empty() || rest == ".*" || rest == "$" || rest == ".*$" {
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

/// Extract the longest contiguous literal substring from a regex pattern.
/// Splits on metacharacters and returns the longest piece.
fn extract_longest_literal(pat: &str) -> Option<String> {
    let mut best = String::new();
    let mut current = String::new();
    let mut chars = pat.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\\' {
            // Escaped character — the next char is a literal
            if let Some(escaped) = chars.next() {
                current.push(escaped);
            }
        } else if is_regex_metachar(c) {
            if current.len() > best.len() {
                best = current.clone();
            }
            current.clear();
        } else {
            current.push(c);
        }
    }
    if current.len() > best.len() {
        best = current;
    }

    if best.is_empty() {
        None
    } else {
        Some(best)
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
/// Returns a list of group names in order of appearance
/// Example: "(?<user>\w+)@(?<domain>\w+)" -> ["user", "domain"]
pub(crate) fn extract_named_groups(pattern: &str) -> Vec<String> {
    let re = regex::Regex::new(r"\(\?<([^>]+)>").unwrap();
    re.captures_iter(pattern)
        .filter_map(|cap| cap.get(1).map(|m| m.as_str().to_string()))
        .collect()
}

/// Convert named capture groups to numbered groups for ClickHouse
/// Example: "(?<user>\w+)" -> "(\w+)"
pub(crate) fn convert_named_groups_to_numbered(pattern: &str) -> String {
    let re = regex::Regex::new(r"\(\?<[^>]+>").unwrap();
    re.replace_all(pattern, "(").to_string()
}

/// Convert wildcard pattern (* and ?) to SQL LIKE pattern (% and _)
pub(crate) fn wildcard_to_like_pattern(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 2);
    for c in s.chars() {
        match c {
            '*' => result.push('%'),
            '?' => result.push('_'),
            '%' => result.push_str("\\%"),
            '_' => result.push_str("\\_"),
            '\'' => result.push_str("''"),
            '\\' => result.push_str("\\\\"),
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

/// Escape an identifier (column/table name)
pub(crate) fn escape_identifier(name: &str) -> String {
    // Use double quotes for identifiers - valid in both ClickHouse and ANSI SQL
    // (backticks work in ClickHouse but fail sqlparser's PostgreSqlDialect validator)
    if name.contains('.') || is_reserved_word(name) || name.contains(' ') {
        format!("\"{}\"", name.replace('"', "\"\""))
    } else {
        name.to_string()
    }
}

/// Check if a word is a ClickHouse reserved word
pub(crate) fn is_reserved_word(word: &str) -> bool {
    matches!(
        word.to_uppercase().as_str(),
        "USER"
            | "ORDER"
            | "GROUP"
            | "SELECT"
            | "FROM"
            | "WHERE"
            | "AND"
            | "OR"
            | "NOT"
            | "NULL"
            | "TRUE"
            | "FALSE"
            | "AS"
            | "BY"
            | "ASC"
            | "DESC"
            | "LIMIT"
            | "OFFSET"
            | "DATABASE"
            | "TABLE"
            | "INDEX"
            | "KEY"
            | "PRIMARY"
            | "ENGINE"
            | "PARTITION"
    )
}

#[cfg(test)]
mod inline_tests {
    use super::*;

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
            analyze_regex_for_optimization("^PowerShell.*$"),
            Some(RegexOptimization::Prefix("powershell".to_string()))
        );
        assert_eq!(
            analyze_regex_for_optimization("^admin$"),
            Some(RegexOptimization::Prefix("admin".to_string()))
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
            Some(RegexOptimization::BloomGuard("powershell".to_string()))
        );
        assert_eq!(
            analyze_regex_for_optimization(r".*mimikatz.*sekurlsa.*"),
            Some(RegexOptimization::BloomGuard("mimikatz".to_string()))
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
            Some("powershell".to_string())
        );
        assert_eq!(extract_longest_literal(".*"), None);
        // Escaped dot is treated as literal, so foo.bar is one contiguous string
        assert_eq!(
            extract_longest_literal(r"foo\.bar"),
            Some("foo.bar".to_string())
        );
    }
}
