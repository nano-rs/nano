// SPDX-License-Identifier: AGPL-3.0-or-later

//! Materialized View Generator for Real-Time Detection
//!
//! This module implements the materialized view generator that creates ClickHouse
//! materialized views for real-time detection rules. Materialized views enable
//! instant detection (10-30s latency) for simple IOC matching rules.
//!
//! Requirements: 4.1, 4.4, 4.5

use crate::detection::risk::default_score_for_severity;
use crate::models::detection_rule::DetectionRule;
use crate::query::{parse_query, ClickHouseSqlGenerator, Query, SearchExpr};
use thiserror::Error;
use tracing::{debug, error, info};

/// Validate that a field name is safe for interpolation into DDL statements.
///
/// This prevents SQL injection via crafted `risk_entity_field` values (e.g.,
/// `concat(currentDatabase(), ':', version())`). The function applies, in order:
/// 1. A strict identifier pattern (defense-in-depth) — `^[a-z][a-z0-9_.]*$`,
///    which blocks parentheses, semicolons, quotes, spaces, and SQL keywords
///    used as function calls. This is the actual injection guard and is applied
///    REGARDLESS of profile, so it can never be loosened by widening the
///    allowlist.
/// 2. An allowlist of *known* field names from the **active schema profile**
///    ([`SchemaProfile::is_known_field`]) — UDM's `src_ip`/`process_name`, OR
///    OCSF's dotted promoted columns (`src_endpoint.ip`, `actor.process.cmd_line`).
/// 3. The overflow escape hatch (`ext.*` for UDM-style overflow).
///
/// NAN-1241 Phase 5: the allowlist is profile-derived so OCSF dotted fields
/// validate, but the strict identifier pattern (step 1) is unchanged — the
/// dotted OCSF names already match `[a-z][a-z0-9_.]*`, so widening the allowlist
/// does not widen what *characters* are accepted, and the guard stays
/// injection-safe.
fn validate_ddl_field_name(
    field: &str,
    profile: &dyn crate::schema::SchemaProfile,
) -> Result<(), MaterializedViewError> {
    // Defense-in-depth: reject anything that doesn't match a strict identifier pattern.
    // This blocks parentheses, semicolons, quotes, spaces, SQL keywords used as
    // function calls, and any other unexpected characters. Applied before (and
    // independently of) the profile allowlist so the injection guard is never
    // relaxed by a broader field universe.
    let is_safe_identifier = !field.is_empty()
        && field.len() <= 128
        && field
            .bytes()
            .next()
            .map_or(false, |b| b.is_ascii_lowercase())
        && field
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'.');

    if !is_safe_identifier {
        return Err(MaterializedViewError::InvalidRule(format!(
            "Invalid field name for DDL interpolation: '{}'. \
             Field names must match [a-z][a-z0-9_.]*",
            field
        )));
    }

    // Check if it's a known field in the active schema's universe. For UDM this
    // is the explicit columns + the generated `UdmField` enum (byte-identical to
    // the previous `field.parse::<UdmField>()` allowlist, since `is_known_field`
    // covers it); for OCSF this is the promoted dotted columns + known paths.
    if profile.is_known_field(field) {
        return Ok(());
    }

    // Allow ext.* extension fields (e.g., ext.custom_field)
    if field.starts_with("ext.") && field.len() > 4 {
        return Ok(());
    }

    Err(MaterializedViewError::InvalidRule(format!(
        "Unknown field '{}' cannot be used in DDL. \
         Must be a known field in the active schema or an ext.* extension field.",
        field
    )))
}

/// Reject search expressions that are valid for scheduled search but not eligible
/// for a real-time materialized view.
///
/// Real-time eligibility must match the historical behavior exactly: `Keyword`
/// (full-text) and `InSubsearch` filters fall back to scheduled mode. Everything
/// else is handed to the canonical `ClickHouseSqlGenerator::generate_search_expr`.
/// The match is exhaustive on purpose: a new `SearchExpr` variant forces a
/// decision here rather than silently slipping into the real-time path.
fn reject_unsupported_for_realtime(expr: &SearchExpr) -> Result<(), MaterializedViewError> {
    match expr {
        SearchExpr::Keyword(_) => Err(MaterializedViewError::InvalidRule(
            "Real-time rules cannot use keyword search (requires full-text search)".to_string(),
        )),
        SearchExpr::InSubsearch { .. } => Err(MaterializedViewError::InvalidRule(
            "Real-time rules cannot use subsearch (IN [...])".to_string(),
        )),
        // NAN-1580: the `ioc` observable-anywhere term expands across many
        // columns (and can be feed-sourced) — not a simple-column predicate, so
        // it is excluded from the real-time materialized-view path.
        SearchExpr::IocMatch { .. } => Err(MaterializedViewError::InvalidRule(
            "Real-time rules cannot use the ioc retro-hunt term".to_string(),
        )),
        SearchExpr::And(left, right) | SearchExpr::Or(left, right) => {
            reject_unsupported_for_realtime(left)?;
            reject_unsupported_for_realtime(right)
        }
        SearchExpr::Not(inner) | SearchExpr::Group(inner) => {
            reject_unsupported_for_realtime(inner)
        }
        SearchExpr::FieldFilter { .. }
        | SearchExpr::FunctionFilter { .. }
        | SearchExpr::FieldFunctionFilter { .. }
        | SearchExpr::InList { .. }
        | SearchExpr::BooleanFunction(_)
        | SearchExpr::LiteralComparison { .. } => Ok(()),
    }
}

/// Errors that can occur during materialized view operations
#[derive(Debug, Error)]
pub enum MaterializedViewError {
    #[error("ClickHouse error: {0}")]
    ClickHouseError(String),

    #[error("Invalid rule for real-time detection: {0}")]
    InvalidRule(String),

    #[error("Query parse error: {0}")]
    QueryParseError(String),

    #[error("DDL generation error: {0}")]
    DdlGenerationError(String),

    #[error("View already exists: {0}")]
    ViewAlreadyExists(String),

    #[error("View not found: {0}")]
    ViewNotFound(String),
}

/// Materialized View Generator
///
/// Generates and manages ClickHouse materialized views for real-time detection rules.
/// Materialized views automatically process incoming logs and write signals to the
/// signals table when matches occur.
///
/// Requirements: 4.1
pub struct MaterializedViewGenerator {
    /// ClickHouse client for DDL operations
    clickhouse_client: clickhouse::Client,
    /// Active schema profile (OCSF, NAN-1241). Drives the entire MV DDL:
    /// - field-name validation ([`validate_ddl_field_name`]),
    /// - risk-entity auto-detection over the profile's entity-extraction order,
    /// - the `FROM` table ([`Self::logs_table_name`]: UDM `logs` / OCSF
    ///   `ocsf_logs`) and the `<table>.id` matched-log key,
    /// - the WHERE clause (profile is injected into the canonical generator in
    ///   [`Self::extract_where_clause`] so UDM field names resolve to the active
    ///   schema's physical columns).
    ///
    /// Defaults to [`UdmProfile`]; the UDM path is byte-identical to the
    /// pre-OCSF DDL (`escape_identifier` is a no-op on single-segment names and
    /// `logs_table_name` returns `logs`).
    profile: std::sync::Arc<dyn crate::schema::SchemaProfile>,
}

impl MaterializedViewGenerator {
    /// Create a new materialized view generator (UDM profile).
    ///
    /// # Arguments
    /// * `clickhouse_client` - ClickHouse client for executing DDL statements
    ///
    /// Requirements: 4.1
    pub fn new(clickhouse_client: clickhouse::Client) -> Self {
        Self {
            clickhouse_client,
            profile: std::sync::Arc::new(crate::schema::UdmProfile::new()),
        }
    }

    /// ` ON CLUSTER \`<name>\`` when `CLICKHOUSE_CLUSTER` is set (the deploy sets
    /// it only on clustered ClickHouse), else empty. Real-time MV DDL is built at
    /// runtime, so — unlike migrations, which the cluster init auto-injects
    /// `ON CLUSTER` into — it must add the clause itself (audit D8).
    ///
    /// NAN-1728: the pure-formatting half now delegates to the canonical runtime
    /// helper in `crate::db::dual_pool` (no behavior change — that helper
    /// preserves the backtick-quoted form). The env read stays here.
    fn on_cluster_clause() -> String {
        Self::format_on_cluster(std::env::var("CLICKHOUSE_CLUSTER").ok().as_deref())
    }

    /// Pure formatter for [`Self::on_cluster_clause`] (testable without env).
    /// Thin re-export of the shared formatter.
    fn format_on_cluster(cluster: Option<&str>) -> String {
        crate::db::dual_pool::format_on_cluster(cluster)
    }

    /// Set the active schema profile (OCSF, NAN-1241). Makes the generated MV
    /// DDL schema-aware end to end: FROM table, `<table>.id` matched-log key,
    /// WHERE-clause column resolution, risk-entity auto-detection, and DDL
    /// field-name validation all follow the injected profile. UDM is the default
    /// and stays byte-identical to the pre-OCSF DDL.
    pub fn with_profile(
        mut self,
        profile: std::sync::Arc<dyn crate::schema::SchemaProfile>,
    ) -> Self {
        self.profile = profile;
        self
    }

    /// Generate materialized view name from rule ID
    ///
    /// Format: mv_rt_detection_{rule_id_without_hyphens}
    ///
    /// Example: mv_rt_detection_550e8400e29b41d4a716446655440000
    fn generate_view_name(rule: &DetectionRule) -> String {
        format!("mv_rt_detection_{}", rule.id.to_string().replace('-', ""))
    }

    /// Bare logs-table name the MV reads `FROM` for the active profile.
    ///
    /// UDM → `logs` (byte-identical to the previous hardcode); OCSF → `ocsf_logs`
    /// (`clickhouse/ocsf/init.sql`). Mirrors `SearchService::logs_table_key`'s
    /// profile→key mapping. The MV body runs in the deployment's default CH
    /// database, so the bare (un-prefixed) name is what the MV needs — the
    /// tenant-aware `table_names` registry (which the search service uses) is not
    /// available on this generator, and the prior code already used the bare
    /// `logs` here.
    fn logs_table_name(profile: &dyn crate::schema::SchemaProfile) -> &'static str {
        match profile.id() {
            crate::schema::SchemaId::Ocsf => "ocsf_logs",
            crate::schema::SchemaId::Udm
            | crate::schema::SchemaId::Spans
            | crate::schema::SchemaId::Metrics => "logs",
        }
    }

    /// Create a materialized view for a real-time detection rule
    ///
    /// This method generates the DDL for the materialized view and executes it
    /// in ClickHouse. The view will automatically process incoming logs and write
    /// signals to the signals table.
    ///
    /// # Arguments
    /// * `rule` - The detection rule to create a view for
    ///
    /// # Returns
    /// * `Ok(String)` - The name of the created view
    /// * `Err(MaterializedViewError)` - If the view creation fails
    ///
    /// Requirements: 4.1
    pub async fn create_view(&self, rule: &DetectionRule) -> Result<String, MaterializedViewError> {
        let view_name = Self::generate_view_name(rule);

        info!(
            "Creating materialized view {} for rule {}",
            view_name, rule.name
        );

        // Generate DDL
        let ddl = self.generate_view_ddl(rule)?;

        debug!("Generated DDL for view {}: {}", view_name, ddl);

        // Execute DDL
        self.clickhouse_client
            .query(&ddl)
            .execute()
            .await
            .map_err(|e| {
                // ALERTING: Log ERROR on materialized view creation failure (Requirement 9.4)
                tracing::error!(
                    view_name = %view_name,
                    rule_id = %rule.id,
                    rule_name = %rule.name,
                    error = %e,
                    "ALERT: Failed to create materialized view for real-time detection rule"
                );
                MaterializedViewError::ClickHouseError(format!(
                    "Failed to create materialized view: {}",
                    e
                ))
            })?;

        info!("Successfully created materialized view {}", view_name);

        Ok(view_name)
    }

    /// Drop a materialized view from ClickHouse
    ///
    /// # Arguments
    /// * `view_name` - The name of the view to drop
    ///
    /// # Returns
    /// * `Ok(())` - If the view was dropped successfully
    /// * `Err(MaterializedViewError)` - If the drop operation fails
    ///
    /// Requirements: 4.5
    pub async fn drop_view(&self, view_name: &str) -> Result<(), MaterializedViewError> {
        info!("Dropping materialized view {}", view_name);

        // Audit D8: drop ON CLUSTER too, or the view lingers on other nodes.
        let ddl = format!(
            "DROP VIEW IF EXISTS {}{}",
            view_name,
            Self::on_cluster_clause()
        );

        self.clickhouse_client
            .query(&ddl)
            .execute()
            .await
            .map_err(|e| {
                error!("Failed to drop materialized view {}: {}", view_name, e);
                MaterializedViewError::ClickHouseError(format!(
                    "Failed to drop materialized view: {}",
                    e
                ))
            })?;

        info!("Successfully dropped materialized view {}", view_name);

        Ok(())
    }

    /// Recreate a materialized view (for rule updates)
    ///
    /// This method drops the existing view and creates a new one with the updated
    /// rule definition. This is necessary when a real-time rule is modified.
    ///
    /// # Arguments
    /// * `rule` - The updated detection rule
    ///
    /// # Returns
    /// * `Ok(String)` - The name of the recreated view
    /// * `Err(MaterializedViewError)` - If the recreation fails
    ///
    /// Requirements: 4.4
    pub async fn recreate_view(
        &self,
        rule: &DetectionRule,
    ) -> Result<String, MaterializedViewError> {
        let view_name = Self::generate_view_name(rule);

        info!(
            "Recreating materialized view {} for rule {}",
            view_name, rule.name
        );

        // Drop existing view (ignore errors if it doesn't exist)
        let _ = self.drop_view(&view_name).await;

        // Create new view
        self.create_view(rule).await.map_err(|e| {
            // ALERTING: Log ERROR on materialized view update failure (Requirement 9.4)
            tracing::error!(
                view_name = %view_name,
                rule_id = %rule.id,
                rule_name = %rule.name,
                error = %e,
                "ALERT: Failed to recreate materialized view for real-time detection rule update"
            );
            e
        })
    }

    /// Generate CREATE MATERIALIZED VIEW DDL statement
    ///
    /// This method parses the detection rule query, extracts filter conditions,
    /// and generates a ClickHouse materialized view DDL statement that writes
    /// matching logs to the signals table.
    ///
    /// # Arguments
    /// * `rule` - The detection rule to generate DDL for
    ///
    /// # Returns
    /// * `Ok(String)` - The generated DDL statement
    /// * `Err(MaterializedViewError)` - If DDL generation fails
    ///
    /// Requirements: 4.1
    pub fn generate_view_ddl(&self, rule: &DetectionRule) -> Result<String, MaterializedViewError> {
        // NAN-1561: spans/metrics rules are scheduled-only. A materialized view
        // reads FROM the logs table (logs_table_name only maps
        // Udm/Ocsf/...→logs|ocsf_logs and has no otel_spans/otel_metrics arm),
        // and the MV codegen assumes UDM/OCSF physical columns. Reject before
        // any DDL is built.
        if let Some(ds) = rule.dataset.as_deref() {
            if crate::query::Dataset::from_selector(ds) != crate::query::Dataset::Logs {
                return Err(MaterializedViewError::InvalidRule(format!(
                    "Real-time rules cannot target dataset '{ds}' \
                     (spans/metrics are scheduled-only). Use scheduled detection mode."
                )));
            }
        }

        // Parse the rule query
        let query = parse_query(&rule.query).map_err(|e| {
            MaterializedViewError::QueryParseError(format!("Failed to parse rule query: {}", e))
        })?;

        // Extract filter conditions from the query
        let where_clause = self.extract_where_clause(&query)?;

        // Get risk entity field - auto-detect if not specified or empty
        let risk_entity_field = match rule.risk_entity_field.as_ref() {
            Some(field) if !field.is_empty() => field.clone(),
            _ => {
                // Auto-detect by analyzing which fields are referenced in the query
                self.auto_detect_risk_entity(&where_clause)
            }
        };

        // Validate risk_entity_field before interpolating into DDL to prevent SQL injection.
        // An attacker could set risk_entity_field to a SQL expression like
        // `concat(currentDatabase(), ':', version())` to exfiltrate data.
        // Validation runs on the UNESCAPED physical name (`src_ip` /
        // `src_endpoint.ip`) against the active profile's field universe; the
        // identity escape below is applied only after the guard passes.
        validate_ddl_field_name(&risk_entity_field, self.profile.as_ref())?;

        // Resolve `risk_entity_field` to the physical column expression the SELECT
        // references via `... AS risk_entity`. Mirrors the canonical scheduled path
        // (`risk::ScoreCalculator::extract_entity`): the stored/auto-detected field
        // is ALREADY a physical column name in the active schema (UDM `src_ip`,
        // OCSF `src_endpoint.ip`) — it is NOT a UDM-semantic alias to translate.
        // We only escape it so dotted OCSF columns are quoted for ClickHouse.
        // `escape_identifier` is a no-op on UDM single-segment names, so UDM DDL
        // is byte-identical; OCSF dotted names become `"src_endpoint.ip"`.
        let risk_entity_sql = crate::query::escape_identifier(&risk_entity_field);

        // Calculate risk score (use rule's risk_score or default based on severity).
        // Severity defaults are sourced from `crate::detection::risk` so the MV path
        // and the scheduled path share the same base-score fallback.
        //
        // This bakes a STATIC base score into the `signals` row as a coarse hint
        // only — it is NOT the authoritative finding score. As of NAN-1663 the
        // `SignalProcessor` recomputes the score for every drained signal through
        // the SAME engine the scheduled path uses (`risk::score_rule_match` →
        // `ScoreCalculator::calculate`), applying the rule's `risk_modifiers` and
        // the global `risk_weight` against the matched event. So a rule scores
        // identically scheduled vs. real-time (audit R1), and this SQL value only
        // needs the shared severity-default fallback (kept in lockstep via
        // `default_score_for_severity`). `| risk score=…` piped rules remain
        // rejected from real-time entirely.
        let risk_score = rule
            .risk_score
            .unwrap_or_else(|| default_score_for_severity(rule.severity));

        // Generate view name
        let view_name = Self::generate_view_name(rule);

        // Resolve the FROM table for the active profile (UDM → `logs`, OCSF →
        // `ocsf_logs`). The MV body runs inside the deployment's default CH
        // database (`nanosiem`), so the bare table name is correct for both and
        // keeps UDM byte-identical (`logs`). `<table>.id` qualifies the row key
        // against the same table (both schemas expose an `id` column).
        let logs_table = Self::logs_table_name(self.profile.as_ref());

        // Generate DDL.
        //
        // R2 (alias-shadows-column, Code 53 class): the projection assigns the
        // *constant* rule metadata to output columns whose names — `rule_name`,
        // `severity`, `risk_score`, `risk_entity` — are ALSO real base columns of
        // the `logs`/`ocsf_logs` table (they are RBA-owned CIM/UDM columns a rule
        // may legitimately filter on). ClickHouse resolves a name that is both a
        // SELECT alias and a table column to the ALIAS EXPRESSION. If the filter
        // predicate lived in the same SELECT scope as `'critical' AS severity`,
        // a rule filtering `severity="high"` would compile to
        // `lower('critical') = lower('high')` — a constant WHERE that silently
        // matches everything or nothing with NO error. (Empirically: a flat MV
        // over a source with a real `severity` column dropped every matching row.)
        //
        // The projection aliases CANNOT simply be renamed with a reserved prefix:
        // a `... TO signals` materialized view matches the SELECT output to the
        // target table **by column NAME**, not by position (ClickHouse raises
        // `THERE_IS_NO_COLUMN` otherwise), so the output names are pinned to the
        // `signals` schema.
        //
        // Fix: evaluate the filter predicate in an inner derived-table subquery,
        // where none of the outer projection aliases are in scope, so the WHERE
        // always references the TRUE base columns. The outer projection then only
        // re-labels already-filtered rows and can safely reuse base-column names.
        // Audit D8: on a cluster the MV must be created ON CLUSTER so it exists
        // (and fires) on every node — otherwise it lives on only the node the
        // admin pool hit, and logs ingested on any other shard/replica never
        // pass it (silent zero alerts). Empty on single-node/open-core, so that
        // DDL is byte-identical. The MV writes `TO signals` (the LOCAL table on
        // each node); `signals_distributed` (already in DISTRIBUTED_TABLE_SET)
        // fans the SignalProcessor's reads across shards.
        //
        // Audit D9: widened the freshness floor from 1h to 24h. Parsed events
        // carry the LOG timestamp, not ingest time, so a 1h floor dropped
        // normal batch-forwarded / outage-replayed events; 24h keeps a bound so
        // the MV doesn't rescan unbounded history per insert.
        let on_cluster = Self::on_cluster_clause();
        let ddl = format!(
            r#"CREATE MATERIALIZED VIEW {}{} TO signals AS
SELECT
    generateUUIDv4() AS id,
    timestamp,
    '{}' AS rule_id,
    '{}' AS rule_name,
    '{}' AS severity,
    {} AS risk_score,
    {} AS risk_entity,
    matched_log_id,
    toJSONString(map()) AS metadata,
    now64(6) AS _inserted_at
FROM (
    SELECT
        *,
        {}.id AS matched_log_id
    FROM {}
    WHERE {}
      AND timestamp >= now() - INTERVAL 24 HOUR
) AS matched_logs"#,
            view_name,
            on_cluster,
            rule.id,
            crate::sql_hygiene::escape_sql_string(&rule.name), // Escape backslashes + single quotes
            format!("{:?}", rule.severity).to_lowercase(),
            risk_score,
            risk_entity_sql,
            logs_table,
            logs_table,
            where_clause
        );

        // R2 GUARD: the filter predicate must live in the inner source subquery,
        // never in the outer projection scope where the constant column aliases
        // (`rule_name`/`severity`/`risk_score`/`risk_entity`) are defined. If a
        // future edit collapses the subquery, those aliases would shadow the
        // base columns and any rule filtering one of them would compile to a
        // constant WHERE (silent match-all / match-none). Assert the structural
        // isolation holds: the `FROM (` subquery boundary must precede the WHERE.
        Self::assert_filter_scope_isolated(&ddl)?;

        Ok(ddl)
    }

    /// Output-projection aliases the MV assigns that COLLIDE with real base
    /// columns of the `logs`/`ocsf_logs` table. These are RBA-owned CIM/UDM
    /// columns a detection rule may filter on, so their names in the outer
    /// projection would shadow the base column inside a shared SELECT scope
    /// (the R2 alias-shadows-column bug). The generated DDL keeps the filter in
    /// an inner subquery so this can never happen; [`Self::assert_filter_scope_isolated`]
    /// enforces that invariant on every generated DDL.
    const SHADOW_PRONE_OUTPUT_ALIASES: &'static [&'static str] =
        &["rule_name", "severity", "risk_score", "risk_entity"];

    /// R2 codegen guard: verify the filter predicate is isolated in the inner
    /// source subquery, so a projection alias can never shadow a filtered base
    /// column. The generated DDL places every rule filter inside
    /// `FROM ( SELECT ... WHERE <filter> ) AS matched_logs`; the outer SELECT —
    /// which defines the shadow-prone aliases — is textually *before* the
    /// `FROM (` boundary, and the WHERE is *after* it. If a future edit collapses
    /// the subquery (moving the WHERE up alongside the constant aliases), this
    /// guard fails fast instead of shipping a silently-constant materialized view.
    fn assert_filter_scope_isolated(ddl: &str) -> Result<(), MaterializedViewError> {
        // The subquery boundary that isolates the filter scope.
        let sub_open = ddl.find("FROM (").ok_or_else(|| {
            MaterializedViewError::DdlGenerationError(
                "real-time MV DDL lost its source subquery — the rule filter is no \
                 longer isolated from output-column aliases (R2 shadowing risk)"
                    .to_string(),
            )
        })?;

        // Every WHERE must appear after the subquery opens (i.e. inside it), so
        // filtered base columns are resolved before the shadow-prone aliases exist.
        if let Some(where_pos) = ddl.find(" WHERE ") {
            if where_pos < sub_open {
                return Err(MaterializedViewError::DdlGenerationError(format!(
                    "real-time MV WHERE is not isolated in the source subquery; a \
                     rule filtering any of {:?} would shadow the base column and \
                     compile to a constant predicate",
                    Self::SHADOW_PRONE_OUTPUT_ALIASES
                )));
            }
        }
        Ok(())
    }

    /// Auto-detect the best risk entity field by analyzing the query
    ///
    /// Analyzes which UDM fields are referenced in the WHERE clause and picks
    /// the most appropriate one for risk scoring based on priority:
    /// 1. IP addresses (src_ip, dest_ip, dvc_ip, etc.)
    /// 2. Hostnames (src_host, dest_host, host, etc.)
    /// 3. Users (src_user, dest_user, user, etc.)
    /// 4. File hashes (file_hash, process_hash, service_hash, ssl_hash)
    ///
    /// # Arguments
    /// * `where_clause` - The SQL WHERE clause to analyze
    ///
    /// # Returns
    /// * The detected field name, or "src_ip" as default
    fn auto_detect_risk_entity(&self, where_clause: &str) -> String {
        // Priority order for risk entity fields, from the active profile's
        // entity-extraction order (NAN-1241). For UDM this reproduces the
        // previous hard-coded list (the superset list is a superset of it; the
        // first match in priority order wins, so a UDM WHERE clause resolves to
        // the same field). For OCSF the WHERE clause is OCSF-shaped, so the scan
        // matches OCSF physical columns (`src_endpoint.ip`, `user.name`, …) which
        // the order yields directly; the returned name is escaped at the DDL
        // interpolation site (`generate_view_ddl`).
        for &(_role, field) in self.profile.entity_extraction_order() {
            if where_clause.contains(field) {
                tracing::debug!(
                    "Auto-detected risk entity field: {} (found in query)",
                    field
                );
                return field.to_string();
            }
        }

        // Default to the profile's risk-entity default (UDM `src_ip` via the
        // first entity-extraction entry) if no fields found.
        let default = self
            .profile
            .entity_extraction_order()
            .first()
            .map(|(_role, f)| *f)
            .unwrap_or("src_ip");
        tracing::debug!("Auto-detected risk entity field: {} (default)", default);
        default.to_string()
    }

    /// Check if a query string contains piped commands
    ///
    /// This is a quick check before parsing to determine if a query
    /// has piped commands that would make it incompatible with real-time mode.
    ///
    /// # Arguments
    /// * `query_str` - The query string to check
    ///
    /// # Returns
    /// * `true` if the query contains piped commands (|)
    /// * `false` if it's a simple filter query
    pub fn has_piped_commands(query_str: &str) -> bool {
        query_str.contains('|')
    }

    /// Real-time (materialized-view) eligibility for a *parsed* query, decoupled
    /// from DDL generation.
    ///
    /// This is the query-shape half of the eligibility gate that
    /// [`Self::extract_where_clause`] applies during DDL generation: reject piped
    /// commands (stats/where/timechart/prevalence/…) and reject the
    /// [`reject_unsupported_for_realtime`] leaf variants (keyword full-text,
    /// `IN [...]` subsearch, `ioc` retro-hunt). It deliberately does NOT check the
    /// dataset (`logs`-only) or the risk-entity column, which need the full
    /// `DetectionRule` context — callers surfacing a hint (e.g. the `/api/rules/validate`
    /// endpoint) gate those separately.
    ///
    /// Sharing this with `extract_where_clause` keeps the "eligible for real-time"
    /// hint in lock-step with what the MV path will actually accept, so we never
    /// nudge a user toward a mode their query would be auto-downgraded out of.
    ///
    /// # Returns
    /// * `Ok(())` if the query shape is real-time eligible
    /// * `Err(MaterializedViewError::InvalidRule)` with a human-readable reason otherwise
    pub fn check_query_realtime_eligible(query: &Query) -> Result<(), MaterializedViewError> {
        match query {
            Query::Search(search_expr) => reject_unsupported_for_realtime(search_expr),
            Query::Piped { .. } => Err(MaterializedViewError::InvalidRule(
                "Real-time rules cannot contain piped commands (stats, where, etc.)".to_string(),
            )),
        }
    }

    /// Extract WHERE clause from parsed query
    ///
    /// Converts the parsed query AST into a ClickHouse WHERE clause.
    /// Only supports simple filters (no aggregations, no joins).
    ///
    /// # Arguments
    /// * `query` - The parsed query AST
    ///
    /// # Returns
    /// * `Ok(String)` - The WHERE clause (without the WHERE keyword)
    /// * `Err(MaterializedViewError)` - If the query contains unsupported features
    ///
    /// Requirements: 4.1
    fn extract_where_clause(&self, query: &Query) -> Result<String, MaterializedViewError> {
        // Real-time eligibility is intentionally narrower than scheduled search:
        // piped commands, keyword (full-text) and subsearch filters are not
        // supported in a materialized view and must fall back to scheduled mode.
        // This is the same gate the `/api/rules/validate` hint uses, so the
        // "eligible for real-time" nudge stays in lock-step with what the MV path
        // actually accepts.
        Self::check_query_realtime_eligible(query)?;
        // Safe: `check_query_realtime_eligible` only returns `Ok` for
        // `Query::Search`. The `else` is unreachable but returns a sane error
        // rather than panicking.
        let Query::Search(search_expr) = query else {
            return Err(MaterializedViewError::InvalidRule(
                "Real-time rules cannot contain piped commands (stats, where, etc.)".to_string(),
            ));
        };

        // Delegate WHERE generation to the canonical generator so the
        // real-time WHERE clause stays byte-for-byte identical to the scheduled
        // path. This module previously carried its own SearchExpr->SQL codegen
        // that had drifted from canonical (no lower(), no field-name
        // normalization, no wildcard->iLike, case-sensitive regex, no hostname
        // FQDN expansion), so a rule could match in scheduled mode yet silently
        // never match in real-time mode (NAN-1142).
        //
        // OCSF (NAN-1241): the generator is built `.with_profile(self.profile)`
        // so UDM field names in the rule query resolve to the active schema's
        // physical columns — UDM `dest_ip="…"` → `lower(dest_ip) = …` (default
        // `UdmProfile`, byte-identical to the previous `new()`), OCSF →
        // `dst_endpoint.ip` etc. `generate_search_expr` emits only the WHERE
        // predicate (no FROM), so the generator's table name is irrelevant here;
        // the FROM table is resolved separately in `generate_view_ddl` via
        // `logs_table_name`.
        ClickHouseSqlGenerator::new()
            .with_profile(self.profile.clone())
            .generate_search_expr(search_expr)
            .map_err(|e| {
                MaterializedViewError::DdlGenerationError(format!(
                    "Failed to generate real-time WHERE clause: {e}"
                ))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::detection_rule::{AiTriageHints, AlertMode, DetectionMode, RuleMode, Severity};
    use chrono::Utc;
    use uuid::Uuid;

    #[test]
    fn format_on_cluster_gates_on_cluster_name() {
        // Audit D8: single-node/open-core (no cluster name) → no clause, so the
        // MV DDL is byte-identical. A configured cluster → the ON CLUSTER clause.
        assert_eq!(MaterializedViewGenerator::format_on_cluster(None), "");
        assert_eq!(MaterializedViewGenerator::format_on_cluster(Some("")), "");
        assert_eq!(MaterializedViewGenerator::format_on_cluster(Some("  ")), "");
        assert_eq!(
            MaterializedViewGenerator::format_on_cluster(Some("nano_cluster")),
            " ON CLUSTER `nano_cluster`"
        );
    }

    /// DetectionRule fixture matching the current struct shape. `DetectionRule`
    /// has no `Default`, so every field is set explicitly; keep this in sync when
    /// the model changes (the previous fixture rotted, which is why this whole
    /// module was `#[cfg(any())]`-disabled before NAN-1142).
    fn create_test_rule() -> DetectionRule {
        DetectionRule {
            id: Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            name: "Test Rule".to_string(),
            description: Some("Test description".to_string()),
            query: "dest_ip=\"192.0.2.1\"".to_string(),
            severity: Severity::High,
            mitre_tactics: vec![],
            mitre_techniques: vec![],
            schedule_cron: None,
            mode: RuleMode::Alerting,
            narrative: None,
            reference_url: None,
            author: None,
            tags: vec![],
            ai_generated: false,
            realtime_enabled: false,
            detection_mode: DetectionMode::RealTime,
            materialized_view_name: None,
            risk_score: Some(75),
            risk_entity_field: Some("src_ip".to_string()),
            risk_modifiers: sqlx::types::Json(vec![]),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_run_at: None,
            last_match_at: None,
            match_count: 0,
            live_match_count: 0,
            archived: false,
            folder: None,
            ai_triage_hints: sqlx::types::Json(AiTriageHints::default()),
            lookback_minutes: None,
            dataset: None,
            auto_tuning_enabled: true,
            auto_tuning_min_confidence: 0.8,
            auto_tuning_critical: false,
            auto_tuning_disabled_until: None,
            case_visibility: "private".to_string(),
            case_assigned_group: None,
            alert_mode: AlertMode::default(),
            next_run_at: None,
            claimed_by: None,
            claimed_at: None,
            playbook_selector_mode: "none".to_string(),
            playbook_id: None,
        }
    }

    /// The WHERE body the canonical (scheduled) generator produces for `query`.
    /// The real-time MV WHERE must equal this exactly — that invariant is the
    /// entire point of NAN-1142.
    fn canonical_where(query: &str) -> String {
        let parsed = parse_query(query).expect("query should parse");
        let expr = match parsed {
            Query::Search(expr) => expr,
            Query::Piped { .. } => panic!("not a search query: {query}"),
        };
        ClickHouseSqlGenerator::new()
            .generate_search_expr(&expr)
            .expect("canonical generation should succeed")
    }

    /// Assert the generated DDL embeds exactly the canonical WHERE for `query`.
    fn assert_where_matches_canonical(query: &str) {
        let mut rule = create_test_rule();
        rule.query = query.to_string();
        let generator = MaterializedViewGenerator::new(clickhouse::Client::default());
        let ddl = generator
            .generate_view_ddl(&rule)
            .unwrap_or_else(|e| panic!("DDL generation failed for {query:?}: {e}"));
        let expected = canonical_where(query);
        assert!(
            ddl.contains(&format!("WHERE {expected}")),
            "real-time WHERE drifted from canonical\n  query:     {query}\n  canonical: {expected}\n  ddl:\n{ddl}"
        );
    }

    /// NAN-1688: `check_query_realtime_eligible` is the query-shape gate the
    /// validate endpoint reuses to nudge scheduled rules that qualify. It must
    /// stay in lock-step with what `generate_view_ddl` actually accepts.
    fn is_realtime_eligible(query: &str) -> bool {
        let parsed = parse_query(query).expect("query should parse");
        MaterializedViewGenerator::check_query_realtime_eligible(&parsed).is_ok()
    }

    #[test]
    fn test_realtime_eligible_simple_filters() {
        // Simple column predicates are the whole point of the MV path.
        assert!(is_realtime_eligible("src_ip=\"10.0.0.1\""));
        assert!(is_realtime_eligible("dest_port=445 AND process_name=\"cmd.exe\""));
        assert!(is_realtime_eligible("NOT (user=\"admin\")"));
    }

    #[test]
    fn test_realtime_ineligible_piped_commands() {
        // Anything after a `|` (stats/where/timechart/prevalence/…) drops out.
        assert!(!is_realtime_eligible("src_ip=\"10.0.0.1\" | stats count by user"));
        assert!(!is_realtime_eligible("error | where count > 10"));
    }

    #[test]
    fn test_realtime_ineligible_keyword_and_ioc() {
        // Keyword full-text and the `ioc` retro-hunt term require full scans,
        // not a simple-column MV predicate.
        assert!(!is_realtime_eligible("malware"));
        assert!(!is_realtime_eligible("ioc"));
    }

    #[test]
    fn test_realtime_eligible_matches_ddl_acceptance() {
        // Lock-step invariant: if the shape gate says eligible, DDL generation
        // must succeed; if it says ineligible, DDL generation must fail.
        for query in ["src_ip=\"10.0.0.1\"", "dest_port=445"] {
            assert!(is_realtime_eligible(query));
            let mut rule = create_test_rule();
            rule.query = query.to_string();
            let generator = MaterializedViewGenerator::new(clickhouse::Client::default());
            assert!(
                generator.generate_view_ddl(&rule).is_ok(),
                "shape gate said eligible but DDL failed for {query:?}"
            );
        }
        for query in ["malware", "src_ip=\"10.0.0.1\" | stats count by user"] {
            assert!(!is_realtime_eligible(query));
            let mut rule = create_test_rule();
            rule.query = query.to_string();
            let generator = MaterializedViewGenerator::new(clickhouse::Client::default());
            assert!(
                generator.generate_view_ddl(&rule).is_err(),
                "shape gate said ineligible but DDL succeeded for {query:?}"
            );
        }
    }

    #[test]
    fn test_generate_view_name() {
        let rule = create_test_rule();
        let view_name = MaterializedViewGenerator::generate_view_name(&rule);
        assert_eq!(view_name, "mv_rt_detection_550e8400e29b41d4a716446655440000");
    }

    #[test]
    fn test_generate_view_ddl_shape() {
        let rule = create_test_rule();
        let generator = MaterializedViewGenerator::new(clickhouse::Client::default());
        let ddl = generator.generate_view_ddl(&rule).unwrap();
        assert!(ddl
            .contains("CREATE MATERIALIZED VIEW mv_rt_detection_550e8400e29b41d4a716446655440000"));
        assert!(ddl.contains("TO signals"));
        assert!(ddl.contains("src_ip AS risk_entity"));
        assert!(ddl.contains("75 AS risk_score"));
        assert!(ddl.contains("AND timestamp >= now() - INTERVAL 24 HOUR"));
        // No CLICKHOUSE_CLUSTER in tests → no ON CLUSTER clause (single-node DDL
        // is byte-identical). Audit D8.
        assert!(!ddl.contains("ON CLUSTER"));
    }

    /// NAN-1142: the real-time WHERE clause must be byte-for-byte identical to the
    /// canonical scheduled-path WHERE across a representative spread of rule shapes.
    /// Before the fix the MV path emitted case-sensitive / wildcard-literal /
    /// non-normalized SQL, so these rules silently failed to match in real-time mode.
    #[test]
    fn test_realtime_where_matches_canonical() {
        for q in [
            "process_name=\"Mimikatz\"",                          // case folding
            "process_name=/mimikatz/",                            // regex -> (?i)/iLike
            "command_line=\"*powershell*\"",                      // wildcard -> iLike
            "src_host=\"dc01\"",                                  // FQDN expansion
            "dest_ip=\"192.0.2.1\"",                              // IP equality
            "dest_port=443",                                      // numeric equality
            "user=\"alice\" AND action=\"login\"",               // AND
            "dest_ip=\"192.0.2.1\" OR dest_ip=\"198.51.100.1\"", // OR
            "NOT process_name=\"explorer.exe\"",                  // NOT
            "dest_ip IN (\"192.0.2.1\", \"198.51.100.1\")",       // IN-list
        ] {
            assert_where_matches_canonical(q);
        }
    }

    /// R2 (alias-shadows-column): a rule filtering a base column whose name
    /// collides with an output-projection alias (`severity`, `risk_score`,
    /// `rule_name`, `risk_entity`) must have its WHERE resolved against the TRUE
    /// base column — not the constant alias expression. The generated DDL
    /// isolates the filter inside the source subquery so ClickHouse cannot
    /// shadow the column (Code 53 class). Before the fix the flat SELECT placed
    /// `'high' AS severity` in the same scope as `WHERE lower(severity) = …`,
    /// collapsing the predicate to a constant that matched everything/nothing.
    #[test]
    fn test_r2_shadow_prone_filter_isolated_in_subquery() {
        for q in ["severity=\"high\"", "risk_score>50"] {
            let mut rule = create_test_rule();
            rule.query = q.to_string();
            let generator = MaterializedViewGenerator::new(clickhouse::Client::default());
            let ddl = generator
                .generate_view_ddl(&rule)
                .unwrap_or_else(|e| panic!("DDL generation failed for {q:?}: {e}"));

            // The canonical WHERE (referencing the real base column) is embedded
            // verbatim — the filter did not silently become a constant.
            let expected = canonical_where(q);
            assert!(
                ddl.contains(&format!("WHERE {expected}")),
                "WHERE drifted from canonical for {q}\n  canonical: {expected}\n  ddl:\n{ddl}"
            );

            // Structural isolation: the source subquery opens (`FROM (`) BEFORE
            // the WHERE, and the shadow-prone output alias is defined in the
            // outer projection, before the subquery. That separation is what
            // guarantees the WHERE binds the base column, not the alias.
            let sub_open = ddl.find("FROM (").expect("DDL must open a source subquery");
            let where_pos = ddl.find(" WHERE ").expect("DDL must have a WHERE");
            let sev_alias = ddl.find("AS severity").expect("severity output alias");
            assert!(
                sev_alias < sub_open && sub_open < where_pos,
                "filter not isolated from output aliases for {q}\n  ddl:\n{ddl}"
            );
        }
    }

    /// The R2 guard rejects a DDL whose WHERE has been hoisted into the outer
    /// projection scope (where the shadow-prone aliases live), and accepts the
    /// real generated shape where the WHERE sits inside the source subquery.
    #[test]
    fn test_r2_guard_rejects_collapsed_where_scope() {
        let collapsed = "SELECT 'x' AS severity FROM logs WHERE lower(severity)='high' \
                         FROM ( SELECT * FROM logs )";
        assert!(matches!(
            MaterializedViewGenerator::assert_filter_scope_isolated(collapsed),
            Err(MaterializedViewError::DdlGenerationError(_))
        ));

        let isolated =
            "SELECT 'x' AS severity FROM ( SELECT * FROM logs WHERE lower(severity)='high' )";
        assert!(MaterializedViewGenerator::assert_filter_scope_isolated(isolated).is_ok());
    }

    #[test]
    fn test_auto_detect_risk_entity_from_query() {
        let mut rule = create_test_rule();
        rule.risk_entity_field = None; // query is dest_ip=... -> auto-detect dest_ip
        let generator = MaterializedViewGenerator::new(clickhouse::Client::default());
        let ddl = generator.generate_view_ddl(&rule).unwrap();
        assert!(ddl.contains("dest_ip AS risk_entity"));
    }

    #[test]
    fn test_auto_detect_src_user() {
        let mut rule = create_test_rule();
        rule.query = "src_user=\"alice\"".to_string();
        rule.risk_entity_field = None;
        let generator = MaterializedViewGenerator::new(clickhouse::Client::default());
        let ddl = generator.generate_view_ddl(&rule).unwrap();
        assert!(ddl.contains("src_user AS risk_entity"));
    }

    #[test]
    fn test_auto_detect_empty_string_triggers_detection() {
        let mut rule = create_test_rule();
        rule.query = "src_user=\"alice\"".to_string();
        rule.risk_entity_field = Some(String::new()); // empty -> auto-detect
        let generator = MaterializedViewGenerator::new(clickhouse::Client::default());
        let ddl = generator.generate_view_ddl(&rule).unwrap();
        assert!(ddl.contains("src_user AS risk_entity"));
    }

    // --- real-time eligibility: unsupported shapes must still fall back to scheduled ---

    #[test]
    fn test_rejects_piped_commands() {
        let mut rule = create_test_rule();
        rule.query = "dest_ip=\"192.0.2.1\" | stats count by src_ip".to_string();
        let generator = MaterializedViewGenerator::new(clickhouse::Client::default());
        assert!(matches!(
            generator.generate_view_ddl(&rule),
            Err(MaterializedViewError::InvalidRule(_))
        ));
    }

    #[test]
    fn test_rejects_spans_metrics_dataset() {
        // NAN-1561: spans/metrics rules are scheduled-only; the MV path must
        // reject them before any DDL is built, even with a logs-shaped query.
        for ds in ["spans", "metrics", "traces", "metric"] {
            let mut rule = create_test_rule();
            rule.dataset = Some(ds.to_string());
            let generator = MaterializedViewGenerator::new(clickhouse::Client::default());
            assert!(
                matches!(
                    generator.generate_view_ddl(&rule),
                    Err(MaterializedViewError::InvalidRule(_))
                ),
                "dataset {ds} must be rejected for real-time"
            );
        }
    }

    #[test]
    fn test_allows_logs_dataset() {
        // An explicit "logs" dataset (or None) must NOT be rejected by the
        // NAN-1561 guard — a logs rule stays byte-identical.
        for ds in [Some("logs".to_string()), None] {
            let mut rule = create_test_rule();
            rule.dataset = ds.clone();
            let generator = MaterializedViewGenerator::new(clickhouse::Client::default());
            // Should pass the dataset guard (may fail later for other reasons,
            // but create_test_rule is a valid logs rule, so it succeeds).
            assert!(
                generator.generate_view_ddl(&rule).is_ok(),
                "dataset {ds:?} must be allowed for real-time"
            );
        }
    }

    #[test]
    fn test_rejects_keyword_search() {
        let mut rule = create_test_rule();
        rule.query = "malware".to_string();
        let generator = MaterializedViewGenerator::new(clickhouse::Client::default());
        assert!(matches!(
            generator.generate_view_ddl(&rule),
            Err(MaterializedViewError::InvalidRule(_))
        ));
    }

    #[test]
    fn test_rejects_nested_keyword_search() {
        // keyword buried inside AND must also reject — the pre-pass is recursive
        let mut rule = create_test_rule();
        rule.query = "dest_ip=\"192.0.2.1\" AND malware".to_string();
        let generator = MaterializedViewGenerator::new(clickhouse::Client::default());
        assert!(matches!(
            generator.generate_view_ddl(&rule),
            Err(MaterializedViewError::InvalidRule(_))
        ));
    }

    // --- DDL field-name validation (risk_entity injection guard) ---

    #[test]
    fn test_validate_ddl_field_name_accepts_udm_and_ext() {
        let udm = crate::schema::UdmProfile::new();
        assert!(validate_ddl_field_name("src_ip", &udm).is_ok());
        assert!(validate_ddl_field_name("process_name", &udm).is_ok());
        assert!(validate_ddl_field_name("ext.custom_field", &udm).is_ok());
    }

    #[test]
    fn test_validate_ddl_field_name_rejects_injection_and_unknown() {
        let udm = crate::schema::UdmProfile::new();
        assert!(validate_ddl_field_name("concat(currentDatabase(), ':', version())", &udm).is_err());
        assert!(validate_ddl_field_name("1; DROP TABLE logs--", &udm).is_err());
        assert!(validate_ddl_field_name("src_ip' OR '1'='1", &udm).is_err());
        assert!(validate_ddl_field_name("", &udm).is_err());
        assert!(validate_ddl_field_name("SRC_IP", &udm).is_err());
        assert!(validate_ddl_field_name("not_a_real_field", &udm).is_err());
        assert!(validate_ddl_field_name("ext.", &udm).is_err());
    }

    // --- OCSF Phase 5: profile-aware DDL validation + entity extraction ---

    #[test]
    fn test_validate_ddl_field_name_ocsf_accepts_dotted_rejects_injection() {
        let ocsf = crate::schema::OcsfProfile::new();
        // OCSF promoted dotted columns validate under the OCSF profile...
        assert!(
            validate_ddl_field_name("src_endpoint.ip", &ocsf).is_ok(),
            "OCSF dotted promoted column must validate"
        );
        assert!(validate_ddl_field_name("actor.process.cmd_line", &ocsf).is_ok());
        // ...but the strict identifier guard still rejects injection regardless
        // of the (now broader) field universe.
        assert!(
            validate_ddl_field_name("concat(currentDatabase(), ':', version())", &ocsf).is_err()
        );
        assert!(validate_ddl_field_name("src_endpoint.ip; DROP TABLE x--", &ocsf).is_err());
        assert!(validate_ddl_field_name("src_endpoint.ip' OR '1'='1", &ocsf).is_err());
        // And a dotted name that is NOT a known OCSF field is still rejected
        // (the allowlist did not become "any dotted identifier").
        assert!(validate_ddl_field_name("not.a.real.ocsf.field", &ocsf).is_err());
        // The dotted OCSF column is NOT a UDM field — it would have been rejected
        // by the old `UdmField`-only allowlist; the profile-derived universe is
        // what makes it valid in OCSF mode.
        let udm = crate::schema::UdmProfile::new();
        assert!(validate_ddl_field_name("src_endpoint.ip", &udm).is_err());
    }

    #[test]
    fn test_auto_detect_risk_entity_is_profile_driven() {
        use crate::schema::SchemaProfile;
        // UDM: a WHERE clause referencing src_user resolves to src_user.
        let udm_gen = MaterializedViewGenerator::new(clickhouse::Client::default());
        assert_eq!(
            udm_gen.auto_detect_risk_entity("lower(src_user) = lower('alice')"),
            "src_user"
        );
        // UDM default (no recognized field) is src_ip.
        assert_eq!(udm_gen.auto_detect_risk_entity("1 = 1"), "src_ip");

        // OCSF: the first entity-extraction entry (src_endpoint.ip) is the
        // default, and a clause referencing user.name resolves to it.
        let ocsf = std::sync::Arc::new(crate::schema::OcsfProfile::new());
        let ocsf_default = ocsf
            .entity_extraction_order()
            .first()
            .map(|(_r, f)| f.to_string());
        let ocsf_gen = MaterializedViewGenerator::new(clickhouse::Client::default())
            .with_profile(ocsf.clone());
        assert_eq!(
            ocsf_gen.auto_detect_risk_entity("1 = 1"),
            ocsf_default.unwrap()
        );
    }

    #[test]
    fn test_rejects_malicious_risk_entity_field() {
        let mut rule = create_test_rule();
        rule.risk_entity_field = Some("concat(currentDatabase(), ':', version())".to_string());
        let generator = MaterializedViewGenerator::new(clickhouse::Client::default());
        match generator.generate_view_ddl(&rule) {
            Err(MaterializedViewError::InvalidRule(msg)) => assert!(msg.contains("concat")),
            other => panic!("expected InvalidRule, got {other:?}"),
        }
    }
}

