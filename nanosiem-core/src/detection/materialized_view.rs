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
use crate::udm::fields::UdmField;
use thiserror::Error;
use tracing::{debug, error, info};

/// Validate that a field name is safe for interpolation into DDL statements.
///
/// This prevents SQL injection via crafted `risk_entity_field` values (e.g.,
/// `concat(currentDatabase(), ':', version())`). The function checks:
/// 1. The field is a known UDM column name, OR
/// 2. The field is a valid `ext.*` extension field
///
/// As defense-in-depth, all fields must also match `^[a-z][a-z0-9_.]*$`.
fn validate_ddl_field_name(field: &str) -> Result<(), MaterializedViewError> {
    // Defense-in-depth: reject anything that doesn't match a strict identifier pattern.
    // This blocks parentheses, semicolons, quotes, spaces, SQL keywords used as
    // function calls, and any other unexpected characters.
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

    // Check if it's a known UDM field
    if field.parse::<UdmField>().is_ok() {
        return Ok(());
    }

    // Allow ext.* extension fields (e.g., ext.custom_field)
    if field.starts_with("ext.") && field.len() > 4 {
        return Ok(());
    }

    Err(MaterializedViewError::InvalidRule(format!(
        "Unknown field '{}' cannot be used in DDL. \
         Must be a valid UDM field name or an ext.* extension field.",
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
}

impl MaterializedViewGenerator {
    /// Create a new materialized view generator
    ///
    /// # Arguments
    /// * `clickhouse_client` - ClickHouse client for executing DDL statements
    ///
    /// Requirements: 4.1
    pub fn new(clickhouse_client: clickhouse::Client) -> Self {
        Self { clickhouse_client }
    }

    /// Generate materialized view name from rule ID
    ///
    /// Format: mv_rt_detection_{rule_id_without_hyphens}
    ///
    /// Example: mv_rt_detection_550e8400e29b41d4a716446655440000
    fn generate_view_name(rule: &DetectionRule) -> String {
        format!("mv_rt_detection_{}", rule.id.to_string().replace('-', ""))
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

        let ddl = format!("DROP VIEW IF EXISTS {}", view_name);

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
        validate_ddl_field_name(&risk_entity_field)?;

        // Calculate risk score (use rule's risk_score or default based on severity).
        // Severity defaults are sourced from `crate::detection::risk` so the MV path
        // and the scheduled path can never drift apart.
        let risk_score = rule
            .risk_score
            .unwrap_or_else(|| default_score_for_severity(rule.severity));

        // Generate view name
        let view_name = Self::generate_view_name(rule);

        // Generate DDL
        let ddl = format!(
            r#"CREATE MATERIALIZED VIEW {} TO signals AS
SELECT
    generateUUIDv4() AS id,
    timestamp,
    '{}' AS rule_id,
    '{}' AS rule_name,
    '{}' AS severity,
    {} AS risk_score,
    {} AS risk_entity,
    logs.id AS matched_log_id,
    toJSONString(map()) AS metadata,
    now64(6) AS _inserted_at
FROM logs
WHERE {}
  AND timestamp >= now() - INTERVAL 1 HOUR"#,
            view_name,
            rule.id,
            rule.name.replace('\'', "''"), // Escape single quotes
            format!("{:?}", rule.severity).to_lowercase(),
            risk_score,
            risk_entity_field,
            where_clause
        );

        Ok(ddl)
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
        // Priority order for risk entity fields (matching risk.rs)
        let priority_fields = [
            // IP addresses (highest priority)
            "src_ip",
            "dest_ip",
            "dvc_ip",
            "src_translated_ip",
            "dest_translated_ip",
            // Hostnames
            "src_host",
            "dest_host",
            "host",
            "hostname",
            "dest_nt_host",
            "src_nt_host",
            "dvc",
            // Users
            "src_user",
            "dest_user",
            "user",
            "src_user_name",
            "dest_user_name",
            // File hashes
            "file_hash",
            "process_hash",
            "service_hash",
            "service_dll_hash",
            "ssl_hash",
        ];

        // Check which fields are referenced in the query
        for field in &priority_fields {
            if where_clause.contains(field) {
                tracing::debug!(
                    "Auto-detected risk entity field: {} (found in query)",
                    field
                );
                return field.to_string();
            }
        }

        // Default to src_ip if no fields found
        tracing::debug!("Auto-detected risk entity field: src_ip (default)");
        "src_ip".to_string()
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
        let search_expr = match query {
            Query::Search(search_expr) => search_expr,
            Query::Piped { .. } => {
                return Err(MaterializedViewError::InvalidRule(
                    "Real-time rules cannot contain piped commands (stats, where, etc.)".to_string(),
                ))
            }
        };

        // Real-time eligibility is intentionally narrower than scheduled search:
        // keyword (full-text) and subsearch filters are not supported in a
        // materialized view and must fall back to scheduled mode. Reject them up
        // front with the historical messages...
        reject_unsupported_for_realtime(search_expr)?;

        // ...then delegate WHERE generation to the canonical generator so the
        // real-time WHERE clause stays byte-for-byte identical to the scheduled
        // path. This module previously carried its own SearchExpr->SQL codegen
        // that had drifted from canonical (no lower(), no field-name
        // normalization, no wildcard->iLike, case-sensitive regex, no hostname
        // FQDN expansion), so a rule could match in scheduled mode yet silently
        // never match in real-time mode (NAN-1142).
        ClickHouseSqlGenerator::new()
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
        assert!(ddl.contains("AND timestamp >= now() - INTERVAL 1 HOUR"));
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
        assert!(validate_ddl_field_name("src_ip").is_ok());
        assert!(validate_ddl_field_name("process_name").is_ok());
        assert!(validate_ddl_field_name("ext.custom_field").is_ok());
    }

    #[test]
    fn test_validate_ddl_field_name_rejects_injection_and_unknown() {
        assert!(validate_ddl_field_name("concat(currentDatabase(), ':', version())").is_err());
        assert!(validate_ddl_field_name("1; DROP TABLE logs--").is_err());
        assert!(validate_ddl_field_name("src_ip' OR '1'='1").is_err());
        assert!(validate_ddl_field_name("").is_err());
        assert!(validate_ddl_field_name("SRC_IP").is_err());
        assert!(validate_ddl_field_name("not_a_real_field").is_err());
        assert!(validate_ddl_field_name("ext.").is_err());
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

