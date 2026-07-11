// SPDX-License-Identifier: AGPL-3.0-or-later

//! MITRE ATT&CK repository for database operations

use crate::log_telemetry::repository::is_safe_source_type;
use crate::mitre::data_sources;
use crate::mitre::types::{
    CoverageLevel, CoverageSummary, CoverageUnit, CoveringRule, DataSource, DataSourceReadiness,
    MitreCoverageResponse, MitreSyncMetadata, MitreSyncState, MitreTactic, MitreTechnique,
    TacticCoverage, TechniqueCoverage, TelemetryReadinessSnapshot,
};
use crate::rule_repository::extract_source_types;
use sqlx::pool::PoolConnection;
use sqlx::{Connection, PgConnection, PgPool, Postgres};
use std::collections::{HashMap, HashSet};

/// Repository for MITRE ATT&CK data
pub struct MitreRepository {
    pool: PgPool,
}

impl MitreRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Acquire the dedicated session used to fence catalog synchronization.
    /// The connection is closed on drop so cancellation cannot return a
    /// session-level advisory lock to the pool.
    pub(crate) async fn try_acquire_sync_connection(
        &self,
        lock_id: i64,
    ) -> Result<Option<PoolConnection<Postgres>>, sqlx::Error> {
        let mut connection = self.pool.acquire().await?;
        connection.close_on_drop();
        let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
            .bind(lock_id)
            .fetch_one(&mut *connection)
            .await?;
        Ok(acquired.then_some(connection))
    }

    pub(crate) async fn catalog_is_current_on(
        connection: &mut PgConnection,
        release_version: &str,
        source_sha256: &str,
    ) -> Result<bool, sqlx::Error> {
        sqlx::query_scalar(
            r#"
            SELECT EXISTS (
                SELECT 1
                FROM mitre_sync_state state
                WHERE state.singleton = TRUE
                  AND state.status = 'succeeded'
                  AND state.release_version = $1
                  AND state.source_sha256 = $2
                  AND state.tactic_count = (SELECT COUNT(*)::integer FROM mitre_tactics)
                  AND state.technique_count = (
                      SELECT COUNT(*)::integer FROM mitre_techniques WHERE deprecated = FALSE
                  )
            )
            "#,
        )
        .bind(release_version)
        .bind(source_sha256)
        .fetch_one(connection)
        .await
    }

    pub(crate) async fn retry_allowed_on(
        connection: &mut PgConnection,
    ) -> Result<bool, sqlx::Error> {
        sqlx::query_scalar(
            r#"
            SELECT COALESCE(next_retry_at <= NOW(), TRUE)
            FROM mitre_sync_state
            WHERE singleton = TRUE
            "#,
        )
        .fetch_optional(connection)
        .await
        .map(|allowed| allowed.unwrap_or(true))
    }

    pub(crate) async fn mark_sync_started_on(
        connection: &mut PgConnection,
        release_version: &str,
        source_url: &str,
        source_sha256: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO mitre_sync_state (
                singleton, status, release_version, source_url, source_sha256,
                last_started_at, updated_at
            )
            VALUES (TRUE, 'syncing', $1, $2, $3, NOW(), NOW())
            ON CONFLICT (singleton) DO UPDATE SET
                status = 'syncing',
                release_version = EXCLUDED.release_version,
                source_url = EXCLUDED.source_url,
                source_sha256 = EXCLUDED.source_sha256,
                last_started_at = NOW(),
                updated_at = NOW()
            "#,
        )
        .bind(release_version)
        .bind(source_url)
        .bind(source_sha256)
        .execute(connection)
        .await?;
        Ok(())
    }

    pub(crate) async fn mark_sync_failed_on(
        connection: &mut PgConnection,
        error: &str,
    ) -> Result<(), sqlx::Error> {
        let failures: i32 = sqlx::query_scalar(
            "SELECT consecutive_failures FROM mitre_sync_state WHERE singleton = TRUE",
        )
        .fetch_optional(&mut *connection)
        .await?
        .unwrap_or(0_i32)
        .saturating_add(1);
        let exponent = (failures - 1).clamp(0, 6) as u32;
        let delay_seconds = (300_i64 * (1_i64 << exponent)).min(21_600);
        let error = error.chars().take(2_000).collect::<String>();

        sqlx::query(
            r#"
            UPDATE mitre_sync_state
            SET status = 'failed',
                last_completed_at = NOW(),
                last_error = $1,
                consecutive_failures = $2,
                next_retry_at = NOW() + make_interval(secs => $3),
                updated_at = NOW()
            WHERE singleton = TRUE
            "#,
        )
        .bind(error)
        .bind(failures)
        .bind(delay_seconds as f64)
        .execute(connection)
        .await?;
        Ok(())
    }

    /// Atomically reconcile the entire active catalog, tactic edges, successful
    /// sync history, and singleton status record.
    ///
    /// Detection-rule mapping reconciliation runs inside this same transaction,
    /// after the catalog is fully written but before the `succeeded` flip and
    /// the commit (NAN-1766 / D3). This closes the crash window where a node
    /// dying between the catalog commit and a separate reconcile pass would
    /// leave `mitre_sync_state = 'succeeded'` while now-invalid rule mappings
    /// stayed live until the next pin bump. Returns the number of rule mappings
    /// quarantined by that reconcile.
    pub(crate) async fn replace_catalog_on(
        connection: &mut PgConnection,
        tactics: &[MitreTactic],
        techniques: &[MitreTechnique],
        release_version: &str,
        source_url: &str,
        source_sha256: &str,
    ) -> Result<u64, sqlx::Error> {
        let mut tx = connection.begin().await?;

        for tactic in tactics {
            sqlx::query(
                r#"
                INSERT INTO mitre_tactics (id, name, short_name, description, url, updated_at)
                VALUES ($1, $2, $3, $4, $5, NOW())
                ON CONFLICT (id) DO UPDATE SET
                    name = EXCLUDED.name,
                    short_name = EXCLUDED.short_name,
                    description = EXCLUDED.description,
                    url = EXCLUDED.url,
                    updated_at = NOW()
                "#,
            )
            .bind(&tactic.id)
            .bind(&tactic.name)
            .bind(&tactic.short_name)
            .bind(&tactic.description)
            .bind(&tactic.url)
            .execute(&mut *tx)
            .await?;
        }

        // Parents are sorted before sub-techniques by the parser.
        for technique in techniques {
            sqlx::query(
                r#"
                INSERT INTO mitre_techniques (
                    id, name, description, url, is_subtechnique, parent_id,
                    deprecated, data_sources, updated_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, FALSE, $7, NOW())
                ON CONFLICT (id) DO UPDATE SET
                    name = EXCLUDED.name,
                    description = EXCLUDED.description,
                    url = EXCLUDED.url,
                    is_subtechnique = EXCLUDED.is_subtechnique,
                    parent_id = EXCLUDED.parent_id,
                    deprecated = FALSE,
                    data_sources = EXCLUDED.data_sources,
                    updated_at = NOW()
                "#,
            )
            .bind(&technique.id)
            .bind(&technique.name)
            .bind(&technique.description)
            .bind(&technique.url)
            .bind(technique.is_subtechnique)
            .bind(&technique.parent_id)
            .bind(&technique.data_sources)
            .execute(&mut *tx)
            .await?;
        }

        sqlx::query("DELETE FROM mitre_technique_tactics")
            .execute(&mut *tx)
            .await?;
        for technique in techniques {
            for tactic_id in &technique.tactic_ids {
                sqlx::query(
                    r#"
                    INSERT INTO mitre_technique_tactics (technique_id, tactic_id)
                    VALUES ($1, $2)
                    "#,
                )
                .bind(&technique.id)
                .bind(tactic_id)
                .execute(&mut *tx)
                .await?;
            }
        }

        let technique_ids: Vec<String> = techniques.iter().map(|item| item.id.clone()).collect();
        sqlx::query("DELETE FROM mitre_techniques WHERE NOT (id = ANY($1::varchar[]))")
            .bind(&technique_ids)
            .execute(&mut *tx)
            .await?;
        let tactic_ids: Vec<String> = tactics.iter().map(|item| item.id.clone()).collect();
        sqlx::query("DELETE FROM mitre_tactics WHERE NOT (id = ANY($1::varchar[]))")
            .bind(&tactic_ids)
            .execute(&mut *tx)
            .await?;

        sqlx::query(
            r#"
            INSERT INTO mitre_sync_metadata (last_sync_at, version, technique_count, tactic_count)
            VALUES (NOW(), $1, $2, $3)
            "#,
        )
        .bind(release_version)
        .bind(techniques.len() as i32)
        .bind(tactics.len() as i32)
        .execute(&mut *tx)
        .await?;

        // Reconcile existing detection-rule mappings against the freshly written
        // (but not yet committed) catalog and quarantine any that are no longer
        // canonical. Running it here — same transaction, before the `succeeded`
        // flip below — guarantees the state record and the reconcile land (or
        // roll back) atomically (NAN-1766 / D3). The catalog tables above are
        // fully populated within this transaction, so the function's own
        // empty-catalog guard never short-circuits here.
        let quarantined = sqlx::query_scalar::<_, i64>(
            "SELECT public.reconcile_detection_rule_mitre_mappings()",
        )
        .fetch_one(&mut *tx)
        .await?;

        sqlx::query(
            r#"
            UPDATE mitre_sync_state
            SET status = 'succeeded',
                release_version = $1,
                source_url = $2,
                source_sha256 = $3,
                tactic_count = $4,
                technique_count = $5,
                last_completed_at = NOW(),
                last_success_at = NOW(),
                last_error = NULL,
                consecutive_failures = 0,
                next_retry_at = NULL,
                updated_at = NOW()
            WHERE singleton = TRUE
            "#,
        )
        .bind(release_version)
        .bind(source_url)
        .bind(source_sha256)
        .bind(tactics.len() as i32)
        .bind(techniques.len() as i32)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(u64::try_from(quarantined).unwrap_or(0))
    }

    /// Get all tactics
    pub async fn get_tactics(&self) -> Result<Vec<MitreTactic>, sqlx::Error> {
        let rows = sqlx::query_as::<_, MitreTactic>(
            r#"
            SELECT id, name, short_name, description, url
            FROM mitre_tactics
            ORDER BY id
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    /// Get all techniques (non-deprecated)
    pub async fn get_techniques(&self) -> Result<Vec<MitreTechnique>, sqlx::Error> {
        let rows = sqlx::query_as::<_, TechniqueRow>(
            r#"
            SELECT
                t.id, t.name, t.description, t.url,
                t.is_subtechnique, t.parent_id, t.deprecated,
                COALESCE(t.data_sources, ARRAY[]::text[]) as data_sources,
                COALESCE(
                    array_agg(tt.tactic_id) FILTER (WHERE tt.tactic_id IS NOT NULL),
                    ARRAY[]::varchar[]
                ) as tactic_ids
            FROM mitre_techniques t
            LEFT JOIN mitre_technique_tactics tt ON t.id = tt.technique_id
            WHERE t.deprecated = false
            GROUP BY t.id, t.name, t.description, t.url, t.is_subtechnique, t.parent_id, t.deprecated, t.data_sources
            ORDER BY t.id
            "#
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|r| r.into()).collect())
    }

    /// Get techniques for a specific tactic
    pub async fn get_techniques_by_tactic(
        &self,
        tactic_id: &str,
    ) -> Result<Vec<MitreTechnique>, sqlx::Error> {
        let rows = sqlx::query_as::<_, TechniqueRow>(
            r#"
            SELECT
                t.id, t.name, t.description, t.url,
                t.is_subtechnique, t.parent_id, t.deprecated,
                COALESCE(t.data_sources, ARRAY[]::text[]) as data_sources,
                COALESCE(
                    array_agg(tt2.tactic_id) FILTER (WHERE tt2.tactic_id IS NOT NULL),
                    ARRAY[]::varchar[]
                ) as tactic_ids
            FROM mitre_techniques t
            INNER JOIN mitre_technique_tactics tt ON t.id = tt.technique_id
            LEFT JOIN mitre_technique_tactics tt2 ON t.id = tt2.technique_id
            WHERE tt.tactic_id = $1 AND t.deprecated = false
            GROUP BY t.id, t.name, t.description, t.url, t.is_subtechnique, t.parent_id, t.deprecated, t.data_sources
            ORDER BY t.id
            "#
        )
        .bind(tactic_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|r| r.into()).collect())
    }

    /// Get sync metadata
    pub async fn get_sync_metadata(&self) -> Result<Option<MitreSyncMetadata>, sqlx::Error> {
        let row = sqlx::query_as::<_, SyncMetadataRow>(
            r#"
            SELECT last_sync_at, version, technique_count, tactic_count
            FROM mitre_sync_metadata
            ORDER BY id DESC
            LIMIT 1
            "#,
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| r.into()))
    }

    pub async fn get_sync_state(&self) -> Result<Option<MitreSyncState>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT status, release_version, source_url, source_sha256,
                   tactic_count, technique_count, last_started_at,
                   last_completed_at, last_success_at, last_error,
                   consecutive_failures, next_retry_at
            FROM mitre_sync_state
            WHERE singleton = TRUE
            "#,
        )
        .fetch_optional(&self.pool)
        .await
    }

    /// Quarantine mappings that became invalid under the newly committed
    /// catalog. The SQL function is installed with the rule-mapping invariant
    /// so reconciliation and trigger validation share one database contract.
    pub async fn reconcile_rule_mappings(&self) -> Result<u64, sqlx::Error> {
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT public.reconcile_detection_rule_mitre_mappings()",
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(u64::try_from(count).unwrap_or(0))
    }

    /// Return source-type identities that the deployment is configured to
    /// ingest. This combines enabled/deployed parser claims with explicit
    /// routes on enabled/deployed source configurations.
    pub async fn configured_source_types(&self) -> Result<HashSet<String>, sqlx::Error> {
        let parser_query = sqlx::query_as::<_, (String, Option<Vec<String>>)>(
            r#"
            SELECT ls.name, ls.match_values
            FROM log_sources ls
            LEFT JOIN source_configurations dispatch
              ON dispatch.id = ls.dispatch_source_config_id
            WHERE ls.enabled = true
              AND ls.deployed = true
              AND ls.kind = 'log'
              AND (
                ls.dispatch_source_config_id IS NULL
                OR (dispatch.enabled = true AND dispatch.deployed = true)
              )
            "#,
        )
        .fetch_all(&self.pool);
        let route_query = sqlx::query_as::<_, (String,)>(
            r#"
            SELECT DISTINCT rr.target_source_type
            FROM source_configurations sc
            INNER JOIN routing_rules rr ON rr.source_configuration_id = sc.id
            WHERE sc.enabled = true
              AND sc.deployed = true
            "#,
        )
        .fetch_all(&self.pool);

        let (parser_rows, route_rows) = tokio::try_join!(parser_query, route_query)?;
        let mut configured = HashSet::new();

        for (name, match_values) in parser_rows {
            let identities = match match_values {
                Some(values) if !values.is_empty() => values,
                _ => vec![parser_source_identity(&name)],
            };
            for identity in identities {
                insert_configured_source_type(&mut configured, &identity);
            }
        }
        for (target_source_type,) in route_rows {
            insert_configured_source_type(&mut configured, &target_source_type);
        }

        Ok(configured)
    }

    /// Get MITRE coverage data - techniques with their covering rules
    /// Optionally filter by severity and mode
    pub async fn get_coverage(
        &self,
        severity_filter: Option<&[String]>,
        mode_filter: Option<&[String]>,
        telemetry: &TelemetryReadinessSnapshot,
    ) -> Result<MitreCoverageResponse, sqlx::Error> {
        // Get all tactics
        let tactics = self.get_tactics().await?;

        // Get all techniques with their tactic associations
        let techniques = self.get_techniques().await?;

        // Build the base rule filter query
        let mut rule_conditions = vec!["r.archived = false".to_string()];
        let mut bind_values: Vec<String> = vec![];

        if let Some(severities) = severity_filter {
            if !severities.is_empty() {
                let placeholders: Vec<String> = severities
                    .iter()
                    .enumerate()
                    .map(|(i, _)| format!("${}", i + 1))
                    .collect();
                rule_conditions.push(format!("r.severity IN ({})", placeholders.join(", ")));
                bind_values.extend(severities.iter().cloned());
            }
        }

        // Use explicit mode filter when provided, otherwise default to alerting/live
        if let Some(modes) = mode_filter {
            if !modes.is_empty() {
                let start_idx = bind_values.len() + 1;
                let placeholders: Vec<String> = modes
                    .iter()
                    .enumerate()
                    .map(|(i, _)| format!("${}", start_idx + i))
                    .collect();
                rule_conditions.push(format!("r.mode IN ({})", placeholders.join(", ")));
                bind_values.extend(modes.iter().cloned());
            }
        } else {
            rule_conditions.push("r.mode IN ('alerting', 'live')".to_string());
        }

        // Query detection rules with MITRE mappings.
        //
        // We pull `query` so we can extract the rule's `source_type` (the
        // parser identifier) — it's not stored as a discrete column.
        // `unnest` expands the mitre_techniques array so we get one row per
        // (rule, technique) edge.
        let query = format!(
            r#"
            SELECT
                r.id,
                r.name,
                r.severity,
                r.mode,
                r.query,
                unnest(r.mitre_techniques) as technique_id
            FROM detection_rules r
            WHERE {} AND r.mitre_techniques IS NOT NULL AND array_length(r.mitre_techniques, 1) > 0
            "#,
            rule_conditions.join(" AND ")
        );

        // Execute dynamic query with bind parameters
        let rule_technique_rows: Vec<RuleTechniqueRow> = {
            let mut q = sqlx::query_as(&query);
            for val in &bind_values {
                q = q.bind(val);
            }
            q.fetch_all(&self.pool).await?
        };

        // Cache extracted source_types per rule id — the same rule may map to
        // many techniques and we don't want to re-parse the nPL each time.
        let mut rule_sources_cache: HashMap<uuid::Uuid, Vec<String>> = HashMap::new();

        // Group rules by technique
        let mut rules_by_technique: HashMap<String, Vec<CoveringRule>> = HashMap::new();
        let mut unique_rules_with_mitre: HashSet<uuid::Uuid> = HashSet::new();

        for row in rule_technique_rows {
            unique_rules_with_mitre.insert(row.id);

            let sources = rule_sources_cache
                .entry(row.id)
                .or_insert_with(|| extract_source_types(&row.query));

            // The mockup's per-rule `source` is a single identifier — pick
            // the first extracted source_type. Empty string when the query
            // doesn't constrain a source type (e.g., a generic search).
            let source = sources.first().cloned().unwrap_or_default();

            rules_by_technique
                .entry(row.technique_id.clone())
                .or_default()
                .push(CoveringRule {
                    id: row.id,
                    name: row.name,
                    severity: row.severity,
                    mode: row.mode,
                    source,
                });
        }

        // Build technique coverage
        let technique_coverages: Vec<TechniqueCoverage> = techniques
            .iter()
            .map(|t| {
                let rules = rules_by_technique.get(&t.id).cloned().unwrap_or_default();
                let rule_count = rules.len() as i32;
                let data_sources = build_data_sources(&t.data_sources, telemetry);
                TechniqueCoverage {
                    technique_id: t.id.clone(),
                    technique_name: t.name.clone(),
                    is_subtechnique: t.is_subtechnique,
                    parent_id: t.parent_id.clone(),
                    tactic_ids: t.tactic_ids.clone(),
                    rule_count,
                    coverage_level: CoverageLevel::from_rule_count(rule_count),
                    rules,
                    data_sources,
                }
            })
            .collect();

        // Build tactic coverage summaries
        let tactic_coverages: Vec<TacticCoverage> = tactics
            .iter()
            .map(|tactic| {
                let tactic_techniques: Vec<&TechniqueCoverage> = technique_coverages
                    .iter()
                    .filter(|t| t.tactic_ids.contains(&tactic.id))
                    .collect();

                let (total, covered) = count_coverage_units(tactic_techniques);

                TacticCoverage {
                    tactic_id: tactic.id.clone(),
                    tactic_name: tactic.name.clone(),
                    short_name: tactic.short_name.clone(),
                    total_techniques: total,
                    covered_techniques: covered,
                }
            })
            .collect();

        // Calculate overall summary
        let (total_techniques, covered_techniques) =
            count_coverage_units(technique_coverages.iter());
        let coverage_percentage = if total_techniques > 0 {
            (covered_techniques as f64 / total_techniques as f64) * 100.0
        } else {
            0.0
        };

        let summary = CoverageSummary {
            coverage_unit: CoverageUnit::Technique,
            total_techniques,
            covered_techniques,
            coverage_percentage,
            total_rules_with_mitre: unique_rules_with_mitre.len() as i32,
        };

        Ok(MitreCoverageResponse {
            tactics: tactic_coverages,
            techniques: technique_coverages,
            summary,
        })
    }
}

/// Count catalog techniques as independent coverage units. A parent does not
/// confer coverage on any child, and a covered child does not cover its parent.
fn count_coverage_units<'a>(
    techniques: impl IntoIterator<Item = &'a TechniqueCoverage>,
) -> (i32, i32) {
    techniques
        .into_iter()
        .fold((0, 0), |(total, covered), technique| {
            (total + 1, covered + i32::from(technique.rule_count > 0))
        })
}

/// Row type for rule-technique mapping query
#[derive(sqlx::FromRow)]
struct RuleTechniqueRow {
    id: uuid::Uuid,
    name: String,
    severity: String,
    mode: String,
    /// nPL query text — used to extract `source_type=...` for
    /// `CoveringRule.source`; telemetry readiness never derives from rules.
    query: String,
    technique_id: String,
}

// Internal row types for query mapping
#[derive(sqlx::FromRow)]
struct TechniqueRow {
    id: String,
    name: String,
    description: Option<String>,
    url: Option<String>,
    is_subtechnique: Option<bool>,
    parent_id: Option<String>,
    deprecated: Option<bool>,
    tactic_ids: Vec<String>,
    data_sources: Vec<String>,
}

impl From<TechniqueRow> for MitreTechnique {
    fn from(r: TechniqueRow) -> Self {
        MitreTechnique {
            id: r.id,
            name: r.name,
            description: r.description,
            url: r.url,
            is_subtechnique: r.is_subtechnique.unwrap_or(false),
            parent_id: r.parent_id,
            tactic_ids: r.tactic_ids,
            deprecated: r.deprecated.unwrap_or(false),
            data_sources: r.data_sources,
        }
    }
}

/// Build the per-technique [`DataSource`] list returned by the coverage API.
///
/// Each MITRE label is mapped (via [`data_sources::nanosiem_sources_for`])
/// to nano source-type identifiers, then classified against configured
/// sources and recent ingestion evidence. Unknown labels stay visible with
/// unknown readiness rather than being treated as missing telemetry.
fn build_data_sources(
    mitre_labels: &[String],
    telemetry: &TelemetryReadinessSnapshot,
) -> Vec<DataSource> {
    mitre_labels
        .iter()
        .map(|label| {
            let mapped = data_sources::nanosiem_sources_for(label);
            let evidence = telemetry.classify(mapped);
            DataSource {
                id: data_sources::stable_id(label),
                name: label.clone(),
                mapping_known: !mapped.is_empty(),
                configured: evidence.configured,
                readiness: evidence.readiness,
                last_seen_at: evidence.last_seen_at,
                connected: evidence.readiness == DataSourceReadiness::Active,
            }
        })
        .collect()
}

fn insert_configured_source_type(configured: &mut HashSet<String>, candidate: &str) {
    let normalized = candidate.trim().to_ascii_lowercase();
    if normalized != "unknown" && is_safe_source_type(&normalized) {
        configured.insert(normalized);
    }
}

/// Parser routing falls back to a safe form of the parser name when no
/// explicit match values exist. Mirror that identity here so configuration
/// readiness agrees with the generated Vector route.
fn parser_source_identity(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}

#[derive(sqlx::FromRow)]
struct SyncMetadataRow {
    last_sync_at: chrono::DateTime<chrono::Utc>,
    version: Option<String>,
    technique_count: Option<i32>,
    tactic_count: Option<i32>,
}

impl From<SyncMetadataRow> for MitreSyncMetadata {
    fn from(r: SyncMetadataRow) -> Self {
        MitreSyncMetadata {
            last_sync_at: r.last_sync_at,
            version: r.version,
            technique_count: r.technique_count.unwrap_or(0),
            tactic_count: r.tactic_count.unwrap_or(0),
        }
    }
}

#[cfg(test)]
mod sync_integration_tests {
    use super::*;

    fn tactic(id: &str, name: &str) -> MitreTactic {
        MitreTactic {
            id: id.to_string(),
            name: name.to_string(),
            short_name: name.to_ascii_lowercase(),
            description: Some(format!("{name} description")),
            url: None,
        }
    }

    fn technique(id: &str, name: &str, tactic_id: &str) -> MitreTechnique {
        MitreTechnique {
            id: id.to_string(),
            name: name.to_string(),
            description: Some(format!("{name} description")),
            url: None,
            is_subtechnique: false,
            parent_id: None,
            tactic_ids: vec![tactic_id.to_string()],
            deprecated: false,
            data_sources: vec!["Process".to_string()],
        }
    }

    #[tokio::test]
    #[ignore = "requires migrated PostgreSQL"]
    async fn catalog_replace_is_locked_atomic_and_removes_absent_objects() {
        const TEST_LOCK: i64 = 0x4d49_5452_4554_4553;
        let url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://nanosiem:nanosiem@localhost:5432/nanosiem".to_string());
        let pool = PgPool::connect(&url)
            .await
            .expect("connect to test PostgreSQL");
        let repository = MitreRepository::new(pool.clone());

        let mut connection = repository
            .try_acquire_sync_connection(TEST_LOCK)
            .await
            .unwrap()
            .expect("first sync owns the lock");

        // The catalog replacement intentionally deletes objects absent from a
        // snapshot. Run that destructive proof in an isolated schema so an
        // ignored test can never replace a developer's real MITRE catalog.
        let schema = format!("mitre_sync_test_{}", uuid::Uuid::now_v7().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&mut *connection)
            .await
            .unwrap();
        sqlx::query(&format!("SET search_path TO {schema}"))
            .execute(&mut *connection)
            .await
            .unwrap();
        for migration in [
            include_str!("../../../migrations/postgres/013_mitre_attack_framework.sql"),
            include_str!("../../../migrations/postgres/164_mitre_technique_data_sources.sql"),
            include_str!("../../../migrations/postgres/226_mitre_sync_state.sql"),
        ] {
            sqlx::raw_sql(migration)
                .execute(&mut *connection)
                .await
                .unwrap();
        }

        assert!(repository
            .try_acquire_sync_connection(TEST_LOCK)
            .await
            .unwrap()
            .is_none());

        let initial_tactics = vec![tactic("TA9001", "Initial"), tactic("TA9002", "Revoked")];
        let initial_techniques = vec![
            technique("T9001", "Initial technique", "TA9001"),
            technique("T9002", "Revoked technique", "TA9002"),
        ];
        MitreRepository::mark_sync_started_on(
            &mut connection,
            "test-v1",
            "https://example.invalid/v1.json",
            &"a".repeat(64),
        )
        .await
        .unwrap();
        MitreRepository::replace_catalog_on(
            &mut connection,
            &initial_tactics,
            &initial_techniques,
            "test-v1",
            "https://example.invalid/v1.json",
            &"a".repeat(64),
        )
        .await
        .unwrap();

        let invalid_tactics = vec![
            tactic("TA9001", "Must roll back"),
            tactic("TACTIC-ID-TOO-LONG", "Invalid"),
        ];
        let sync_error = MitreRepository::replace_catalog_on(
            &mut connection,
            &invalid_tactics,
            &initial_techniques,
            "test-invalid",
            "https://example.invalid/invalid.json",
            &"b".repeat(64),
        )
        .await
        .expect_err("oversized tactic id must abort the snapshot");
        MitreRepository::mark_sync_failed_on(&mut connection, &sync_error.to_string())
            .await
            .unwrap();
        let preserved_name: String =
            sqlx::query_scalar("SELECT name FROM mitre_tactics WHERE id = 'TA9001'")
                .fetch_one(&mut *connection)
                .await
                .unwrap();
        assert_eq!(preserved_name, "Initial");
        let failure_state: (String, Option<String>, bool) = sqlx::query_as(
            "SELECT status, last_error, next_retry_at > NOW()
             FROM mitre_sync_state WHERE singleton = TRUE",
        )
        .fetch_one(&mut *connection)
        .await
        .unwrap();
        assert_eq!(failure_state.0, "failed");
        assert!(failure_state.1.is_some());
        assert!(failure_state.2);

        let upgraded_tactics = vec![tactic("TA9001", "Upgraded")];
        let upgraded_techniques = vec![technique("T9001", "Upgraded technique", "TA9001")];
        MitreRepository::replace_catalog_on(
            &mut connection,
            &upgraded_tactics,
            &upgraded_techniques,
            "test-v2",
            "https://example.invalid/v2.json",
            &"c".repeat(64),
        )
        .await
        .unwrap();

        let revoked_tactic_exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mitre_tactics WHERE id = 'TA9002')")
                .fetch_one(&mut *connection)
                .await
                .unwrap();
        let revoked_technique_exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mitre_techniques WHERE id = 'T9002')")
                .fetch_one(&mut *connection)
                .await
                .unwrap();
        assert!(!revoked_tactic_exists);
        assert!(!revoked_technique_exists);

        let state: (String, Option<String>, Option<i32>, Option<i32>) = sqlx::query_as(
            "SELECT status, release_version, tactic_count, technique_count
             FROM mitre_sync_state WHERE singleton = TRUE",
        )
        .fetch_one(&mut *connection)
        .await
        .unwrap();
        assert_eq!(
            state,
            (
                "succeeded".to_string(),
                Some("test-v2".to_string()),
                Some(1),
                Some(1)
            )
        );

        sqlx::query("SELECT pg_advisory_unlock($1)")
            .bind(TEST_LOCK)
            .execute(&mut *connection)
            .await
            .unwrap();
        sqlx::query("RESET search_path")
            .execute(&mut *connection)
            .await
            .unwrap();
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&mut *connection)
            .await
            .unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mitre::types::TELEMETRY_STALE_AFTER_MINUTES;
    use chrono::{TimeZone, Utc};

    const PROCESS_SOURCE: &str = "Process: Process Creation";

    fn observed_at() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 10, 12, 0, 0)
            .single()
            .expect("valid fixture timestamp")
    }

    fn configured(sources: &[&str]) -> HashSet<String> {
        sources.iter().map(|source| (*source).to_string()).collect()
    }

    fn process_data_source(snapshot: &TelemetryReadinessSnapshot) -> DataSource {
        build_data_sources(&[PROCESS_SOURCE.to_string()], snapshot)
            .into_iter()
            .next()
            .expect("one data source")
    }

    #[test]
    fn rule_reference_without_configuration_remains_unknown() {
        // A rule mentioning windows_sysmon does not enter the readiness
        // snapshot. Even observed events cannot make an unconfigured source
        // look connected.
        let last_seen = HashMap::from([("windows_sysmon".to_string(), observed_at())]);
        let snapshot =
            TelemetryReadinessSnapshot::observed(HashSet::new(), last_seen, observed_at());

        let source = process_data_source(&snapshot);
        assert!(!source.configured);
        assert!(source.mapping_known);
        assert_eq!(source.readiness, DataSourceReadiness::Unknown);
        assert_eq!(source.last_seen_at, None);
        assert!(!source.connected);
    }

    #[test]
    fn configured_idle_source_is_stale_without_fabricated_last_seen() {
        let snapshot = TelemetryReadinessSnapshot::observed(
            configured(&["windows_sysmon"]),
            HashMap::new(),
            observed_at(),
        );

        let source = process_data_source(&snapshot);
        assert!(source.configured);
        assert_eq!(source.readiness, DataSourceReadiness::Stale);
        assert_eq!(source.last_seen_at, None);
        assert!(!source.connected);
    }

    #[test]
    fn configured_source_with_recent_ingestion_is_active() {
        let last_seen = observed_at() - chrono::Duration::minutes(5);
        let snapshot = TelemetryReadinessSnapshot::observed(
            configured(&["windows_sysmon"]),
            HashMap::from([("windows_sysmon".to_string(), last_seen)]),
            observed_at(),
        );

        let source = process_data_source(&snapshot);
        assert_eq!(source.readiness, DataSourceReadiness::Active);
        assert_eq!(source.last_seen_at, Some(last_seen));
        assert!(source.connected);
    }

    #[test]
    fn configured_source_with_old_ingestion_is_stale() {
        let last_seen =
            observed_at() - chrono::Duration::minutes(TELEMETRY_STALE_AFTER_MINUTES + 1);
        let snapshot = TelemetryReadinessSnapshot::observed(
            configured(&["windows_sysmon"]),
            HashMap::from([("windows_sysmon".to_string(), last_seen)]),
            observed_at(),
        );

        let source = process_data_source(&snapshot);
        assert_eq!(source.readiness, DataSourceReadiness::Stale);
        assert_eq!(source.last_seen_at, Some(last_seen));
        assert!(!source.connected);
    }

    #[test]
    fn stale_cutoff_boundary_is_explicit_and_inclusive() {
        let at_cutoff = observed_at() - chrono::Duration::minutes(TELEMETRY_STALE_AFTER_MINUTES);
        let just_stale = at_cutoff - chrono::Duration::seconds(1);

        let active = TelemetryReadinessSnapshot::observed(
            configured(&["windows_sysmon"]),
            HashMap::from([("windows_sysmon".to_string(), at_cutoff)]),
            observed_at(),
        );
        let stale = TelemetryReadinessSnapshot::observed(
            configured(&["windows_sysmon"]),
            HashMap::from([("windows_sysmon".to_string(), just_stale)]),
            observed_at(),
        );

        assert_eq!(
            process_data_source(&active).readiness,
            DataSourceReadiness::Active
        );
        assert_eq!(
            process_data_source(&stale).readiness,
            DataSourceReadiness::Stale
        );
    }

    #[test]
    fn unavailable_ingestion_health_never_claims_stale_or_active() {
        let snapshot =
            TelemetryReadinessSnapshot::unavailable(configured(&["windows_sysmon"]), observed_at());

        let source = process_data_source(&snapshot);
        assert!(source.configured);
        assert_eq!(source.readiness, DataSourceReadiness::Unknown);
        assert_eq!(source.last_seen_at, None);
        assert!(!source.connected);
    }

    #[test]
    fn parser_identity_matches_vector_fallback_shape() {
        assert_eq!(parser_source_identity("AWS CloudTrail"), "aws_cloudtrail");
        assert_eq!(parser_source_identity("okta-system"), "okta_system");
    }

    #[test]
    fn configured_source_inventory_normalizes_and_rejects_sentinels() {
        let mut sources = HashSet::new();
        insert_configured_source_type(&mut sources, " AWS_CloudTrail ");
        insert_configured_source_type(&mut sources, "unknown");
        insert_configured_source_type(&mut sources, "${source_type}");

        assert_eq!(sources, configured(&["aws_cloudtrail"]));
    }

    #[test]
    fn unknown_attack_label_is_not_reported_as_an_unconfigured_known_source() {
        let source = build_data_sources(
            &["Unmapped Telemetry: Future Component".to_string()],
            &TelemetryReadinessSnapshot::observed(HashSet::new(), HashMap::new(), observed_at()),
        )
        .into_iter()
        .next()
        .expect("one data source");

        assert!(!source.mapping_known);
        assert!(!source.configured);
        assert_eq!(source.readiness, DataSourceReadiness::Unknown);
    }
}

#[cfg(test)]
mod coverage_unit_tests {
    use super::*;

    fn technique(
        id: &str,
        is_subtechnique: bool,
        parent_id: Option<&str>,
        rule_count: i32,
    ) -> TechniqueCoverage {
        TechniqueCoverage {
            technique_id: id.to_string(),
            technique_name: id.to_string(),
            is_subtechnique,
            parent_id: parent_id.map(str::to_string),
            tactic_ids: vec!["TA0002".to_string()],
            rule_count,
            coverage_level: CoverageLevel::from_rule_count(rule_count),
            rules: Vec::new(),
            data_sources: Vec::new(),
        }
    }

    #[test]
    fn covered_parent_does_not_cover_uncovered_child() {
        let techniques = [
            technique("T1059", false, None, 1),
            technique("T1059.001", true, Some("T1059"), 0),
        ];

        assert_eq!(count_coverage_units(&techniques), (2, 1));
    }

    #[test]
    fn coverage_unit_serializes_as_technique() {
        assert_eq!(
            serde_json::to_value(CoverageUnit::Technique).unwrap(),
            serde_json::json!("technique")
        );
    }
}
