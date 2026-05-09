// SPDX-License-Identifier: AGPL-3.0-or-later

//! MITRE ATT&CK repository for database operations

use crate::mitre::data_sources;
use crate::mitre::types::{
    CoverageLevel, CoverageSummary, CoveringRule, DataSource, MitreCoverageResponse,
    MitreSyncMetadata, MitreTactic, MitreTechnique, TacticCoverage, TechniqueCoverage,
};
use crate::rule_repository::extract_source_types;
use sqlx::PgPool;
use std::collections::{HashMap, HashSet};

/// Repository for MITRE ATT&CK data
pub struct MitreRepository {
    pool: PgPool,
}

impl MitreRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
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

    /// Insert or update a tactic
    pub async fn upsert_tactic(&self, tactic: &MitreTactic) -> Result<(), sqlx::Error> {
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
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Insert or update a technique
    pub async fn upsert_technique(&self, technique: &MitreTechnique) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO mitre_techniques (id, name, description, url, is_subtechnique, parent_id, deprecated, data_sources, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
            ON CONFLICT (id) DO UPDATE SET
                name = EXCLUDED.name,
                description = EXCLUDED.description,
                url = EXCLUDED.url,
                is_subtechnique = EXCLUDED.is_subtechnique,
                parent_id = EXCLUDED.parent_id,
                deprecated = EXCLUDED.deprecated,
                data_sources = EXCLUDED.data_sources,
                updated_at = NOW()
            "#
        )
        .bind(&technique.id)
        .bind(&technique.name)
        .bind(&technique.description)
        .bind(&technique.url)
        .bind(technique.is_subtechnique)
        .bind(&technique.parent_id)
        .bind(technique.deprecated)
        .bind(&technique.data_sources)
        .execute(&self.pool)
        .await?;

        // Update tactic associations
        sqlx::query("DELETE FROM mitre_technique_tactics WHERE technique_id = $1")
            .bind(&technique.id)
            .execute(&self.pool)
            .await?;

        for tactic_id in &technique.tactic_ids {
            sqlx::query(
                r#"
                INSERT INTO mitre_technique_tactics (technique_id, tactic_id)
                VALUES ($1, $2)
                ON CONFLICT DO NOTHING
                "#,
            )
            .bind(&technique.id)
            .bind(tactic_id)
            .execute(&self.pool)
            .await?;
        }

        Ok(())
    }

    /// Record sync metadata
    pub async fn record_sync(
        &self,
        version: Option<&str>,
        technique_count: i32,
        tactic_count: i32,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO mitre_sync_metadata (last_sync_at, version, technique_count, tactic_count)
            VALUES (NOW(), $1, $2, $3)
            "#,
        )
        .bind(version)
        .bind(technique_count)
        .bind(tactic_count)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Check if data exists
    pub async fn has_data(&self) -> Result<bool, sqlx::Error> {
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM mitre_tactics")
            .fetch_one(&self.pool)
            .await?;

        Ok(count.0 > 0)
    }

    /// Returns the set of nanosiem `source_type` identifiers that appear in
    /// at least one non-archived detection rule's nPL query. Used to derive
    /// `DataSource.connected` for the coverage API.
    ///
    /// This is a heuristic — "we have any rule referencing this telemetry"
    /// is the cheapest available proxy for "this telemetry is active in the
    /// deployment". A future improvement would consult a parser registry or
    /// recent ingestion stats.
    pub async fn connected_source_types(&self) -> Result<HashSet<String>, sqlx::Error> {
        let rows: Vec<(String,)> = sqlx::query_as(
            r#"
            SELECT query FROM detection_rules WHERE archived = false
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let mut set = HashSet::new();
        for (query,) in rows {
            for st in extract_source_types(&query) {
                set.insert(st);
            }
        }
        Ok(set)
    }

    /// Get MITRE coverage data - techniques with their covering rules
    /// Optionally filter by severity and mode
    pub async fn get_coverage(
        &self,
        severity_filter: Option<&[String]>,
        mode_filter: Option<&[String]>,
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

        // Build the set of "connected" source_types for the data-sources
        // marker. We deliberately scan ALL non-archived rules here (not just
        // the ones that pass the severity/mode filter, and not just the ones
        // with MITRE mappings) because `connected` means "is this telemetry
        // present in the deployment" — that's a property of the deployment,
        // not the current filter. This way, filtering coverage to e.g.
        // `mode=alerting` doesn't make a technique flip from `hot-gap` to
        // `gap` just because we have a `live` (but not yet alerting) rule
        // for the relevant source.
        let connected_source_types = self.connected_source_types().await?;

        // Build technique coverage
        let technique_coverages: Vec<TechniqueCoverage> = techniques
            .iter()
            .map(|t| {
                let rules = rules_by_technique.get(&t.id).cloned().unwrap_or_default();
                let rule_count = rules.len() as i32;
                let data_sources = build_data_sources(&t.data_sources, &connected_source_types);
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

                let total = tactic_techniques.len() as i32;
                let covered = tactic_techniques
                    .iter()
                    .filter(|t| t.rule_count > 0)
                    .count() as i32;

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
        let total_techniques = techniques.len() as i32;
        let covered_techniques = technique_coverages
            .iter()
            .filter(|t| t.rule_count > 0)
            .count() as i32;
        let coverage_percentage = if total_techniques > 0 {
            (covered_techniques as f64 / total_techniques as f64) * 100.0
        } else {
            0.0
        };

        let summary = CoverageSummary {
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

/// Row type for rule-technique mapping query
#[derive(sqlx::FromRow)]
struct RuleTechniqueRow {
    id: uuid::Uuid,
    name: String,
    severity: String,
    mode: String,
    /// nPL query text — used to extract `source_type=...` to populate
    /// `CoveringRule.source` and to compute connected source-types.
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
/// to a set of nanosiem source-type identifiers; if any of them appears in
/// `connected_source_types` (i.e. some detection rule references it), the
/// data source is marked `connected = true`.
///
/// MITRE-declared labels with no mapping yield `connected = false` rather
/// than being silently dropped — the frontend still wants to show what the
/// technique requires even if we can't tell whether we have it.
fn build_data_sources(
    mitre_labels: &[String],
    connected_source_types: &HashSet<String>,
) -> Vec<DataSource> {
    mitre_labels
        .iter()
        .map(|label| {
            let mapped = data_sources::nanosiem_sources_for(label);
            let connected = mapped
                .iter()
                .any(|st| connected_source_types.contains(*st));
            DataSource {
                id: data_sources::stable_id(label),
                name: label.clone(),
                connected,
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
