// SPDX-License-Identifier: AGPL-3.0-or-later

//! Case entity operations: add/update entities, grouped retrieval, enrichment

use uuid::Uuid;

use super::{
    CaseEntity, CaseRepository, CaseRepositoryError, EntityTypeSummary, NewCaseEntity,
    UpdateEntityEnrichment,
};

impl CaseRepository {
    // ==================== CASE ENTITIES ====================

    /// Add or update an entity in a case
    pub async fn add_or_update_entity(
        &self,
        entity: &NewCaseEntity,
    ) -> Result<CaseEntity, CaseRepositoryError> {
        let entity_type_str = entity.entity_type.to_string();

        let result = sqlx::query_as::<_, CaseEntity>(
            r#"
            INSERT INTO case_entities (case_id, entity_type, entity_value, is_primary)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (case_id, entity_type, entity_value) DO UPDATE SET
                occurrence_count = case_entities.occurrence_count + 1,
                last_seen_at = NOW()
            RETURNING *
            "#,
        )
        .bind(entity.case_id)
        .bind(&entity_type_str)
        .bind(&entity.entity_value)
        .bind(entity.is_primary)
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }

    /// Get entities for a case grouped by type
    pub async fn get_entities_grouped(
        &self,
        case_id: Uuid,
    ) -> Result<Vec<EntityTypeSummary>, CaseRepositoryError> {
        let entities = sqlx::query_as::<_, CaseEntity>(
            r#"
            SELECT * FROM case_entities
            WHERE case_id = $1
            ORDER BY is_primary DESC, occurrence_count DESC, entity_value
            "#,
        )
        .bind(case_id)
        .fetch_all(&self.pool)
        .await?;

        // Group by entity type
        let mut grouped: std::collections::HashMap<String, Vec<CaseEntity>> =
            std::collections::HashMap::new();
        for entity in entities {
            grouped
                .entry(entity.entity_type.clone())
                .or_default()
                .push(entity);
        }

        let summaries = grouped
            .into_iter()
            .map(|(entity_type, entities)| EntityTypeSummary {
                count: entities.len() as i64,
                entity_type,
                entities,
            })
            .collect();

        Ok(summaries)
    }

    /// Update entity enrichment data
    pub async fn update_entity_enrichment(
        &self,
        entity_id: Uuid,
        enrichment: &UpdateEntityEnrichment,
    ) -> Result<CaseEntity, CaseRepositoryError> {
        let result = sqlx::query_as::<_, CaseEntity>(
            r#"
            UPDATE case_entities SET
                risk_score = COALESCE($2, risk_score),
                enrichment_data = COALESCE($3, enrichment_data),
                enrichment_updated_at = NOW()
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(entity_id)
        .bind(enrichment.risk_score)
        .bind(&enrichment.enrichment_data)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(CaseRepositoryError::EntityNotFound(entity_id))?;

        Ok(result)
    }
}
