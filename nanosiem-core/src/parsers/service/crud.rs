// SPDX-License-Identifier: AGPL-3.0-or-later

//! Parser CRUD operations (create, read, update, delete, enable, disable)

use uuid::Uuid;

use super::ParserService;
use super::ParserServiceError;
use crate::parsers::types::{NewParser, Parser, UpdateParser};
use crate::parsers::vector_config::VectorConfigManager;

/// NAN-1124: the `nano_` source_type prefix is reserved for nano-internal
/// enrichment routing (e.g. `nano_enrich`). The dynamic router emits a route
/// `<safe_name(name)> = '.source_type == "<safe_name(name)>"'` for each parser
/// (match_values is migration-seeded only, never settable through this API), so
/// a parser whose name maps to a `nano_*` route would pull enrichment records
/// out of `enrichment_router` into a log parser (double-write into the logs
/// table). Reserve the prefix at save time — mirrors the HEC reserved-key guard
/// (NAN-938). Returns the offending claimed source_type if reserved.
const RESERVED_SOURCE_TYPE_PREFIX: &str = "nano_";

fn reserved_route_claim(name: &str) -> Option<String> {
    let claim = VectorConfigManager::safe_name(name);
    claim
        .starts_with(RESERVED_SOURCE_TYPE_PREFIX)
        .then_some(claim)
}

/// NAN-2305: decide whether `name` would take a generated Vector identifier
/// that another log source already holds.
///
/// `log_sources.name` is UNIQUE, but that uniqueness is on the raw string,
/// and nothing the deploy writes uses the raw string. `<safe_name>.toml`,
/// `[transforms.<safe_name>_parse]` and the `source_router.<safe_name>` route
/// key all key off the lossy form, so `My Source` and `my-source` are two
/// accepted rows fighting over one filename and one route key. The deploy
/// loop writes both to `my_source.toml` (last wins) and its disabled branch
/// deletes that same path, so a disabled namesake can remove an enabled
/// source's config outright. Either way one log source silently stops being
/// ingested.
///
/// Pure so the decision is testable without a database; the caller supplies
/// the existing `(id, name)` rows and excludes the row being renamed.
fn identity_conflict(
    name: &str,
    existing: &[(Uuid, String)],
    exclude: Option<Uuid>,
) -> Option<String> {
    // NAN-2311: delegates to the shared rule so the parser and log-source
    // paths cannot drift apart — they guard the same generated namespace.
    crate::vector_naming::generated_identity_conflict("log source", name, existing, exclude)
}

impl ParserService {
    /// List all parsers
    pub async fn list(&self) -> Result<Vec<Parser>, ParserServiceError> {
        Ok(self.repository().list().await?)
    }

    /// List enabled parsers
    pub async fn list_enabled(&self) -> Result<Vec<Parser>, ParserServiceError> {
        Ok(self.repository().list_enabled().await?)
    }

    /// Get a parser by ID
    pub async fn get(&self, id: Uuid) -> Result<Parser, ParserServiceError> {
        Ok(self.repository().find_by_id(id).await?)
    }

    /// Get a parser by name
    pub async fn get_by_name(&self, name: &str) -> Result<Parser, ParserServiceError> {
        Ok(self.repository().find_by_name(name).await?)
    }

    /// NAN-2305: reject a name whose generated Vector identifier is taken.
    ///
    /// Racy on its own (list-then-write), exactly like the NAN-883
    /// single-instance check: migration 283's unique index on the normalized
    /// name is the backstop that closes the window between two concurrent
    /// creates. This runs first so the ordinary case gets an error naming the
    /// conflicting source instead of a bare unique-violation.
    async fn ensure_generated_identity_free(
        &self,
        name: &str,
        exclude: Option<Uuid>,
    ) -> Result<(), ParserServiceError> {
        let existing = self.repository().list_identities().await?;
        match identity_conflict(name, &existing, exclude) {
            Some(detail) => Err(ParserServiceError::NameCollision(detail)),
            None => Ok(()),
        }
    }

    /// Create a new parser
    pub async fn create(&self, new_parser: NewParser) -> Result<Parser, ParserServiceError> {
        // Validate source type
        let valid_types = crate::parsers::types::SourceType::all_types();
        if !valid_types.contains(&new_parser.source_type.as_str()) {
            return Err(ParserServiceError::InvalidSourceType(
                new_parser.source_type.clone(),
            ));
        }

        // NAN-1124: reserve the `nano_` source_type namespace for enrichment routing.
        if let Some(claim) = reserved_route_claim(&new_parser.name) {
            return Err(ParserServiceError::InvalidSourceType(format!(
                "parser name maps to the reserved source_type '{claim}': the 'nano_' prefix is reserved for nano-internal enrichment routing (NAN-1124). Rename the parser."
            )));
        }

        // NAN-2305: the DB's UNIQUE(name) accepts `my-source` next to
        // `My Source`; the generated namespace does not.
        self.ensure_generated_identity_free(&new_parser.name, None)
            .await?;

        if matches!(
            new_parser.source_type.as_str(),
            "kafka" | "aws_s3" | "aws_sqs" | "gcp_pubsub"
        ) && new_parser.dispatch_source_config_id.is_none()
        {
            return Err(ParserServiceError::InvalidSourceType(
                format!(
                    "{} parsers require dispatch_source_config_id; transport configuration belongs to source_configurations",
                    new_parser.source_type
                ),
            ));
        }

        // Basic VRL syntax validation
        let validation = self.validate_vrl(&new_parser.parser_vrl);
        if !validation.valid {
            return Err(ParserServiceError::InvalidVrl(
                validation.error.unwrap_or_default(),
            ));
        }

        // Validate parser fields against UDM schema
        // This logs warnings for unmapped fields but doesn't fail
        let field_validation = self.validate_parser_fields(&new_parser.parser_vrl);
        if !field_validation.warnings.is_empty() {
            tracing::info!(
                "Parser '{}' field validation warnings: {:?}",
                new_parser.name,
                field_validation.warnings
            );
        }

        let parser = self.repository().create(&new_parser).await?;

        // Mark as validated and enabled since VRL passed validation
        self.repository()
            .set_validation_status(parser.id, true, None)
            .await?;
        self.repository().enable(parser.id).await?;

        self.get(parser.id).await
    }

    /// Update a parser
    pub async fn update(
        &self,
        id: Uuid,
        update: UpdateParser,
    ) -> Result<Parser, ParserServiceError> {
        // NAN-1124: reserve the `nano_` source_type namespace (a rename to a
        // nano_* name would otherwise claim the enrichment route).
        if let Some(ref name) = update.name {
            if let Some(claim) = reserved_route_claim(name) {
                return Err(ParserServiceError::InvalidSourceType(format!(
                    "parser name maps to the reserved source_type '{claim}': the 'nano_' prefix is reserved for nano-internal enrichment routing (NAN-1124). Rename the parser."
                )));
            }

            // NAN-2305: a rename into another source's generated identifier is
            // the same collision as a create, and the rename path is the more
            // likely one — the operator is editing an existing source and has
            // no reason to suspect the new name overlaps. `id` is excluded so
            // a rename that keeps the same stem still succeeds.
            self.ensure_generated_identity_free(name, Some(id)).await?;
        }

        // Validate source type if provided
        if let Some(ref source_type) = update.source_type {
            let valid_types = crate::parsers::types::SourceType::all_types();
            if !valid_types.contains(&source_type.as_str()) {
                return Err(ParserServiceError::InvalidSourceType(source_type.clone()));
            }

            if matches!(source_type.as_str(), "kafka" | "aws_s3" | "aws_sqs" | "gcp_pubsub")
                && update.dispatch_source_config_id.is_none()
            {
                let existing = self.get(id).await?;
                if existing.dispatch_source_config_id.is_none() {
                    return Err(ParserServiceError::InvalidSourceType(
                        format!(
                            "{source_type} parsers require dispatch_source_config_id; transport configuration belongs to source_configurations"
                        ),
                    ));
                }
            }
        }

        // Validate VRL if provided
        if let Some(ref vrl) = update.parser_vrl {
            let validation = self.validate_vrl(vrl);
            if !validation.valid {
                return Err(ParserServiceError::InvalidVrl(
                    validation.error.unwrap_or_default(),
                ));
            }

            // Validate parser fields against UDM schema
            // This logs warnings for unmapped fields but doesn't fail
            let field_validation = self.validate_parser_fields(vrl);
            if !field_validation.warnings.is_empty() {
                tracing::info!(
                    "Parser update field validation warnings: {:?}",
                    field_validation.warnings
                );
            }
        }

        let parser = self.repository().update(id, &update).await?;

        // Re-validate and set status since the repo resets validated=false on any update
        // We already validated VRL above if it was provided, so just set the status
        self.repository()
            .set_validation_status(parser.id, true, None)
            .await?;

        self.get(parser.id).await
    }

    /// Delete a parser
    ///
    /// This removes the parser from the database and cleans up the Vector config files.
    /// The combiner and router configs are also updated to remove references to the deleted parser.
    pub async fn delete(&self, id: Uuid) -> Result<(), ParserServiceError> {
        // Get parser info before deleting (for cleanup)
        let parser = self.repository().find_by_id(id).await?;
        let parser_name = parser.name.clone();

        // Delete from database
        self.repository().delete(id).await?;

        // Clean up the config file for this parser
        if let Err(e) = self.vector_config.remove_parser_config(&parser_name).await {
            tracing::warn!(
                "Failed to remove parser config file for '{}': {}",
                parser_name,
                e
            );
        }

        // Redeploy to update combiner and router (removes references to deleted parser)
        if let Err(e) = self.deploy_to_vector().await {
            tracing::warn!(
                "Failed to redeploy after deleting parser '{}': {}",
                parser_name,
                e
            );
        }

        tracing::info!("Deleted parser '{}' ({})", parser_name, id);
        Ok(())
    }

    /// Enable a parser (must be validated first)
    pub async fn enable(&self, id: Uuid) -> Result<Parser, ParserServiceError> {
        let parser = self.get(id).await?;
        if !parser.validated {
            return Err(ParserServiceError::NotValidated);
        }
        let result = self.repository().enable(id).await?;

        // Deploy updated config to Vector
        if let Err(e) = self.deploy_to_vector().await {
            tracing::warn!("Failed to deploy parser config to Vector: {}", e);
        }

        Ok(result)
    }

    /// Disable a parser
    pub async fn disable(&self, id: Uuid) -> Result<Parser, ParserServiceError> {
        let result = self.repository().disable(id).await?;

        // Deploy updated config to Vector
        if let Err(e) = self.deploy_to_vector().await {
            tracing::warn!("Failed to deploy parser config to Vector: {}", e);
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests;
