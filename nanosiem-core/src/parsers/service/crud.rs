// SPDX-License-Identifier: AGPL-3.0-or-later

//! Parser CRUD operations (create, read, update, delete, enable, disable)

use uuid::Uuid;

use super::ParserService;
use super::ParserServiceError;
use crate::parsers::types::{NewParser, Parser, UpdateParser};

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

    /// Create a new parser
    pub async fn create(&self, new_parser: NewParser) -> Result<Parser, ParserServiceError> {
        // Validate source type
        let valid_types = crate::parsers::types::SourceType::all_types();
        if !valid_types.contains(&new_parser.source_type.as_str()) {
            return Err(ParserServiceError::InvalidSourceType(
                new_parser.source_type.clone(),
            ));
        }

        // Azure Blob requires credential_id (AWS S3 can use IAM roles)
        if new_parser.source_type == "azure_blob" && new_parser.credential_id.is_none() {
            return Err(ParserServiceError::InvalidSourceType(
                "azure_blob source type requires credential_id".to_string(),
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
        // Validate source type if provided
        if let Some(ref source_type) = update.source_type {
            let valid_types = crate::parsers::types::SourceType::all_types();
            if !valid_types.contains(&source_type.as_str()) {
                return Err(ParserServiceError::InvalidSourceType(source_type.clone()));
            }

            // Azure Blob requires credential_id
            if source_type == "azure_blob" && update.credential_id.is_none() {
                // Check if the existing parser has a credential_id
                let existing = self.get(id).await?;
                if existing.credential_id.is_none() {
                    return Err(ParserServiceError::InvalidSourceType(
                        "azure_blob source type requires credential_id".to_string(),
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
