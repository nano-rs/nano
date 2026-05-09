// SPDX-License-Identifier: AGPL-3.0-or-later

//! Parser library management

use uuid::Uuid;

use super::ParserService;
use super::ParserServiceError;
use crate::parsers::types::{DeploymentResult, NewParser, ParserLibraryEntry};

impl ParserService {
    /// Get all library parsers, optionally filtered by category
    ///
    /// Requirements: 10.2
    pub async fn get_library_parsers(
        &self,
        category: Option<&str>,
    ) -> Result<Vec<ParserLibraryEntry>, ParserServiceError> {
        Ok(self
            .library_repository()
            .get_library_parsers(category)
            .await?)
    }

    /// Get a library parser by ID
    ///
    /// Requirements: 10.2
    pub async fn get_library_parser(
        &self,
        id: Uuid,
    ) -> Result<ParserLibraryEntry, ParserServiceError> {
        Ok(self
            .library_repository()
            .get_library_parser_by_id(id)
            .await?)
    }

    /// Deploy a library parser
    ///
    /// This creates a new parser from a library entry and deploys it.
    /// If the user already has a parser with the same source_type, it creates
    /// a user copy with a unique name.
    ///
    /// Requirements: 10.2, 10.5
    pub async fn deploy_library_parser(
        &self,
        library_id: Uuid,
    ) -> Result<DeploymentResult, ParserServiceError> {
        // Get the library parser
        let library_entry = self
            .library_repository()
            .get_library_parser_by_id(library_id)
            .await?;

        tracing::info!(
            "Deploying library parser '{}' ({})",
            library_entry.display_name,
            library_id
        );

        // Check if a parser with this source_type already exists
        let existing_parsers = self.list().await?;
        let existing_with_source_type = existing_parsers
            .iter()
            .find(|p| p.source_type == library_entry.source_type);

        // Generate a unique name for the parser
        let parser_name = if existing_with_source_type.is_some() {
            // Create a user copy with a unique name
            let base_name = format!("{}_custom", library_entry.name);
            let mut name = base_name.clone();
            let mut counter = 1;
            while existing_parsers.iter().any(|p| p.name == name) {
                name = format!("{}_{}", base_name, counter);
                counter += 1;
            }
            name
        } else {
            library_entry.name.clone()
        };

        // Create the parser from the library entry
        let new_parser = NewParser {
            name: parser_name.clone(),
            description: library_entry.description.clone(),
            source_type: library_entry.source_type.clone(),
            source_config: serde_json::json!({
                "address": "0.0.0.0:8080"
            }),
            parser_vrl: library_entry.parser_vrl.clone(),
            output_fields: Some(library_entry.field_mappings.clone()),
            feed_id: None,
            credential_id: None,
        };

        // Create the parser
        let parser = self.create(new_parser).await?;

        // Deploy the parser with full validation
        self.deploy_parser(parser.id).await
    }
}
