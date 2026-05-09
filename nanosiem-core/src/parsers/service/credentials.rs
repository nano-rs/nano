// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cloud credential injection for parsers

use super::ParserService;
use super::ParserServiceError;
use crate::parsers::types::{Parser, SourceType};

impl ParserService {
    /// Inject decrypted credentials into parser source_config for cloud sources
    ///
    /// For aws_s3 and azure_blob source types with a credential_id,
    /// this fetches the decrypted credentials and adds them to source_config
    /// under the "_credentials" key for use by VectorConfigManager.
    pub(crate) async fn inject_credentials(
        &self,
        parser: &Parser,
    ) -> Result<Parser, ParserServiceError> {
        // Check if this is a cloud source type that needs credentials
        let source_type = SourceType::from_str(&parser.source_type);
        let needs_credentials = source_type
            .map(|st| st.requires_credentials())
            .unwrap_or(false);

        if !needs_credentials {
            return Ok(parser.clone());
        }

        // If there's no credential_id, return as-is (IAM role for S3, or error at runtime for Azure)
        let credential_id = match parser.credential_id {
            Some(id) => id,
            None => return Ok(parser.clone()),
        };

        // Fetch and decrypt credentials
        let credential_repo = self.credential_repository();
        let creds = credential_repo.get_decrypted(credential_id).await?;

        // Best-effort: stamp last_used_at so the UI can show recency. Telemetry
        // failures must never block a deploy, so we swallow the error.
        if let Err(err) = credential_repo.mark_used(credential_id).await {
            tracing::debug!(
                credential_id = %credential_id,
                error = %err,
                "credential mark_used failed (non-fatal)"
            );
        }

        // Clone parser and inject credentials into source_config
        let mut modified_parser = parser.clone();
        let mut source_config = parser.source_config.clone();

        if let Some(obj) = source_config.as_object_mut() {
            obj.insert("_credentials".to_string(), creds);
        }

        modified_parser.source_config = source_config;
        Ok(modified_parser)
    }

    /// Inject credentials for all parsers that need them
    pub(crate) async fn inject_credentials_for_all(
        &self,
        parsers: &[Parser],
    ) -> Result<Vec<Parser>, ParserServiceError> {
        let mut result = Vec::with_capacity(parsers.len());
        for parser in parsers {
            result.push(self.inject_credentials(parser).await?);
        }
        Ok(result)
    }
}
