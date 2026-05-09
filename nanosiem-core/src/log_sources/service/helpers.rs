// SPDX-License-Identifier: AGPL-3.0-or-later

//! Helper functions and credential injection for log sources

use super::LogSourceService;
use super::LogSourceServiceError;
use crate::log_sources::types::{LogSource, SourceType};
use crate::parsers::Parser;

impl LogSourceService {
    /// Inject credentials for cloud sources
    pub(super) async fn inject_credentials(
        &self,
        log_source: &LogSource,
    ) -> Result<LogSource, LogSourceServiceError> {
        let source_type = SourceType::from_str(&log_source.source_type);
        let needs_credentials = source_type
            .map(|st| st.requires_credentials())
            .unwrap_or(false);

        if !needs_credentials {
            return Ok(log_source.clone());
        }

        let credential_id = match log_source.credential_id {
            Some(id) => id,
            None => return Ok(log_source.clone()),
        };

        let creds = self
            .credential_repository()
            .get_decrypted(credential_id)
            .await?;

        let mut modified = log_source.clone();
        let mut source_config = log_source.source_config.clone();

        if let Some(obj) = source_config.as_object_mut() {
            obj.insert("_credentials".to_string(), creds);
        }

        modified.source_config = source_config;
        Ok(modified)
    }

    /// Inject credentials for all log sources
    pub(super) async fn inject_credentials_for_all(
        &self,
        log_sources: &[LogSource],
    ) -> Result<Vec<LogSource>, LogSourceServiceError> {
        let mut result = Vec::with_capacity(log_sources.len());
        for ls in log_sources {
            result.push(self.inject_credentials(ls).await?);
        }
        Ok(result)
    }
}

// ============================================================================
// Free Functions
// ============================================================================

pub(super) fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

/// Convert LogSource to Parser for VectorConfigManager compatibility
pub(super) fn log_source_to_parser(ls: LogSource) -> Parser {
    Parser {
        id: ls.id,
        name: ls.name,
        description: ls.description,
        source_type: ls.source_type,
        source_config: ls.source_config,
        parser_vrl: ls.parser_vrl,
        output_fields: ls.output_fields,
        feed_id: None, // No longer used
        credential_id: ls.credential_id,
        namespace: ls.namespace,
        enabled: ls.enabled,
        validated: ls.validated,
        validation_error: ls.validation_error,
        timezone: ls.timezone,
        match_values: ls.match_values,
        sampling_ratio: ls.sampling_ratio,
        sampling_exclude_condition: ls.sampling_exclude_condition,
        category: ls.category,
        vendor: ls.vendor,
        product: ls.product,
        created_at: ls.created_at,
        updated_at: ls.updated_at,
    }
}
