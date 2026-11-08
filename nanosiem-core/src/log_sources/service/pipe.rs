// SPDX-License-Identifier: AGPL-3.0-or-later

//! Nano Pipe source helpers (NAN-4919): the identities a pipeline workspace
//! needs for one log source, and its preview samples from ClickHouse.

use super::{LogSourceService, LogSourceServiceError};
use crate::log_sources::types::LogSource;

/// Most samples one request may load.
pub const MAX_PIPE_SAMPLES: usize = 100;

/// The `source_type` a source's events carry in ClickHouse (and in the
/// caller's source scope): a routed source writes its safe name, every other
/// transport its declared type (mirrors `parser_config::generate_output_transform`).
pub fn pipe_route_key(source: &LogSource) -> String {
    if source.source_type == "routed" {
        crate::vector_naming::safe_name(&source.name)
    } else {
        source.source_type.clone()
    }
}

/// The Vector component whose INPUT is the source's pipeline input: the
/// `_parse` slot, or the extension when the source is extension-only.
pub fn pipe_tap_component(source: &LogSource) -> String {
    let safe = crate::vector_naming::safe_name(&source.name);
    let stub = source.parser_vrl.trim().is_empty()
        && source.extension_enabled
        && source
            .extension_vrl
            .as_deref()
            .is_some_and(|ext| !ext.trim().is_empty());
    if stub {
        format!("{safe}_extension")
    } else {
        format!("{safe}_parse")
    }
}

impl LogSourceService {
    /// Recent stored events of `source` as preview inputs (`{"message": …}`),
    /// newest first, under the caller's source scope.
    pub async fn pipe_recent_events(
        &self,
        source: &LogSource,
        limit: usize,
        scope: &crate::auth::ScopeSet,
    ) -> Result<Vec<serde_json::Value>, LogSourceServiceError> {
        let rows = self
            .fetch_recent_messages(
                &pipe_route_key(source),
                limit.clamp(1, MAX_PIPE_SAMPLES),
                scope,
            )
            .await?;
        Ok(rows
            .into_iter()
            .map(|message| serde_json::json!({ "message": message }))
            .collect())
    }
}
