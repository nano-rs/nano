// SPDX-License-Identifier: AGPL-3.0-or-later

//! Helper functions for log sources

use super::LogSourceService;
use super::LogSourceServiceError;
use crate::parsers::Parser;

impl LogSourceService {
    /// NAN-928 / NAN-930: thin wrapper around the canonical
    /// `parsers::repository::resolve_parser_dispatch_routes`. Kept on
    /// `LogSourceService` so existing call sites in this module stay terse;
    /// the real implementation is shared with `ParserService` so both
    /// deploy paths produce identical Vector config for a given Parser slice
    /// (NAN-930 follow-up — the parser-service path was missing the resolve
    /// step and re-introduced the double-write topology at API startup).
    pub(super) async fn resolve_dispatch_route_names(
        &self,
        parsers: &mut [Parser],
    ) -> Result<(), LogSourceServiceError> {
        crate::parsers::resolve_parser_dispatch_routes(&self.pool, parsers)
            .await
            .map_err(|e| LogSourceServiceError::DeploymentFailed(e.to_string()))
    }

    /// The effective deployed parser set, with dispatch routes stamped —
    /// exactly what `ParserService` renders for publication. NAN-2304.
    ///
    /// Replaces `list_enabled_for_deploy()` + `log_source_to_parser`, a second
    /// hand-written LogSource→Parser mapping that could (and did) drift from
    /// the one publication uses. Disabled sources are now included: the
    /// generator needs them to prune their generated files, and it filters on
    /// `enabled` everywhere else.
    pub(super) async fn effective_deployed_parsers(
        &self,
    ) -> Result<Vec<Parser>, LogSourceServiceError> {
        let mut parsers = crate::parsers::list_effective_deployed_parsers(&self.pool)
            .await
            .map_err(|e| LogSourceServiceError::DeploymentFailed(e.to_string()))?;
        self.resolve_dispatch_route_names(&mut parsers).await?;
        Ok(parsers)
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

