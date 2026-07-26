// SPDX-License-Identifier: AGPL-3.0-or-later

//! Helper functions for log sources

use super::LogSourceService;
use super::LogSourceServiceError;
use crate::log_sources::types::LogSource;
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
        parser_vrl: ls.parser_vrl,
        output_fields: ls.output_fields,
        feed_id: None, // No longer used
        // NAN-928: carry the dispatch source-config binding through to the
        // generator so kafka/aws_s3/gcp_pubsub branches can emit a filter on
        // the source-config's `*_route` instead of a parser-owned source.
        dispatch_source_config_id: ls.dispatch_source_config_id,
        // Resolved at deploy time by `resolve_dispatch_route_names` — leave
        // None here; only the deploy entry-points have the pool needed to
        // look up the source-config's safe_name.
        dispatch_route_name: None,
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
        // NAN-1149: carry the enrichment-parser flavor through so an
        // enrichment source published via LogSourceService::deploy stages into
        // the push enrichment lane (write_enrichment_config) instead of being
        // misrouted as a log parser. For ordinary log sources these are the
        // schema defaults (kind="log", rest None) — behaviour-preserving.
        kind: ls.kind,
        enrich_kind: ls.enrich_kind,
        enrich_source: ls.enrich_source,
        target_table: ls.target_table,
        normalize_vrl: ls.normalize_vrl,
        extension_vrl: ls.extension_vrl,
        extension_enabled: ls.extension_enabled,
        created_at: ls.created_at,
        updated_at: ls.updated_at,
    }
}
