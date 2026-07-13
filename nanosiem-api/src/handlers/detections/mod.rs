// SPDX-License-Identifier: AGPL-3.0-or-later

//! Detection rule endpoint handlers
//!
//! Split into focused submodules by domain:
//! - `types` — request/response types and query parameters
//! - `crud` — list, get, create, update, delete
//! - `lifecycle` — pause, resume, promote, demote
//! - `testing` — test rule, test query, format query, validate
//! - `import_export` — import and export rules
//! - `stats` — trigger, stats, today counts, matches

mod aggregates;
mod bulk;
mod crud;
mod dispositions;
mod import_export;
mod lifecycle;
mod predicates;
mod retro_hunt;
mod reviews;
mod stats;
mod testing;
pub mod types;

pub use aggregates::*;
pub use bulk::*;
pub use crud::*;
pub use dispositions::*;
pub use import_export::*;
pub use lifecycle::*;
pub use predicates::*;
pub use retro_hunt::*;
pub use reviews::*;
pub use stats::*;
pub use testing::*;
pub use types::*;

use crate::handlers::AuditExt;

// =============================================================================
// SHARED HELPERS
// =============================================================================

/// Strip comments from a detection query
///
/// Supports:
/// - Single-line comments: // comment
/// - Multi-line comments: /* comment */
///
/// Returns the query with comments removed and extra whitespace cleaned up.
pub(crate) fn strip_comments(query: &str) -> String {
    let mut result = String::new();
    let mut chars = query.chars().peekable();
    let mut in_string = false;
    let mut string_char = '"';

    while let Some(c) = chars.next() {
        // Track string state to avoid stripping inside strings
        if !in_string && (c == '"' || c == '\'') {
            in_string = true;
            string_char = c;
            result.push(c);
            continue;
        }

        if in_string {
            result.push(c);
            if c == string_char && result.chars().last() != Some('\\') {
                in_string = false;
            }
            continue;
        }

        // Check for comments
        if c == '/' {
            if let Some(&next) = chars.peek() {
                if next == '/' {
                    // Single-line comment - skip until newline
                    chars.next(); // consume the second /
                    while let Some(&ch) = chars.peek() {
                        if ch == '\n' {
                            break;
                        }
                        chars.next();
                    }
                    continue;
                } else if next == '*' {
                    // Multi-line comment - skip until */
                    chars.next(); // consume the *
                    while let Some(ch) = chars.next() {
                        if ch == '*' {
                            if let Some(&'/') = chars.peek() {
                                chars.next(); // consume the /
                                break;
                            }
                        }
                    }
                    continue;
                }
            }
        }

        result.push(c);
    }

    // Clean up empty lines (e.g. from stripped comments) but preserve intentional newlines
    result
        .lines()
        .map(|line| line.trim_end())
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

// =============================================================================
// OPENAPI DOCUMENTATION
// =============================================================================

/// OpenAPI documentation for detection endpoints
pub struct DetectionsApiDoc;

impl utoipa::OpenApi for DetectionsApiDoc {
    fn openapi() -> utoipa::openapi::OpenApi {
        use utoipa::OpenApi;

        #[derive(OpenApi)]
        #[openapi(
            paths(
                list_detections,
                get_detection,
                create_detection,
                update_detection,
                delete_detection,
                pause_detection,
                resume_detection,
                test_detection,
                test_query,
                promote_detection,
                demote_detection,
                import_detections,
                export_detections,
                trigger_detection,
                get_detection_stats,
                get_today_counts,
                get_detection_matches,
                format_query,
                validate_detection,
                bulk_update_rules,
                get_detection_health_summary,
                get_fleet_health,
                get_noisy_rules,
                mark_match_reviewed,
                unmark_match_reviewed,
                get_rule_disposition_stats,
                set_match_disposition,
                get_rule_predicates,
                // NAN-1791: auto retro-hunt rules
                create_retro_hunt,
                get_retro_hunt,
                update_retro_hunt,
                list_retro_hunt_runs,
                list_retro_hunt_feeds,
            ),
            components(schemas(
                TestRuleRequest,
                TimeRangeRequest,
                ImportRulesRequest,
                ImportResponse,
                DetectionResponse,
                DetectionMatchesResponse,
                DetectionMatch,
                FormatQueryRequest,
                FormatQueryResponse,
                ValidateDetectionRequest,
                ValidateDetectionResponse,
                BulkUpdateRulesRequest,
                BulkUpdateRulesResponse,
                BulkRuleFailure,
                DetectionHealthSummary,
                FleetHealthSummary,
                NoisyRule,
                NoisyRulesResponse,
                MarkReviewRequest,
                MatchReviewResponse,
                DispositionStatsResponse,
                SetDispositionRequest,
                MatchDispositionResponse,
                RulePredicatesResponse,
                Predicate,
                PredicateKind,
                PipeStage,
                // NAN-1791: auto retro-hunt rules
                nanosiem_core::models::retro_hunt::CreateRetroHuntRequest,
                nanosiem_core::models::retro_hunt::UpdateRetroHuntConfigRequest,
                nanosiem_core::models::retro_hunt::RetroHuntConfig,
                nanosiem_core::models::retro_hunt::RetroHuntState,
                nanosiem_core::models::retro_hunt::RetroHuntRuleView,
                nanosiem_core::models::retro_hunt::RetroHuntRun,
            ))
        )]
        struct ApiDoc;

        ApiDoc::openapi()
    }
}
