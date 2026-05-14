// SPDX-License-Identifier: AGPL-3.0-or-later

//! Query processing utilities for command extraction and manipulation

pub mod auto_sort;
pub mod command_extraction;
pub mod query_manipulation;

// Re-export commonly used items
pub use command_extraction::{
    classify_query_cost, detect_oom_risk, extract_ai_command, extract_asset_command,
    extract_asset_identifier_from_query, extract_base_query, extract_cloud_command,
    extract_inputlookup_commands, extract_lateral_command, extract_lookup_commands,
    extract_post_ai_commands, extract_post_inputlookup_commands, extract_post_lateral_commands,
    extract_funnel_command, extract_post_prevalence_commands, extract_prevalence_commands,
    extract_tree_command, has_aggregation_before_prevalence,
    has_only_simple_post_prevalence_commands, query_has_aggregation,
    validate_panel_query_commands, validate_panel_query_unscoped_prevalence, AiCommandInfo,
    AssetCommandInfo, CloudCommandInfo, FunnelCommandInfo, InputLookupCommandInfo,
    LateralCommandInfo, LookupCommandInfo, OomRisk, PanelBlockedCommand, PrevalenceCommandInfo,
    TreeCommandInfo, FUNNEL_DROPPER_FIELDS, HEAVY_TIME_RANGE_DAYS,
};
pub use auto_sort::{apply_auto_sort, auto_sort_warning, AutoSortDecision};
pub use query_manipulation::{
    enforce_non_audit_query, enforce_source_type_exclusion, strip_ai_and_after,
    strip_inputlookup_and_after, strip_lateral_and_after, strip_post_prevalence_commands,
    strip_prevalence_and_after,
};
