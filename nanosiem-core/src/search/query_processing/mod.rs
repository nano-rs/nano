// SPDX-License-Identifier: AGPL-3.0-or-later

//! Query processing utilities for command extraction and manipulation

pub mod auto_sort;
pub mod command_extraction;
pub mod detection_sources;
pub mod panel_variables;
pub mod query_manipulation;

// Re-export commonly used items
pub use panel_variables::substitute_panel_variables;
pub use detection_sources::{
    analyze_detection_sources, pin_detection_query, DetectionShapeError, DetectionSourcePlan,
    PinnedDetectionQuery, MAX_DETECTION_NESTED_SCANS, MAX_DETECTION_RULE_SOURCES,
};
pub use auto_sort::{apply_auto_sort, auto_sort_warning, AutoSortDecision};
pub use command_extraction::{
    check_prevalence_pushdown_eligible, classify_query_cost, detect_oom_risk, extract_ai_command,
    extract_asset_command, extract_asset_identifier_from_query, extract_base_query,
    extract_baseline_command, extract_cloud_command, extract_funnel_command,
    extract_inputlookup_commands, extract_lake_lateral_identifier_from_query,
    extract_lateral_command, extract_lookup_commands, extract_post_ai_commands,
    extract_post_inputlookup_commands, extract_post_lateral_commands,
    extract_post_prevalence_commands, extract_prevalence_commands, extract_tree_command,
    funnel_dropper_fields, has_aggregation_before_prevalence,
    has_only_simple_post_prevalence_commands, query_has_aggregation, query_has_per_row_filters,
    resolve_baseline_entity, validate_panel_query_commands,
    validate_panel_query_unscoped_prevalence, AiCommandInfo, AssetCommandInfo, BaselineCommandInfo,
    CloudCommandInfo, FunnelCommandInfo, InputLookupCommandInfo, LateralCommandInfo,
    LookupCommandInfo, OomRisk, PanelBlockedCommand, PrevalenceCommandInfo, TreeCommandInfo,
    FUNNEL_DROPPER_FIELDS, HEAVY_TIME_RANGE_DAYS, OCSF_FUNNEL_DROPPER_FIELDS,
};
#[cfg(feature = "enterprise")]
pub use command_extraction::{
    validate_enterprise_shared_query_dependencies,
    validate_enterprise_shared_query_dependencies_with, EnterpriseSharedBlockedDependency,
    EnterpriseSharedQueryCapabilities,
};
pub use query_manipulation::{
    apply_profile_product_semantics, lake_tree_candidate_query, tree_candidate_parts, tree_field_alternates,
    tree_field_candidates, tree_key_shape, TreeKeyShape, LAKE_TREE_CANDIDATE_CAP, contains_lake_post_processing_anywhere,
    contains_nested_lake_post_processing, enforce_exact_source_scope, enforce_exact_source_scope_with_field, enforce_non_audit_query,
    enforce_source_scope, enforce_source_scope_with_field, strip_lake_source_scope_gate, query_has_nested_scan, enforce_source_type_exclusion, enforce_source_visibility_with_field, otlp_dataset_denied, LAKE_EVENT_UID_FIELD, LAKE_SOURCE_FIELD, OTLP_DATASET_SOURCES,
    lake_post_processing_replaces_source, split_lake_post_processing, strip_ai_and_after,
    strip_inputlookup_and_after, strip_lateral_and_after, strip_post_prevalence_commands,
    strip_prevalence_and_after,
};
