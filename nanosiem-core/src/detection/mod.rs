// SPDX-License-Identifier: AGPL-3.0-or-later

//! Detection Engine Module
//!
//! This module provides the detection engine functionality for NanoSIEM:
//! - Detection rule CRUD operations with query validation
//! - Scheduled rule execution
//! - Real-time rule evaluation
//! - Alert generation
//! - Historical analysis for false positive tuning
//! - Rule modes: live (bake-in) and alerting (production)
//! - Finding logging: detection matches and alerts logged as searchable events
//! - Risk-based alerting with weighted scoring
//! - Cumulative risk detection for meta-detections
//! - Prevalence-based detection conditions

pub mod distributed_scheduler;
pub mod error;
pub mod findings;
pub mod materialized_view;
pub mod prevalence;
pub mod query_enrichment;
pub mod realtime;
pub mod risk;
pub mod scheduler;
pub mod service;
pub mod signal_processor;

pub use distributed_scheduler::{
    generate_node_id, DistributedDetectionScheduler, DistributedSchedulerConfig,
};
pub use error::DetectionError;
pub use findings::{FindingEvent, FindingLogError, FindingLogger, FindingType};
pub use materialized_view::{MaterializedViewError, MaterializedViewGenerator};
pub use prevalence::{
    extract_prevalence_conditions, has_prevalence_conditions, ArtifactPrevalenceInfo,
    PrevalenceCondition, PrevalenceContext, PrevalenceEvaluator,
};
pub use realtime::{RealtimeConfig, RealtimeEvaluator};
pub use risk::{
    extract_cumulative_risk_config, is_cumulative_risk_rule, CumulativeRiskConfig,
    CumulativeRiskResult, RiskError, RiskModifier, RiskResult, ScoreCalculator,
};
pub use scheduler::{
    calculate_next_run_with_jitter, calculate_next_runs, describe_cron_expression,
    validate_cron_expression,
};
pub use service::{
    DailyMatchCount, DetectionService, DetectionServiceConfig, HistoricalAnalysisResult, TimeBucket,
};
pub use signal_processor::{SignalProcessor, SignalProcessorConfig};
