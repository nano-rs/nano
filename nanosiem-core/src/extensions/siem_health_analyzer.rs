// SPDX-License-Identifier: AGPL-3.0-or-later

//! `SiemHealthAiAnalyzer` — extension point for AI-driven SIEM health
//! analysis.
//!
//! Used by `siem_health/scheduler.rs::run_health_check_with_trigger`. The
//! scheduler always calls the trait; on `Err(ExtensionError::Unavailable)`
//! (open-core build, no AI configured) or any other failure (real AI call
//! errored), the scheduler falls back to the rules-based
//! `analyzer::fallback_report` which stays in core.
//!
//! The actual AI implementation — system prompt, AI invocation, JSON
//! response parsing — lives in `nanosiem-enterprise::siem_health::ai_analyzer`
//! (lifted in Phase 3.6 of NAN-744). Open-core wires
//! `NoopSiemHealthAiAnalyzer`; enterprise wires `AiPoweredSiemHealthAnalyzer`,
//! which adapts an `Arc<dyn AiClient>` into this trait.

use async_trait::async_trait;

use crate::extensions::ExtensionError;
use crate::siem_health::analyzer::SuppressedFinding;
use crate::siem_health::types::{AnalysisResult, CollectedMetrics};

/// Runs AI-driven analysis over collected SIEM health metrics. The single
/// entry point mirrors today's `analyzer::analyze` signature minus the
/// `&dyn AiClient` parameter — the implementation owns its own AI client.
#[async_trait]
pub trait SiemHealthAiAnalyzer: Send + Sync {
    async fn analyze_with_ai(
        &self,
        metrics: &CollectedMetrics,
        suppressions: &[SuppressedFinding],
    ) -> Result<AnalysisResult, ExtensionError>;
}

/// Open-core no-op. Always returns `Unavailable` so the scheduler falls
/// through to the rules-based `analyzer::fallback_report`.
pub struct NoopSiemHealthAiAnalyzer;

#[async_trait]
impl SiemHealthAiAnalyzer for NoopSiemHealthAiAnalyzer {
    async fn analyze_with_ai(
        &self,
        _metrics: &CollectedMetrics,
        _suppressions: &[SuppressedFinding],
    ) -> Result<AnalysisResult, ExtensionError> {
        Err(ExtensionError::Unavailable(
            "siem_health AI analyzer not wired in (open-core build)",
        ))
    }
}
