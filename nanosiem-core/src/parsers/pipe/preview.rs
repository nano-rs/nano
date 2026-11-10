// SPDX-License-Identifier: AGPL-3.0-or-later
//! Nano Pipe draft preview (NAN-4919, open core).
//!
//! A preview runs a log source's DRAFT parser (a stored processing plan or
//! plain VRL) plus its optional extension over at most [`MAX_EVENTS`] events
//! the caller supplies: live-tap captures, recent ClickHouse samples, or
//! pasted events. Nothing is persisted.
//!
//! [`run`] is the engine. It executes only inside the isolated worker process
//! ([`super::sandbox`]); the API process never runs preview VRL itself.
//! Native steps (dedupe, route, lookup, combine) are simulated with fresh
//! state per run by [`super::batch`]; every VRL program compiles through the
//! guarded compiler against the parser allowlist.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Events per preview.
pub const MAX_EVENTS: usize = 100;
/// One serialized event.
pub const MAX_EVENT_BYTES: usize = 64 * 1024;
/// The whole serialized request.
pub const MAX_REQUEST_BYTES: usize = 1024 * 1024;
/// The worker's serialized response (outputs plus per-step traces).
pub const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PipePreviewRequest {
    /// The draft parser: a stored processing plan (`# nano-pipe-v2 …`) or
    /// plain VRL. Omitted = the source's saved working copy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parser_vrl: Option<String>,
    /// The draft extension, run after the pipeline in its own remap scope.
    /// Omitted = the source's saved extension (when enabled).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension_vrl: Option<String>,
    /// 1–100 events, each at most 64 KiB serialized.
    #[schema(value_type = Vec<Object>)]
    pub events: Vec<Value>,
    /// Optional per-event input identity (`push:<credential id>`), as the
    /// live tap reports it, so Route by input previews faithfully.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inputs: Option<Vec<Option<String>>>,
}

impl PipePreviewRequest {
    pub fn validate(&self) -> Result<(), String> {
        if self.events.is_empty() || self.events.len() > MAX_EVENTS {
            return Err(format!("A preview takes 1–{MAX_EVENTS} events"));
        }
        for event in &self.events {
            let bytes = serde_json::to_vec(event).map_err(|e| e.to_string())?.len();
            if bytes > MAX_EVENT_BYTES {
                return Err(format!(
                    "Each preview event is at most {} KiB",
                    MAX_EVENT_BYTES / 1024
                ));
            }
        }
        if self
            .inputs
            .as_ref()
            .is_some_and(|inputs| inputs.len() != self.events.len())
        {
            return Err("Preview inputs must name one input per event".into());
        }
        let bytes = serde_json::to_vec(self).map_err(|e| e.to_string())?.len();
        if bytes > MAX_REQUEST_BYTES {
            return Err("A preview request is at most 1 MiB".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PipePreviewTrace {
    /// The step id, or `existing-source-extension` for the extension.
    pub step_id: String,
    #[schema(value_type = Vec<Object>)]
    pub outputs: Vec<Value>,
    pub error: Option<String>,
    /// The step did not apply to this event (disabled, or its condition
    /// was false).
    pub bypassed: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PipePreviewEvent {
    pub index: usize,
    /// `retained`, `filtered`, `sampled_out`, `split`, `combined` or `error`.
    pub disposition: String,
    #[schema(value_type = Vec<Object>)]
    pub outputs: Vec<Value>,
    pub error: Option<String>,
    pub traces: Vec<PipePreviewTrace>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PipePreviewSummary {
    pub input_events: usize,
    pub output_events: usize,
    pub dropped_events: usize,
    pub error_events: usize,
    /// Serialized bytes in and out: the reduction a pipeline buys.
    pub input_bytes: usize,
    pub output_bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PipePreviewResponse {
    /// `vrl` (plain parser), `pipeline` (stateless plan) or
    /// `pipeline+native` (simulated native steps).
    pub engine: String,
    /// `true` when this preview ran without Linux resource limits (a
    /// development host): bounded by the wall-clock deadline only.
    pub degraded_isolation: bool,
    pub results: Vec<PipePreviewEvent>,
    pub summary: PipePreviewSummary,
    pub warnings: Vec<String>,
}

fn size(value: &impl Serialize) -> usize {
    serde_json::to_vec(value).map(|v| v.len()).unwrap_or(0)
}

/// Run a validated request. `parser_vrl` / `extension_vrl` are resolved by the
/// caller (the worker never touches a database).
pub async fn run(request: &PipePreviewRequest) -> Result<PipePreviewResponse, String> {
    request.validate()?;
    let parser_vrl = request.parser_vrl.as_deref().unwrap_or_default();
    let extension = request
        .extension_vrl
        .as_deref()
        .filter(|ext| !ext.trim().is_empty());
    // Already inside the preview worker process: execute here (NAN-5234).
    let validator = crate::parsers::VrlValidator::new().inside_worker();
    let mut warnings = vec![
        "Preview simulates the pipeline in isolation: platform normalization, sink encoding, \
         sampling and live Vector state are not modelled. Implicit timezones use UTC."
            .to_string(),
    ];
    if let Some(extension) = extension {
        let validation = validator
            .validate_vrl(extension)
            .await
            .map_err(|e| e.to_string())?;
        if !validation.valid {
            return Err(format!(
                "Extension: {}",
                validation.error.unwrap_or_default()
            ));
        }
    }
    let (engine, rows) = match super::stored_plan(parser_vrl)? {
        Some(plan) => {
            let validation = validator
                .validate_vrl(parser_vrl)
                .await
                .map_err(|e| e.to_string())?;
            if !validation.valid {
                return Err(validation.error.unwrap_or_default());
            }
            warnings.extend(
                validation
                    .warnings
                    .into_iter()
                    .filter(|w| w.contains("reduce and lua")),
            );
            let engine = if plan.has_native() {
                "pipeline+native"
            } else {
                "pipeline"
            };
            let rows = super::batch::run_from(
                &plan,
                &request.events,
                extension,
                request.inputs.as_deref(),
            )?;
            let results = rows
                .into_iter()
                .enumerate()
                .map(|(index, row)| PipePreviewEvent {
                    index,
                    disposition: row.disposition,
                    outputs: row.outputs,
                    error: row.error,
                    traces: row
                        .traces
                        .into_iter()
                        .map(|t| PipePreviewTrace {
                            step_id: t.id,
                            outputs: t.outputs,
                            error: t.error,
                            bypassed: t.bypassed,
                        })
                        .collect(),
                })
                .collect::<Vec<_>>();
            (engine, results)
        }
        None => {
            if parser_vrl.trim().is_empty() && extension.is_none() {
                return Err("The source has no parser or extension to preview".into());
            }
            if !parser_vrl.trim().is_empty() {
                let validation = validator
                    .validate_vrl(parser_vrl)
                    .await
                    .map_err(|e| e.to_string())?;
                if !validation.valid {
                    return Err(validation.error.unwrap_or_default());
                }
            }
            let inputs: Vec<String> = request.events.iter().map(Value::to_string).collect();
            let stages: Vec<&str> = [Some(parser_vrl), extension].into_iter().flatten().collect();
            let mut results = Vec::with_capacity(inputs.len());
            for (index, input) in inputs.iter().enumerate() {
                let tested = validator
                    .test_vrl_chain(&stages, input)
                    .await
                    .map_err(|e| e.to_string())?;
                let outputs = match tested.output {
                    Some(Value::Array(values)) => values,
                    Some(value) => vec![value],
                    None => vec![],
                };
                let disposition = if tested.error.is_some() {
                    "error"
                } else if outputs.is_empty() {
                    "filtered"
                } else if outputs.len() > 1 {
                    "split"
                } else {
                    "retained"
                };
                results.push(PipePreviewEvent {
                    index,
                    disposition: disposition.into(),
                    outputs,
                    error: tested.error,
                    traces: vec![],
                });
            }
            ("vrl", results)
        }
    };
    let summary = PipePreviewSummary {
        input_events: request.events.len(),
        output_events: rows.iter().map(|r| r.outputs.len()).sum(),
        dropped_events: rows
            .iter()
            .filter(|r| r.error.is_none() && r.outputs.is_empty())
            .count(),
        error_events: rows.iter().filter(|r| r.error.is_some()).count(),
        input_bytes: request.events.iter().map(size).sum(),
        output_bytes: rows.iter().flat_map(|r| &r.outputs).map(size).sum(),
    };
    Ok(PipePreviewResponse {
        engine: engine.into(),
        degraded_isolation: false,
        results: rows,
        summary,
        warnings,
    })
}
