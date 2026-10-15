// SPDX-License-Identifier: AGPL-3.0-or-later
//! Source onboarding: users edit planning fields; telemetry owns progress.
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use uuid::Uuid;
pub mod csv;

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct Wave {
    pub id: Uuid,
    pub name: String,
    pub target: Option<NaiveDate>,
    pub order: i32,
}
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PlannedSource {
    pub id: Uuid,
    pub name: String,
    pub vendor: String,
    pub expected_type: Option<String>,
    pub wave_id: Option<Uuid>,
    pub priority: i16,
    pub owner: String,
    pub target: Option<NaiveDate>,
    pub notes: String,
    pub linked_log_source_id: Option<Uuid>,
    pub dismissed_log_source_ids: Vec<Uuid>,
    pub completed: bool,
    pub completed_at: Option<DateTime<Utc>>,
    pub completed_by: Option<Uuid>,
}
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LiveSignals {
    pub eps: Option<f64>,
    pub last_event_at: Option<DateTime<Utc>>,
    pub parse_success_pct: Option<f64>,
    pub refused24h: Option<i64>,
    pub rules_using: usize,
    pub status: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct Progress {
    pub c1: bool,
    pub c2: bool,
    pub c3: bool,
    pub c4: bool,
    pub c5: bool,
    pub issue: bool,
    pub ready: bool,
    pub stage: String,
    pub late: bool,
    pub parsing_known: bool,
}
/// Unknown parse telemetry cannot satisfy the completion gate. It is displayed
/// explicitly, rather than describing admitted-only counters as 100% parsed.
pub fn progress(
    p: &PlannedSource,
    live: Option<&LiveSignals>,
    suggested: bool,
    wave_target: Option<NaiveDate>,
    now: DateTime<Utc>,
) -> Progress {
    let c1 = live.is_some();
    let c2 = live
        .and_then(|l| l.last_event_at)
        .is_some_and(|t| t > now - chrono::Duration::minutes(15));
    let parsing_known = live.and_then(|l| l.parse_success_pct).is_some();
    let c3 = live
        .and_then(|l| l.parse_success_pct)
        .is_some_and(|pct| pct.is_finite() && pct >= 99.0);
    let c4 = live.is_some_and(|l| l.rules_using > 0);
    let c5 = c1 && c2 && c3 && c4 && live.is_some_and(|l| l.status == "healthy");
    let issue = live.is_some_and(|l| {
        !c2 || (parsing_known && !c3) || matches!(l.status.as_str(), "lagging" | "error")
    });
    let ready = c5 && !p.completed;
    let stage = if p.completed && issue {
        "Regressed since complete".into()
    } else if p.completed {
        "Complete".into()
    } else if !c1 && suggested {
        "Match suggested".into()
    } else if !c1 {
        "Not connected".into()
    } else if issue && !c2 {
        let minutes = live
            .and_then(|l| l.last_event_at)
            .map(|t| (now - t).num_minutes().max(0));
        format!(
            "Quiet for {}",
            minutes
                .map(|m| if m >= 1440 {
                    format!("{}d", m / 1440)
                } else if m >= 60 {
                    format!("{}h", m / 60)
                } else {
                    format!("{m}m")
                })
                .unwrap_or_else(|| "unknown duration".into())
        )
    } else if issue && !c3 && parsing_known {
        "Refusing events".into()
    } else if issue {
        "Lagging".into()
    } else if c5 {
        "Ready to complete".into()
    } else if !parsing_known {
        "Parsing unknown".into()
    } else if !c4 {
        "No detections use it".into()
    } else {
        "In progress".into()
    };
    let late = p
        .target
        .or(wave_target)
        .is_some_and(|t| t < now.date_naive())
        && !ready
        && !p.completed;
    Progress {
        c1,
        c2,
        c3,
        c4,
        c5,
        issue,
        ready,
        stage,
        late,
        parsing_known,
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct MatchCandidate {
    pub id: Uuid,
    pub name: String,
    pub source_type: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct Suggestion {
    pub source: MatchCandidate,
    pub confidence: f64,
    pub overlapping_tokens: Vec<String>,
    pub type_match: bool,
}
fn tokens(text: &str) -> BTreeSet<String> {
    text.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| t.len() > 2 && !["log", "logs", "app", "the", "and"].contains(t))
        .map(String::from)
        .collect()
}
pub fn suggest(
    name: &str,
    vendor: &str,
    expected: Option<&str>,
    candidates: &[MatchCandidate],
    excluded: &BTreeSet<Uuid>,
) -> Option<Suggestion> {
    let wanted = tokens(&format!("{name} {vendor}"));
    let mut matches: Vec<_> = candidates
        .iter()
        .filter(|c| !excluded.contains(&c.id))
        .filter_map(|c| {
            let found = tokens(&format!("{} {}", c.name, c.source_type));
            let overlap: Vec<_> = wanted.intersection(&found).cloned().collect();
            if overlap.is_empty() {
                return None;
            }
            let type_match = expected.is_some_and(|t| t.eq_ignore_ascii_case(&c.source_type));
            let score = overlap.len() + usize::from(type_match) * 2;
            Some((
                score,
                Suggestion {
                    source: c.clone(),
                    confidence: ((overlap.len() as f64 / wanted.len().max(1) as f64)
                        + if type_match { 0.2 } else { 0.0 })
                    .min(1.0),
                    overlapping_tokens: overlap,
                    type_match,
                },
            ))
        })
        .collect();
    matches.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.source.id.cmp(&b.1.source.id)));
    matches.into_iter().next().map(|m| m.1)
}
#[cfg(test)]
mod tests;

pub mod repository;
pub mod service;
