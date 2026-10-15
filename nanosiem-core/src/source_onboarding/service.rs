// SPDX-License-Identifier: AGPL-3.0-or-later
use super::repository::{Plan, Settings, SourceOnboardingRepository as Repo};
use super::*;
use sqlx::{Postgres, Transaction};
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("not found")]
    NotFound,
    #[error("{0}")]
    Invalid(String),
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PlanningFields {
    pub name: String,
    pub vendor: String,
    pub expected_type: Option<String>,
    pub wave_id: Option<Uuid>,
    pub priority: i16,
    pub owner: String,
    pub target: Option<NaiveDate>,
    pub notes: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(
    tag = "action",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum Action {
    CreateWave {
        name: String,
        target: Option<NaiveDate>,
    },
    UpdateWave {
        id: Uuid,
        name: String,
        target: Option<NaiveDate>,
        order: i32,
    },
    DeleteWave {
        id: Uuid,
    },
    CreateSource {
        fields: PlanningFields,
    },
    UpdateSource {
        id: Uuid,
        fields: PlanningFields,
    },
    DeleteSource {
        id: Uuid,
    },
    Link {
        id: Uuid,
        source_id: Uuid,
    },
    Unlink {
        id: Uuid,
    },
    Dismiss {
        id: Uuid,
        source_id: Uuid,
    },
    Complete {
        id: Uuid,
    },
    Reopen {
        id: Uuid,
    },
    Settings {
        settings: Settings,
    },
    Import {
        csv: String,
    },
    AddUnplanned {
        source_ids: Vec<Uuid>,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct LiveSource {
    pub source: MatchCandidate,
    pub signals: LiveSignals,
    pub labels: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct JoinedSource {
    #[serde(flatten)]
    pub planned: PlannedSource,
    pub suggestion: Option<Suggestion>,
    pub live: Option<LiveSource>,
    pub progress: Progress,
    pub rules_needed: usize,
    pub rules: Vec<RuleReference>,
    pub effective_target: Option<NaiveDate>,
}
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RuleReference {
    pub id: Uuid,
    pub name: String,
    pub sources: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct JoinedPlan {
    pub waves: Vec<Wave>,
    pub sources: Vec<JoinedSource>,
    pub settings: Settings,
    pub live_sources: Vec<LiveSource>,
}
pub struct SourceOnboardingService;
impl SourceOnboardingService {
    pub fn join(plan: Plan, live: Vec<LiveSource>, rules: &[RuleReference]) -> JoinedPlan {
        let taken: BTreeSet<_> = plan
            .sources
            .iter()
            .filter_map(|p| p.linked_log_source_id)
            .collect();
        let candidates: Vec<_> = live.iter().map(|l| l.source.clone()).collect();
        let rows = plan
            .sources
            .into_iter()
            .map(|p| {
                let mut excluded = taken.clone();
                excluded.extend(&p.dismissed_log_source_ids);
                let suggestion = if p.linked_log_source_id.is_none() && plan.settings.auto_suggest {
                    suggest(
                        &p.name,
                        &p.vendor,
                        p.expected_type.as_deref(),
                        &candidates,
                        &excluded,
                    )
                } else {
                    None
                };
                let mut l = live
                    .iter()
                    .find(|l| Some(l.source.id) == p.linked_log_source_id)
                    .cloned();
                let required: Vec<_> = rules
                    .iter()
                    .filter(|r| {
                        if let Some(l) = &l {
                            r.sources.iter().any(|s| l.labels.contains(s))
                        } else {
                            p.expected_type.as_ref().is_some_and(|t| {
                                r.sources.iter().any(|s| s.eq_ignore_ascii_case(t))
                            })
                        }
                    })
                    .cloned()
                    .collect();
                if let Some(l) = &mut l {
                    l.signals.rules_using = required.len();
                }
                let wave_target = plan
                    .waves
                    .iter()
                    .find(|w| Some(w.id) == p.wave_id)
                    .and_then(|w| w.target);
                let progress = progress(
                    &p,
                    l.as_ref().map(|l| &l.signals),
                    suggestion.is_some(),
                    wave_target,
                    Utc::now(),
                );
                let effective_target = p.target.or(wave_target);
                JoinedSource {
                    planned: p,
                    suggestion,
                    live: l,
                    progress,
                    rules_needed: required.len(),
                    rules: required,
                    effective_target,
                }
            })
            .collect();
        JoinedPlan {
            waves: plan.waves,
            sources: rows,
            settings: plan.settings,
            live_sources: live,
        }
    }
    pub async fn apply(
        tx: &mut Transaction<'_, Postgres>,
        tenant: Uuid,
        actor: Uuid,
        action: &Action,
        live: &[LiveSource],
        rules: &[RuleReference],
    ) -> Result<(), Error> {
        Repo::lock(tx, tenant).await?;
        let mut plan = Repo::read(tx, tenant).await?;
        let joined = Self::join(plan.clone(), live.to_vec(), rules);
        let invalid = |s: &str| Error::Invalid(s.into());
        let validate_fields = |f: &PlanningFields| -> Result<(), Error> {
            if f.name.trim().is_empty()
                || f.name.len() > 200
                || f.vendor.len() > 200
                || f.owner.len() > 200
                || f.notes.len() > 10000
                || !(1..=3).contains(&f.priority)
                || f.expected_type.as_ref().is_some_and(|t| t.len() > 100)
            {
                return Err(invalid("Invalid planning fields"));
            }
            if f.wave_id
                .is_some_and(|id| !plan.waves.iter().any(|w| w.id == id))
            {
                return Err(Error::NotFound);
            }
            Ok(())
        };
        let create = |f: &PlanningFields| PlannedSource {
            id: Uuid::new_v4(),
            name: f.name.trim().into(),
            vendor: f.vendor.clone(),
            expected_type: f.expected_type.clone(),
            wave_id: f.wave_id,
            priority: f.priority,
            owner: f.owner.clone(),
            target: f.target,
            notes: f.notes.clone(),
            linked_log_source_id: None,
            dismissed_log_source_ids: vec![],
            completed: false,
            completed_at: None,
            completed_by: None,
        };
        match action {
            Action::CreateWave { name, target } => {
                if plan.waves.len() >= 200 {
                    return Err(invalid("Plan supports at most 200 waves"));
                }
                if name.trim().is_empty() || name.len() > 200 {
                    return Err(invalid("Wave name must be 1–200 characters"));
                }
                let w = Wave {
                    id: Uuid::new_v4(),
                    name: name.trim().into(),
                    target: *target,
                    order: plan.waves.iter().map(|w| w.order).max().unwrap_or(-1) + 1,
                };
                Repo::save_wave(tx, tenant, &w).await?;
            }
            Action::UpdateWave {
                id,
                name,
                target,
                order,
            } => {
                if name.trim().is_empty() || name.len() > 200 {
                    return Err(invalid("Invalid wave name"));
                }
                let pos = plan
                    .waves
                    .iter()
                    .position(|w| w.id == *id)
                    .ok_or(Error::NotFound)?;
                let mut w = plan.waves.remove(pos);
                w.name = name.trim().into();
                w.target = *target;
                let destination = (*order).max(0) as usize;
                let destination = destination.min(plan.waves.len());
                plan.waves.insert(destination, w);
                for (index, w) in plan.waves.iter_mut().enumerate() {
                    w.order = index as i32;
                    Repo::save_wave(tx, tenant, w).await?;
                }
            }
            Action::DeleteWave { id } => {
                if !plan.waves.iter().any(|w| w.id == *id) {
                    return Err(Error::NotFound);
                }
                Repo::delete_wave(tx, tenant, *id).await?;
            }
            Action::CreateSource { fields } => {
                if plan.sources.len() >= 5000 {
                    return Err(invalid("Plan supports at most 5000 sources"));
                }
                validate_fields(fields)?;
                Repo::save_source(tx, tenant, &create(fields)).await?;
            }
            Action::UpdateSource { id, fields } => {
                validate_fields(fields)?;
                let p = plan
                    .sources
                    .iter_mut()
                    .find(|p| p.id == *id)
                    .ok_or(Error::NotFound)?;
                let n = create(fields);
                p.name = n.name;
                p.vendor = n.vendor;
                p.expected_type = n.expected_type;
                p.wave_id = n.wave_id;
                p.priority = n.priority;
                p.owner = n.owner;
                p.target = n.target;
                p.notes = n.notes;
                Repo::save_source(tx, tenant, p).await?;
            }
            Action::DeleteSource { id } => {
                if !plan.sources.iter().any(|p| p.id == *id) {
                    return Err(Error::NotFound);
                }
                Repo::delete_source(tx, tenant, *id).await?;
            }
            Action::Settings { settings } => {
                if !["wave", "priority", "none"].contains(&settings.group_by.as_str()) {
                    return Err(invalid("Invalid grouping"));
                }
                Repo::save_settings(tx, tenant, settings).await?;
            }
            Action::AddUnplanned { source_ids } => {
                if plan.sources.len()
                    + source_ids
                        .iter()
                        .copied()
                        .collect::<BTreeSet<_>>()
                        .iter()
                        .filter(|id| {
                            !plan
                                .sources
                                .iter()
                                .any(|p| p.linked_log_source_id == Some(**id))
                        })
                        .count()
                    > 5000
                {
                    return Err(invalid("Plan supports at most 5000 sources"));
                }
                if source_ids.len() > 1000 {
                    return Err(invalid("Too many sources"));
                }
                for id in source_ids.iter().collect::<BTreeSet<_>>() {
                    if plan
                        .sources
                        .iter()
                        .any(|p| p.linked_log_source_id == Some(*id))
                    {
                        continue;
                    }
                    let l = live
                        .iter()
                        .find(|l| l.source.id == *id)
                        .ok_or(Error::NotFound)?;
                    let f = PlanningFields {
                        name: l.source.name.clone(),
                        vendor: String::new(),
                        expected_type: Some(l.source.source_type.clone()),
                        wave_id: None,
                        priority: 3,
                        owner: String::new(),
                        target: None,
                        notes: String::new(),
                    };
                    validate_fields(&f)?;
                    let mut p = create(&f);
                    p.linked_log_source_id = Some(*id);
                    Repo::save_source(tx, tenant, &p).await?;
                }
            }
            Action::Import { csv } => {
                let rows = super::csv::parse(
                    csv,
                    &plan.waves,
                    &plan
                        .sources
                        .iter()
                        .map(|p| p.name.clone())
                        .collect::<Vec<_>>(),
                )
                .map_err(Error::Invalid)?;
                if plan.sources.len() + rows.iter().filter(|r| !r.duplicate).count() > 5000 {
                    return Err(invalid("Plan supports at most 5000 sources"));
                }
                for r in rows.into_iter().filter(|r| !r.duplicate) {
                    let mut wave_id = r.wave_id;
                    if r.new_wave {
                        if let Some(name) = r.wave {
                            if let Some(w) = plan
                                .waves
                                .iter()
                                .find(|w| w.name.eq_ignore_ascii_case(&name))
                            {
                                wave_id = Some(w.id);
                            } else {
                                if plan.waves.len() >= 200 {
                                    return Err(invalid("Plan supports at most 200 waves"));
                                }
                                let w = Wave {
                                    id: Uuid::new_v4(),
                                    name,
                                    target: None,
                                    order: plan.waves.len() as i32,
                                };
                                if w.name.len() > 200 {
                                    return Err(invalid("Wave name too long"));
                                }
                                Repo::save_wave(tx, tenant, &w).await?;
                                wave_id = Some(w.id);
                                plan.waves.push(w);
                            }
                        }
                    }
                    let f = PlanningFields {
                        name: r.name,
                        vendor: r.vendor,
                        expected_type: r.expected_type,
                        wave_id,
                        priority: r.priority,
                        owner: r.owner,
                        target: r.target,
                        notes: r.notes,
                    };
                    if f.name.len() > 200
                        || f.vendor.len() > 200
                        || f.owner.len() > 200
                        || f.notes.len() > 10000
                        || f.expected_type.as_ref().is_some_and(|t| t.len() > 100)
                    {
                        return Err(invalid("CSV field exceeds limit"));
                    }
                    Repo::save_source(tx, tenant, &create(&f)).await?;
                }
            }
            _ => {
                let id = match action {
                    Action::Link { id, .. }
                    | Action::Unlink { id }
                    | Action::Dismiss { id, .. }
                    | Action::Complete { id }
                    | Action::Reopen { id } => *id,
                    _ => unreachable!(),
                };
                let p = plan
                    .sources
                    .iter_mut()
                    .find(|p| p.id == id)
                    .ok_or(Error::NotFound)?;
                match action {
                    Action::Link { source_id, .. } => {
                        if !live.iter().any(|l| l.source.id == *source_id) {
                            return Err(Error::NotFound);
                        }
                        if joined.sources.iter().any(|p| {
                            p.planned.id != id && p.planned.linked_log_source_id == Some(*source_id)
                        }) {
                            return Err(invalid("Live source already linked"));
                        }
                        p.linked_log_source_id = Some(*source_id);
                        p.completed = false;
                        p.completed_at = None;
                        p.completed_by = None;
                    }
                    Action::Unlink { .. } => {
                        p.linked_log_source_id = None;
                        p.completed = false;
                        p.completed_at = None;
                        p.completed_by = None;
                    }
                    Action::Dismiss { source_id, .. } => {
                        if !live.iter().any(|l| l.source.id == *source_id) {
                            return Err(Error::NotFound);
                        }
                        if !p.dismissed_log_source_ids.contains(source_id) {
                            p.dismissed_log_source_ids.push(*source_id);
                        }
                    }
                    Action::Complete { .. } => {
                        if plan.settings.complete_gate
                            && !joined
                                .sources
                                .iter()
                                .any(|r| r.planned.id == id && r.progress.ready)
                        {
                            return Err(invalid("Complete unlocks when all checks pass"));
                        }
                        p.completed = true;
                        p.completed_at = Some(Utc::now());
                        p.completed_by = Some(actor);
                    }
                    Action::Reopen { .. } => {
                        p.completed = false;
                        p.completed_at = None;
                        p.completed_by = None;
                    }
                    _ => unreachable!(),
                }
                Repo::save_source(tx, tenant, p).await?;
            }
        }
        Ok(())
    }
}

/// Exact named-source analysis is an honest proxy: it counts live/alerting,
/// non-archived rules that explicitly name the source in any nPL scan. It
/// does not claim that arbitrary unconstrained rules require that source.
/// Dedicated (open core and enterprise dedicated) rule references.
///
/// A dedicated deployment is single-tenant and open core's `detection_rules`
/// has no `tenant_id` column (only the enterprise schema adds it), so this
/// read must not filter on it: doing so failed every open-core onboarding
/// request with `column "tenant_id" does not exist` (NAN-3769).
pub async fn read_dedicated_rules(
    tx: &mut Transaction<'_, Postgres>,
) -> Result<Vec<RuleReference>, sqlx::Error> {
    let rows: Vec<(Uuid, String, String)> = sqlx::query_as(
        "SELECT id,name,query FROM detection_rules WHERE mode IN ('live','alerting') AND NOT archived",
    )
    .fetch_all(&mut **tx)
    .await?;
    Ok(rule_references(rows))
}
/// Hosted rule references for one tenant; hosted `detection_rules` carries
/// `tenant_id`.
async fn read_tenant_rules(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
) -> Result<Vec<RuleReference>, sqlx::Error> {
    let rows: Vec<(Uuid, String, String)> = sqlx::query_as(
        "SELECT id,name,query FROM detection_rules WHERE tenant_id=$1 AND mode IN ('live','alerting') AND NOT archived",
    )
    .bind(tenant)
    .fetch_all(&mut **tx)
    .await?;
    Ok(rule_references(rows))
}
fn rule_references(rows: Vec<(Uuid, String, String)>) -> Vec<RuleReference> {
    rows.into_iter()
        .filter_map(|(id, name, q)| {
            let mut sources = BTreeSet::new();
            for field in ["metadata.log_source", "source_type"] {
                if let Ok(p) =
                    crate::search::query_processing::detection_sources::analyze_detection_sources(
                        &q, field,
                    )
                {
                    sources.extend(p.named);
                }
            }
            (!sources.is_empty()).then(|| RuleReference {
                id,
                name,
                sources: sources.into_iter().collect(),
            })
        })
        .collect()
}
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CsvRequest {
    pub csv: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct PreviewRow {
    #[serde(flatten)]
    pub row: super::csv::ImportRow,
    pub suggestion: Option<Suggestion>,
}
pub fn preview(plan: &Plan, live: &[LiveSource], input: &str) -> Result<Vec<PreviewRow>, Error> {
    let rows = super::csv::parse(
        input,
        &plan.waves,
        &plan
            .sources
            .iter()
            .map(|p| p.name.clone())
            .collect::<Vec<_>>(),
    )
    .map_err(Error::Invalid)?;
    let mut taken: BTreeSet<_> = plan
        .sources
        .iter()
        .filter_map(|p| p.linked_log_source_id)
        .collect();
    let candidates: Vec<_> = live.iter().map(|l| l.source.clone()).collect();
    Ok(rows
        .into_iter()
        .map(|row| {
            let suggestion = if !row.duplicate && plan.settings.auto_suggest {
                suggest(
                    &row.name,
                    &row.vendor,
                    row.expected_type.as_deref(),
                    &candidates,
                    &taken,
                )
            } else {
                None
            };
            if let Some(s) = &suggestion {
                taken.insert(s.source.id);
            }
            PreviewRow { row, suggestion }
        })
        .collect())
}
pub fn export(plan: &JoinedPlan) -> Result<String, Error> {
    let mut writer = ::csv::Writer::from_writer(vec![]);
    writer
        .write_record([
            "name",
            "vendor",
            "wave",
            "priority",
            "owner",
            "target",
            "notes",
            "expectedType",
            "live_source",
            "status",
            "completed",
        ])
        .map_err(|e| Error::Invalid(e.to_string()))?;
    for r in &plan.sources {
        let p = &r.planned;
        // Every cell is user-controlled text (or derived from it): neutralize
        // spreadsheet formulas (`=HYPERLINK(..)`, `=cmd|..`) before the writer
        // applies RFC 4180 quoting. `csv::parse` strips the marker on re-import.
        let cells = [
            p.name.clone(),
            p.vendor.clone(),
            plan.waves
                .iter()
                .find(|w| Some(w.id) == p.wave_id)
                .map(|w| w.name.clone())
                .unwrap_or_default(),
            p.priority.to_string(),
            p.owner.clone(),
            p.target.map(|d| d.to_string()).unwrap_or_default(),
            p.notes.clone(),
            p.expected_type.clone().unwrap_or_default(),
            r.live
                .as_ref()
                .map(|l| l.source.name.clone())
                .unwrap_or_default(),
            r.progress.stage.clone(),
            p.completed.to_string(),
        ];
        writer
            .write_record(
                cells
                    .iter()
                    .map(|c| crate::csv_safe::neutralize_formula(c).into_owned()),
            )
            .map_err(|e| Error::Invalid(e.to_string()))?;
    }
    String::from_utf8(
        writer
            .into_inner()
            .map_err(|e| Error::Invalid(e.to_string()))?,
    )
    .map_err(|e| Error::Invalid(e.to_string()))
}

/// Hosted rule bindings include unconstrained nPL rules pinned to this source.
pub async fn read_shared_rules(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
) -> Result<Vec<RuleReference>, sqlx::Error> {
    let mut rules = read_tenant_rules(tx, tenant).await?;
    let bindings:Vec<(Uuid,String,String)>=sqlx::query_as("SELECT DISTINCT d.id,d.name,s.source_slug FROM detection_rules d JOIN enterprise_shared_detection_rule_sources s ON s.tenant_id=d.tenant_id AND s.rule_id=d.id WHERE d.tenant_id=$1 AND d.mode IN ('live','alerting') AND NOT d.archived AND s.state='active' AND s.effective_at<=now() AND (s.expires_at IS NULL OR s.expires_at>now())").bind(tenant).fetch_all(&mut **tx).await?;
    for (id, name, source) in bindings {
        if let Some(r) = rules.iter_mut().find(|r| r.id == id) {
            if !r.sources.contains(&source) {
                r.sources.push(source);
            }
        } else {
            rules.push(RuleReference {
                id,
                name,
                sources: vec![source],
            });
        }
    }
    Ok(rules)
}

/// Admission counters include accepted parse failures and strictly refused rows.
/// Without a refusal-capable counter contract, admitted rows alone cannot prove parsing.
pub fn admission_parse_success_pct(
    admitted: i64,
    parse_failures: i64,
    refused: Option<i64>,
) -> Option<f64> {
    let refused = refused?;
    if admitted < 0 || refused < 0 || parse_failures < 0 || parse_failures > admitted {
        return None;
    }
    let total = admitted.checked_add(refused)?;
    (total > 0).then(|| (admitted - parse_failures) as f64 / total as f64 * 100.0)
}
