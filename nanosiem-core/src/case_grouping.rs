// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure alert → case grouping evaluation (NAN-2361 wave 4).
//!
//! The dedicated `CaseService::process_alert_for_grouping`
//! (`enterprise/src/cases/service/grouping.rs`) and the
//! hosted-shared tenant grouping hook
//! (the hosted case-grouping module) must agree on WHAT groups
//! and WHY: which event fields identify the grouping entity for a rule, how
//! the grouping key is hashed, how the per-rule window/max caps are clamped
//! by the global (tenant) settings, how a title template renders and when a
//! joining alert escalates the case. That evaluation is pure and lives here
//! once; both consumers call it. Everything that touches a database (find an
//! open case, attach, create, audit) stays in the respective consumer,
//! because the dedicated path uses a `PgPool` repository and the shared path
//! a signed tenant transaction.

use sha2::{Digest, Sha256};
use tracing::debug;

use crate::models::case::{CaseGroupingRule, GroupingType};
use crate::models::Alert;
use crate::entity_extraction::EntityExtractor;
use crate::schema::{active_profile_from_env, EntityType, SchemaProfile};

/// Maximum rendered case title length (characters).
pub const MAX_TITLE_CHARS: usize = 120;

/// Schema-aware entity-field candidates for case grouping (NAN-1296).
///
/// Returns every field the ACTIVE schema profile marks with `target` entity
/// type, source/primary fields first (deterministic; preserves the historical
/// "prefer source side" priority). Replaces the old hardcoded per-match_type
/// lists, which lagged the schema and silently dropped fields (OCSF
/// `device.hostname`; UDM `dvc` / `dvc_ip` / `user_name`).
pub fn entity_field_candidates(target: EntityType) -> Vec<&'static str> {
    // NAN-2361: no UdmProfile substitution on error. Under the canonical OCSF lake
    // the UDM field set marks entity types on names the events do not contain, so
    // grouping either found nothing or grouped on a same-named field with different
    // semantics — both silent. No candidates means the alert drops to the
    // standalone-case fallback, which is already handled and logged by the caller.
    let Ok(profile) = active_profile_from_env().inspect_err(|error| {
        tracing::error!(
            %error,
            ?target,
            "case grouping has no entity-field candidates: cannot resolve the active \
             schema profile; refusing to group against a different schema"
        );
    }) else {
        return Vec::new();
    };
    entity_field_candidates_in(profile.as_ref(), target)
}

/// [`entity_field_candidates`] for an explicit schema profile.
pub fn entity_field_candidates_in(profile: &dyn SchemaProfile, target: EntityType) -> Vec<&'static str> {
    let mut fields: Vec<&'static str> = profile
        .fields()
        .iter()
        .filter(|f| f.entity_type == Some(target))
        .map(|f| f.name)
        .collect();
    // Destination-side fields rank after source/primary ones; a stable sort keeps
    // the profile's declared order within each rank group.
    fields.sort_by_key(|f| usize::from(f.contains("dst") || f.contains("dest")));
    fields
}

/// Read a query-facing field from an alert event. Legacy UDM results may carry
/// a literal dotted top-level key; canonical OCSF results are nested objects.
/// Prefer the literal key for compatibility, then walk the semantic path.
pub fn event_field_string(event: &serde_json::Value, field: &str) -> Option<String> {
    let value = event.get(field).or_else(|| {
        field
            .split('.')
            .try_fold(event, |current, component| current.get(component))
    })?;
    let value = value.as_str()?.trim();
    if value.is_empty() || value == "-" || value.eq_ignore_ascii_case("null") {
        None
    } else {
        Some(value.to_string())
    }
}

/// The first non-empty value of `fields` (in priority order) across the
/// alert's matched events.
pub fn field_value_prioritized(events: &serde_json::Value, fields: &[&str]) -> Option<String> {
    let events_to_check: Vec<&serde_json::Value> = match events {
        serde_json::Value::Array(arr) => arr.iter().collect(),
        serde_json::Value::Object(_) => vec![events],
        _ => return None,
    };
    for field in fields {
        for event in &events_to_check {
            if let Some(value) = event_field_string(event, field) {
                return Some(value);
            }
        }
    }
    None
}

/// The raw grouping entity value a rule selects from an alert: the
/// prioritized schema field for `host` / `user` / `ip`, the rule id for
/// `rule`. `None` when the rule cannot classify the alert.
pub fn grouping_entity_value(alert: &Alert, rule: &CaseGroupingRule) -> Option<String> {
    grouping_entity_value_with(alert, rule, entity_field_candidates)
}

fn grouping_entity_value_with(
    alert: &Alert,
    rule: &CaseGroupingRule,
    candidates: impl Fn(EntityType) -> Vec<&'static str>,
) -> Option<String> {
    let entity_value = match rule.match_type.as_str() {
        "host" => field_value_prioritized(&alert.matched_events, &candidates(EntityType::Host)),
        "user" => field_value_prioritized(&alert.matched_events, &candidates(EntityType::User)),
        "ip" => field_value_prioritized(&alert.matched_events, &candidates(EntityType::Ip)),
        "rule" => alert.rule_id.map(|r| r.to_string()),
        _ => None,
    };
    // A non-string scalar/object at every candidate path leaves the alert
    // without a grouping entity. Surface it so an operator can see WHY the
    // alert dropped to the standalone-case fallback.
    if entity_value.is_none() && matches!(rule.match_type.as_str(), "host" | "user" | "ip") {
        debug!(
            alert_id = %alert.id,
            match_type = %rule.match_type,
            "No groupable entity value found in matched_events (all candidate fields missing, non-string, or nested); alert will fall back to a standalone case"
        );
    }
    entity_value
}

/// Compute a grouping key for an alert based on rule type.
///
/// For host/user/ip grouping the entity is read directly from
/// `matched_events`, SOURCE fields before DESTINATION fields, so alerts from
/// the same source group together even when they touch different
/// destinations.
pub fn compute_grouping_key(alert: &Alert, rule: &CaseGroupingRule) -> Option<String> {
    grouping_entity_value(alert, rule).map(|value| compute_key_hash(&rule.match_type, &value))
}

/// Hash the grouping-key components for a `match_type` + entity `value`.
///
/// G7 (NAN-1749): the entity `value` is LOWERCASED before hashing. `user` /
/// `host` are not ingest-lowercased (only IPs/hashes are), so `WORKSTATION-1`
/// (winevent) and `workstation-1` (sysmon) would otherwise hash to two
/// different keys and split one host into two cases. UUID values (match_type =
/// "rule") are already lowercase, so this is a no-op for them.
pub fn compute_key_hash(match_type: &str, value: &str) -> String {
    let value = value.to_lowercase();
    let mut hasher = Sha256::new();
    hasher.update(match_type.as_bytes());
    hasher.update(b":");
    hasher.update(value.as_bytes());
    hex::encode(hasher.finalize())
}

/// The grouping type a rule's `match_type` denotes, if recognized.
pub fn grouping_type_of(rule: &CaseGroupingRule) -> Option<GroupingType> {
    rule.match_type.parse::<GroupingType>().ok()
}

/// Effective attach caps for a rule: G12 (NAN-1749) — the global (tenant)
/// `max_alerts_per_case` / `default_time_window_minutes` are HARD CAPS, not
/// mere defaults; a per-rule value is only honored up to the global ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectiveGroupingCaps {
    pub time_window_minutes: i32,
    pub max_alerts: i32,
}

pub fn effective_caps(
    rule: &CaseGroupingRule,
    global_max_alerts_per_case: i32,
    global_default_time_window_minutes: i32,
) -> EffectiveGroupingCaps {
    EffectiveGroupingCaps {
        time_window_minutes: rule.time_window_minutes.min(global_default_time_window_minutes),
        max_alerts: rule.max_alerts.min(global_max_alerts_per_case),
    }
}

/// Render a grouping rule's `case_title_template` (G4 / NAN-1754).
///
/// Substitutes `{{rule_name}}`, `{{severity}}`, and the grouping-entity value.
/// The entity value is bound to `{{entity}}` AND to the entity-type aliases the
/// shipped default rules use (`{{host}}`, `{{user}}`, `{{ip}}`, `{{hash}}`,
/// `{{domain}}`) so those templates render a real value instead of a literal
/// placeholder. Unknown tokens are left verbatim.
pub fn render_case_title_template(tmpl: &str, rule_name: &str, severity: &str, entity: &str) -> String {
    let mut out = tmpl
        .replace("{{rule_name}}", rule_name)
        .replace("{{severity}}", severity);
    for token in ["{{entity}}", "{{host}}", "{{user}}", "{{ip}}", "{{hash}}", "{{domain}}"] {
        out = out.replace(token, entity);
    }
    out
}

/// Truncate a rendered case title to a sane max length (120 chars) without
/// splitting a UTF-8 boundary. Used for `case_title_template` output (G4).
pub fn truncate_title(mut title: String) -> String {
    if title.chars().count() <= MAX_TITLE_CHARS {
        return title;
    }
    let end = title
        .char_indices()
        .nth(MAX_TITLE_CHARS)
        .map(|(i, _)| i)
        .unwrap_or(title.len());
    title.truncate(end);
    title
}

/// The base title of an auto-created case: the rule name, or a placeholder
/// naming the (possibly deleted) rule id.
pub fn base_case_title(rule_name: Option<&str>, alert: &Alert) -> String {
    rule_name.map(|name| name.to_string()).unwrap_or_else(|| match alert.rule_id {
        Some(rid) => format!("Alert from rule {rid}"),
        None => "Alert from deleted rule".to_string(),
    })
}

/// The entity a grouping rule's title template names (NAN-3036): the value
/// the rule grouped the alert on (`host` / `user` / `ip`), read exactly like
/// the grouping key so the title and the grouping can never disagree. `rule`
/// grouping has no entity to name (its value is the rule UUID).
pub fn grouping_title_entity(alert: &Alert, rule: &CaseGroupingRule) -> Option<String> {
    grouping_title_entity_with(alert, rule, entity_field_candidates)
}

fn grouping_title_entity_with(
    alert: &Alert,
    rule: &CaseGroupingRule,
    candidates: impl Fn(EntityType) -> Vec<&'static str>,
) -> Option<String> {
    matches!(rule.match_type.as_str(), "host" | "user" | "ip")
        .then(|| grouping_entity_value_with(alert, rule, candidates))
        .flatten()
}

/// Title of an auto-created case for `alert` (both the dedicated
/// `CaseService` and the hosted-shared tenant grouping hook call this).
///
/// The grouping rule's template renders the grouped entity (`Alerts on host:
/// ws-1`), falling back to the event-context suffix; without a template the
/// historical `"<rule name> - <context suffix>"` form applies.
pub fn auto_case_title(
    extractor: &EntityExtractor,
    alert: &Alert,
    rule_name: Option<&str>,
    grouping_rule: Option<&CaseGroupingRule>,
) -> String {
    let grouped = grouping_rule.and_then(|rule| grouping_title_entity(alert, rule));
    let suffix = extractor.build_title_suffix(&alert.matched_events);
    finish_auto_case_title(alert, rule_name, grouping_rule, grouped, suffix)
}

/// [`auto_case_title`] against an explicit schema profile instead of the
/// env-resolved one (tests pin the profile the shared jobs runtime uses).
pub fn auto_case_title_in(
    profile: &dyn SchemaProfile,
    extractor: &EntityExtractor,
    alert: &Alert,
    rule_name: Option<&str>,
    grouping_rule: Option<&CaseGroupingRule>,
) -> String {
    let grouped = grouping_rule
        .and_then(|rule| grouping_title_entity_with(alert, rule, |target| entity_field_candidates_in(profile, target)));
    let suffix = extractor.build_title_suffix_for(&alert.matched_events, profile.id());
    finish_auto_case_title(alert, rule_name, grouping_rule, grouped, suffix)
}

fn finish_auto_case_title(
    alert: &Alert,
    rule_name: Option<&str>,
    grouping_rule: Option<&CaseGroupingRule>,
    grouped: Option<String>,
    suffix: Option<String>,
) -> String {
    compose_case_title(
        &base_case_title(rule_name, alert),
        &format!("{:?}", alert.severity).to_lowercase(),
        suffix.as_deref(),
        grouped.as_deref(),
        grouping_rule,
    )
}

/// Compose the title of an auto-created case: the grouping rule's
/// `case_title_template` when set (rendered with `grouping_entity`, else the
/// context suffix, then truncated), otherwise the historical
/// `"<rule name> - <entity suffix>"` form capped at 120 chars.
pub fn compose_case_title(
    base_title: &str,
    severity: &str,
    entity_suffix: Option<&str>,
    grouping_entity: Option<&str>,
    grouping_rule: Option<&CaseGroupingRule>,
) -> String {
    let template = grouping_rule
        .and_then(|r| r.case_title_template.as_deref())
        .map(str::trim)
        .filter(|t| !t.is_empty());
    match template {
        Some(tmpl) => truncate_title(render_case_title_template(
            tmpl,
            base_title,
            severity,
            grouping_entity.or(entity_suffix).unwrap_or(""),
        )),
        None => match entity_suffix {
            Some(suffix) => {
                // Truncate suffix if needed to keep title reasonable (max 120 chars)
                let max_suffix_len = MAX_TITLE_CHARS.saturating_sub(base_title.len() + 3); // 3 for " - "
                if suffix.len() > max_suffix_len && max_suffix_len > 10 {
                    format!("{} - {}...", base_title, &suffix[..max_suffix_len - 3])
                } else if max_suffix_len > 10 {
                    format!("{base_title} - {suffix}")
                } else {
                    base_title.to_string()
                }
            }
            None => base_title.to_string(),
        },
    }
}

/// Rank a severity string: lower = more severe. Unknown values rank last so a
/// recognized severity always wins over garbage. Mirrors the SQL ranking in
/// `CaseRepository::escalate_severity` (G4).
pub fn severity_rank(severity: &str) -> i32 {
    match severity {
        "critical" => 1,
        "high" => 2,
        "medium" => 3,
        "low" => 4,
        "informational" => 5,
        _ => 6,
    }
}

/// Decide whether joining a `candidate`-severity alert should escalate a case
/// currently at `current` severity (the `highest` rule). Returns `Some(candidate)`
/// only when `candidate` is STRICTLY more severe than `current`; `None` means
/// leave the case as-is. Pure counterpart to the atomic UPDATE in
/// `CaseRepository::escalate_severity`, used as a fast-path skip (G4).
pub fn escalated_severity<'a>(current: &str, candidate: &'a str) -> Option<&'a str> {
    if severity_rank(candidate) < severity_rank(current) {
        Some(candidate)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn rule(match_type: &str, template: Option<&str>) -> CaseGroupingRule {
        let now = Utc::now();
        CaseGroupingRule {
            id: Uuid::new_v4(),
            name: "r".into(),
            description: None,
            enabled: true,
            priority: 1,
            match_type: match_type.into(),
            match_conditions: None,
            time_window_minutes: 90,
            min_alerts: 1,
            max_alerts: 500,
            auto_create_case: true,
            case_title_template: template.map(str::to_string),
            case_severity_rule: "highest".into(),
            auto_assign_to: None,
            created_at: now,
            updated_at: now,
            created_by: None,
        }
    }

    fn alert(events: serde_json::Value) -> Alert {
        Alert {
            id: Uuid::new_v4(),
            rule_id: Some(Uuid::from_u128(7)),
            rule_name: Some("Rule".into()),
            severity: crate::models::Severity::High,
            status: crate::models::AlertStatus::New,
            disposition: None,
            matched_events: events,
            matched_event_count: Some(1),
            event_hash: None,
            assigned_to: None,
            acknowledged_by: None,
            acknowledged_at: None,
            closed_by: None,
            closed_at: None,
            created_at: Utc::now(),
            triage_verdict: None,
            triage_confidence: None,
            triage_verdict_details: None,
            case_id: None,
            kind: "detection".into(),
            source_id: None,
            source_types: vec![],
        }
    }

    #[test]
    fn rule_match_type_keys_on_the_rule_id_and_is_stable() {
        let a = alert(serde_json::json!([{"x": 1}]));
        let key = compute_grouping_key(&a, &rule("rule", None)).unwrap();
        assert_eq!(key, compute_key_hash("rule", &Uuid::from_u128(7).to_string()));
        assert!(compute_grouping_key(&a, &rule("manual", None)).is_none());
    }

    #[test]
    fn key_hash_is_case_insensitive_and_type_scoped() {
        assert_eq!(compute_key_hash("host", "WORKSTATION-1"), compute_key_hash("host", "workstation-1"));
        assert_ne!(compute_key_hash("host", "a"), compute_key_hash("user", "a"));
        assert_eq!(compute_key_hash("ip", "10.0.0.1").len(), 64);
    }

    #[test]
    fn caps_are_clamped_by_the_global_ceiling() {
        let caps = effective_caps(&rule("host", None), 100, 60);
        assert_eq!(caps, EffectiveGroupingCaps { time_window_minutes: 60, max_alerts: 100 });
        let caps = effective_caps(&rule("host", None), 1000, 4320);
        assert_eq!(caps, EffectiveGroupingCaps { time_window_minutes: 90, max_alerts: 500 });
    }

    #[test]
    fn title_composition_prefers_the_template_then_the_suffix() {
        let r = rule("host", Some("Alerts on host: {{host}} [{{severity}}]"));
        assert_eq!(compose_case_title("Rule", "high", Some("ws-1"), None, Some(&r)), "Alerts on host: ws-1 [high]");
        assert_eq!(compose_case_title("Rule", "high", Some("ws-1"), None, None), "Rule - ws-1");
        assert_eq!(compose_case_title("Rule", "high", None, None, None), "Rule");
        let long = "x".repeat(300);
        let title = compose_case_title("Rule", "high", Some(&long), None, None);
        assert!(title.len() <= MAX_TITLE_CHARS && title.ends_with("..."));
        let blank = rule("host", Some("   "));
        assert_eq!(compose_case_title("Rule", "high", Some("ws-1"), None, Some(&blank)), "Rule - ws-1");
    }

    #[test]
    fn base_title_names_the_rule_or_its_id() {
        let a = alert(serde_json::json!([]));
        assert_eq!(base_case_title(Some("Named"), &a), "Named");
        assert_eq!(base_case_title(None, &a), format!("Alert from rule {}", Uuid::from_u128(7)));
    }

    #[test]
    fn escalation_is_strict() {
        assert_eq!(escalated_severity("medium", "critical"), Some("critical"));
        assert_eq!(escalated_severity("critical", "critical"), None);
        assert_eq!(escalated_severity("garbage", "low"), Some("low"));
        assert_eq!(escalated_severity("low", "garbage"), None);
    }

    /// NAN-3036: a lean OCSF alert is an aggregated row with a literal dotted
    /// `device.hostname` key. The host template names the grouped host (the
    /// same value the grouping key hashes), never an empty string and never
    /// the `user@host` context suffix.
    #[test]
    fn host_template_names_the_grouped_ocsf_host() {
        let ocsf = crate::schema::OcsfProfile::new();
        let candidates = |target| entity_field_candidates_in(&ocsf, target);
        let a = alert(serde_json::json!([{
            "_nano_source_types": ["windows_sysmon"],
            "device.hostname": "e2e-b98b021b-ps.corp.local",
            "users": "lwalker", "hits": 1,
        }]));
        let host = rule("host", Some("Alerts on host: {{host}}"));
        let grouped = grouping_title_entity_with(&a, &host, candidates).unwrap();
        assert_eq!(grouped, "e2e-b98b021b-ps.corp.local");
        assert_eq!(
            grouping_entity_value_with(&a, &host, candidates).as_deref(),
            Some(grouped.as_str()),
            "the title names exactly what the grouping key hashes"
        );
        assert_eq!(
            compose_case_title("Rule", "high", Some("lwalker@e2e-b98b021b-ps.corp.local"), Some(&grouped), Some(&host)),
            "Alerts on host: e2e-b98b021b-ps.corp.local"
        );
        // Nested OCSF resolves the same way.
        let nested = alert(serde_json::json!([{"device": {"hostname": "ws-1"}}]));
        assert_eq!(grouping_title_entity_with(&nested, &host, candidates).as_deref(), Some("ws-1"));
        // `rule` grouping names no entity (its value is the rule UUID).
        assert_eq!(grouping_title_entity_with(&a, &rule("rule", Some("{{entity}}")), candidates), None);
        // No grouped entity: fall back to the context suffix.
        assert_eq!(compose_case_title("Rule", "high", Some("ws-2"), None, Some(&host)), "Alerts on host: ws-2");
    }

    /// NAN-3048: live case #22 on the lean tenant (case_01m3q8xm24epgrqvmty8sd3kpw,
    /// alert_4fgd1gfzcs9zjvhdrnr7e2er2q) was titled "Alerts on host: " because
    /// the staging-jobs pod — which runs the hosted-shared grouping hook —
    /// was still on a pre-NAN-3036 image. This is that alert's exact
    /// matched_events, run through the full title path the hook calls, under
    /// the canonical shared-lake profile the jobs process resolves.
    #[test]
    fn live_lean_case_22_alert_titles_with_its_grouped_host() {
        let profile = crate::schema::tenant_lake_schema::canonical_shared_lake_profile();
        let a = alert(serde_json::json!([
            {"_nano_source_types":["windows_sysmon"],"actor.user.name":"dmartinez",
             "commands":"certutil.exe -encode C:\\temp\\backup.zip C:\\temp\\backup.b64, robocopy C:\\Users\\Public\\Documents C:\\temp\\staging *.docx *.xlsx *.pdf /S, powershell.exe -c \"Compress-Archive -Path C:\\temp\\staging -DestinationPath C:\\temp\\backup.zip -Force\"",
             "device.hostname":"e2e-900292a3-ex.corp.local","hits":3,
             "tools":"robocopy.exe, certutil.exe, powershell.exe","unique_tools":3},
            {"_nano_source_types":["windows_sysmon"],"actor.user.name":"mlee",
             "commands":"powershell.exe -c \"Compress-Archive -Path C:\\temp\\lsass.dmp -DestinationPath C:\\temp\\data.zip\"",
             "device.hostname":"e2e-900292a3-qk.corp.local","hits":1,
             "tools":"powershell.exe","unique_tools":1}
        ]));
        // The seeded "Group by Host" rule (9000003_seed_enterprise_baseline).
        let host = rule("host", Some("Alerts on host: {{host}}"));
        let title = auto_case_title_in(
            profile.as_ref(),
            &EntityExtractor::new(),
            &a,
            Some("data_staging_and_exfiltration"),
            Some(&host),
        );
        assert_eq!(title, "Alerts on host: e2e-900292a3-ex.corp.local");
        // The title names exactly the host the grouping key hashes.
        let key = grouping_entity_value_with(&a, &host, |t| entity_field_candidates_in(profile.as_ref(), t));
        assert_eq!(key.as_deref(), Some("e2e-900292a3-ex.corp.local"));
        // Without a template the historical "<rule> - <context>" form still
        // carries a non-empty context from the literal dotted keys.
        let plain = auto_case_title_in(profile.as_ref(), &EntityExtractor::new(), &a, Some("data_staging_and_exfiltration"), None);
        assert!(plain.starts_with("data_staging_and_exfiltration - ") && plain.len() > 33, "{plain}");
    }

    #[test]
    fn nested_and_flat_event_fields_resolve() {
        let event = serde_json::json!({"device": {"hostname": "H"}, "flat.key": "F", "empty": " ", "dash": "-"});
        assert_eq!(event_field_string(&event, "device.hostname").as_deref(), Some("H"));
        assert_eq!(event_field_string(&event, "flat.key").as_deref(), Some("F"));
        assert_eq!(event_field_string(&event, "empty"), None);
        assert_eq!(event_field_string(&event, "dash"), None);
        assert_eq!(field_value_prioritized(&serde_json::json!([{"a": null}, {"b": "second"}]), &["a", "b"]).as_deref(), Some("second"));
        assert_eq!(field_value_prioritized(&serde_json::json!("scalar"), &["a"]), None);
    }
}
