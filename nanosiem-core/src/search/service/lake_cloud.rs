// SPDX-License-Identifier: AGPL-3.0-or-later

//! Canonical OCSF 1.9 implementation of the Cloud investigation view.
//!
//! Flat `cloud_*` keys are a deliberately isolated frontend DTO. Lake queries
//! and stored events use only the exact nested OCSF paths documented below.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};

use super::cloud_dossier::{
    CloudDossier, CloudDossierActionRow, CloudDossierAssumeChain, CloudDossierAssumeHop,
    CloudDossierAuthPosture, CloudDossierErrorCode, CloudDossierErrorRate,
    CloudDossierFacetFilters, CloudDossierFacetItem, CloudDossierFacets, CloudDossierIdentity,
    CloudDossierIp, CloudDossierKeyAction, CloudDossierPosturePrincipal, CloudDossierRegion,
    CloudDossierResource, CloudDossierRisk, CloudDossierRiskFactor, CloudDossierStreamEvent,
    CloudDossierTimeline, CloudDossierTimelineLane, CloudDossierTimelineMarker,
    CloudDossierUserAgent,
};
use super::cloud_overview::{
    CloudOverview, CloudOverviewAccount, CloudOverviewAnomaly, CloudOverviewChange,
    CloudOverviewHeader, CloudOverviewOpenAlerts, CloudOverviewPrincipal,
    CloudOverviewProviderBreakdown, CloudOverviewServiceHealth, CloudOverviewTimeline,
    CloudOverviewTimelineLane, CloudOverviewTimelineMarker,
};
use super::lake_views::lake_product_cursor;
use super::*;
use crate::auth::ScopeSet;
use crate::query::Query;
use crate::risk::{RiskFilter, RiskTimeWindow};
use crate::search::query_processing::CloudCommandInfo;

const LAKE_CLOUD_SCAN_CAP: usize = 50_000;
const LAKE_CLOUD_OVERVIEW_GROUP_CAP: usize = 50_000;

const LAKE_CLOUD_PROJECTION: &[&str] = &[
    "time",
    "metadata.uid",
    "metadata.log_source",
    "activity_name",
    "session.uid",
    "actor.user.name",
    "actor.user.uid",
    "api.operation",
    "api.service.name",
    "cloud.account.uid",
    "cloud.provider",
    "cloud.region",
    "http_request.user_agent",
    "http_response.code",
    "is_mfa",
    "message",
    "resources.uid",
    "resources.name",
    "resources.type",
    "src_endpoint.ip",
    "status",
    "status_detail",
    "status_id",
    "unmapped.error_code",
    "unmapped.mfa_authenticated",
    "user.name",
];

fn cloud_value<'a>(row: &'a Value, path: &str) -> Option<&'a Value> {
    row.get(path)
        .or_else(|| path.split('.').try_fold(row, |value, part| value.get(part)))
}

fn cloud_string(row: &Value, path: &str) -> Option<String> {
    match cloud_value(row, path)? {
        Value::String(value) if !value.is_empty() => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn cloud_u64(row: &Value, path: &str) -> Option<u64> {
    cloud_value(row, path).and_then(Value::as_u64)
}

fn cloud_bool(row: &Value, path: &str) -> Option<bool> {
    cloud_value(row, path).and_then(Value::as_bool)
}

fn safe_cloud_literal(value: &str, description: &str) -> Result<String, SearchError> {
    if value.is_empty()
        || value.len() > 2_048
        || value.chars().any(char::is_control)
        || (value.contains('"') && value.contains('\''))
    {
        return Err(SearchError::SqlValidationError(format!(
            "{description} cannot be represented safely in nPL"
        )));
    }
    Ok(crate::query::npl_quoted_literal(value))
}

fn quoted_cloud_list(values: &[String], description: &str) -> Result<String, SearchError> {
    if values.len() > 100 {
        return Err(SearchError::SqlValidationError(format!(
            "{description} accepts at most 100 values"
        )));
    }
    values
        .iter()
        .map(|value| safe_cloud_literal(value, description))
        .collect::<Result<Vec<_>, _>>()
        .map(|values| values.join(","))
}

fn build_cloud_filter_predicate(
    filters: Option<&CloudEventFilters>,
) -> Result<Option<String>, SearchError> {
    let Some(filters) = filters else {
        return Ok(None);
    };
    let mut clauses = Vec::new();
    for (values, field, description) in [
        (
            &filters.cloud_providers,
            "cloud.provider",
            "cloud provider filter",
        ),
        (
            &filters.cloud_services,
            "api.service.name",
            "cloud service filter",
        ),
        (
            &filters.cloud_regions,
            "cloud.region",
            "cloud region filter",
        ),
        (
            &filters.cloud_account_ids,
            "cloud.account.uid",
            "cloud account filter",
        ),
    ] {
        if let Some(values) = values.as_ref().filter(|values| !values.is_empty()) {
            clauses.push(format!(
                "{field} IN ({})",
                quoted_cloud_list(values, description)?
            ));
        }
    }
    if let Some(values) = filters
        .resource_types
        .as_ref()
        .filter(|values| !values.is_empty())
    {
        clauses.push(format!(
            "({})",
            values
                .iter()
                .map(|value| {
                    safe_cloud_literal(value, "cloud resource type filter")
                        .map(|literal| format!("array_contains(resources.type,{literal})>0"))
                })
                .collect::<Result<Vec<_>, _>>()?
                .join(" OR ")
        ));
    }
    if let Some(values) = filters
        .change_types
        .as_ref()
        .filter(|values| !values.is_empty())
    {
        clauses.push(format!(
            "activity_name IN ({})",
            quoted_cloud_list(values, "cloud change type filter")?
        ));
    }
    if let Some(term) = filters
        .search_text
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        let literal = safe_cloud_literal(term, "cloud search text")?;
        let mut text = [
            "message",
            "api.operation",
            "api.service.name",
            "activity_name",
            "actor.user.name",
            "user.name",
            "src_endpoint.ip",
            "cloud.provider",
            "cloud.region",
            "cloud.account.uid",
            "http_request.user_agent",
        ]
        .iter()
        .map(|field| format!("{field} contains {literal}"))
        .collect::<Vec<_>>();
        for field in ["resources.uid", "resources.name", "resources.type"] {
            text.push(format!("array_contains({field},{literal})>0"));
        }
        clauses.push(format!("({})", text.join(" OR ")));
    }
    Ok((!clauses.is_empty()).then(|| clauses.join(" AND ")))
}

fn apply_cloud_filters(
    base: &str,
    filters: Option<&CloudEventFilters>,
) -> Result<String, SearchError> {
    Ok(match build_cloud_filter_predicate(filters)? {
        Some(filters) => format!("({base}) AND ({filters})"),
        None => base.to_string(),
    })
}

fn root_search(query: &Query) -> Query {
    match query {
        Query::Search(_) => query.clone(),
        Query::Piped { source, .. } => root_search(source),
    }
}

fn canonical_cloud_base(query_str: &str) -> Result<String, SearchError> {
    let parsed = parse_query(query_str).map_err(convert_parse_error)?;
    let root = root_search(&parsed).pretty_print();
    // The Cloud investigation product is the OCSF API Activity class. Using
    // `cloud.provider != ""` as a broad alternate admitted unrelated classes,
    // defeated class pruning, and made unbounded aggregate analysis ambiguous.
    let cloud_predicate = "class_uid=6003";
    if root.trim() == "*" {
        Ok(cloud_predicate.to_string())
    } else {
        Ok(format!("({root}) AND {cloud_predicate}"))
    }
}

fn canonical_cloud_base_from_query(query: &Query) -> String {
    let root = root_search(query).pretty_print();
    let cloud_predicate = "class_uid=6003";
    if root.trim() == "*" {
        cloud_predicate.to_string()
    } else {
        format!("({root}) AND {cloud_predicate}")
    }
}

fn cloud_principal(row: &Value) -> String {
    cloud_string(row, "actor.user.name")
        .or_else(|| cloud_string(row, "user.name"))
        .unwrap_or_default()
}

fn cloud_change_type(row: &Value) -> String {
    cloud_string(row, "activity_name")
        .unwrap_or_else(|| "activity".to_string())
        .to_ascii_lowercase()
}

fn cloud_mfa(row: &Value) -> bool {
    cloud_bool(row, "is_mfa")
        .or_else(|| cloud_bool(row, "unmapped.mfa_authenticated"))
        .unwrap_or(false)
}

fn cloud_resources(row: &Value) -> impl Iterator<Item = Value> {
    if let Some(resources) = cloud_value(row, "resources").and_then(Value::as_array) {
        return resources.clone().into_iter();
    }
    let values = |path: &str| {
        cloud_value(row, path)
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    };
    let uids = values("resources.uid");
    let names = values("resources.name");
    let types = values("resources.type");
    let count = uids.len().max(names.len()).max(types.len());
    (0..count)
        .map(|index| {
            json!({
                "uid": uids.get(index).cloned().unwrap_or(Value::Null),
                "name": names.get(index).cloned().unwrap_or(Value::Null),
                "type": types.get(index).cloned().unwrap_or(Value::Null),
            })
        })
        .collect::<Vec<_>>()
        .into_iter()
}

/// NAN-2370: surface the OCSF threat-intel enrichment attached to the event's
/// source IP.
///
/// The cloud sheets used to read UDM `ioc_src_ip_threat_type` /
/// `ioc_src_ip_malware` / `ioc_src_ip_confidence` off each row. The lake DTO
/// never emitted those keys, so the threat-intel badges were permanently blank
/// on lake — no error, no empty state, just absent, which reads as "this IP is
/// clean" rather than "we never looked".
///
/// The data was there the whole time: the ingest enricher attaches matches to
/// the OCSF `enrichments[]` array (`nanosiem-lake-worker/src/enrichment.rs`,
/// `enrich_iocs`) as `{type: "threat_intelligence", value, data: {ioc_type,
/// malware, confidence, matched_field, ...}}`. Select the entry whose matched
/// value IS this event's source IP — an event can carry enrichments for several
/// observables (a file hash, a domain), and attributing a hash's verdict to the
/// source IP would be a false accusation on a security surface.
///
/// Returned under an OCSF-shaped key rather than reviving the UDM `ioc_src_ip_*`
/// names: UDM is retired, and those names are rejected by the strict validator
/// if a user tries to query what the badge shows them.
fn cloud_src_endpoint_threat(row: &Value) -> Option<Value> {
    let src_ip = cloud_string(row, "src_endpoint.ip")?;
    let enrichments = cloud_value(row, "enrichments")?.as_array()?;

    enrichments.iter().find_map(|enrichment| {
        if enrichment.get("type").and_then(Value::as_str) != Some("threat_intelligence") {
            return None;
        }
        // Match on the enriched value, falling back to the recorded
        // `matched_field` so a producer that omits `value` still attributes
        // correctly. Anything we cannot positively tie to the source IP is
        // skipped rather than guessed.
        let attributed_to_src_ip = enrichment
            .get("value")
            .and_then(Value::as_str)
            .is_some_and(|value| value.eq_ignore_ascii_case(&src_ip))
            || enrichment
                .get("data")
                .and_then(|data| data.get("matched_field"))
                .and_then(Value::as_str)
                .is_some_and(|field| field == "src_endpoint.ip");
        if !attributed_to_src_ip {
            return None;
        }

        let data = enrichment.get("data");
        let threat_type = data
            .and_then(|d| d.get("ioc_type"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        let malware = data
            .and_then(|d| d.get("malware"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        let confidence = data
            .and_then(|d| d.get("confidence"))
            .and_then(Value::as_u64)
            .unwrap_or_default();
        if threat_type.is_empty() && malware.is_empty() && confidence == 0 {
            return None;
        }
        Some(json!({
            "threat_type": threat_type,
            "malware": malware,
            "confidence": confidence,
        }))
    })
}

fn cloud_primary_resource(row: &Value, field: &str) -> String {
    cloud_resources(row)
        .find_map(|resource| {
            resource
                .get(field)
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_default()
}

fn cloud_event_dto(row: &Value) -> Value {
    json!({
        "id": cloud_string(row, "metadata.uid").unwrap_or_default(),
        "timestamp": cloud_string(row, "time").unwrap_or_default(),
        "cloud_provider": cloud_string(row, "cloud.provider").unwrap_or_default(),
        "cloud_service": cloud_string(row, "api.service.name").unwrap_or_default(),
        "cloud_region": cloud_string(row, "cloud.region").unwrap_or_default(),
        "cloud_account_id": cloud_string(row, "cloud.account.uid").unwrap_or_default(),
        "resource_id": cloud_primary_resource(row, "uid"),
        "resource_name": cloud_primary_resource(row, "name"),
        "resource_type": cloud_primary_resource(row, "type"),
        "change_type": cloud_change_type(row),
        "mfa_used": if cloud_mfa(row) { 1 } else { 0 },
        "user": cloud_principal(row),
        "src_ip": cloud_string(row, "src_endpoint.ip").unwrap_or_default(),
        "http_user_agent": cloud_string(row, "http_request.user_agent").unwrap_or_default(),
        "source_type": cloud_string(row, "metadata.log_source").unwrap_or_default(),
        "event_type": cloud_string(row, "api.operation").or_else(|| cloud_string(row, "activity_name")).unwrap_or_default(),
        "status": cloud_string(row, "status").unwrap_or_default(),
        "http_status_code": cloud_u64(row, "http_response.code").unwrap_or_default(),
        // NAN-2370: OCSF threat-intel verdict for the source IP, or null when
        // the IP carries none. `null` is meaningful here — it lets the sheet
        // distinguish "no IOC match" from "this build never supplied one".
        "src_endpoint_threat": cloud_src_endpoint_threat(row).unwrap_or(Value::Null),
        // NAN-2370: geo/ASN for the source IP from its OCSF-native homes. The
        // sheets previously read UDM `enriched_src_country_code` /
        // `enriched_src_asn` / `enriched_src_as_name`, which this DTO never
        // emitted and which the strict validator now rejects outright — so the
        // country and ASN badges were as silently blank as the IOC ones.
        "src_endpoint_geo": json!({
            "country": cloud_string(row, "src_endpoint.location.country").unwrap_or_default(),
            "asn": cloud_u64(row, "src_endpoint.autonomous_system.number").unwrap_or_default(),
            "as_name": cloud_string(row, "src_endpoint.autonomous_system.name").unwrap_or_default(),
        }),
        "details": row,
    })
}

/// The multi-pass ranking the streaming dossier replaced; kept for the
/// equivalence oracle in `lake_cloud_dossier_stream_tests.rs`.
#[cfg(test)]
fn ranked(values: impl Iterator<Item = String>, cap: usize) -> Vec<(String, u64)> {
    let mut counts = BTreeMap::<String, u64>::new();
    for value in values.filter(|value| !value.is_empty()) {
        *counts.entry(value).or_default() += 1;
    }
    let mut values = counts.into_iter().collect::<Vec<_>>();
    values.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    values.truncate(cap);
    values
}

fn cloud_group_counts(rows: &[Value], field: &str) -> Vec<(String, u64)> {
    rows.iter()
        .filter_map(|row| {
            let value = cloud_string(row, field)?;
            let count = cloud_u64(row, "event_count").unwrap_or_default();
            (!value.is_empty()).then_some((value, count))
        })
        .collect()
}

#[path = "lake_cloud_summary.rs"]
mod correlated_summary;
use correlated_summary::CLOUD_SUMMARY_GROUP_CAP;

fn cloud_facets_from_grouped(
    providers: &[Value],
    services: &[Value],
    regions: &[Value],
    accounts: &[Value],
    resource_types: &[Value],
    change_types: &[Value],
) -> CloudFacets {
    CloudFacets {
        cloud_provider: cloud_group_counts(providers, "cloud.provider"),
        cloud_service: cloud_group_counts(services, "api.service.name"),
        cloud_region: cloud_group_counts(regions, "cloud.region"),
        cloud_account_id: cloud_group_counts(accounts, "cloud.account.uid"),
        resource_type: cloud_group_counts(resource_types, "resources.type"),
        change_type: cloud_group_counts(change_types, "activity_name"),
    }
}

fn cloud_resource_rollup_from_grouped(rows: &[Value]) -> Vec<Value> {
    rows.iter()
        .filter_map(|row| {
            let resource_id =
                cloud_string(row, "resource_id").or_else(|| cloud_string(row, "resources.uid"))?;
            let change_types = match cloud_value(row, "change_types") {
                Some(Value::Array(values)) => values.clone(),
                Some(Value::String(values)) => values
                    .split(',')
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(|value| Value::String(value.to_string()))
                    .collect(),
                _ => Vec::new(),
            };
            (!resource_id.is_empty()).then(|| {
                json!({
                    "resource_id": resource_id,
                    "resource_name": cloud_string(row, "resource_name")
                        .or_else(|| cloud_string(row, "resources.name"))
                        .unwrap_or_default(),
                    "resource_type": cloud_string(row, "resource_type")
                        .or_else(|| cloud_string(row, "resources.type"))
                        .unwrap_or_default(),
                    "event_count": cloud_u64(row, "event_count").unwrap_or_default(),
                    "first_seen": cloud_string(row, "first_seen").unwrap_or_default(),
                    "last_seen": cloud_string(row, "last_seen").unwrap_or_default(),
                    "change_types": change_types,
                })
            })
        })
        .collect()
}

fn cloud_user_activity_from_grouped(rows: &[Value]) -> Vec<CloudUserActivity> {
    rows.iter()
        .filter_map(|row| {
            let user = cloud_string(row, "cloud_user")?;
            if user.is_empty() {
                return None;
            }
            let event_count = cloud_u64(row, "event_count").unwrap_or_default();
            let distinct_services = cloud_u64(row, "distinct_services").unwrap_or_default();
            let distinct_regions = cloud_u64(row, "distinct_regions").unwrap_or_default();
            let distinct_ips = cloud_u64(row, "distinct_ips").unwrap_or_default();
            let fail_count = cloud_u64(row, "fail_count").unwrap_or_default();
            let permission_change_count =
                cloud_u64(row, "permission_change_count").unwrap_or_default();
            let delete_count = cloud_u64(row, "delete_count").unwrap_or_default();
            let mfa_count = cloud_u64(row, "mfa_count").unwrap_or_default();
            let no_mfa_count = event_count.saturating_sub(mfa_count);
            let mut risk_indicators = Vec::new();
            if event_count > 0 && fail_count as f64 / event_count as f64 > 0.3 {
                risk_indicators.push("high_fail_rate".to_string());
            }
            if permission_change_count > 0 && fail_count > 0 {
                risk_indicators.push("privilege_escalation".to_string());
            }
            if distinct_regions > 2 {
                risk_indicators.push("multi_region".to_string());
            }
            if no_mfa_count > 0 {
                risk_indicators.push("no_mfa".to_string());
            }
            if delete_count > 5 {
                risk_indicators.push("high_delete".to_string());
            }
            Some(CloudUserActivity {
                user,
                event_count,
                distinct_services,
                distinct_regions,
                distinct_ips,
                fail_count,
                permission_change_count,
                delete_count,
                mfa_count,
                no_mfa_count,
                risk_indicators,
            })
        })
        .collect()
}

fn cloud_user_activity(rows: &[Value]) -> Vec<CloudUserActivity> {
    #[derive(Default)]
    struct Activity {
        events: u64,
        services: BTreeSet<String>,
        regions: BTreeSet<String>,
        ips: BTreeSet<String>,
        failures: u64,
        permission_changes: u64,
        deletes: u64,
        mfa: u64,
        no_mfa: u64,
    }
    let mut users = BTreeMap::<String, Activity>::new();
    for row in rows {
        let user = cloud_principal(row);
        if user.is_empty() {
            continue;
        }
        let activity = users.entry(user).or_default();
        activity.events += 1;
        if let Some(value) = cloud_string(row, "api.service.name") {
            activity.services.insert(value);
        }
        if let Some(value) = cloud_string(row, "cloud.region") {
            activity.regions.insert(value);
        }
        if let Some(value) = cloud_string(row, "src_endpoint.ip") {
            activity.ips.insert(value);
        }
        let failed = cloud_string(row, "status")
            .is_some_and(|value| value.eq_ignore_ascii_case("failure"))
            || cloud_u64(row, "http_response.code").is_some_and(|value| value >= 400);
        activity.failures += u64::from(failed);
        let change = cloud_change_type(row);
        activity.permission_changes +=
            u64::from(change.contains("permission") || change.contains("privilege"));
        activity.deletes += u64::from(change == "delete");
        if cloud_mfa(row) {
            activity.mfa += 1;
        } else {
            activity.no_mfa += 1;
        }
    }
    let mut values = users
        .into_iter()
        .map(|(user, row)| {
            let mut risk_indicators = Vec::new();
            if row.events > 0 && row.failures as f64 / row.events as f64 > 0.3 {
                risk_indicators.push("high_fail_rate".to_string());
            }
            if row.permission_changes > 0 && row.failures > 0 {
                risk_indicators.push("privilege_escalation".to_string());
            }
            if row.regions.len() > 2 {
                risk_indicators.push("multi_region".to_string());
            }
            if row.no_mfa > 0 {
                risk_indicators.push("no_mfa".to_string());
            }
            if row.deletes > 5 {
                risk_indicators.push("high_delete".to_string());
            }
            CloudUserActivity {
                user,
                event_count: row.events,
                distinct_services: row.services.len() as u64,
                distinct_regions: row.regions.len() as u64,
                distinct_ips: row.ips.len() as u64,
                fail_count: row.failures,
                permission_change_count: row.permission_changes,
                delete_count: row.deletes,
                mfa_count: row.mfa,
                no_mfa_count: row.no_mfa,
                risk_indicators,
            }
        })
        .collect::<Vec<_>>();
    values.sort_by(|left, right| {
        right
            .event_count
            .cmp(&left.event_count)
            .then_with(|| left.user.cmp(&right.user))
    });
    values.truncate(100);
    values
}

fn cloud_session_summary(rows: &[Value]) -> CloudUserSessionSummary {
    let activity = cloud_user_activity(rows).into_iter().next();
    let services = rows
        .iter()
        .filter_map(|row| cloud_string(row, "api.service.name"))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let regions = rows
        .iter()
        .filter_map(|row| cloud_string(row, "cloud.region"))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let ips = rows
        .iter()
        .filter_map(|row| cloud_string(row, "src_endpoint.ip"))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    match activity {
        Some(row) => CloudUserSessionSummary {
            services,
            regions,
            ips,
            event_count: row.event_count,
            fail_count: row.fail_count,
            permission_change_count: row.permission_change_count,
            delete_count: row.delete_count,
            has_no_mfa: row.no_mfa_count > 0,
            risk_indicators: row.risk_indicators,
        },
        None => CloudUserSessionSummary {
            services,
            regions,
            ips,
            event_count: 0,
            fail_count: 0,
            permission_change_count: 0,
            delete_count: 0,
            has_no_mfa: false,
            risk_indicators: Vec::new(),
        },
    }
}

fn cloud_operation(row: &Value) -> String {
    cloud_string(row, "api.operation")
        .or_else(|| cloud_string(row, "activity_name"))
        .unwrap_or_default()
}

fn cloud_service(row: &Value) -> String {
    cloud_string(row, "api.service.name").unwrap_or_default()
}

fn cloud_account(row: &Value) -> String {
    cloud_string(row, "cloud.account.uid").unwrap_or_default()
}

fn cloud_provider(row: &Value) -> String {
    cloud_string(row, "cloud.provider").unwrap_or_default()
}

fn cloud_region(row: &Value) -> String {
    cloud_string(row, "cloud.region").unwrap_or_default()
}

fn cloud_time(row: &Value) -> String {
    cloud_string(row, "last_seen")
        .or_else(|| cloud_string(row, "time"))
        .unwrap_or_default()
}

fn cloud_error(row: &Value) -> bool {
    // NAN-3465: OCSF `status_id` 2 (Failure) is authoritative even when the
    // producer left the `status` caption empty.
    cloud_u64(row, "http_response.code").is_some_and(|code| code >= 400)
        || cloud_string(row, "status_id").as_deref() == Some("2")
        || cloud_string(row, "status").is_some_and(|status| {
            let status = status.to_ascii_lowercase();
            status.contains("fail") || status.contains("error") || status.contains("denied")
        })
}

fn cloud_denied(row: &Value) -> bool {
    [
        cloud_string(row, "status"),
        cloud_string(row, "status_detail"),
        cloud_string(row, "unmapped.error_code"),
        cloud_string(row, "message"),
    ]
    .into_iter()
    .flatten()
    .any(|value| {
        let value = value.to_ascii_lowercase();
        value.contains("denied") || value.contains("unauthorized") || value.contains("forbidden")
    })
}

fn cloud_error_label(row: &Value) -> Option<String> {
    cloud_string(row, "status_detail")
        .or_else(|| cloud_string(row, "unmapped.error_code"))
        .or_else(|| cloud_error(row).then(|| "request_failed".to_string()))
}

fn cloud_sensitive(row: &Value) -> bool {
    let operation = cloud_operation(row).to_ascii_lowercase();
    [
        "assumerole",
        "createaccesskey",
        "attach",
        "putpolicy",
        "putrolepolicy",
        "updateassumerolepolicy",
        "authorize",
        "delete",
        "terminate",
        "schedulekeydeletion",
        "putbucketpolicy",
        "getsecretvalue",
    ]
    .iter()
    .any(|needle| operation.contains(needle))
}

fn lake_cloud_band(score: u32) -> String {
    match score {
        80.. => "critical",
        60..=79 => "high",
        35..=59 => "medium",
        _ => "low",
    }
    .to_string()
}

fn lake_cloud_window_label(time_range: &TimeRange) -> String {
    let seconds = (time_range.end - time_range.start).num_seconds().max(0);
    if seconds <= 3_600 {
        "last 1h".to_string()
    } else if seconds <= 26 * 3_600 {
        format!("last {}h", (seconds / 3_600).max(1))
    } else {
        format!("last {}d", (seconds / 86_400).max(1))
    }
}

fn lake_cloud_hhmm(value: &str) -> String {
    value.get(11..16).unwrap_or(value).to_string()
}

fn cloud_bucket(row: &Value, time_range: &TimeRange, buckets: u32) -> u32 {
    let value = cloud_time(row);
    if value.is_empty() {
        return 0;
    }
    let timestamp = chrono::DateTime::parse_from_rfc3339(&value)
        .map(|value| value.timestamp())
        .or_else(|_| {
            chrono::NaiveDateTime::parse_from_str(&value, "%Y-%m-%d %H:%M:%S%.f")
                .map(|value| value.and_utc().timestamp())
        })
        .unwrap_or(time_range.start.timestamp());
    let span = (time_range.end - time_range.start).num_seconds().max(1);
    let offset = (timestamp - time_range.start.timestamp()).clamp(0, span - 1);
    ((offset as i128 * buckets as i128) / span as i128) as u32
}

fn cloud_principal_type(principal: &str, row: Option<&Value>) -> String {
    let uid = row
        .and_then(|row| {
            cloud_string(row, "actor.user.uid").or_else(|| cloud_string(row, "principal_uid"))
        })
        .unwrap_or_default()
        .to_ascii_lowercase();
    let principal = principal.to_ascii_lowercase();
    if uid.contains(":assumed-role/") || principal.contains("assumed-role") {
        "assumed_role"
    } else if uid.contains(":role/") || principal.ends_with("role") {
        "role"
    } else if principal.contains("serviceaccount") || principal.contains("service-account") {
        "service_account"
    } else {
        "iam_user"
    }
    .to_string()
}

#[cfg(test)]
fn lake_cloud_facet(values: impl Iterator<Item = String>) -> Vec<CloudDossierFacetItem> {
    ranked(values, 20)
        .into_iter()
        .map(|(name, count)| CloudDossierFacetItem {
            name,
            count,
            ..Default::default()
        })
        .collect()
}

/// NAN-3078: the Cloud dossier as a single-pass fold over newest-first event
/// rows. The interactive lane pushes its bounded page; the durable lane
/// streams an unbounded event set through it batch by batch, so its memory is
/// the rollup state (distinct values plus a bounded head of rows), never the
/// event set.
pub struct CloudDossierAccumulator {
    principal: String,
    filters: CloudDossierFacetFilters,
    time_range: TimeRange,
    rows: u64,
    first_row: Option<Value>,
    first_seen: Option<String>,
    last_seen: Option<String>,
    user_agents: BTreeMap<String, u64>,
    ips: BTreeMap<String, (u64, String, String)>,
    all_mfa: bool,
    console: bool,
    assumed_roles: BTreeSet<String>,
    providers: BTreeMap<String, u64>,
    services: BTreeMap<String, u64>,
    regions: BTreeMap<String, u64>,
    accounts: BTreeMap<String, u64>,
    resource_types: BTreeMap<String, u64>,
    change_types: BTreeMap<String, u64>,
    assume_rows: Vec<Value>,
    sensitive_rows: Vec<Value>,
    points: BTreeMap<(u32, String), u64>,
    actions: BTreeMap<(String, String), (u64, u64, String)>,
    resources: BTreeMap<String, CloudDossierResourceRollup>,
    privileged_calls: u64,
    failed: u64,
    denied: u64,
    errors: BTreeMap<String, u64>,
    stream_rows: Vec<Value>,
}

#[derive(Default)]
struct CloudDossierResourceRollup {
    kind: String,
    account: String,
    changes: u64,
    last_at: String,
    actions: BTreeSet<String>,
    spark: Vec<u64>,
    sensitive: bool,
}

const CLOUD_DOSSIER_HOPS: usize = 12;
const CLOUD_DOSSIER_KEY_ACTIONS: usize = 20;
const CLOUD_DOSSIER_STREAM: usize = 200;

fn count_nonempty(counts: &mut BTreeMap<String, u64>, value: String) {
    if !value.is_empty() {
        *counts.entry(value).or_default() += 1;
    }
}

/// [`ranked`] over counts already folded.
fn ranked_counts(counts: &BTreeMap<String, u64>, cap: usize) -> Vec<(String, u64)> {
    let mut values = counts
        .iter()
        .map(|(value, count)| (value.clone(), *count))
        .collect::<Vec<_>>();
    values.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    values.truncate(cap);
    values
}

fn facet_counts(counts: &BTreeMap<String, u64>) -> Vec<CloudDossierFacetItem> {
    ranked_counts(counts, 20)
        .into_iter()
        .map(|(name, count)| CloudDossierFacetItem {
            name,
            count,
            ..Default::default()
        })
        .collect()
}

impl CloudDossierAccumulator {
    pub fn new(
        principal: &str,
        filters: &CloudDossierFacetFilters,
        time_range: &TimeRange,
    ) -> Self {
        Self {
            principal: principal.to_string(),
            filters: filters.clone(),
            time_range: time_range.clone(),
            rows: 0,
            first_row: None,
            first_seen: None,
            last_seen: None,
            user_agents: BTreeMap::new(),
            ips: BTreeMap::new(),
            all_mfa: true,
            console: false,
            assumed_roles: BTreeSet::new(),
            providers: BTreeMap::new(),
            services: BTreeMap::new(),
            regions: BTreeMap::new(),
            accounts: BTreeMap::new(),
            resource_types: BTreeMap::new(),
            change_types: BTreeMap::new(),
            assume_rows: Vec::new(),
            sensitive_rows: Vec::new(),
            points: BTreeMap::new(),
            actions: BTreeMap::new(),
            resources: BTreeMap::new(),
            privileged_calls: 0,
            failed: 0,
            denied: 0,
            errors: BTreeMap::new(),
            stream_rows: Vec::new(),
        }
    }

    /// Rows pushed so far that matched the facet filters.
    pub fn rows(&self) -> u64 {
        self.rows
    }

    /// Fold one event row. Rows must arrive newest first (the dossier event
    /// query sorts `-time`): the identity row, hops, key actions and stream
    /// are the newest matching rows.
    pub fn push(&mut self, row: Value) {
        if !cloud_rows_match_dossier_filters(&row, &self.filters) {
            return;
        }
        self.rows += 1;
        let time = cloud_time(&row);
        if !time.is_empty() {
            if self.first_seen.as_ref().is_none_or(|first| time < *first) {
                self.first_seen = Some(time.clone());
            }
            if self.last_seen.as_ref().is_none_or(|last| time > *last) {
                self.last_seen = Some(time.clone());
            }
        }
        if let Some(agent) = cloud_string(&row, "http_request.user_agent") {
            count_nonempty(&mut self.user_agents, agent);
        }
        if let Some(ip) = cloud_string(&row, "src_endpoint.ip").filter(|value| !value.is_empty()) {
            let rollup = self.ips.entry(ip).or_default();
            rollup.0 += 1;
            if rollup.1.is_empty() || time < rollup.1 {
                rollup.1 = time.clone();
            }
            if time > rollup.2 {
                rollup.2 = time.clone();
            }
        }
        self.all_mfa &= cloud_mfa(&row);
        let operation = cloud_operation(&row);
        let lower_operation = operation.to_ascii_lowercase();
        self.console |= lower_operation.contains("consolelogin")
            || cloud_string(&row, "http_request.user_agent")
                .is_some_and(|value| value.to_ascii_lowercase().contains("mozilla"));
        let assume = operation.eq_ignore_ascii_case("AssumeRole");
        if assume {
            self.assumed_roles.extend(cloud_resources(&row).filter_map(|resource| {
                resource
                    .get("name")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            }));
        }
        let service = cloud_service(&row);
        count_nonempty(&mut self.providers, cloud_provider(&row));
        count_nonempty(&mut self.services, service.clone());
        count_nonempty(&mut self.regions, cloud_region(&row));
        count_nonempty(&mut self.accounts, cloud_account(&row));
        for resource in cloud_resources(&row) {
            if let Some(kind) = resource.get("type").and_then(Value::as_str) {
                count_nonempty(&mut self.resource_types, kind.to_string());
            }
        }
        count_nonempty(&mut self.change_types, cloud_change_type(&row));
        *self
            .points
            .entry((cloud_bucket(&row, &self.time_range, 45), service.clone()))
            .or_default() += 1;
        let sensitive = cloud_sensitive(&row);
        let error = cloud_error(&row);
        if !operation.is_empty() {
            let rollup = self
                .actions
                .entry((operation.clone(), service.clone()))
                .or_default();
            rollup.0 += 1;
            rollup.1 += error as u64;
            rollup.2 = cloud_principal(&row);
        }
        for resource in cloud_resources(&row) {
            let Some(uid) = resource
                .get("uid")
                .or_else(|| resource.get("name"))
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
            else {
                continue;
            };
            let rollup = self
                .resources
                .entry(uid.to_string())
                .or_insert_with(|| CloudDossierResourceRollup {
                    spark: vec![0; 8],
                    ..Default::default()
                });
            rollup.kind = resource
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            rollup.account = cloud_account(&row);
            rollup.changes += 1;
            if time > rollup.last_at {
                rollup.last_at = time.clone();
            }
            rollup.actions.insert(operation.clone());
            rollup.sensitive |= sensitive;
            let bucket = cloud_bucket(&row, &self.time_range, 8) as usize;
            if let Some(slot) = rollup.spark.get_mut(bucket.min(7)) {
                *slot += 1;
            }
        }
        self.privileged_calls += sensitive as u64;
        if error {
            self.failed += 1;
            *self
                .errors
                .entry(cloud_error_label(&row).unwrap_or_else(|| "request_failed".to_string()))
                .or_default() += 1;
        }
        self.denied += cloud_denied(&row) as u64;
        if assume && self.assume_rows.len() < CLOUD_DOSSIER_HOPS {
            self.assume_rows.push(row.clone());
        }
        if sensitive && self.sensitive_rows.len() < CLOUD_DOSSIER_KEY_ACTIONS {
            self.sensitive_rows.push(row.clone());
        }
        if self.stream_rows.len() < CLOUD_DOSSIER_STREAM {
            self.stream_rows.push(row.clone());
        }
        if self.first_row.is_none() {
            self.first_row = Some(row);
        }
    }

    pub fn finish(self, risk_summary: Option<(i32, Option<String>)>) -> CloudDossier {
        let principal = self.principal.as_str();
        let time_range = &self.time_range;
        let any_rows = self.rows > 0;
        let first_seen = self.first_seen.clone();
        let last_seen = self.last_seen.clone();
        let first_row = self.first_row.as_ref();
        let account = first_row
            .map(cloud_account)
            .filter(|value| !value.is_empty());
        let arn = first_row
            .and_then(|row| cloud_string(row, "actor.user.uid"))
            .filter(|value| !value.is_empty());

        let user_agents = ranked_counts(&self.user_agents, 10)
            .into_iter()
            .map(|(ua, count)| {
                let lower = ua.to_ascii_lowercase();
                let kind = if lower.contains("terraform") {
                    "terraform"
                } else if lower.contains("aws-cli")
                    || lower.contains("gcloud")
                    || lower.contains("azure-cli")
                {
                    "cli"
                } else if lower.contains("sdk") || lower.contains("boto") {
                    "sdk"
                } else if lower.contains("mozilla")
                    || lower.contains("chrome")
                    || lower.contains("safari")
                {
                    "browser"
                } else {
                    "other"
                };
                CloudDossierUserAgent {
                    ua,
                    kind: kind.to_string(),
                    count,
                }
            })
            .collect::<Vec<_>>();

        let mut ips = self.ips.into_iter().collect::<Vec<_>>();
        ips.sort_by(|left, right| right.1 .0.cmp(&left.1 .0));
        let ips = ips
            .into_iter()
            .take(20)
            .map(|(ip, (count, first, last))| CloudDossierIp {
                ip,
                first_seen: Some(first).filter(|value| !value.is_empty()),
                last_seen: Some(last).filter(|value| !value.is_empty()),
                event_count: count,
                ..Default::default()
            })
            .collect::<Vec<_>>();

        let mfa = any_rows.then_some(self.all_mfa);
        let console = self.console;
        let identity = CloudDossierIdentity {
            id: principal.to_string(),
            principal_type: cloud_principal_type(principal, first_row),
            arn,
            account: account.clone(),
            first_seen: first_seen.clone(),
            last_seen: last_seen.clone(),
            mfa,
            console,
            api_only: !console,
            assumed_roles: self.assumed_roles.into_iter().collect(),
            user_agents,
            ips: ips.clone(),
            ..Default::default()
        };

        let risk_score = risk_summary
            .as_ref()
            .map(|(score, _)| score.max(&0).to_owned() as u32)
            .unwrap_or(0)
            .min(100);
        let risk = CloudDossierRisk {
            score: risk_score,
            band: lake_cloud_band(risk_score),
            factors: risk_summary
                .and_then(|(_, rule)| rule)
                .map(|rule| {
                    vec![CloudDossierRiskFactor {
                        w: risk_score,
                        label: rule,
                        detail: "latest matching detection".to_string(),
                    }]
                })
                .unwrap_or_default(),
            ..Default::default()
        };

        let facets = CloudDossierFacets {
            provider: facet_counts(&self.providers),
            service: facet_counts(&self.services),
            region: facet_counts(&self.regions),
            account: facet_counts(&self.accounts),
            resource_type: facet_counts(&self.resource_types),
            change_type: facet_counts(&self.change_types),
        };

        let hops = self
            .assume_rows
            .iter()
            .map(|row| CloudDossierAssumeHop {
                at: cloud_time(row),
                session_name: cloud_string(row, "session.uid").unwrap_or_default(),
                via: "sts:AssumeRole".to_string(),
                to_label: cloud_primary_resource(row, "name"),
                to_account: Some(cloud_account(row)).filter(|value| !value.is_empty()),
                calls: 1,
                sensitive: true,
                ..Default::default()
            })
            .collect::<Vec<_>>();
        let key_actions = self
            .sensitive_rows
            .iter()
            .map(|row| CloudDossierKeyAction {
                at: cloud_time(row),
                role: cloud_principal(row),
                action: cloud_operation(row),
                target: cloud_primary_resource(row, "name"),
                severity: if cloud_denied(row) { "high" } else { "medium" }.to_string(),
                detail: cloud_string(row, "message"),
            })
            .collect::<Vec<_>>();
        let assume_chain = CloudDossierAssumeChain {
            origin_label: principal.to_string(),
            origin_account: account.clone(),
            origin_ip: ips.first().map(|row| row.ip.clone()),
            origin_first_at: first_seen.clone(),
            hops,
            key_actions: key_actions.clone(),
            ..Default::default()
        };

        let service_rank = ranked_counts(&self.services, 5);
        let lanes = service_rank
            .iter()
            .map(|(service, _)| CloudDossierTimelineLane {
                id: service.clone(),
                label: service.clone(),
                accent: lake_cloud_service_accent(service),
            })
            .collect::<Vec<_>>();
        let lane_ids = lanes
            .iter()
            .map(|lane| lane.id.as_str())
            .collect::<BTreeSet<_>>();
        let timeline = CloudDossierTimeline {
            label: lake_cloud_window_label(time_range),
            buckets: 45,
            lanes: lanes.clone(),
            points: self
                .points
                .iter()
                .filter(|((_, service), _)| lane_ids.contains(service.as_str()))
                .map(|((bucket, service), count)| json!([bucket, service, (*count).min(3)]))
                .collect(),
            markers: key_actions
                .iter()
                .take(6)
                .map(|action| CloudDossierTimelineMarker {
                    at: 44,
                    label: action.action.clone(),
                    severity: action.severity.clone(),
                })
                .collect(),
        };

        let regions = ranked_counts(&self.regions, 20)
            .into_iter()
            .map(|(id, count)| CloudDossierRegion {
                id,
                count,
                ..Default::default()
            })
            .collect::<Vec<_>>();

        let mut top_actions = self.actions.into_iter().collect::<Vec<_>>();
        top_actions.sort_by(|left, right| right.1 .0.cmp(&left.1 .0));
        let top_actions = top_actions
            .into_iter()
            .take(16)
            .map(|((name, service), (count, errors, principal))| CloudDossierActionRow {
                sensitive: cloud_sensitive(&json!({"api": {"operation": name}})),
                anomaly: errors > 0,
                name,
                service,
                count,
                errors,
                principal: Some(principal).filter(|value| !value.is_empty()),
            })
            .collect::<Vec<_>>();

        let mut top_resources = self.resources.into_iter().collect::<Vec<_>>();
        top_resources.sort_by(|left, right| right.1.changes.cmp(&left.1.changes));
        let top_resources = top_resources
            .into_iter()
            .take(8)
            .map(|(arn, rollup)| CloudDossierResource {
                arn,
                r#type: rollup.kind,
                account: rollup.account,
                changes: rollup.changes,
                last_at: rollup.last_at,
                severity: if rollup.sensitive { "medium" } else { "low" }.to_string(),
                spark: rollup.spark,
                touched: rollup.actions.into_iter().collect(),
            })
            .collect::<Vec<_>>();

        let privileged_calls = self.privileged_calls;
        let auth_posture = CloudDossierAuthPosture {
            total_principals: any_rows as u64,
            with_mfa: (mfa == Some(true)) as u64,
            without_mfa: (mfa == Some(false)) as u64,
            privileged_without_mfa: (mfa == Some(false) && privileged_calls > 0) as u64,
            privileged_calls_without_mfa: if mfa == Some(false) {
                privileged_calls
            } else {
                0
            },
            console_logins: console as u64,
            console_logins_without_mfa: (console && mfa == Some(false)) as u64,
            api_key_only_principals: (any_rows && !console) as u64,
            principals: any_rows
                .then(|| CloudDossierPosturePrincipal {
                    name: principal.to_string(),
                    mfa,
                    privileged: privileged_calls > 0,
                    last_call: last_seen.clone(),
                    privileged_calls,
                    anomaly: mfa == Some(false) && privileged_calls > 0,
                    is_role: identity.principal_type.contains("role"),
                    ..Default::default()
                })
                .into_iter()
                .collect(),
            ..Default::default()
        };

        let failed = self.failed;
        let mut error_counts = self.errors.into_iter().collect::<Vec<_>>();
        error_counts.sort_by(|left, right| right.1.cmp(&left.1));
        let error_rate = CloudDossierErrorRate {
            events_total: self.rows,
            events_allowed: self.rows - failed,
            events_failed: failed,
            events_denied: self.denied,
            top_errors: error_counts
                .into_iter()
                .take(5)
                .map(|(code, count)| CloudDossierErrorCode {
                    code,
                    count,
                    pct: count as f64 / failed.max(1) as f64,
                    severity: if count * 2 >= failed {
                        "high"
                    } else {
                        "medium"
                    }
                    .to_string(),
                })
                .collect(),
        };

        let stream = self
            .stream_rows
            .into_iter()
            .enumerate()
            .map(|(index, row)| {
                let service = cloud_service(&row);
                let operation = cloud_operation(&row);
                let change = cloud_change_type(&row);
                let event_type = if service.eq_ignore_ascii_case("sts")
                    || operation.to_ascii_lowercase().contains("login")
                {
                    "AUTH"
                } else if cloud_sensitive(&row) {
                    "PERM"
                } else if operation.to_ascii_lowercase().starts_with("get")
                    || operation.to_ascii_lowercase().starts_with("list")
                    || operation.to_ascii_lowercase().starts_with("describe")
                {
                    "READ"
                } else {
                    "WRITE"
                };
                CloudDossierStreamEvent {
                    id: cloud_string(&row, "metadata.uid")
                        .unwrap_or_else(|| format!("cloud-event-{index}")),
                    ts: cloud_time(&row),
                    r#type: event_type.to_string(),
                    event_name: operation,
                    service,
                    user: cloud_principal(&row),
                    account: cloud_account(&row),
                    region: cloud_region(&row),
                    source_ip: cloud_string(&row, "src_endpoint.ip").unwrap_or_default(),
                    resource: cloud_primary_resource(&row, "name"),
                    error_code: cloud_error_label(&row),
                    summary: json!({
                        "change_type": change,
                        "provider": cloud_provider(&row),
                        "status": cloud_string(&row, "status"),
                    }),
                    interesting: cloud_error(&row) || cloud_sensitive(&row),
                    detail: row,
                }
            })
            .collect::<Vec<_>>();

        CloudDossier {
            bounded_preview: false,
            identity,
            risk,
            facets,
            assume_chain,
            timeline,
            regions,
            top_actions,
            top_resources,
            auth_posture,
            error_rate,
            stream,
            window_label: lake_cloud_window_label(time_range),
            durable_job: None,
        }
    }
}

fn lake_cloud_service_accent(service: &str) -> String {
    match service.to_ascii_lowercase().as_str() {
        "iam" => "oklch(65% 0.19 30)",
        "sts" => "oklch(68% 0.14 30)",
        "s3" => "oklch(66% 0.16 170)",
        "kms" => "oklch(68% 0.13 290)",
        "ec2" => "oklch(66% 0.13 240)",
        "lambda" => "oklch(66% 0.15 30)",
        _ => "oklch(65% 0.05 250)",
    }
    .to_string()
}

fn cloud_rows_match_dossier_filters(row: &Value, filters: &CloudDossierFacetFilters) -> bool {
    let contains = |values: &[String], candidate: &str| {
        values.is_empty()
            || values
                .iter()
                .any(|value| value.eq_ignore_ascii_case(candidate))
    };
    contains(&filters.services, &cloud_service(row))
        && contains(&filters.regions, &cloud_region(row))
        && contains(&filters.accounts, &cloud_account(row))
        && contains(&filters.change_types, &cloud_change_type(row))
        && (filters.resource_types.is_empty()
            || cloud_resources(row).any(|resource| {
                resource
                    .get("type")
                    .and_then(Value::as_str)
                    .is_some_and(|kind| contains(&filters.resource_types, kind))
            }))
}

struct CloudOverviewQueries {
    identities: String,
    services: String,
    changes: String,
    denied: String,
}

fn cloud_overview_queries(base: &str) -> CloudOverviewQueries {
    CloudOverviewQueries {
        // NAN-3059: `actor.user.uid` is carried as a value, not a group key.
        // For assumed roles it is the per-session ARN, so grouping by it made
        // one group per STS session: a 24h CloudTrail window on the lean
        // tenant produced >50k identity groups (1h: ~16k), overflowed the
        // interactive envelope and fell to the durable lane. The principal is
        // `actor.user.name`; the uid only classifies its type.
        identities: format!(
            "{base} | stats count() as events, max(time) as last_seen, \
             latest(actor.user.uid) as principal_uid by \
             cloud.provider, cloud.account.uid, cloud.region, actor.user.name, \
             user.name | sort -last_seen"
        ),
        services: format!(
            "{base} | stats count() as events, max(time) as last_seen by \
             api.service.name, cloud.account.uid, status, status_detail, \
             unmapped.error_code, http_response.code | sort -last_seen"
        ),
        changes: format!(
            "({base}) AND (api.operation!=\"\" OR activity_name!=\"\") \
             | stats count() as events, max(time) as last_seen by api.operation, \
             activity_name, actor.user.name, user.name, cloud.account.uid, \
             api.service.name, status, status_detail, unmapped.error_code \
             | sort -last_seen | head 200"
        ),
        denied: format!(
            "({base}) AND (message contains \"denied\" OR message contains \
             \"unauthorized\" OR message contains \"forbidden\" OR \
             status_detail contains \"denied\" OR unmapped.error_code contains \
             \"denied\") | stats count() as events"
        ),
    }
}

fn cloud_overview_base(
    provider_filter: Option<&str>,
    account_filter: Option<&str>,
) -> Result<String, SearchError> {
    let mut base = "class_uid=6003".to_string();
    if let Some(provider) = provider_filter.filter(|value| !value.is_empty()) {
        base.push_str(&format!(
            " AND lower(cloud.provider)=lower({})",
            safe_cloud_literal(provider, "cloud provider")?
        ));
    }
    if let Some(account) = account_filter.filter(|value| !value.is_empty()) {
        base.push_str(&format!(
            " AND cloud.account.uid={}",
            safe_cloud_literal(account, "cloud account")?
        ));
    }
    Ok(base)
}

fn cloud_dossier_base(
    principal: &str,
    account_filter: Option<&str>,
    provider_filter: Option<&str>,
) -> Result<String, SearchError> {
    let principal_literal = safe_cloud_literal(principal, "cloud principal")?;
    let mut base = format!(
        "(class_uid=6003 OR cloud.provider!=\"\") AND (actor.user.name={principal_literal} OR user.name={principal_literal})"
    );
    if let Some(provider) = provider_filter.filter(|value| !value.is_empty()) {
        base.push_str(&format!(
            " AND lower(cloud.provider)=lower({})",
            safe_cloud_literal(provider, "cloud provider")?
        ));
    }
    if let Some(account) = account_filter.filter(|value| !value.is_empty()) {
        base.push_str(&format!(
            " AND cloud.account.uid={}",
            safe_cloud_literal(account, "cloud account")?
        ));
    }
    Ok(base)
}

impl SearchService {
    async fn lake_cloud_rows(
        &self,
        base: String,
        time_range: &TimeRange,
        scope: &ScopeSet,
        view: &str,
    ) -> Result<Vec<Value>, SearchError> {
        let range = time_range.clone();
        let response = self
            .execute_lake_view_query(
                format!(
                    "{base} | table {} | sort -time",
                    LAKE_CLOUD_PROJECTION.join(",")
                ),
                &range,
                scope,
                view,
                LAKE_CLOUD_SCAN_CAP,
            )
            .await?;
        if !response.total_count_exact {
            return Err(SearchError::ResourceExhausted(format!(
                "{view} exceeds the interactive 50000-row envelope"
            )));
        }
        Ok(response.results)
    }

    async fn lake_cloud_product_rows(
        &self,
        base: String,
        time_range: &TimeRange,
        scope: &ScopeSet,
        view: &str,
    ) -> Result<Vec<Value>, SearchError> {
        let range = time_range.clone();
        let response = self
            .execute_lake_view_query(
                format!(
                    "{base} | table {} | sort -time",
                    LAKE_CLOUD_PROJECTION.join(",")
                ),
                &range,
                scope,
                view,
                LAKE_CLOUD_SCAN_CAP,
            )
            .await?;
        if !response.total_count_exact {
            return Err(SearchError::ResourceExhausted(
                "Cloud dossier exceeds the interactive 50000-row envelope".to_string(),
            ));
        }
        Ok(response.results)
    }

    async fn lake_cloud_overview_rows(
        &self,
        base: String,
        time_range: &TimeRange,
        scope: &ScopeSet,
    ) -> Result<(Vec<Value>, Vec<Value>, Vec<Value>, u64), SearchError> {
        let range = time_range.clone();
        let queries = cloud_overview_queries(&base);
        let identities = self
            .execute_lake_view_query(
                queries.identities,
                &range,
                scope,
                "cloud-overview-identities",
                LAKE_CLOUD_OVERVIEW_GROUP_CAP,
            )
            .await?;
        if !identities.total_count_exact {
            return Err(SearchError::ResourceExhausted(
                "Cloud overview identity groups exceed the interactive envelope".to_string(),
            ));
        }
        let services = self
            .execute_lake_view_query(
                queries.services,
                &range,
                scope,
                "cloud-overview-services",
                LAKE_CLOUD_OVERVIEW_GROUP_CAP,
            )
            .await?;
        if !services.total_count_exact {
            return Err(SearchError::ResourceExhausted(
                "Cloud overview service groups exceed the interactive envelope".to_string(),
            ));
        }
        let changes = self
            .execute_lake_view_query(
                queries.changes,
                &range,
                scope,
                "cloud-overview-changes",
                200,
            )
            .await?
            .results;
        let denied = self
            .execute_lake_view_query(queries.denied, &range, scope, "cloud-overview-denied", 1)
            .await?
            .results
            .first()
            .and_then(|row| cloud_u64(row, "events"))
            .unwrap_or(0);
        Ok((identities.results, services.results, changes, denied))
    }

    /// NAN-3094: served from a 2-minute single-flight cache per
    /// `(tenant, scope, filters, window)`, so a reload, a second analyst or the
    /// page's own background companions never re-run the four aggregates.
    pub(crate) async fn query_lake_cloud_overview(
        &self,
        provider_filter: Option<&str>,
        account_filter: Option<&str>,
        time_range: &TimeRange,
        scope: &ScopeSet,
    ) -> Result<CloudOverview, SearchError> {
        let key = self.lake_cloud_cache_key(
            "cloud-overview-v1",
            &[provider_filter.unwrap_or(""), account_filter.unwrap_or("")],
            time_range,
            scope,
        );
        super::lake_view_cache::lake_view_once(&key, false, || {
            self.compute_lake_cloud_overview(provider_filter, account_filter, time_range, scope)
        })
        .await
    }

    fn lake_cloud_cache_key(
        &self,
        view: &str,
        parts: &[&str],
        time_range: &TimeRange,
        scope: &ScopeSet,
    ) -> String {
        let tenant = self
            .lake_query
            .assigned_tenant_id()
            .unwrap_or("dedicated")
            .to_string();
        let scope = format!("{scope:?}");
        let start = time_range.start.timestamp_micros().to_string();
        let end = time_range.end.timestamp_micros().to_string();
        let mut all = vec![
            view,
            tenant.as_str(),
            scope.as_str(),
            start.as_str(),
            end.as_str(),
        ];
        all.extend_from_slice(parts);
        super::lake_view_cache::lake_view_cache_key(&all)
    }

    async fn compute_lake_cloud_overview(
        &self,
        provider_filter: Option<&str>,
        account_filter: Option<&str>,
        time_range: &TimeRange,
        scope: &ScopeSet,
    ) -> Result<CloudOverview, SearchError> {
        let base = cloud_overview_base(provider_filter, account_filter)?;
        let (identity_rows, service_rows, interesting_rows, denied) = self
            .lake_cloud_overview_rows(base, time_range, scope)
            .await?;

        let risk_by_principal = self.lake_cloud_overview_risk(&identity_rows, scope).await;

        Ok(Self::assemble_lake_cloud_overview(
            identity_rows,
            service_rows,
            interesting_rows,
            denied,
            time_range,
            &risk_by_principal,
        ))
    }

    async fn lake_cloud_overview_risk(&self, identity_rows: &[Value], scope: &ScopeSet) -> BTreeMap<String, (u32, Option<String>)> {
        // Risk is control-plane state rather than event-lake state. Capture a
        // bounded map before assembling the response so the exact same pure
        // assembler can run inside an isolated durable worker without network
        // or database access.
        let mut principal_counts = BTreeMap::<String, u64>::new();
        for row in identity_rows {
            let principal = cloud_principal(row);
            if !principal.is_empty() {
                *principal_counts.entry(principal).or_default() +=
                    cloud_u64(row, "events").unwrap_or(1);
            }
        }
        let mut principal_counts = principal_counts.into_iter().collect::<Vec<_>>();
        principal_counts.sort_by(|left, right| right.1.cmp(&left.1));
        principal_counts.truncate(8);
        let mut risk_by_principal = BTreeMap::new();
        for (principal, _) in principal_counts {
            if let Ok(Some(summary)) = self
                .cloud_risk
                .risk_for_entities(std::slice::from_ref(&principal), scope)
                .await
            {
                risk_by_principal.insert(
                    principal,
                    (summary.risk_score.max(0) as u32, summary.last_rule_name),
                );
            }
        }

        risk_by_principal
    }

    /// Independent overview sections share the original queries and assembler.
    pub async fn query_cloud_overview_section(
        &self, section: &str, provider: Option<&str>, account: Option<&str>,
        time_range: &TimeRange, scope: &ScopeSet,
    ) -> Result<CloudOverview, SearchError> {
        if !matches!(section, "page" | "identities" | "services" | "changes" | "denied") {
            return Err(SearchError::SqlValidationError("Unknown Cloud overview section".into()));
        }
        if self.backend() != crate::search::config::SearchBackend::Lake {
            return self.query_cloud_overview(provider, account, time_range, scope).await;
        }
        let Some(range) = self.retention_bound_query_range(time_range, chrono::Utc::now())? else {
            return Ok(CloudOverview { section: Some(section.into()), ..Default::default() });
        };
        let key = self.lake_cloud_cache_key("cloud-overview-section-v1", &[section, provider.unwrap_or(""), account.unwrap_or("")], &range, scope);
        super::lake_view_cache::lake_view_once(&key, false, || async {
            let base = cloud_overview_base(provider, account)?;
            if section == "page" {
                let rows = self.execute_lake_view_query(
                    format!("{base} | table {} | sort -time | head 200", LAKE_CLOUD_PROJECTION.join(",")),
                    &range, scope, "cloud-overview-preview", 200,
                ).await?.results;
                let page = Self::assemble_lake_cloud_dossier("", rows, &CloudDossierFacetFilters::default(), &range, None);
                return Ok(CloudOverview { section: Some(section.into()), preview_events: page.stream,
                    header: CloudOverviewHeader { window_label: lake_cloud_window_label(&range), ..Default::default() },
                    ..Default::default() });
            }
            let queries = cloud_overview_queries(&base);
            let (query, limit) = match section {
                "identities" => (queries.identities, LAKE_CLOUD_OVERVIEW_GROUP_CAP),
                "services" => (queries.services, LAKE_CLOUD_OVERVIEW_GROUP_CAP),
                "changes" => (queries.changes, 200),
                "denied" => (queries.denied, 1),
                _ => unreachable!(),
            };
            let response = self.execute_lake_view_query(query, &range, scope, &format!("cloud-overview-{section}"), limit).await?;
            if matches!(section, "identities" | "services") && !response.total_count_exact {
                return Err(SearchError::ResourceExhausted("Cloud overview groups exceed the interactive envelope".into()));
            }
            let risk = if section == "identities" { self.lake_cloud_overview_risk(&response.results, scope).await } else { BTreeMap::new() };
            let mut overview = match section {
                "identities" => Self::assemble_lake_cloud_overview(response.results, vec![], vec![], 0, &range, &risk),
                "services" => Self::assemble_lake_cloud_overview(vec![], response.results, vec![], 0, &range, &risk),
                "changes" => Self::assemble_lake_cloud_overview(vec![], vec![], response.results, 0, &range, &risk),
                "denied" => Self::assemble_lake_cloud_overview(vec![], vec![], vec![], response.results.first().and_then(|row| cloud_u64(row, "events")).unwrap_or(0), &range, &risk),
                _ => unreachable!(),
            };
            overview.section = Some(section.into());
            Ok(overview)
        }).await
    }

    pub fn assemble_lake_cloud_overview(
        identity_rows: Vec<Value>,
        service_rows: Vec<Value>,
        interesting_rows: Vec<Value>,
        denied: u64,
        time_range: &TimeRange,
        risk_by_principal: &BTreeMap<String, (u32, Option<String>)>,
    ) -> CloudOverview {
        #[derive(Default)]
        struct AccountRollup {
            events: u64,
            provider: String,
            principals: BTreeSet<String>,
            regions: BTreeSet<String>,
            failures: u64,
            principal_counts: BTreeMap<String, u64>,
        }
        #[derive(Default)]
        struct PrincipalRollup {
            account: String,
            events: u64,
            last_seen: String,
            sparkline: Vec<u64>,
        }
        #[derive(Default)]
        struct ServiceRollup {
            events: u64,
            errors: u64,
            error_counts: BTreeMap<String, u64>,
            trend: Vec<u64>,
        }

        let mut provider_counts = BTreeMap::<String, u64>::new();
        let mut accounts = BTreeMap::<String, AccountRollup>::new();
        let mut principals = BTreeMap::<String, PrincipalRollup>::new();
        let mut services = BTreeMap::<String, ServiceRollup>::new();
        let mut regions = BTreeSet::<String>::new();
        let mut timeline_points = BTreeMap::<(u32, String), u64>::new();
        let mut failed = 0u64;
        let mut total_events = 0u64;

        for row in &identity_rows {
            let events = cloud_u64(row, "events").unwrap_or(1);
            total_events = total_events.saturating_add(events);
            let provider = cloud_provider(row);
            let account = cloud_account(row);
            let principal = cloud_principal(row);
            let region = cloud_region(row);
            let bucket48 = cloud_bucket(row, time_range, 48);
            let bucket12 = cloud_bucket(row, time_range, 12) as usize;
            if !provider.is_empty() {
                *provider_counts.entry(provider.clone()).or_default() += events;
            }
            if !region.is_empty() {
                regions.insert(region.clone());
            }
            if !account.is_empty() {
                let rollup = accounts.entry(account.clone()).or_default();
                rollup.events += events;
                rollup.provider = provider.clone();
                if !principal.is_empty() {
                    rollup.principals.insert(principal.clone());
                    *rollup
                        .principal_counts
                        .entry(principal.clone())
                        .or_default() += events;
                }
                if !region.is_empty() {
                    rollup.regions.insert(region.clone());
                }
                *timeline_points
                    .entry((bucket48, account.clone()))
                    .or_default() += events;
            }
            if !principal.is_empty() {
                let rollup = principals
                    .entry(principal)
                    .or_insert_with(|| PrincipalRollup {
                        sparkline: vec![0; 12],
                        ..Default::default()
                    });
                rollup.account = account;
                rollup.events += events;
                let timestamp = cloud_time(row);
                if timestamp > rollup.last_seen {
                    rollup.last_seen = timestamp;
                }
                if let Some(slot) = rollup.sparkline.get_mut(bucket12.min(11)) {
                    *slot += events;
                }
            }
        }
        for row in &service_rows {
            let events = cloud_u64(row, "events").unwrap_or(1);
            let account = cloud_account(row);
            let service = cloud_service(row);
            let error = cloud_error(row);
            let bucket12 = cloud_bucket(row, time_range, 12) as usize;
            if error {
                failed += events;
                if let Some(account) = accounts.get_mut(&account) {
                    account.failures += events;
                }
            }
            if !service.is_empty() {
                let rollup = services.entry(service).or_insert_with(|| ServiceRollup {
                    trend: vec![0; 12],
                    ..Default::default()
                });
                rollup.events += events;
                if error {
                    rollup.errors += events;
                    if let Some(label) = cloud_error_label(row) {
                        *rollup.error_counts.entry(label).or_default() += events;
                    }
                }
                if let Some(slot) = rollup.trend.get_mut(bucket12.min(11)) {
                    *slot += events;
                }
            }
        }

        let mut principal_values = principals.into_iter().collect::<Vec<_>>();
        principal_values.sort_by(|left, right| right.1.events.cmp(&left.1.events));
        principal_values.truncate(8);
        let mut risky_principals = Vec::with_capacity(principal_values.len());
        for (id, rollup) in principal_values {
            let (score, reason) = risk_by_principal.get(&id).cloned().unwrap_or((0, None));
            let score = score.min(100);
            risky_principals.push(CloudOverviewPrincipal {
                principal_type: cloud_principal_type(&id, None),
                id,
                account: rollup.account,
                risk: score,
                band: lake_cloud_band(score),
                events_24h: rollup.events,
                reasons: reason.into_iter().collect(),
                last_seen: (!rollup.last_seen.is_empty()).then_some(rollup.last_seen),
                sparkline: rollup.sparkline,
                ..Default::default()
            });
        }
        risky_principals.sort_by(|left, right| {
            right
                .risk
                .cmp(&left.risk)
                .then_with(|| right.events_24h.cmp(&left.events_24h))
        });

        let principal_risk = risky_principals
            .iter()
            .map(|principal| (principal.id.clone(), principal.risk))
            .collect::<BTreeMap<_, _>>();
        let mut account_values = accounts.into_iter().collect::<Vec<_>>();
        account_values.sort_by(|left, right| right.1.events.cmp(&left.1.events));
        account_values.truncate(12);
        let accounts = account_values
            .iter()
            .map(|(id, rollup)| {
                let top_principal = rollup
                    .principal_counts
                    .iter()
                    .max_by_key(|(_, count)| *count)
                    .map(|(principal, _)| principal.clone());
                let top_principal_risk = top_principal
                    .as_ref()
                    .and_then(|principal| principal_risk.get(principal))
                    .copied()
                    .unwrap_or(0);
                let heuristic = ((rollup.failures * 100) / rollup.events.max(1)).min(100) as u32;
                let risk = heuristic.max(top_principal_risk);
                CloudOverviewAccount {
                    id: id.clone(),
                    name: id.clone(),
                    provider: rollup.provider.clone(),
                    events: rollup.events,
                    risk,
                    band: lake_cloud_band(risk),
                    alerts: rollup.failures,
                    principals: rollup.principals.len() as u64,
                    regions: rollup.regions.len() as u64,
                    top_principal,
                    top_principal_risk,
                    ..Default::default()
                }
            })
            .collect::<Vec<_>>();

        let lanes = account_values
            .iter()
            .take(6)
            .enumerate()
            .map(|(index, (id, _))| CloudOverviewTimelineLane {
                id: id.clone(),
                label: id.clone(),
                accent: [
                    "oklch(68% 0.18 28)",
                    "oklch(70% 0.15 50)",
                    "oklch(68% 0.14 170)",
                    "oklch(68% 0.14 240)",
                    "oklch(65% 0.16 0)",
                    "oklch(68% 0.12 290)",
                ][index % 6]
                    .to_string(),
            })
            .collect::<Vec<_>>();
        let lane_ids = lanes
            .iter()
            .map(|lane| lane.id.as_str())
            .collect::<BTreeSet<_>>();
        let points = timeline_points
            .into_iter()
            .filter(|((_, account), _)| lane_ids.contains(account.as_str()))
            .map(|((bucket, account), count)| json!([bucket, account, count.min(3)]))
            .collect::<Vec<_>>();

        let mut service_values = services.into_iter().collect::<Vec<_>>();
        service_values.sort_by(|left, right| right.1.events.cmp(&left.1.events));
        service_values.truncate(10);
        let service_health = service_values
            .into_iter()
            .map(|(id, rollup)| {
                let error_rate = rollup.errors as f64 / rollup.events.max(1) as f64;
                let top_error = rollup
                    .error_counts
                    .into_iter()
                    .max_by_key(|(_, count)| *count)
                    .map(|(label, _)| label);
                CloudOverviewServiceHealth {
                    label: id.clone(),
                    id: id.clone(),
                    events: rollup.events,
                    errors: rollup.errors,
                    error_rate,
                    accent: lake_cloud_service_accent(&id),
                    status: if error_rate >= 0.25 {
                        "bad"
                    } else if error_rate >= 0.05 {
                        "warn"
                    } else {
                        "ok"
                    }
                    .to_string(),
                    top_error,
                    trend: rollup.trend,
                    ..Default::default()
                }
            })
            .collect::<Vec<_>>();

        let mut interesting = interesting_rows
            .iter()
            .filter(|row| cloud_error(row) || cloud_sensitive(row))
            .collect::<Vec<_>>();
        interesting.sort_by_key(|row| std::cmp::Reverse(cloud_time(row)));
        let anomalies = interesting
            .iter()
            .take(20)
            .enumerate()
            .map(|(index, row)| CloudOverviewAnomaly {
                id: cloud_string(row, "metadata.uid")
                    .unwrap_or_else(|| format!("cloud-anomaly-{index}")),
                at: lake_cloud_hhmm(&cloud_time(row)),
                severity: if cloud_denied(row) { "high" } else { "medium" }.to_string(),
                kind: if cloud_denied(row) {
                    "access-denied"
                } else if cloud_sensitive(row) {
                    "sensitive-change"
                } else {
                    "request-failure"
                }
                .to_string(),
                title: cloud_operation(row),
                detail: cloud_error_label(row).unwrap_or_else(|| cloud_change_type(row)),
                principal: Some(cloud_principal(row)).filter(|value| !value.is_empty()),
                account: Some(cloud_account(row)).filter(|value| !value.is_empty()),
                service: Some(cloud_service(row)).filter(|value| !value.is_empty()),
            })
            .collect::<Vec<_>>();
        let changes = interesting
            .iter()
            .filter(|row| cloud_sensitive(row))
            .take(10)
            .map(|row| CloudOverviewChange {
                at: lake_cloud_hhmm(&cloud_time(row)),
                kind: cloud_change_type(row),
                severity: if cloud_denied(row) { "high" } else { "medium" }.to_string(),
                account: cloud_account(row),
                actor: cloud_principal(row),
                action: cloud_operation(row),
                target: cloud_primary_resource(row, "name"),
                detail: cloud_string(row, "message"),
            })
            .collect::<Vec<_>>();
        let max_risk = risky_principals
            .iter()
            .map(|principal| principal.risk)
            .max()
            .unwrap_or_else(|| ((failed * 100) / total_events.max(1)).min(100) as u32);

        CloudOverview {
            section: None, preview_events: Vec::new(), requires_durable: false,
            header: CloudOverviewHeader {
                org: "Current tenant".to_string(),
                org_id: "tenant-scoped".to_string(),
                window_label: lake_cloud_window_label(time_range),
                accounts: accounts.len() as u64,
                principals: principal_risk.len() as u64,
                regions: regions.len() as u64,
                providers: provider_counts
                    .into_iter()
                    .map(|(id, events)| CloudOverviewProviderBreakdown {
                        label: id.clone(),
                        id,
                        events,
                    })
                    .collect(),
                events_total: total_events,
                events_failed: failed,
                events_denied: denied,
                open_alerts: CloudOverviewOpenAlerts {
                    critical: risky_principals.iter().filter(|row| row.risk >= 80).count() as u64,
                    high: risky_principals
                        .iter()
                        .filter(|row| (60..80).contains(&row.risk))
                        .count() as u64,
                    medium: risky_principals
                        .iter()
                        .filter(|row| (35..60).contains(&row.risk))
                        .count() as u64,
                },
                posture_score: max_risk,
                posture_reason: risky_principals
                    .first()
                    .map(|principal| format!("driven by {}", principal.id)),
                ..Default::default()
            },
            accounts,
            risky_principals,
            timeline: CloudOverviewTimeline {
                label: lake_cloud_window_label(time_range),
                buckets: 48,
                lanes,
                points,
                markers: anomalies
                    .iter()
                    .take(5)
                    .enumerate()
                    .map(|(index, anomaly)| CloudOverviewTimelineMarker {
                        at: (47usize.saturating_sub(index * 3)) as u32,
                        label: anomaly.title.clone(),
                        severity: anomaly.severity.clone(),
                    })
                    .collect(),
            },
            anomalies,
            service_health,
            changes,
            durable_job: None,
        }
    }

    /// Admit the complete Cloud overview to the isolated durable lane after a
    /// bounded interactive aggregate reaches its resource envelope. The task
    /// contains only server-authored nPL and a bounded control-plane risk
    /// snapshot; object-store coordinates and arbitrary SQL never cross the
    /// public API boundary.
    pub async fn enqueue_durable_cloud_overview(
        &self,
        provider_filter: Option<&str>,
        account_filter: Option<&str>,
        time_range: &TimeRange,
        scope: &ScopeSet,
        user_id: uuid::Uuid,
        authority: Option<&crate::search::DurableSearchJobAuthority>,
    ) -> Result<String, SearchError> {
        // NAN-3078: bound to the retention cutoff; the job result carries its proof.
        let (generation_pin, time_range) =
            self.durable_view_admission("durable Cloud overviews", time_range).await?;
        let time_range = &time_range;
        if self.lake_query.mode != super::LakeQueryMode::Primary {
            return Err(SearchError::ServiceUnavailable(
                "durable Cloud overviews require the primary lake backend".to_string(),
            ));
        }
        let base = cloud_overview_base(provider_filter, account_filter)?;
        let queries = cloud_overview_queries(&base);
        let risk = self
            .cloud_risk
            .risky_entities(
                RiskTimeWindow::Last7Days,
                &RiskFilter {
                    limit: Some(1_000),
                    ..Default::default()
                },
                scope,
            )
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|summary| {
                (
                    summary.entity,
                    summary.risk_score.max(0),
                    summary.last_rule_name,
                )
            })
            .collect::<Vec<_>>();
        let range = time_range.clone();
        let mut query = "| cloud".to_string();
        if let Some(provider) = provider_filter.filter(|value| !value.is_empty()) {
            query.push_str(&format!(
                " provider={}",
                safe_cloud_literal(provider, "cloud provider")?
            ));
        }
        if let Some(account) = account_filter.filter(|value| !value.is_empty()) {
            query.push_str(&format!(
                " account={}",
                safe_cloud_literal(account, "cloud account")?
            ));
        }
        let request = SearchRequest {
            query,
            time_range: TimeRangeInput::new(range.start, range.end),
            limit: Some(1),
            offset: Some(0),
            include_sql: Some(false),
            skip_histogram: true,
            skip_field_stats: true,
            use_cache: false,
            table_view: false,
            request_id: None,
            async_mode: true,
            priority: Some("analytics".to_string()),
            dataset: Some("logs".to_string()),
        };
        self.job_control()
            .create_durable_queued(
                request,
                &crate::search::DurableLakeTask::CloudOverviewV1 {
                    provider: provider_filter.map(str::to_string),
                    account: account_filter.map(str::to_string),
                    identity_query: queries.identities,
                    service_query: queries.services,
                    change_query: queries.changes,
                    denied_query: queries.denied,
                    risk,
                },
                user_id,
                crate::search::QueryPriority::Analytics,
                scope,
                &generation_pin,
                authority,
            )
            .await
            .map_err(|error| {
                SearchError::ServiceUnavailable(format!(
                    "durable Cloud overview admission failed: {error}"
                ))
            })
    }

    /// A bounded first event page, independent of full-window aggregates and risk.
    pub async fn query_cloud_dossier_preview(
        &self,
        principal: &str,
        account_filter: Option<&str>,
        provider_filter: Option<&str>,
        facet_filters: &CloudDossierFacetFilters,
        time_range: &TimeRange,
        scope: &ScopeSet,
    ) -> Result<CloudDossier, SearchError> {
        if self.backend() != crate::search::config::SearchBackend::Lake {
            return self.query_cloud_dossier(principal, account_filter, provider_filter, facet_filters, time_range, scope).await;
        }
        let Some(range) = self.retention_bound_query_range(time_range, chrono::Utc::now())? else {
            return Ok(CloudDossier { bounded_preview: true, ..Default::default() });
        };
        let base = cloud_dossier_base(principal, account_filter, provider_filter)?;
        let response = self.execute_lake_view_query(
            format!("{base} | table {} | sort -time | head {CLOUD_DOSSIER_STREAM}", LAKE_CLOUD_PROJECTION.join(",")),
            &range, scope, "cloud-dossier-preview", CLOUD_DOSSIER_STREAM,
        ).await?;
        // Apply the identical facet predicate to this newest-page sample. A
        // filtered empty preview does not establish an empty requested window.
        let mut preview = Self::assemble_lake_cloud_dossier(principal, response.results, facet_filters, &range, None);
        preview.bounded_preview = true;
        Ok(preview)
    }

    /// NAN-3094: 2-minute single-flight cache, like the overview.
    pub(crate) async fn query_lake_cloud_dossier(
        &self,
        principal: &str,
        account_filter: Option<&str>,
        provider_filter: Option<&str>,
        facet_filters: &CloudDossierFacetFilters,
        time_range: &TimeRange,
        scope: &ScopeSet,
    ) -> Result<CloudDossier, SearchError> {
        let facets = serde_json::to_string(facet_filters).unwrap_or_default();
        let key = self.lake_cloud_cache_key(
            "cloud-dossier-v1",
            &[
                principal,
                account_filter.unwrap_or(""),
                provider_filter.unwrap_or(""),
                &facets,
            ],
            time_range,
            scope,
        );
        super::lake_view_cache::lake_view_once(&key, false, || {
            self.compute_lake_cloud_dossier(
                principal,
                account_filter,
                provider_filter,
                facet_filters,
                time_range,
                scope,
            )
        })
        .await
    }

    async fn compute_lake_cloud_dossier(
        &self,
        principal: &str,
        account_filter: Option<&str>,
        provider_filter: Option<&str>,
        facet_filters: &CloudDossierFacetFilters,
        time_range: &TimeRange,
        scope: &ScopeSet,
    ) -> Result<CloudDossier, SearchError> {
        let base = cloud_dossier_base(principal, account_filter, provider_filter)?;
        let rows = self
            .lake_cloud_product_rows(base, time_range, scope, "cloud-dossier")
            .await?;

        let risk_summary = self
            .cloud_risk
            .risk_for_entities(&[principal.to_string()], scope)
            .await
            .ok()
            .flatten();
        Ok(Self::assemble_lake_cloud_dossier(
            principal,
            rows,
            facet_filters,
            time_range,
            risk_summary.map(|summary| (summary.risk_score, summary.last_rule_name)),
        ))
    }

    pub fn assemble_lake_cloud_dossier(
        principal: &str,
        rows: Vec<Value>,
        facet_filters: &CloudDossierFacetFilters,
        time_range: &TimeRange,
        risk_summary: Option<(i32, Option<String>)>,
    ) -> CloudDossier {
        let mut accumulator = CloudDossierAccumulator::new(principal, facet_filters, time_range);
        for row in rows {
            accumulator.push(row);
        }
        accumulator.finish(risk_summary)
    }

    pub async fn enqueue_durable_cloud_dossier(
        &self,
        principal: &str,
        account_filter: Option<&str>,
        provider_filter: Option<&str>,
        facet_filters: &CloudDossierFacetFilters,
        time_range: &TimeRange,
        scope: &ScopeSet,
        user_id: uuid::Uuid,
        authority: Option<&crate::search::DurableSearchJobAuthority>,
    ) -> Result<String, SearchError> {
        // NAN-3078: bound to the retention cutoff; the job result carries its proof.
        let (generation_pin, time_range) =
            self.durable_view_admission("durable Cloud dossiers", time_range).await?;
        let time_range = &time_range;
        if self.lake_query.mode != super::LakeQueryMode::Primary {
            return Err(SearchError::ServiceUnavailable(
                "durable Cloud dossiers require the primary lake backend".to_string(),
            ));
        }
        let base = cloud_dossier_base(principal, account_filter, provider_filter)?;
        let event_query = format!(
            "{base} | table {} | sort -time",
            LAKE_CLOUD_PROJECTION.join(",")
        );
        let risk = self
            .cloud_risk
            .risk_for_entities(&[principal.to_string()], scope)
            .await
            .ok()
            .flatten()
            .map(|summary| (summary.risk_score.max(0), summary.last_rule_name));
        let range = time_range.clone();
        let mut query = format!(
            "| cloud principal={}",
            safe_cloud_literal(principal, "cloud principal")?
        );
        if let Some(account) = account_filter.filter(|value| !value.is_empty()) {
            query.push_str(&format!(
                " account={}",
                safe_cloud_literal(account, "cloud account")?
            ));
        }
        let request = SearchRequest {
            query,
            time_range: TimeRangeInput::new(range.start, range.end),
            limit: Some(1),
            offset: Some(0),
            include_sql: Some(false),
            skip_histogram: true,
            skip_field_stats: true,
            use_cache: false,
            table_view: false,
            request_id: None,
            async_mode: true,
            priority: Some("analytics".to_string()),
            dataset: Some("logs".to_string()),
        };
        self.job_control()
            .create_durable_queued(
                request,
                &crate::search::DurableLakeTask::CloudDossierV1 {
                    principal: principal.to_string(),
                    account: account_filter.map(str::to_string),
                    provider: provider_filter.map(str::to_string),
                    filters: facet_filters.clone(),
                    event_query,
                    risk,
                },
                user_id,
                crate::search::QueryPriority::Analytics,
                scope,
                &generation_pin,
                authority,
            )
            .await
            .map_err(|error| {
                SearchError::ServiceUnavailable(format!(
                    "durable Cloud dossier admission failed: {error}"
                ))
            })
    }

    pub(crate) async fn build_lake_cloud_view(
        &self,
        query: &Query,
        info: &CloudCommandInfo,
        _time_range: &TimeRange,
        _scope: &ScopeSet,
    ) -> Result<Vec<Value>, SearchError> {
        let base = canonical_cloud_base_from_query(query);
        // The Search response is only the typed dispatcher marker. The actual
        // overview/dossier endpoint owns the single bounded event read, which
        // avoids scanning the same Iceberg snapshot twice for every `| cloud`
        // navigation.
        Ok(vec![json!({
            "_display_type": "cloud",
            "_cloud_group_by": info.group_by.as_str(),
            "_cloud_principal": info.principal,
            "_cloud_account": info.account,
            "_cloud_query": base,
            "_cloud_show_mfa": info.show_mfa,
            "_storage_model": "ocsf-1.9-iceberg",
        })])
    }

    pub(crate) async fn query_lake_cloud_events_paginated(
        &self,
        query_str: &str,
        time_range: &TimeRange,
        offset: usize,
        limit: usize,
        filters: Option<&CloudEventFilters>,
        scope: &ScopeSet,
    ) -> Result<
        (
            Vec<Value>,
            u64,
            CloudFacets,
            Option<Vec<Value>>,
            Option<Vec<CloudUserActivity>>,
        ),
        SearchError,
    > {
        let (events, _, _) = self
            .query_lake_cloud_events_page(
                query_str, time_range, offset, limit, None, filters, scope,
            )
            .await?;
        let (total_count, facets, panels, activity) = self
            .query_lake_cloud_events_summary(query_str, time_range, filters, scope, offset == 0)
            .await?;
        Ok((events, total_count, facets, panels, activity))
    }

    pub(crate) async fn query_lake_cloud_events_page(
        &self,
        query_str: &str,
        time_range: &TimeRange,
        offset: usize,
        limit: usize,
        cursor: Option<&ProductViewCursor>,
        filters: Option<&CloudEventFilters>,
        scope: &ScopeSet,
    ) -> Result<(Vec<Value>, bool, Option<ProductViewCursor>), SearchError> {
        if limit == 0 || limit > 5_000 {
            return Err(SearchError::SqlValidationError(
                "lake cloud page limit must be between 1 and 5000".to_string(),
            ));
        }
        let base = canonical_cloud_base(query_str)?;
        let filtered = apply_cloud_filters(&base, filters)?;
        let page_query = format!(
            "{filtered} | table {} | sort -time -metadata.uid",
            LAKE_CLOUD_PROJECTION.join(",")
        );
        let page = self
            .execute_lake_view_query_cursor_page(
                page_query,
                time_range,
                scope,
                "cloud-page",
                limit.saturating_add(1),
                if cursor.is_some() { 0 } else { offset },
                cursor,
            )
            .await?;
        let has_more = page.results.len() > limit;
        let next_cursor = if has_more {
            page.results
                .get(limit.saturating_sub(1))
                .map(lake_product_cursor)
                .transpose()?
        } else {
            None
        };
        let events = page
            .results
            .iter()
            .take(limit)
            .map(cloud_event_dto)
            .collect();
        Ok((events, has_more, next_cursor))
    }

    pub(crate) async fn query_lake_cloud_events_summary(
        &self,
        query_str: &str,
        time_range: &TimeRange,
        filters: Option<&CloudEventFilters>,
        scope: &ScopeSet,
        include_panels: bool,
    ) -> Result<
        (
            u64,
            CloudFacets,
            Option<Vec<Value>>,
            Option<Vec<CloudUserActivity>>,
        ),
        SearchError,
    > {
        let base = canonical_cloud_base(query_str)?;
        let filtered = apply_cloud_filters(&base, filters)?;
        let queries = Self::lake_cloud_events_summary_queries(&filtered);
        let summary = self
            .execute_lake_view_query(
                Self::lake_cloud_correlated_summary_query(&filtered),
                time_range,
                scope,
                "cloud-correlated-facets",
                CLOUD_SUMMARY_GROUP_CAP,
            )
            .await?;
        if !summary.total_count_exact {
            return Err(SearchError::ResourceExhausted(
                "Cloud summary groups exceed the interactive envelope".to_string(),
            ));
        }
        let (total, facets) = Self::assemble_lake_cloud_correlated_summary(&summary.results);
        let (resources, users) = if include_panels {
            let (resources, users) = tokio::try_join!(
                self.execute_lake_view_query(
                    queries.resources.clone(),
                    time_range,
                    scope,
                    "cloud-resources",
                    100
                ),
                self.execute_lake_view_query(
                    queries.users.clone(),
                    time_range,
                    scope,
                    "cloud-users",
                    100
                ),
            )?;
            (resources.results, users.results)
        } else {
            (Vec::new(), Vec::new())
        };
        Ok((
            total,
            facets,
            include_panels.then(|| cloud_resource_rollup_from_grouped(&resources)),
            include_panels.then(|| cloud_user_activity_from_grouped(&users)),
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn assemble_lake_cloud_events_summary(
        total: &[Value],
        providers: &[Value],
        services: &[Value],
        regions: &[Value],
        accounts: &[Value],
        resource_types: &[Value],
        change_types: &[Value],
        resources: &[Value],
        users: &[Value],
        include_panels: bool,
    ) -> (
        u64,
        CloudFacets,
        Option<Vec<Value>>,
        Option<Vec<CloudUserActivity>>,
    ) {
        let total_count = total
            .first()
            .and_then(|row| cloud_u64(row, "event_count"))
            .unwrap_or_default();
        let facets = cloud_facets_from_grouped(
            providers,
            services,
            regions,
            accounts,
            resource_types,
            change_types,
        );
        let panels = include_panels.then(|| cloud_resource_rollup_from_grouped(resources));
        let activity = include_panels.then(|| cloud_user_activity_from_grouped(users));
        (total_count, facets, panels, activity)
    }

    pub async fn enqueue_durable_cloud_events_summary(
        &self,
        query_str: &str,
        time_range: &TimeRange,
        filters: Option<&CloudEventFilters>,
        include_panels: bool,
        scope: &ScopeSet,
        user_id: uuid::Uuid,
        authority: Option<&crate::search::DurableSearchJobAuthority>,
    ) -> Result<String, SearchError> {
        // NAN-3078: bound to the retention cutoff; the job result carries its proof.
        let (generation_pin, time_range) =
            self.durable_view_admission("durable Cloud summaries", time_range).await?;
        let time_range = &time_range;
        if self.lake_query.mode != super::LakeQueryMode::Primary {
            return Err(SearchError::ServiceUnavailable(
                "durable Cloud summaries require the primary lake backend".to_string(),
            ));
        }
        let base = canonical_cloud_base(query_str)?;
        let filtered = apply_cloud_filters(&base, filters)?;
        let queries = Self::lake_cloud_events_summary_queries(&filtered);
        let request = SearchRequest {
            query: query_str.to_string(),
            time_range: TimeRangeInput::new(time_range.start, time_range.end),
            limit: Some(1),
            offset: Some(0),
            include_sql: Some(false),
            skip_histogram: true,
            skip_field_stats: true,
            use_cache: false,
            table_view: false,
            request_id: None,
            async_mode: true,
            priority: Some("analytics".to_string()),
            dataset: Some("logs".to_string()),
        };
        self.job_control()
            .create_durable_queued(
                request,
                &crate::search::DurableLakeTask::CloudEventsSummaryV1 {
                    query: query_str.to_string(),
                    filters: filters.cloned(),
                    queries,
                    include_panels,
                },
                user_id,
                crate::search::QueryPriority::Analytics,
                scope,
                &generation_pin,
                authority,
            )
            .await
            .map_err(|error| {
                SearchError::ServiceUnavailable(format!(
                    "durable Cloud summary admission failed: {error}"
                ))
            })
    }

    pub(crate) async fn query_lake_cloud_user_timeline(
        &self,
        query_str: &str,
        time_range: &TimeRange,
        user: &str,
        scope: &ScopeSet,
    ) -> Result<(Vec<Value>, CloudUserSessionSummary), SearchError> {
        let base = canonical_cloud_base(query_str)?;
        let user_literal = safe_cloud_literal(user, "cloud principal")?;
        let query =
            format!("({base}) AND (actor.user.name={user_literal} OR user.name={user_literal})");
        let rows = self
            .lake_cloud_rows(query, time_range, scope, "cloud-user")
            .await?;
        Ok(Self::assemble_lake_cloud_user_timeline(rows))
    }

    pub fn assemble_lake_cloud_user_timeline(
        mut rows: Vec<Value>,
    ) -> (Vec<Value>, CloudUserSessionSummary) {
        rows.sort_by_key(|row| cloud_string(row, "time").unwrap_or_default());
        let summary = cloud_session_summary(&rows);
        (rows.iter().map(cloud_event_dto).collect(), summary)
    }

    pub async fn enqueue_durable_cloud_user_timeline(
        &self,
        query_str: &str,
        time_range: &TimeRange,
        user: &str,
        scope: &ScopeSet,
        user_id: uuid::Uuid,
        authority: Option<&crate::search::DurableSearchJobAuthority>,
    ) -> Result<String, SearchError> {
        // NAN-3078: this view's assembler holds the whole event set, which
        // a lean cell cannot; a shared tenant gets the budget refusal (422),
        // not an outage. Dedicated deployments keep their durable lane.
        self.require_materializing_view_lane("durable Cloud user timelines")?;
        let (generation_pin, time_range) =
            self.durable_view_admission("durable Cloud user timelines", time_range).await?;
        let time_range = &time_range;
        if self.lake_query.mode != super::LakeQueryMode::Primary {
            return Err(SearchError::ServiceUnavailable(
                "durable Cloud user timelines require the primary lake backend".to_string(),
            ));
        }
        let base = canonical_cloud_base(query_str)?;
        let user_literal = safe_cloud_literal(user, "cloud principal")?;
        let base =
            format!("({base}) AND (actor.user.name={user_literal} OR user.name={user_literal})");
        let event_query = format!(
            "{base} | table {} | sort -time",
            LAKE_CLOUD_PROJECTION.join(",")
        );
        let request = SearchRequest {
            query: query_str.to_string(),
            time_range: TimeRangeInput::new(time_range.start, time_range.end),
            limit: Some(1),
            offset: Some(0),
            include_sql: Some(false),
            skip_histogram: true,
            skip_field_stats: true,
            use_cache: false,
            table_view: false,
            request_id: None,
            async_mode: true,
            priority: Some("analytics".to_string()),
            dataset: Some("logs".to_string()),
        };
        self.job_control()
            .create_durable_queued(
                request,
                &crate::search::DurableLakeTask::CloudUserTimelineV1 {
                    user: user.to_string(),
                    event_query,
                },
                user_id,
                crate::search::QueryPriority::Analytics,
                scope,
                &generation_pin,
                authority,
            )
            .await
            .map_err(|error| {
                SearchError::ServiceUnavailable(format!(
                    "durable Cloud user timeline admission failed: {error}"
                ))
            })
    }

    pub(crate) async fn query_lake_cloud_entity_pivot(
        &self,
        query_str: &str,
        time_range: &TimeRange,
        entity_type: &str,
        entity_value: &str,
        scope: &ScopeSet,
    ) -> Result<(Vec<Value>, Vec<EntityCrossReference>, Value), SearchError> {
        let fields: &[&str] = match entity_type {
            "user" => &["actor.user.name", "user.name"],
            "ip" => &["src_endpoint.ip"],
            "resource" => &["resources.uid", "resources.name"],
            _ => {
                return Err(SearchError::SqlValidationError(
                    "cloud entity type must be user, ip, or resource".to_string(),
                ));
            }
        };
        let base = canonical_cloud_base(query_str)?;
        let literal = safe_cloud_literal(entity_value, "cloud pivot entity")?;
        let entity_predicate = if entity_type == "resource" {
            // Array-object predicates are not currently exposed by nPL. Keep the
            // worker scan bounded and apply this one product predicate in Rust.
            base
        } else {
            format!(
                "({base}) AND ({})",
                fields
                    .iter()
                    .map(|field| format!("{field}={literal}"))
                    .collect::<Vec<_>>()
                    .join(" OR ")
            )
        };
        let rows = self
            .lake_cloud_rows(entity_predicate, time_range, scope, "cloud-pivot")
            .await?;
        Ok(Self::assemble_lake_cloud_entity_pivot(
            rows,
            entity_type,
            entity_value,
        ))
    }

    pub fn assemble_lake_cloud_entity_pivot(
        mut rows: Vec<Value>,
        entity_type: &str,
        entity_value: &str,
    ) -> (Vec<Value>, Vec<EntityCrossReference>, Value) {
        rows.retain(|row| match entity_type {
            "user" => ["actor.user.name", "user.name"]
                .iter()
                .any(|field| cloud_string(row, field).as_deref() == Some(entity_value)),
            "ip" => cloud_string(row, "src_endpoint.ip").as_deref() == Some(entity_value),
            "resource" => cloud_resources(row).any(|resource| {
                ["uid", "name"]
                    .iter()
                    .any(|field| resource.get(field).and_then(Value::as_str) == Some(entity_value))
            }),
            _ => false,
        });
        rows.sort_by_key(|row| cloud_string(row, "time").unwrap_or_default());

        let mut refs = BTreeMap::<(String, String), u64>::new();
        for row in &rows {
            for (kind, value) in [
                ("user", cloud_principal(row)),
                (
                    "ip",
                    cloud_string(row, "src_endpoint.ip").unwrap_or_default(),
                ),
            ] {
                if !value.is_empty() && !(kind == entity_type && value == entity_value) {
                    *refs.entry((kind.to_string(), value)).or_default() += 1;
                }
            }
            for resource in cloud_resources(row) {
                if let Some(value) = resource
                    .get("uid")
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                {
                    if !(entity_type == "resource" && value == entity_value) {
                        *refs
                            .entry(("resource".to_string(), value.to_string()))
                            .or_default() += 1;
                    }
                }
            }
        }
        let mut cross_references = refs
            .into_iter()
            .map(
                |((entity_type, entity_value), event_count)| EntityCrossReference {
                    entity_type,
                    entity_value,
                    event_count,
                },
            )
            .collect::<Vec<_>>();
        cross_references.sort_by(|left, right| {
            right
                .event_count
                .cmp(&left.event_count)
                .then_with(|| left.entity_value.cmp(&right.entity_value))
        });
        cross_references.truncate(100);

        let first_seen = rows.first().and_then(|row| cloud_string(row, "time"));
        let last_seen = rows.last().and_then(|row| cloud_string(row, "time"));
        let fail_count = rows
            .iter()
            .filter(|row| {
                cloud_string(row, "status")
                    .is_some_and(|value| value.eq_ignore_ascii_case("failure"))
                    || cloud_u64(row, "http_response.code").is_some_and(|value| value >= 400)
            })
            .count();
        let services = rows
            .iter()
            .filter_map(|row| cloud_string(row, "api.service.name"))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let change_types = rows
            .iter()
            .map(cloud_change_type)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let summary = json!({
            "event_count": rows.len(),
            "fail_count": fail_count,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "change_types": change_types,
            "services": services,
        });
        (
            rows.iter().map(cloud_event_dto).collect(),
            cross_references,
            summary,
        )
    }

    pub async fn enqueue_durable_cloud_entity_pivot(
        &self,
        query_str: &str,
        time_range: &TimeRange,
        entity_type: &str,
        entity_value: &str,
        scope: &ScopeSet,
        user_id: uuid::Uuid,
        authority: Option<&crate::search::DurableSearchJobAuthority>,
    ) -> Result<String, SearchError> {
        // NAN-3078: this view's assembler holds the whole event set, which
        // a lean cell cannot; a shared tenant gets the budget refusal (422),
        // not an outage. Dedicated deployments keep their durable lane.
        self.require_materializing_view_lane("durable Cloud entity pivots")?;
        let (generation_pin, time_range) =
            self.durable_view_admission("durable Cloud entity pivots", time_range).await?;
        let time_range = &time_range;
        if self.lake_query.mode != super::LakeQueryMode::Primary {
            return Err(SearchError::ServiceUnavailable(
                "durable Cloud entity pivots require the primary lake backend".to_string(),
            ));
        }
        let fields: &[&str] = match entity_type {
            "user" => &["actor.user.name", "user.name"],
            "ip" => &["src_endpoint.ip"],
            "resource" => &["resources.uid", "resources.name"],
            _ => {
                return Err(SearchError::SqlValidationError(
                    "cloud entity type must be user, ip, or resource".to_string(),
                ));
            }
        };
        let base = canonical_cloud_base(query_str)?;
        let literal = safe_cloud_literal(entity_value, "cloud pivot entity")?;
        let base = if entity_type == "resource" {
            base
        } else {
            format!(
                "({base}) AND ({})",
                fields
                    .iter()
                    .map(|field| format!("{field}={literal}"))
                    .collect::<Vec<_>>()
                    .join(" OR ")
            )
        };
        let event_query = format!(
            "{base} | table {} | sort -time",
            LAKE_CLOUD_PROJECTION.join(",")
        );
        let request = SearchRequest {
            query: query_str.to_string(),
            time_range: TimeRangeInput::new(time_range.start, time_range.end),
            limit: Some(1),
            offset: Some(0),
            include_sql: Some(false),
            skip_histogram: true,
            skip_field_stats: true,
            use_cache: false,
            table_view: false,
            request_id: None,
            async_mode: true,
            priority: Some("analytics".to_string()),
            dataset: Some("logs".to_string()),
        };
        self.job_control()
            .create_durable_queued(
                request,
                &crate::search::DurableLakeTask::CloudEntityPivotV1 {
                    entity_type: entity_type.to_string(),
                    entity_value: entity_value.to_string(),
                    event_query,
                },
                user_id,
                crate::search::QueryPriority::Analytics,
                scope,
                &generation_pin,
                authority,
            )
            .await
            .map_err(|error| {
                SearchError::ServiceUnavailable(format!(
                    "durable Cloud entity pivot admission failed: {error}"
                ))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "enterprise")]
    #[tokio::test]
    async fn independent_overview_sections_preserve_full_scoped_aggregate_content() {
        use wiremock::{matchers::{method, path}, Mock, MockServer, ResponseTemplate};
        use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
        let server = MockServer::start().await;
        let tenant = uuid::Uuid::from_u128(0x3077);
        let temp = tempfile::tempdir().unwrap();
        let token_file = temp.path().join("router.token");
        std::fs::write(&token_file, "local-test-router-token-1234567890").unwrap();
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o400)).unwrap();
        }
        let calls = Arc::new(AtomicUsize::new(0));
        let recorded = calls.clone();
        Mock::given(method("POST"))
            .and(path(format!("/v1/tenants/{tenant}/query/v1/query")))
            .respond_with(move |request: &wiremock::Request| {
                let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                assert_eq!(body["deny_source_types"], json!(["audit"]));
                recorded.fetch_add(1, Ordering::SeqCst);
                let query = body["query"].as_str().unwrap();
                assert!(query.contains("cloud.account.uid=\"123\""));
                let rows = if query.contains("latest(actor.user.uid)") {
                    vec![json!({"events": 42, "last_seen": "2026-09-30T00:05:00Z", "cloud.account.uid": "123", "cloud.provider": "AWS", "cloud.region": "us-east-1"})]
                } else if query.contains("by api.service.name") {
                    vec![json!({"events": 42, "api.service.name": "iam", "cloud.account.uid": "123", "status": "Success"})]
                } else if query.contains("by api.operation") {
                    vec![json!({"events": 2, "api.operation": "DeleteRole", "actor.user.name": "alice", "cloud.account.uid": "123", "last_seen": "2026-09-30T00:05:00Z"})]
                } else if query.contains("stats count() as events") {
                    vec![json!({"events": 3})]
                } else {
                    assert_eq!(body["limit"], 200);
                    vec![json!({"time": "2026-09-30T00:05:00Z", "metadata.uid": "preview", "api.operation": "ListRoles", "cloud.account.uid": "123"})]
                };
                let answer = ResponseTemplate::new(200).set_body_json(json!({
                    "ok": true, "schema_version": 1, "request_id": body["request_id"], "tenant_id": tenant,
                    "route": "broad_npl", "source_mode": "parts", "wall_seconds": 0.01,
                    "result": {"result_rows": rows.len(), "rows": rows, "page_has_more": false}
                }));
                answer
            }).mount(&server).await;
        let pool = crate::db::DualPool::new_lake_control_plane(&crate::db::DualPoolConfig::with_auth(
            "postgres://unused:unused@127.0.0.1:1/nanosiem", "http://127.0.0.1:1", "nanosiem", "unused", "nanosiem",
        )).await.unwrap();
        let view = SearchService::with_dual_pool(&pool).enterprise_shared_cell_tenant_view(
            &crate::search::LakeCellRoute { tenant_id: tenant, assignment_generation: 1, part_log_writer_epoch: 1,
                worker_revision: 1, assignment_fenced: true, cell_origin: server.uri(),
                query_base_url: format!("{}/v1/tenants/{tenant}/query", server.uri()), router_token_file: token_file },
            crate::search::SearchTenantScope::enterprise_shared_retained(tenant, 1, 90, 0).unwrap(),
            Arc::new(crate::search::InMemoryJobStore::new()),
        ).unwrap();
        let range = TimeRange::new(chrono::DateTime::parse_from_rfc3339("2026-09-30T00:00:00Z").unwrap().with_timezone(&chrono::Utc),
            chrono::DateTime::parse_from_rfc3339("2026-09-30T01:00:00Z").unwrap().with_timezone(&chrono::Utc));
        let scope = ScopeSet::from_denied(BTreeSet::from(["audit".to_string()]));
        let page = view.query_cloud_overview_section("page", Some("AWS"), Some("123"), &range, &scope).await.unwrap();
        assert_eq!(page.preview_events[0].id, "preview");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let full = view.query_cloud_overview(Some("AWS"), Some("123"), &range, &scope).await.unwrap();
        let full = serde_json::to_value(full).unwrap();
        for (section, fields) in [
            ("identities", vec!["accounts", "risky_principals"]),
            ("services", vec!["service_health"]), ("changes", vec!["anomalies", "changes"]),
            ("denied", vec![]),
        ] {
            let part = view.query_cloud_overview_section(section, Some("AWS"), Some("123"), &range, &scope).await.unwrap();
            let part = serde_json::to_value(part).unwrap();
            for field in fields { assert_eq!(part[field], full[field], "{section}.{field}"); }
            if section == "identities" {
                let mut header = part["header"].clone(); header["events_denied"] = full["header"]["events_denied"].clone();
                assert_eq!(header, full["header"]);
                assert_eq!(part["timeline"]["lanes"], full["timeline"]["lanes"]);
                assert_eq!(part["timeline"]["points"], full["timeline"]["points"]);
            }
            if section == "changes" { assert_eq!(part["timeline"]["markers"], full["timeline"]["markers"]); }
            if section == "denied" { assert_eq!(part["header"]["events_denied"], full["header"]["events_denied"]); }
        }
        assert_eq!(calls.load(Ordering::SeqCst), 9);
    }

    #[cfg(feature = "enterprise")]
    #[tokio::test]
    async fn dossier_preview_uses_one_bounded_scoped_read_and_keeps_filter_semantics() {
        use wiremock::{matchers::{method, path}, Mock, MockServer, ResponseTemplate};
        use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
        let server = MockServer::start().await;
        let tenant = uuid::Uuid::from_u128(0x3077);
        let temp = tempfile::tempdir().unwrap();
        let token_file = temp.path().join("router.token");
        std::fs::write(&token_file, "local-test-router-token-1234567890").unwrap();
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o400)).unwrap();
        }
        let calls = Arc::new(AtomicUsize::new(0));
        let recorded = calls.clone();
        Mock::given(method("POST"))
            .and(path(format!("/v1/tenants/{tenant}/query/v1/query")))
            .respond_with(move |request: &wiremock::Request| {
                let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                assert_eq!(body["deny_source_types"], json!(["audit"]));
                recorded.fetch_add(1, Ordering::SeqCst);
                let query = body["query"].as_str().unwrap();
                assert_eq!(body["limit"], 200);
                assert!(query.contains("cloud.account.uid=\"123\""));
                let rows = vec![json!({"time": "2026-09-30T00:05:00Z", "metadata.uid": "page-1",
                    "actor.user.name": "alice", "cloud.account.uid": "123", "cloud.provider": "AWS",
                    "api.service.name": "iam", "status": "Success"})];
                let answer = ResponseTemplate::new(200).set_body_json(json!({
                    "ok": true, "schema_version": 1, "request_id": body["request_id"], "tenant_id": tenant,
                    "route": "broad_npl", "source_mode": "parts", "wall_seconds": 0.01,
                    "result": {"result_rows": rows.len(), "rows": rows, "page_has_more": false}
                }));
                answer
            }).mount(&server).await;
        let pool = crate::db::DualPool::new_lake_control_plane(&crate::db::DualPoolConfig::with_auth(
            "postgres://unused:unused@127.0.0.1:1/nanosiem", "http://127.0.0.1:1", "nanosiem", "unused", "nanosiem",
        )).await.unwrap();
        let view = SearchService::with_dual_pool(&pool).enterprise_shared_cell_tenant_view(
            &crate::search::LakeCellRoute { tenant_id: tenant, assignment_generation: 1, part_log_writer_epoch: 1,
                worker_revision: 1, assignment_fenced: true, cell_origin: server.uri(),
                query_base_url: format!("{}/v1/tenants/{tenant}/query", server.uri()), router_token_file: token_file },
            crate::search::SearchTenantScope::enterprise_shared_retained(tenant, 1, 90, 0).unwrap(),
            Arc::new(crate::search::InMemoryJobStore::new()),
        ).unwrap();
        let range = TimeRange::new(chrono::DateTime::parse_from_rfc3339("2026-09-30T00:00:00Z").unwrap().with_timezone(&chrono::Utc),
            chrono::DateTime::parse_from_rfc3339("2026-09-30T01:00:00Z").unwrap().with_timezone(&chrono::Utc));
        let scope = ScopeSet::from_denied(BTreeSet::from(["audit".to_string()]));
        let filters = CloudDossierFacetFilters { services: vec!["IAM".into()], ..Default::default() };
        let preview = view.query_cloud_dossier_preview("alice", Some("123"), Some("AWS"), &filters, &range, &scope).await.unwrap();
        assert!(preview.bounded_preview);
        assert_eq!(preview.stream.len(), 1);
        assert_eq!(preview.stream[0].id, "page-1");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn cloud_dto_reads_exact_ocsf_paths() {
        let row = json!({
            "time": "2026-08-11 01:00:00.000000",
            "activity_name": "Create",
            "metadata": {"uid": "event-1", "log_source": "aws_cloudtrail"},
            "actor": {"user": {"name": "alice"}},
            "api": {"operation": "CreateBucket", "service": {"name": "s3"}},
            "cloud": {"provider": "AWS", "region": "us-east-1", "account": {"uid": "123"}},
            "src_endpoint": {"ip": "192.0.2.1"},
            "resources.uid": ["arn:bucket"],
            "resources.name": ["bucket"],
            "resources.type": ["AWS::S3::Bucket"],
        });
        let dto = cloud_event_dto(&row);
        assert_eq!(dto["cloud_service"], "s3");
        assert_eq!(dto["user"], "alice");
        assert_eq!(dto["resource_id"], "arn:bucket");
        assert_eq!(dto["details"]["actor"]["user"]["name"], "alice");
    }

    /// NAN-3059: the overview's identity groups are per principal, not per
    /// STS session ARN, and the session uid still classifies the principal.
    #[test]
    fn overview_identity_groups_are_per_principal_not_per_session() {
        let queries = cloud_overview_queries("class_uid=6003");
        let by = queries.identities.split(" by ").nth(1).unwrap();
        assert!(!by.contains("actor.user.uid"), "{}", queries.identities);
        assert!(queries.identities.contains("latest(actor.user.uid) as principal_uid"));
        parse_query(&queries.identities).expect("identity query parses");
        let row = json!({
            "actor.user.name": "eks-node-role",
            "principal_uid": "arn:aws:sts::123456789012:assumed-role/eks-node-role/session-1",
        });
        assert_eq!(cloud_principal_type("eks-node-role", Some(&row)), "assumed_role");
    }

    #[test]
    fn cloud_base_never_emits_legacy_query_names() {
        let query = parse_query("metadata.log_source=\"aws_cloudtrail\" | cloud").unwrap();
        let base = canonical_cloud_base_from_query(&query);
        assert!(base.contains("metadata.log_source"));
        assert!(base.contains("class_uid=6003"));
        assert!(!base.contains("source_type"));
        assert!(!base.contains("cloud_provider="));
    }

    #[test]
    fn dotted_cloud_projection_becomes_explicit_view_dto() {
        let row = json!({
            "time": "2026-08-11 01:00:00.000000",
            "activity_name": "Create",
            "metadata.uid": "event-2",
            "metadata.log_source": "aws_cloudtrail",
            "actor.user.name": "alice",
            "api.operation": "CreateBucket",
            "api.service.name": "s3",
            "cloud.provider": "AWS",
            "cloud.region": "us-east-1",
            "cloud.account.uid": "123",
            "src_endpoint.ip": "192.0.2.1",
            "resources": [{"uid": "arn:bucket", "name": "bucket", "type": "AWS::S3::Bucket"}],
        });
        let dto = cloud_event_dto(&row);
        assert_eq!(dto["cloud_service"], "s3");
        assert_eq!(dto["user"], "alice");
        assert_eq!(dto["resource_id"], "arn:bucket");
        assert_eq!(dto["source_type"], "aws_cloudtrail");
    }

    #[test]
    fn cloud_filters_compile_to_canonical_ocsf_predicates() {
        let filters = CloudEventFilters {
            cloud_providers: Some(vec!["AWS".to_string()]),
            cloud_services: Some(vec!["IAM".to_string()]),
            cloud_regions: Some(vec!["us-east-1".to_string()]),
            cloud_account_ids: Some(vec!["123".to_string()]),
            resource_types: Some(vec!["AWS::IAM::Role".to_string()]),
            change_types: Some(vec!["Create".to_string()]),
            search_text: Some("alice".to_string()),
        };
        let predicate = build_cloud_filter_predicate(Some(&filters))
            .unwrap()
            .unwrap();
        assert!(predicate.contains("cloud.provider IN"));
        assert!(predicate.contains("array_contains(resources.type"));
        assert!(predicate.contains("actor.user.name contains"));
        assert!(!predicate.contains("cloud_provider"));
        parse_query(&predicate).expect("generated cloud predicate must remain valid nPL");
    }

    #[test]
    fn durable_cloud_companion_assemblers_preserve_exact_typed_semantics() {
        let rows = vec![
            json!({
                "time": "2026-08-11 01:00:00.000000",
                "metadata.uid": "event-1",
                "actor.user.name": "alice",
                "api.operation": "CreateBucket",
                "api.service.name": "s3",
                "cloud.provider": "AWS",
                "cloud.region": "us-east-1",
                "src_endpoint.ip": "192.0.2.1",
                "resources": [{"uid": "arn:bucket:one", "name": "one"}],
                "status": "Success",
            }),
            json!({
                "time": "2026-08-11 02:00:00.000000",
                "metadata.uid": "event-2",
                "actor.user.name": "alice",
                "api.operation": "DeleteBucket",
                "api.service.name": "s3",
                "cloud.provider": "AWS",
                "cloud.region": "us-west-2",
                "src_endpoint.ip": "192.0.2.2",
                "resources": [{"uid": "arn:bucket:two", "name": "two"}],
                "status": "Failure",
            }),
        ];

        let (timeline, summary) = SearchService::assemble_lake_cloud_user_timeline(rows.clone());
        assert_eq!(timeline.len(), 2);
        assert_eq!(summary.event_count, 2);

        let (events, references, entity_summary) =
            SearchService::assemble_lake_cloud_entity_pivot(rows, "resource", "arn:bucket:one");
        assert_eq!(events.len(), 1);
        assert_eq!(entity_summary["event_count"], 1);
        assert!(references.iter().any(|reference| {
            reference.entity_type == "user" && reference.entity_value == "alice"
        }));
    }

    #[test]
    fn grouped_cloud_rows_preserve_exact_counts() {
        let providers = vec![json!({"cloud.provider": "AWS", "event_count": 12})];
        let services = vec![json!({"api.service.name": "iam", "event_count": 7})];
        let regions = vec![json!({"cloud.region": "us-east-1", "event_count": 12})];
        let accounts = vec![json!({"cloud.account.uid": "123", "event_count": 12})];
        let resources = vec![json!({"resources.type": "AWS::IAM::Role", "event_count": 3})];
        let changes = vec![json!({"activity_name": "Create", "event_count": 4})];
        let facets = cloud_facets_from_grouped(
            &providers, &services, &regions, &accounts, &resources, &changes,
        );
        assert_eq!(facets.cloud_provider, vec![("AWS".to_string(), 12)]);
        assert_eq!(
            facets.resource_type,
            vec![("AWS::IAM::Role".to_string(), 3)]
        );
        assert_eq!(facets.change_type, vec![("Create".to_string(), 4)]);

        let rollup = cloud_resource_rollup_from_grouped(&[json!({
            "resource_id": "arn:bucket",
            "resource_name": "bucket",
            "resource_type": "AWS::S3::Bucket",
            "event_count": 3,
            "change_types": "Delete, Read, PutBucketAcl",
        })]);
        assert_eq!(
            rollup[0]["change_types"],
            json!(["Delete", "Read", "PutBucketAcl"])
        );
    }

    /// NAN-3465: a CloudTrail-style failure carrying only `status_id` 2.
    #[test]
    fn cloud_error_reads_status_id() {
        assert!(cloud_error(&json!({"status_id": 2})));
        assert!(!cloud_error(&json!({"status_id": 1})));
        assert!(cloud_error(&json!({"status": "Failure"})));
        assert!(LAKE_CLOUD_PROJECTION.contains(&"status_id"));
    }

    #[test]
    fn cloud_server_aggregate_shapes_parse_as_npl() {
        parse_query(
            "class_uid=6003 | eval resource_pair=mvzip(resources.uid,resources.name,\"||\"), resource_tuple=mvzip(resource_pair,resources.type,\"||\") | mvexpand resource_tuple | eval resource_parts=split(resource_tuple,\"||\"), resource_id=mvindex(resource_parts,0), resource_name=mvindex(resource_parts,1), resource_type=mvindex(resource_parts,2) | where resource_id!=\"\" | stats count() as event_count, min(time) as first_seen, max(time) as last_seen, values(activity_name) as change_types by resource_id, resource_name, resource_type | sort -event_count | head 100",
        )
        .expect("resource rollup must parse");
        parse_query(
            "class_uid=6003 | eval cloud_user=coalesce(actor.user.name,user.name) | where cloud_user!=\"\" | stats count() as event_count, dc(api.service.name) as distinct_services, count(eval(status_id=2 OR lower(status)=\"failure\" OR http_response.code>=400)) as fail_count by cloud_user | sort -event_count | head 100",
        )
        .expect("user activity rollup must parse");
    }

    #[test]
    fn durable_cloud_assemblers_return_typed_product_payloads() {
        let range = TimeRange::new(
            chrono::DateTime::parse_from_rfc3339("2026-08-11T00:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            chrono::DateTime::parse_from_rfc3339("2026-08-11T02:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        );
        let identity = json!({
            "events": 4,
            "last_seen": "2026-08-11T01:30:00Z",
            "cloud.provider": "AWS",
            "cloud.account.uid": "123",
            "cloud.region": "us-east-1",
            "actor.user.name": "alice",
        });
        let service = json!({
            "events": 4,
            "last_seen": "2026-08-11T01:30:00Z",
            "api.service.name": "iam",
            "cloud.account.uid": "123",
            "status": "Success",
        });
        let overview = SearchService::assemble_lake_cloud_overview(
            vec![identity],
            vec![service],
            Vec::new(),
            0,
            &range,
            &BTreeMap::from([("alice".to_string(), (72, Some("rule".to_string())))]),
        );
        assert_eq!(overview.header.events_total, 4);
        assert_eq!(overview.risky_principals[0].risk, 72);

        let dossier = SearchService::assemble_lake_cloud_dossier(
            "alice",
            vec![json!({
                "time": "2026-08-11T01:30:00Z",
                "metadata.uid": "event-1",
                "cloud.provider": "AWS",
                "cloud.account.uid": "123",
                "cloud.region": "us-east-1",
                "actor.user.name": "alice",
                "api.operation": "ListRoles",
                "api.service.name": "iam",
                "status": "Success",
            })],
            &CloudDossierFacetFilters::default(),
            &range,
            Some((72, Some("rule".to_string()))),
        );
        assert_eq!(dossier.identity.id, "alice");
        assert_eq!(dossier.risk.score, 72);
        assert_eq!(dossier.error_rate.events_total, 1);
        assert!(dossier.durable_job.is_none());

        let (total, facets, resources, users) = SearchService::assemble_lake_cloud_events_summary(
            &[json!({"event_count": 42})],
            &[json!({"cloud.provider": "AWS", "event_count": 42})],
            &[json!({"api.service.name": "iam", "event_count": 30})],
            &[json!({"cloud.region": "us-east-1", "event_count": 42})],
            &[json!({"cloud.account.uid": "123", "event_count": 42})],
            &[json!({"resources.type": "AWS::IAM::Role", "event_count": 8})],
            &[json!({"activity_name": "Update", "event_count": 11})],
            &[json!({
                "resource_id": "arn:role/admin",
                "resource_name": "admin",
                "resource_type": "AWS::IAM::Role",
                "event_count": 8,
                "change_types": "Create, Update",
            })],
            &[json!({
                "cloud_user": "alice",
                "event_count": 30,
                "distinct_services": 2,
                "fail_count": 3,
            })],
            true,
        );
        assert_eq!(total, 42);
        assert_eq!(facets.cloud_provider, vec![("AWS".to_string(), 42)]);
        assert_eq!(
            resources.as_ref().unwrap()[0]["resource_id"],
            "arn:role/admin"
        );
        assert_eq!(users.as_ref().unwrap()[0].fail_count, 3);
    }
}

#[cfg(test)]
#[path = "lake_cloud_dossier_stream_tests.rs"]
mod dossier_stream_tests;
