// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3078: the retention-cutoff proof a durable product view carries, and
//! the typed view tasks a lean cell runs.

use super::*;
use chrono::Duration;

#[cfg(feature = "enterprise")]
fn tenant(days: u16, floor_micros: i64) -> SearchTenantScope {
    SearchTenantScope::enterprise_shared_retained(Uuid::from_u128(0xa), 3, days, floor_micros).unwrap()
}

#[cfg(feature = "enterprise")]
fn proof_for(tenant: SearchTenantScope, now: DateTime<Utc>, start: DateTime<Utc>) -> DurableResultRetentionProof {
    DurableResultRetentionProof::from_shared_job(tenant, now, &TimeRangeInput::new(start, now)).unwrap()
}

#[cfg(feature = "enterprise")]
fn result_ref(tenant: SearchTenantScope, proof: DurableResultRetentionProof) -> SearchJobResultRef {
    SearchJobResultRef {
        tenant_id: tenant.tenant_id(),
        manifest_uri: "s3://results/manifest.json".to_string(),
        manifest_sha256: "a".repeat(64),
        rows: 1,
        parts: 1,
        has_more: false,
        page_rows: 10_000,
        retention_proof: Some(proof),
    }
}

#[cfg(feature = "enterprise")]
#[test]
fn a_job_range_that_crosses_the_cutoff_is_admitted_only_from_the_cutoff() {
    let now = Utc::now();
    let tenant = tenant(30, 0);
    // The caller asked for 40 days; the tenant keeps 30. A proof over the
    // raw range is refused, so the admitted range must start at the cutoff.
    let raw = TimeRangeInput::new(now - Duration::days(40), now);
    assert!(DurableResultRetentionProof::from_shared_job(tenant, now, &raw).is_err());
    let cutoff = tenant.event_time_cutoff(now).unwrap();
    let proof = proof_for(tenant, now, cutoff);
    assert_eq!(proof.min_event_time_micros, cutoff.timestamp_micros());
}

#[cfg(feature = "enterprise")]
#[test]
fn the_execution_floor_follows_the_moving_cutoff() {
    // Proof times are microseconds.
    let now = DateTime::from_timestamp_micros(Utc::now().timestamp_micros()).unwrap();
    let tenant = tenant(30, 0);
    let cutoff = tenant.event_time_cutoff(now).unwrap();
    let proof = proof_for(tenant, now, cutoff);
    // Executed at once, the floor is the admitted start.
    assert_eq!(proof.execution_floor(now).unwrap(), cutoff);
    // A job that waited a day reads one day less: the floor is the cutoff
    // at execution, never the stale cutoff at admission.
    let later = now + Duration::days(1);
    assert_eq!(proof.execution_floor(later).unwrap(), tenant.event_time_cutoff(later).unwrap());
    // A clock behind the evaluation never lowers the floor.
    assert_eq!(proof.execution_floor(now - Duration::days(5)).unwrap(), cutoff);
    // A range that starts after the cutoff keeps its own start.
    let inside = proof_for(tenant, now, now - Duration::hours(1));
    assert_eq!(inside.execution_floor(now).unwrap(), now - Duration::hours(1));
}

#[cfg(feature = "enterprise")]
#[test]
fn an_irreversible_erasure_floor_raises_the_execution_floor() {
    let now = DateTime::from_timestamp_micros(Utc::now().timestamp_micros()).unwrap();
    let erased = now - Duration::days(3);
    let tenant = tenant(90, erased.timestamp_micros());
    let proof = proof_for(tenant, now, erased);
    assert_eq!(proof.execution_floor(now).unwrap(), erased);
    assert!(DurableResultRetentionProof::from_shared_job(
        tenant,
        now,
        &TimeRangeInput::new(erased - Duration::seconds(1), now),
    )
    .is_err());
}

#[cfg(feature = "enterprise")]
#[test]
fn a_forged_or_inconsistent_proof_bounds_nothing() {
    let now = Utc::now();
    let tenant = tenant(30, 0);
    let proof = proof_for(tenant, now, tenant.event_time_cutoff(now).unwrap());
    let forged = |edit: fn(&mut DurableResultRetentionProof)| {
        let mut proof = proof.clone();
        edit(&mut proof);
        proof.execution_floor(now)
    };
    // A cutoff that is not the policy's cutoff at evaluation.
    assert!(forged(|p| p.cutoff_micros -= 86_400_000_000).is_err());
    // A contribution range that starts before its own cutoff.
    assert!(forged(|p| p.min_event_time_micros = p.cutoff_micros - 1).is_err());
    // A retention period outside the product's closed set.
    assert!(forged(|p| p.retention_days = 7).is_err());
    // An empty or reversed range.
    assert!(forged(|p| p.max_event_time_micros = p.min_event_time_micros).is_err());
}

#[cfg(feature = "enterprise")]
#[test]
fn a_view_result_expires_when_the_cutoff_crosses_its_start() {
    let now = Utc::now();
    let tenant = tenant(30, 0);
    let start = now - Duration::days(10);
    let reference = result_ref(tenant, proof_for(tenant, now, start));
    let admitted = TimeRangeInput::new(start, now);
    reference.verify_retention_for_range(tenant, &admitted, now).unwrap();
    reference
        .verify_retention_for_range(tenant, &admitted, now + Duration::days(19))
        .unwrap();
    // Twenty days later the cutoff is past the result's oldest possible
    // contributing event: the whole artifact is hidden, not trimmed.
    assert!(reference
        .verify_retention_for_range(tenant, &admitted, now + Duration::days(20) + Duration::seconds(1))
        .is_err());
    // Another tenant's scope never verifies it.
    let other = SearchTenantScope::enterprise_shared_retained(Uuid::from_u128(0xb), 3, 30, 0).unwrap();
    assert!(reference.verify_retention_for_range(other, &admitted, now).is_err());
}

fn baseline_task() -> DurableLakeTask {
    let end = Utc::now();
    DurableLakeTask::BaselineV1 {
        entity_type: "host".to_string(),
        entity_value: "gate-01".to_string(),
        window_days: 7,
        activity_days: 30,
        dims: None,
        incident_start_micros: (end - Duration::hours(1)).timestamp_micros(),
        incident_end_micros: end.timestamp_micros(),
    }
}

#[test]
fn baseline_tasks_validate_their_typed_inputs() {
    let task = baseline_task();
    task.validate().unwrap();
    assert_eq!(task.kind(), "baseline_v1");
    let invalid = |edit: fn(&mut DurableLakeTask)| {
        let mut task = baseline_task();
        edit(&mut task);
        task.validate().is_err()
    };
    assert!(invalid(|t| if let DurableLakeTask::BaselineV1 { entity_type, .. } = t { *entity_type = "process".into() }));
    assert!(invalid(|t| if let DurableLakeTask::BaselineV1 { entity_value, .. } = t { *entity_value = "a\nb".into() }));
    assert!(invalid(|t| if let DurableLakeTask::BaselineV1 { window_days, .. } = t { *window_days = 91 }));
    assert!(invalid(|t| if let DurableLakeTask::BaselineV1 { dims, .. } = t { *dims = Some(Vec::new()) }));
    assert!(invalid(|t| if let DurableLakeTask::BaselineV1 { incident_start_micros, incident_end_micros, .. } = t {
        *incident_start_micros = *incident_end_micros - 8 * 86_400_000_000;
    }));
    // Round-trips through the signed job envelope's JSON.
    let wire = serde_json::to_string(&task).unwrap();
    assert_eq!(serde_json::from_str::<DurableLakeTask>(&wire).unwrap(), task);
}

#[test]
fn only_range_bounded_views_run_on_a_lean_cell() {
    assert!(baseline_task().is_lean_view());
    assert!(!DurableLakeTask::SearchNplV1.is_lean_view());
    assert!(DurableLakeTask::SearchNplV1.is_search());
    // NAN-3086: every Retro read is a sub-window of the admitted range, so
    // it runs on the cell under the proof. NAN-3088: so does a prevalence
    // export, whose cell relation is built over the clamped window.
    let retro = DurableLakeTask::RetroV1 {
        indicators: vec!["1.2.3.4".to_string()],
        axis: "indicator".to_string(),
        submode: "summary".to_string(),
        offset: 0,
        limit: 10,
    };
    assert!(retro.is_lean_view() && !retro.is_search());
    let export = DurableLakeTask::PrevalenceExportV1 {
        window: "24h".to_string(),
        artifact_type: None,
        max_prevalence: 5,
        format: "csv".to_string(),
    };
    assert!(export.is_lean_view() && !export.is_search());
    // Views whose artifact is the event set itself need a streaming
    // assembler first.
    let timeline = DurableLakeTask::CloudUserTimelineV1 { user: "alice".into(), event_query: "*".into() };
    assert!(!timeline.is_lean_view());
}
