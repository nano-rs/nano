// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5683: the `log_source_deleted` audit row names the deleted source and,
//! read back through the audit API, carries its public `lsrc_` TypeID — for a
//! single delete and for every source of a bulk delete.

use super::*;
use nanosiem_core::audit::query::ClickHouseAuditEntry;
use nanosiem_core::auth::api_key::ApiKeyInfo;

fn auth() -> AuthContext {
    AuthContext::from_api_key(&ApiKeyInfo {
        id: uuid::Uuid::now_v7(),
        name: "NAN-5683 deleter".to_string(),
        permissions: vec![nanosiem_core::auth::permissions::LOG_SOURCES_DELETE.to_string()],
        user_id: Some(uuid::Uuid::now_v7()),
    })
}

/// What the audit API returns for `event` once it is stored (the store keeps
/// the raw UUID and the name; the read path renders the TypeID).
fn read_back(event: &AuditEvent) -> crate::handlers::audit::AuditLogEntry {
    let metadata = event.metadata_json();
    crate::handlers::audit::AuditLogEntry::from(ClickHouseAuditEntry {
        event_id: "evt".to_string(),
        timestamp: chrono::Utc::now(),
        user: None,
        action: Some(event.action.clone()),
        source: None,
        src_ip: None,
        user_agent: None,
        status: Some("success".to_string()),
        message: event.message(),
        metadata: metadata.clone(),
        actor_id: None,
        resource_type: event.resource_type.clone(),
        resource_id: event.resource_id.map(|id| id.to_string()),
        resource_name: event.resource_name.clone(),
        api_key_id: None,
        api_key_name: None,
    })
}

#[test]
fn deleted_event_records_the_source_name_and_public_id() {
    let id = uuid::Uuid::now_v7();
    let deleted = DeletedLogSource { name: "fw-edge-syslog".to_string() };
    let event = log_source_deleted_event(&auth(), &ClientContext::default(), id, &deleted, None, &[]);

    assert_eq!(event.action, LOG_SOURCE_DELETED);
    assert_eq!(event.resource_type.as_deref(), Some("log_source"));
    assert_eq!(event.resource_id, Some(id));
    assert_eq!(event.resource_name.as_deref(), Some("fw-edge-syslog"));

    let row = read_back(&event);
    let public_id = nanosiem_core::typeid::encode(nanosiem_core::typeid::log_source::PREFIX, &id);
    assert_eq!(row.resource_id.as_deref(), Some(public_id.as_str()));
    assert!(public_id.starts_with("lsrc_"));
    assert_eq!(row.resource_name.as_deref(), Some("fw-edge-syslog"));
}

#[test]
fn bulk_delete_audits_each_source_by_its_own_name() {
    let sources: Vec<(uuid::Uuid, DeletedLogSource)> = (0..3)
        .map(|i| (uuid::Uuid::now_v7(), DeletedLogSource { name: format!("bulk-{i}") }))
        .collect();
    let auth = auth();
    let rows: Vec<_> = sources
        .iter()
        .map(|(id, deleted)| read_back(&log_source_deleted_event(&auth, &ClientContext::default(), *id, deleted, None, &[])))
        .collect();
    for ((id, deleted), row) in sources.iter().zip(&rows) {
        assert_eq!(row.resource_name.as_deref(), Some(deleted.name.as_str()));
        assert_eq!(
            row.resource_id,
            Some(nanosiem_core::typeid::encode(nanosiem_core::typeid::log_source::PREFIX, id))
        );
    }
}

#[test]
fn deleted_event_records_the_health_tombstone() {
    let id = uuid::Uuid::now_v7();
    let deleted = DeletedLogSource { name: "fw".to_string() };
    let keys = vec!["fw_edge".to_string()];
    let with = log_source_deleted_event(&auth(), &ClientContext::default(), id, &deleted, Some(&keys), &[]);
    let details = with.metadata_json();
    let text = serde_json::to_string(&details).unwrap();
    assert!(text.contains("health_tombstone") && text.contains("fw_edge"), "{text}");

    let without = log_source_deleted_event(&auth(), &ClientContext::default(), id, &deleted, None, &[]);
    let text = serde_json::to_string(&without.metadata_json()).unwrap();
    assert!(text.contains("\"recorded\":false"), "{text}");
}

/// NAN-5785: a delete that left a live stale-feed alert open names it in the
/// source's delete audit row.
#[test]
fn deleted_event_names_the_alerts_left_open() {
    let id = uuid::Uuid::now_v7();
    let alert = uuid::Uuid::now_v7();
    let deleted = DeletedLogSource { name: "fw".to_string() };
    let event = log_source_deleted_event(&auth(), &ClientContext::default(), id, &deleted, None, &[alert]);
    let text = serde_json::to_string(&event.metadata_json()).unwrap();
    assert!(text.contains("health_alerts_left_open") && text.contains(&alert.to_string()), "{text}");
}

/// NAN-5785: an update records every monitoring field it actually changed
/// (from/to), and nothing for a no-op.
#[test]
fn update_audit_records_monitoring_changes() {
    assert_eq!(
        monitoring_changes((true, true, 15), (true, false, 10080)),
        serde_json::json!({
            "stale_alert_enabled": {"from": true, "to": false},
            "stale_threshold_minutes": {"from": 15, "to": 10080},
        })
    );
    assert_eq!(monitoring_changes((false, false, 15), (false, false, 15)), serde_json::json!({}));
}
