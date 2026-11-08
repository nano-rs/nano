// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4954: event identity and timestamps that make outbox re-delivery safe.

use super::emitter::udm_row_id;
use super::{AuditEvent, AuditSource};

#[test]
fn event_identity_is_fixed_at_build_time() {
    let event = AuditEvent::builder(AuditSource::Auth, "login_success")
        .actor(None, Some("Dan".to_string()))
        .build();
    // The UDM row id is derived from occurred_at + message, so a re-delivery
    // minutes later produces the same id (the drainer's duplicate check).
    let first = udm_row_id(&event);
    std::thread::sleep(std::time::Duration::from_millis(5));
    assert_eq!(first, udm_row_id(&event));
    assert_eq!(event.to_parsed_log().timestamp, event.occurred_at);

    let other = AuditEvent::builder(AuditSource::Auth, "login_success").build();
    assert_ne!(event.event_id, other.event_id);
}

#[test]
fn outbox_json_round_trips_and_old_payloads_still_load() {
    let event = AuditEvent::builder(AuditSource::ApiKey, "apikey_created").build();
    let json = serde_json::to_value(&event).unwrap();
    let back: AuditEvent = serde_json::from_value(json).unwrap();
    assert_eq!(back.event_id, event.event_id);
    assert_eq!(back.occurred_at, event.occurred_at);

    // Events serialized before NAN-4954 (full-event log lines) lack both fields.
    let old = serde_json::json!({
        "source": "auth", "action": "login_success", "actor_id": null,
        "actor_name": null, "api_key_id": null, "api_key_name": null,
        "resource_type": null, "resource_id": null, "resource_name": null,
        "ip_address": null, "user_agent": null, "success": true, "details": null
    });
    let loaded: AuditEvent = serde_json::from_value(old).expect("pre-NAN-4954 event loads");
    assert_eq!(loaded.action, "login_success");
}
