// SPDX-License-Identifier: AGPL-3.0-or-later

use super::{SearchResponse, SearchStreamEvent};
use serde_json::json;

#[test]
fn response_request_timing_is_optional_and_distinct_on_the_wire() {
    let mut response = SearchResponse::empty();
    let old_wire = serde_json::to_value(&response).unwrap();
    assert!(old_wire.get("server_wall_ms").is_none());
    assert!(old_wire.get("queue_wait_ms").is_none());

    response.execution_time_ms = 1_920;
    response.server_wall_ms = Some(23_300);
    response.queue_wait_ms = Some(18_000);
    let wire = serde_json::to_value(&response).unwrap();
    assert_eq!(wire["execution_time_ms"], json!(1_920));
    assert_eq!(wire["server_wall_ms"], json!(23_300));
    assert_eq!(wire["queue_wait_ms"], json!(18_000));

    let mut legacy = wire;
    legacy.as_object_mut().unwrap().remove("server_wall_ms");
    legacy.as_object_mut().unwrap().remove("queue_wait_ms");
    let decoded: SearchResponse = serde_json::from_value(legacy).unwrap();
    assert_eq!(decoded.server_wall_ms, None);
    assert_eq!(decoded.queue_wait_ms, None);
}

#[test]
fn stream_metadata_serializes_distinct_request_timing() {
    let event = SearchStreamEvent::Metadata {
        total_count: 3,
        execution_time_ms: 1_920,
        server_wall_ms: Some(23_300),
        queue_wait_ms: Some(18_000),
        fields: Vec::new(),
        histogram: None,
        warnings: None,
        cost_score: None,
        display_type: None,
        column_order: None,
        generated_sql: None,
    };
    let wire = serde_json::to_value(event).unwrap();
    assert_eq!(wire["data"]["execution_time_ms"], 1_920);
    assert_eq!(wire["data"]["server_wall_ms"], 23_300);
    assert_eq!(wire["data"]["queue_wait_ms"], 18_000);
}
