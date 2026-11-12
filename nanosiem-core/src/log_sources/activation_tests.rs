// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use crate::parsers::vector_config_remote_delivery::{DeliveryState, GenerationDelivery};

#[test]
fn available_needs_slots_and_a_verifiable_reload() {
    assert!(available_with(true, false, None));
    assert!(available_with(true, false, Some("on")));
    assert!(!available_with(false, false, None), "no parked filter without slots");
    assert!(!available_with(true, true, None), "a pull install cannot verify phase A");
    for off in ["off", "OFF", "false", "0", " off "] {
        assert!(!available_with(true, false, Some(off)), "{off}");
    }
}

#[test]
fn only_router_fed_log_sources_take_two_phases() {
    assert!(eligible("log", "routed"));
    assert!(eligible("log", "http"));
    assert!(eligible("log", "apache_access"));
    assert!(eligible("log", "vector"));
    assert!(!eligible("enrichment", "routed"));
    for lane in ["splunk_hec", "hec", "otlp", "opentelemetry", "kafka", "aws_s3", "gcp_pubsub"] {
        assert!(!eligible("log", lane), "{lane}");
    }
}

fn delivered(state: DeliveryState, pending: &[&str]) -> Option<(String, GenerationDelivery)> {
    Some((
        format!("generation 7: {state:?}"),
        GenerationDelivery {
            state,
            generation: 7,
            host_count: 3,
            pending_hosts: pending.iter().map(|h| h.to_string()).collect(),
            sync_interval_secs: 5,
            status_path: "/api/log-sources/delivery-status?generation=7".to_string(),
        },
    ))
}

/// Role split (multi-host): phase B (routing) may only go out once EVERY
/// ingest host acknowledged phase A. A reload the deploy counts as live can
/// still leave hosts installing (`Pending`, NAN-5279); that, a missing report
/// and every other state withdraw the deploy, carrying the delivery note.
#[test]
fn role_split_phase_a_needs_every_host_acknowledged() {
    assert_eq!(staged_on_every_host(delivered(DeliveryState::Acknowledged, &[])), Ok(()));
    for (state, pending) in [
        (DeliveryState::Pending, &["http://ingest-2:9600"][..]),
        (DeliveryState::Rejected, &[][..]),
        (DeliveryState::Unconfirmed, &[][..]),
        (DeliveryState::NotApplicable, &[][..]),
    ] {
        let note = staged_on_every_host(delivered(state, pending)).expect_err(&format!("{state:?}"));
        assert_eq!(note, format!("generation 7: {state:?}"), "the withdrawal carries the delivery note");
    }
    assert_eq!(
        staged_on_every_host(None),
        Err("no ingest host reported it".to_string()),
        "no delivery report is no evidence: withdraw"
    );
}
