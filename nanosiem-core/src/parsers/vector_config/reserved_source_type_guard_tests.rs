// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5032: platform-owned source types are rewritten at the UDM storage
//! boundary of the generated pipeline, and the three copies of the list (Rust
//! registry, VRL guard, ClickHouse backstop) agree.

use serde_json::{json, Value};

use super::RESERVED_SOURCE_TYPE_GUARD_VRL;
use crate::auth::reserved_source_types::{
    ENFORCED, PLATFORM_LANES, SPOOF_MARKER, WARN_ONLY, WARN_ONLY_PREFIXES,
};

const CH_BACKSTOP: &str = include_str!("../../../../clickhouse/192_reserved_source_type_guard.sql");

fn run(event: Value) -> Value {
    let compiled = vrl::compiler::compile(RESERVED_SOURCE_TYPE_GUARD_VRL, &vrl::stdlib::all())
        .unwrap_or_else(|d| panic!("guard VRL compiles: {d:?}"))
        .program;
    let mut target = vrl::compiler::TargetValue {
        value: vrl::value::Value::from(event),
        metadata: vrl::value::Value::from(json!({})),
        secrets: vrl::value::Secrets::new(),
    };
    vrl::compiler::runtime::Runtime::new(vrl::compiler::state::RuntimeState::default())
        .resolve(&mut target, &compiled, &vrl::compiler::TimeZone::Local)
        .unwrap_or_else(|e| panic!("VRL runtime: {e:?}"));
    target.value.try_into().expect("event json")
}

#[test]
fn a_forged_audit_or_findings_row_is_rewritten_and_the_claim_kept() {
    for forged in ["audit", "AUDIT", "Findings", "findings"] {
        let out = run(json!({"source_type": forged, "user": "ceo", "action": "login"}));
        assert_eq!(out["source_type"], SPOOF_MARKER, "{forged} was stored as-is");
        assert_eq!(out["claimed_source_type"], forged, "the forgery attempt must stay visible");
    }
}

#[test]
fn an_existing_claim_is_not_overwritten() {
    let out = run(json!({"source_type": "audit", "claimed_source_type": "audit_from_body"}));
    assert_eq!(out["source_type"], SPOOF_MARKER);
    assert_eq!(out["claimed_source_type"], "audit_from_body");
}

#[test]
fn ordinary_and_warn_only_source_types_are_untouched() {
    for legit in [
        "syslog",
        "linux_audit",
        "auditd",
        "parse_failure",
        "unknown",
        "otlp_log",
        "nano_enrich",
        "nano_operational",
        "signal", // warn-only in v2.0.1
        "nano_custom",
    ] {
        let out = run(json!({"source_type": legit}));
        assert_eq!(out["source_type"], legit, "{legit} must not be rewritten");
        assert!(out.get("claimed_source_type").is_none());
    }
    // A missing source_type stays missing.
    let out = run(json!({"message": "x"}));
    assert!(out.get("source_type").is_none());
}

#[test]
fn the_three_copies_of_the_reserved_list_agree() {
    for v in ENFORCED {
        assert!(
            RESERVED_SOURCE_TYPE_GUARD_VRL.contains(&format!("\"{v}\"")),
            "VRL guard misses enforced value {v}"
        );
        assert!(CH_BACKSTOP.contains(&format!("'{v}'")), "CH backstop misses {v}");
    }
    assert!(RESERVED_SOURCE_TYPE_GUARD_VRL.contains(&format!("\"{SPOOF_MARKER}\"")));
    assert!(CH_BACKSTOP.contains(&format!("'{SPOOF_MARKER}'")));
    for v in WARN_ONLY.iter().chain(WARN_ONLY_PREFIXES).chain(PLATFORM_LANES) {
        assert!(RESERVED_SOURCE_TYPE_GUARD_VRL.contains(&format!("\"{v}\"")), "VRL misses {v}");
    }
}

#[test]
fn the_guard_is_spliced_into_the_udm_storage_boundary() {
    let deploy = include_str!("deploy.rs");
    let mapping = deploy
        .split("[transforms.clickhouse_mapping]")
        .nth(1)
        .expect("clickhouse_mapping transform");
    let mapping = &mapping[..mapping.find("[transforms.").unwrap_or(mapping.len())];
    assert!(
        mapping.contains("reserved_source_type_guard_vrl!()"),
        "clickhouse_mapping (the one block every UDM row passes) lost the reserved guard"
    );
}

// --- OCSF generic lane (review) --------------------------------------------

fn run_ocsf(declared: &str) -> String {
    let program = format!(
        "src_type = {declared:?}\n{}\n.out = src_type\n",
        super::RESERVED_OCSF_SOURCE_TYPE_GUARD_VRL
    );
    let compiled = vrl::compiler::compile(&program, &vrl::stdlib::all())
        .unwrap_or_else(|d| panic!("OCSF guard VRL compiles: {d:?}"))
        .program;
    let mut target = vrl::compiler::TargetValue {
        value: vrl::value::Value::from(json!({})),
        metadata: vrl::value::Value::from(json!({})),
        secrets: vrl::value::Secrets::new(),
    };
    vrl::compiler::runtime::Runtime::new(vrl::compiler::state::RuntimeState::default())
        .resolve(&mut target, &compiled, &vrl::compiler::TimeZone::Local)
        .unwrap_or_else(|e| panic!("VRL runtime: {e:?}"));
    let out: Value = target.value.try_into().expect("event json");
    out["out"].as_str().unwrap().to_string()
}

#[test]
fn the_ocsf_generic_lane_rewrites_forged_findings_and_audit() {
    // `src_type` is already downcased by generic_ocsf_prepare.
    assert_eq!(run_ocsf("findings"), SPOOF_MARKER);
    assert_eq!(run_ocsf("audit"), SPOOF_MARKER);
    for legit in ["syslog", "linux_audit", "unknown", "otlp_log", "nano_enrich"] {
        assert_eq!(run_ocsf(legit), legit);
    }
}

#[test]
fn the_ocsf_guard_is_spliced_where_the_row_source_type_is_stamped() {
    let deploy = include_str!("deploy.rs");
    let lane = deploy
        .split("[transforms.generic_ocsf_prepare]")
        .nth(1)
        .expect("generic_ocsf_prepare transform");
    let guard = lane.find("reserved_ocsf_source_type_guard_vrl!()").expect("guard spliced");
    let stamp = lane.find(r#""source_type": src_type"#).expect("row stamp");
    assert!(guard < stamp, "the rewrite must run before the row's source_type is stamped");
}
