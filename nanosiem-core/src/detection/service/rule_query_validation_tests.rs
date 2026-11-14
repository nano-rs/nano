// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5348: rule queries naming a field the profile refuses.
//!
//! - Save time: create / update / import run the search path's field
//!   validator, so `hostname` on OCSF is rejected with "did you mean".
//! - Execution: a refused field (`FieldNotFound`) or a generation guardrail
//!   (`SqlGenError` "Invalid query: …") is a deterministic failure, so the
//!   scheduler backs the rule off (NAN-4031) instead of retrying every tick.

use super::execution::detection_error_from_search;
use super::DetectionService;
use crate::detection::distributed_scheduler::is_deterministic_failure;
use crate::detection::DetectionError;
use crate::schema::{OcsfProfile, UdmProfile};
use crate::search::SearchError;

fn deterministic(e: SearchError) -> bool {
    is_deterministic_failure::<()>(&Err(detection_error_from_search(e)))
}

#[test]
fn refused_field_and_guardrails_back_off() {
    assert!(deterministic(SearchError::FieldNotFound {
        field: "hostname".into(),
        suggestions: vec!["device.hostname".into()],
        message: "Field 'hostname' is not an OCSF field".into(),
    }));
    assert!(deterministic(SearchError::SqlGenError(
        "Invalid query: 'tcpx' is not a valid value for 'protocol'".into()
    )));
    assert!(deterministic(SearchError::SqlGenError(
        "Unsupported operation: x".into()
    )));
    assert!(deterministic(SearchError::SqlValidationError("bad".into())));
    assert!(deterministic(SearchError::ParseError("bad".into())));
    // Outages keep retrying.
    assert!(!deterministic(SearchError::Timeout(30_000)));
    assert!(!deterministic(SearchError::SqlGenError("internal".into())));
}

#[test]
fn refused_field_message_keeps_the_suggestions() {
    let e = detection_error_from_search(SearchError::FieldNotFound {
        field: "hostname".into(),
        suggestions: vec!["device.hostname".into(), "src_endpoint.hostname".into()],
        message: "Field 'hostname' is not an OCSF field".into(),
    });
    match e {
        DetectionError::InvalidQuery(m) => {
            assert!(m.contains("device.hostname, src_endpoint.hostname"), "{m}")
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn save_rejects_a_refused_field_with_did_you_mean() {
    let ocsf = OcsfProfile::new();
    let err = DetectionService::validate_rule_query_with_profile(
        &ocsf,
        r#"class_uid=1007 hostname="ws-01" | stats count by hostname"#,
        None,
    )
    .unwrap_err();
    match err {
        DetectionError::InvalidQuery(m) => {
            assert!(m.contains("hostname"), "{m}");
            assert!(m.contains("Did you mean"), "{m}");
            assert!(m.contains("device.hostname"), "{m}");
        }
        other => panic!("{other:?}"),
    }
    // Same profile, explicit logs dataset.
    assert!(DetectionService::validate_rule_query_with_profile(&ocsf, "app=x", Some("logs")).is_err());
}

#[test]
fn save_accepts_valid_ocsf_and_legacy_udm_rules() {
    let ocsf = OcsfProfile::new();
    for q in [
        r#"class_uid=1007 device.hostname="ws-01" | stats count by device.hostname"#,
        r#"protocol="tcp" | stats count by dst_endpoint.port"#,
        r#"| inputlookup assets | where host="x""#,
        r#"* | eval host=device.hostname | stats count by host"#,
    ] {
        DetectionService::validate_rule_query_with_profile(&ocsf, q, None)
            .unwrap_or_else(|e| panic!("{q}: {e}"));
    }
    // UDM keeps its names.
    DetectionService::validate_rule_query_with_profile(
        &UdmProfile::new(),
        r#"hostname="ws-01" | stats count by src_ip"#,
        None,
    )
    .unwrap();
}

#[test]
fn save_uses_the_rule_dataset_profile_and_still_rejects_bad_syntax() {
    let ocsf = OcsfProfile::new();
    // A spans rule validates against the spans profile, not OCSF.
    DetectionService::validate_rule_query_with_profile(
        &ocsf,
        r#"service_name="api" | stats count by host"#,
        Some("spans"),
    )
    .unwrap();
    // An inline dataset selector is resolved by the search service; only parsed.
    DetectionService::validate_rule_query_with_profile(&ocsf, "dataset=risk | stats count by host", None)
        .unwrap();
    assert!(matches!(
        DetectionService::validate_rule_query_with_profile(&ocsf, "a=(", None),
        Err(DetectionError::QueryParseError(_))
    ));
}

/// Content sync must keep working: every rule in the `nano-rs/rules` content
/// repo passes the save-time check under its profile (`*-ocsf` folders under
/// OCSF, the rest under UDM). Set `NANO_RULES_DIR` to a checkout to run it.
#[test]
fn content_repo_rules_pass_save_time_validation() {
    let Ok(dir) = std::env::var("NANO_RULES_DIR") else {
        eprintln!("NANO_RULES_DIR not set; skipping");
        return;
    };
    let mut checked = 0;
    let mut failures = Vec::new();
    let mut stack = vec![std::path::PathBuf::from(dir)];
    while let Some(p) = stack.pop() {
        for entry in std::fs::read_dir(&p).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                if !path.ends_with(".git") {
                    stack.push(path);
                }
                continue;
            }
            if !matches!(path.extension().and_then(|e| e.to_str()), Some("yml" | "yaml")) {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            // Frontmatter between the first two `---` lines; the query follows.
            let Some((front, query)) = text
                .strip_prefix("---\n")
                .and_then(|rest| rest.split_once("\n---\n"))
            else {
                continue;
            };
            let query = query.trim();
            if query.is_empty() {
                continue;
            }
            let dataset = front
                .lines()
                .find_map(|l| l.strip_prefix("dataset:"))
                .map(|d| d.trim().trim_matches('"').to_string());
            let ocsf_folder = path.components().any(|c| c.as_os_str().to_string_lossy().ends_with("-ocsf"));
            let result = if ocsf_folder {
                DetectionService::validate_rule_query_with_profile(&OcsfProfile::new(), query, dataset.as_deref())
            } else {
                DetectionService::validate_rule_query_with_profile(&UdmProfile::new(), query, dataset.as_deref())
            };
            checked += 1;
            if let Err(e) = result {
                failures.push(format!("{}: {e}", path.display()));
            }
        }
    }
    eprintln!("checked {checked} content rules");
    assert!(checked > 0);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
