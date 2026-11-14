// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5348: nPL alias gaps on the OCSF store.
//!
//! - `protocol` aliases `connection_info.protocol_num` (Int32). The IANA
//!   protocol names in the manifest `enum_values` turn `protocol="tcp"` into
//!   `= 6` instead of a string compare against an int column, in the search
//!   expression, `| where` and `eval` comparisons alike.
//! - Bare legacy names with no single OCSF target (`host`, `hostname`, `src`,
//!   `dest`, `signature`, `app`, `dest_domain`) used to fall through to the
//!   `unmapped` spill (`app`: the whole OCSF `app` object) and silently return
//!   nothing. The validator now refuses them with "did you mean <OCSF path>"
//!   (the NAN-3893 direction). A field an earlier stage derives under that
//!   name still works, and so does any column after `| inputlookup`.
//! - `process` is NOT refused: it has one unambiguous meaning (the command
//!   line, UDM migration 086) and resolves to the class-split
//!   `command_line_unified` column.

use std::sync::Arc;

use crate::query::clickhouse_sql_gen::ClickHouseSqlGenerator;
use crate::query::{parse_query, validate_query_fields_with_profile, TimeRange};
use crate::schema::{FieldResolution, OcsfProfile, SchemaProfile, UdmProfile};

fn time_range() -> TimeRange {
    TimeRange {
        start: "2026-11-13T00:00:00Z".parse().unwrap(),
        end: "2026-11-13T01:00:00Z".parse().unwrap(),
    }
}

fn ocsf_sql(npl: &str) -> String {
    let query = parse_query(npl).unwrap_or_else(|e| panic!("{npl:?}: parse: {e}"));
    ClickHouseSqlGenerator::new()
        .with_profile(Arc::new(OcsfProfile::new()))
        .generate(&query, &time_range())
        .unwrap_or_else(|e| panic!("{npl:?}: generate: {e}"))
}

fn ocsf_sql_err(npl: &str) -> String {
    let query = parse_query(npl).unwrap_or_else(|e| panic!("{npl:?}: parse: {e}"));
    ClickHouseSqlGenerator::new()
        .with_profile(Arc::new(OcsfProfile::new()))
        .generate(&query, &time_range())
        .expect_err(npl)
        .to_string()
}

fn ocsf_errors(npl: &str) -> Vec<crate::query::validation::FieldValidationError> {
    let query = parse_query(npl).unwrap_or_else(|e| panic!("{npl:?}: parse: {e}"));
    validate_query_fields_with_profile(&query, Some(&OcsfProfile::new()))
}

const RETIRED: &[&str] = &[
    "host",
    "hostname",
    "src",
    "dest",
    "signature",
    "app",
    "dest_domain",
];

// --- protocol names ---------------------------------------------------------

#[test]
fn protocol_name_compares_the_iana_number() {
    let sql = ocsf_sql(r#"protocol="tcp""#);
    assert!(sql.contains("\"connection_info.protocol_num\" = 6"), "{sql}");
    assert!(!sql.contains("'tcp'"), "{sql}");

    // Case-insensitive, and the native column spelling takes names too.
    let sql = ocsf_sql(r#"connection_info.protocol_num="UDP""#);
    assert!(sql.contains("\"connection_info.protocol_num\" = 17"), "{sql}");

    // A number still passes through.
    let sql = ocsf_sql("protocol=6");
    assert!(sql.contains("\"connection_info.protocol_num\" = 6"), "{sql}");
}

#[test]
fn protocol_name_list_and_negation() {
    let sql = ocsf_sql(r#"protocol IN ("tcp", "udp", "icmp")"#);
    assert!(sql.contains("\"connection_info.protocol_num\" IN (6, 17, 1)"), "{sql}");
    let sql = ocsf_sql(r#"protocol!="udp""#);
    assert!(sql.contains("\"connection_info.protocol_num\" != 17"), "{sql}");
}

#[test]
fn unknown_protocol_name_is_a_loud_error() {
    let err = ocsf_sql_err(r#"protocol="tcpx""#);
    assert!(err.contains("is not a valid value for 'protocol'"), "{err}");
    assert!(err.contains("tcp"), "{err}");
}

#[test]
fn protocol_is_a_known_field_on_both_profiles() {
    assert!(ocsf_errors(r#"protocol="tcp" | stats count by protocol"#).is_empty());
    let udm = parse_query(r#"protocol="tcp""#).unwrap();
    assert!(validate_query_fields_with_profile(&udm, Some(&UdmProfile::new())).is_empty());
}

// --- retired bare names -----------------------------------------------------

#[test]
fn retired_names_are_refused_with_ocsf_suggestions() {
    let profile = OcsfProfile::new();
    for name in RETIRED {
        for npl in [
            format!(r#"{name}="x""#),
            format!("* | stats count by {name}"),
            format!("* | table timestamp, {name}"),
            format!(r#"* | where {name}="x""#),
        ] {
            let errors = ocsf_errors(&npl);
            assert_eq!(errors.len(), 1, "{npl}: {errors:?}");
            let err = &errors[0];
            assert_eq!(err.field_name, *name, "{npl}");
            let expected = profile.retired_field_suggestions(name).unwrap();
            assert_eq!(err.suggestions, expected, "{npl}");
            // Every suggestion is a real OCSF field.
            for s in &err.suggestions {
                assert!(profile.is_known_field(s), "{name}: suggestion {s} is not an OCSF field");
            }
            assert!(err.to_string().contains("Did you mean"), "{err}");
            assert!(err.to_string().contains(&format!("unmapped.{name}")), "{err}");
        }
        assert!(!profile.is_queryable_field(name), "{name} must be flagged in the editor");
    }
}

#[test]
fn retired_names_never_resolve_to_a_promoted_column() {
    // The refusal is only right while nothing real sits under the bare name:
    // if one is ever promoted or aliased, this fails and the entry must go.
    let profile = OcsfProfile::new();
    for name in RETIRED {
        assert!(
            !matches!(profile.resolve(name), FieldResolution::ExplicitColumn(_)),
            "{name} now resolves to a column; drop it from OCSF_RETIRED_FIELDS"
        );
        assert!(profile.udm_column_sql(name).is_none(), "{name} has a UDM-alias column");
    }
}

#[test]
fn derived_fields_under_a_retired_name_still_work() {
    assert!(ocsf_errors(r#"* | eval host=device.hostname | stats count by host"#).is_empty());
    assert!(ocsf_errors("* | rename src_endpoint.ip as src | table src").is_empty());
    assert!(ocsf_errors("* | stats count as app by metadata.product.name | where app > 1").is_empty());
}

#[test]
fn ocsf_paths_and_spill_spelling_are_unaffected() {
    for npl in [
        r#"device.hostname="ws-01" | stats count by src_endpoint.hostname"#,
        r#"process.cmd_line CONTAINS "-enc" | table process.name, actor.process.cmd_line"#,
        r#"unmapped.host="x" | stats count by unmapped.app"#,
        r#"query.hostname="evil.com" OR http_request.url.hostname="evil.com""#,
        r#"finding_info.title="x" | stats count by metadata.product.name"#,
    ] {
        assert!(ocsf_errors(npl).is_empty(), "{npl}: {:?}", ocsf_errors(npl));
    }
}

#[test]
fn udm_profile_keeps_the_legacy_names() {
    let udm = UdmProfile::new();
    for name in RETIRED {
        assert!(udm.retired_field_suggestions(name).is_none());
        let q = parse_query(&format!(r#"{name}="x""#)).unwrap();
        let errors = validate_query_fields_with_profile(&q, Some(&udm));
        assert!(
            errors.iter().all(|e| !e.message.contains("is not an OCSF field")),
            "{name}: {errors:?}"
        );
    }
}


#[test]
fn process_stays_the_cross_class_command_line_alias() {
    assert!(ocsf_errors(r#"process CONTAINS "-enc" | stats count by process"#).is_empty());
    let sql = ocsf_sql(r#"process="x""#);
    assert!(sql.contains("lower(command_line_unified) = 'x'"), "{sql}");
    assert!(!sql.contains("unmapped"), "{sql}");
}

// --- review follow-ups -------------------------------------------------------

#[test]
fn protocol_name_in_where_and_eval() {
    let sql = ocsf_sql(r#"* | where protocol="tcp""#);
    assert!(sql.contains(r#""connection_info.protocol_num" = 6"#), "where: {sql}");
    assert!(!sql.contains("'tcp'"), "where: {sql}");
    let sql = ocsf_sql(r#"* | eval is_udp=if(protocol="udp", 1, 0) | stats sum(is_udp)"#);
    assert!(!sql.contains("'udp'"), "eval: {sql}");
    assert!(sql.contains(r#"("connection_info.protocol_num" = 17)"#), "eval: {sql}");
    let sql = ocsf_sql(r#"* | where status_id!="failure""#);
    assert!(sql.contains(r#""status_id" != 2"#) || sql.contains("status_id != 2"), "where enum: {sql}");
}

#[test]
fn inputlookup_columns_are_not_refused() {
    for npl in [
        r#"| inputlookup assets | where host="x""#,
        "| inputlookup assets | stats count by app",
        "| inputlookup assets | table hostname, src, dest_domain, signature",
    ] {
        assert!(ocsf_errors(npl).is_empty(), "{npl}: {:?}", ocsf_errors(npl));
    }
    // A log search outside the lookup pipeline is still refused.
    assert_eq!(ocsf_errors(r#"host="x" | stats count by device.hostname"#).len(), 1);
}

#[test]
fn ocsf_sequence_step_columns_validate() {
    // Content rules (`nano-rs/rules` *-ocsf) read the underscore spelling the
    // codegen emits for a dotted capture field.
    let npl = r#"class_uid=1007 | sequence by device.hostname maxspan=10m fields(process.name, process.cmd_line) [process.name="whoami.exe"] [process.name="net.exe"] | table device.hostname, step1_process_name, step2_process_cmd_line, sequence_duration_seconds"#;
    assert!(ocsf_errors(npl).is_empty(), "{:?}", ocsf_errors(npl));
    ocsf_sql(npl);
}
