// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5301: the asset dossier's DNS card applied `lower()` to OCSF
//! `answers.rdata` (`Array(String)`), a ClickHouse Code 43 that failed the
//! whole dossier with a 400 for every host, user and IP. The NX predicate must
//! be element-wise on array columns and keep the scalar form on UDM.

use super::asset_dossier::dns_nx_expr;
use crate::schema::{OcsfProfile, SchemaProfile, UdmProfile};

#[test]
fn ocsf_nx_predicate_is_array_membership_not_scalar_lower() {
    let ocsf = OcsfProfile::new();
    assert!(
        ocsf.is_array_field("answer"),
        "OCSF `answer` resolves to answers.rdata, an Array(String)"
    );
    let expr = dns_nx_expr(&ocsf);
    assert_eq!(
        expr,
        r#"(empty("answers.rdata") OR has(arrayMap(x -> lower(x), "answers.rdata"), 'nxdomain'))"#
    );
    assert!(
        !expr.contains(r#"lower("answers.rdata")"#),
        "scalar lower() on an Array column is CH Code 43: {expr}"
    );
    assert!(!expr.contains(r#""answers.rdata" = ''"#), "{expr}");
}

#[test]
fn udm_nx_predicate_keeps_scalar_form() {
    let udm = UdmProfile::new();
    assert_eq!(
        dns_nx_expr(&udm),
        "(answer = '' OR lower(answer) = 'nxdomain')"
    );
}

/// Every other UDM concept the dossier aggregates with scalar String/number
/// operators must stay scalar on OCSF. If one of these ever resolves to an
/// Array column, that card would fail the whole dossier the same way
/// `answer` did; make it array-aware like [`dns_nx_expr`] first.
#[test]
fn other_dossier_concepts_are_scalar_on_ocsf() {
    let ocsf = OcsfProfile::new();
    for concept in [
        "action",
        "auth_result",
        "auth_type",
        "bytes_in",
        "bytes_out",
        "command_line",
        "dest_host",
        "dest_ip",
        "file_action",
        "file_name",
        "file_path",
        "file_size",
        "parent_process_name",
        "process_hash",
        "process_name",
        "query",
        "result",
        "src_host",
        "src_ip",
        "user",
    ] {
        if ocsf.udm_column_sql(concept).is_some() {
            assert!(
                !ocsf.is_array_field(concept),
                "dossier concept `{concept}` is an Array column on OCSF"
            );
        }
    }
}
