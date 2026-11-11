// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5271: the cloud pivot / timeline enrichment tail. Under OCSF it reads the
//! source endpoint's geo / ASN and the `enrichments.ioc_src_ip_*` columns and
//! aliases them to the result keys the sheets read; UDM is byte-identical.

use super::SearchService;

#[test]
fn ocsf_tail_reads_ocsf_columns_under_the_sheet_keys() {
    let ocsf = crate::schema::OcsfProfile::new();
    let tail = SearchService::cloud_enrichment_tail(&ocsf);
    for (col, key) in [
        ("`src_endpoint.location.country`", "enriched_src_country_code"),
        ("`src_endpoint.autonomous_system.name`", "enriched_src_as_name"),
        ("`enrichments.ioc_src_ip_threat_type`", "ioc_src_ip_threat_type"),
        ("`enrichments.ioc_src_ip_malware`", "ioc_src_ip_malware"),
        ("`enrichments.ioc_src_ip_confidence`", "ioc_src_ip_confidence"),
    ] {
        assert!(tail.contains(&format!("{col} AS {key}")), "{col} -> {key} missing: {tail}");
    }
    // The ASN is Int64 on OCSF; the sheet treats it as a string and 0 as unset.
    assert!(tail.contains(
        "if(`src_endpoint.autonomous_system.number` = 0, '', toString(`src_endpoint.autonomous_system.number`)) AS enriched_src_asn"
    ));
    // No UDM physical column is referenced on OCSF (they do not exist there).
    for line in tail.lines().filter(|l| !l.trim().is_empty() && l.trim() != ",") {
        let src = line.split(" AS ").next().unwrap_or("");
        assert!(!src.contains("enriched_") && !src.trim_start().starts_with("ioc_"), "UDM column on OCSF: {line}");
    }
}

#[test]
fn udm_tail_is_unchanged() {
    let udm = crate::schema::UdmProfile::new();
    assert_eq!(
        SearchService::cloud_enrichment_tail(&udm),
        ",\n                   enriched_src_country_code, enriched_src_asn, enriched_src_as_name,\n                   ioc_src_ip_threat_type, ioc_src_ip_malware, ioc_src_ip_confidence"
    );
}
