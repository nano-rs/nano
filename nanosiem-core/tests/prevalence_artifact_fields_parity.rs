// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5280: the server's query-artifact paths and the search Rarity view's
//! client-side extractor must list the same fields.
//!
//! `nanosiem_core::prevalence::artifact_fields` is the server copy;
//! `nanosiem-web/src/lib/prevalence/artifactFields.ts` is the client copy.
//! Before NAN-5280 the client learned the OCSF paths (NAN-5270) and the server
//! did not, so the UI showed Sysmon hashes and DNS names that
//! `POST /api/prevalence/query-artifacts` returned as empty lists. This test
//! parses the six `as const` arrays out of the TS file and compares them, in
//! order, to the Rust consts. `nanosiem-web/` ships in both the enterprise and
//! the open-core tree, so the `include_str!` path is never stripped.

use nanosiem_core::prevalence::artifact_fields as af;

const ARTIFACT_FIELDS_TS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../nanosiem-web/src/lib/prevalence/artifactFields.ts"
));

/// The string literals of `export const <name> = [ ... ] as const;`.
fn ts_list(name: &str) -> Vec<String> {
    let start = ARTIFACT_FIELDS_TS
        .find(&format!("export const {name} = ["))
        .unwrap_or_else(|| panic!("artifactFields.ts no longer exports {name}"));
    let body = &ARTIFACT_FIELDS_TS[start..];
    let open = body.find('[').expect("list open");
    let close = body.find("] as const").unwrap_or_else(|| panic!("{name}: no `] as const`"));
    body[open + 1..close]
        .split(',')
        .map(|s| s.trim().trim_matches('\'').trim_matches('"').to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

#[test]
fn rust_and_ts_artifact_paths_match() {
    let pairs: [(&str, &[&str]); 6] = [
        ("UDM_HASH_FIELDS", af::UDM_HASH_FIELDS),
        ("OCSF_HASH_FIELDS", af::OCSF_HASH_FIELDS),
        ("UDM_DOMAIN_FIELDS", af::UDM_DOMAIN_FIELDS),
        ("OCSF_DOMAIN_FIELDS", af::OCSF_DOMAIN_FIELDS),
        ("UDM_URL_FIELDS", af::UDM_URL_FIELDS),
        ("OCSF_URL_FIELDS", af::OCSF_URL_FIELDS),
    ];
    for (name, rust) in pairs {
        assert_eq!(
            ts_list(name),
            rust.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            "{name} drifted between artifactFields.ts and prevalence/artifact_fields.rs — edit both"
        );
    }
}

#[test]
fn ts_parser_sees_real_entries() {
    // Guard the parser itself: an empty parse would make the parity check vacuous.
    assert!(ts_list("OCSF_HASH_FIELDS").contains(&"process.file.hashes.sha256".to_string()));
    assert!(ts_list("OCSF_DOMAIN_FIELDS").contains(&"query.hostname".to_string()));
}
