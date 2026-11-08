// SPDX-License-Identifier: AGPL-3.0-or-later

use super::canonical_dynamic_field_name;

#[test]
fn ocsf_catalog_names_the_searchable_unmapped_path() {
    assert_eq!(
        canonical_dynamic_field_name("unmapped", true, "objects"),
        "unmapped.objects"
    );
    assert_eq!(
        canonical_dynamic_field_name("unmapped", true, "nested.child"),
        "unmapped.nested.child"
    );
}

#[test]
fn udm_catalog_keeps_legacy_bare_extension_names() {
    assert_eq!(
        canonical_dynamic_field_name("ext", false, "objects"),
        "objects"
    );
}
