// SPDX-License-Identifier: AGPL-3.0-or-later

//! OCSF `resources.*` are Array(String): equality must be the index-matching
//! `has(arrayMap(x -> lower(x), col), lower(?))` form and substring matching
//! element-wise; UDM string columns keep their historical SQL.

use super::cloud_overview::{resource_contains_lower, resource_eq_ci, scalar_resource_column};

#[test]
fn ocsf_array_columns_use_index_matching_forms() {
    assert_eq!(
        resource_eq_ci("`resources.uid`"),
        "has(arrayMap(x -> lower(x), `resources.uid`), lower(?))"
    );
    assert_eq!(
        resource_contains_lower("`resources.name`"),
        "arrayExists(x -> x != '' AND position(lower(x), ?) > 0, `resources.name`)"
    );
    assert_eq!(
        scalar_resource_column("`resources.type`".into()),
        "arrayStringConcat(arrayFlatten(array(`resources.type`)), ',')"
    );
}

#[test]
fn udm_string_columns_are_unchanged() {
    assert_eq!(resource_eq_ci("resource_id"), "lower(resource_id) = lower(?)");
    assert_eq!(
        resource_contains_lower("resource_name"),
        "(resource_name != '' AND position(lower(resource_name), ?) > 0)"
    );
}

/// NAN-4928 review P2: OCSF resource aggregates ARRAY JOIN the zipped
/// (uid, name, type) tuple, so each element keeps its own name and type;
/// UDM needs no join.
#[test]
fn resource_rows_zip_ocsf_arrays_and_leave_udm_scalar() {
    use super::cloud_overview::resource_rows;
    let ocsf = crate::schema::OcsfProfile::new();
    let rows = resource_rows(&ocsf);
    assert!(rows.array_join.contains("ARRAY JOIN arrayZip("), "{}", rows.array_join);
    assert!(rows.array_join.contains("resources.uid") && rows.array_join.contains("resources.type"));
    assert_eq!((rows.id.as_str(), rows.name.as_str(), rows.ty.as_str()), ("__resource.1", "__resource.2", "__resource.3"));
    let udm = crate::schema::UdmProfile::new();
    let rows = resource_rows(&udm);
    assert!(rows.array_join.is_empty());
    assert_eq!(rows.id, "resource_id");
}
