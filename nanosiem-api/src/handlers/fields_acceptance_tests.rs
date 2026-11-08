// SPDX-License-Identifier: AGPL-3.0-or-later

#[test]
fn field_values_endpoint_accepts_the_catalog_and_search_field_spelling() {
    let source = include_str!("fields.rs");
    let start = source
        .find("pub async fn get_field_values(")
        .expect("field-values handler");
    let end = source[start..]
        .find("\n/// Build the source-inventory SQL")
        .map(|offset| start + offset)
        .expect("end of field-values handler");
    let handler = &source[start..end];

    assert!(
        handler.contains(".get_named_field_values(&field_name"),
        "field-values must use the profile-aware named-field path"
    );
    assert!(
        !handler.contains("field_name.parse()") && !handler.contains("let field: UdmField"),
        "class_uid and unmapped.* must not be rejected by the UDM-only enum parser"
    );
}
