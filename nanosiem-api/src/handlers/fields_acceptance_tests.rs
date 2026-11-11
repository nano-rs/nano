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

/// NAN-5265: `bucket` is optional (old clients — the desktop app, the editor
/// highlighter — keep getting the bare spill keys) and selects the OCSF
/// Extended inventory when set.
#[test]
fn ext_fields_bucket_defaults_to_the_spill() {
    use super::ExtFieldsQuery;
    use nanosiem_core::search::service::DynamicFieldBucket;

    let legacy: ExtFieldsQuery = serde_json::from_str(r#"{"query":"*"}"#).unwrap();
    assert_eq!(legacy.bucket.unwrap_or_default(), DynamicFieldBucket::Spill);

    let extended: ExtFieldsQuery = serde_json::from_str(r#"{"bucket":"extended"}"#).unwrap();
    assert_eq!(extended.bucket, Some(DynamicFieldBucket::Extended));

    assert!(serde_json::from_str::<ExtFieldsQuery>(r#"{"bucket":"unmapped.unmapped"}"#).is_err());

    let source = include_str!("fields.rs");
    assert!(
        source.contains("params.bucket.unwrap_or_default()"),
        "both ext-fields routes must pass the requested bucket to the service"
    );
}
