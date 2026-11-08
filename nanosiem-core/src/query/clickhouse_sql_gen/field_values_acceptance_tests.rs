// SPDX-License-Identifier: AGPL-3.0-or-later

use std::sync::Arc;

use super::ClickHouseSqlGenerator;
use crate::schema::OcsfProfile;

#[test]
fn ocsf_field_values_resolve_native_taxonomy_and_unmapped_fields() {
    let generator = ClickHouseSqlGenerator::new().with_profile(Arc::new(OcsfProfile::new()));

    assert_eq!(
        generator.field_values_display_expr("class_uid"),
        "class_uid"
    );
    let dynamic = generator.field_values_display_expr("unmapped.objects");
    assert!(
        dynamic.contains("unmapped.\"objects\"") && dynamic.starts_with("multiIf("),
        "unmapped.objects did not resolve through the OCSF Dynamic column: {dynamic}"
    );
}
