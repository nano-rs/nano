// SPDX-License-Identifier: AGPL-3.0-or-later

//! Correlated producer-only Asset evidence in the signed entity-range partial.
//! Keep the full identity tuple: an event matching two identities counts once.

pub const PATH: &str = "nano.asset_facets.v1";
pub const FIELDS: [&str; 12] = [
    "device.hostname",
    "src_endpoint.hostname",
    "dst_endpoint.hostname",
    "src_endpoint.ip",
    "dst_endpoint.ip",
    "src_endpoint.mac",
    "dst_endpoint.mac",
    "user.name",
    "actor.user.name",
    "metadata.log_source",
    "class_uid",
    "status",
];
pub const OUTPUT_FIELDS: [&str; 4] = [
    "metadata.log_source",
    "class_uid",
    "asset_auth_failure",
    "asset_user",
];
pub const SUFFIX: &str = " | eval asset_user=coalesce(actor.user.name,user.name), asset_auth_failure=if(class_uid=3002 AND lower(status)=\"failure\", 1, 0) | stats count() as event_count by metadata.log_source, class_uid, asset_auth_failure, asset_user";

pub fn enabled() -> bool {
    std::env::var("NANO_LAKE_ASSET_FACET_SUMMARIES").as_deref() == Ok("1")
}

pub fn reads_enabled() -> bool {
    std::env::var("NANO_LAKE_ASSET_FACET_READS").as_deref() == Ok("1")
}
