// SPDX-License-Identifier: AGPL-3.0-or-later
//! Scalar compatibility selectors over already-authorized stored records.
//! Provider, subject, status and payload always use the same array index.
use super::types::FieldType;

pub(super) const FIELDS: &[&str] = &[
    "ioc_hash_confidence",
    "ioc_hash_malware",
    "ioc_domain_confidence",
    "ioc_domain_malware",
    "ioc_dest_ip_confidence",
    "ioc_dest_ip_malware",
    "ioc_src_ip_confidence",
    "ioc_src_ip_malware",
    "enriched_src_country",
    "enriched_dest_country",
    "src_is_tor",
    "dest_is_tor",
    "enriched_src_is_tor",
    "enriched_dest_is_tor",
    "ioc_src_ip_threat_type",
    "ioc_dest_ip_threat_type",
    "ioc_domain_threat_type",
    "ioc_hash_threat_type",
    "synthient_src_vpn",
    "synthient_dest_vpn",
    "synthient_src_proxy",
    "synthient_dest_proxy",
    "synthient_src_residential_proxy",
    "synthient_dest_residential_proxy",
    "synthient_src_bot",
    "synthient_dest_bot",
];

pub(super) struct Selector {
    pub provider: &'static str,
    pub subject: &'static str,
    pub payload: &'static str,
    pub field_type: FieldType,
}

pub(super) fn selector(field: &str) -> Option<Selector> {
    let (provider, subject, payload, field_type) = match field {
        "enriched_src_country" => (
            "platform/ipinfo_lite",
            "src_endpoint.ip",
            "enrichments.data.country_name",
            FieldType::String,
        ),
        "enriched_dest_country" => (
            "platform/ipinfo_lite",
            "dst_endpoint.ip",
            "enrichments.data.country_name",
            FieldType::String,
        ),
        "src_is_tor" | "enriched_src_is_tor" => (
            "platform/tor_exit_nodes",
            "src_endpoint.ip",
            "enrichments.data.is_tor",
            FieldType::Boolean,
        ),
        "dest_is_tor" | "enriched_dest_is_tor" => (
            "platform/tor_exit_nodes",
            "dst_endpoint.ip",
            "enrichments.data.is_tor",
            FieldType::Boolean,
        ),
        "ioc_src_ip_threat_type" => (
            "platform/threatfox",
            "src_endpoint.ip",
            "enrichments.data.threat_type",
            FieldType::String,
        ),
        "ioc_dest_ip_threat_type" => (
            "platform/threatfox",
            "dst_endpoint.ip",
            "enrichments.data.threat_type",
            FieldType::String,
        ),
        "ioc_domain_threat_type" => (
            "platform/threatfox",
            "query.hostname",
            "enrichments.data.threat_type",
            FieldType::String,
        ),
        "ioc_hash_threat_type" => (
            "platform/threatfox",
            "file.hashes",
            "enrichments.data.threat_type",
            FieldType::String,
        ),
        "synthient_src_vpn" => (
            "platform/synthient",
            "src_endpoint.ip",
            "enrichments.data.vpn",
            FieldType::Boolean,
        ),
        "synthient_dest_vpn" => (
            "platform/synthient",
            "dst_endpoint.ip",
            "enrichments.data.vpn",
            FieldType::Boolean,
        ),
        "synthient_src_proxy" => (
            "platform/synthient",
            "src_endpoint.ip",
            "enrichments.data.proxy",
            FieldType::Boolean,
        ),
        "synthient_dest_proxy" => (
            "platform/synthient",
            "dst_endpoint.ip",
            "enrichments.data.proxy",
            FieldType::Boolean,
        ),
        "synthient_src_residential_proxy" => (
            "platform/synthient",
            "src_endpoint.ip",
            "enrichments.data.residential_proxy",
            FieldType::Boolean,
        ),
        "synthient_dest_residential_proxy" => (
            "platform/synthient",
            "dst_endpoint.ip",
            "enrichments.data.residential_proxy",
            FieldType::Boolean,
        ),
        "synthient_src_bot" => (
            "platform/synthient",
            "src_endpoint.ip",
            "enrichments.data.bot",
            FieldType::Boolean,
        ),
        "synthient_dest_bot" => (
            "platform/synthient",
            "dst_endpoint.ip",
            "enrichments.data.bot",
            FieldType::Boolean,
        ),
        "ioc_src_ip_malware" => (
            "platform/threatfox",
            "src_endpoint.ip",
            "enrichments.data.malware",
            FieldType::String,
        ),
        "ioc_src_ip_confidence" => (
            "platform/threatfox",
            "src_endpoint.ip",
            "enrichments.data.confidence_level",
            FieldType::Integer,
        ),
        "ioc_dest_ip_malware" => (
            "platform/threatfox",
            "dst_endpoint.ip",
            "enrichments.data.malware",
            FieldType::String,
        ),
        "ioc_dest_ip_confidence" => (
            "platform/threatfox",
            "dst_endpoint.ip",
            "enrichments.data.confidence_level",
            FieldType::Integer,
        ),
        "ioc_domain_malware" => (
            "platform/threatfox",
            "query.hostname",
            "enrichments.data.malware",
            FieldType::String,
        ),
        "ioc_domain_confidence" => (
            "platform/threatfox",
            "query.hostname",
            "enrichments.data.confidence_level",
            FieldType::Integer,
        ),
        "ioc_hash_malware" => (
            "platform/threatfox",
            "file.hashes",
            "enrichments.data.malware",
            FieldType::String,
        ),
        "ioc_hash_confidence" => (
            "platform/threatfox",
            "file.hashes",
            "enrichments.data.confidence_level",
            FieldType::Integer,
        ),
        _ => return None,
    };
    Some(Selector {
        provider,
        subject,
        payload,
        field_type,
    })
}

impl Selector {
    pub fn expression(&self, available: impl Fn(&str) -> bool) -> (String, Vec<&'static str>) {
        let mut inputs = vec![
            "enrichments.name",
            "enrichments.provider",
            "enrichments.data.status",
            self.payload,
        ];
        let ty = match self.field_type {
            FieldType::Boolean => "Bool",
            FieldType::Integer => "Int64",
            _ => "String",
        };
        let country = self.payload == "enrichments.data.country_name";
        if country {
            inputs.push("enrichments.data.owned_fields");
        }
        if !inputs.iter().all(|name| available(name)) {
            return (format!("CAST(NULL AS Nullable({ty}))"), vec![]);
        }
        let ownership = if country {
            format!(
                " AND has(o, '{}.location.country')",
                self.subject.trim_end_matches(".ip")
            )
        } else {
            String::new()
        };
        let arguments = if country { ", o" } else { "" };
        let arrays = if country {
            ", \"enrichments.data.owned_fields\""
        } else {
            ""
        };
        let index = format!(
            "arrayFirstIndex((n, p, s{arguments}) -> n = '{}' AND p = '{}' AND s IN ('match', 'no_match'){ownership}, \"enrichments.name\", \"enrichments.provider\", \"enrichments.data.status\"{arrays})",
            self.subject, self.provider
        );
        let value = format!("arrayElementOrNull(\"{}\", {index})", self.payload);
        let sql = if self.field_type == FieldType::Boolean {
            // Null and invalid text remain unknown; never turn absence into false.
            format!("multiIf(toString({value}) IN ('true', '1'), CAST(1 AS Nullable(Bool)), toString({value}) IN ('false', '0'), CAST(0 AS Nullable(Bool)), CAST(NULL AS Nullable(Bool)))")
        } else if self.field_type == FieldType::Integer {
            format!("toInt64OrNull(toString({value}))")
        } else {
            format!("CAST({value} AS Nullable(String))")
        };
        (sql, inputs)
    }
}
