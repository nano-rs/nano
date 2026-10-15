// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3451: the ingest-time prevalence stamp an open-core lake row carries in
//! `enrichments[]`, read from a result row in Rust.
//!
//! This is the row-side twin of the SQL derivation in
//! `schema/lake_prevalence.rs`: same artifacts, same normalization, same
//! sentinels. Surfaces that only hold rows (the tree view) use it when a row
//! has no flat `prevalence_*` keys, which is every open-core lake row.
//!
//! Rows arrive in three shapes and all are read: `enrichments` as an array of
//! objects, the same array serialized as a JSON string, or the flattened
//! parallel arrays `enrichments.name` / `enrichments.value` / ….

use serde_json::Value;

/// Field N/A: no artifact, or no nano stamp for it.
pub const PREVALENCE_NA: u16 = 65_535;
/// The artifact's host set saturated: common.
pub const PREVALENCE_COMMON: u16 = 9_999;

/// One `name = 'prevalence'`, `provider = 'nano'` stamp.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Stamp {
    value: String,
    host_count: Option<u64>,
    saturated: bool,
}

impl Stamp {
    fn scalar(&self) -> u16 {
        if self.saturated {
            return PREVALENCE_COMMON;
        }
        match self.host_count {
            Some(hosts) => hosts.clamp(1, 9_998) as u16,
            None => PREVALENCE_NA,
        }
    }
}

/// The five scalars of one row, valued exactly as lean stamps them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RowPrevalence {
    pub file_hash: u16,
    pub process_hash: u16,
    pub dest_domain: u16,
    pub dest_ip: u16,
    pub min: u16,
}

/// Read `path` from a row that is either flat (`"a.b": …`) or nested
/// (`{"a": {"b": …}}`), flattening arrays of objects along the way.
fn values_at<'a>(row: &'a Value, path: &str) -> Vec<&'a Value> {
    if let Some(value) = row.get(path) {
        return match value {
            Value::Array(items) => items.iter().collect(),
            other => vec![other],
        };
    }
    let mut current = vec![row];
    for part in path.split('.') {
        current = current
            .into_iter()
            .flat_map(|value| match value {
                Value::Array(items) => items.iter().filter_map(|item| item.get(part)).collect(),
                other => other.get(part).into_iter().collect::<Vec<_>>(),
            })
            .collect();
    }
    current
        .into_iter()
        .flat_map(|value| match value {
            Value::Array(items) => items.iter().collect(),
            other => vec![other],
        })
        .collect()
}

fn text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(flag) => Some(flag.to_string()),
        _ => None,
    }
}

fn normalize(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn first_text(row: &Value, path: &str) -> Option<String> {
    values_at(row, path).into_iter().find_map(text)
}

fn stamp_from_object(entry: &Value) -> Option<Stamp> {
    let name = entry.get("name").and_then(Value::as_str)?;
    let provider = entry.get("provider").and_then(Value::as_str)?;
    if name != "prevalence" || provider != "nano" {
        return None;
    }
    let data = entry.get("data");
    let field = |key: &str| data.and_then(|data| data.get(key)).and_then(text);
    Some(Stamp {
        value: entry.get("value").and_then(text)?,
        host_count: field("host_count").and_then(|count| count.parse().ok()),
        saturated: field("host_count_saturated").is_some_and(|flag| flag == "true" || flag == "1"),
    })
}

fn stamps(row: &Value) -> Vec<Stamp> {
    let nested = match row.get("enrichments") {
        Some(Value::Array(entries)) => Some(entries.clone()),
        Some(Value::String(json)) => serde_json::from_str::<Vec<Value>>(json).ok(),
        _ => None,
    };
    if let Some(entries) = nested {
        return entries.iter().filter_map(stamp_from_object).collect();
    }
    // Flattened parallel arrays, aligned by index (the SQL derivation's shape).
    let column = |key: &str| match row.get(key) {
        Some(Value::Array(items)) => items.clone(),
        _ => Vec::new(),
    };
    let names = column("enrichments.name");
    let providers = column("enrichments.provider");
    let values = column("enrichments.value");
    let counts = column("enrichments.data.host_count");
    let saturated = column("enrichments.data.host_count_saturated");
    (0..names.len())
        .filter_map(|index| {
            let entry = serde_json::json!({
                "name": names.get(index),
                "provider": providers.get(index),
                "value": values.get(index),
                "data": {
                    "host_count": counts.get(index),
                    "host_count_saturated": saturated.get(index),
                },
            });
            stamp_from_object(&entry)
        })
        .collect()
}

fn lookup(stamps: &[Stamp], artifact: Option<String>) -> u16 {
    let Some(artifact) = artifact.filter(|artifact| !artifact.is_empty()) else {
        return PREVALENCE_NA;
    };
    stamps
        .iter()
        .find(|stamp| stamp.value == artifact)
        .map_or(PREVALENCE_NA, Stamp::scalar)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn sha256_artifact(row: &Value, path: &str) -> Option<String> {
    values_at(row, path)
        .into_iter()
        .filter_map(text)
        .map(|value| normalize(&value))
        .find(|value| is_sha256(value))
}

fn is_ipv4_literal(value: &str) -> bool {
    let parts = value.split('.').collect::<Vec<_>>();
    parts.len() == 4
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn domain_artifact(row: &Value) -> Option<String> {
    let host = ["dst_endpoint.hostname", "query.hostname"]
        .into_iter()
        .filter_map(|path| first_text(row, path))
        .map(|value| normalize(&value))
        .find(|value| !value.is_empty())?;
    (!is_ipv4_literal(&host)).then_some(host)
}

impl RowPrevalence {
    /// The row's scalars from its nano prevalence stamps, or `None` when the
    /// row carries no stamp at all (UDM / ClickHouse rows, unstamped lake
    /// rows), so a caller never reports a made-up value.
    pub fn from_stamped_row(row: &Value) -> Option<Self> {
        let stamps = stamps(row);
        if stamps.is_empty() {
            return None;
        }
        let file_hash = lookup(&stamps, sha256_artifact(row, "file.hashes.value"));
        let process_hash = lookup(&stamps, sha256_artifact(row, "process.file.hashes.value"));
        let dest_domain = lookup(&stamps, domain_artifact(row));
        let dest_ip = lookup(
            &stamps,
            first_text(row, "dst_endpoint.ip").map(|ip| normalize(&ip)),
        );
        let min = [file_hash, process_hash, dest_domain, dest_ip]
            .into_iter()
            .map(|value| {
                if value == PREVALENCE_NA {
                    PREVALENCE_COMMON
                } else {
                    value
                }
            })
            .min()
            .unwrap_or(PREVALENCE_COMMON);
        Some(Self {
            file_hash,
            process_hash,
            dest_domain,
            dest_ip,
            min,
        })
    }

    /// The rarest stamped value among the values the row holds at `path`
    /// (a tree's `prevalence=` field), or `None` when none is stamped.
    pub fn for_field(row: &Value, path: &str) -> Option<u16> {
        let stamps = stamps(row);
        values_at(row, path)
            .into_iter()
            .filter_map(text)
            .map(|value| lookup(&stamps, Some(normalize(&value))))
            .filter(|value| *value != PREVALENCE_NA)
            .min()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const H1: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const H2: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn stamp(value: &str, hosts: Option<u64>, saturated: bool) -> Value {
        json!({"name": "prevalence", "provider": "nano", "value": value, "type": "reputation",
               "data": {"host_count": hosts, "host_count_saturated": saturated}})
    }

    #[test]
    fn nested_row_matches_lean_semantics() {
        let row = json!({
            "file": {"hashes": [{"algorithm_id": 1, "value": "d41d8cd98f00b204e9800998ecf8427e"},
                                {"algorithm_id": 3, "value": format!(" {} ", H1.to_uppercase())}]},
            "dst_endpoint": {"ip": "8.8.8.8", "hostname": "10.1.2.3"},
            "query": {"hostname": "evil.example"},
            "enrichments": [
                {"name": "threatfox", "provider": "platform/threatfox", "value": H1, "data": {}},
                stamp(H1, Some(5), false),
                stamp("8.8.8.8", Some(700), true),
                stamp("evil.example", Some(1), false),
            ],
        });
        let scalars = RowPrevalence::from_stamped_row(&row).unwrap();
        assert_eq!(scalars.file_hash, 5);
        assert_eq!(scalars.process_hash, PREVALENCE_NA);
        // An IPv4 literal in dst_endpoint.hostname is no domain, and lean does
        // not fall back to query.hostname past it.
        assert_eq!(scalars.dest_domain, PREVALENCE_NA);
        assert_eq!(scalars.dest_ip, PREVALENCE_COMMON);
        assert_eq!(scalars.min, 5);
    }

    #[test]
    fn new_artifacts_are_rare_and_unstamped_artifacts_are_na() {
        let new = json!({"file": {"hashes": [{"value": H2}]},
                         "enrichments": [{"name": "prevalence", "provider": "nano", "value": H2,
                                          "data": {"host_count": 1, "host_count_saturated": false, "is_new": true}}]});
        assert_eq!(RowPrevalence::from_stamped_row(&new).unwrap().min, 1);
        let other_artifact = json!({"file": {"hashes": [{"value": H1}]},
                                    "enrichments": [stamp(H2, Some(1), false)]});
        let scalars = RowPrevalence::from_stamped_row(&other_artifact).unwrap();
        assert_eq!(scalars.file_hash, PREVALENCE_NA);
        assert_eq!(scalars.min, PREVALENCE_COMMON);
        let unstamped = json!({"file": {"hashes": [{"value": H1}]}});
        assert_eq!(RowPrevalence::from_stamped_row(&unstamped), None);
        let foreign = json!({"file": {"hashes": [{"value": H1}]},
                             "enrichments": [{"name": "prevalence", "provider": "other", "value": H1,
                                              "data": {"host_count": 1}}]});
        assert_eq!(RowPrevalence::from_stamped_row(&foreign), None);
    }

    #[test]
    fn json_string_and_flattened_shapes_read_the_same() {
        let entries = json!([stamp(H1, Some(2), false)]);
        let as_string = json!({"process.file.hashes.value": [H1],
                               "enrichments": entries.to_string()});
        assert_eq!(
            RowPrevalence::from_stamped_row(&as_string)
                .unwrap()
                .process_hash,
            2
        );
        let flat = json!({
            "query.hostname": " Evil.EXAMPLE ",
            "dst_endpoint.hostname": "",
            "enrichments.name": ["prevalence"],
            "enrichments.provider": ["nano"],
            "enrichments.value": ["evil.example"],
            "enrichments.data.host_count": ["3"],
            "enrichments.data.host_count_saturated": [false],
        });
        let scalars = RowPrevalence::from_stamped_row(&flat).unwrap();
        assert_eq!(scalars.dest_domain, 3);
        assert_eq!(scalars.min, 3);
    }

    #[test]
    fn for_field_reads_the_tree_prevalence_field() {
        let row = json!({
            "process": {"file": {"hashes": [{"value": H1}, {"value": H2}]}},
            "enrichments": [stamp(H1, Some(40), false), stamp(H2, Some(2), false)],
        });
        assert_eq!(
            RowPrevalence::for_field(&row, "process.file.hashes.value"),
            Some(2)
        );
        assert_eq!(RowPrevalence::for_field(&row, "file.hashes.value"), None);
    }
}
