// SPDX-License-Identifier: AGPL-3.0-or-later

//! OCSF 1.9 projections for Detection Finding (class 2004) rows (NAN-3224).
//!
//! Pure functions over the finding's rule metadata and its bounded matched
//! event sample:
//!
//! - [`attacks`]: one `attack` per technique, paired with the rule tactics the
//!   technique belongs to in ATT&CK v19.1, with tactic / technique /
//!   sub-technique names from the compiled-in snapshot
//!   ([`crate::mitre::attack_names`]).
//! - [`evidences`]: one `evidences[]` object per matched event, holding a
//!   curated, fixed set of OCSF attributes (actor, user, process, device,
//!   endpoints, file, DNS query, URL, registry) plus the raw event as a JSON
//!   string in `evidences[].data`. Unbounded producer shapes never become
//!   typed columns: only the curated leaves are structured.
//! - [`evidence_observables`]: user, IP, hostname/domain, process, hash and
//!   URL observables pointing at those evidence leaves.
//!
//! Every attribute used here exists in the pinned OCSF 1.9.0 contract
//! (`nanosiem-core/src/parsers/ocsf-1.9.0-contract.json.gz`); the
//! `findings.rs` tests validate whole events against it.
//!
//! Determinism matters: the shared detection path compares a replayed outbox
//! row byte-for-byte with the stored one, so nothing here reads a clock or a
//! mutable catalog.

use std::collections::BTreeSet;

use serde_json::{json, Map, Value};

use crate::mitre::attack_names;

/// ATT&CK release the compiled-in name snapshot (and `sync.rs`) pins.
pub(crate) const ATTACK_VERSION: &str = "19.1";
/// At most this many matched events become evidence (the sample is ≤ 5).
pub(crate) const MAX_EVIDENCES: usize = 5;
/// A raw matched event larger than this keeps its curated evidence fields
/// but omits `evidences[].data`.
pub(crate) const MAX_EVIDENCE_DATA_BYTES: usize = 16 * 1024;
/// Curated string leaves are truncated to this many bytes (on a char
/// boundary); the untruncated value stays in `evidences[].data`.
const MAX_EVIDENCE_STRING_BYTES: usize = 4 * 1024;
/// Observables per finding (entity first, then evidence-derived).
pub(crate) const MAX_OBSERVABLES: usize = 32;

/// OCSF `observable.type_id` values used by findings (OCSF 1.9.0 captions).
pub(crate) mod observable_type {
    pub const HOSTNAME: (i64, &str) = (1, "Hostname");
    pub const IP_ADDRESS: (i64, &str) = (2, "IP Address");
    pub const USER_NAME: (i64, &str) = (4, "User Name");
    pub const EMAIL_ADDRESS: (i64, &str) = (5, "Email Address");
    pub const URL_STRING: (i64, &str) = (6, "URL String");
    pub const PROCESS_NAME: (i64, &str) = (9, "Process Name");
    pub const HASH: (i64, &str) = (8, "Hash");
    pub const RESOURCE_UID: (i64, &str) = (10, "Resource UID");
    pub const OTHER: (i64, &str) = (99, "Other");
}

fn tactic_object(uid: &str) -> Value {
    let mut tactic = Map::from_iter([("uid".to_string(), json!(uid))]);
    if let Some(name) = attack_names::tactic_name(uid) {
        tactic.insert("name".to_string(), json!(name));
    }
    Value::Object(tactic)
}

fn technique_object(uid: &str) -> Value {
    let mut technique = Map::from_iter([("uid".to_string(), json!(uid))]);
    if let Some(name) = attack_names::technique_name(uid) {
        technique.insert("name".to_string(), json!(name));
    }
    Value::Object(technique)
}

fn clean_ids(values: &[String]) -> Vec<String> {
    let mut seen = BTreeSet::new();
    values
        .iter()
        .map(|value| value.trim().to_ascii_uppercase())
        .filter(|value| !value.is_empty() && seen.insert(value.clone()))
        .collect()
}

/// `finding_info.attacks[]`: one object per technique, paired with the rule's
/// tactics that the technique belongs to in ATT&CK v19.1. A sub-technique
/// (`T1547.001`) is `sub_technique` under its parent `technique` (`T1547`).
/// `tactic` is the first paired tactic and `tactics` lists them all when a
/// technique pairs with more than one. Rule tactics no technique pairs with
/// are kept as tactic-only objects, so no mapping on the rule is lost.
pub(crate) fn attacks(rule_tactics: &[String], rule_techniques: &[String]) -> Vec<Value> {
    let tactics = clean_ids(rule_tactics);
    let techniques = clean_ids(rule_techniques);
    let mut paired_tactics = BTreeSet::new();
    let mut attacks = Vec::new();
    for uid in &techniques {
        let catalog_tactics = attack_names::technique_tactics(uid);
        let paired = tactics
            .iter()
            .filter(|tactic| catalog_tactics.iter().any(|known| known == *tactic))
            .collect::<Vec<_>>();
        let mut attack = Map::new();
        match uid.split_once('.') {
            Some((parent, _)) => {
                attack.insert("technique".to_string(), technique_object(parent));
                attack.insert("sub_technique".to_string(), technique_object(uid));
            }
            None => {
                attack.insert("technique".to_string(), technique_object(uid));
            }
        }
        if let Some(first) = paired.first() {
            attack.insert("tactic".to_string(), tactic_object(first));
        }
        if paired.len() > 1 {
            attack.insert(
                "tactics".to_string(),
                Value::Array(paired.iter().map(|tactic| tactic_object(tactic)).collect()),
            );
        }
        attack.insert("version".to_string(), json!(ATTACK_VERSION));
        paired_tactics.extend(paired.into_iter().cloned());
        attacks.push(Value::Object(attack));
    }
    for tactic in tactics
        .iter()
        .filter(|tactic| !paired_tactics.contains(*tactic))
    {
        attacks.push(json!({ "tactic": tactic_object(tactic), "version": ATTACK_VERSION }));
    }
    attacks
}

/// The value at a dotted path (a literal dotted key wins, as for flattened
/// UDM rows).
fn at<'a>(event: &'a Value, path: &str) -> Option<&'a Value> {
    event.get(path).or_else(|| {
        path.split('.')
            .try_fold(event, |current, component| current.get(component))
    })
}

fn bounded(text: &str) -> String {
    if text.len() <= MAX_EVIDENCE_STRING_BYTES {
        return text.to_string();
    }
    let mut end = MAX_EVIDENCE_STRING_BYTES;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_string()
}

/// First non-blank string at any of `paths`.
fn text(event: &Value, paths: &[&str]) -> Option<String> {
    paths.iter().find_map(|path| {
        at(event, path)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(bounded)
    })
}

/// First integer (or canonical integer string) at any of `paths`.
fn integer(event: &Value, paths: &[&str]) -> Option<i64> {
    paths.iter().find_map(|path| match at(event, path)? {
        Value::Number(number) => number.as_i64(),
        Value::String(text) => text.trim().parse::<i64>().ok(),
        _ => None,
    })
}

/// First string at `paths` that parses as an IP address (OCSF `ip_t`).
fn ip(event: &Value, paths: &[&str]) -> Option<String> {
    paths.iter().find_map(|path| {
        at(event, path)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| value.parse::<std::net::IpAddr>().is_ok())
            .map(str::to_string)
    })
}

fn port(event: &Value, paths: &[&str]) -> Option<i64> {
    integer(event, paths).filter(|port| (0..=65_535).contains(port))
}

fn insert(object: &mut Map<String, Value>, key: &str, value: Option<impl Into<Value>>) {
    if let Some(value) = value {
        object.insert(key.to_string(), value.into());
    }
}

/// OCSF `fingerprint.algorithm_id` inferred from a hex digest's length.
fn hash_algorithm(value: &str) -> (i64, &'static str) {
    if !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return (0, "Unknown");
    }
    match value.len() {
        32 => (1, "MD5"),
        40 => (2, "SHA-1"),
        64 => (3, "SHA-256"),
        128 => (4, "SHA-512"),
        _ => (0, "Unknown"),
    }
}

fn fingerprint(value: &str) -> Value {
    let (algorithm_id, algorithm) = hash_algorithm(value);
    json!({ "algorithm_id": algorithm_id, "algorithm": algorithm, "value": bounded(value) })
}

/// `file.hashes[]` from an OCSF `hashes` array (algorithm kept when it is a
/// valid id) or a flat UDM digest string.
fn hashes(event: &Value, array_path: &str, flat_paths: &[&str]) -> Vec<Value> {
    let mut out = Vec::new();
    if let Some(items) = at(event, array_path).and_then(Value::as_array) {
        for item in items.iter().take(4) {
            let Some(value) = item
                .get("value")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
            else {
                continue;
            };
            let mut hash = fingerprint(value);
            if let Some(algorithm_id) = item
                .get("algorithm_id")
                .and_then(Value::as_i64)
                .filter(|id| (0..=20).contains(id) || *id == 99)
            {
                hash["algorithm_id"] = json!(algorithm_id);
                match item.get("algorithm").and_then(Value::as_str) {
                    Some(name) if !name.trim().is_empty() => {
                        hash["algorithm"] = json!(bounded(name))
                    }
                    _ => {
                        if let Some(object) = hash.as_object_mut() {
                            object.remove("algorithm");
                        }
                    }
                }
            }
            out.push(hash);
        }
    }
    if out.is_empty() {
        if let Some(value) = text(event, flat_paths) {
            out.push(fingerprint(&value));
        }
    }
    out
}

fn basename(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

/// An OCSF `file` (requires `name` and `type_id`).
fn file(
    event: &Value,
    prefix: &str,
    flat_path: &[&str],
    flat_name: &[&str],
    flat_hash: &[&str],
) -> Option<Value> {
    let path = text(event, &[&format!("{prefix}.path")]).or_else(|| text(event, flat_path));
    let name = text(event, &[&format!("{prefix}.name")])
        .or_else(|| text(event, flat_name))
        .or_else(|| {
            path.as_deref()
                .map(basename)
                .filter(|n| !n.is_empty())
                .map(str::to_string)
        })?;
    let mut file = Map::from_iter([
        ("name".to_string(), json!(name)),
        (
            "type_id".to_string(),
            json!(integer(event, &[&format!("{prefix}.type_id")])
                .filter(|id| (0..=8).contains(id) || *id == 99)
                .unwrap_or(0)),
        ),
    ]);
    insert(&mut file, "path", path);
    let hashes = hashes(event, &format!("{prefix}.hashes"), flat_hash);
    if !hashes.is_empty() {
        file.insert("hashes".to_string(), Value::Array(hashes));
    }
    Some(Value::Object(file))
}

/// An OCSF `process`. The 1.9 contract requires one of `pid`/`uid`/`cpid`,
/// so a process the event identifies by neither is not projected (its fields
/// stay in `evidences[].data`).
fn process(event: &Value, prefix: &str, flat: ProcessFlat<'_>) -> Option<Value> {
    let pid = integer(event, &[&format!("{prefix}.pid")]).or_else(|| integer(event, flat.pid));
    let uid = text(event, &[&format!("{prefix}.uid")]);
    if pid.is_none() && uid.is_none() {
        return None;
    }
    let mut process = Map::new();
    insert(&mut process, "pid", pid);
    insert(&mut process, "uid", uid);
    insert(
        &mut process,
        "name",
        text(event, &[&format!("{prefix}.name")]).or_else(|| text(event, flat.name)),
    );
    insert(
        &mut process,
        "cmd_line",
        text(event, &[&format!("{prefix}.cmd_line")]).or_else(|| text(event, flat.cmd_line)),
    );
    insert(
        &mut process,
        "file",
        file(event, &format!("{prefix}.file"), flat.path, &[], flat.hash),
    );
    Some(Value::Object(process))
}

#[derive(Clone, Copy)]
struct ProcessFlat<'a> {
    pid: &'a [&'a str],
    name: &'a [&'a str],
    cmd_line: &'a [&'a str],
    path: &'a [&'a str],
    hash: &'a [&'a str],
}

const NO_FLAT: ProcessFlat<'static> = ProcessFlat {
    pid: &[],
    name: &[],
    cmd_line: &[],
    path: &[],
    hash: &[],
};

fn user(event: &Value, prefix: &str, flat_name: &[&str]) -> Option<Value> {
    let mut user = Map::new();
    insert(
        &mut user,
        "name",
        text(event, &[&format!("{prefix}.name")]).or_else(|| text(event, flat_name)),
    );
    insert(&mut user, "uid", text(event, &[&format!("{prefix}.uid")]));
    if user.is_empty() {
        return None;
    }
    insert(
        &mut user,
        "domain",
        text(event, &[&format!("{prefix}.domain")]),
    );
    Some(Value::Object(user))
}

fn endpoint(
    event: &Value,
    prefix: &str,
    flat_ip: &[&str],
    flat_host: &[&str],
    flat_port: &[&str],
) -> Option<Value> {
    let mut endpoint = Map::new();
    insert(
        &mut endpoint,
        "ip",
        ip(event, &[&format!("{prefix}.ip")]).or_else(|| ip(event, flat_ip)),
    );
    insert(
        &mut endpoint,
        "hostname",
        text(event, &[&format!("{prefix}.hostname")]).or_else(|| text(event, flat_host)),
    );
    insert(
        &mut endpoint,
        "domain",
        text(event, &[&format!("{prefix}.domain")]),
    );
    // A port alone does not identify an endpoint (OCSF at_least_one).
    if endpoint.is_empty() {
        return None;
    }
    insert(
        &mut endpoint,
        "port",
        port(event, &[&format!("{prefix}.port")]).or_else(|| port(event, flat_port)),
    );
    Some(Value::Object(endpoint))
}

fn device(event: &Value) -> Option<Value> {
    let mut device = Map::new();
    insert(
        &mut device,
        "hostname",
        text(event, &["device.hostname", "host", "hostname"]),
    );
    insert(&mut device, "ip", ip(event, &["device.ip"]));
    insert(&mut device, "name", text(event, &["device.name"]));
    insert(&mut device, "uid", text(event, &["device.uid"]));
    if device.is_empty() {
        return None;
    }
    device.insert(
        "type_id".to_string(),
        json!(integer(event, &["device.type_id"])
            .filter(|id| (0..=15).contains(id) || *id == 99)
            .unwrap_or(0)),
    );
    Some(Value::Object(device))
}

/// The curated OCSF evidence of one matched event, or `None` when the event
/// carries none of the attributes OCSF requires at least one of.
fn evidence(event: &Value) -> Option<Map<String, Value>> {
    let mut evidence = Map::new();

    let mut actor = Map::new();
    insert(&mut actor, "user", user(event, "actor.user", &["user"]));
    insert(
        &mut actor,
        "process",
        process(
            event,
            "actor.process",
            ProcessFlat {
                pid: &["parent_process_id"],
                name: &["parent_process_name"],
                cmd_line: &["parent_command_line"],
                path: &["parent_process_path"],
                hash: &[],
            },
        ),
    );
    if !actor.is_empty() {
        evidence.insert("actor".to_string(), Value::Object(actor));
    }
    // OCSF `user` is an object; a flat UDM `user` string is the actor above.
    insert(&mut evidence, "user", user(event, "user", &[]));
    insert(
        &mut evidence,
        "process",
        process(
            event,
            "process",
            ProcessFlat {
                pid: &["process_id", "pid"],
                name: &["process_name"],
                cmd_line: &["command_line"],
                path: &["process_path"],
                hash: &["process_hash"],
            },
        ),
    );
    insert(&mut evidence, "device", device(event));
    insert(
        &mut evidence,
        "src_endpoint",
        endpoint(
            event,
            "src_endpoint",
            &["src_ip"],
            &["src_host"],
            &["src_port"],
        ),
    );
    insert(
        &mut evidence,
        "dst_endpoint",
        endpoint(
            event,
            "dst_endpoint",
            &["dest_ip", "dst_ip"],
            &["dest_host", "dst_host"],
            &["dest_port", "dst_port"],
        ),
    );
    insert(
        &mut evidence,
        "file",
        file(
            event,
            "file",
            &["file_path"],
            &["file_name"],
            &["file_hash"],
        ),
    );
    if let Some(hostname) = text(event, &["query.hostname"]) {
        evidence.insert("query".to_string(), json!({ "hostname": hostname }));
    }
    let mut url = Map::new();
    insert(
        &mut url,
        "url_string",
        text(event, &["url.url_string", "url"]),
    );
    insert(&mut url, "hostname", text(event, &["url.hostname"]));
    if url.contains_key("url_string") {
        evidence.insert("url".to_string(), Value::Object(url));
    }
    if let Some(path) = text(event, &["reg_key.path", "registry_path"]) {
        evidence.insert("reg_key".to_string(), json!({ "path": path }));
    }
    if let (Some(path), Some(name)) = (
        text(event, &["reg_value.path"]),
        text(event, &["reg_value.name"]),
    ) {
        evidence.insert(
            "reg_value".to_string(),
            json!({ "path": path, "name": name }),
        );
    }
    // Keep the `.process` sub-object's NAN-1800 neutrality: nothing here is
    // derived from anything but the (already redaction-filtered) sample.
    if evidence.is_empty() {
        return None;
    }
    insert(&mut evidence, "uid", text(event, &["metadata.uid", "id"]));
    insert(&mut evidence, "name", text(event, &["class_name"]));
    Some(evidence)
}

/// The OCSF projection of a finding's matched event sample.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct EvidenceProjection {
    /// `evidences[]`: curated attributes + raw `data` (a JSON string).
    pub evidences: Vec<Value>,
    /// `finding_info.related_events[]`: the matched events' own uids.
    pub related_events: Vec<Value>,
    /// Matched events with none of the attributes an OCSF evidence requires.
    /// They keep the pre-NAN-3224 home, `unmapped.matched_events_sample`.
    pub unmapped_samples: Vec<Value>,
}

/// Project the (already redaction-filtered, ≤ 5) matched event sample.
pub(crate) fn evidences(sample: &[Value]) -> EvidenceProjection {
    let mut projection = EvidenceProjection::default();
    for event in sample.iter().take(MAX_EVIDENCES) {
        let encoded =
            serde_json::to_string(event).expect("serializing serde_json::Value cannot fail");
        match evidence(event) {
            Some(mut evidence) => {
                if let Some(uid) = evidence.get("uid").and_then(Value::as_str) {
                    let mut related = Map::from_iter([("uid".to_string(), json!(uid))]);
                    insert(&mut related, "type_uid", integer(event, &["type_uid"]));
                    insert(&mut related, "type_name", text(event, &["type_name"]));
                    projection.related_events.push(Value::Object(related));
                }
                if encoded.len() <= MAX_EVIDENCE_DATA_BYTES {
                    evidence.insert("data".to_string(), Value::String(encoded));
                }
                projection.evidences.push(Value::Object(evidence));
            }
            None => projection.unmapped_samples.push(Value::String(encoded)),
        }
    }
    projection
}

/// Observable-bearing leaves of an evidence: (relative path, type).
const EVIDENCE_OBSERVABLE_LEAVES: &[(&str, (i64, &str))] = &[
    ("actor.user.name", observable_type::USER_NAME),
    ("user.name", observable_type::USER_NAME),
    ("actor.process.name", observable_type::PROCESS_NAME),
    ("process.name", observable_type::PROCESS_NAME),
    ("device.hostname", observable_type::HOSTNAME),
    ("device.ip", observable_type::IP_ADDRESS),
    ("src_endpoint.ip", observable_type::IP_ADDRESS),
    ("src_endpoint.hostname", observable_type::HOSTNAME),
    ("src_endpoint.domain", observable_type::HOSTNAME),
    ("dst_endpoint.ip", observable_type::IP_ADDRESS),
    ("dst_endpoint.hostname", observable_type::HOSTNAME),
    ("dst_endpoint.domain", observable_type::HOSTNAME),
    ("query.hostname", observable_type::HOSTNAME),
    ("url.url_string", observable_type::URL_STRING),
];

/// Observable-bearing hash arrays of an evidence.
const EVIDENCE_HASH_ARRAYS: &[&str] = &[
    "actor.process.file.hashes",
    "process.file.hashes",
    "file.hashes",
];

pub(crate) fn observable(name: &str, (type_id, type_name): (i64, &str), value: &str) -> Value {
    json!({ "name": name, "type": type_name, "type_id": type_id, "value": value })
}

/// Append evidence-derived observables to `observables`, de-duplicated by
/// `(type_id, value)` against what is already there, up to
/// [`MAX_OBSERVABLES`].
pub(crate) fn evidence_observables(observables: &mut Vec<Value>, evidences: &[Value]) {
    let mut seen = observables
        .iter()
        .filter_map(|observable| {
            Some((
                observable.get("type_id")?.as_i64()?,
                observable.get("value")?.as_str()?.to_string(),
            ))
        })
        .collect::<BTreeSet<_>>();
    let mut push = |observables: &mut Vec<Value>, name: String, kind: (i64, &str), value: &str| {
        if observables.len() < MAX_OBSERVABLES && seen.insert((kind.0, value.to_string())) {
            observables.push(observable(&name, kind, value));
        }
    };
    for (index, evidence) in evidences.iter().enumerate() {
        for (path, kind) in EVIDENCE_OBSERVABLE_LEAVES {
            if let Some(value) = at(evidence, path).and_then(Value::as_str) {
                push(
                    observables,
                    format!("evidences[{index}].{path}"),
                    *kind,
                    value,
                );
            }
        }
        for array in EVIDENCE_HASH_ARRAYS {
            for (hash_index, hash) in at(evidence, array)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .enumerate()
            {
                if let Some(value) = hash.get("value").and_then(Value::as_str) {
                    push(
                        observables,
                        format!("evidences[{index}].{array}[{hash_index}].value"),
                        observable_type::HASH,
                        value,
                    );
                }
            }
        }
    }
}

/// Earliest and latest event time of the matched events, as OCSF epoch
/// milliseconds. Aggregate rows contribute their `_first_seen`/`_last_seen`
/// window bounds.
pub(crate) fn seen_window_ms(
    events: &[Value],
    parse: impl Fn(&Value) -> Option<chrono::DateTime<chrono::Utc>>,
) -> Option<(i64, i64)> {
    let mut window: Option<(i64, i64)> = None;
    let mut widen = |ms: i64| {
        window = Some(match window {
            Some((first, last)) => (first.min(ms), last.max(ms)),
            None => (ms, ms),
        });
    };
    for event in events {
        for path in [
            "_first_seen",
            "_last_seen",
            "time",
            "timestamp",
            "start_time",
            "end_time",
        ] {
            if let Some(time) = at(event, path).and_then(&parse) {
                widen(time.timestamp_millis());
            }
        }
    }
    window
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn attacks_pair_technique_with_its_tactic_and_names() {
        let attacks = attacks(&ids(&["TA0003"]), &ids(&["T1547.001"]));
        assert_eq!(
            attacks,
            vec![json!({
                "technique": {"uid": "T1547", "name": "Boot or Logon Autostart Execution"},
                "sub_technique": {"uid": "T1547.001", "name": "Registry Run Keys / Startup Folder"},
                "tactic": {"uid": "TA0003", "name": "Persistence"},
                "version": "19.1",
            })]
        );
    }

    #[test]
    fn attacks_list_every_paired_tactic_and_keep_unpaired_ones() {
        // T1547.001 is Persistence + Privilege Escalation; TA0002 (Execution)
        // pairs with no technique on the rule and is kept tactic-only.
        let attacks = attacks(
            &ids(&["TA0004", "TA0003", "TA0002", "ta0003"]),
            &ids(&["T1547.001", "T9999"]),
        );
        assert_eq!(attacks.len(), 3, "{attacks:#?}");
        assert_eq!(attacks[0]["tactic"]["uid"], "TA0004");
        assert_eq!(attacks[0]["tactics"][1]["uid"], "TA0003");
        assert_eq!(attacks[0]["tactics"].as_array().unwrap().len(), 2);
        // Unknown technique: uid kept, no name, no invented tactic.
        assert_eq!(
            attacks[1],
            json!({"technique": {"uid": "T9999"}, "version": "19.1"})
        );
        assert_eq!(
            attacks[2],
            json!({"tactic": {"uid": "TA0002", "name": "Execution"}, "version": "19.1"})
        );
        assert!(super::attacks(&[], &[]).is_empty());
    }

    fn sysmon_registry_event() -> Value {
        json!({
            "metadata": {"uid": "evt-1", "log_source": "windows_sysmon"},
            "class_name": "Registry Value Activity",
            "type_uid": 201_403,
            "time": 1_790_000_000_000_i64,
            "actor": {
                "user": {"name": "CORP\\alice", "uid": "S-1-5-21-1"},
                "process": {
                    "pid": 4242,
                    "name": "reg.exe",
                    "cmd_line": "reg add HKCU\\...\\Run /v x /d c:\\x.exe",
                    "file": {"path": "C:\\Windows\\System32\\reg.exe",
                             "hashes": [{"algorithm_id": 3, "algorithm": "SHA-256",
                                         "value": "a".repeat(64)}]},
                },
            },
            "device": {"hostname": "ws-fin-011", "ip": "10.1.2.3", "type_id": 2},
            "reg_value": {"path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "name": "x"},
            "reg_key": {"path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
            "src_endpoint": {"ip": "not-an-ip", "port": 99_999},
        })
    }

    #[test]
    fn evidence_is_curated_bounded_and_keeps_raw_data() {
        let projection = evidences(&[sysmon_registry_event()]);
        assert!(projection.unmapped_samples.is_empty());
        let evidence = &projection.evidences[0];
        assert_eq!(evidence["actor"]["user"]["name"], "CORP\\alice");
        assert_eq!(evidence["actor"]["process"]["pid"], 4242);
        assert_eq!(evidence["actor"]["process"]["file"]["name"], "reg.exe");
        assert_eq!(evidence["actor"]["process"]["file"]["type_id"], 0);
        assert_eq!(evidence["device"]["hostname"], "ws-fin-011");
        assert_eq!(evidence["device"]["type_id"], 2);
        assert_eq!(evidence["reg_value"]["name"], "x");
        assert_eq!(evidence["uid"], "evt-1");
        assert_eq!(evidence["name"], "Registry Value Activity");
        // An invalid IP and an out-of-range port are dropped, so the
        // endpoint (which nothing else identifies) is omitted.
        assert!(evidence.get("src_endpoint").is_none());
        let raw: Value = serde_json::from_str(evidence["data"].as_str().unwrap()).unwrap();
        assert_eq!(raw, sysmon_registry_event());
        assert_eq!(
            projection.related_events,
            vec![json!({"uid": "evt-1", "type_uid": 201_403})]
        );
    }

    #[test]
    fn evidences_are_capped_and_oversized_raw_data_is_omitted() {
        let mut big = sysmon_registry_event();
        big["unmapped"] = json!({"blob": "x".repeat(MAX_EVIDENCE_DATA_BYTES)});
        big["actor"]["process"]["cmd_line"] = json!("y".repeat(3 * MAX_EVIDENCE_STRING_BYTES));
        let sample = vec![big; 7];
        let projection = evidences(&sample);
        assert_eq!(projection.evidences.len(), MAX_EVIDENCES);
        for evidence in &projection.evidences {
            assert!(evidence.get("data").is_none());
            assert_eq!(
                evidence["actor"]["process"]["cmd_line"]
                    .as_str()
                    .unwrap()
                    .len(),
                MAX_EVIDENCE_STRING_BYTES
            );
        }
    }

    #[test]
    fn udm_rows_map_and_unmappable_rows_keep_the_unmapped_sample() {
        let udm = json!({
            "id": "udm-1", "user": "bob", "src_ip": "192.0.2.7", "dest_ip": "198.51.100.9",
            "dest_port": "443", "process_name": "curl", "process_id": 77,
            "command_line": "curl http://x", "file_hash": "d41d8cd98f00b204e9800998ecf8427e",
            "url": "http://x/a",
        });
        let aggregate = json!({"count": 12, "_nano_source_types": ["x"]});
        let projection = evidences(&[udm, aggregate.clone()]);
        assert_eq!(projection.evidences.len(), 1);
        let evidence = &projection.evidences[0];
        assert_eq!(evidence["actor"]["user"]["name"], "bob");
        assert_eq!(evidence["src_endpoint"], json!({"ip": "192.0.2.7"}));
        assert_eq!(
            evidence["dst_endpoint"],
            json!({"ip": "198.51.100.9", "port": 443})
        );
        assert_eq!(evidence["process"]["name"], "curl");
        assert_eq!(evidence["process"]["cmd_line"], "curl http://x");
        assert_eq!(evidence["url"]["url_string"], "http://x/a");
        assert_eq!(
            projection.unmapped_samples,
            vec![Value::String(aggregate.to_string())]
        );

        let mut observables = Vec::new();
        evidence_observables(&mut observables, &projection.evidences);
        let kinds = observables
            .iter()
            .map(|o| {
                (
                    o["type_id"].as_i64().unwrap(),
                    o["value"].as_str().unwrap().to_string(),
                )
            })
            .collect::<Vec<_>>();
        assert!(kinds.contains(&(4, "bob".into())));
        assert!(kinds.contains(&(2, "192.0.2.7".into())));
        assert!(kinds.contains(&(9, "curl".into())));
        assert!(kinds.contains(&(6, "http://x/a".into())));
        // A process without pid/uid is not an OCSF process; its hash stays in data.
        assert!(kinds.iter().all(|(type_id, _)| *type_id != 8));
    }

    #[test]
    fn observables_dedupe_against_the_entity_and_cap() {
        let mut observables = vec![observable(
            "resources[0].hostname",
            observable_type::HOSTNAME,
            "ws-fin-011",
        )];
        let projection = evidences(&[sysmon_registry_event()]);
        evidence_observables(&mut observables, &projection.evidences);
        let hostnames = observables
            .iter()
            .filter(|o| o["value"] == "ws-fin-011")
            .count();
        assert_eq!(hostnames, 1);
        assert!(observables
            .iter()
            .any(|o| o["type_id"] == 8
                && o["name"] == "evidences[0].actor.process.file.hashes[0].value"));
        assert!(observables
            .iter()
            .any(|o| o["type_id"] == 9 && o["value"] == "reg.exe"));

        let many = (0..40)
            .map(|i| json!({"src_ip": format!("10.0.0.{i}")}))
            .collect::<Vec<_>>();
        let many = many
            .iter()
            .map(|event| Value::Object(evidence(event).unwrap()))
            .collect::<Vec<_>>();
        let mut capped = Vec::new();
        evidence_observables(&mut capped, &many);
        assert_eq!(capped.len(), MAX_OBSERVABLES);
    }
}
