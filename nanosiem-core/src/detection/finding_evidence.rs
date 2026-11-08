// SPDX-License-Identifier: AGPL-3.0-or-later

//! Engine-agnostic evidence for detection findings (NAN-4902, port of the
//! agnostic half of NAN-3224 / main `cf492a0d5`).
//!
//! Pure functions over the finding's rule metadata and its matched events:
//!
//! - [`attacks`]: one object per ATT&CK technique, paired with the rule tactics
//!   the technique belongs to in ATT&CK v19.1, with names from the compiled-in
//!   snapshot ([`crate::mitre::attack_names`]).
//! - [`observables`]: the scored entity first, then user / IP / host / process /
//!   hash / URL values from the (already redaction-filtered) sample,
//!   de-duplicated by `(type_id, value)` and capped at [`MAX_OBSERVABLES`].
//!   Flat UDM columns and OCSF paths (nested or literal dotted keys) both count.
//! - [`related_events`]: the sampled events' own ids.
//! - [`seen_window`]: earliest / latest event time across ALL matched events.
//! - [`analytic_state`] and [`alert_src_url`]: rule mode and alert link.
//!
//! Nothing here reads a clock or a mutable catalog, so a finding built twice
//! from the same inputs is identical. The OCSF 2004 placement of these values
//! (`finding_info.attacks[]`, `observables[]`, `evidences[]`) is a separate,
//! OCSF-only concern; here they ride on the findings row.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::mitre::attack_names;

/// ATT&CK release the compiled-in name snapshot (and `mitre/sync.rs`) pins.
pub(crate) const ATTACK_VERSION: &str = "19.1";
/// Observables per finding (entity first, then sample-derived).
pub(crate) const MAX_OBSERVABLES: usize = 32;
/// Observable values longer than this are not observables (bounded rows).
const MAX_OBSERVABLE_BYTES: usize = 2 * 1024;

/// OCSF `observable.type_id` values (OCSF 1.9.0 captions), so the row reads
/// the same whichever schema profile is active.
pub(crate) mod observable_type {
    pub const HOSTNAME: (i64, &str) = (1, "Hostname");
    pub const IP_ADDRESS: (i64, &str) = (2, "IP Address");
    pub const USER_NAME: (i64, &str) = (4, "User Name");
    pub const EMAIL_ADDRESS: (i64, &str) = (5, "Email Address");
    pub const URL_STRING: (i64, &str) = (6, "URL String");
    pub const HASH: (i64, &str) = (8, "Hash");
    pub const PROCESS_NAME: (i64, &str) = (9, "Process Name");
    pub const RESOURCE_UID: (i64, &str) = (10, "Resource UID");
    pub const OTHER: (i64, &str) = (99, "Other");
}

use observable_type as ot;

/// Observable-bearing leaves of a matched event: flat UDM columns first, then
/// OCSF paths. A path resolves as a literal key first (flattened rows), then
/// as nested objects.
const OBSERVABLE_LEAVES: &[(&str, (i64, &str))] = &[
    // UDM
    ("user", ot::USER_NAME),
    ("src_user", ot::USER_NAME),
    ("dest_user", ot::USER_NAME),
    ("src_ip", ot::IP_ADDRESS),
    ("dest_ip", ot::IP_ADDRESS),
    ("src_host", ot::HOSTNAME),
    ("dest_host", ot::HOSTNAME),
    ("url_domain", ot::HOSTNAME),
    ("query", ot::HOSTNAME),
    ("process_name", ot::PROCESS_NAME),
    ("parent_process_name", ot::PROCESS_NAME),
    ("process_hash", ot::HASH),
    ("file_hash", ot::HASH),
    ("url", ot::URL_STRING),
    // OCSF
    ("actor.user.name", ot::USER_NAME),
    ("user.name", ot::USER_NAME),
    ("actor.process.name", ot::PROCESS_NAME),
    ("process.name", ot::PROCESS_NAME),
    ("device.hostname", ot::HOSTNAME),
    ("device.ip", ot::IP_ADDRESS),
    ("src_endpoint.ip", ot::IP_ADDRESS),
    ("src_endpoint.hostname", ot::HOSTNAME),
    ("dst_endpoint.ip", ot::IP_ADDRESS),
    ("dst_endpoint.hostname", ot::HOSTNAME),
    ("query.hostname", ot::HOSTNAME),
    ("url.url_string", ot::URL_STRING),
    ("actor.process.file.hashes.value", ot::HASH),
    ("process.file.hashes.value", ot::HASH),
    ("file.hashes.value", ot::HASH),
];

/// OCSF hash arrays (`[{algorithm_id, value}]`) whose values are observables.
const OCSF_HASH_ARRAYS: &[&str] = &[
    "actor.process.file.hashes",
    "process.file.hashes",
    "file.hashes",
];

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

/// One object per technique, paired with the rule's tactics that the
/// technique belongs to in ATT&CK v19.1. A sub-technique (`T1547.001`) is
/// `sub_technique` under its parent `technique` (`T1547`). `tactic` is the
/// first paired tactic and `tactics` lists them all when a technique pairs
/// with more than one. Rule tactics no technique pairs with are kept as
/// tactic-only objects, so no mapping on the rule is lost.
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
    for tactic in tactics.iter().filter(|tactic| !paired_tactics.contains(*tactic)) {
        attacks.push(json!({ "tactic": tactic_object(tactic), "version": ATTACK_VERSION }));
    }
    attacks
}

/// The value at a dotted path: a literal dotted key wins (flattened rows),
/// otherwise nested objects are walked.
fn at<'a>(event: &'a Value, path: &str) -> Option<&'a Value> {
    if let Some(value) = event.get(path) {
        return Some(value);
    }
    path.split('.').try_fold(event, |node, key| node.get(key))
}

/// A usable observable value: a non-empty, bounded string that is not one of
/// the placeholder values ingest uses for "absent".
fn observable_value(value: &Value) -> Option<&str> {
    let text = value.as_str()?.trim();
    let placeholder = matches!(text, "" | "-" | "unknown" | "null" | "0.0.0.0" | "::");
    (!placeholder && text.len() <= MAX_OBSERVABLE_BYTES).then_some(text)
}

fn observable(name: &str, (type_id, type_name): (i64, &str), value: &str) -> Value {
    json!({ "name": name, "type": type_name, "type_id": type_id, "value": value })
}

/// Observable type of the scored entity, from the write-side entity type
/// (`FindingLogger::infer_entity_type`).
fn entity_observable_type(entity_type: &str) -> (i64, &'static str) {
    match entity_type {
        "user" => ot::USER_NAME,
        "hostname" | "host" | "domain" => ot::HOSTNAME,
        "ip" => ot::IP_ADDRESS,
        "email" => ot::EMAIL_ADDRESS,
        "hash" => ot::HASH,
        "url" => ot::URL_STRING,
        "cloud_account" => ot::RESOURCE_UID,
        _ => ot::OTHER,
    }
}

/// The finding's observables: the scored entity (named by the field it came
/// from), then values from the matched-event sample, de-duplicated by
/// `(type_id, value)` and capped at [`MAX_OBSERVABLES`].
///
/// Callers pass the post-redaction entity and sample: a finding whose origin
/// is restricted has an empty sample and entity, so it carries no observables.
pub(crate) fn observables(
    risk_entity: &str,
    risk_entity_type: &str,
    risk_entity_field: Option<&str>,
    sample: &[Value],
) -> Vec<Value> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    let mut push = |out: &mut Vec<Value>, name: String, kind: (i64, &str), value: &str| {
        if out.len() < MAX_OBSERVABLES && seen.insert((kind.0, value.to_string())) {
            out.push(observable(&name, kind, value));
        }
    };
    if let Some(entity) = observable_value(&Value::String(risk_entity.to_string())) {
        push(
            &mut out,
            risk_entity_field.unwrap_or("risk_entity").to_string(),
            entity_observable_type(risk_entity_type),
            entity,
        );
    }
    for (index, event) in sample.iter().enumerate() {
        for (path, kind) in OBSERVABLE_LEAVES {
            if let Some(value) = at(event, path).and_then(observable_value) {
                push(&mut out, format!("matched_events_sample[{index}].{path}"), *kind, value);
            }
        }
        for array in OCSF_HASH_ARRAYS {
            let hashes = at(event, array).and_then(Value::as_array).into_iter().flatten();
            for (hash_index, hash) in hashes.enumerate() {
                if let Some(value) = hash.get("value").and_then(observable_value) {
                    push(
                        &mut out,
                        format!("matched_events_sample[{index}].{array}[{hash_index}].value"),
                        ot::HASH,
                        value,
                    );
                }
            }
        }
    }
    out
}

/// The sampled events' own ids (UDM `id`, OCSF `metadata.uid`), so a finding
/// links back to the exact rows that fired it.
pub(crate) fn related_events(sample: &[Value]) -> Vec<Value> {
    let mut seen = BTreeSet::new();
    sample
        .iter()
        .filter_map(|event| {
            let uid = ["id", "metadata.uid"]
                .iter()
                .find_map(|path| at(event, path).and_then(observable_value))?;
            seen.insert(uid.to_string()).then(|| json!({ "uid": uid }))
        })
        .collect()
}

/// Parse an event-time value: the ClickHouse/serialized string forms detection
/// events carry, or an integer epoch (milliseconds when it is that large, as
/// OCSF `time` is; otherwise seconds).
pub(crate) fn parse_event_time(value: &Value) -> Option<DateTime<Utc>> {
    if let Some(text) = value.as_str() {
        for format in ["%Y-%m-%d %H:%M:%S%.f", "%Y-%m-%d %H:%M:%S"] {
            if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(text, format) {
                return Some(DateTime::from_naive_utc_and_offset(naive, Utc));
            }
        }
        return DateTime::parse_from_rfc3339(text)
            .ok()
            .map(|dt| dt.with_timezone(&Utc));
    }
    let epoch = value.as_i64()?;
    if epoch.unsigned_abs() >= 100_000_000_000 {
        DateTime::from_timestamp_millis(epoch)
    } else {
        DateTime::from_timestamp(epoch, 0)
    }
}

/// Earliest and latest event time across the matched events. Aggregate rows
/// contribute their `_first_seen` / `_last_seen` window bounds.
pub(crate) fn seen_window(events: &[Value]) -> Option<(DateTime<Utc>, DateTime<Utc>)> {
    let mut window: Option<(DateTime<Utc>, DateTime<Utc>)> = None;
    for event in events {
        for path in ["_first_seen", "_last_seen", "timestamp", "time"] {
            if let Some(time) = at(event, path).and_then(parse_event_time) {
                window = Some(match window {
                    Some((first, last)) => (first.min(time), last.max(time)),
                    None => (time, time),
                });
            }
        }
    }
    window
}

/// OCSF `analytic.state_id` / `state` for a rule mode (OCSF 1.9.0 captions).
/// Alerting = Active, Live = Experimental (bake-in), Paused = Suppressed;
/// anything else (Staging rule tests) is Other with the mode as its `state`.
pub(crate) fn analytic_state(rule_mode: &str) -> (i64, String) {
    match rule_mode {
        "alerting" => (1, "Active".to_string()),
        "paused" => (2, "Suppressed".to_string()),
        "live" => (3, "Experimental".to_string()),
        "" => (0, "Unknown".to_string()),
        other => (99, other.to_string()),
    }
}

/// The app-relative deep link of a finding's alert (`/alerts/<alert typeid>`),
/// the form in-app notifications use. Relative, so the stored row never embeds
/// a host that can change.
pub(crate) fn alert_src_url(alert_id: &Uuid) -> String {
    format!("/alerts/{}", crate::typeid::encode(crate::typeid::alert::PREFIX, alert_id))
}
