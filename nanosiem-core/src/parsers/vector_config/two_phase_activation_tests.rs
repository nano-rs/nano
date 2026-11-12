// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5132 (PR 5): two-phase activation render contract.
//!
//! * pre → A (stage): the new source's chain and slots appear, its entry reads
//!   the parked filter, and `source_router` is byte-identical: no event is
//!   routed differently on a host that installed A.
//! * A → B (activate): only `source_router` and the source's own chain entry
//!   change; no fan-in, slot or sink is rebuilt. B equals a one-phase render.
//! * Removal mirrors it: A unroutes and parks, B drops the chain.

use std::collections::{BTreeMap, BTreeSet};

use super::fanin_slots::{assign, force_for_test, slot_id, without_env, Family, PARKED};
use super::*;
use tempfile::TempDir;

fn parser(name: &str, nth: i64) -> Parser {
    let mut bytes = [0u8; 16];
    for (i, b) in name.bytes().enumerate() {
        bytes[i % 16] = bytes[i % 16].wrapping_mul(31).wrapping_add(b);
    }
    let at = chrono::DateTime::from_timestamp(1_700_000_000 + nth * 60, 0).unwrap();
    Parser {
        id: uuid::Uuid::from_bytes(bytes),
        name: name.to_string(),
        description: None,
        source_type: "http".to_string(),
        parser_vrl: format!(".vendor = \"{name}\""),
        output_fields: None,
        feed_id: None,
        dispatch_source_config_id: None,
        dispatch_route_name: None,
        enabled: true,
        validated: true,
        validation_error: None,
        category: None,
        vendor: None,
        product: None,
        kind: "log".to_string(),
        enrich_kind: None,
        enrich_source: None,
        target_table: None,
        normalize_vrl: None,
        namespace: "default".to_string(),
        timezone: "UTC".to_string(),
        match_values: None,
        sampling_ratio: None,
        sampling_exclude_condition: None,
        extension_vrl: None,
        extension_enabled: false,
        activation_parked: false,
        created_at: at,
        updated_at: at,
    }
}

fn fleet(n: usize) -> Vec<Parser> {
    (0..n).map(|i| parser(&format!("source_{i:02}"), i as i64)).collect()
}

fn components(manager: &VectorConfigManager) -> BTreeMap<String, toml::Value> {
    let mut out = BTreeMap::new();
    for entry in std::fs::read_dir(manager.parsers_dir()).unwrap().flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(".toml") {
            continue;
        }
        let raw = std::fs::read_to_string(entry.path()).unwrap();
        let value: toml::Value =
            toml::from_str(&without_env(&raw)).unwrap_or_else(|e| panic!("{name}: {e}"));
        for kind in ["sources", "transforms", "sinks"] {
            if let Some(table) = value.get(kind).and_then(|t| t.as_table()) {
                for (id, def) in table {
                    out.insert(format!("{kind}.{id}"), def.clone());
                }
            }
        }
    }
    out
}

async fn render(manager: &VectorConfigManager, parsers: &[Parser]) -> BTreeMap<String, toml::Value> {
    manager.stage_parsers(parsers).await.expect("stage");
    manager.promote_staged().await.expect("promote");
    components(manager)
}

fn changed(a: &BTreeMap<String, toml::Value>, b: &BTreeMap<String, toml::Value>) -> BTreeSet<String> {
    a.keys()
        .chain(b.keys())
        .filter(|k| a.get(*k) != b.get(*k))
        .cloned()
        .collect()
}

fn inputs(def: &toml::Value) -> Vec<String> {
    def.get("inputs")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

fn chain_prefix(p: &Parser) -> String {
    format!("transforms.{}_", VectorConfigManager::safe_name(&p.name))
}

fn slot_components(slot: usize) -> Vec<String> {
    [Family::Out, Family::Kept, Family::Ocsf]
        .iter()
        .map(|f| format!("transforms.{}", slot_id(*f, slot)))
        .collect()
}

/// Every component that reads anything outside `source`'s own chain.
fn chain_entries(tree: &BTreeMap<String, toml::Value>, source: &Parser) -> Vec<(String, Vec<String>)> {
    let prefix = chain_prefix(source);
    let own = |input: &str| format!("transforms.{input}").starts_with(&prefix);
    tree.iter()
        .filter(|(id, _)| id.starts_with(&prefix))
        .filter_map(|(id, def)| {
            let outside: Vec<String> = inputs(def).into_iter().filter(|i| !own(i)).collect();
            (!outside.is_empty()).then(|| (id.clone(), outside))
        })
        .collect()
}

fn reads(tree: &BTreeMap<String, toml::Value>, upstream: &str) -> Vec<String> {
    tree.iter()
        .filter(|(_, def)| inputs(def).iter().any(|i| i == upstream))
        .map(|(id, _)| id.clone())
        .collect()
}

#[tokio::test]
async fn staging_changes_no_routing_and_activation_touches_only_router_and_entry() {
    force_for_test(Some(true));
    let tmp = TempDir::new().unwrap();
    let manager = VectorConfigManager::new(tmp.path());
    let base = fleet(8);
    let before = render(&manager, &base).await;

    let mut added = parser("added_source", 50);
    added.activation_parked = true;
    let mut staged = base.clone();
    staged.push(added.clone());
    let slot = assign(&staged).iter().position(|p| p.is_some_and(|p| p.id == added.id)).unwrap();
    let a = render(&manager, &staged).await;

    // pre → A: routing is byte-identical; only the new chain and its slots.
    let diff = changed(&before, &a);
    assert!(!diff.contains("transforms.source_router"), "phase A changed the router");
    let slots = slot_components(slot);
    let stray: Vec<&String> = diff
        .iter()
        .filter(|c| !c.starts_with(&chain_prefix(&added)) && !slots.contains(c))
        .collect();
    assert!(stray.is_empty(), "phase A changed {stray:?}");
    let route = format!("source_router.{}", VectorConfigManager::safe_name(&added.name));
    assert!(reads(&a, &route).is_empty(), "something reads {route} in phase A");
    let entries = chain_entries(&a, &added);
    assert!(!entries.is_empty());
    for (id, outside) in &entries {
        assert_eq!(outside, &vec![PARKED.to_string()], "{id} is not parked");
    }
    // The slots already carry the chain, so B never rebuilds a fan-in.
    assert!(slots.iter().any(|s| inputs(&a[s]).iter().any(|i| i.starts_with("added_source_"))));

    // A → B: the router and the chain's entry only.
    let mut active = staged.clone();
    active.last_mut().unwrap().activation_parked = false;
    let b = render(&manager, &active).await;
    let diff = changed(&a, &b);
    assert!(diff.contains("transforms.source_router"));
    let entry_ids: Vec<&String> = entries.iter().map(|(id, _)| id).collect();
    let stray: Vec<&String> = diff
        .iter()
        .filter(|c| c.as_str() != "transforms.source_router" && !entry_ids.contains(c))
        .collect();
    assert!(stray.is_empty(), "phase B changed {stray:?}");
    assert!(!reads(&b, &route).is_empty(), "nothing reads {route} after activation");

    // B is exactly the one-phase render of the grown set.
    let fresh_dir = TempDir::new().unwrap();
    let fresh = render(&VectorConfigManager::new(fresh_dir.path()), &active).await;
    assert_eq!(b, fresh);

    // Removal: A' unroutes and parks the chain (slots untouched), B' drops it.
    let mut parking = active.clone();
    parking.last_mut().unwrap().activation_parked = true;
    let a2 = render(&manager, &parking).await;
    assert_eq!(a2, a, "parking a live source renders phase A again");
    let b2 = render(&manager, &base).await;
    let diff = changed(&a2, &b2);
    assert!(!diff.contains("transforms.source_router"), "phase B of a removal changed the router");
    assert_eq!(b2, before);
}

#[test]
fn without_slots_a_hold_renders_the_source_live() {
    force_for_test(Some(false));
    let manager = VectorConfigManager::new("/nonexistent");
    let mut p = parser("held", 1);
    p.activation_parked = true;
    let (_, input) = manager.generate_source_config(&p);
    assert_eq!(input, "source_router.held");
    force_for_test(Some(true));
    let (_, input) = manager.generate_source_config(&p);
    assert_eq!(input, PARKED);
    force_for_test(None);
}

#[test]
fn only_router_fed_parsers_park() {
    force_for_test(Some(true));
    let manager = VectorConfigManager::new("/nonexistent");
    let mut hec = parser("hec_one", 1);
    hec.source_type = "splunk_hec".to_string();
    hec.match_values = Some(vec!["x".to_string()]);
    hec.activation_parked = true;
    let (_, input) = manager.generate_source_config(&hec);
    assert_ne!(input, PARKED, "a HEC parser reads its own lane and never parks");
    force_for_test(None);
}
