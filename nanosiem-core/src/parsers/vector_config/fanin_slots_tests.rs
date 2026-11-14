// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5132: stable fan-in slots. Adding or removing a source changes no
//! component except the router, the source's own chain and its slots.

use std::collections::{BTreeMap, BTreeSet};

use super::*;
use tempfile::TempDir;

fn parser(name: &str, nth: i64) -> Parser {
    // Fixed ids and creation times, so two renders agree.
    let mut bytes = [0u8; 16];
    for (i, b) in name.bytes().enumerate() {
        bytes[i % 16] = bytes[i % 16].wrapping_mul(31).wrapping_add(b);
    }
    let at = chrono::DateTime::from_timestamp(1_700_000_000 + nth * 60, 0).unwrap();
    Parser {
        activation_parked: false,
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
        created_at: at,
        updated_at: at,
    }
}

fn fleet(n: usize) -> Vec<Parser> {
    (0..n).map(|i| parser(&format!("source_{i:02}"), i as i64)).collect()
}

#[test]
fn capacity_has_headroom_and_steps_in_powers_of_two() {
    assert_eq!(capacity(0), MIN_SLOTS);
    assert_eq!(capacity(12), 16);
    assert_eq!(capacity(13), 32);
    assert_eq!(capacity(25), 32);
    assert_eq!(capacity(26), 64);
    assert_eq!(capacity(200), 256);
}

#[test]
fn a_new_source_never_moves_an_existing_one() {
    let mut set = fleet(11);
    let before: BTreeMap<uuid::Uuid, usize> = assign(&set)
        .iter()
        .enumerate()
        .filter_map(|(i, p)| p.map(|p| (p.id, i)))
        .collect();
    set.push(parser("newest", 99));
    let after: BTreeMap<uuid::Uuid, usize> = assign(&set)
        .iter()
        .enumerate()
        .filter_map(|(i, p)| p.map(|p| (p.id, i)))
        .collect();
    for (id, slot) in &before {
        assert_eq!(after.get(id), Some(slot), "existing source moved");
    }
    assert_eq!(after.len(), 12);
    // Input order does not matter: the assignment is a function of the set.
    let mut shuffled = set.clone();
    shuffled.reverse();
    let again: Vec<Option<uuid::Uuid>> = assign(&shuffled).iter().map(|p| p.map(|p| p.id)).collect();
    let first: Vec<Option<uuid::Uuid>> = assign(&set).iter().map(|p| p.map(|p| p.id)).collect();
    assert_eq!(again, first);
}

#[test]
fn disabled_and_enrichment_parsers_take_no_slot() {
    let mut set = fleet(3);
    set[1].enabled = false;
    set[2].kind = "enrichment".to_string();
    assert_eq!(assign(&set).iter().filter(|p| p.is_some()).count(), 1);
}

/// Components (transforms and sinks) of every TOML in the active tree.
fn components(manager: &VectorConfigManager) -> BTreeMap<String, toml::Value> {
    let mut out = BTreeMap::new();
    for entry in std::fs::read_dir(manager.parsers_dir()).unwrap().flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(".toml") {
            continue;
        }
        let raw = std::fs::read_to_string(entry.path()).unwrap();
        let raw = without_env(&raw);
        let value: toml::Value = toml::from_str(&raw).unwrap_or_else(|e| panic!("{name}: {e}"));
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

async fn deploy(manager: &VectorConfigManager, parsers: &[Parser]) -> BTreeMap<String, toml::Value> {
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

/// What adding/removing `source` may touch: the router, its own chain, its
/// slots in every family.
fn allowed(source: &Parser, slot: usize) -> impl Fn(&str) -> bool {
    let safe = format!("transforms.{}_", VectorConfigManager::safe_name(&source.name));
    let slots: Vec<String> = [Family::Out, Family::Kept, Family::Ocsf]
        .iter()
        .map(|f| format!("transforms.{}", slot_id(*f, slot)))
        .collect();
    move |component: &str| {
        component == "transforms.source_router"
            || component.starts_with(&safe)
            || slots.iter().any(|s| s == component)
    }
}

#[tokio::test]
async fn adding_or_removing_a_source_rebuilds_no_fanin() {
    // NAN-5346: the persisted family differs by profile (UDM `Kept`, OCSF
    // `Ocsf`); both must keep the fan-ins constant.
    for (schema, family) in [
        (crate::schema::SchemaId::Udm, Family::Kept),
        (crate::schema::SchemaId::Ocsf, Family::Ocsf),
    ] {
        let _pin = crate::schema::pin_active_schema_for_test(schema);
        adding_or_removing_one_source_rebuilds_no_fanin(family).await;
    }
}

async fn adding_or_removing_one_source_rebuilds_no_fanin(family: Family) {
    super::force_for_test(Some(true));
    let tmp = TempDir::new().unwrap();
    let manager = VectorConfigManager::new(tmp.path());
    let base = fleet(8);
    let before = deploy(&manager, &base).await;

    let mut grown = base.clone();
    let added = parser("added_source", 50);
    grown.push(added.clone());
    let slot = assign(&grown).iter().position(|p| p.is_some_and(|p| p.id == added.id)).unwrap();
    let after = deploy(&manager, &grown).await;

    let diff = changed(&before, &after);
    let ok = allowed(&added, slot);
    let stray: Vec<&String> = diff.iter().filter(|c| !ok(c)).collect();
    assert!(stray.is_empty(), "adding one source changed {stray:?}");
    for fanin in ["transforms.db_parsers_combined", "transforms.db_parser_health"] {
        assert!(!diff.contains(fanin), "{fanin} was rebuilt");
        assert!(after.contains_key(fanin));
    }
    assert!(diff.contains("transforms.source_router"));
    assert!(diff.contains(&format!("transforms.{}", slot_id(family, slot))));

    // Removing it again is just as narrow, and restores the previous tree.
    let restored = deploy(&manager, &base).await;
    let stray: Vec<String> = changed(&after, &restored).into_iter().filter(|c| !ok(c)).collect();
    assert!(stray.is_empty(), "removing one source changed {stray:?}");
    assert_eq!(restored, before);
}

#[test]
fn ocsf_fanins_and_the_disk_buffered_sink_are_constant_across_an_add() {
    super::force_for_test(Some(true));
    let base = fleet(8);
    let mut grown = base.clone();
    grown.push(parser("added_source", 50));

    let sink = |set: &[Parser]| {
        VectorConfigManager::ocsf_sink_content(&VectorConfigManager::ocsf_sink_inputs_for(true, set))
    };
    assert_eq!(sink(&base), sink(&grown), "clickhouse_ocsf_logs would be rebuilt");

    let fanins = |set: &[Parser]| -> BTreeMap<String, toml::Value> {
        let doc: toml::Value =
            toml::from_str(&VectorConfigManager::combiner_config_content_for(set, true)).unwrap();
        let t = doc.get("transforms").unwrap().as_table().unwrap();
        ["db_parsers_combined", "db_parser_health"]
            .iter()
            .map(|n| (n.to_string(), t[*n].clone()))
            .collect()
    };
    assert_eq!(fanins(&base), fanins(&grown));
}

#[test]
fn resolved_inputs_reach_every_parser_through_its_slots() {
    super::force_for_test(Some(true));
    let mut set = fleet(3);
    set[0].sampling_ratio = Some(0.5);
    let combiner = VectorConfigManager::combiner_config_content_for(&set, true);
    let sink = VectorConfigManager::ocsf_sink_content(&VectorConfigManager::ocsf_sink_inputs_for(true, &set));

    // NAN-5346: under OCSF the persisted UDM stream reads only the parked
    // (never-matching) filter, and health reads the OCSF lane.
    assert_eq!(resolved_inputs(&[&combiner], "db_parsers_combined"), vec!["prepare_output"]);
    let udm = VectorConfigManager::combiner_config_content_for(&set, false);
    let mut kept = resolved_inputs(&[&udm], "db_parsers_combined");
    kept.sort();
    assert_eq!(kept, vec!["source_00_sample", "source_01_output", "source_02_output"]);

    let mut health = resolved_inputs(&[&udm], "db_parser_health");
    health.sort();
    assert_eq!(health, vec!["source_00_output", "source_01_output", "source_02_output"]);
    let mut health = resolved_inputs(&[&combiner], "db_parser_health");
    health.sort();
    assert_eq!(
        health,
        vec!["source_00_ocsf_prepare", "source_01_ocsf_prepare", "source_02_ocsf_prepare"]
    );

    let mut ocsf = resolved_inputs(&[&combiner, &sink], "clickhouse_ocsf_logs");
    ocsf.sort();
    assert_eq!(
        ocsf,
        vec!["generic_ocsf_prepare", "source_00_ocsf_prepare", "source_01_ocsf_prepare", "source_02_ocsf_prepare"]
    );
}

#[test]
fn zero_sources_render_the_same_fanins_with_every_slot_parked() {
    super::force_for_test(Some(true));
    let combiner = VectorConfigManager::combiner_config_content_for(&[], false);
    assert!(resolved_inputs(&[&combiner], "db_parsers_combined").is_empty());
    assert!(combiner.contains(&format!("[transforms.{PARKED}]")));
    assert_eq!(combiner.matches("condition = \"true\"").count(), 2 * MIN_SLOTS);
}

/// `VECTOR_FANIN_SLOTS=off`: no slot filters, and every fan-in reaches the
/// same parser components it reaches through the slots.
#[test]
fn slots_off_wires_the_same_components_directly() {
    super::force_for_test(None);
    let mut set = fleet(5);
    set[2].sampling_ratio = Some(0.5);
    for ocsf in [false, true] {
        let on = VectorConfigManager::combiner_config_content_with(&set, ocsf, true);
        let off = VectorConfigManager::combiner_config_content_with(&set, ocsf, false);
        // No slot filters; only the parked filter (OCSF's persisted input,
        // NAN-5346) may exist.
        assert!(!off.replace(PARKED, "").contains("nano-slot-"), "{off}");
        for fanin in ["db_parsers_combined", "db_parser_health"] {
            let mut a = resolved_inputs(&[&on], fanin);
            let mut b = resolved_inputs(&[&off], fanin);
            a.sort();
            b.sort();
            assert_eq!(a, b, "{fanin} (ocsf={ocsf})");
        }
    }
    let on = VectorConfigManager::ocsf_sink_inputs_with(true, true, &set);
    let off = VectorConfigManager::ocsf_sink_inputs_with(true, false, &set);
    let combiner = VectorConfigManager::combiner_config_content_with(&set, true, true);
    let sink_on = VectorConfigManager::ocsf_sink_content(&on);
    let sink_off = VectorConfigManager::ocsf_sink_content(&off);
    let mut a = resolved_inputs(&[&combiner, &sink_on], "clickhouse_ocsf_logs");
    let mut b = resolved_inputs(&[&sink_off], "clickhouse_ocsf_logs");
    a.sort();
    b.sort();
    assert_eq!(a, b);

    // Zero sources, slots off: the fan-ins still have a valid input.
    let empty = VectorConfigManager::combiner_config_content_with(&[], true, false);
    assert!(empty.contains(&format!("[transforms.{PARKED}]")), "{empty}");
    // The parked filter reads `prepare_output` and never passes an event.
    assert_eq!(
        resolved_inputs(&[&empty], "db_parsers_combined"),
        vec!["prepare_output".to_string()]
    );
}

#[test]
fn slots_are_opt_in() {
    super::force_for_test(None);
    // Off unless VECTOR_FANIN_SLOTS says on (the test env does not set it).
    if std::env::var("VECTOR_FANIN_SLOTS").is_err() {
        assert!(!super::enabled());
    }
    super::force_for_test(Some(true));
    assert!(super::enabled());
    super::force_for_test(None);
}
