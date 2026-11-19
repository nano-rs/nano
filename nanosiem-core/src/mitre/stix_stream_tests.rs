// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5668: the streaming, filtering STIX decode.

use super::*;

const MIXED: &str = r#"{
    "spec_version": "2.1",
    "type": "bundle",
    "objects": [
        {"type": "x-mitre-tactic", "id": "x-mitre-tactic--1", "name": "Execution",
         "x_mitre_shortname": "execution",
         "description": "First paragraph.\n\nSecond paragraph that is never stored.",
         "external_references": [
            {"source_name": "mitre-attack", "external_id": "TA0002", "url": "https://attack.mitre.org/tactics/TA0002/"},
            {"source_name": "Citation", "description": "long citation"}
         ]},
        {"type": "attack-pattern", "id": "attack-pattern--1", "name": "Cmd",
         "external_references": [
            {"source_name": "Citation", "description": "listed first"},
            {"source_name": "mitre-attack", "external_id": "T1059"},
            {"source_name": "mitre-attack", "external_id": "T9999"}
         ]},
        {"type": "x-mitre-data-component", "id": "dc--1", "name": "Process Creation", "description": "prose"},
        {"type": "x-mitre-analytic", "id": "an--1", "description": "prose",
         "x_mitre_log_source_references": [{"x_mitre_data_component_ref": "dc--1"}]},
        {"type": "x-mitre-detection-strategy", "id": "det--1", "description": "prose", "x_mitre_analytic_refs": ["an--1"]},
        {"type": "relationship", "id": "rel--detects", "relationship_type": "detects",
         "source_ref": "det--1", "target_ref": "attack-pattern--1", "description": "prose"},
        {"type": "relationship", "id": "rel--revoked", "relationship_type": "revoked-by",
         "source_ref": "attack-pattern--old", "target_ref": "attack-pattern--1"},
        {"type": "relationship", "id": "rel--uses", "relationship_type": "uses",
         "source_ref": "intrusion-set--1", "target_ref": "attack-pattern--1", "description": "prose"},
        {"type": "intrusion-set", "id": "intrusion-set--1", "name": "Group", "description": "prose"},
        {"type": "malware", "id": "malware--1", "name": "Tool", "x_mitre_aliases": ["a", "b"]},
        {"type": "x-mitre-collection", "id": "x-mitre-collection--1", "x_mitre_contents": [{"object_ref": "x"}]}
    ],
    "id": "bundle--mixed"
}"#;

#[test]
fn keeps_only_catalog_objects_and_counts_every_object() {
    let filtered = decode_filtered_bundle(MIXED.as_bytes()).expect("decodes");
    assert_eq!(filtered.bundle.bundle_type, "bundle");
    // `id` after `objects` and unknown top-level keys are fine.
    assert_eq!(filtered.bundle.id, "bundle--mixed");
    assert_eq!(filtered.object_count, 11);
    let kept: Vec<&str> = filtered.bundle.objects.iter().map(|o| o.id.as_str()).collect();
    assert_eq!(
        kept,
        ["x-mitre-tactic--1", "attack-pattern--1", "dc--1", "an--1", "det--1", "rel--detects", "rel--revoked"]
    );
}

#[test]
fn trims_prose_but_keeps_what_the_catalog_reads() {
    let filtered = decode_filtered_bundle(MIXED.as_bytes()).expect("decodes");
    let by_id = |id: &str| filtered.bundle.objects.iter().find(|o| o.id == id).unwrap();

    let tactic = by_id("x-mitre-tactic--1");
    assert_eq!(tactic.description.as_deref(), Some("First paragraph."));
    let refs = tactic.external_references.as_deref().unwrap();
    assert_eq!(refs.len(), 1);
    assert_eq!(refs[0].external_id.as_deref(), Some("TA0002"));
    assert_eq!(refs[0].url.as_deref(), Some("https://attack.mitre.org/tactics/TA0002/"));

    // The FIRST mitre-attack reference wins, as `mitre_external_id` reads it.
    let technique = by_id("attack-pattern--1");
    let refs = technique.external_references.as_deref().unwrap();
    assert_eq!(refs.len(), 1);
    assert_eq!(refs[0].external_id.as_deref(), Some("T1059"));

    for id in ["dc--1", "an--1", "det--1", "rel--detects"] {
        assert!(by_id(id).description.is_none(), "{id} prose must be dropped");
    }
    assert_eq!(by_id("dc--1").name.as_deref(), Some("Process Creation"));
    assert_eq!(by_id("det--1").x_mitre_analytic_refs.as_deref(), Some(&["an--1".to_string()][..]));
    assert_eq!(
        by_id("an--1").x_mitre_log_source_references.as_deref().unwrap()[0]
            .x_mitre_data_component_ref
            .as_deref(),
        Some("dc--1")
    );
    assert_eq!(by_id("rel--revoked").target_ref.as_deref(), Some("attack-pattern--1"));
}

#[test]
fn truncation_is_idempotent_so_pre_cutting_stores_the_same_text() {
    for description in [
        "short".to_string(),
        "para one\n\npara two".to_string(),
        "é".repeat(600),
        format!("{}\n\nrest", "x".repeat(800)),
    ] {
        let once = truncate_description(&description);
        assert_eq!(truncate_description(&once), once, "{description:?}");
    }
}

#[test]
fn rejects_malformed_bundles() {
    // Missing objects / identity.
    assert!(decode_filtered_bundle(br#"{"type":"bundle","id":"bundle--x"}"#).is_err());
    assert!(decode_filtered_bundle(br#"{"type":"bundle","objects":[]}"#).is_err());
    // Duplicate keys would let a second `objects` replace the first.
    assert!(decode_filtered_bundle(br#"{"type":"bundle","id":"b","objects":[],"objects":[]}"#).is_err());
    // Trailing bytes, as `from_slice` rejects them.
    assert!(decode_filtered_bundle(br#"{"type":"bundle","id":"b","objects":[]} x"#).is_err());
    // A malformed object fails the whole decode, retained type or not.
    assert!(decode_filtered_bundle(br#"{"type":"bundle","id":"b","objects":[{"id":"no-type"}]}"#).is_err());
    assert!(decode_filtered_bundle(br#"{"type":"bundle","id":"b","objects":[{"type":"malware","id":7}]}"#).is_err());
}
