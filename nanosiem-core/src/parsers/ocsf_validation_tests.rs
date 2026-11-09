// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unit tests for the offline OCSF event validator.

use super::*;

fn base_http() -> Value {
    serde_json::json!({
        "activity_id": 3,
        "category_uid": 4,
        "class_uid": 4002,
        "type_uid": 400203,
        "severity_id": 1,
        "time": 1786406400000_i64,
        "metadata": {
            "product": {"name": "nano", "vendor_name": "nano"},
            "version": "1.9.0"
        },
        "http_request": {
            "http_method": "GET",
            "url": {"path": "/"}
        }
    })
}

#[test]
fn accepts_valid_ocsf_1_9_event() {
    let result = validate_ocsf_event(&base_http());
    assert!(result.valid, "{:?}", result.errors);
}

#[test]
fn dns_activity_requires_an_endpoint_and_accepts_the_observing_host() {
    let mut event = serde_json::json!({
        "activity_id": 1,
        "category_uid": 4,
        "class_uid": 4003,
        "type_uid": 400301,
        "severity_id": 1,
        "time": 1786406400000_i64,
        "metadata": {
            "product": {"name": "Sysmon", "vendor_name": "Microsoft"},
            "version": "1.9.0"
        },
        "query": {"hostname": "example.com"}
    });

    let missing_endpoint = validate_ocsf_event(&event);
    assert!(missing_endpoint.errors.iter().any(|error| {
        error.code == "constraint_failed"
            && error.message == "at least one of [dst_endpoint, src_endpoint] is required"
    }));

    event["src_endpoint"] = serde_json::json!({"hostname": "host.example"});
    let with_observer = validate_ocsf_event(&event);
    assert!(with_observer.valid, "{:?}", with_observer.errors);
}

#[test]
fn undotted_all_null_at_least_one_is_unchanged() {
    // Explicit nulls satisfied undotted constraints before NAN-4392
    // (`contains_key`) and still do: live parsers emit these.
    let event = serde_json::json!({
        "activity_id": 1,
        "category_uid": 4,
        "class_uid": 4003,
        "type_uid": 400301,
        "severity_id": 1,
        "time": 1786406400000_i64,
        "metadata": {
            "product": {"name": "Sysmon", "vendor_name": "Microsoft"},
            "version": "1.9.0"
        },
        "query": {"hostname": "example.com"},
        "dst_endpoint": null,
        "src_endpoint": null
    });
    let result = validate_ocsf_event(&event);
    assert!(result.valid, "{:?}", result.errors);
}

#[test]
fn rejects_unknown_field_and_wrong_type_with_paths() {
    let mut event = base_http();
    event["http_response"] = serde_json::json!({"code": "200"});
    event["made_up"] = Value::Bool(true);

    let result = validate_ocsf_event(&event);
    assert!(!result.valid);
    assert!(result.errors.iter().any(|error| {
        error.code == "attribute_wrong_type" && error.attribute_path == "http_response.code"
    }));
    assert!(result.errors.iter().any(|error| {
        error.code == "attribute_unknown" && error.attribute_path == "made_up"
    }));
}

#[test]
fn profile_fields_require_declared_profile() {
    let mut event = base_http();
    event["action_id"] = Value::from(2);

    let without_profile = validate_ocsf_event(&event);
    assert!(without_profile.errors.iter().any(|error| {
        error.code == "attribute_unknown" && error.attribute_path == "action_id"
    }));

    event["metadata"]["profiles"] = serde_json::json!(["security_control"]);
    event["action"] = Value::from("Denied");
    let with_profile = validate_ocsf_event(&event);
    assert!(with_profile.valid, "{:?}", with_profile.errors);
}

#[test]
fn catches_required_nested_attributes_and_type_uid() {
    let mut event = base_http();
    event["type_uid"] = Value::from(400201);
    event["metadata"].as_object_mut().unwrap().remove("product");

    let result = validate_ocsf_event(&event);
    assert!(result.errors.iter().any(|error| {
        error.code == "attribute_required_missing" && error.attribute_path == "metadata.product"
    }));
    assert!(result.errors.iter().any(|error| {
        error.code == "type_uid_incorrect" && error.attribute_path == "type_uid"
    }));
}

#[test]
fn generic_unmapped_object_accepts_source_native_keys() {
    let mut event = base_http();
    event["unmapped"] = serde_json::json!({
        "cache_status": "expired",
        "tls_intercepted": true,
        "vendor": {"nested": [1, "two", false]}
    });

    let result = validate_ocsf_event(&event);
    assert!(result.valid, "{:?}", result.errors);
}

/// The exact Patch State event an open-core user reported (NAN-4392).
fn patch_state_repro() -> Value {
    serde_json::json!({
        "class_uid": 5004,
        "category_uid": 5,
        "activity_id": 1,
        "type_uid": 500401,
        "severity_id": 1,
        "time": 1792689305000_i64,
        "metadata": {
            "version": "1.9.0",
            "product": {"name": "Example", "vendor_name": "Example"}
        },
        "device": {
            "type_id": 1,
            "hostname": "host-1",
            "os": {"name": "Ubuntu", "type_id": 200, "version": "24.04.3"}
        },
        "raw_data": "example"
    })
}

const PATCH_STATE_CONSTRAINT: &str =
    "at least one of [device.os.sp_name, device.os.sp_ver, device.os.version] is required";

#[test]
fn dotted_at_least_one_resolves_nested_attribute() {
    let result = validate_ocsf_event(&patch_state_repro());
    assert!(result.valid, "{:?}", result.errors);
}

#[test]
fn dotted_at_least_one_fails_when_every_nested_member_is_absent() {
    let mut event = patch_state_repro();
    event["device"]["os"]
        .as_object_mut()
        .unwrap()
        .remove("version");
    let missing = validate_ocsf_event(&event);
    assert!(!missing.valid);
    assert!(missing.errors.iter().any(|error| {
        error.code == "constraint_failed"
            && error.attribute_path.is_empty()
            && error.message == PATCH_STATE_CONSTRAINT
    }));

    // A null leaf is present, the `contains_key` rule constraints have
    // always used for undotted names.
    event["device"]["os"]["version"] = Value::Null;
    let null_leaf = validate_ocsf_event(&event);
    assert!(null_leaf.valid, "{:?}", null_leaf.errors);

    // A null intermediate object has nothing to descend into.
    event["device"]["os"] = Value::Null;
    let null_parent = validate_ocsf_event(&event);
    assert!(null_parent
        .errors
        .iter()
        .any(|error| error.message == PATCH_STATE_CONSTRAINT));

    // Any one member satisfies the constraint.
    event["device"]["os"] = serde_json::json!({"name": "Ubuntu", "type_id": 200, "sp_ver": 3});
    let sp_ver = validate_ocsf_event(&event);
    assert!(sp_ver.valid, "{:?}", sp_ver.errors);
}

/// NAN-4885: the class card carries what the draft got wrong on the
/// NanoVPN feed, straight from the embedded contract.
#[test]
fn class_grounding_states_requirements_types_profiles_and_actor_placement() {
    let auth = ocsf_class_grounding(3002).unwrap();
    assert!(auth.starts_with("Authentication (class_uid 3002, category_uid 3)"), "{auth}");
    assert!(auth.contains("activity_id int {0,1,2,3,4,5,6,7,99}"), "{auth}");
    assert!(auth.contains("user object<user>"), "{auth}");
    assert!(auth.contains("severity_id int"), "{auth}");
    assert!(auth.contains("at least one of: service, dst_endpoint"), "{auth}");
    assert!(auth.contains("booleans (JSON true/false"), "{auth}");
    assert!(auth.contains("is_mfa"), "{auth}");
    assert!(auth.contains("host: device"), "{auth}");
    assert!(auth.contains("metadata requires product object<product>, version string"), "{auth}");
    assert!(auth.contains("user at least one of: account, name, uid"), "{auth}");

    let network = ocsf_class_grounding(4001).unwrap();
    assert!(network.starts_with("Network Activity (class_uid 4001, category_uid 4)"), "{network}");
    assert!(network.contains("at least one of: dst_endpoint, src_endpoint"), "{network}");
    assert!(
        network.contains("no top-level user/session: use actor.user, actor.session (actor needs profile host)"),
        "{network}"
    );
    assert!(network.contains("network_connection_info requires direction_id int {0,1,2,3,4,99}"), "{network}");
    assert!(network.contains("connection_info<network_connection_info>"), "{network}");

    let http = ocsf_class_grounding(4002).unwrap();
    assert!(http.contains("activity_id int {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,99}"), "{http}");

    let base = ocsf_class_grounding(0).unwrap();
    assert!(base.contains("activity_id int {0,99}"), "{base}");
    assert_eq!(ocsf_class_name(4001).as_deref(), Some("Network Activity"));
    assert!(ocsf_class_grounding(123_456).is_none());
    // Compact: a card is a few hundred tokens, not the recursive schema.
    assert!(network.len() < 4_000, "{} chars:\n{network}", network.len());
}

#[test]
fn dotted_just_one_counts_nested_attributes() {
    let item: SchemaItem = serde_json::from_value(serde_json::json!({
        "attributes": {},
        "constraints": {"just_one": ["device.os.version", "device.hostname", "user"]}
    }))
    .unwrap();
    let check = |event: Value| {
        let mut errors = Vec::new();
        validate_constraints(event.as_object().unwrap(), &item, "", &mut errors);
        errors
    };

    assert!(check(serde_json::json!({"device": {"os": {"version": "1"}}})).is_empty());
    assert!(check(serde_json::json!({"user": {"name": "a"}})).is_empty());
    // An array on the path counts when any element carries the rest.
    assert!(check(serde_json::json!({"device": [{"os": {}}, {"hostname": "h"}]})).is_empty());

    // A null leaf is present; a null parent is not.
    assert!(check(serde_json::json!({"device": {"os": {"version": null}}})).is_empty());
    let none = check(serde_json::json!({"device": {"os": null}}));
    assert_eq!(none.len(), 1);
    assert!(none[0].message.ends_with("found 0"), "{:?}", none);

    let two = check(serde_json::json!({"device": {"hostname": "h", "os": {"version": "1"}}}));
    assert_eq!(two.len(), 1);
    assert!(two[0].message.ends_with("found 2"), "{:?}", two);

    // A scalar where an object is expected does not satisfy a deeper path.
    let scalar = check(serde_json::json!({"device": "h"}));
    assert!(scalar[0].message.ends_with("found 0"), "{:?}", scalar);
}

#[test]
fn validator_reads_the_registry_contracts() {
    // One embedded copy: the validator decodes exactly the files the
    // version-agnostic registry embeds, and binds to the newest one.
    let versions = crate::schema::ocsf_registry::versions();
    assert_eq!(ocsf_validation_version(), *versions.last().unwrap());
    assert_eq!(runtime_contracts().len(), versions.len());
    for (version, runtime) in runtime_contracts() {
        let runtime = runtime.as_ref().expect("embedded contract decodes");
        assert_eq!(runtime.contract.version, *version);
    }
}

#[test]
fn validator_and_registry_agree_on_event_classes() {
    let runtime = runtime_contract().expect("contract");
    for (uid, name) in &runtime.class_by_uid {
        assert_eq!(
            crate::schema::ocsf_registry::class_name(*uid),
            Some(name.as_str()),
            "class_uid {uid}"
        );
    }
    assert_eq!(ocsf_class_name(3002).as_deref(), Some("Authentication"));
}

#[test]
fn absent_version_is_checked_against_the_newest_contract() {
    let mut event = base_http();
    event["metadata"].as_object_mut().unwrap().remove("version");
    let result = validate_ocsf_event(&event);
    assert_eq!(result.schema_version, ocsf_validation_version());
    // metadata.version is required by the spec, so its absence is the only error.
    let paths: Vec<_> = result.errors.iter().map(|e| e.attribute_path.as_str()).collect();
    assert_eq!(paths, vec!["metadata.version"], "{:?}", result.errors);
}

#[test]
fn unembedded_version_is_reported_as_incompatible() {
    let mut event = base_http();
    event["metadata"]["version"] = serde_json::json!("1.8.0");
    let result = validate_ocsf_event(&event);
    assert!(!result.valid);
    let incompatible = result
        .errors
        .iter()
        .find(|e| e.code == "version_incompatible")
        .expect("version_incompatible");
    assert_eq!(incompatible.attribute_path, "metadata.version");
    assert!(incompatible.message.contains("1.8.0"), "{}", incompatible.message);
    assert!(
        incompatible.message.contains(ocsf_validation_version()),
        "{}",
        incompatible.message
    );
}

#[test]
fn every_embedded_data_type_regex_compiles() {
    // A regex that failed to compile would silently skip its check.
    for (version, runtime) in runtime_contracts() {
        let runtime = runtime.as_ref().unwrap();
        for (name, data_type) in &runtime.contract.types {
            if data_type.regex.is_some() {
                assert!(runtime.regexes.contains_key(name), "{version} {name}");
            }
        }
    }
}

#[test]
fn recursive_objects_are_bounded() {
    let mut process = serde_json::json!({"name": "leaf", "pid": 1});
    for _ in 0..200 {
        process = serde_json::json!({"name": "p", "pid": 1, "parent_process": process});
    }
    let event = serde_json::json!({
        "activity_id": 1, "category_uid": 1, "class_uid": 1007, "type_uid": 100701,
        "severity_id": 1, "time": 1786406400000_i64,
        "metadata": {"product": {"name": "nano"}, "version": "1.9.0"},
        "process": process,
    });
    let result = validate_ocsf_event(&event);
    assert!(result
        .errors
        .iter()
        .any(|e| e.code == "attribute_nesting_too_deep"));
}
