// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5225: an AI provider update that changes the endpoint may not keep
//! sending the stored API key to the new destination.

use super::*;
use serde_json::json;

fn check(
    stored: serde_json::Value,
    new: Option<serde_json::Value>,
    has_key: bool,
    key_supplied: bool,
) -> Result<(), &'static str> {
    ensure_api_key_follows_destination(Some(&stored), new.as_ref(), has_key, key_supplied)
}

#[test]
fn base_url_host_change_with_stored_key_requires_key() {
    let stored = json!({"base_url": "https://llm.corp.example/v1"});
    let new = json!({"base_url": "https://llm.other.example/v1"});
    assert_eq!(
        check(stored.clone(), Some(new.clone()), true, false),
        Err(AI_KEY_DESTINATION_CHANGED)
    );
    assert!(check(stored, Some(new), true, true).is_ok(), "new key or blank clear passes");
}

#[test]
fn adding_base_url_over_vendor_default_is_a_destination_change() {
    let stored = json!({"model": "m"});
    let new = json!({"model": "m", "base_url": "https://llm.other.example/v1"});
    assert!(check(stored, Some(new), true, false).is_err());
}

#[test]
fn removing_base_url_is_a_destination_change() {
    let stored = json!({"base_url": "https://llm.corp.example/v1"});
    assert!(check(stored, Some(json!({})), true, false).is_err());
}

#[test]
fn api_base_is_compared_too() {
    let stored = json!({"api_base": "https://a.openai.azure.com"});
    let new = json!({"api_base": "https://b.openai.azure.com"});
    assert!(check(stored, Some(new), true, false).is_err());
}

#[test]
fn same_origin_and_non_url_edits_keep_the_key() {
    let stored = json!({"base_url": "https://llm.corp.example/v1", "model": "a"});
    let path_only = json!({"base_url": "https://LLM.corp.example/v2/", "model": "b"});
    assert!(check(stored.clone(), Some(path_only), true, false).is_ok());
    assert!(check(stored, None, true, false).is_ok(), "config omitted = unchanged");
    assert!(check(json!({"region": "us-east-1"}), Some(json!({"region": "eu-west-1"})), true, false).is_ok());
}

#[test]
fn no_stored_key_is_unconstrained() {
    let stored = json!({"base_url": "http://ollama.lan:11434/v1"});
    let new = json!({"base_url": "http://ollama2.lan:11434/v1"});
    assert!(check(stored, Some(new), false, false).is_ok());
}

#[test]
fn missing_stored_config_treated_as_vendor_default() {
    let new = json!({"base_url": "https://llm.other.example/v1"});
    assert!(ensure_api_key_follows_destination(None, Some(&new), true, false).is_err());
    assert!(ensure_api_key_follows_destination(None, Some(&json!({})), true, false).is_ok());
}
