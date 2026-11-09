// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5136: self-hosted provider id routing and model discovery parsing.

use super::*;
use serde_json::json;

#[test]
fn self_hosted_prefix_is_recognised() {
    assert!(is_self_hosted_model("self-hosted/qwen2.5:0.5b"));
    // vLLM serves HF-style ids with their own slash; only the first segment
    // is the provider.
    assert!(is_self_hosted_model("self-hosted/Qwen/Qwen2.5-7B-Instruct"));
}

#[test]
fn other_prefixes_are_not_self_hosted() {
    assert!(!is_self_hosted_model("openai/gpt-5-nano"));
    assert!(!is_self_hosted_model("workers-ai/@cf/zai-org/glm-5.2"));
    assert!(!is_self_hosted_model("self-hosted/"));
    assert!(!is_self_hosted_model("self-hosted"));
    assert!(!is_self_hosted_model("self-hostedx/qwen"));
}

#[test]
fn discovery_urls_for_each_preset() {
    // Ollama, vLLM, LM Studio all take a /v1 base.
    assert_eq!(openai_models_url("http://ollama:11434/v1"), "http://ollama:11434/v1/models");
    assert_eq!(openai_models_url("http://vllm:8000/v1/"), "http://vllm:8000/v1/models");
    assert_eq!(ollama_tags_url("http://ollama:11434/v1"), "http://ollama:11434/api/tags");
    assert_eq!(ollama_tags_url("http://ollama:11434/v1/"), "http://ollama:11434/api/tags");
    // A base without /v1 keeps its path.
    assert_eq!(ollama_tags_url("http://ollama:11434"), "http://ollama:11434/api/tags");
}

#[test]
fn parses_openai_model_list() {
    // Real Ollama /v1/models body.
    let body = json!({"object":"list","data":[
        {"id":"qwen2.5:0.5b","object":"model","created":1794233381,"owned_by":"library"},
        {"id":"qwen2.5:0.5b"},
        {"id":"  "},
        {"no_id": true},
        {"id":"llama3.2:1b"}
    ]});
    assert_eq!(parse_openai_model_list(&body), vec!["qwen2.5:0.5b", "llama3.2:1b"]);
}

#[test]
fn parses_ollama_tags() {
    let body = json!({"models":[{"name":"qwen2.5:0.5b","model":"qwen2.5:0.5b"},{"name":"bad\nname"}]});
    assert_eq!(parse_ollama_tags(&body), vec!["qwen2.5:0.5b"]);
}

#[test]
fn malformed_bodies_yield_nothing() {
    assert!(parse_openai_model_list(&json!({"data": "nope"})).is_empty());
    assert!(parse_openai_model_list(&json!([])).is_empty());
    assert!(parse_ollama_tags(&serde_json::Value::Null).is_empty());
}

#[test]
fn discovery_is_bounded() {
    let data: Vec<_> = (0..MAX_DISCOVERED_MODELS + 50)
        .map(|i| json!({ "id": format!("m{i}") }))
        .collect();
    assert_eq!(parse_openai_model_list(&json!({ "data": data })).len(), MAX_DISCOVERED_MODELS);
}

/// Self-run AI is BYO: a self-hosted model never costs nano AI credits, on
/// every pricing path (name heuristic, catalog tier, flat full-cost sites).
#[test]
fn self_hosted_models_cost_no_credits() {
    use crate::settings::tier::{
        ai_request_cost, credits_for_cost_tier, full_request_cost, AI_CREDIT_FULL,
        AI_CREDIT_NONE,
    };
    let id = "self-hosted/qwen2.5:0.5b";
    assert_eq!(ai_request_cost(id), AI_CREDIT_NONE);
    assert_eq!(credits_for_cost_tier(Some("frontier"), id), AI_CREDIT_NONE);
    assert_eq!(credits_for_cost_tier(None, id), AI_CREDIT_NONE);
    assert_eq!(full_request_cost(id), AI_CREDIT_NONE);
    // Managed / vendor models are unchanged.
    assert_eq!(full_request_cost("openai/gpt-5"), AI_CREDIT_FULL);
    assert_eq!(credits_for_cost_tier(Some("frontier"), "openai/gpt-5"), AI_CREDIT_FULL);
}
