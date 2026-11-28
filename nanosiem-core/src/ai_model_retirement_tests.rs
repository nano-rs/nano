// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;

const FLASH: &str = "workers-ai/@cf/zai-org/glm-5.3-flash";
const DEEPSEEK: &str = "workers-ai/@cf/deepseek-ai/deepseek-v4.1-flash-1017";

#[test]
fn glm_5_3_flash_is_retired_and_points_at_deepseek() {
    assert_eq!(retired_replacement(FLASH), Some(DEEPSEEK));
    assert_eq!(retired_replacement("@cf/zai-org/glm-5.3-flash"), Some(DEEPSEEK), "bare id");
    assert_eq!(retired_replacement(" WORKERS-AI/@CF/ZAI-ORG/GLM-5.3-FLASH "), Some(DEEPSEEK));
}

#[test]
fn live_models_are_not_retired() {
    for id in [
        "workers-ai/@cf/zai-org/glm-5.3",
        DEEPSEEK,
        "workers-ai/@cf/zai-org/glm-5.3-flash-v2",
        "anthropic/claude-sonnet-5-5",
    ] {
        assert!(!is_retired_model(id), "{id}");
    }
}

#[test]
fn no_replacement_is_itself_retired() {
    for (_, replacement) in RETIRED_MODELS {
        assert!(!is_retired_model(replacement), "{replacement}");
    }
}

#[test]
fn retired_responses_are_410_or_a_404_that_says_so() {
    assert!(is_model_retired_response(410, ""));
    assert!(is_model_retired_response(410, "anything"));
    assert!(is_model_retired_response(404, "The model `gpt-4-0314` has been deprecated"));
    assert!(is_model_retired_response(404, "Model was retired on 2026-11-20"));
    assert!(!is_model_retired_response(404, "model not found"));
    assert!(!is_model_retired_response(400, "temperature is deprecated for this model"));
    assert!(!is_model_retired_response(500, "model retired"));
}

#[test]
fn message_names_the_model_and_the_fix() {
    let m = retired_model_message(FLASH);
    assert!(m.contains(FLASH));
    assert!(m.contains("Settings > AI > Agent Models"));
    assert!(m.contains(DEEPSEEK));
    let other = retired_model_message("openai/gpt-4-0314");
    assert!(other.contains("openai/gpt-4-0314") && !other.contains("recommends"));
}

#[test]
fn deepseek_replacement_runs_at_low_effort() {
    assert_eq!(replacement_default_effort(DEEPSEEK), Some("low"));
    assert_eq!(replacement_default_effort("workers-ai/@cf/zai-org/glm-5.3"), None);
    assert_eq!(replacement_model_ids(), vec![DEEPSEEK.to_string()]);
    assert_eq!(retired_model_ids(), vec![FLASH.to_string()]);
}

#[test]
fn the_model_is_recovered_from_a_wrapped_message() {
    let wrapped = format!("Summarize failed: AI provider error: {}", retired_model_message(FLASH));
    assert_eq!(model_from_retired_message(&wrapped), Some(FLASH));
    assert_eq!(model_from_retired_message("Summarize failed: timeout"), None);
    assert_eq!(model_from_retired_message("The AI model  has been retired by its provider"), None);
}
