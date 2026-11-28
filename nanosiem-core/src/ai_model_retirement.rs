// SPDX-License-Identifier: AGPL-3.0-or-later

//! AI models their provider has retired (NAN-5952).
//!
//! A retired model no longer answers: the provider returns HTTP 410 (or a
//! 404 that says the model is retired). The model catalog (`nano-rs/models`)
//! drops such models and the daily sync marks them deprecated, but an agent
//! an admin pinned to one by hand (`source = 'custom'`) is never changed by
//! sync, and a binary can ship before the catalog syncs. This list is the
//! code-side backstop: SIEM Health names agents still on one of these, and
//! the AI client's "model retired" error suggests the replacement.
//!
//! Each entry is `(retired catalog id, replacement catalog id)`. Ids use the
//! catalog's `provider/model` form and are compared case-insensitively.

/// Retired models and the replacement the provider recommends.
pub const RETIRED_MODELS: &[(&str, &str)] = &[
    // Cloudflare retired GLM-5.3 Flash on 2026-11-20 (HTTP 410, error 5028)
    // and recommends DeepSeek V4.1 Flash for the same fast tier.
    (
        "workers-ai/@cf/zai-org/glm-5.3-flash",
        "workers-ai/@cf/deepseek-ai/deepseek-v4.1-flash-1017",
    ),
];

/// The reasoning effort a replacement runs at when nano moves an agent onto
/// it and nothing else set one. DeepSeek V4.1 Flash reasons at `high` by
/// default, too slow for the fast tier; the catalog sets `low` for it.
pub fn replacement_default_effort(replacement: &str) -> Option<&'static str> {
    match replacement.trim().to_ascii_lowercase().as_str() {
        "workers-ai/@cf/deepseek-ai/deepseek-v4.1-flash-1017" => Some("low"),
        _ => None,
    }
}

/// Catalog ids nano moved agents onto in place of a retired model. A stale
/// catalog that does not list them yet must not deprecate them.
pub fn replacement_model_ids() -> Vec<String> {
    RETIRED_MODELS.iter().map(|(_, r)| r.to_string()).collect()
}

/// The retired catalog ids, lowercase.
pub fn retired_model_ids() -> Vec<String> {
    RETIRED_MODELS.iter().map(|(id, _)| id.to_ascii_lowercase()).collect()
}

/// The replacement for `model_id` when it is a known retired model.
/// Accepts the catalog id with or without its `workers-ai/` style prefix.
pub fn retired_replacement(model_id: &str) -> Option<&'static str> {
    let id = model_id.trim().to_ascii_lowercase();
    RETIRED_MODELS.iter().find_map(|(retired, replacement)| {
        let bare = retired.split_once('/').map(|(_, rest)| rest).unwrap_or(retired);
        (id == *retired || id == bare).then_some(*replacement)
    })
}

/// True when `model_id` is a known retired model.
pub fn is_retired_model(model_id: &str) -> bool {
    retired_replacement(model_id).is_some()
}

/// True when a provider's error response says the model itself is gone:
/// HTTP 410 always; a 404 only when its message says the model was retired,
/// deprecated or decommissioned (OpenAI and others answer a retired model
/// with 404). A 400 never counts: "deprecated" there usually names a
/// request parameter, not the model.
pub fn is_model_retired_response(status: u16, message: &str) -> bool {
    match status {
        410 => true,
        404 => {
            let m = message.to_ascii_lowercase();
            m.contains("model")
                && ["retired", "deprecated", "decommissioned", "no longer available", "no longer supported"]
                    .iter()
                    .any(|w| m.contains(w))
        }
        _ => false,
    }
}

/// The plain-English message an admin sees when an agent's model is retired.
pub fn retired_model_message(model_id: &str) -> String {
    let hint = match retired_replacement(model_id) {
        Some(r) => format!(" The provider recommends {r}."),
        None => String::new(),
    };
    format!(
        "The AI model {model_id} has been retired by its provider and no longer answers requests. \
         An admin needs to pick another model for this agent in Settings > AI > Agent Models.{hint}"
    )
}

/// The model id inside a [`retired_model_message`], wherever it was wrapped
/// in other text. Lets an error that was turned into a string on the way up
/// (several agent error types keep only the message) still be reported as a
/// retired model.
pub fn model_from_retired_message(message: &str) -> Option<&str> {
    const HEAD: &str = "The AI model ";
    const TAIL: &str = " has been retired by its provider";
    let start = message.find(HEAD)? + HEAD.len();
    let len = message[start..].find(TAIL)?;
    let model = &message[start..start + len];
    (!model.is_empty() && !model.contains(char::is_whitespace)).then_some(model)
}

#[cfg(test)]
#[path = "ai_model_retirement_tests.rs"]
mod tests;
