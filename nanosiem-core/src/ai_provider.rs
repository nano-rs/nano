// SPDX-License-Identifier: AGPL-3.0-or-later

//! Direct (non-gateway) AI provider endpoints.
//!
//! An AI provider row carries a JSONB `config`. When that config holds a
//! non-empty `base_url`, nano sends inference straight to that endpoint and the
//! managed Cloudflare AI Gateway is out of the path entirely (NAN-1207). This
//! started as the air-gapped inference story but is equally the
//! bring-your-own-model story: a self-hosted operator who does not want
//! inference traffic transiting Cloudflare — data-residency rules being the
//! usual reason — points nano at their own endpoint (NAN-2231).
//!
//! Two things have to be resolved from that config, in exactly the same way on
//! both the request path (`AiGatewayClient`) and the "Test connection" probe
//! (the AI-providers handler), which is why they live here rather than in
//! either crate:
//!
//! 1. **Where** to send the request — the trimmed `base_url`.
//! 2. **What wire format** to speak — [`DirectApiStyle`], read from
//!    `config.api_style` and otherwise inferred.
//!
//! The inference default is deliberately conservative. Before NAN-2231 every
//! direct endpoint was assumed OpenAI-compatible, so anything other than
//! "OpenAI-compatible unless we are certain" would silently re-shape requests
//! for an existing air-gapped deployment. Certainty here means Anthropic's own
//! API host: everything else stays OpenAI-compatible until an operator says
//! otherwise via `api_style`.

/// Provider key for Anthropic in the `ai_provider_credentials` table.
pub const ANTHROPIC_PROVIDER: &str = "anthropic";

/// Anthropic's public API host. A direct endpoint here speaks the native
/// Messages API, so it is the one case where the wire format can be inferred
/// rather than configured.
const ANTHROPIC_API_HOST: &str = "api.anthropic.com";

/// The wire format spoken by a directly-configured provider endpoint.
///
/// This is *not* the same axis as the provider itself: Claude can be reached
/// over either format (Anthropic publishes an OpenAI-compatible layer at
/// `api.anthropic.com/v1/`), and an OpenAI-shaped corporate proxy can front
/// almost any model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectApiStyle {
    /// OpenAI-compatible `POST {base_url}/chat/completions`, bearer auth.
    /// vLLM, Ollama, TGI, LM Studio, LiteLLM and friends — and Anthropic's own
    /// compatibility layer.
    OpenAi,
    /// Anthropic Messages `POST {base_url}/messages`, `x-api-key` +
    /// `anthropic-version`. The full Claude feature set (prompt caching,
    /// strict tool schemas) rather than the compat layer's lossy subset.
    Anthropic,
}

impl DirectApiStyle {
    /// Parse an explicit operator choice from `config.api_style`.
    ///
    /// Anything unrecognised — including the UI's "auto" and an empty string —
    /// returns `None` so the caller falls back to inference. An unknown value
    /// must never hard-fail a provider that was working before.
    fn from_config_value(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "anthropic" | "anthropic_messages" | "messages" => Some(Self::Anthropic),
            "openai" | "openai_compatible" | "chat_completions" => Some(Self::OpenAi),
            _ => None,
        }
    }
}

/// A resolved direct endpoint: where to send inference, and how to shape it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectEndpoint {
    /// Base URL with any trailing slash removed. Expected to already carry the
    /// API version segment (e.g. `https://api.anthropic.com/v1`), so callers
    /// append only the path.
    pub base_url: String,
    /// Wire format to speak at that URL.
    pub style: DirectApiStyle,
}

impl DirectEndpoint {
    /// Whether this endpoint speaks Anthropic's native Messages API.
    pub fn is_anthropic_native(&self) -> bool {
        self.style == DirectApiStyle::Anthropic
    }

    /// The chat endpoint URL for this style.
    pub fn chat_url(&self) -> String {
        match self.style {
            DirectApiStyle::Anthropic => format!("{}/messages", self.base_url),
            DirectApiStyle::OpenAi => format!("{}/chat/completions", self.base_url),
        }
    }
}

/// The direct base URL configured on a provider, if any.
///
/// A blank or whitespace-only `base_url` is treated as unset, so clearing the
/// field in the UI falls back to the managed gateway instead of leaving a
/// half-configured empty string behind. A non-object `config` yields `None`.
pub fn direct_base_url(config: &serde_json::Value) -> Option<String> {
    config
        .get("base_url")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.trim_end_matches('/').to_string())
}

/// Whether a provider config points at a direct endpoint rather than the
/// managed gateway.
pub fn has_direct_base_url(config: &serde_json::Value) -> bool {
    direct_base_url(config).is_some()
}

/// Resolve a provider's direct endpoint, or `None` when it should use the
/// managed Cloudflare AI Gateway.
///
/// Style resolution, in order:
///
/// 1. An explicit `config.api_style` of `anthropic` or `openai` wins. This is
///    the escape hatch for Claude behind an OpenAI-shaped proxy, or for an
///    Anthropic-compatible endpoint on a host we cannot recognise.
/// 2. Otherwise: Anthropic-native only when this is the `anthropic` provider
///    *and* the URL points at Anthropic's own API host.
/// 3. Otherwise: OpenAI-compatible — the pre-NAN-2231 behaviour, and the right
///    default for every on-prem inference server.
pub fn direct_endpoint(provider: &str, config: &serde_json::Value) -> Option<DirectEndpoint> {
    let base_url = direct_base_url(config)?;

    let style = config
        .get("api_style")
        .and_then(|v| v.as_str())
        .and_then(DirectApiStyle::from_config_value)
        .unwrap_or_else(|| {
            if provider.eq_ignore_ascii_case(ANTHROPIC_PROVIDER) && is_anthropic_host(&base_url) {
                DirectApiStyle::Anthropic
            } else {
                DirectApiStyle::OpenAi
            }
        });

    Some(DirectEndpoint { base_url, style })
}

/// Whether a URL's host is Anthropic's API.
///
/// Matches the apex API host and any `*.anthropic.com` subdomain, so a future
/// regional or gov endpoint infers correctly without a code change. An
/// unparseable URL is not Anthropic's — it will fail the SSRF guard later
/// regardless, and guessing "native" for it would be the worse failure.
fn is_anthropic_host(base_url: &str) -> bool {
    url::Url::parse(base_url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_ascii_lowercase()))
        .is_some_and(|host| host == ANTHROPIC_API_HOST || host.ends_with(".anthropic.com"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn no_base_url_means_managed_gateway() {
        assert!(direct_endpoint("anthropic", &json!({})).is_none());
        assert!(direct_endpoint("openai", &json!({ "region": "us-east-1" })).is_none());
    }

    /// A cleared field in the UI must fall back to the gateway, not leave a
    /// half-configured empty endpoint behind.
    #[test]
    fn blank_base_url_means_managed_gateway() {
        assert!(direct_endpoint("anthropic", &json!({ "base_url": "   " })).is_none());
        assert!(direct_endpoint("anthropic", &json!({ "base_url": "" })).is_none());
    }

    /// A non-object config (null from an unset column) must not panic.
    #[test]
    fn non_object_config_means_managed_gateway() {
        assert!(direct_endpoint("anthropic", &serde_json::Value::Null).is_none());
        assert!(!has_direct_base_url(&serde_json::Value::Null));
    }

    #[test]
    fn trailing_slash_is_trimmed() {
        let ep = direct_endpoint("openai", &json!({ "base_url": "http://vllm.internal:8000/v1/" }))
            .expect("endpoint");
        assert_eq!(ep.base_url, "http://vllm.internal:8000/v1");
        assert_eq!(ep.chat_url(), "http://vllm.internal:8000/v1/chat/completions");
    }

    /// The headline NAN-2231 case: BYO Anthropic key, no Cloudflare.
    #[test]
    fn anthropic_provider_on_anthropic_host_infers_native() {
        let ep = direct_endpoint(
            "anthropic",
            &json!({ "base_url": "https://api.anthropic.com/v1" }),
        )
        .expect("endpoint");
        assert_eq!(ep.style, DirectApiStyle::Anthropic);
        assert!(ep.is_anthropic_native());
        assert_eq!(ep.chat_url(), "https://api.anthropic.com/v1/messages");
    }

    #[test]
    fn anthropic_subdomain_infers_native() {
        let ep = direct_endpoint(
            "anthropic",
            &json!({ "base_url": "https://eu.api.anthropic.com/v1" }),
        )
        .expect("endpoint");
        assert_eq!(ep.style, DirectApiStyle::Anthropic);
    }

    /// Zero-regression guard: an existing air-gapped deployment pointing any
    /// provider at an on-prem OpenAI server keeps the OpenAI wire format.
    #[test]
    fn on_prem_host_stays_openai_even_for_anthropic_provider() {
        let ep = direct_endpoint(
            "anthropic",
            &json!({ "base_url": "http://claude-proxy.internal:8000/v1" }),
        )
        .expect("endpoint");
        assert_eq!(ep.style, DirectApiStyle::OpenAi);
        assert_eq!(
            ep.chat_url(),
            "http://claude-proxy.internal:8000/v1/chat/completions"
        );
    }

    /// A lookalike domain must not be mistaken for Anthropic's.
    #[test]
    fn anthropic_lookalike_host_stays_openai() {
        for host in [
            "https://api.anthropic.com.evil.test/v1",
            "https://notanthropic.com/v1",
            "https://anthropic.com.co/v1",
        ] {
            let ep = direct_endpoint("anthropic", &json!({ "base_url": host })).expect("endpoint");
            assert_eq!(ep.style, DirectApiStyle::OpenAi, "host {host} must not infer native");
        }
    }

    /// Claude behind an OpenAI-shaped corporate proxy — the operator overrides
    /// inference the other way.
    #[test]
    fn explicit_api_style_overrides_inference() {
        let forced_openai = direct_endpoint(
            "anthropic",
            &json!({ "base_url": "https://api.anthropic.com/v1", "api_style": "openai" }),
        )
        .expect("endpoint");
        assert_eq!(forced_openai.style, DirectApiStyle::OpenAi);

        let forced_native = direct_endpoint(
            "openai",
            &json!({ "base_url": "https://claude.internal/v1", "api_style": "Anthropic" }),
        )
        .expect("endpoint");
        assert_eq!(forced_native.style, DirectApiStyle::Anthropic);
        assert_eq!(forced_native.chat_url(), "https://claude.internal/v1/messages");
    }

    /// The UI's "auto" option, and any value we do not recognise, must fall
    /// through to inference rather than fail the provider.
    #[test]
    fn unrecognised_api_style_falls_back_to_inference() {
        for raw in ["auto", "", "  ", "bedrock-converse"] {
            let ep = direct_endpoint(
                "anthropic",
                &json!({ "base_url": "https://api.anthropic.com/v1", "api_style": raw }),
            )
            .expect("endpoint");
            assert_eq!(ep.style, DirectApiStyle::Anthropic, "api_style {raw:?}");
        }
    }
}
