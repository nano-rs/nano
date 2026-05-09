// SPDX-License-Identifier: AGPL-3.0-or-later

//! `AiClient` — extension point for AI completion + nPL `| ai` row enrichment.
//!
//! Used by `siem_health/{analyzer,scheduler}.rs`, the `| ai` pipe operator in
//! `query/clickhouse_sql_gen/`, `cases/closure_summary.rs`,
//! `cases/shadow_investigation/`, `custom_enrichment/code_generator.rs`, and
//! the AI-driven tuning agents (`tuning/{agent,orchestrator,hint_agent,safety}`).
//!
//! Open-core builds wire `NoopAiClient`. Callers with a non-AI fallback
//! (siem_health rules-based scoring) check `is_available()` before calling
//! `complete`; nPL `enrich_rows` returns rows tagged `ai_verdict = "SKIPPED"`
//! so table shape is preserved without a hard error.

use async_trait::async_trait;
use serde_json::Value;

use crate::extensions::ExtensionError;

/// Conversation message used by the core-side AI surface. Mirrors the
/// enterprise `melod::Message` but keeps core decoupled from meloD types.
#[derive(Debug, Clone)]
pub struct AiMessage {
    pub role: AiRole,
    pub content: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AiRole {
    User,
    Assistant,
    System,
}

impl AiMessage {
    pub fn user(content: impl Into<String>) -> Self {
        Self {
            role: AiRole::User,
            content: content.into(),
        }
    }
    pub fn assistant(content: impl Into<String>) -> Self {
        Self {
            role: AiRole::Assistant,
            content: content.into(),
        }
    }
    pub fn system(content: impl Into<String>) -> Self {
        Self {
            role: AiRole::System,
            content: content.into(),
        }
    }
}

/// Free-form agent identifier passed to `complete_for_agent` /
/// `complete_streaming`. The trait is decoupled from the enterprise `AgentId`
/// enum — implementations that don't support per-agent provider routing
/// ignore the argument and fall through to the default client.
///
/// Canonical values used across the codebase (keep in sync with enterprise
/// `melod::AgentId` mappings):
///
/// - `"shadow_hunting"`, `"shadow_narrative"` — cases::shadow_investigation
/// - `"closure_summary"` — cases::closure_summary
/// - `"siem_health"` — siem_health::analyzer
/// - `"enrichment_codegen"` — custom_enrichment::code_generator
/// - `"tuning_proposal"`, `"tuning_hints"`, `"tuning_safety"` — tuning agents
/// - `"ai_pipe"` — nPL `| ai` operator
pub type AiAgentId<'a> = &'a str;

/// Streaming text response. Mirrors `melod::ai_client::AiStreamingResponse`
/// but lives in core so consumers don't pull in the meloD types.
///
/// Two construction modes:
/// - `from_complete(s)` — non-streaming providers / fallback paths emit the
///   full response as a single chunk.
/// - `from_channel(rx)` — streaming providers feed chunks through the
///   receiver; each chunk is text already decoded into UTF-8.
///
/// Consumers call `next_chunk()` in a loop or `collect_all()` to drain.
pub struct AiStream {
    inner: AiStreamInner,
}

enum AiStreamInner {
    /// `Some` on first call, taken to `None` on receive — second call
    /// returns `None` to signal end-of-stream.
    Complete(Option<String>),
    Channel(tokio::sync::mpsc::Receiver<Result<String, ExtensionError>>),
}

impl AiStream {
    /// Wrap a fully-buffered response so callers using the streaming API
    /// still work against non-streaming providers.
    pub fn from_complete(content: String) -> Self {
        Self {
            inner: AiStreamInner::Complete(Some(content)),
        }
    }

    /// Wrap an mpsc receiver of decoded text chunks. The producer is
    /// responsible for dropping the sender to signal end-of-stream.
    pub fn from_channel(rx: tokio::sync::mpsc::Receiver<Result<String, ExtensionError>>) -> Self {
        Self {
            inner: AiStreamInner::Channel(rx),
        }
    }

    /// Receive the next text chunk. Returns `None` when the stream is
    /// exhausted.
    pub async fn next_chunk(&mut self) -> Option<Result<String, ExtensionError>> {
        match &mut self.inner {
            AiStreamInner::Complete(content) => content.take().map(Ok),
            AiStreamInner::Channel(rx) => rx.recv().await,
        }
    }

    /// Drain the stream into a single string. Bounded at 10 MiB to match the
    /// existing meloD streaming contract — protects against runaway
    /// providers without forcing every caller to implement the cap.
    pub async fn collect_all(&mut self) -> Result<String, ExtensionError> {
        const MAX_RESPONSE_SIZE: usize = 10 * 1024 * 1024;
        let mut result = String::new();
        while let Some(chunk) = self.next_chunk().await {
            let chunk = chunk?;
            if result.len() + chunk.len() > MAX_RESPONSE_SIZE {
                return Err(ExtensionError::AiProvider(format!(
                    "ai response exceeded {MAX_RESPONSE_SIZE} bytes",
                )));
            }
            result.push_str(&chunk);
        }
        Ok(result)
    }
}

#[async_trait]
pub trait AiClient: Send + Sync {
    /// Returns true when a real AI provider is wired in. Call sites that have
    /// a non-AI fallback check this before paying serialization cost.
    fn is_available(&self) -> bool {
        false
    }

    /// Synchronous text completion against the default agent / provider.
    /// Used by siem_health analyzer and `cases::closure_summary`.
    async fn complete(
        &self,
        messages: Vec<AiMessage>,
        system_prompt: &str,
    ) -> Result<String, ExtensionError>;

    /// Synchronous text completion routed to a specific agent (provider /
    /// model config). Implementations that don't support per-agent routing
    /// fall through to `complete`. Used by shadow_investigation and the
    /// tuning agents to pick agent-specific models when configured.
    async fn complete_for_agent(
        &self,
        _agent_id: AiAgentId<'_>,
        messages: Vec<AiMessage>,
        system_prompt: &str,
    ) -> Result<String, ExtensionError> {
        self.complete(messages, system_prompt).await
    }

    /// Streaming text completion. Default implementation buffers the full
    /// response from `complete_for_agent` and yields it as one chunk —
    /// providers that natively support streaming (meloD's gateway) override.
    /// Used by `custom_enrichment::code_generator` for SSE-style responses.
    async fn complete_streaming(
        &self,
        agent_id: AiAgentId<'_>,
        messages: Vec<AiMessage>,
        system_prompt: &str,
    ) -> Result<AiStream, ExtensionError> {
        let response = self
            .complete_for_agent(agent_id, messages, system_prompt)
            .await?;
        Ok(AiStream::from_complete(response))
    }

    /// nPL `| ai` pipe row enrichment. Takes raw JSON rows + an analyst
    /// prompt, returns rows enriched with `ai_verdict` / `ai_confidence` /
    /// `ai_reasoning` columns. Capped at `max_rows`; overflow rows get
    /// `ai_verdict = "SKIPPED"` per the existing AiPipeAgent contract.
    async fn enrich_rows(
        &self,
        rows: Vec<Value>,
        prompt: &str,
        max_rows: usize,
    ) -> Result<Vec<Value>, ExtensionError>;
}

/// No-op AI client used by open-core builds. AI-using code paths must check
/// `is_available()` and fall back (e.g. rules-based analysis in siem_health)
/// rather than treat `Unavailable` as a hard error.
pub struct NoopAiClient;

#[async_trait]
impl AiClient for NoopAiClient {
    fn is_available(&self) -> bool {
        false
    }

    async fn complete(
        &self,
        _messages: Vec<AiMessage>,
        _system_prompt: &str,
    ) -> Result<String, ExtensionError> {
        Err(ExtensionError::Unavailable("AI client not configured"))
    }

    async fn enrich_rows(
        &self,
        rows: Vec<Value>,
        _prompt: &str,
        _max_rows: usize,
    ) -> Result<Vec<Value>, ExtensionError> {
        // Tag every row as SKIPPED so the frontend can show a "AI unavailable"
        // hint without breaking the table shape.
        Ok(rows
            .into_iter()
            .map(|mut row| {
                if let Some(obj) = row.as_object_mut() {
                    obj.insert("ai_verdict".into(), Value::String("SKIPPED".into()));
                    obj.insert("ai_confidence".into(), Value::Number(0.into()));
                    obj.insert(
                        "ai_reasoning".into(),
                        Value::String("AI unavailable in this build".into()),
                    );
                }
                row
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ai_stream_from_complete_yields_one_chunk() {
        let mut s = AiStream::from_complete("hello".to_string());
        assert_eq!(s.next_chunk().await.unwrap().unwrap(), "hello");
        assert!(s.next_chunk().await.is_none());
    }

    #[tokio::test]
    async fn ai_stream_from_complete_empty_string_yields_one_empty_chunk_then_none() {
        // Locks in the `Option::take()`-based contract: an empty content
        // string is a real chunk, not a sentinel for end-of-stream. Drain
        // returns "", subsequent reads return None.
        let mut s = AiStream::from_complete(String::new());
        assert_eq!(s.next_chunk().await.unwrap().unwrap(), "");
        assert!(s.next_chunk().await.is_none());
    }

    #[tokio::test]
    async fn ai_stream_collect_all_drains_complete() {
        let mut s = AiStream::from_complete("hello world".to_string());
        assert_eq!(s.collect_all().await.unwrap(), "hello world");
    }

    #[tokio::test]
    async fn ai_stream_from_channel_collects_chunks() {
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        tokio::spawn(async move {
            tx.send(Ok("hel".to_string())).await.unwrap();
            tx.send(Ok("lo".to_string())).await.unwrap();
        });
        let mut s = AiStream::from_channel(rx);
        assert_eq!(s.collect_all().await.unwrap(), "hello");
    }

    #[tokio::test]
    async fn noop_client_complete_streaming_falls_through() {
        let client = NoopAiClient;
        let result = client
            .complete_streaming("any_agent", vec![AiMessage::user("hi")], "")
            .await;
        // Default implementation calls complete_for_agent → complete → Unavailable
        assert!(matches!(result, Err(ExtensionError::Unavailable(_))));
    }
}
