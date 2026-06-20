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

    /// Structured completion: ask the model to return a single JSON object
    /// matching `json_schema` and return it parsed (NAN-1251).
    ///
    /// The default impl appends a strict "respond with ONLY JSON" instruction
    /// to the system prompt, calls `complete_for_agent`, and tolerantly
    /// extracts the JSON object from the text (handling ```json fences and
    /// leading/trailing prose). Enterprise implementations that support native
    /// tool-calling override this to force a tool-call against the schema,
    /// which is far more reliable than text parsing.
    ///
    /// `json_schema` is a JSON Schema object describing the expected shape.
    /// The returned value is shape-validated against the schema (top-level type
    /// + required fields, via [`validate_structured`]) before it is handed
    /// back; on a parse or validation failure the model is re-prompted once
    /// with the specific error, and a terminal failure surfaces as an error.
    /// Callers must NOT substitute an empty default on `Err` — for an
    /// investigation agent a malformed response would otherwise masquerade as a
    /// genuine "nothing found" (NAN-1489).
    async fn complete_structured(
        &self,
        agent_id: AiAgentId<'_>,
        messages: Vec<AiMessage>,
        system_prompt: &str,
        json_schema: &Value,
    ) -> Result<Value, ExtensionError> {
        let augmented_system = format!(
            "{system_prompt}\n\n## OUTPUT FORMAT\n\
            Respond with ONLY a single JSON object matching this schema. \
            No prose, no markdown, no code fences — just the raw JSON object.\n\
            Schema:\n{}",
            serde_json::to_string(json_schema).unwrap_or_default()
        );

        // Two attempts: the model occasionally returns prose-wrapped or
        // schema-violating JSON, and feeding the specific error back fixes the
        // common cases without unbounded cost.
        let mut convo = messages;
        let mut last_err = String::new();
        for _ in 0..MAX_STRUCTURED_ATTEMPTS {
            let raw = self
                .complete_for_agent(agent_id, convo.clone(), &augmented_system)
                .await?;
            match extract_json_object(&raw) {
                Some(value) => match validate_structured(&value, json_schema) {
                    Ok(()) => return Ok(value),
                    Err(e) => last_err = e,
                },
                None => {
                    last_err =
                        format!("response was not parseable JSON (got {} chars)", raw.len())
                }
            }
            // Feed the bad turn + a corrective instruction into the retry.
            convo.push(AiMessage::assistant(raw));
            convo.push(AiMessage::user(structured_retry_followup(&last_err)));
        }

        Err(ExtensionError::AiProvider(format!(
            "structured completion failed validation after {MAX_STRUCTURED_ATTEMPTS} attempts: {last_err}"
        )))
    }
}

/// Maximum attempts for a structured completion (initial + one schema-aware
/// retry). Shared by the core default impl and the enterprise bridge override
/// so both paths bound retry cost identically.
pub const MAX_STRUCTURED_ATTEMPTS: usize = 2;

/// Corrective instruction appended after a malformed or schema-violating
/// structured response. Fed back to the model on the retry attempt so it can
/// repair the specific problem rather than guessing.
pub fn structured_retry_followup(error: &str) -> String {
    format!(
        "Your previous response could not be used: {error}. \
        Respond again with ONLY a single JSON object that matches the required schema — \
        no prose, no markdown, no code fences."
    )
}

/// Lightweight structural validation of an LLM-produced value against a JSON
/// Schema fragment. This is deliberately NOT a full JSON Schema validator — it
/// checks the failure modes that actually bite a SIEM agent: a wrong top-level
/// type (e.g. the model returns an object where an array was required, or vice
/// versa) and missing required fields, one level deep plus required fields on
/// array items. `Ok(())` means "the shape looks right", not "fully schema
/// valid"; callers still clamp/validate individual values. Returns a
/// human-readable error suitable for feeding back to the model on a retry.
pub fn validate_structured(value: &Value, schema: &Value) -> Result<(), String> {
    validate_node(value, schema, "$")
}

fn validate_node(value: &Value, schema: &Value, path: &str) -> Result<(), String> {
    if let Some(expected) = schema.get("type").and_then(|t| t.as_str()) {
        if !type_matches(value, expected) {
            return Err(format!(
                "{path}: expected {expected}, got {}",
                json_type_name(value)
            ));
        }
    }

    // Required object fields must be present and non-null.
    if let Some(required) = schema.get("required").and_then(|r| r.as_array()) {
        let obj = value.as_object();
        for req in required {
            if let Some(key) = req.as_str() {
                let present = obj
                    .and_then(|o| o.get(key))
                    .map(|v| !v.is_null())
                    .unwrap_or(false);
                if !present {
                    return Err(format!("{path}: missing required field '{key}'"));
                }
            }
        }
    }

    // Recurse into declared object properties that are present, so nested
    // shape errors (e.g. a wrong-typed field, or array items below) are caught.
    if let (Some(props), Some(obj)) = (
        schema.get("properties").and_then(|p| p.as_object()),
        value.as_object(),
    ) {
        for (key, subschema) in props {
            if let Some(child) = obj.get(key) {
                validate_node(child, subschema, &format!("{path}.{key}"))?;
            }
        }
    }

    // Array element shape — catches an array of the wrong item type or items
    // missing their required fields.
    if let (Some(items_schema), Some(arr)) = (schema.get("items"), value.as_array()) {
        for (i, item) in arr.iter().enumerate() {
            validate_node(item, items_schema, &format!("{path}[{i}]"))?;
        }
    }

    Ok(())
}

fn type_matches(value: &Value, expected: &str) -> bool {
    match expected {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "number" => value.is_number(),
        "integer" => value.is_i64() || value.is_u64(),
        "boolean" => value.is_boolean(),
        "null" => value.is_null(),
        // Unknown or compound (`["string","null"]`) type spec — don't reject.
        _ => true,
    }
}

fn json_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Tolerantly pull a single JSON object out of an LLM text response. Handles
/// the model wrapping the object in ```json fences or surrounding prose by
/// scanning for the first balanced `{...}` span and parsing that. Returns
/// `None` if no valid JSON object is found.
pub fn extract_json_object(raw: &str) -> Option<Value> {
    // Fast path: the whole thing is valid JSON.
    if let Ok(v @ Value::Object(_)) = serde_json::from_str::<Value>(raw.trim()) {
        return Some(v);
    }

    // Strip a ```json ... ``` (or bare ``` ... ```) fence if present.
    let unfenced = strip_code_fence(raw);
    if let Ok(v @ Value::Object(_)) = serde_json::from_str::<Value>(unfenced.trim()) {
        return Some(v);
    }

    // Scan for the first balanced top-level object, respecting strings/escapes.
    let bytes = unfenced.as_bytes();
    let start = bytes.iter().position(|&b| b == b'{')?;
    let mut depth = 0usize;
    let mut in_str = false;
    let mut escaped = false;
    for (i, &b) in bytes.iter().enumerate().skip(start) {
        if in_str {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_str = false;
            }
            continue;
        }
        match b {
            b'"' => in_str = true,
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    let candidate = &unfenced[start..=i];
                    return serde_json::from_str::<Value>(candidate)
                        .ok()
                        .filter(|v| v.is_object());
                }
            }
            _ => {}
        }
    }
    None
}

/// Remove a surrounding ```json / ``` fence if the text is fenced.
fn strip_code_fence(raw: &str) -> &str {
    let trimmed = raw.trim();
    if let Some(rest) = trimmed.strip_prefix("```") {
        // Drop an optional language tag on the first line (e.g. "json").
        let after_tag = rest.splitn(2, '\n').nth(1).unwrap_or("");
        return after_tag.strip_suffix("```").unwrap_or(after_tag);
    }
    trimmed
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

    #[test]
    fn extract_json_object_handles_bare_object() {
        let v = extract_json_object(r#"{"disposition":"false_positive","confidence":0.9}"#).unwrap();
        assert_eq!(v["disposition"], "false_positive");
    }

    #[test]
    fn extract_json_object_strips_code_fence() {
        let raw = "```json\n{\"disposition\":\"benign\",\"confidence\":0.8}\n```";
        let v = extract_json_object(raw).unwrap();
        assert_eq!(v["disposition"], "benign");
    }

    #[test]
    fn extract_json_object_finds_object_amid_prose() {
        let raw = "Here is my verdict:\n{\"disposition\":\"true_positive\",\
            \"rationale\":\"found IEX cradle from evil.com\"} — hope that helps!";
        let v = extract_json_object(raw).unwrap();
        assert_eq!(v["disposition"], "true_positive");
        assert_eq!(v["rationale"], "found IEX cradle from evil.com");
    }

    #[test]
    fn extract_json_object_respects_braces_in_strings() {
        // A `}` inside a string value must not prematurely close the object.
        let raw = r#"{"note":"contains a } brace","ok":true}"#;
        let v = extract_json_object(raw).unwrap();
        assert_eq!(v["note"], "contains a } brace");
        assert_eq!(v["ok"], true);
    }

    #[test]
    fn extract_json_object_returns_none_on_garbage() {
        assert!(extract_json_object("no json here at all").is_none());
        assert!(extract_json_object("").is_none());
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

    #[test]
    fn validate_structured_accepts_matching_object() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": { "query": { "type": "string" } },
            "required": ["query"]
        });
        let value = serde_json::json!({ "query": "error | head 5", "reason": "scope" });
        assert!(validate_structured(&value, &schema).is_ok());
    }

    #[test]
    fn validate_structured_rejects_wrong_top_level_type() {
        // The model returned a bare array where the schema required an object —
        // exactly the Step-7 wrapping mismatch we want caught, not silently
        // accepted.
        let schema = serde_json::json!({ "type": "object", "required": ["queries"] });
        let value = serde_json::json!([{ "query": "x" }]);
        let err = validate_structured(&value, &schema).unwrap_err();
        assert!(err.contains("expected object"), "got: {err}");
    }

    #[test]
    fn validate_structured_rejects_missing_required_field() {
        let schema = serde_json::json!({ "type": "object", "required": ["queries"] });
        let value = serde_json::json!({ "other": 1 });
        let err = validate_structured(&value, &schema).unwrap_err();
        assert!(err.contains("missing required field 'queries'"), "got: {err}");
    }

    #[test]
    fn validate_structured_rejects_null_required_field() {
        // A present-but-null required field is as useless as a missing one.
        let schema = serde_json::json!({ "type": "object", "required": ["queries"] });
        let value = serde_json::json!({ "queries": null });
        assert!(validate_structured(&value, &schema).is_err());
    }

    #[test]
    fn validate_structured_checks_array_item_required_fields() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "queries": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": { "query": { "type": "string" } },
                        "required": ["query"]
                    }
                }
            },
            "required": ["queries"]
        });
        let ok = serde_json::json!({ "queries": [{ "query": "a" }, { "query": "b" }] });
        assert!(validate_structured(&ok, &schema).is_ok());

        // Second element is missing `query`.
        let bad = serde_json::json!({ "queries": [{ "query": "a" }, { "reason": "no query" }] });
        let err = validate_structured(&bad, &schema).unwrap_err();
        assert!(err.contains("[1]"), "expected the offending index in: {err}");
        assert!(err.contains("missing required field 'query'"), "got: {err}");
    }

    /// Scripted client that returns a queued sequence of responses, recording
    /// how many times it was invoked — lets us assert the retry actually fires
    /// and that the corrective turn is appended.
    #[derive(Debug)]
    struct ScriptedClient {
        responses: std::sync::Mutex<std::collections::VecDeque<String>>,
        calls: std::sync::atomic::AtomicUsize,
        last_message_count: std::sync::atomic::AtomicUsize,
    }

    impl ScriptedClient {
        fn new(responses: Vec<&str>) -> Self {
            Self {
                responses: std::sync::Mutex::new(
                    responses.into_iter().map(String::from).collect(),
                ),
                calls: std::sync::atomic::AtomicUsize::new(0),
                last_message_count: std::sync::atomic::AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl AiClient for ScriptedClient {
        fn is_available(&self) -> bool {
            true
        }

        async fn complete(
            &self,
            messages: Vec<AiMessage>,
            _system_prompt: &str,
        ) -> Result<String, ExtensionError> {
            use std::sync::atomic::Ordering;
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.last_message_count
                .store(messages.len(), Ordering::SeqCst);
            Ok(self
                .responses
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| "still not json".to_string()))
        }

        async fn enrich_rows(
            &self,
            rows: Vec<Value>,
            _prompt: &str,
            _max_rows: usize,
        ) -> Result<Vec<Value>, ExtensionError> {
            Ok(rows)
        }
    }

    fn obj_schema() -> Value {
        serde_json::json!({
            "type": "object",
            "properties": { "verdict": { "type": "string" } },
            "required": ["verdict"]
        })
    }

    #[tokio::test]
    async fn complete_structured_returns_valid_first_try() {
        let client = ScriptedClient::new(vec![r#"{"verdict":"benign"}"#]);
        let v = client
            .complete_structured("agent", vec![AiMessage::user("go")], "sys", &obj_schema())
            .await
            .unwrap();
        assert_eq!(v["verdict"], "benign");
        assert_eq!(client.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn complete_structured_retries_then_succeeds() {
        // First response is unparseable prose; the retry returns valid JSON.
        let client = ScriptedClient::new(vec![
            "I cannot help with that.",
            r#"{"verdict":"malicious"}"#,
        ]);
        let v = client
            .complete_structured("agent", vec![AiMessage::user("go")], "sys", &obj_schema())
            .await
            .unwrap();
        assert_eq!(v["verdict"], "malicious");
        // Two invocations, and the second carried the appended corrective turns
        // (original user + assistant echo + corrective user = 3 messages).
        assert_eq!(client.calls.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert_eq!(
            client
                .last_message_count
                .load(std::sync::atomic::Ordering::SeqCst),
            3
        );
    }

    #[tokio::test]
    async fn complete_structured_surfaces_error_not_empty_default() {
        // Both attempts return schema-violating JSON (missing `verdict`). The
        // result must be an Err the caller can record as a degradation — NOT a
        // silent empty object that reads as "investigation found nothing".
        let client = ScriptedClient::new(vec![r#"{"foo":1}"#, r#"{"bar":2}"#]);
        let result = client
            .complete_structured("agent", vec![AiMessage::user("go")], "sys", &obj_schema())
            .await;
        assert!(matches!(result, Err(ExtensionError::AiProvider(_))));
        assert_eq!(client.calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    }
}
