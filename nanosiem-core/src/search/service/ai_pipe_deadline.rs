// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3190: bounded `| ai` enrichment.
//!
//! The provider call behind `| ai` has its own HTTP timeout (minutes, plus
//! retries), far beyond the 60 s edge timeout in front of search. When the
//! provider is unreachable (dropped egress, stalled gateway) the request
//! used to hang until the edge returned a bare 502 and the handler future was
//! dropped without a single log line. The pipe now runs under a hard deadline
//! below the edge timeout; on timeout or error every row is tagged
//! `ai_verdict = "ERROR"` with the reason, so the search still answers.

use std::time::Duration;

use serde_json::Value;

use crate::extensions::AiClient;

/// Outer safety net for one `| ai` stage. The enterprise pipe batches rows
/// and enforces its own per-batch timeout and 50 s total budget (marking
/// unfinished batches per row, keeping finished ones); this bound only catches
/// a stall outside that loop (tenant settings / entitlement / credential reads)
/// and stays under the 60 s edge timeout. `| ai` runs only on the synchronous
/// lane (the durable lane refuses it, NAN-3071), for the web UI and API alike.
pub(super) const AI_PIPE_DEADLINE: Duration = Duration::from_secs(55);

/// Run `| ai` enrichment under `deadline`. Never fails: errors and timeouts
/// become per-row `ERROR` verdicts carrying the reason.
pub(super) async fn enrich_rows_with_deadline(
    client: &dyn AiClient,
    rows: Vec<Value>,
    prompt: &str,
    max_rows: usize,
    deadline: Duration,
) -> Vec<Value> {
    if rows.is_empty() {
        return rows;
    }
    let started = std::time::Instant::now();
    let reason =
        match tokio::time::timeout(deadline, client.enrich_rows(rows.clone(), prompt, max_rows))
            .await
        {
            Ok(Ok(enriched)) => {
                tracing::info!(
                    rows = enriched.len(),
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    "AI pipe enrichment complete"
                );
                return enriched;
            }
            Ok(Err(error)) => {
                tracing::warn!(
                    error = %error,
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    "AI pipe enrichment failed"
                );
                format!("AI enrichment failed: {error}")
            }
            Err(_) => {
                tracing::warn!(
                    deadline_s = deadline.as_secs(),
                    rows = rows.len(),
                    "AI pipe enrichment timed out; AI provider did not respond"
                );
                format!(
                    "AI enrichment timed out: the AI provider did not respond within {} s",
                    deadline.as_secs()
                )
            }
        };
    mark_rows_ai_error(rows, &reason)
}

fn mark_rows_ai_error(mut rows: Vec<Value>, reason: &str) -> Vec<Value> {
    for row in &mut rows {
        if let Some(object) = row.as_object_mut() {
            object.insert("ai_verdict".to_string(), Value::String("ERROR".to_string()));
            object.insert("ai_confidence".to_string(), serde_json::json!(0.0));
            object.insert(
                "ai_reasoning".to_string(),
                Value::String(reason.to_string()),
            );
        }
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extensions::{AiMessage, ExtensionError};
    use async_trait::async_trait;
    use serde_json::json;

    enum Behavior {
        Hang,
        Fail,
        Verdict,
    }

    struct StubClient(Behavior);

    #[async_trait]
    impl AiClient for StubClient {
        async fn complete(
            &self,
            _messages: Vec<AiMessage>,
            _system_prompt: &str,
        ) -> Result<String, ExtensionError> {
            unreachable!()
        }

        async fn enrich_rows(
            &self,
            mut rows: Vec<Value>,
            _prompt: &str,
            _max_rows: usize,
        ) -> Result<Vec<Value>, ExtensionError> {
            match self.0 {
                Behavior::Hang => std::future::pending().await,
                Behavior::Fail => Err(ExtensionError::Unavailable("provider unavailable")),
                Behavior::Verdict => {
                    for row in &mut rows {
                        row["ai_verdict"] = json!("NORMAL");
                    }
                    Ok(rows)
                }
            }
        }
    }

    fn rows() -> Vec<Value> {
        vec![json!({"_time": "t1"}), json!({"_time": "t2"})]
    }

    #[tokio::test(start_paused = true)]
    async fn hung_provider_fails_fast_with_per_row_reason() {
        let out = enrich_rows_with_deadline(
            &StubClient(Behavior::Hang),
            rows(),
            "classify",
            5,
            AI_PIPE_DEADLINE,
        )
        .await;
        assert_eq!(out.len(), 2);
        for row in &out {
            assert_eq!(row["ai_verdict"], "ERROR");
            assert_eq!(row["ai_confidence"], 0.0);
            assert!(row["ai_reasoning"]
                .as_str()
                .unwrap()
                .contains("did not respond within 55 s"));
            assert!(row["_time"].is_string(), "original columns survive");
        }
    }

    #[tokio::test]
    async fn provider_error_is_per_row_reason() {
        let out = enrich_rows_with_deadline(
            &StubClient(Behavior::Fail),
            rows(),
            "classify",
            5,
            AI_PIPE_DEADLINE,
        )
        .await;
        assert!(out.iter().all(|row| row["ai_verdict"] == "ERROR"
            && row["ai_reasoning"]
                .as_str()
                .unwrap()
                .contains("provider unavailable")));
    }

    #[tokio::test]
    async fn success_passes_through() {
        let out = enrich_rows_with_deadline(
            &StubClient(Behavior::Verdict),
            rows(),
            "classify",
            5,
            AI_PIPE_DEADLINE,
        )
        .await;
        assert!(out.iter().all(|row| row["ai_verdict"] == "NORMAL"));
    }

    #[test]
    fn deadline_is_below_edge_timeout() {
        assert!(AI_PIPE_DEADLINE < Duration::from_secs(60));
    }
}
