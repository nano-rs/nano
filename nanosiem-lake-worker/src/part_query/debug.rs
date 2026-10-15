// SPDX-License-Identifier: AGPL-3.0-or-later
//! Request-scoped diagnostics, enabled only by the authenticated search debug header.
//! Bound diagnostic output to 4 MiB; never serialize parameter values.
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

tokio::task_local! {
    static DEBUG: Arc<Mutex<Value>>;
}

pub(super) fn enabled() -> bool {
    DEBUG.try_with(|_| ()).is_ok()
}

pub(super) async fn collect<E, F: std::future::Future<Output = Result<Value, E>>>(
    work: F,
) -> Result<Value, E> {
    // NAN-3141: one heap copy of `work`, not an inline one per await point.
    let work = Box::pin(work);
    let evidence = Arc::new(Mutex::new(
        json!({"files":[], "statements":[], "diagnostic_bytes":0, "truncated":false}),
    ));
    let answer = DEBUG.scope(evidence.clone(), work).await;
    let evidence = evidence.lock().unwrap_or_else(|e| e.into_inner()).clone();
    tracing::debug!(diagnostics = %evidence, "native query diagnostics");
    let mut answer = answer?;
    if !answer["planner"].is_object() {
        answer["planner"] = json!({});
    }
    answer["planner"]["native_debug"] = evidence;
    Ok(answer)
}

pub(super) fn file(key: &str, tier: &str, bytes: u64) {
    let _ = DEBUG.try_with(|evidence| {
        let mut evidence = evidence.lock().unwrap_or_else(|e| e.into_inner());
        let files = evidence["files"].as_array_mut().expect("files array");
        let file = json!({"key":key,"tier":tier,"bytes":bytes});
        if files.contains(&file) {
            return;
        }
        let bytes = file.to_string().len() as u64;
        if evidence["diagnostic_bytes"].as_u64().unwrap_or(0) + bytes > 4 * 1024 * 1024 {
            evidence["truncated"] = json!(true);
            return;
        }
        evidence["diagnostic_bytes"] =
            json!(evidence["diagnostic_bytes"].as_u64().unwrap_or(0) + bytes);
        evidence["files"]
            .as_array_mut()
            .expect("files array")
            .push(file);
    });
}

/// Preserve typed placeholders; redact all literal strings (including escaped quotes).
/// Bound parameters are never serialized. SQL comes from the trusted compiler/planner.
pub(super) fn redact(sql: &str) -> String {
    let mut result = String::new();
    let mut chars = sql.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\'' {
            result.push(c);
            continue;
        }
        result.push_str("{literal:String}");
        while let Some(c) = chars.next() {
            if c == '\\' {
                chars.next();
            } else if c == '\'' {
                if chars.peek() == Some(&'\'') {
                    chars.next();
                } else {
                    break;
                }
            }
        }
    }
    result
}

/// One statement attempt; `timing` (an object: per-attempt native times,
/// lane class, error kind) is merged into its record.
pub(super) fn statement(sql: &str, settings: Value, lane: &str, lane_wait_ms: f64, output: Option<(u64, u64)>, timing: Value) {
    let _ = DEBUG.try_with(|evidence| {
        let mut evidence = evidence.lock().unwrap_or_else(|e| e.into_inner());
        let mut statement = json!({"sql":redact(sql),"native_settings":settings,"lane":lane,"lane_wait_ms":lane_wait_ms,"completed":output.is_some(),"storage_rows":output.map(|o|o.0),"storage_bytes":output.map(|o|o.1)});
        if let (Some(record), Value::Object(extra)) = (statement.as_object_mut(), timing) {
            for (name, value) in extra {
                record.entry(name).or_insert(value);
            }
        }
        let bytes = statement.to_string().len() as u64;
        if evidence["diagnostic_bytes"].as_u64().unwrap_or(0) + bytes > 4 * 1024 * 1024 {
            evidence["truncated"] = json!(true);
            return;
        }
        evidence["diagnostic_bytes"] = json!(evidence["diagnostic_bytes"].as_u64().unwrap_or(0) + bytes);
        evidence["statements"].as_array_mut().expect("statements array").push(statement);
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn redacts_escaped_literals_and_keeps_parameter_types() {
        assert_eq!(redact("SELECT 'secret', 'a\\\'b', 'a''b', {path:String} SETTINGS max_threads=2"),
            "SELECT {literal:String}, {literal:String}, {literal:String}, {path:String} SETTINGS max_threads=2");
    }
    #[tokio::test]
    async fn collection_is_scoped_deduplicated_and_bounded() {
        let answer = collect(async {
            file("s3://bucket/h/data.parquet", "h", 123);
            file("s3://bucket/h/data.parquet", "h", 123);
            file(&"x".repeat(4 * 1024 * 1024), "h", 123);
            Ok::<_, ()>(json!({"planner":{}}))
        })
        .await
        .unwrap();
        assert_eq!(
            answer["planner"]["native_debug"]["files"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(answer["planner"]["native_debug"]["truncated"], true);
        assert!(!enabled());
    }

    #[tokio::test]
    async fn statement_lane_evidence_respects_the_output_bound() {
        let answer = collect(async {
            statement("SELECT {private:String}", json!({}), "small", 12.5, Some((1, 2)), json!({}));
            statement(&"x".repeat(4 * 1024 * 1024), json!({}), "large", 0.0, None, json!({}));
            Ok::<_, ()>(json!({}))
        }).await.unwrap();
        let evidence = &answer["planner"]["native_debug"];
        assert_eq!(evidence["statements"].as_array().unwrap().len(), 1);
        assert_eq!(evidence["statements"][0]["lane"], "small");
        assert_eq!(evidence["statements"][0]["lane_wait_ms"], 12.5);
        assert!(evidence["statements"][0].get("params").is_none());
        assert_eq!(evidence["truncated"], true);
    }

    #[tokio::test]
    async fn statement_attempts_carry_their_own_timing() {
        let answer = collect(async {
            statement("SELECT 1", json!({}), "small", 0.5, None,
                json!({"native_fetch_ms": 812.5, "lane_class": "small", "bounded_reader": true, "error": "memory_limit", "lane": "spoof"}));
            statement("SELECT 1", json!({}), "large", 0.0, Some((3, 4)), json!({"native_fetch_ms": 90.0, "lane_class": "large"}));
            Ok::<_, ()>(json!({}))
        }).await.unwrap();
        let statements = answer["planner"]["native_debug"]["statements"].as_array().unwrap().clone();
        assert_eq!(statements.len(), 2);
        assert_eq!((statements[0]["completed"].clone(), statements[0]["error"].clone()), (json!(false), json!("memory_limit")));
        assert_eq!(statements[0]["native_fetch_ms"], 812.5);
        assert_eq!(statements[0]["bounded_reader"], true);
        // Timing never overwrites the record's own fields.
        assert_eq!(statements[0]["lane"], "small");
        assert_eq!((statements[1]["lane_class"].clone(), statements[1]["native_fetch_ms"].clone()), (json!("large"), json!(90.0)));
    }

    #[test]
    fn ordinary_requests_have_no_collector() {
        assert!(!enabled());
    }
}

/// Process cache counters contain no predicates, row identities or tenant data.
pub(super) fn result_cache(counters: Value) {
    let _ = DEBUG.try_with(|evidence| {
        evidence.lock().unwrap_or_else(|e| e.into_inner())["result_cache"] = counters;
    });
}
