// SPDX-License-Identifier: AGPL-3.0-or-later
//! Golden byte-identity gate for nPL → ClickHouse SQL (security review
//! 2026-11-08, Group A).
//!
//! A wrong escape silently changes search results, so every change to SQL
//! escaping must prove that the SQL generated for legitimate queries is
//! unchanged. The runner renders every query in
//! `tests/fixtures/npl_golden/corpus.jsonl` through [`SearchService::explain`]
//! (the same parse → validate → auto-sort → prevalence-pushdown → codegen path
//! the executed search takes) under the UDM and OCSF profiles, hashes the SQL,
//! and compares against `tests/fixtures/npl_golden/expected.jsonl`.
//!
//! The corpus is the `rules` content repo, the nPL examples in `docs/`, the
//! pipelines embedded in the generator/parser tests, and a hand-written block
//! covering every construct the escaping work touches.
//!
//! # Reusing the runner
//!
//! Other tests (for example a source-scoped pass) call [`load_corpus`] and
//! [`render_corpus`] with their own [`ScopeSet`] and compare or inspect the
//! rendered rows. The fixture paths are [`corpus_path`] / [`expected_path`].
//!
//! Environment knobs for [`npl_golden_corpus_sql_is_unchanged`]:
//! - `NPL_GOLDEN_UPDATE=1` rewrites `expected.jsonl` from the current code.
//!   Only do this after reviewing every diff it reports.
//! - `NPL_GOLDEN_DUMP=<path>` also writes the full rendered SQL (one JSON object
//!   per query and profile) so two commits can be diffed line by line.
//!
//! Timestamp literals are normalised before hashing: time modifiers such as
//! `earliest=-2h` resolve against the wall clock, and only the shape matters.

use super::SearchService;
use crate::auth::ScopeSet;
use crate::search::TimeRangeInput;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Arc;

/// One corpus entry: where it came from and the nPL text.
#[derive(serde::Deserialize, Debug, Clone)]
pub(crate) struct CorpusRow {
    pub(crate) src: String,
    pub(crate) q: String,
}

/// One rendered query: corpus index, profile (`udm` / `ocsf`) and the
/// normalised SQL, or `ERR:<message>` when the query is rejected.
#[derive(Debug, Clone)]
pub(crate) struct RenderedRow {
    pub(crate) index: usize,
    pub(crate) profile: &'static str,
    pub(crate) sql: String,
}

#[derive(serde::Serialize, serde::Deserialize, PartialEq, Eq, Debug, Clone)]
struct ExpectedRow {
    i: usize,
    p: String,
    h: String,
}

/// Profiles every corpus query is rendered under.
pub(crate) const PROFILES: [&str; 2] = ["udm", "ocsf"];

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/npl_golden")
}

/// `tests/fixtures/npl_golden/corpus.jsonl`.
pub(crate) fn corpus_path() -> PathBuf {
    fixture_dir().join("corpus.jsonl")
}

/// `tests/fixtures/npl_golden/expected.jsonl` (unscoped pass).
pub(crate) fn expected_path() -> PathBuf {
    fixture_dir().join("expected.jsonl")
}

/// Load the corpus fixture.
pub(crate) fn load_corpus() -> Vec<CorpusRow> {
    let path = corpus_path();
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("bad corpus row {l}: {e}")))
        .collect()
}

/// Replace every `'YYYY-MM-DD HH:MM:SS[.ffffff]'` literal with a placeholder.
pub(crate) fn normalise(sql: &str) -> String {
    let re = regex::Regex::new(r"'\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(\.\d+)?'")
        .expect("static regex");
    re.replace_all(sql, "'<TS>'").into_owned()
}

/// A `SearchService` that can render SQL but never connects anywhere.
pub(crate) fn sql_only_service(profile: &str) -> SearchService {
    let pool = crate::db::DualPool::for_sql_generation_tests(false);
    let schema: Arc<dyn crate::schema::SchemaProfile> = match profile {
        "udm" => Arc::new(crate::schema::UdmProfile::new()),
        "ocsf" => Arc::new(crate::schema::OcsfProfile::new()),
        other => panic!("unknown profile {other}"),
    };
    let mut svc = SearchService::with_dual_pool_and_profile(&pool, schema);
    // The prevalence pushdown only renders when a prevalence service exists.
    svc.set_prevalence_service(crate::prevalence::PrevalenceService::new(
        pool.clickhouse().clone(),
        pool.table_names(),
    ));
    svc
}

/// Render one query to its normalised SQL, or `ERR:<message>`.
pub(crate) async fn render(svc: &SearchService, query: &str, scope: &ScopeSet) -> String {
    let range = TimeRangeInput::new(
        chrono::DateTime::parse_from_rfc3339("2026-11-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
        chrono::DateTime::parse_from_rfc3339("2026-11-02T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
    );
    match svc.explain(query, &range, false, None, scope).await {
        Ok(sql) => normalise(&sql),
        Err(e) => format!("ERR:{e}"),
    }
}

/// Render the whole corpus under every profile in [`PROFILES`] with `scope`.
pub(crate) async fn render_corpus(corpus: &[CorpusRow], scope: &ScopeSet) -> Vec<RenderedRow> {
    let mut out = Vec::with_capacity(corpus.len() * PROFILES.len());
    for profile in PROFILES {
        let svc = sql_only_service(profile);
        for (index, row) in corpus.iter().enumerate() {
            out.push(RenderedRow {
                index,
                profile,
                sql: render(&svc, &row.q, scope).await,
            });
        }
    }
    out
}

fn digest(s: &str) -> String {
    hex::encode(&Sha256::digest(s.as_bytes())[..12])
}

#[tokio::test]
async fn npl_golden_corpus_sql_is_unchanged() {
    let corpus = load_corpus();
    assert!(corpus.len() > 1000, "corpus unexpectedly small: {}", corpus.len());
    let rendered = render_corpus(&corpus, &ScopeSet::unrestricted()).await;
    let actual: Vec<ExpectedRow> = rendered
        .iter()
        .map(|r| ExpectedRow {
            i: r.index,
            p: r.profile.to_string(),
            h: digest(&r.sql),
        })
        .collect();

    if let Ok(path) = std::env::var("NPL_GOLDEN_DUMP") {
        let body: String = rendered
            .iter()
            .map(|r| {
                let v = serde_json::json!({
                    "i": r.index, "p": r.profile, "src": corpus[r.index].src,
                    "q": corpus[r.index].q, "sql": r.sql,
                });
                format!("{v}\n")
            })
            .collect();
        std::fs::write(&path, body).unwrap_or_else(|e| panic!("write {path}: {e}"));
    }

    if std::env::var("NPL_GOLDEN_UPDATE").as_deref() == Ok("1") {
        let body: String = actual
            .iter()
            .map(|r| format!("{}\n", serde_json::to_string(r).unwrap()))
            .collect();
        std::fs::write(expected_path(), body).expect("write expected.jsonl");
        return;
    }

    let expected: Vec<ExpectedRow> = std::fs::read_to_string(expected_path())
        .unwrap_or_else(|e| panic!("read {}: {e}", expected_path().display()))
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("bad expected row"))
        .collect();
    assert_eq!(expected.len(), actual.len(), "corpus and expected.jsonl are out of step");

    let diffs: Vec<String> = expected
        .iter()
        .zip(&actual)
        .filter(|(e, a)| e != a)
        .map(|(_, a)| format!("[{} #{}] {}", a.p, a.i, corpus[a.i].q))
        .collect();
    assert!(
        diffs.is_empty(),
        "{} generated-SQL change(s) vs the golden corpus. Review each with \
         NPL_GOLDEN_DUMP at the old and new commit; only then refresh with \
         NPL_GOLDEN_UPDATE=1:\n{}",
        diffs.len(),
        diffs.join("\n")
    );
}

/// Layer 2 (security review 2026-11-08): the log-only tripwire must stay
/// silent on every legitimate query before it can ever be enforced.
#[tokio::test]
async fn npl_golden_corpus_never_trips_the_generated_sql_tripwire() {
    let corpus = load_corpus();
    let rendered = render_corpus(&corpus, &ScopeSet::unrestricted()).await;
    let hits: Vec<String> = rendered
        .iter()
        .filter(|r| !r.sql.starts_with("ERR:"))
        .filter_map(|r| {
            // `explain` appends `-- Note:` lines that never execute; drop them.
            let executed = r.sql.split("\n\n-- Note").next().unwrap_or_default();
            let hits = crate::query::generated_sql_tripwire::check(executed);
            (!hits.is_empty()).then(|| {
                format!("[{} #{}] {:?} {}", r.profile, r.index, hits, corpus[r.index].q)
            })
        })
        .collect();
    assert!(hits.is_empty(), "{} legitimate queries trip:\n{}", hits.len(), hits.join("\n"));

    // Cost of the check on real generated SQL (printed with --nocapture).
    let sqls: Vec<&str> = rendered
        .iter()
        .filter(|r| !r.sql.starts_with("ERR:"))
        .map(|r| r.sql.as_str())
        .collect();
    let bytes: usize = sqls.iter().map(|s| s.len()).sum();
    let started = std::time::Instant::now();
    for sql in &sqls {
        std::hint::black_box(crate::query::generated_sql_tripwire::check(sql));
    }
    let elapsed = started.elapsed();
    eprintln!(
        "tripwire: {} queries, {} KiB total, max {} KiB, {:.1} µs/query mean (debug build)",
        sqls.len(),
        bytes / 1024,
        sqls.iter().map(|s| s.len()).max().unwrap_or(0) / 1024,
        elapsed.as_secs_f64() * 1e6 / sqls.len().max(1) as f64
    );
}
