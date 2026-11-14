// SPDX-License-Identifier: AGPL-3.0-or-later
//! The IR/SOC benchmark corpora must stay valid on their schema profile.
//!
//! `benchmarks/results/soc_ir_corpus.json` (OCSF, the default profile) and
//! `benchmarks/results/soc_ir_corpus_udm.json` (UDM) are replayed by the k6
//! benchmarks and the public benchmark kit. A query that no longer compiles
//! on its profile shows up there as an analyst error. The v2.0.23 dry run
//! (NAN-5414) counted three 400s from UDM-only syntax in the corpus:
//! `auth_type=RemoteInteractive` twice, and `eventstats … by uri_path`.
//!
//! Every query is rendered through [`SearchService::explain`] — the same
//! parse → field validation → codegen path an executed search takes — with
//! no database. The checks:
//!
//! - every query compiles on its profile (no `ERR:`);
//! - no OCSF query reads the `unmapped` spill: a UDM-era name with no OCSF
//!   column falls through to `unmapped.<name>`, compiles, and silently matches
//!   nothing (what `uri_path` did outside `eventstats`);
//! - both files carry the same use cases in the same order, so the two
//!   profiles benchmark the same hunts.
//!
//! Runtime ClickHouse errors (a type error on a column, an unknown identifier
//! in a stage) need a ClickHouse to surface; the PR that changes the corpus
//! should run it once against a real store.

use super::npl_golden_corpus_tests::{render, sql_only_service};
use crate::auth::ScopeSet;
use std::path::PathBuf;

/// Queries in each corpus. Changing the corpus size is deliberate: update it.
const CORPUS_QUERIES: usize = 94;

struct CorpusQuery {
    index: usize,
    use_case: String,
    query: String,
}

fn corpus_path(file: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../benchmarks/results").join(file)
}

/// Load a corpus file and check its declared profile.
fn load(file: &str, profile: &str) -> Vec<CorpusQuery> {
    let path = corpus_path(file);
    let body = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let json: serde_json::Value =
        serde_json::from_str(&body).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));
    assert_eq!(json["profile"], profile, "{file}: declared profile");
    let domains = json["domains"].as_array().unwrap_or_else(|| panic!("{file}: no domains"));
    let mut out = Vec::new();
    for domain in domains {
        let key = domain["key"].as_str().unwrap_or_default();
        for q in domain["queries"].as_array().unwrap_or_else(|| panic!("{file}/{key}: no queries")) {
            out.push(CorpusQuery {
                index: out.len() + 1,
                use_case: q["use_case"].as_str().unwrap_or_default().to_string(),
                query: q["query"]
                    .as_str()
                    .unwrap_or_else(|| panic!("{file}/{key}: query without text"))
                    .to_string(),
            });
        }
    }
    assert_eq!(out.len(), CORPUS_QUERIES, "{file}: query count");
    out
}

/// Render every query on `profile`; return `(query, sql)` pairs.
async fn render_all(corpus: &[CorpusQuery], profile: &str) -> Vec<(usize, String, String)> {
    let svc = sql_only_service(profile);
    let mut out = Vec::with_capacity(corpus.len());
    for q in corpus {
        out.push((q.index, q.query.clone(), render(&svc, &q.query, &ScopeSet::unrestricted()).await));
    }
    out
}

fn compile_failures(rendered: &[(usize, String, String)]) -> Vec<String> {
    rendered
        .iter()
        .filter(|(_, _, sql)| sql.starts_with("ERR:"))
        .map(|(i, q, sql)| format!("#{i} {q}\n    {sql}"))
        .collect()
}

#[tokio::test]
async fn ocsf_corpus_compiles_on_the_ocsf_profile() {
    let corpus = load("soc_ir_corpus.json", "ocsf");
    let rendered = render_all(&corpus, "ocsf").await;
    let failures = compile_failures(&rendered);
    assert!(
        failures.is_empty(),
        "{} OCSF corpus queries fail on the OCSF query path:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[tokio::test]
async fn ocsf_corpus_never_reads_the_unmapped_spill() {
    let corpus = load("soc_ir_corpus.json", "ocsf");
    let spill = regex::Regex::new(r#"unmapped\.(?:\^)?"([^"]+)""#).expect("static regex");
    let hits: Vec<String> = render_all(&corpus, "ocsf")
        .await
        .into_iter()
        .filter_map(|(i, q, sql)| {
            let mut names: Vec<&str> = spill.captures_iter(&sql).map(|c| c.get(1).unwrap().as_str()).collect();
            names.sort_unstable();
            names.dedup();
            (!names.is_empty()).then(|| format!("#{i} reads unmapped {names:?}: {q}"))
        })
        .collect();
    assert!(
        hits.is_empty(),
        "OCSF corpus queries use names with no OCSF column (they match nothing):\n{}",
        hits.join("\n")
    );
}

#[tokio::test]
async fn udm_corpus_compiles_on_the_udm_profile() {
    let corpus = load("soc_ir_corpus_udm.json", "udm");
    let rendered = render_all(&corpus, "udm").await;
    let failures = compile_failures(&rendered);
    assert!(
        failures.is_empty(),
        "{} UDM corpus queries fail on the UDM query path:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn corpora_stay_in_step() {
    let ocsf = load("soc_ir_corpus.json", "ocsf");
    let udm = load("soc_ir_corpus_udm.json", "udm");
    for (o, u) in ocsf.iter().zip(&udm) {
        assert_eq!(o.use_case, u.use_case, "#{}: the corpora list different hunts", o.index);
    }
}

/// The three queries the v2.0.23 dry run failed with 400s (NAN-5414), plus
/// the NAN-5416 regex on an Int64 column, must keep their OCSF rewrite.
#[test]
fn dry_run_failures_stay_fixed() {
    let ocsf = load("soc_ir_corpus.json", "ocsf");
    for q in &ocsf {
        assert!(!q.query.contains("auth_type=RemoteInteractive"), "#{}: {}", q.index, q.query);
        assert!(!q.query.contains("uri_path"), "#{}: {}", q.index, q.query);
        assert!(!q.query.contains("enriched_src_asn=/"), "#{}: {}", q.index, q.query);
    }
}
