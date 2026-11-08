// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4926: the enterprise risk features (watchlists, watchlist entity
//! suggestions, the entity risk timeline) live in `nanosiem-enterprise`.
//! `nanosiem-core` ships to the open-core mirror wholesale, so it may carry
//! only the neutral read-time score-weight plumbing those features bind
//! (`risk::score_weights`, the `RiskScoreWeightsSource` hook). This test fails
//! the moment their implementation, permission or audit vocabulary is
//! reintroduced anywhere under `nanosiem-core/src`.

use std::path::Path;

/// Case-insensitive markers of the enterprise implementations.
const FORBIDDEN: &[&str] = &[
    "watchlist",
    "risk:watchlists",
    "rule_timeline_buckets",
    "risktimelinebucket",
    "entityrisktimeline",
    "suggest_query",
    "riskSuggest",
    "risksuggest",
];

fn scan(dir: &Path, hits: &mut Vec<String>) {
    for entry in std::fs::read_dir(dir).expect("read nanosiem-core/src") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            scan(&path, hits);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            let text = std::fs::read_to_string(&path).expect("read source").to_lowercase();
            for marker in FORBIDDEN {
                if text.contains(&marker.to_lowercase()) {
                    hits.push(format!("{} contains `{marker}`", path.display()));
                }
            }
        }
    }
}

#[test]
fn core_carries_no_enterprise_risk_implementation() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut hits = Vec::new();
    scan(&src, &mut hits);
    assert!(
        hits.is_empty(),
        "enterprise risk code leaked into the open core:\n{}",
        hits.join("\n")
    );
    // The enterprise modules must not come back as core modules either.
    for module in ["watchlist.rs", "watchlist_suggest.rs", "timeline.rs"] {
        assert!(
            !src.join("risk").join(module).exists(),
            "nanosiem-core/src/risk/{module} belongs in nanosiem-enterprise"
        );
    }
}
