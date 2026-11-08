// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4917 regression tests: chained-eval / deep-expression stack safety and
//! the alias-inlined complexity budget.

use super::*;
use crate::query::{parse_query, ClickHouseSqlGenerator, PrettyPrint, TimeRange};

fn tr() -> TimeRange {
    TimeRange {
        start: "2024-01-01T00:00:00Z".parse().unwrap(),
        end: "2024-01-02T00:00:00Z".parse().unwrap(),
    }
}

/// `stages` chained evals, each wrapping the previous field in `depth` nested
/// `md5(...)` calls — the shape from the NAN-4917 report (6×20).
fn hash_chain(stages: usize, depth: usize) -> String {
    let mut q = String::from("*");
    let mut prev = "src_ip".to_string();
    for s in 0..stages {
        let mut e = prev.clone();
        for _ in 0..depth {
            e = format!("md5({e})");
        }
        q.push_str(&format!(" | eval h{s}={e}"));
        prev = format!("h{s}");
    }
    q
}

/// `stages` chained evals, each referencing the previous field `refs` times —
/// multiplicative growth once ClickHouse substitutes the aliases.
fn fanout_chain(stages: usize, refs: usize, single_eval: bool) -> String {
    let mut prev = "src_ip".to_string();
    let mut parts = Vec::new();
    for s in 0..stages {
        parts.push(format!("h{s}=md5({})", vec![prev.as_str(); refs].join(" . ")));
        prev = format!("h{s}");
    }
    if single_eval {
        format!("* | eval {}", parts.join(", "))
    } else {
        format!("* | eval {}", parts.join(" | eval "))
    }
}

fn assert_too_complex(q: &str) {
    match parse_query(q) {
        Ok(_) => panic!("expected a complexity rejection for query of {} bytes", q.len()),
        Err(e) => assert!(
            e.message.contains("Query too complex") || e.message.contains("TooLarge"),
            "unexpected error: {}",
            e.message
        ),
    }
}

/// Run `f` on a deliberately small thread stack. Before NAN-4917 the shapes
/// below needed 0.9-16 MiB (debug); a regression aborts the test process.
fn on_small_stack<R: Send + 'static>(f: impl FnOnce() -> R + Send + 'static) -> R {
    std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(f)
        .unwrap()
        .join()
        .unwrap()
}

#[test]
fn reported_6x20_hash_chain_is_rejected() {
    assert_too_complex(&hash_chain(6, 20));
}

#[test]
fn larger_hash_chains_are_rejected() {
    assert_too_complex(&hash_chain(10, 30));
    assert_too_complex(&hash_chain(25, 49));
}

#[test]
fn multiplicative_alias_fanout_is_rejected() {
    assert_too_complex(&fanout_chain(6, 20, false));
    assert_too_complex(&fanout_chain(6, 20, true));
    // Fan-out of 2 over every allowed pipe stage: 2^24 nodes once inlined.
    assert_too_complex(&fanout_chain(24, 2, false));
}

#[test]
fn rejection_happens_on_small_stack_without_overflow() {
    on_small_stack(|| {
        assert_too_complex(&hash_chain(6, 20));
        assert_too_complex(&fanout_chain(6, 20, false));
    });
}

#[test]
fn rename_carries_alias_size() {
    // `rename` re-exposes the same expression under a new name.
    let mut q = String::from("* | eval a=md5(src_ip . src_ip . src_ip . src_ip . src_ip . src_ip . src_ip . src_ip . src_ip . src_ip)");
    for i in 0..5 {
        let prev = if i == 0 { "a".to_string() } else { format!("b{}", i - 1) };
        q.push_str(&format!(" | rename {prev} as r{i} | eval b{i}=md5({})", vec![format!("r{i}"); 10].join(" . ")));
    }
    assert_too_complex(&q);
}

#[test]
fn where_referencing_huge_alias_many_times_is_rejected() {
    // Each alias stays under budget on its own, but the where clause copies it
    // per reference.
    let q = format!(
        "{} | where {}",
        fanout_chain(3, 20, false), // h2 ≈ 20^3 = 8000 nodes
        vec!["h2=\"x\""; 20].join(" OR ")
    );
    assert_too_complex(&q);
}

#[test]
fn normal_eval_chains_are_unchanged() {
    let queries = [
        "* | eval a=lower(user) | eval b=a . \"-x\" | eval c=if(len(b) > 3, b, \"short\")",
        "* | eval total=bytes_in + bytes_out | eval mb=round(total / 1048576, 2) | where mb > 10",
        "* | eval h=sha256(lower(trim(command_line))) | stats count by h",
        "* | eval d=extract_domain(url), dd=defang(d), b=base64_decode(dd) | table d, dd, b",
        "* | eval x=md5(src_ip . dest_ip) | eval y=md5(x . x) | eval z=md5(y . y)",
    ];
    let gen = ClickHouseSqlGenerator::new();
    for q in queries {
        let parsed = parse_query(q).unwrap_or_else(|e| panic!("{q}: {e:?}"));
        gen.generate(&parsed, &tr())
            .unwrap_or_else(|e| panic!("{q}: {e:?}"));
    }
}

#[test]
fn parser_max_single_expression_still_accepted() {
    // A single expression at the parser's own nesting cap (49 < 50) is legal.
    let q = hash_chain(1, 49);
    let parsed = parse_query(&q).expect("49-deep single expression parses");
    ClickHouseSqlGenerator::new().generate(&parsed, &tr()).unwrap();
}

#[test]
fn full_length_chain_still_accepted() {
    // MAX_CHAIN_LEN (1024) terms remains legal — big IOC-style OR lists.
    let terms: Vec<String> = (0..1024).map(|i| format!("src_port={i}")).collect();
    parse_query(&terms.join(" OR ")).expect("1024-term OR chain parses");
    parse_query(&format!("* | where {}", terms.join(" OR "))).expect("1024-term where parses");
}

#[test]
fn stacked_grouped_chains_exceed_ast_depth() {
    // A left-nested group of a long chain inside another long chain: each level
    // adds a full chain to the AST spine (parser nesting cap alone allowed
    // ~50 × 1024 levels).
    let chain = vec!["src_port=1"; 1000].join(" AND ");
    let q = format!("(({chain}) AND {chain}) AND {chain}");
    assert_too_complex(&q);
}

#[test]
fn nested_append_subsearches_count_toward_nesting() {
    let mut q = String::from("error");
    for _ in 0..60 {
        q = format!("* | append [{q}]");
    }
    assert!(parse_query(&q).is_err(), "60 nested append subsearches must be rejected");
    let mut q = String::from("error");
    for _ in 0..60 {
        q = format!("* | join src_ip [{q}]");
    }
    assert!(parse_query(&q).is_err(), "60 nested join subsearches must be rejected");
}

/// Worst-case shapes the budget still ADMITS must compile and pretty-print on
/// a small stack (the in-memory evaluator has its own test in
/// `post_processing/deep_expression_stack_tests.rs`): every recursive walk is either guarded by
/// `ensure_sufficient_stack` or bounded by `MAX_AST_DEPTH`.
#[test]
fn admitted_worst_cases_survive_small_stack() {
    on_small_stack(|| {
        let and_chain: Vec<String> = (0..1024).map(|i| format!("src_port>{i}")).collect();
        let plus_chain = vec!["src_port"; 1024].join(" + ");
        let mut nested_if = "src_ip".to_string();
        for _ in 0..49 {
            nested_if = format!("if(src_port>1, {nested_if}, \"a\")");
        }
        let mut nested_paren = "src_port=1".to_string();
        for _ in 0..48 {
            nested_paren = format!("({nested_paren} OR src_port=2)");
        }
        let queries = vec![
            and_chain.join(" AND "),
            format!("* | where {}", and_chain.join(" AND ")),
            format!("* | eval x={plus_chain} | where x > 3"),
            format!("* | eval x={nested_if}"),
            hash_chain(1, 49),
            nested_paren,
        ];
        let gen = ClickHouseSqlGenerator::new();
        for q in queries {
            let parsed = parse_query(&q).unwrap_or_else(|e| panic!("{e:?}"));
            gen.generate(&parsed, &tr()).unwrap();
            let printed = parsed.pretty_print();
            assert!(!printed.is_empty());
        }
    });
}

/// Property-style sweep over alias-chain shapes: whatever the parser admits
/// generates SQL whose size is LINEAR in the query text (nano never inlines
/// aliases itself — each eval is its own CTE stage), and whatever ClickHouse
/// would inline stays under the node budget.
#[test]
fn alias_chain_sweep_bounds_generated_sql() {
    let gen = ClickHouseSqlGenerator::new();
    // Fixed per-query SQL overhead (base CTE projection list etc.).
    let baseline = gen
        .generate(&parse_query("*").unwrap(), &tr())
        .unwrap()
        .len();
    let mut admitted = 0;
    let mut rejected = 0;
    for stages in 1..=8usize {
        for refs in 1..=5usize {
            for depth in [1usize, 4, 12, 30] {
                for q in [
                    fanout_chain(stages, refs, false),
                    fanout_chain(stages, refs, true),
                    hash_chain(stages, depth),
                ] {
                    match parse_query(&q) {
                        Ok(parsed) => {
                            admitted += 1;
                            let sql = gen.generate(&parsed, &tr()).unwrap();
                            assert!(
                                sql.len() <= baseline + 64 * q.len() + 4096,
                                "SQL grew super-linearly: query {} bytes -> SQL {} bytes",
                                q.len(),
                                sql.len()
                            );
                            check_query_complexity(&parsed).unwrap();
                        }
                        Err(e) => {
                            rejected += 1;
                            assert!(e.message.contains("Query too complex"), "{}", e.message);
                        }
                    }
                }
            }
        }
    }
    assert!(admitted > 0 && rejected > 0, "sweep must exercise both sides");
}

// ---------------------------------------------------------------------------
// Review follow-ups (codex pass on 899b697d4)
// ---------------------------------------------------------------------------

fn inner_pipeline(stages: usize) -> String {
    format!("error{}", " | head 1".repeat(stages))
}

/// P1-1: the 25-stage cap applies inside every subsearch, not just the root
/// spine, and an attacker-sized inner pipeline is rejected without overflow.
#[test]
fn subsearch_pipelines_are_stage_capped() {
    on_small_stack(|| {
        for stages in [26usize, 20_000] {
            let inner = inner_pipeline(stages);
            for q in [
                format!("* | append [{inner}]"),
                format!("* | join src_ip [{inner}]"),
                format!("src_ip IN [{inner}]"),
            ] {
                let err = parse_query(&q).expect_err("over-long subsearch pipeline must be rejected");
                assert!(
                    err.message.contains("maximum 25 pipe commands"),
                    "{stages} stages: {}",
                    err.message
                );
            }
        }
        // 25 inner stages is still legal.
        parse_query(&format!("* | append [{}]", inner_pipeline(24))).expect("24 inner stages");
        // Root spine keeps its message.
        let err = parse_query(&inner_pipeline(20_000)).unwrap_err();
        assert!(err.message.contains("maximum 25 pipe commands"), "{}", err.message);
    });
}

#[test]
fn subsearch_breadth_is_bounded_query_wide() {
    // 25 root stages, each an append carrying a 24-stage subsearch: every
    // pipeline is individually legal, the whole query is not.
    let inner = inner_pipeline(23);
    let q = format!("error{}", format!(" | append [{inner}]").repeat(25));
    let err = parse_query(&q).unwrap_err();
    assert!(err.message.contains("pipe commands across the query"), "{}", err.message);
}

/// P1-2: a tree combining the maximum legal paren nesting with long chains at
/// every eval precedence level must be rejected before it is materialized
/// (its recursive Drop would overflow), on a small caller stack.
#[test]
fn max_nesting_times_chain_lengths_rejected_without_materializing() {
    on_small_stack(|| {
        let chain = |op: &str, term: &str, n: usize| format!(" {op} {term}").repeat(n);
        let mut e = "src_port".to_string();
        for _ in 0..40 {
            e = format!(
                "({e}{}{}{}{}{})",
                chain(".", "a", 1000),
                chain("*", "2", 1000),
                chain("+", "3", 1000),
                chain("AND", "b", 1000),
                chain("OR", "c", 1000),
            );
        }
        let q = format!("* | eval x={e}");
        assert!(q.len() < 1_048_576, "query must stay under the length cap");
        let err = parse_query(&q).expect_err("must be rejected");
        assert!(err.message.contains("chained operators"), "{}", err.message);
        // Same shape in a where clause.
        let mut w = "src_port=1".to_string();
        for _ in 0..40 {
            w = format!("({w}{}{})", chain("AND", "a=1", 1000), chain("OR", "b=2", 1000));
        }
        let err = parse_query(&format!("* | where {w}")).expect_err("must be rejected");
        assert!(err.message.contains("chained operators"), "{}", err.message);
    });
}

fn refs(name: &str, n: usize) -> String {
    vec![name; n].join(" . ")
}

/// P1-3: `table … AS` carries lineage (does not reset it to a leaf).
#[test]
fn table_alias_carries_lineage() {
    let q = format!(
        "{} | table h2 AS t | eval d=md5({}) | table d AS u | eval e=md5({})",
        fanout_chain(3, 20, false),
        refs("t", 20),
        refs("u", 20)
    );
    assert_too_complex(&q);
    // Same through rename and bin aliases.
    let q = format!(
        "{} | rename h2 as t | eval d=md5({})",
        fanout_chain(3, 20, false),
        refs("t", 20)
    );
    assert_too_complex(&q);
}

/// P1-3: a projection that re-binds an old alias name to a cheap field shadows
/// the stale lineage; projected-out and aggregated names reset.
#[test]
fn projection_shadows_and_resets_lineage() {
    let gen = ClickHouseSqlGenerator::new();
    for q in [
        format!("{} | table src_ip AS h2 | eval d=md5({})", fanout_chain(3, 20, false), refs("h2", 20)),
        format!("{} | fields - h2 | eval d=md5({})", fanout_chain(3, 20, false), refs("h2", 20)),
        format!("{} | fields src_ip | eval d=md5({})", fanout_chain(3, 20, false), refs("h2", 20)),
        format!("{} | stats count by src_ip | eval d=md5({})", fanout_chain(3, 20, false), refs("h2", 20)),
        format!("{} | eval h2=src_ip | eval d=md5({})", fanout_chain(3, 20, false), refs("h2", 20)),
    ] {
        let parsed = parse_query(&q).unwrap_or_else(|e| panic!("{q}: {}", e.message));
        gen.generate(&parsed, &tr()).unwrap();
    }
}

/// P1-3: field-only consumers are charged at inlined size.
#[test]
fn field_only_consumers_count_toward_budget() {
    let big = fanout_chain(3, 20, false); // h2 ≈ 16k nodes
    let many = |sep: &str, n: usize| vec!["h2"; n].join(sep);
    assert_too_complex(&format!("{big} | sort {}", many(", ", 30)));
    assert_too_complex(&format!("{big} | dedup {}", many(", ", 30)));
    assert_too_complex(&format!("{big} | stats count by {}", many(", ", 30)));
}

/// P2-4: individually legal references to one large alias still exceed the
/// query-wide expanded-node budget.
#[test]
fn query_wide_expanded_node_budget() {
    let outs: Vec<String> = (1..=31).map(|i| format!("o{i}=h2")).collect();
    let q = format!("{} | eval {}", fanout_chain(3, 20, false), outs.join(", "));
    let err = parse_query(&q).unwrap_err();
    assert!(err.message.contains("Query too complex"), "{}", err.message);
    // A handful of references stays legal.
    let q = format!("{} | eval o1=h2, o2=h2", fanout_chain(3, 20, false));
    parse_query(&q).expect("two references fit the budget");
}
