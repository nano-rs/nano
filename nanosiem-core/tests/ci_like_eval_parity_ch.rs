// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4943 × NAN-4933: an nPL predicate means the same thing wherever it
//! runs. For every predicate class (substring / LIKE / regex — literal,
//! anchored, alternation, real RE2 — string `=` / `!=`, `IN` / `NOT IN` on
//! scalars and arrays, bare / wildcard keywords, field-vs-function equality)
//! these paths must return identical rows, on ClickHouse 26.10 with the
//! production `logs` / `ocsf_logs` DDL:
//!
//! 1. the canonical SQL (`| where P`, or the search term for keywords);
//! 2. eval / `if()` SQL (`eval m=if(P, 1, 0)`), for eval-valid predicates;
//! 3. the predicate AFTER `| prevalence`, pushed down: the prevalence-join
//!    WHERE (`prevalence_where_sql`) run over the joined `l` row;
//! 4. the predicate after `| prevalence`, NOT pushed: the post-stage
//!    (Nano-side) evaluator, as `| where P`;
//! 5. the post-stage evaluator as `eval m=if(P, 1, 0)`.
//!
//! Each class pins mixed-case ASCII parity plus the documented outcomes for
//! U+017F LONG S, U+212A KELVIN SIGN, `Ä` and Cyrillic (`ci_like`).
//!
//! ```text
//! NANOSIEM_TEST_CLICKHOUSE_URL=http://127.0.0.1:8123 NANOSIEM_TEST_CLICKHOUSE_USER=default \
//!   cargo test -p nanosiem-core --test ci_like_eval_parity_ch
//! ```
//! Without `NANOSIEM_TEST_CLICKHOUSE_URL` the test returns early.
#[path = "npl_wrong_answer_ch/harness.rs"]
mod harness;
use harness::*;

use std::collections::BTreeSet;

use chrono::Duration;
use nanosiem_core::query::{parse_query, Command, Query};
use serde_json::json;

/// The value each fixture row carries in `{user}` and (one element) `{tags}`;
/// its `message` is `run <value> now`.
const VALUES: &[&str] = &[
    "MimiKatz", "mimikatz", "MIMIKATZ", "Kerberos", "KERBEROS", "kerberos", "50%_Off", "50x_off",
    "svchost", "\u{17F}vchost", "\u{212A}elvin", "kelvin", "Äbc", "äbc", "Жук", "жук",
];

fn set(v: &[&str]) -> BTreeSet<String> {
    v.iter().map(|s| s.to_string()).collect()
}

fn all_but(v: &BTreeSet<String>) -> BTreeSet<String> {
    VALUES.iter().map(|s| s.to_string()).filter(|s| !v.contains(s)).collect()
}

/// Case-insensitive ASCII match of each value against a LIKE `pattern` — the
/// expectation for mixed-case ASCII, computed independently of the generator.
fn ascii_like(pattern: &str) -> BTreeSet<String> {
    let mut re = String::from("^");
    for c in pattern.to_ascii_lowercase().chars() {
        match c {
            '%' => re.push_str(".*"),
            '_' => re.push('.'),
            c => re.push_str(&regex::escape(&c.to_string())),
        }
    }
    re.push('$');
    let re = regex::Regex::new(&re).unwrap();
    VALUES.iter().filter(|v| re.is_match(&v.to_ascii_lowercase())).map(|v| v.to_string()).collect()
}

async fn add_rows(ch: &Ch) {
    let ts = (t0() + Duration::minutes(5)).format("%Y-%m-%d %H:%M:%S%.3f").to_string();
    for p in BOTH {
        let rows: Vec<String> = VALUES
            .iter()
            .enumerate()
            .map(|(i, v)| {
                let message = format!("run {v} now");
                match p {
                    Profile::Udm => json!({"timestamp": ts, "source_type": "ci4943", "user": v, "message": message}),
                    Profile::Ocsf => json!({
                        "timestamp": ts, "source_type": "ci4943", "class_uid": 4001,
                        "metadata.uid": format!("ci-{i:02}"), "actor.user.name": v, "message": message,
                        "resources.type": [v], "resources.uid": [format!("r{i}")], "resources.name": [format!("n{i}")],
                    }),
                }
                .to_string()
            })
            .collect();
        ch.insert(p, &rows).await;
    }
}

/// The `{user}` values of the rows a query returns.
async fn user_rows(ch: &Ch, p: Profile, q: &str) -> BTreeSet<String> {
    let user = f(p, "user");
    let q = npl(p, &format!("{q} | stats count by {user}"));
    let sql = ch.sql(p, &q, &window()).unwrap();
    assert!(!sql.contains("iLike") && !sql.contains("positionCaseInsensitive"), "{p:?} `{q}`:\n{sql}");
    ch.rows(p, &q).await.iter().map(|r| s(r, user)).collect()
}

/// The single `| where` / `| search` / `| eval` command of `* | <stage>`.
fn command(p: Profile, stage: &str) -> Command {
    match parse_query(&format!("* | {}", npl(p, stage))).unwrap() {
        Query::Piped { command, .. } => command,
        other => panic!("{other:?}"),
    }
}

/// Path 3: the prevalence pushdown WHERE over the joined `l` row, on CH.
async fn prevalence_pushed(ch: &Ch, p: Profile, stage: &str) -> BTreeSet<String> {
    let Command::Where { condition } = command(p, stage) else { panic!("{stage}: not a where") };
    let gen = ch.generator(p);
    let pred = nanosiem_core::search::prevalence_where_sql(&gen, &condition)
        .unwrap_or_else(|e| panic!("{p:?} `{stage}`: {e:?}"));
    assert!(!pred.contains("iLike") && !pred.contains("(?i)kelvin"), "{p:?} `{stage}`: {pred}");
    // The rows a prevalence query joins are the base search's own rows.
    let base = ch.sql(p, r#"source_type="ci4943""#, &window()).unwrap();
    let user = f(p, "user");
    let sql = format!("SELECT `{user}` AS u FROM ({base}) AS l WHERE {pred}");
    ch.try_rows(&sql)
        .await
        .unwrap_or_else(|e| panic!("{p:?} `{stage}`: {e}\n{sql}"))
        .iter()
        .map(|r| s(r, "u"))
        .collect()
}

/// Paths 4/5: the post-stage evaluator over the same rows.
fn nano_rows(p: Profile, stage: &str) -> BTreeSet<String> {
    let (user, tags) = (f(p, "user"), f(p, "tags"));
    let rows = VALUES
        .iter()
        .map(|v| json!({ user: v, tags: [v], "message": format!("run {v} now") }))
        .collect();
    let out = nanosiem_core::search::apply_post_prevalence_commands(rows, &[command(p, stage)])
        .unwrap_or_else(|e| panic!("{stage}: {e:?}"));
    out.results
        .iter()
        .filter(|r| r.get("m").is_none_or(|m| m.as_f64() == Some(1.0)))
        .map(|r| r[user].as_str().unwrap().to_string())
        .collect()
}

struct Case {
    /// The predicate, with `{F}` for the target field.
    pred: &'static str,
    want: BTreeSet<String>,
    /// Also valid inside `eval` / `if()`.
    eval: bool,
    /// Also run against the OCSF array field (`resources.type`).
    array: bool,
    /// A search term (keyword), run as `| search P` instead of `| where P`.
    keyword: bool,
}

fn case(pred: &'static str, want: BTreeSet<String>) -> Case {
    Case { pred, want, eval: true, array: true, keyword: false }
}

#[tokio::test]
async fn every_predicate_class_agrees_across_sql_eval_prevalence_and_post_stage() {
    let Some(ch) = Ch::connect("ci4943eval").await else { return };
    add_rows(&ch).await;
    let kerberos = ascii_like("kerberos");
    let mimikatz = ascii_like("mimikatz");
    let cases = vec![
        // Substring / LIKE.
        case(r#"{F} CONTAINS "MimiKatz""#, ascii_like("%mimikatz%")),
        case(r#"{F} CONTAINS "50%_off""#, set(&["50%_Off"])),
        case(r#"{F} LIKE "KERB%""#, ascii_like("kerb%")),
        case(r#"{F} LIKE "50%_off""#, set(&["50%_Off", "50x_off"])),
        Case { array: false, ..case(r#"like({F}, "%ATZ")"#, ascii_like("%atz")) },
        case(r#"{F} CONTAINS "kelvin""#, set(&["kelvin"])),
        case(r#"{F} CONTAINS "svchost""#, set(&["svchost"])),
        case(r#"{F} CONTAINS "ÄBC""#, set(&["Äbc"])),
        Case { array: false, ..case(r#"like({F}, "ж%")"#, set(&["жук"])) },
        // Regex: literal / anchored / alternation are the lowercase match;
        // a real regex stays RE2 (`(?i)` folds U+212A onto k there).
        case(r#"{F}=/kelvin/"#, set(&["kelvin"])),
        case(r#"{F}!=/kelvin/"#, all_but(&set(&["kelvin"]))),
        case(r#"{F}=/^KERB/"#, kerberos.clone()),
        case(r#"{F}=/(mimikatz|kerberos)/"#, mimikatz.union(&kerberos).cloned().collect()),
        case(r#"{F}=/k.lvin/"#, set(&["kelvin", "\u{212A}elvin"])),
        // String equality.
        case(r#"{F}="KERBEROS""#, kerberos.clone()),
        case(r#"{F}!="KERBEROS""#, all_but(&kerberos)),
        case(r#"{F}="ÄBC""#, set(&["Äbc"])),
        // IN lists.
        case(r#"{F} IN ("MIMIKATZ", "ÄBC")"#, mimikatz.union(&set(&["Äbc"])).cloned().collect()),
        case(r#"{F} NOT IN ("MIMIKATZ", "ÄBC")"#, all_but(&mimikatz.union(&set(&["Äbc"])).cloned().collect())),
        // Field vs function (string equality folds both sides).
        Case { eval: false, array: false, ..case(r#"{F}=lower("KERBEROS")"#, kerberos.clone()) },
        Case { eval: false, array: false, ..case(r#"{F}!=lower("KERBEROS")"#, all_but(&kerberos)) },
        Case { eval: false, array: false, ..case(r#"{F}=lower("ÄBC")"#, set(&["Äbc"])) },
        // Keywords over the body (`message = "run <v> now"`).
        Case { eval: false, array: false, keyword: true, ..case("MimiKatz", mimikatz.clone()) },
        Case { eval: false, array: false, keyword: true, ..case("svch*", set(&["svchost"])) },
        Case { eval: false, array: false, keyword: true, ..case("*ATZ", mimikatz.clone()) },
        Case { eval: false, array: false, keyword: true, ..case("*imika*", mimikatz.clone()) },
        Case { eval: false, array: false, keyword: true, ..case("kelvin", set(&["kelvin"])) },
        Case { eval: false, array: false, keyword: true, ..case("ÄBC", set(&["Äbc"])) },
    ];

    let mut bad = Vec::new();
    let mut check = |p: Profile, path: &str, pred: &str, got: BTreeSet<String>, want: &BTreeSet<String>| {
        if &got != want {
            bad.push(format!("{p:?} {path} `{}`: {got:?} != {want:?}", npl(p, pred)));
        }
    };
    for p in BOTH {
        for c in &cases {
            let mut targets = vec!["{user}"];
            // OCSF `resources.type` keeps its case at rest (UDM `tags` are
            // lowercase), so the array forms run on OCSF.
            if c.array && p == Profile::Ocsf {
                targets.push("{tags}");
            }
            for target in targets {
                let pred = c.pred.replace("{F}", target);
                let stage = if c.keyword { format!("search {pred}") } else { format!("where {pred}") };
                let canonical = if c.keyword {
                    format!(r#"source_type="ci4943" {pred}"#)
                } else {
                    format!(r#"source_type="ci4943" | where {pred}"#)
                };
                check(p, "canonical SQL", &pred, user_rows(&ch, p, &canonical).await, &c.want);
                check(p, "prevalence pushed", &pred, prevalence_pushed(&ch, p, &stage).await, &c.want);
                check(p, "post-stage where", &pred, nano_rows(p, &stage), &c.want);
                if c.eval {
                    let eval = format!("eval m=if({pred}, 1, 0)");
                    let sql_if = user_rows(&ch, p, &format!(r#"source_type="ci4943" | {eval} | where m=1"#)).await;
                    check(p, "eval/if SQL", &pred, sql_if, &c.want);
                    check(p, "post-stage eval", &pred, nano_rows(p, &eval), &c.want);
                }
            }
        }
    }
    ch.drop().await;
    assert!(bad.is_empty(), "{} mismatches:\n{}", bad.len(), bad.join("\n"));
}
