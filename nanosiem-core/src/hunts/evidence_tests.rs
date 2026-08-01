// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2238 — evidence-resolution unit tests.
//!
//! These cover the parts that decide what the server is willing to believe
//! about a sweep's evidence. They are deliberately about BEHAVIOUR under a
//! hostile report (unparseable ids, a padded id list, a corrupt timestamp)
//! rather than restatements of the SQL string.

use std::collections::BTreeSet;

use chrono::{TimeZone, Utc};

use super::*;

fn resolved(sources: &[&str], unresolved: &[&str]) -> ResolvedEvidence {
    ResolvedEvidence {
        events: sources
            .iter()
            .enumerate()
            .map(|(i, s)| ResolvedEvent {
                canonical_event_id: format!("0190{i:04}-0000-7000-8000-000000000000"),
                timestamp: Utc.timestamp_opt(1_700_000_000 + i as i64, 0).unwrap(),
                source_type: s.to_string(),
                summary: String::new(),
                row: serde_json::json!({}),
                entities: BTreeSet::new(),
            })
            .collect(),
        observed_entities: BTreeSet::new(),
        unresolved: unresolved.iter().map(|s| s.to_string()).collect(),
    }
}

#[test]
fn an_unresolved_id_makes_the_whole_manifest_incomplete() {
    // The load-bearing rule: an id the server could not read is an input it
    // cannot account for. Stamping "complete for the survivors" would let a
    // lead whose narrative quotes a denied source stay readable by someone
    // denied that source.
    let clean = resolved(&["windows_security", "sysmon"], &[]);
    assert!(clean.provenance().is_complete());
    assert_eq!(
        clean.provenance().source_types(),
        &["sysmon".to_string(), "windows_security".to_string()]
    );

    let partial = resolved(&["windows_security"], &["0190aaaa-0000-7000-8000-000000000000"]);
    assert!(
        !partial.provenance().is_complete(),
        "a partially resolved evidence list claimed a complete manifest"
    );
    // The sources it DID see are still recorded — dropping them would lose
    // information without buying any safety.
    assert_eq!(
        partial.provenance().source_types(),
        &["windows_security".to_string()]
    );
}

#[test]
fn a_lead_with_no_resolvable_evidence_fails_closed() {
    // `SourceProvenance::complete` refuses an empty manifest, so this lands as
    // incomplete rather than as "provably not source-derived". Worth pinning:
    // the opposite reading would make an evidence-free lead visible to every
    // restricted reader.
    let nothing = resolved(&[], &[]);
    assert!(!nothing.provenance().is_complete());
    assert!(nothing.provenance().source_types().is_empty());
}

#[test]
fn distinct_source_types_normalizes_before_counting() {
    // Corroboration is the strongest honest factor in the score. Two spellings
    // of one source type counting as two would inflate every lead from a source
    // whose parser is inconsistent about case.
    let mixed = resolved(&["Windows_Security", "windows_security", " sysmon "], &[]);
    assert_eq!(
        mixed.distinct_source_types(),
        BTreeSet::from(["sysmon".to_string(), "windows_security".to_string()])
    );
}

/// The values a probe binds, in order, as plain strings.
fn probe_binds(probe: &EntityProbe) -> Vec<String> {
    probe
        .binds
        .iter()
        .map(|b| match b {
            Bound::Text(v) => v.clone(),
            Bound::TextList(v) => v.join(","),
        })
        .collect()
}

#[test]
fn entity_predicates_probe_only_columns_that_mean_that_entity() {
    // A hostname appearing inside a command line must not corroborate a claim
    // about a host, so the probe is column-scoped rather than a free-text
    // search.
    let host = entity_predicate("host", "SRV-Web06").expect("host is probeable");
    assert!(host.sql.contains("lower(src_host)"));
    assert!(host.sql.contains("lower(dest_host)"));
    assert!(
        !host.sql.contains("command_line") && !host.sql.contains("message"),
        "the host probe reached a free-text column"
    );

    // Unknown types have nothing honest to probe.
    assert!(entity_predicate("unicorn", "x").is_none());
}

#[test]
fn case_folding_follows_the_fingerprints_rules() {
    // Must agree with `fingerprint::CASE_INSENSITIVE_TYPES`. If the probe folds
    // a type the fingerprint does not, a lead about `/etc/Admin` gets its
    // history answered from `/etc/admin` — and the two are different files.
    //
    // The fold now happens on the BOUND value, so this reads the argument
    // rather than the text: `lower(col) = ?` with `'SRV-Web06'` bound would
    // match nothing at all while looking perfectly case-insensitive.
    let host = entity_predicate("host", "SRV-Web06").unwrap();
    assert!(host.sql.contains("lower(src_host) = ?"));
    assert!(
        probe_binds(&host).iter().all(|v| v == "srv-web06"),
        "hostnames compare folded: {:?}",
        probe_binds(&host)
    );

    let path = entity_predicate("file", "/etc/Admin").unwrap();
    assert!(
        probe_binds(&path).iter().all(|v| v == "/etc/Admin"),
        "file paths compare verbatim: {:?}",
        probe_binds(&path)
    );
    assert!(!path.sql.contains("lower("), "file paths must not be folded");
}

#[test]
fn an_entity_value_never_becomes_query_text() {
    // The value comes from a sweep report, which is downstream of
    // attacker-authored log content. Escaping it correctly was the old
    // property; the stronger one is that it is not text at all — there is no
    // literal for a payload to close, because the probe emits no literal.
    let evil = entity_predicate("file", "/tmp/a' OR 1=1 --").unwrap();
    assert!(
        !evil.sql.contains('\''),
        "the probe emitted a string literal: {}",
        evil.sql
    );
    assert!(
        !evil.sql.contains("OR 1=1"),
        "the payload reached the query text: {}",
        evil.sql
    );
    // …and it reaches the driver verbatim, undoubled and unescaped. A value
    // mangled on the way to a bind is a probe that answers a question about a
    // different entity.
    assert!(
        probe_binds(&evil)
            .iter()
            .all(|v| v == "/tmp/a' OR 1=1 --"),
        "the bound value was rewritten: {:?}",
        probe_binds(&evil)
    );
}

#[test]
fn every_placeholder_has_exactly_one_argument() {
    // A template with more `?` than arguments fails with `unbound query
    // argument`; one with fewer silently leaves an argument unused. Both are
    // runtime-only failures, and both are one edit away whenever a column is
    // added to `entity_columns`.
    for entity_type in [
        "ip", "host", "user", "domain", "hash", "process", "file", "url", "email",
    ] {
        let probe = entity_predicate(entity_type, "value").expect("probeable");
        assert_eq!(
            probe.sql.matches('?').count(),
            probe.binds.len(),
            "{entity_type}: placeholders and arguments disagree: {}",
            probe.sql
        );
        assert_eq!(
            probe.binds.len(),
            entity_columns(entity_type).len(),
            "{entity_type}: a column lost its argument"
        );
    }
}

#[test]
fn every_probe_column_exists_in_the_logs_schema() {
    // NAN-2266. `entity_columns` named `domain`, `dns_query`, `email_sender`
    // and `email_recipient` — none of which are columns on `logs` — so the
    // FIRST domain or email lead a sweep ever reported errored its prevalence
    // probe at ClickHouse (`UNKNOWN_IDENTIFIER`) and 500'd the whole report,
    // stranding the sweep's lease with six minutes of work unfiled. Every
    // shape test passed while it did, because a probe over a nonexistent
    // column assembles cleanly and only fails at the server.
    //
    // So resolve the columns against the schema the server actually creates.
    // `clickhouse/init.sql` is the canonical `logs` DDL (later migrations only
    // ADD columns, so membership here is sufficient, not merely indicative).
    let ddl = include_str!("../../../clickhouse/init.sql");
    let start = ddl
        .find("CREATE TABLE IF NOT EXISTS nanosiem.logs\n")
        .expect("logs DDL exists in clickhouse/init.sql");
    let block = &ddl[start..];
    let block = &block[..block.find("ENGINE").expect("logs DDL has an ENGINE clause")];

    let schema_columns: BTreeSet<&str> = block
        .lines()
        .filter_map(|line| {
            let line = line.trim_start();
            let name = line.strip_prefix('`')?;
            name.split('`').next()
        })
        .collect();
    assert!(
        schema_columns.len() > 50,
        "the logs column parse collapsed — found only {:?}",
        schema_columns
    );

    for entity_type in [
        "ip", "host", "user", "domain", "hash", "process", "file", "url", "email",
    ] {
        for column in entity_columns(entity_type) {
            assert!(
                schema_columns.contains(column),
                "entity_columns({entity_type:?}) names `{column}`, which is not a column \
                 on nanosiem.logs — the probe will error at ClickHouse and fail every \
                 sweep report that carries a {entity_type} lead"
            );
        }
    }
}

#[test]
fn the_scope_clause_cannot_smuggle_a_placeholder_into_the_template() {
    // The scope predicate is the one fragment still interpolated, because the
    // canonical builder (NAN-1801) returns finished SQL. Its deny values are
    // operator-configured, but a `?` in one would be read as a placeholder and
    // error every evidence lookup — the same failure a `?` in a URL used to
    // cause.
    let scoped = ClickHouseEvidenceResolver::scope_clause(&ScopeSet::from_denied(BTreeSet::from([
        "weird?source".to_string(),
    ])));
    assert!(
        scoped.contains("weird??source"),
        "a bare `?` survived into the template: {scoped}"
    );
    assert_eq!(
        ClickHouseEvidenceResolver::scope_clause(&ScopeSet::unrestricted()),
        "1 = 1",
        "an unrestricted reader must still get the one-shape tautology"
    );
}

#[test]
fn clickhouse_instants_are_typed_not_bare() {
    // A bare integer compared against DateTime64(6) is read as SECONDS and
    // silently selects the wrong window; a bare string leaves precision to
    // inference. Both have bitten this codebase before.
    let rendered = ch_instant(&Utc.timestamp_opt(1_700_000_000, 0).unwrap());
    assert!(rendered.starts_with("toDateTime64('"));
    assert!(rendered.ends_with(", 6, 'UTC')"));
}

#[test]
fn clickhouse_timestamps_parse_in_the_format_clickhouse_actually_emits() {
    // JSONEachRow renders DateTime64(6,'UTC') without a zone suffix, so
    // chrono's RFC3339 parser rejects it. Falling back to `Utc::now()` on every
    // row would silently stamp every piece of evidence with the commit time.
    let native = parse_ch_timestamp("2026-07-30 11:22:33.123456").expect("native form parses");
    assert_eq!(native.timestamp(), 1_785_410_553);
    assert!(parse_ch_timestamp("2026-07-30T11:22:33.123456Z").is_some());
    assert!(parse_ch_timestamp("not a timestamp").is_none());
}

#[test]
fn large_counts_survive_the_json_number_string_boundary() {
    // ClickHouse emits UInt64 above 2^53 as a JSON *string*; a plain `as_u64()`
    // returns None on exactly the large counts a prevalence denominator hits,
    // which would silently report "no assets in the window".
    assert_eq!(json_u64(&serde_json::json!(42)), Some(42));
    assert_eq!(
        json_u64(&serde_json::json!("18446744073709551615")),
        Some(u64::MAX)
    );
    assert_eq!(json_u64(&serde_json::json!("nope")), None);
}

#[test]
fn a_question_mark_in_an_entity_value_stays_in_the_value() {
    // The `clickhouse` crate treats a bare `?` in the TEMPLATE as a parameter
    // placeholder, even inside a string literal — which is why a URL with a
    // query string used to error every prevalence and first-seen probe out.
    //
    // A bound value is not part of the template: the driver splits the template
    // once and substitutes arguments as opaque parts, so the `?` must survive
    // UNDOUBLED. Doubling it here — the old fix, applied in the wrong place —
    // would probe for a URL nobody visited.
    let url = entity_predicate("url", "https://evil.test/a?b=1&c=2").expect("url is probeable");
    assert_eq!(
        url.sql.matches('?').count(),
        url.binds.len(),
        "the value's `?` leaked into the template: {}",
        url.sql
    );
    assert_eq!(
        probe_binds(&url),
        vec!["https://evil.test/a?b=1&c=2".to_string()],
        "the bound value was doubled or escaped"
    );
}

/// Statements that EXECUTE against a local ClickHouse.
///
/// Everything above asserts the SHAPE of a query, which is exactly what the
/// bug this module already fixed once got past: a probe that assembles cleanly
/// and errors at the driver is indistinguishable from a correct one until it
/// runs. These are `#[ignore]`d so `cargo test --lib` stays hermetic. Run:
///
/// ```text
/// cargo test -p nanosiem-core --lib -- hunts::evidence::live --ignored --nocapture
/// ```
#[cfg(test)]
mod live {
    use super::*;

    fn resolver() -> ClickHouseEvidenceResolver {
        let client = clickhouse::Client::default()
            .with_url("http://localhost:8123")
            .with_database("nanosiem");
        ClickHouseEvidenceResolver::for_tests(client, "logs")
    }

    /// The most recent event in the store, as `(id, timestamp, source_type)`.
    async fn newest_event() -> Option<(String, chrono::DateTime<Utc>, String)> {
        let rows = resolver()
            .fetch_json(
                "SELECT id, timestamp, source_type FROM logs ORDER BY timestamp DESC LIMIT 1",
                &[],
            )
            .await
            .expect("local ClickHouse is reachable");
        let row = rows.first()?;
        Some((
            row.get("id")?.as_str()?.to_string(),
            parse_ch_timestamp(row.get("timestamp")?.as_str()?)?,
            row.get("source_type")?.as_str()?.to_string(),
        ))
    }

    #[tokio::test]
    #[ignore = "requires a local ClickHouse on :8123 with logs"]
    async fn resolve_binds_the_id_array_and_accounts_for_every_id() {
        let (id, _, source_type) = newest_event().await.expect("the log store has events");
        let missing = "00000000-0000-4000-8000-000000000000".to_string();

        let resolved = resolver()
            .resolve(
                &[id.clone(), "not-a-uuid".to_string(), missing.clone()],
                &ScopeSet::unrestricted(),
            )
            .await
            .expect("the bound id array executed");
        assert_eq!(resolved.events.len(), 1, "the real id did not come back");
        assert_eq!(resolved.events[0].canonical_event_id, id);
        // Unparseable and absent ids are both UNACCOUNTED, which is what makes
        // the manifest incomplete.
        assert_eq!(resolved.unresolved.len(), 2, "{:?}", resolved.unresolved);
        assert!(!resolved.provenance().is_complete());

        // The same lookup under a scope that denies the event's own source must
        // come back empty — the scope clause is interpolated, so this is the
        // live proof it still lands in the statement.
        let denied = resolver()
            .resolve(
                &[id.clone()],
                &ScopeSet::from_denied(BTreeSet::from([source_type.clone()])),
            )
            .await
            .expect("the scoped lookup executed");
        assert!(
            denied.events.is_empty(),
            "a denied source's event resolved anyway"
        );
        assert_eq!(denied.unresolved, vec![id]);
    }

    #[tokio::test]
    #[ignore = "requires a local ClickHouse on :8123 with logs"]
    async fn a_question_mark_in_a_real_url_finds_the_event_instead_of_erroring() {
        // The regression this module already had: a `?` in an entity value was
        // read as a bind placeholder and errored the probe out. A negative
        // result would not prove the fix — a bind that quietly matches nothing
        // looks the same — so this uses a URL that IS in the local store and
        // asserts it is FOUND.
        let url = "https://www.google.com/search?q=windows+document+search+tool";
        let seen_at = chrono::DateTime::parse_from_rfc3339("2026-07-24T14:53:28Z")
            .unwrap()
            .with_timezone(&Utc);

        let history = resolver()
            .had_prior_history("url", url, seen_at + chrono::Duration::hours(1), &ScopeSet::unrestricted())
            .await
            .expect("a `?` in a bound value must not error the probe");
        assert!(history, "the URL with a query string was not found");

        // …and the same value one window later has no history, so the probe is
        // answering about the value rather than matching everything.
        let before = resolver()
            .had_prior_history("url", url, seen_at - chrono::Duration::days(1), &ScopeSet::unrestricted())
            .await
            .expect("executed");
        assert!(!before, "the probe matched outside its window");
    }

    #[tokio::test]
    #[ignore = "requires a local ClickHouse on :8123 with logs"]
    async fn hostile_entity_values_execute_and_match_nothing() {
        // Quotes, a backslash, a comment marker and a `?`. None of these exist
        // in the store, so the honest answer is "no history, no prevalence" —
        // and the failure being ruled out is a driver or syntax ERROR, which is
        // what an escaped-literal form produces the moment an escape is missed.
        let start = chrono::DateTime::parse_from_rfc3339("2026-07-24T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let end = start + chrono::Duration::days(1);
        for (entity_type, value) in [
            ("file", "/tmp/a' OR 1=1 --"),
            ("host", "srv'; DROP TABLE logs --"),
            ("url", "https://x.test/a?b=1&c=2'"),
            ("user", r"dom\ain\who?am'i"),
            // Embedded tab/newline, which the driver escapes on the way out.
            // Not TRAILING ones: `entity_predicate` trims, so "cmd.exe\t\n"
            // probes for `cmd.exe` and would find real history.
            ("process", "cmd\t\n.exe' --"),
        ] {
            let history = resolver()
                .had_prior_history(entity_type, value, end, &ScopeSet::unrestricted())
                .await
                .unwrap_or_else(|e| panic!("{entity_type} probe for {value:?} errored: {e}"));
            assert!(!history, "{entity_type} {value:?} should have no history");

            let prevalence = resolver()
                .asset_prevalence(entity_type, value, start, end, &ScopeSet::unrestricted())
                .await
                .unwrap_or_else(|e| panic!("{entity_type} prevalence for {value:?} errored: {e}"));
            assert_eq!(
                prevalence,
                Some(0.0),
                "{entity_type} {value:?} claimed prevalence"
            );
        }
    }

    #[tokio::test]
    #[ignore = "requires a local ClickHouse on :8123 with logs"]
    async fn every_entity_type_probe_executes_against_the_real_schema() {
        // NAN-2266's failure class: a probe over a column that does not exist
        // assembles cleanly, passes every shape test, and errors only at the
        // server — which turned the first email lead any sweep reported into a
        // 500 on the whole report. The hermetic schema test resolves the
        // columns against init.sql; this is the stronger claim that each
        // probe's SQL actually EXECUTES, for every entity type the report
        // path admits (`service::ALLOWED_ENTITY_TYPES`).
        let start = chrono::DateTime::parse_from_rfc3339("2026-07-24T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let end = start + chrono::Duration::days(1);
        for (entity_type, value) in [
            ("ip", "203.0.113.254"),
            ("host", "nan2266-no-such-host"),
            ("user", "nan2266_no_such_user"),
            ("domain", "nan2266-no-such.example.invalid"),
            ("hash", "d0e5f00dd0e5f00dd0e5f00dd0e5f00d"),
            ("process", "nan2266_no_such.exe"),
            ("file", "/tmp/nan2266_no_such_file"),
            ("url", "https://nan2266.example.invalid/x"),
            ("email", "nan2266@example.invalid"),
        ] {
            let history = resolver()
                .had_prior_history(entity_type, value, end, &ScopeSet::unrestricted())
                .await
                .unwrap_or_else(|e| panic!("{entity_type} history probe errored: {e}"));
            assert!(!history, "{entity_type} {value:?} should have no history");

            resolver()
                .asset_prevalence(entity_type, value, start, end, &ScopeSet::unrestricted())
                .await
                .unwrap_or_else(|e| panic!("{entity_type} prevalence probe errored: {e}"));
        }
    }

    #[tokio::test]
    #[ignore = "requires a local ClickHouse on :8123 with logs"]
    async fn a_folded_entity_still_matches_through_the_bind() {
        // Folding moved from the SQL text onto the bound value. If it moved to
        // the wrong side — `lower(col) = ?` with an unfolded argument — every
        // case-insensitive probe would return "no history" without erroring,
        // and every hunted host would look brand new to the estate.
        let start = chrono::DateTime::parse_from_rfc3339("2026-07-24T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let end = start + chrono::Duration::days(2);
        let scope = ScopeSet::unrestricted();

        let history = resolver()
            .had_prior_history("host", "LT-FIN-009.CORP.LOCAL", end, &scope)
            .await
            .expect("executed");
        assert!(history, "an upper-cased hostname lost its history");

        let prevalence = resolver()
            .asset_prevalence("host", "LT-FIN-009.Corp.Local", start, end, &scope)
            .await
            .expect("executed")
            .expect("assets were active in the window");
        assert!(
            prevalence > 0.0,
            "an upper-cased hostname measured 0% prevalence"
        );
    }

    #[tokio::test]
    #[ignore = "requires a local ClickHouse on :8123 with logs"]
    async fn a_question_mark_in_a_denied_source_does_not_break_the_scope_clause() {
        // The scope predicate is the one fragment still interpolated. Its
        // question-mark escape is asserted as a string above; this proves the
        // driver accepts what that escape produces.
        let (id, _, _) = newest_event().await.expect("the log store has events");
        let resolved = resolver()
            .resolve(
                &[id],
                &ScopeSet::from_denied(BTreeSet::from([
                    "weird?source".to_string(),
                    "other?source".to_string(),
                ])),
            )
            .await
            .expect("a `?` in a denied source type must not error the lookup");
        assert_eq!(resolved.events.len(), 1);
    }

    #[tokio::test]
    #[ignore = "requires a local ClickHouse on :8123 with logs"]
    async fn silent_source_types_binds_the_candidate_list() {
        let since = Utc::now() - chrono::Duration::days(7);
        let silent = resolver()
            .silent_source_types(
                &[
                    "gws_login".to_string(),
                    "definitely_not_a_source".to_string(),
                    // A candidate carrying the characters that used to have to
                    // be escaped into the `IN` list.
                    "weird?'source".to_string(),
                ],
                since,
            )
            .await
            .expect("the bound candidate list executed");
        assert!(
            silent.contains(&"definitely_not_a_source".to_string()),
            "a source with no telemetry was not reported silent: {silent:?}"
        );
        assert!(
            silent.contains(&"weird?'source".to_string()),
            "the hostile candidate was dropped rather than reported: {silent:?}"
        );
        assert!(
            !silent.contains(&"gws_login".to_string()),
            "a source the rollup has events for was reported silent: {silent:?}"
        );
    }
}

#[test]
fn the_silent_source_probe_reads_the_profile_aware_rollup() {
    // `logs_per_source_5m_v2` is the profile-aware successor (NAN-2154) AND is
    // in DISTRIBUTED_TABLES, so `TableNames::read` gives the `_distributed`
    // wrapper on a cluster. Reading the legacy or local table would report every
    // source carried by the other shards as silent — an alarm on the Hunting
    // rail for a perfectly healthy estate.
    let clustered = crate::db::TableNames::new(true);
    assert_eq!(
        clustered.read("logs_per_source_5m_v2"),
        "nanosiem.logs_per_source_5m_v2_distributed"
    );
    let single = crate::db::TableNames::new(false);
    assert_eq!(
        single.read("logs_per_source_5m_v2"),
        "nanosiem.logs_per_source_5m_v2"
    );
}
