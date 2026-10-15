// SPDX-License-Identifier: AGPL-3.0-or-later

//! Regression coverage for the two silent-wrong-answer field defects found by
//! running the detection corpus against a live OCSF 1.9 lake.
//!
//! * NAN-2378 — `| where <fieldA> != <fieldB>` parsed the RHS as a string
//!   literal, so the predicate was the EXACT INVERSE of what was written.
//! * NAN-2379 — the `[]` repeated-attribute paths the field universe advertises
//!   could not be tokenized, and their bare form was rejected as non-canonical:
//!   a closed loop with no way to address the field.
//!
//! These are end-to-end (nPL text → SQL) on purpose. Both defects lived in the
//! seam BETWEEN the tokenizer, the field universe, and codegen, so a unit test
//! against any one of them would have passed while the product stayed wrong.

use std::sync::Arc;

use crate::query::clickhouse_sql_gen::ClickHouseSqlGenerator;
use crate::query::{parse_query, TimeRange};
use crate::schema::{OcsfProfile, SchemaProfile};

fn time_range() -> TimeRange {
    TimeRange {
        start: "2024-01-01T00:00:00Z".parse().unwrap(),
        end: "2024-01-02T00:00:00Z".parse().unwrap(),
    }
}

/// A lake profile whose snapshot carries `process.file.name` — the OCSF leaf
/// the masquerading family compares against. It is snapshot-discovered rather
/// than part of the build-time manifest, exactly as on the live deployment.
fn lake_profile() -> OcsfProfile {
    OcsfProfile::try_lake_1_9_with_snapshot_field_types(std::collections::BTreeMap::from([
        (
            "process.file.name".to_string(),
            crate::schema::FieldType::String,
        ),
        (
            "process.file.path".to_string(),
            crate::schema::FieldType::String,
        ),
    ]))
    .expect("lake profile")
}

fn lake() -> ClickHouseSqlGenerator {
    ClickHouseSqlGenerator::new().with_profile(Arc::new(lake_profile()))
}

fn lake_sql(npl: &str) -> String {
    let query = parse_query(npl).unwrap_or_else(|e| panic!("{npl:?} must parse: {e}"));
    lake()
        .generate(&query, &time_range())
        .unwrap_or_else(|e| panic!("{npl:?} must generate SQL: {e:?}"))
}

#[test]
fn lean_prevalence_predicates_read_persisted_part_columns() {
    let fields = [
        "prevalence_file_hash", "prevalence_process_hash",
        "prevalence_dest_domain", "prevalence_dest_ip", "prevalence_min",
    ];
    let profile = OcsfProfile::try_lake_1_9_with_snapshot_field_types(
        fields.iter().map(|name| (name.to_string(), crate::schema::FieldType::Integer)).collect()
    ).unwrap();
    let generator = ClickHouseSqlGenerator::new().with_profile(Arc::new(profile));
    for field in fields {
        let query = parse_query(&format!("* | where {field} <= 5")).unwrap();
        let sql = generator.generate(&query, &time_range()).unwrap();
        assert!(sql.contains(field), "{field}: {sql}");
        assert!(!sql.contains("enrichments.data.host_count"), "saved-event predicate used current enrichment: {sql}");
    }
}

fn udm_sql(npl: &str) -> String {
    try_udm_sql(npl).unwrap_or_else(|e| panic!("{npl:?} must generate SQL: {e}"))
}

/// UDM codegen that surfaces the error instead of panicking — NAN-2380 makes an
/// ambiguous bare comparison a hard failure, so tests need to read it.
fn try_udm_sql(npl: &str) -> Result<String, String> {
    let query = parse_query(npl).unwrap_or_else(|e| panic!("{npl:?} must parse: {e}"));
    ClickHouseSqlGenerator::new()
        .generate(&query, &time_range())
        .map_err(|e| format!("{e}"))
}

// ---------------------------------------------------------------------------
// NAN-2378 — field-to-field comparison
// ---------------------------------------------------------------------------

/// THE regression test for the inverted predicate.
///
/// Live repro: `class_uid=1007 activity_id=1 | where process.name !=
/// process.file.name` returned 3 rows, every one of them with the two fields
/// IDENTICAL, while the `=` form returned 0. The RHS had become the literal
/// text `'process.file.name'`, so `!=` matched everything and `=` matched
/// nothing — the whole masquerading detection family (T1036.003) inverted, at
/// a plausible alert volume.
#[test]
fn field_to_field_inequality_compares_columns_not_the_literal_text() {
    let sql = lake_sql("class_uid=1007 | where process.name != process.file.name");

    // The RHS must appear as a COLUMN reference, never as a quoted value.
    assert!(
        !sql.contains("'process.file.name'"),
        "RHS was emitted as a string literal — the inverted-predicate bug: {sql}"
    );
    assert!(
        sql.contains("process.file.name"),
        "RHS column missing entirely: {sql}"
    );
    // Both sides present, compared against each other.
    assert!(sql.contains("process.name"), "{sql}");
    assert!(sql.contains("!="), "{sql}");
}

#[test]
fn field_to_field_equality_compares_columns_not_the_literal_text() {
    let sql = lake_sql("class_uid=1007 | where process.name = process.file.name");
    assert!(
        !sql.contains("'process.file.name'"),
        "RHS was emitted as a string literal: {sql}"
    );
    assert!(sql.contains("process.file.name"), "{sql}");
}

/// The same resolution must apply in the base scope, not only after a pipe —
/// the two live on different codegen arms.
#[test]
fn field_to_field_resolves_in_base_scope_too() {
    let sql = lake_sql("process.name != process.file.name");
    assert!(
        !sql.contains("'process.file.name'"),
        "base-scope RHS was emitted as a string literal: {sql}"
    );
    assert!(sql.contains("process.file.name"), "{sql}");
}

/// A dotted RHS that is NOT a column of the active schema is still a literal.
/// `file.name=cmd.exe` is the single most common shape in the detection corpus;
/// promoting it to a column reference would break every one of those rules.
#[test]
fn a_dotted_value_that_is_not_a_column_stays_a_literal() {
    let sql = lake_sql("file.name = cmd.exe");
    assert!(
        sql.contains("'cmd.exe'"),
        "a non-column dotted value must stay a literal: {sql}"
    );
}

/// A flat value that is NOT a column of the active schema stays a literal, on
/// every profile. This is the overwhelming majority of real filters
/// (`source_type=squid_proxy`, `action=allow`) and nothing about NAN-2380 may
/// touch them.
#[test]
fn flat_values_that_are_not_columns_stay_literals() {
    for npl in [
        "source_type=squid_proxy",
        "action=allow",
        "user=administrator",
        "dest_port=443",
    ] {
        let value = npl.split('=').nth(1).unwrap();
        let sql = udm_sql(npl);
        assert!(sql.contains(value), "{npl} must keep a literal RHS: {sql}");
    }
}

/// NAN-2380 — THE regression test for the inversion on UDM.
///
/// `| where src_ip != dest_ip` compiled to `src_ip != 'dest_ip'`: true for
/// every row ever ingested, and its `=` mirror false for every row. Before this
/// change the query returned a plausible row count and no error. It must never
/// again produce SQL that compares a column against the TEXT of another column
/// name — and because a flat bare token on UDM genuinely cannot be resolved
/// (`target_type=user` is an ordinary log value), the honest answer is a loud
/// failure, not a guess.
#[test]
fn bare_flat_field_comparison_on_udm_fails_loudly_instead_of_inverting() {
    for npl in [
        // base scope and piped `where` are different codegen arms
        "src_ip != dest_ip",
        "* | where src_ip != dest_ip",
        "src_ip = dest_ip",
        "* | where user = src_host",
    ] {
        let err = try_udm_sql(npl)
            .err()
            .unwrap_or_else(|| panic!("{npl:?} must NOT silently compile to a literal comparison"));
        assert!(err.contains("Ambiguous"), "{npl}: {err}");
        // The message must name BOTH readings and the way to write each.
        assert!(err.contains('`'), "{npl}: no backtick form offered: {err}");
        assert!(
            err.contains("eval same ="),
            "{npl}: no eval form offered: {err}"
        );
        assert!(
            err.contains("literal text"),
            "{npl}: no literal form offered: {err}"
        );
    }
}

/// The QUOTED form is unambiguous and must still mean the literal text — this
/// is the escape hatch the error message points at, and the reason the error is
/// safe to raise at all.
#[test]
fn quoting_a_colliding_value_keeps_it_a_literal_on_udm() {
    for npl in [
        "user=\"message\"",
        "target_type=\"user\"",
        "src_ip!=\"dest_ip\"",
    ] {
        let sql = udm_sql(npl);
        assert!(
            sql.contains("'message'") || sql.contains("'user'") || sql.contains("'dest_ip'"),
            "{npl} must keep a literal RHS: {sql}"
        );
    }
}

/// The explicit backtick field reference resolves to a COLUMN comparison on
/// UDM — the flat case the dotted rule can never reach.
#[test]
fn backtick_field_reference_compares_columns_on_udm() {
    let sql = udm_sql("* | where src_ip != `dest_ip`");
    assert!(
        !sql.contains("'dest_ip'"),
        "backticked RHS was emitted as a literal: {sql}"
    );
    assert!(sql.contains("dest_ip"), "{sql}");
    assert!(sql.contains("src_ip"), "{sql}");
}

/// …and on the lake/OCSF profile too, including for dotted paths.
#[test]
fn backtick_field_reference_compares_columns_on_the_lake_profile() {
    let sql = lake_sql("class_uid=1007 | where process.name != `process.file.name`");
    assert!(
        !sql.contains("'process.file.name'"),
        "backticked RHS was emitted as a literal: {sql}"
    );
    assert!(sql.contains("process.file.name"), "{sql}");
}

/// The documented workaround must keep working, unchanged, on UDM. It is what
/// the error message tells the analyst to do, so if it broke the error would be
/// a dead end.
#[test]
fn eval_comparison_workaround_still_works_on_udm() {
    let sql = udm_sql("* | eval same = (src_ip = dest_ip) | where same = true");
    assert!(
        !sql.contains("'dest_ip'"),
        "the eval workaround must compare COLUMNS: {sql}"
    );
    assert!(sql.contains("src_ip"), "{sql}");
    assert!(sql.contains("dest_ip"), "{sql}");
}

/// Quotedness survives the AST -> text -> AST round-trip the source-scope gate
/// performs, in BOTH directions. If it did not, a scoped query would silently
/// revert to the inverted literal reading.
#[test]
fn rhs_syntax_survives_a_pretty_print_round_trip() {
    use crate::query::PrettyPrint;

    for npl in [
        "process.name != process.file.name",
        "user!=\"message\"",
        // the explicit form must survive too: printed bare it would re-parse as
        // an ambiguous (or literal) comparison instead of a column reference
        "src_ip!=`dest_ip`",
        "src_ip=`dest_ip`",
    ] {
        let first = parse_query(npl).expect("parses");
        let printed = first.pretty_print();
        let second = parse_query(&printed).unwrap_or_else(|e| panic!("{printed:?}: {e}"));
        assert_eq!(
            first, second,
            "round-trip changed the AST: {npl:?} -> {printed:?}"
        );
    }
}

/// UDM deployments are entirely inert: no UDM column name contains a dot, so
/// the rule can never fire there.
#[test]
fn udm_profile_is_unaffected() {
    let generator = ClickHouseSqlGenerator::new();
    for column in generator.profile.fields().iter().map(|f| f.name) {
        assert!(
            !crate::query::clickhouse_sql_gen::search_expr::is_dotted_schema_path(column),
            "UDM column {column} is dotted — the NAN-2378 rule is no longer inert on UDM"
        );
    }
}

#[test]
fn dotted_schema_path_shape_rejects_value_shapes() {
    use crate::query::clickhouse_sql_gen::search_expr::is_dotted_schema_path;
    assert!(is_dotted_schema_path("process.file.name"));
    assert!(is_dotted_schema_path("src_endpoint.ip"));
    // Not a path: no dot, an IP, a wildcard, empty or numeric-leading segments.
    assert!(!is_dotted_schema_path("process"));
    assert!(!is_dotted_schema_path("10.0.0.1"));
    assert!(!is_dotted_schema_path("cmd.exe*"));
    assert!(!is_dotted_schema_path("a..b"));
    assert!(!is_dotted_schema_path(".leading"));
    assert!(!is_dotted_schema_path("trailing."));
    assert!(!is_dotted_schema_path("a.1b"));
}

// ---------------------------------------------------------------------------
// NAN-2379 — `[]` repeated-attribute paths
// ---------------------------------------------------------------------------

/// Every `[]` path the OCSF field universe advertises must tokenize, validate
/// against the canonical field gate, and reach a physical column.
///
/// This is the closed loop the defect described: the bracket form failed to
/// parse ("Unexpected token '['") and the bare form was rejected as
/// non-canonical, so six of these nine had NO expressible spelling at all —
/// including `answers[].rdata`, which is the DNS answer record and therefore
/// the home of every DNS-tunnelling and fast-flux detection.
#[test]
fn every_advertised_array_path_is_queryable() {
    let profile = lake_profile();
    let advertised: Vec<&str> = profile
        .fields()
        .iter()
        .map(|f| f.name)
        .filter(|name| name.contains('['))
        .collect();

    // NOT asserted: that the universe advertises `[]` spellings at all. It no
    // longer does — the flat leaf (`file.hashes.value`) addresses the SAME
    // serving column, so publishing both was a duplicate, and the tokenizer
    // drops `[]` regardless. That dedup is deliberate.
    //
    // The invariant this test exists for is the other direction and is checked
    // below plus in `bracket_spellings_stay_accepted_even_when_not_advertised`:
    // everything advertised must be queryable, and the OCSF spec spelling must
    // keep working for anyone pasting a path from the spec or a vendor doc.
    // Asserting the universe still CONTAINS brackets encoded an implementation
    // choice, not the contract.
    // Every advertised bracket path is the plain `[]` marker — key-selector
    // recipes (`enrichments[name=…].value`) are no longer published because no
    // tokenizer can address them.
    for name in &advertised {
        assert!(
            !name.contains("[name="),
            "{name} is a promotion recipe, not an addressable path"
        );
    }

    for name in &advertised {
        let npl = format!("{name} = \"probe\"");
        let query = parse_query(&npl).unwrap_or_else(|e| panic!("{npl:?} must parse: {e}"));
        let errors = crate::query::validation::validate_query_fields_with_profile(
            &query,
            Some(&profile as &dyn SchemaProfile),
        );
        assert!(
            errors.is_empty(),
            "{name} is advertised but rejected by canonical validation: {}",
            errors
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
        );
        let sql = lake()
            .generate(&query, &time_range())
            .unwrap_or_else(|e| panic!("{npl:?} must generate SQL: {e:?}"));
        assert!(
            !sql.contains('['),
            "{name} leaked a bracket into SQL: {sql}"
        );
    }
}

/// The nine specific paths, spelled out, with the exact column each must land
/// on. `every_advertised_array_path_is_queryable` proves the loop is closed;
/// this proves it closes on the RIGHT column — a `[]` path that resolved to the
/// wrong leaf would be another silent wrong answer.
#[test]
fn array_paths_resolve_to_their_value_carrying_leaf() {
    let profile = lake_profile();
    for (path, expected) in [
        ("answers[].rdata", "answers.rdata"),
        ("email.to[]", "email.to"),
        ("resources[].name", "resources.name"),
        ("resources[].type", "resources.type"),
        ("resources[].uid", "resources.uid"),
        ("vulnerabilities[].cve.uid", "vulnerabilities.cve.uid"),
        // An array of `fingerprint` OBJECTS: the value lives one level down.
        ("file.hashes[]", "file.hashes.value"),
        ("process.file.hashes[]", "process.file.hashes.value"),
        (
            "actor.process.file.hashes[]",
            "actor.process.file.hashes.value",
        ),
    ] {
        let sql = lake_sql(&format!("{path} = \"probe\""));
        assert!(
            sql.contains(expected),
            "{path} must resolve to {expected}: {sql}"
        );
        assert!(profile.is_known_field(path), "{path} must be a known field");
    }
}

/// The reported repro: `class_uid=4009 email.to[] CONTAINS "gmail.com"`.
/// A word-comparator on an array leaf must generate an element-wise predicate,
/// not a scalar compare against an `Array` column.
#[test]
fn array_path_contains_generates_an_array_predicate() {
    let sql = lake_sql("class_uid=4009 email.to[] CONTAINS \"gmail.com\"");
    assert!(sql.contains("email.to"), "{sql}");
    assert!(
        sql.contains("arrayExists") || sql.contains("has("),
        "array leaf must use element-wise semantics: {sql}"
    );
}

/// The three paths that already had a working dotted sibling must keep behaving
/// identically — the bracket form is an alias for it, not a second column.
#[test]
fn bracket_and_dotted_siblings_agree() {
    for (bracket, dotted) in [
        ("answers[].rdata", "answers.rdata"),
        ("resources[].name", "resources.name"),
        ("file.hashes[]", "file.hashes.value"),
    ] {
        assert_eq!(
            lake_sql(&format!("{bracket} = \"probe\"")),
            lake_sql(&format!("{dotted} = \"probe\"")),
            "{bracket} must be an alias for {dotted}"
        );
    }
}

/// `[]` must be accepted only as the exact empty pair, so bracket forms that
/// mean something else in the grammar are untouched.
#[test]
fn the_repeated_marker_does_not_swallow_other_bracket_syntax() {
    // Subsearch membership still parses.
    assert!(parse_query("src_endpoint.ip IN [search class_uid=4001]").is_ok());
    // A key-selector is still a parse error, not a silently mangled field.
    assert!(parse_query("enrichments[name=x].value = \"probe\"").is_err());
}

/// A `[]` repeated marker must never swallow a bracket that belongs to an
/// enclosing construct. The first cut of the marker support added `[` and `]` to
/// the wildcard field-name character set, so `| table user, department, manager]`
/// parsed `manager]` as a field name and ate the subsearch's closing bracket —
/// every `join`/subsearch query then failed to parse at all (7 docs tests, all
/// silently attributed to the wrong stage because the reported error pointed at
/// the first `|`). Marker support and subsearch syntax share the same character,
/// so they need a test that holds both at once.
#[test]
fn repeated_marker_does_not_eat_a_subsearch_closing_bracket() {
    for query in [
        r#"action=login | join type=left user [search source_type="user_directory" | table user, department, manager]"#,
        r#"action=login | join type=inner src_ip [search source_type="threat_feed" | table src_ip, threat]"#,
        // The marker itself must still work INSIDE a subsearch projection.
        r#"* | join type=left user [search class_uid=4009 | table user, email.to[]]"#,
    ] {
        assert!(
            crate::query::parse_query(query).is_ok(),
            "subsearch must parse; the `[]` marker must not consume the closing bracket:\n  {query}"
        );
    }
}

/// 37 of the 278 promoted OCSF 1.9 fields are FLAT — `status`, `disposition`,
/// `severity`, `activity_name`, `logon_type`, `risk_level`, `class_name`. The
/// first cut of field-to-field support required a dotted right-hand side to keep
/// UDM inert, which left every flat-to-flat comparison on the lake silently
/// inverted: exactly the defect the feature exists to fix, just on a third of
/// the field universe.
#[test]
fn flat_ocsf_fields_compare_as_columns_on_a_strict_profile() {
    for (lhs, rhs) in [
        ("status", "status_detail"),
        ("severity", "risk_level"),
        ("activity_name", "class_name"),
    ] {
        let sql = lake_sql(&format!("* | where {lhs} != {rhs}"));
        assert!(
            !sql.contains(&format!("'{rhs}'")),
            "`{lhs} != {rhs}` must compare two columns, not `{lhs}` against the literal text \
             '{rhs}' — that inverts the predicate. SQL:\n{sql}"
        );
    }
}

/// The other half of the same contract: an ordinary VALUE must stay a literal.
/// `status=Success` is not a field comparison, and neither is a value that does
/// not resolve to a promoted field.
#[test]
fn ordinary_values_stay_literals_on_a_strict_profile() {
    for (lhs, rhs) in [
        ("status", "Success"),
        ("activity_name", "Launch"),
        ("severity", "High"),
    ] {
        let sql = lake_sql(&format!("* | where {lhs} = {rhs}"));
        assert!(
            sql.contains(&format!("'{}'", rhs.to_lowercase())) || sql.contains(&format!("'{rhs}'")),
            "`{lhs} = {rhs}` must stay a literal comparison. SQL:\n{sql}"
        );
    }
}

// ---------------------------------------------------------------------------
// NAN-2380 — blast radius: the real-time materialized-view lane
// ---------------------------------------------------------------------------

/// `SearchExpr::FieldFilter` is accepted by `reject_unsupported_for_realtime`,
/// which then hands the node to THIS generator. So a real-time rule written
/// `src_ip != dest_ip` used to install a materialized view whose WHERE was
/// always true — a detection firing on literally every ingested event, forever.
/// It must now fail DDL generation instead.
#[test]
fn ambiguous_comparison_fails_the_realtime_materialized_view_too() {
    use crate::detection::materialized_view::MaterializedViewGenerator;

    // The MV gate accepts the node kind, so the failure has to come from codegen.
    let query = parse_query("src_ip != dest_ip").expect("parses");
    assert!(
        MaterializedViewGenerator::check_query_realtime_eligible(&query).is_ok(),
        "the MV node-kind gate still accepts a FieldFilter — so codegen is the \
         only thing standing between this rule and an always-true real-time view"
    );
    let err = ClickHouseSqlGenerator::new()
        .generate(&query, &time_range())
        .expect_err("an always-true real-time rule must not be installable");
    assert!(format!("{err}").contains("Ambiguous"), "{err:?}");
}

/// …and the explicit backtick form stays real-time eligible and lowers to a
/// column-to-column WHERE, so the fix does not push masquerading rules off the
/// real-time path.
#[test]
fn backtick_field_reference_is_realtime_eligible() {
    use crate::detection::materialized_view::MaterializedViewGenerator;

    let query = parse_query("src_ip != `dest_ip`").expect("parses");
    MaterializedViewGenerator::check_query_realtime_eligible(&query)
        .expect("an explicit field comparison must stay real-time eligible");
    let sql = udm_sql("src_ip != `dest_ip`");
    assert!(!sql.contains("'dest_ip'"), "{sql}");
}

/// The AST contract itself: the tokenizer must record whether the RHS was
/// written bare or quoted. Everything above is built on this one bit, and it is
/// the bit the language did not have before NAN-2380.
#[test]
fn the_ast_records_whether_the_rhs_was_quoted() {
    use crate::query::{Query, RhsSyntax, SearchExpr};

    fn rhs_of(npl: &str) -> RhsSyntax {
        match parse_query(npl).expect("parses") {
            Query::Search(SearchExpr::FieldFilter { rhs, .. }) => rhs,
            other => panic!("{npl:?} did not parse to a field filter: {other:?}"),
        }
    }

    assert_eq!(rhs_of("src_ip=dest_ip"), RhsSyntax::Bareword);
    assert_eq!(
        rhs_of("process.name=process.file.name"),
        RhsSyntax::Bareword
    );
    // Quoted, wildcarded, typed or otherwise non-identifier RHS values are
    // never ambiguous and must stay literals.
    assert_eq!(rhs_of("src_ip=\"dest_ip\""), RhsSyntax::Literal);
    assert_eq!(rhs_of("src_ip='dest_ip'"), RhsSyntax::Literal);
    assert_eq!(rhs_of("user=admin*"), RhsSyntax::Literal);
    assert_eq!(rhs_of("file_path=C:\\Windows"), RhsSyntax::Literal);
    assert_eq!(rhs_of("user=dan@nano.rs"), RhsSyntax::Literal);
    assert_eq!(rhs_of("status=200"), RhsSyntax::Literal);
    assert_eq!(rhs_of("src_ip=10.0.0.1"), RhsSyntax::Literal);
    assert_eq!(rhs_of("enabled=true"), RhsSyntax::Literal);
}

// ---------------------------------------------------------------------------
// NAN-2380 — the third lane: OCSF 1.8 on ClickHouse
// ---------------------------------------------------------------------------

/// The generator is shared by three lanes that differ only in profile: UDM on
/// ClickHouse, OCSF 1.8 on ClickHouse, and the OCSF 1.9 object lake. OCSF 1.8
/// is NOT strict-canonical (`uses_strict_canonical_fields()` is false there), so
/// it behaves like UDM for flat tokens — and its field names are dotted, so the
/// dotted resolution reaches it. Prove all three shapes on that lane.
#[test]
fn ocsf_1_8_on_clickhouse_resolves_dotted_errors_on_flat_and_honours_backticks() {
    let generator =
        ClickHouseSqlGenerator::new().with_profile(Arc::new(crate::schema::OcsfProfile::new()));
    let sql_for = |npl: &str| {
        let q = parse_query(npl).unwrap_or_else(|e| panic!("{npl:?} must parse: {e}"));
        generator.generate(&q, &time_range())
    };

    // Dotted, both sides real columns -> column comparison.
    let sql = sql_for("* | where src_endpoint.ip != dst_endpoint.ip").expect("dotted resolves");
    assert!(
        !sql.contains("'dst_endpoint.ip'"),
        "dotted RHS emitted as a literal on OCSF 1.8: {sql}"
    );

    // Flat, both sides real columns -> ambiguous, and therefore loud.
    let err = sql_for("* | where severity != status")
        .expect_err("a flat both-fields comparison must not silently invert on OCSF 1.8");
    assert!(format!("{err:?}").contains("Ambiguous"), "{err:?}");

    // The explicit form works here too.
    let sql = sql_for("* | where severity != `status`").expect("backticks resolve");
    assert!(!sql.contains("'status'"), "{sql}");

    // And an ordinary value is still an ordinary value.
    let sql = sql_for("* | where severity = High").expect("a plain value still compiles");
    assert!(sql.to_lowercase().contains("high"), "{sql}");
}

// ---------------------------------------------------------------------------
// NAN-2380 — blast radius: query validation (and the Rust-evaluated `| where`)
// ---------------------------------------------------------------------------

/// A `| where` that follows a prevalence/risk stage is evaluated in Rust over
/// JSON rows — it never reaches the SQL generator, so a codegen-only guard would
/// leave that lane silently inverted. Validation runs on every search path
/// (core_search / streaming / explain) with the profile, so the ambiguity is
/// caught there for every stage of the pipeline, before anything executes.
#[test]
fn validation_rejects_the_ambiguous_comparison_in_every_stage() {
    use crate::query::validation::validate_query_fields_with_profile;
    use crate::schema::{SchemaProfile, UdmProfile};

    let udm = UdmProfile::new();
    for npl in [
        "src_ip != dest_ip",
        "* | where src_ip != dest_ip",
        // the Rust-evaluated lane: a `where` after a Nano-side stage
        "* | prevalence file_hash | where src_ip != dest_ip",
    ] {
        let query = parse_query(npl).unwrap_or_else(|e| panic!("{npl:?} must parse: {e}"));
        let errors = validate_query_fields_with_profile(&query, Some(&udm as &dyn SchemaProfile));
        assert!(
            errors.iter().any(|e| e.message.contains("Ambiguous")),
            "{npl:?} was not flagged before execution: {errors:?}"
        );
    }

    // …and the unambiguous spellings validate cleanly.
    for npl in [
        "src_ip != `dest_ip`",
        "src_ip != \"dest_ip\"",
        "* | eval same = (src_ip = dest_ip) | where same = true",
        "source_type=squid_proxy",
    ] {
        let query = parse_query(npl).unwrap_or_else(|e| panic!("{npl:?} must parse: {e}"));
        let errors = validate_query_fields_with_profile(&query, Some(&udm as &dyn SchemaProfile));
        assert!(
            !errors.iter().any(|e| e.message.contains("Ambiguous")),
            "{npl:?} must not be flagged: {errors:?}"
        );
    }
}

/// The exact spellings the nPL reference and the user guide publish must
/// compile. A documented example that errors is worse than no example.
#[test]
fn the_documented_backtick_examples_compile() {
    for npl in [
        "* | where process_name != `file_name`",
        "* | where src_ip = `dest_ip`",
        "* | eval same = (src_ip = dest_ip) | where same = true",
        "src_ip != \"dest_ip\"",
    ] {
        udm_sql(npl);
    }
}

/// The dedup above removed the `[]` spellings from the ADVERTISED universe. They
/// must still be ACCEPTED: an analyst pasting `answers[].rdata` out of the OCSF
/// spec, or reusing a rule authored against the spec spelling, has to keep
/// working. This is the half of the contract that survives the dedup.
#[test]
fn bracket_spellings_stay_accepted_even_when_not_advertised() {
    let profile = lake_profile();
    for (bracket, flat) in [
        ("answers[].rdata", "answers.rdata"),
        ("email.to[]", "email.to"),
        ("file.hashes[]", "file.hashes.value"),
        ("vulnerabilities[].cve.uid", "vulnerabilities.cve.uid"),
    ] {
        let bracket_sql = lake_sql(&format!("{bracket} = \"probe\""));
        assert!(
            !bracket_sql.contains('['),
            "{bracket} must lower to a bracket-free column: {bracket_sql}"
        );
        // And it must address the SAME column as the flat leaf, or the two
        // spellings would silently mean different things.
        assert_eq!(
            bracket_sql,
            lake_sql(&format!("{flat} = \"probe\"")),
            "{bracket} and {flat} must compile identically"
        );
    }
}

#[test]
fn lookup_splunk_order_compiles_event_side_and_keeps_result_suffix() {
    use crate::query::validation::validate_query_fields_with_profile;
    use crate::search::query_processing::split_lake_post_processing;
    for output in ["OUTPUT", "OUTPUTNEW"] {
        let text = format!("* | stats count by src_endpoint.ip | lookup assets ip AS src_endpoint.ip {output} owner AS asset_owner | where asset_owner=\"bob\" | table src_endpoint.ip, asset_owner");
        let query = parse_query(&text).unwrap();
        assert!(validate_query_fields_with_profile(&query, Some(&lake_profile())).is_empty());
        let (prefix, suffix) = split_lake_post_processing(&query);
        let sql = lake().generate(&prefix, &time_range()).unwrap();
        assert!(sql.contains("src_endpoint.ip"), "{sql}");
        assert!(!sql.contains("asset_owner"), "lookup output must remain in the result suffix: {sql}");
        assert!(matches!(suffix.first(), Some(crate::query::Command::Lookup {
            event_field, key_field, output_new, ..
        }) if event_field == "src_endpoint.ip" && key_field == "ip" && *output_new == (output == "OUTPUTNEW")));
        assert_eq!(suffix.len(), 3);
    }
}

/// NAN-3329 #1: a bare dotted field after an ordering operator is a column.
#[test]
fn ordering_comparison_against_a_dotted_field_is_field_to_field_nan3329() {
    let sql = lake_sql("* | where src_endpoint.port > dst_endpoint.port");
    assert!(!sql.contains("'dst_endpoint.port'"), "RHS read as a literal:\n{sql}");
    assert!(sql.contains("dst_endpoint.port"), "{sql}");
    // A quoted RHS stays a literal.
    let quoted = lake_sql("* | where src_endpoint.hostname > \"dst_endpoint.port\"");
    assert!(quoted.contains("'dst_endpoint.port'"), "{quoted}");
}

/// NAN-3329 #2: arithmetic on the event time is in epoch seconds, not NULL.
#[test]
fn eval_arithmetic_on_time_is_epoch_seconds_nan3329() {
    let sql = lake_sql("* | eval d=time - 1000");
    assert!(!sql.contains("toFloat64OrNull(toString(time))"), "{sql}");
    assert!(sql.contains("toFloat64(toDateTime64(time, 3, 'UTC')) - 1000"), "{sql}");
    // Both datetime operands are seconds: `now() - time` is a number, not a
    // DateTime near 1970 (review of #5676).
    // (NAN-3382 pins the datetime - datetime form below.)
    // `<datetime> ± INTERVAL` stays datetime arithmetic, then compares as seconds.
    let sql = lake_sql("* | eval recent=if(time > now() - INTERVAL 1 HOUR, 1, 0)");
    assert!(
        sql.contains("toFloat64(toDateTime64((now() - INTERVAL 1 HOUR), 3, 'UTC'))"),
        "{sql}"
    );
    let sql = lake_sql("* | eval cutoff=now() - INTERVAL 1 HOUR");
    assert!(sql.contains("(now() - INTERVAL 1 HOUR) AS cutoff"), "{sql}");
    if let Ok(path) = std::env::var("NAN3329_SQL_OUT") {
        std::fs::write(path, lake_sql("* | eval age=now()-time, d=time - 1000, recent=if(time > now() - INTERVAL 1 HOUR, 1, 0) | streamstats current=false last(time) as prev_time | eval gap=time - prev_time | table time, age, d, recent, gap")).unwrap();
    }
}

/// NAN-3382: a datetime minus a datetime (`now() - time`, and the `_time` /
/// `timestamp` aliases of the event time) is the elapsed time in WHOLE
/// seconds, computed in integer milliseconds so a float rounding error can
/// never drop a second (`age=474.54299998` and `3599.9999998` were possible).
#[test]
fn eval_datetime_difference_is_integer_seconds_nan3382() {
    let int_age = "toInt64(floor((toUnixTimestamp64Milli(toDateTime64(now(), 3, 'UTC')) - \
                   toUnixTimestamp64Milli(toDateTime64(time, 3, 'UTC'))) / 1000)) AS age";
    for npl in [
        "* | eval age=now()-time",
        "* | eval age=now() - _time",
        "* | eval age=now()-timestamp",
    ] {
        let sql = lake_sql(npl);
        assert!(sql.contains(int_age), "{npl}:\n{sql}");
        assert!(
            !sql.contains("toFloat64(toDateTime64(now()"),
            "{npl}:\n{sql}"
        );
    }
    // A comparison on the difference works on the integer.
    let sql = lake_sql("* | eval recent=if(now() - time < 3600, 1, 0)");
    assert!(
        sql.contains("toInt64(floor((toUnixTimestamp64Milli("),
        "{sql}"
    );
    // Datetime minus a number keeps epoch-seconds Float64 (NAN-3329).
    let sql = lake_sql("* | eval d=time - 1000");
    assert!(
        sql.contains("toFloat64(toDateTime64(time, 3, 'UTC')) - 1000"),
        "{sql}"
    );
    // Datetime ± INTERVAL stays a datetime operand of the difference.
    let sql = lake_sql("* | eval w=time - (now() - INTERVAL 1 HOUR)");
    assert!(
        sql.contains("toUnixTimestamp64Milli(toDateTime64((now() - INTERVAL 1 HOUR), 3, 'UTC'))"),
        "{sql}"
    );
}

/// NAN-3329 #3/#4: `window=N` covers N events, and `current=false` value
/// functions are NULL (not 1970) on a group's first event.
#[test]
fn streamstats_window_and_empty_frame_nan3329() {
    let sql = lake_sql("* | streamstats window=5 count");
    assert!(sql.contains("ROWS BETWEEN 4 PRECEDING AND CURRENT ROW"), "{sql}");
    let sql = lake_sql("* | streamstats current=false window=5 count");
    assert!(sql.contains("ROWS BETWEEN 5 PRECEDING AND 1 PRECEDING"), "{sql}");
    let sql = lake_sql("* | streamstats current=false last(time) as prev_time by user.name");
    assert!(sql.contains("lagInFrame(toNullable(time), 1)"), "{sql}");
}

/// NAN-3327 #1: `spath input=raw_data` parses the column's JSON text instead
/// of compiling to the bogus `ext.raw_dataeventName`; the column is projected.
#[test]
fn spath_over_a_scalar_json_column_nan3327() {
    let npl = "* | spath input=raw_data path=userIdentity.arn output=arn | table arn";
    let sql = lake_sql(npl);
    assert!(!sql.contains("raw_dataeventName") && !sql.contains("raw_data.userIdentity"), "{sql}");
    assert!(sql.contains("JSONExtractString(toString(raw_data), 'userIdentity', 'arn') AS arn"), "{sql}");
    let referenced = lake().referenced_fields_for_query(&parse_query(npl).unwrap());
    assert!(referenced.contains("raw_data"), "{referenced:?}");
    // A real nested schema path keeps addressing the column.
    let nested = lake_sql("* | spath input=src_endpoint path=ip output=x | table x");
    assert!(!nested.contains("JSONExtractString(toString(src_endpoint)"), "{nested}");
}

/// NAN-3327 #2-#4: rex reads a projected source column, assigns named groups
/// by their index among all capturing groups, and sed rewrites in place.
#[test]
fn rex_projection_group_index_and_sed_in_place_nan3327() {
    let npl = r#"* | rex field=raw_data "eventName\":\"(?<en>[^\"]+)" | table en"#;
    let referenced = lake().referenced_fields_for_query(&parse_query(npl).unwrap());
    assert!(referenced.contains("raw_data"), "{referenced:?}");

    let sql = lake_sql(
        r#"* | rex field=http_request.url.url_string "https?://(?<host>[^/:]+)(:(?<port>\d+))?(?<path>/.*)" | table host, port, path"#,
    );
    assert!(sql.contains("[1] AS host") && sql.contains("[3] AS port") && sql.contains("[4] AS path"), "{sql}");

    let sql = lake_sql(r#"* | rex field=user.name mode=sed "s/corp\\\\//" | stats count by user.name"#);
    assert!(!sql.contains("rex_result"), "{sql}");
    assert!(sql.contains("REPLACE(replaceRegexpAll("), "{sql}");
}
