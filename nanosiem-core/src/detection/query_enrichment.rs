// SPDX-License-Identifier: AGPL-3.0-or-later

//! Query enrichment for detection rules
//!
//! Auto-injects `min(timestamp) as _first_seen` and `max(timestamp) as _last_seen`
//! into stats commands so aggregated detection results always carry real event
//! time bounds for latency calculation.

use crate::query::{AggFunc, Aggregation, BinSpan, Command, Query, TableField, WindowType};

/// Enriches the **first** aggregation over the raw event stream with timestamp
/// bounds so aggregated detection results carry event timing for latency
/// calculation and the canonical finding-dedup window.
///
/// For each `Command::Stats`/`Command::Chart` whose input still carries the raw
/// `timestamp` column, appends `min(timestamp) as _first_seen` and
/// `max(timestamp) as _last_seen` (unless already present).
///
/// **Audit D3:** injection is gated on `timestamp` still being in the stream.
/// A *second* aggregation, or an aggregation after a projection that dropped
/// `timestamp` (`fields`, `table`, an earlier `stats`/`chart`, …), is left
/// alone — injecting `min(timestamp)` there references a column that no longer
/// exists, which errors the whole query. The old code injected into *every*
/// stage, so any multi-stage aggregate rule (e.g.
/// `… | stats count by x | where count > 1 | stats sum(count)`) errored on every
/// cycle while looking healthy in the tester.
///
/// **Audit D15 (NAN-1711):** `Timechart`, `Top` and `Rare` are enriched too —
/// their rows carry a drifting `count`/`percent`, so without the canonical
/// bounds they fell to the content-hash dedup branch and re-emitted every cycle
/// (the NAN-1308/1309 flood, for these command types). `Timechart` has an
/// `aggregations` list, so it takes the same `enrich_aggregations` path as
/// `Stats`/`Chart` (per-bucket/per-series bounds). `Top`/`Rare` have hand-built
/// SQL, so they carry an `inject_bounds` flag that makes the SQL generator
/// append `min/max(timestamp)` — same D3 gate: only set while the raw
/// `timestamp` is still in the stream.
/// Whether a `top`/`rare` ranked field or split field IS one of the canonical
/// bound aliases (`_first_seen`/`_last_seen`). Injecting the bounds then would
/// collide the alias (ClickHouse `MULTIPLE_EXPRESSIONS_FOR_ALIAS`), so the SQL
/// generator skips it — and enrichment MUST report `output_bounds = false` to
/// match, or a downstream `table`/`fields` carry-through selects a `_last_seen`
/// that was never emitted (`UNKNOWN_IDENTIFIER`, every cycle — audit D15, codex).
/// A literal name check is sufficient: the canonical bounds are fixed system
/// names, and a `top`/`rare` field's output name equals one only when the field
/// IS literally that name.
fn top_rare_bounds_collision(field: &str, by_fields: &[String]) -> bool {
    let is_bound = |f: &str| f == "_first_seen" || f == "_last_seen";
    is_bound(field) || by_fields.iter().any(|f| is_bound(f))
}

pub fn inject_timestamp_bounds(query: &Query) -> Query {
    inject_bounds_tracked(query).0
}

/// Recurse bottom-up, returning the (possibly enriched) query, whether its
/// **output** stream still carries the raw `timestamp` column, and whether it
/// carries the canonical `_first_seen`/`_last_seen` bounds (audit D14).
fn inject_bounds_tracked(query: &Query) -> (Query, bool, bool) {
    match query {
        Query::Search(expr) => (Query::Search(expr.clone()), true, false),
        Query::Piped { source, command } => {
            let (enriched_source, source_ts, source_bounds) = inject_bounds_tracked(source);

            let (new_command, output_ts, output_bounds) = match command {
                // First aggregation over the raw stream: inject the canonical
                // bounds. Aggregation collapses the raw stream (timestamp gone),
                // but the output now CARRIES `_first_seen`/`_last_seen`.
                Command::Stats {
                    aggregations,
                    group_by,
                } if source_ts => (
                    Command::Stats {
                        aggregations: enrich_aggregations(aggregations),
                        group_by: group_by.clone(),
                    },
                    false,
                    true,
                ),
                Command::Chart {
                    aggregations,
                    group_by,
                } if source_ts => (
                    Command::Chart {
                        aggregations: enrich_aggregations(aggregations),
                        group_by: group_by.clone(),
                    },
                    false,
                    true,
                ),
                // Audit D15 (NAN-1711): timechart rows carry a drifting count and
                // no window bounds, so `| timechart …` alerting rules re-hashed
                // (and re-emitted) every cycle. Inject the same canonical pair —
                // per (time_bucket[, split_by]) row, min/max(timestamp) is the
                // bucket's own activity window. The injected aggregations are
                // APPENDED, so a `limit=N` split-series ranking (which keys on
                // the FIRST aggregation) is unchanged.
                Command::Timechart {
                    span,
                    aggregations,
                    split_by,
                    limit,
                    cont,
                } if source_ts => (
                    Command::Timechart {
                        span: *span,
                        aggregations: enrich_aggregations(aggregations),
                        split_by: split_by.clone(),
                        limit: *limit,
                        cont: *cont,
                    },
                    false,
                    true,
                ),
                // Audit D15 (NAN-1711): top/rare have no aggregations list —
                // their SQL is hand-built — so the canonical bounds ride on the
                // `inject_bounds` flag (SQL gen appends `min(timestamp) AS
                // _first_seen, max(timestamp) AS _last_seen`). Same D3 gate as
                // stats: only when the raw `timestamp` is still in the stream.
                Command::Top {
                    field,
                    limit,
                    by_fields,
                    show_count,
                    show_percent,
                    inject_bounds: _,
                } if source_ts => {
                    // `output_bounds` must track the ACTUAL injection: skip (and
                    // report no bounds) on an alias collision so downstream
                    // projections don't carry a `_last_seen` we never emit.
                    let inject = !top_rare_bounds_collision(field, by_fields);
                    (
                        Command::Top {
                            field: field.clone(),
                            limit: *limit,
                            by_fields: by_fields.clone(),
                            show_count: *show_count,
                            show_percent: *show_percent,
                            inject_bounds: inject,
                        },
                        false,
                        inject,
                    )
                }
                Command::Rare {
                    field,
                    limit,
                    by_fields,
                    show_count,
                    show_percent,
                    inject_bounds: _,
                } if source_ts => {
                    let inject = !top_rare_bounds_collision(field, by_fields);
                    (
                        Command::Rare {
                            field: field.clone(),
                            limit: *limit,
                            by_fields: by_fields.clone(),
                            show_count: *show_count,
                            show_percent: *show_percent,
                            inject_bounds: inject,
                        },
                        false,
                        inject,
                    )
                }
                // Audit D14: a projection AFTER the enriched aggregation would
                // drop `_first_seen`/`_last_seen`, degrading finding dedup to a
                // content hash that includes the drifting count → re-emit every
                // cycle (the NAN-1308/1309 flood). Carry the canonical bounds
                // through the projection so dedup keeps keying on the stable
                // window.
                Command::Table { fields } if source_bounds => {
                    (Command::Table { fields: with_canonical_table_fields(fields) }, false, true)
                }
                Command::Fields { fields, keep } if source_bounds && *keep => {
                    (Command::Fields { fields: with_canonical_fields(fields), keep: true }, false, true)
                }
                other => (
                    other.clone(),
                    source_ts && command_preserves_raw_timestamp(other),
                    source_bounds && command_keeps_bounds(other),
                ),
            };

            (
                Query::Piped {
                    source: Box::new(enriched_source),
                    command: new_command,
                },
                output_ts,
                output_bounds,
            )
        }
    }
}

/// Whether `command` leaves the canonical `_first_seen`/`_last_seen` columns in
/// the stream.
///
/// **Safe direction (codex):** default to `false` (assume dropped) — only
/// commands *known* to pass all columns through return `true`. Over-reporting
/// bounds would make a later `table`/`fields` carry-through select a column that
/// no longer exists → invalid SQL; under-reporting only forgoes the dedup
/// optimization (content-hash fallback, the pre-fix behavior). `table`/`fields`
/// are handled explicitly above; every (re-)aggregation and unknown/future
/// command drops to the `false` default.
fn command_keeps_bounds(command: &Command) -> bool {
    matches!(
        command,
        Command::Where { .. }
            | Command::Sort { .. }
            | Command::Head { .. }
            | Command::Tail { .. }
            | Command::Eval { .. }
            | Command::Dedup { .. }
            | Command::Rex { .. }
            | Command::Lookup { .. }
            | Command::Fillnull { .. }
            | Command::Mvexpand { .. }
            | Command::Spath { .. }
            | Command::StreamStats { .. }
            | Command::Join { .. }
            | Command::Append { .. }
            // `rename` emits `SELECT *, col AS new`, so the original bound column
            // survives; `bin` adds a bucket column and keeps `*`.
            | Command::Rename { .. }
            | Command::Bin { .. }
    )
}

/// Append `_first_seen`/`_last_seen` to a `fields +` keep-list if absent.
fn with_canonical_fields(fields: &[String]) -> Vec<String> {
    let mut out = fields.to_vec();
    for name in ["_first_seen", "_last_seen"] {
        if !out.iter().any(|f| f == name) {
            out.push(name.to_string());
        }
    }
    out
}

/// Append `_first_seen`/`_last_seen` to a `table` projection if its OUTPUT does
/// not already expose that column.
///
/// Presence is checked against the *output* name (`alias` if set, else `name`),
/// not the source name (codex): `table _first_seen as first_seen` outputs
/// `first_seen`, so `_first_seen` is still missing and must be re-added — the
/// source column exists, so selecting it again under its own name is valid.
fn with_canonical_table_fields(fields: &[TableField]) -> Vec<TableField> {
    let mut out = fields.to_vec();
    for name in ["_first_seen", "_last_seen"] {
        let present = out
            .iter()
            .any(|f| f.alias.as_deref().unwrap_or(f.name.as_str()) == name);
        if !present {
            out.push(TableField {
                name: name.to_string(),
                alias: None,
            });
        }
    }
    out
}

/// Whether `command` leaves the raw `timestamp` column in the output stream.
///
/// **Safe direction:** default to `false` (assume dropped → skip injection).
/// A false negative only costs the canonical `_first_seen`/`_last_seen` — the
/// finding dedup falls back to a content hash. A false *positive* injects
/// `min(timestamp)` into a stage that no longer has the column and errors the
/// whole query (audit D3). So only commands *known* to preserve raw `timestamp`
/// return `true`; everything else (aggregations, `table`, unknown/future
/// commands) takes the `false` default.
fn command_preserves_raw_timestamp(command: &Command) -> bool {
    match command {
        // Row-preserving / field-adding: raw `timestamp` untouched. `rename`
        // emits `SELECT *, <col> AS <new>`, so the raw column also survives.
        Command::Where { .. }
        | Command::Sort { .. }
        | Command::Head { .. }
        | Command::Tail { .. }
        | Command::Eval { .. }
        | Command::Dedup { .. }
        | Command::Rex { .. }
        | Command::Lookup { .. }
        | Command::Fillnull { .. }
        | Command::Mvexpand { .. }
        | Command::Spath { .. }
        | Command::StreamStats { .. }
        | Command::Join { .. }
        | Command::Append { .. }
        | Command::Rename { .. } => true,
        // `fields + …` keeps the raw column only if it explicitly retains it
        // (or `*`); `fields - …` keeps it unless it is removed.
        Command::Fields { fields, keep } => {
            if *keep {
                fields.iter().any(|f| f == "timestamp" || f == "*")
            } else {
                !fields.iter().any(|f| f == "timestamp")
            }
        }
        // `bin` keeps the raw `timestamp` column except when a hop window or an
        // in-place tumbling bin rewrites `timestamp` itself.
        Command::Bin {
            span,
            field,
            alias,
            window_type,
        } => bin_keeps_raw_timestamp(span, field.as_deref(), alias.as_deref(), window_type),
        _ => false,
    }
}

/// Whether a `bin` command leaves the raw `timestamp` column intact, mirroring
/// the SQL generation in `clickhouse_sql_gen::commands`:
/// - numeric bins touch a numeric column, never `timestamp`;
/// - time bins on a *non-`timestamp`* field leave `timestamp` alone;
/// - a **tumbling** time bin that writes the bucket to a *different* column
///   (`SELECT *, … AS time_bucket`) keeps `timestamp`;
/// - a **hop** window or an **in-place** tumbling bin (`alias == "timestamp"`)
///   emits `SELECT * EXCEPT (timestamp), …` and drops the raw column.
fn bin_keeps_raw_timestamp(
    span: &BinSpan,
    field: Option<&str>,
    alias: Option<&str>,
    window_type: &WindowType,
) -> bool {
    let BinSpan::Time(_) = span else {
        return true; // numeric bin never touches `timestamp`
    };
    let field_name = match field {
        Some("_time") | None => "timestamp",
        Some(f) => f,
    };
    if field_name != "timestamp" {
        return true;
    }
    // Default alias matches the SQL generator: an explicit field bins in place
    // (alias = field name); the default `timestamp` field bins to `time_bucket`.
    let alias_name = alias.unwrap_or(if field.is_some() {
        field_name
    } else {
        "time_bucket"
    });
    matches!(window_type, WindowType::Tumbling) && alias_name != "timestamp"
}

/// Append the canonical `min(timestamp) as _first_seen` /
/// `max(timestamp) as _last_seen` aggregations.
///
/// NAN-1308: this is **unconditional** — we always add the system-named
/// `_first_seen`/`_last_seen`, even when the rule already aliases its own
/// `min/max(timestamp)` (e.g. `... as first_seen`). The canonical pair is the
/// stable, user-uncontrollable identity the cross-execution finding dedup keys
/// on; backing off whenever a user supplied their own (arbitrarily-named) time
/// aggregation left findings without a canonical window and re-hashed every
/// cycle (flood). The only skip is idempotency: don't add a `_first_seen` /
/// `_last_seen` that is already present (e.g. on a second enrichment pass).
fn enrich_aggregations(aggregations: &[Aggregation]) -> Vec<Aggregation> {
    let mut new_aggs = aggregations.to_vec();

    if !alias_in_use(&new_aggs, "_first_seen") {
        new_aggs.push(Aggregation::with_alias(
            AggFunc::Min,
            Some("timestamp".to_string()),
            "_first_seen".to_string(),
        ));
    }

    if !alias_in_use(&new_aggs, "_last_seen") {
        new_aggs.push(Aggregation::with_alias(
            AggFunc::Max,
            Some("timestamp".to_string()),
            "_last_seen".to_string(),
        ));
    }

    new_aggs
}

/// Whether some aggregation already uses `alias` (only the canonical
/// `_first_seen`/`_last_seen` system names matter here — user aliases like
/// `first_seen` do NOT suppress injection, by design).
fn alias_in_use(aggregations: &[Aggregation], alias: &str) -> bool {
    aggregations
        .iter()
        .any(|agg| agg.alias.as_deref() == Some(alias))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::parse_query;

    #[test]
    fn test_injects_timestamp_bounds_into_stats() {
        let query = parse_query("error | stats count by src_ip").unwrap();
        let enriched = inject_timestamp_bounds(&query);

        // Extract the stats command
        if let Query::Piped { command, .. } = &enriched {
            if let Command::Stats { aggregations, .. } = command {
                assert_eq!(aggregations.len(), 3); // count + _first_seen + _last_seen
                assert_eq!(aggregations[1].alias.as_deref(), Some("_first_seen"));
                assert_eq!(aggregations[1].func, AggFunc::Min);
                assert_eq!(aggregations[1].field.as_deref(), Some("timestamp"));
                assert_eq!(aggregations[2].alias.as_deref(), Some("_last_seen"));
                assert_eq!(aggregations[2].func, AggFunc::Max);
                assert_eq!(aggregations[2].field.as_deref(), Some("timestamp"));
            } else {
                panic!("Expected Stats command");
            }
        } else {
            panic!("Expected Piped query");
        }
    }

    #[test]
    fn test_injects_canonical_even_when_user_aliases_own_window() {
        // NAN-1308: a rule that aliases its OWN min/max(timestamp) to arbitrary
        // names (here `first_seen`/`last_seen`) must STILL get the canonical
        // `_first_seen`/`_last_seen` injected, so the finding dedup has a
        // system-controlled window regardless of user naming.
        let query = parse_query(
            "error | stats count, min(timestamp) as first_seen, max(timestamp) as last_seen by src_ip",
        )
        .unwrap();
        let enriched = inject_timestamp_bounds(&query);

        if let Query::Piped {
            command: Command::Stats { aggregations, .. },
            ..
        } = &enriched
        {
            // count + user first_seen + user last_seen + _first_seen + _last_seen
            assert_eq!(aggregations.len(), 5);
            assert!(aggregations
                .iter()
                .any(|a| a.alias.as_deref() == Some("_first_seen")));
            assert!(aggregations
                .iter()
                .any(|a| a.alias.as_deref() == Some("_last_seen")));
        } else {
            panic!("Expected Stats command");
        }
    }

    #[test]
    fn test_idempotent_when_canonical_alias_already_present() {
        // Two enrichment passes must not duplicate the canonical pair.
        let query = parse_query("error | stats count by src_ip").unwrap();
        let once = inject_timestamp_bounds(&query);
        let twice = inject_timestamp_bounds(&once);

        if let Query::Piped {
            command: Command::Stats { aggregations, .. },
            ..
        } = &twice
        {
            assert_eq!(aggregations.len(), 3); // count + _first_seen + _last_seen, no dupes
        } else {
            panic!("Expected Stats command");
        }
    }

    #[test]
    fn test_no_modification_for_non_stats_query() {
        let query = parse_query("error | where status=500 | head 10").unwrap();
        let enriched = inject_timestamp_bounds(&query);

        // Should pass through unchanged (no stats command)
        // Just verify it doesn't panic
        assert!(matches!(enriched, Query::Piped { .. }));
    }

    #[test]
    fn test_handles_search_only_query() {
        let query = parse_query("error").unwrap();
        let enriched = inject_timestamp_bounds(&query);
        assert!(matches!(enriched, Query::Search(_)));
    }

    #[test]
    fn test_nested_pipes_with_stats() {
        let query = parse_query("error | where status=500 | stats count by src_ip").unwrap();
        let enriched = inject_timestamp_bounds(&query);

        // The stats is the outermost command, should be enriched
        if let Query::Piped { command, .. } = &enriched {
            if let Command::Stats { aggregations, .. } = command {
                assert_eq!(aggregations.len(), 3);
            } else {
                panic!("Expected Stats command");
            }
        } else {
            panic!("Expected Piped query");
        }
    }

    #[test]
    fn only_first_aggregation_over_raw_stream_is_enriched() {
        // Audit D3: a multi-stage aggregate must enrich ONLY the first stats
        // (which still sees `timestamp`); the second stats runs over collapsed
        // rows where `timestamp` no longer exists, so injecting there would
        // error the whole query every cycle.
        let query = parse_query(
            "error | stats count by src_ip | where count > 1 | stats sum(count) as total",
        )
        .unwrap();
        let enriched = inject_timestamp_bounds(&query);

        // Outer command = the second stats → NOT enriched (only `total`).
        let Query::Piped {
            command: outer,
            source,
        } = &enriched
        else {
            panic!("expected piped");
        };
        match outer {
            Command::Stats { aggregations, .. } => {
                assert_eq!(aggregations.len(), 1, "second stats must not be enriched");
                assert!(!aggregations
                    .iter()
                    .any(|a| a.alias.as_deref() == Some("_first_seen")));
            }
            _ => panic!("expected outer Stats"),
        }

        // Inner first stats (dig past the `where`) → enriched (count + bounds).
        let Query::Piped {
            source: inner_src, ..
        } = source.as_ref()
        else {
            panic!("expected where over stats");
        };
        match inner_src.as_ref() {
            Query::Piped {
                command: Command::Stats { aggregations, .. },
                ..
            } => {
                assert_eq!(aggregations.len(), 3, "first stats must be enriched");
                assert!(aggregations
                    .iter()
                    .any(|a| a.alias.as_deref() == Some("_first_seen")));
                assert!(aggregations
                    .iter()
                    .any(|a| a.alias.as_deref() == Some("_last_seen")));
            }
            _ => panic!("expected inner Stats"),
        }
    }

    #[test]
    fn aggregation_after_fields_projection_is_not_enriched() {
        // `fields src_ip` drops `timestamp`, so the following stats must not be
        // enriched (would reference a nonexistent column). Audit D3.
        let query = parse_query("error | fields src_ip | stats count by src_ip").unwrap();
        let enriched = inject_timestamp_bounds(&query);
        let Query::Piped {
            command: Command::Stats { aggregations, .. },
            ..
        } = &enriched
        else {
            panic!("expected outer Stats");
        };
        assert_eq!(
            aggregations.len(),
            1,
            "stats after `fields` must not be enriched"
        );
        assert!(!aggregations
            .iter()
            .any(|a| a.alias.as_deref() == Some("_first_seen")));
    }

    #[test]
    fn aggregation_after_tumbling_bin_is_enriched() {
        // A tumbling `bin span=5m` keeps `timestamp` (adds a `time_bucket`
        // column via `SELECT *, … AS time_bucket`), so the stats over it is
        // still the first aggregation over the raw stream → enriched.
        let query = parse_query("error | bin span=5m | stats count by time_bucket").unwrap();
        let enriched = inject_timestamp_bounds(&query);
        let Query::Piped {
            command: Command::Stats { aggregations, .. },
            ..
        } = &enriched
        else {
            panic!("expected outer Stats");
        };
        assert!(aggregations
            .iter()
            .any(|a| a.alias.as_deref() == Some("_first_seen")));
        assert!(aggregations
            .iter()
            .any(|a| a.alias.as_deref() == Some("_last_seen")));
    }

    #[test]
    fn hop_bin_drops_timestamp_so_following_stats_is_not_enriched() {
        // Audit D3 (codex): a hop window emits `SELECT * EXCEPT (timestamp)`, so
        // the raw column is gone — the stats over it must NOT be enriched or the
        // query errors every cycle.
        let query =
            parse_query("error | bin span=1h hop=5m | stats count by time_bucket").unwrap();
        let enriched = inject_timestamp_bounds(&query);
        let Query::Piped {
            command: Command::Stats { aggregations, .. },
            ..
        } = &enriched
        else {
            panic!("expected outer Stats");
        };
        assert!(!aggregations
            .iter()
            .any(|a| a.alias.as_deref() == Some("_first_seen")));
    }

    #[test]
    fn rename_preserves_timestamp_so_following_stats_is_enriched() {
        // `rename` emits `SELECT *, <col> AS <new>` — raw `timestamp` survives.
        let query = parse_query("error | rename status as st | stats count by src_ip").unwrap();
        let enriched = inject_timestamp_bounds(&query);
        let Query::Piped {
            command: Command::Stats { aggregations, .. },
            ..
        } = &enriched
        else {
            panic!("expected outer Stats");
        };
        assert!(aggregations
            .iter()
            .any(|a| a.alias.as_deref() == Some("_first_seen")));
    }

    #[test]
    fn bin_keeps_raw_timestamp_classification() {
        use std::time::Duration as StdDuration;
        let hour = BinSpan::Time(StdDuration::from_secs(3600));
        let numeric = BinSpan::Numeric(5000.0);
        let hop = WindowType::Hop {
            advance: StdDuration::from_secs(300),
        };

        // `bin span=1h` (default timestamp field → `time_bucket` alias): keeps it.
        assert!(bin_keeps_raw_timestamp(&hour, None, None, &WindowType::Tumbling));
        // Hop window on timestamp: drops it.
        assert!(!bin_keeps_raw_timestamp(&hour, None, None, &hop));
        // In-place bin on timestamp (`bin timestamp span=1h`): drops it.
        assert!(!bin_keeps_raw_timestamp(
            &hour,
            Some("timestamp"),
            None,
            &WindowType::Tumbling
        ));
        // Binning a non-timestamp column leaves timestamp intact.
        assert!(bin_keeps_raw_timestamp(
            &hour,
            Some("bytes"),
            None,
            &WindowType::Tumbling
        ));
        // Numeric bin never touches timestamp.
        assert!(bin_keeps_raw_timestamp(
            &numeric,
            Some("bytes"),
            None,
            &WindowType::Tumbling
        ));
    }

    #[test]
    fn table_after_aggregation_carries_canonical_bounds() {
        // Audit D14: `stats … | table …` must keep _first_seen/_last_seen so the
        // finding dedup keys on the stable window, not a content hash of the
        // drifting count.
        let q = parse_query("error | stats count by src_ip | table src_ip, count").unwrap();
        let enriched = inject_timestamp_bounds(&q);
        let Query::Piped {
            command: Command::Table { fields },
            ..
        } = &enriched
        else {
            panic!("expected outer Table");
        };
        assert!(fields.iter().any(|f| f.name == "_first_seen"));
        assert!(fields.iter().any(|f| f.name == "_last_seen"));
        assert!(fields.iter().any(|f| f.name == "src_ip"), "original field kept");
    }

    #[test]
    fn fields_after_aggregation_carries_canonical_bounds() {
        // Audit D14: same for a `fields` keep-list projection.
        let q = parse_query("error | stats count by src_ip | fields src_ip, count").unwrap();
        let enriched = inject_timestamp_bounds(&q);
        let Query::Piped {
            command: Command::Fields { fields, keep },
            ..
        } = &enriched
        else {
            panic!("expected outer Fields");
        };
        assert!(*keep);
        assert!(fields.iter().any(|f| f == "_first_seen"));
        assert!(fields.iter().any(|f| f == "_last_seen"));
    }

    // === Audit D15 (NAN-1711): timechart / top / rare enrichment ===

    #[test]
    fn timechart_over_raw_stream_gets_canonical_bounds() {
        let q = parse_query("error | timechart span=1h count by src_ip").unwrap();
        let enriched = inject_timestamp_bounds(&q);
        let Query::Piped {
            command: Command::Timechart { aggregations, .. },
            ..
        } = &enriched
        else {
            panic!("expected outer Timechart");
        };
        assert_eq!(aggregations.len(), 3, "count + _first_seen + _last_seen");
        // Appended (never prepended): the split-series `limit=N` ranking keys on
        // the FIRST aggregation and must stay on the user's count.
        assert_eq!(aggregations[1].alias.as_deref(), Some("_first_seen"));
        assert_eq!(aggregations[1].func, AggFunc::Min);
        assert_eq!(aggregations[2].alias.as_deref(), Some("_last_seen"));
        assert_eq!(aggregations[2].func, AggFunc::Max);
    }

    #[test]
    fn timechart_after_timestamp_drop_is_not_enriched() {
        // Audit D3 trap: `fields src_ip` drops `timestamp`; injecting
        // min(timestamp) into the timechart would error the whole query.
        let q = parse_query("error | fields src_ip | timechart span=1h count").unwrap();
        let enriched = inject_timestamp_bounds(&q);
        let Query::Piped {
            command: Command::Timechart { aggregations, .. },
            ..
        } = &enriched
        else {
            panic!("expected outer Timechart");
        };
        assert_eq!(aggregations.len(), 1, "no bounds after timestamp is gone");
    }

    #[test]
    fn timechart_enrichment_is_idempotent() {
        let q = parse_query("error | timechart span=1h count").unwrap();
        let twice = inject_timestamp_bounds(&inject_timestamp_bounds(&q));
        let Query::Piped {
            command: Command::Timechart { aggregations, .. },
            ..
        } = &twice
        else {
            panic!("expected outer Timechart");
        };
        assert_eq!(aggregations.len(), 3, "no duplicate canonical pair");
    }

    #[test]
    fn top_and_rare_over_raw_stream_get_inject_bounds() {
        for (q, want_top) in [("error | top src_ip", true), ("error | rare src_ip", false)] {
            let enriched = inject_timestamp_bounds(&parse_query(q).unwrap());
            let Query::Piped { command, .. } = &enriched else {
                panic!("expected piped");
            };
            match command {
                Command::Top { inject_bounds, .. } if want_top => {
                    assert!(*inject_bounds, "{q}: top must be flagged")
                }
                Command::Rare { inject_bounds, .. } if !want_top => {
                    assert!(*inject_bounds, "{q}: rare must be flagged")
                }
                other => panic!("{q}: unexpected command {other:?}"),
            }
        }
    }

    #[test]
    fn top_after_timestamp_drop_is_not_flagged() {
        // Audit D3 trap: after `fields src_ip` the SQL gen would emit
        // min(timestamp) over a stream without the column.
        let q = parse_query("error | fields src_ip | top src_ip").unwrap();
        let enriched = inject_timestamp_bounds(&q);
        let Query::Piped {
            command: Command::Top { inject_bounds, .. },
            ..
        } = &enriched
        else {
            panic!("expected outer Top");
        };
        assert!(!*inject_bounds, "top after timestamp drop must stay unflagged");
    }

    #[test]
    fn table_after_enriched_top_carries_canonical_bounds() {
        // Audit D14 carry-through applies to the enriched top output too.
        let q = parse_query("error | top src_ip | table src_ip, count").unwrap();
        let enriched = inject_timestamp_bounds(&q);
        let Query::Piped {
            command: Command::Table { fields },
            ..
        } = &enriched
        else {
            panic!("expected outer Table");
        };
        assert!(fields.iter().any(|f| f.name == "_first_seen"));
        assert!(fields.iter().any(|f| f.name == "_last_seen"));
    }

    #[test]
    fn enriched_query_survives_pretty_print_reparse_round_trip() {
        // evaluate_window pretty-prints the enriched AST back to nPL and the
        // search service re-parses it — the enrichment must survive that
        // round-trip byte-exactly or the whole fix is a no-op in production.
        for q in [
            "error | top src_ip",
            "error | rare 5 status by user",
            "error | timechart span=1h count by src_ip",
        ] {
            let enriched = inject_timestamp_bounds(&parse_query(q).unwrap());
            let printed = crate::query::PrettyPrint::pretty_print(&enriched);
            let reparsed = parse_query(&printed)
                .unwrap_or_else(|e| panic!("{q}: round-trip parse failed on `{printed}`: {e}"));
            assert_eq!(
                reparsed, enriched,
                "{q}: enriched AST must survive pretty_print → re-parse (got `{printed}`)"
            );
        }
    }

    #[test]
    fn top_on_bound_alias_skips_injection_no_carry_through() {
        // Audit D15 (codex): `| top _first_seen` collides the injected alias, so
        // SQL-gen skips the bounds. Enrichment must set `inject_bounds = false`
        // AND NOT mark the stream as carrying bounds — else a downstream `table`
        // appends a `_last_seen` that was never emitted → UNKNOWN_IDENTIFIER
        // every cycle.
        let q = parse_query("* | top _first_seen | table _first_seen, count").unwrap();
        let enriched = inject_timestamp_bounds(&q);
        let Query::Piped {
            command: Command::Table { fields },
            source,
        } = &enriched
        else {
            panic!("expected outer Table");
        };
        // No `_last_seen` carry-through (it was never emitted by the top).
        assert!(
            !fields.iter().any(|f| f.name == "_last_seen"),
            "collision must NOT carry `_last_seen` through the table"
        );
        // The inner top must have `inject_bounds = false`.
        let Query::Piped {
            command:
                Command::Top {
                    inject_bounds, ..
                },
            ..
        } = source.as_ref()
        else {
            panic!("expected inner Top");
        };
        assert!(
            !inject_bounds,
            "collision must skip bounds injection on the top"
        );
    }
}
