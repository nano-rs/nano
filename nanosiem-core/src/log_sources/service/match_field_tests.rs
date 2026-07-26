// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2158: write-boundary validation of `log_sources.match_field`.
//!
//! `match_field` names the COLUMN the source-health query matches on and is
//! interpolated into generated ClickHouse SQL as a bare identifier. #3406
//! hardened the read SINK (which is what neutralizes rows already persisted
//! with a hostile value); these tests pin the other half — that the service
//! refuses to STORE one in the first place, on every writer, not just the HTTP
//! handler.
//!
//! The end-to-end payload behaviour (that the hostile value cannot comment out
//! the appended source-scope predicate) is covered at the sink by
//! `log_sources::repository::health::hostile_match_field_cannot_comment_out_the_scope_predicate`.

use super::crud::validate_match_field;
use super::LogSourceServiceError;

fn rejects(field: &str) -> bool {
    matches!(
        validate_match_field(Some(field)),
        Err(LogSourceServiceError::InvalidMatchField(_))
    )
}

/// The exact NAN-2158 proof payload. `lower(` closes early and `--` comments
/// out everything appended to the line, including the source-scope gate.
#[test]
fn the_scope_bypass_payload_is_refused_at_the_write_boundary() {
    assert!(rejects("source_type) = 'audit' --"));
}

#[test]
fn expression_breakouts_are_refused() {
    for payload in [
        "source_type)/*",
        "source_type; DROP TABLE logs",
        "source_type) OR 1=1 --",
        "(SELECT 1)",
        "'source_type'",
        "`source_type`",
        "source type",
        "source\ntype",
        "source-type",
    ] {
        assert!(rejects(payload), "should refuse {payload:?}");
    }
}

/// A rejected write must name the field so an operator repairing a legacy row
/// can see WHICH value is wrong — the read sink's silent downgrade to
/// `source_type` is exactly the failure mode this replaces.
#[test]
fn the_error_names_the_offending_value() {
    let Err(LogSourceServiceError::InvalidMatchField(msg)) =
        validate_match_field(Some("source_type) = 'audit' --"))
    else {
        panic!("expected InvalidMatchField");
    };
    assert!(msg.contains("source_type) = 'audit' --"), "got: {msg}");
}

/// Real column names — including the dotted OCSF nested form — must keep
/// working, or this change breaks ingestion telemetry for every OCSF feed.
#[test]
fn legitimate_column_names_are_accepted() {
    for ok in [
        "source_type",
        "host",
        "src_host",
        "metadata.product.name",
        "src_endpoint.ip",
    ] {
        assert!(
            validate_match_field(Some(ok)).is_ok(),
            "should accept {ok:?}"
        );
    }
}

/// `None` (field omitted / "no change" on update) and `""` both mean "no
/// explicit match column"; the sink falls back to `source_type`. Rejecting
/// them would break every log source created without one — which, on the dev
/// database, is all of them.
#[test]
fn absent_and_empty_are_allowed() {
    assert!(validate_match_field(None).is_ok());
    assert!(validate_match_field(Some("")).is_ok());
}

/// The write validator and the read sink must agree, or a value accepted on
/// write would still be silently downgraded at query time (and vice versa: a
/// value the sink accepts would be un-storable).
#[test]
fn write_validator_agrees_with_the_read_sink_validator() {
    for candidate in [
        "source_type",
        "metadata.product.name",
        "source_type) = 'audit' --",
        "source-type",
        "a b",
        "",
    ] {
        let write_ok = validate_match_field(Some(candidate)).is_ok();
        let sink_ok = crate::sql_hygiene::is_safe_sql_identifier(candidate);
        // Empty is the one deliberate divergence: the write path treats it as
        // "unset" while the sink treats it as not-an-identifier. Both end up
        // falling back to `source_type`, so the outcomes still agree.
        if candidate.is_empty() {
            assert!(write_ok && !sink_ok);
            continue;
        }
        assert_eq!(
            write_ok, sink_ok,
            "write and sink disagree about {candidate:?}"
        );
    }
}
