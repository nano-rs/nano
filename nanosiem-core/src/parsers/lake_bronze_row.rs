// SPDX-License-Identifier: AGPL-3.0-or-later

//! The fixed bronze row contract (NAN-3339).
//!
//! Vector's bronze sink (`ocsf_parquet_bronze`, `schema_mode = "auto_infer"`)
//! encodes each batch as ONE Parquet file whose Arrow schema it infers from
//! that batch. One row whose shape conflicts with the others (an object where
//! the rest carry a string, an array beside a scalar, a number beside a
//! string, an empty object) fails the encode, and Vector drops the WHOLE
//! batch: every co-batched row of every source, after the sender was already
//! acknowledged. NAN-3079 and NAN-3304 closed two instances lane by lane.
//!
//! [`LAKE_BRONZE_ROW_VRL`] closes the class. It runs as the last step of
//! `ocsf_lake_storage_prepare`, the one transform every lane (generic,
//! platform audit, every tenant parser's `_ocsf_prepare`) passes through on
//! its way to the bronze sink (`ocsf_output_guard` is its only consumer and
//! the sink's only input; the product contract pins that wiring). After it,
//! every bronze row has exactly the same columns, whatever its lane or
//! payload:
//!
//! * `time`: the event time, always a timestamp (the stage sets it), so the
//!   column stays the Timestamp it was and bronze objects keep their time
//!   statistics;
//! * [`BRONZE_EVENT_COLUMN`]: the rest of the canonical OCSF row as ONE
//!   JSON string.
//!
//! (`_nano_bronze_partition` stays a top-level helper for the S3 key
//! template; the sink's `except_fields` strips it before encoding.)
//!
//! A batch of such rows has one schema by construction, so shape drift can
//! no longer fail the encode. `ingest[T]` turns the row back into the event
//! the columnar form decoded to (`nanosiem_lake_worker::bronze::decode_bronze_row`),
//! and still reads columnar bronze written before the contract.

/// The bronze column carrying the OCSF row (minus `time`) as one JSON string.
pub const BRONZE_EVENT_COLUMN: &str = "_nano_bronze_event";

/// The bronze column carrying the event time (a Parquet timestamp).
pub const BRONZE_TIME_COLUMN: &str = "time";

/// First line of [`LAKE_BRONZE_ROW_VRL`]: marks a storage stage that already
/// carries the contract.
pub const LAKE_BRONZE_ROW_MARKER: &str = "# NAN-3339: the fixed bronze row contract.";

/// The contract's VRL, appended to the end of `ocsf_lake_storage_prepare`
/// (after it has stamped metadata, `time` and the partition helper).
/// Infallible: it cannot error or abort, so it adds no drop path.
pub const LAKE_BRONZE_ROW_VRL: &str = r#"# NAN-3339: the fixed bronze row contract.
# The sink infers ONE Parquet schema per Vector batch, so a single row of
# another shape (an object where other rows carry a string, an array beside
# a scalar, a number beside a string, an empty object) failed the encode and
# Vector dropped the WHOLE batch, every lane's rows. Every bronze row now has
# the same columns: `time` (a timestamp) and `_nano_bronze_event`, the rest
# of the OCSF row as ONE JSON string. ingest[T] decodes it back.
bronze_row = {}
if exists(._nano_bronze_partition) { bronze_row._nano_bronze_partition = del(._nano_bronze_partition) }
bronze_time = del(.time)
# This stage always sets `.time` to a timestamp; the fallback only keeps the
# column's type fixed.
if !is_timestamp(bronze_time) { bronze_time = now() }
bronze_row.time = bronze_time
bronze_row._nano_bronze_event = encode_json(.)
. = bronze_row
"#;

/// Append [`LAKE_BRONZE_ROW_VRL`] to the `[transforms.ocsf_lake_storage_prepare]`
/// VRL of one `_ocsf_sink.toml` text (the end of its `source = '''` block).
/// `None` when the text has no such stage, when it is not exactly one, or
/// when the stage already carries the contract.
pub fn append_to_storage_prepare(text: &str) -> Option<String> {
    const SECTION: &str = "[transforms.ocsf_lake_storage_prepare]\n";
    const OPEN: &str = "source = '''\n";
    const CLOSE: &str = "\n'''\n";
    if text.matches(SECTION).count() != 1 {
        return None;
    }
    let start = text.find(SECTION)?;
    let body_start = start + text[start..].find(OPEN)? + OPEN.len();
    // The stage's own `source` must open before the next section.
    let next_section = text[start + SECTION.len()..]
        .find("\n[")
        .map(|i| start + SECTION.len() + i);
    if next_section.is_some_and(|next| body_start > next) {
        return None;
    }
    let body_end = body_start + text[body_start..].find(CLOSE)?;
    if text[body_start..body_end].contains(LAKE_BRONZE_ROW_MARKER) {
        return None;
    }
    Some(format!(
        "{}\n{}{}",
        &text[..body_end],
        LAKE_BRONZE_ROW_VRL.trim_end_matches('\n'),
        &text[body_end..]
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_contract_vrl_compiles_and_is_infallible() {
        let compiled = vrl::compiler::compile(LAKE_BRONZE_ROW_VRL, &vrl::stdlib::all())
            .unwrap_or_else(|d| panic!("{d:?}"));
        assert!(compiled.warnings.is_empty(), "{:?}", compiled.warnings);
        assert!(LAKE_BRONZE_ROW_VRL.starts_with(LAKE_BRONZE_ROW_MARKER));
        assert!(LAKE_BRONZE_ROW_VRL.contains(BRONZE_EVENT_COLUMN));
        assert!(!LAKE_BRONZE_ROW_VRL.contains("abort") && !LAKE_BRONZE_ROW_VRL.contains("!("));
    }

    #[test]
    fn append_edits_only_the_storage_stage_once() {
        let text = "[transforms.ocsf_lake_storage_prepare]\ntype = \"remap\"\nsource = '''\n.a = 1\n'''\n\n[sinks.x]\ntype = \"blackhole\"\n";
        let out = append_to_storage_prepare(text).unwrap();
        assert!(out.starts_with("[transforms.ocsf_lake_storage_prepare]\ntype = \"remap\"\nsource = '''\n.a = 1\n# NAN-3339"));
        assert!(
            out.ends_with(". = bronze_row\n'''\n\n[sinks.x]\ntype = \"blackhole\"\n"),
            "{out}"
        );
        assert_eq!(
            append_to_storage_prepare(&out),
            None,
            "already carries the contract"
        );
        assert_eq!(append_to_storage_prepare("[sinks.x]\n"), None);
        assert_eq!(append_to_storage_prepare(&format!("{text}{text}")), None);
    }
}
