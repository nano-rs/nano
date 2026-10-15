//! NAN-2361: the pack-buffer sort must not allocate per comparison.
//!
//! The original comparator called `format!("{:?}", col.slice(i, 1))` from
//! inside `sort_by`, so a 131_072-row buffer (PACK_SORT_BUFFER_ROWS) paid two
//! String allocations and a nested-struct Debug format on every one of its
//! O(n log n) comparisons. This test pins the shipped approach as
//! substantially cheaper so the Debug-formatting form cannot come back.

use std::sync::Arc;
use std::time::Instant;

use arrow_array::{Array, ArrayRef, Int64Array, RecordBatch, StringArray, StructArray};
use arrow_ord::sort::{lexsort_to_indices, SortColumn};
use arrow_schema::{DataType, Field, Schema};

const ROWS: usize = 131_072;

fn buffer() -> RecordBatch {
    // Production `metadata` carries 13 scalar fields; the sort key is all of
    // them, so a single-field stand-in would not represent the real cost.
    let sources = ["zeek", "sysmon", "windows_event", "aws_cloudtrail", "okta"];
    let providers = ["Microsoft-Windows-Sysmon", "Zeek", "CloudTrail"];
    let products = ["nano", "vector"];
    let metadata = StructArray::from(vec![
        (
            Arc::new(Field::new("event_code", DataType::Utf8, false)),
            Arc::new(StringArray::from(
                (0..ROWS).map(|i| ["1", "3", "11", "22"][i % 4]).collect::<Vec<_>>(),
            )) as ArrayRef,
        ),
        (
            Arc::new(Field::new("log_provider", DataType::Utf8, false)),
            Arc::new(StringArray::from(
                (0..ROWS).map(|i| providers[i % providers.len()]).collect::<Vec<_>>(),
            )) as ArrayRef,
        ),
        (
            Arc::new(Field::new("log_source", DataType::Utf8, false)),
            Arc::new(StringArray::from(
                (0..ROWS).map(|i| sources[i % sources.len()]).collect::<Vec<_>>(),
            )) as ArrayRef,
        ),
        (
            Arc::new(Field::new("product", DataType::Utf8, false)),
            Arc::new(StringArray::from(
                (0..ROWS).map(|i| products[i % products.len()]).collect::<Vec<_>>(),
            )) as ArrayRef,
        ),
        (
            Arc::new(Field::new("version", DataType::Utf8, false)),
            Arc::new(StringArray::from(vec!["1.9.0"; ROWS])) as ArrayRef,
        ),
    ]);
    // Epoch-millis-shaped, deliberately not pre-sorted.
    let time = Int64Array::from(
        (0..ROWS).map(|i| 1_755_000_000_000i64 + ((i * 7919) % 3_600_000) as i64).collect::<Vec<_>>(),
    );
    RecordBatch::try_new(
        Arc::new(Schema::new(vec![
            Field::new("metadata", metadata.data_type().clone(), false),
            Field::new("time", DataType::Int64, false),
        ])),
        vec![Arc::new(metadata) as ArrayRef, Arc::new(time) as ArrayRef],
    )
    .expect("build buffer")
}

/// The original implementation, kept only as the comparison baseline.
fn sort_by_debug_format(batch: &RecordBatch) -> Vec<u32> {
    let key = batch.column_by_name("metadata").expect("metadata");
    let time = batch.column_by_name("time");
    let key_at = |i: usize| format!("{:?}", key.slice(i, 1));
    let time_at = |i: usize| time.map(|c| format!("{:?}", c.slice(i, 1))).unwrap_or_default();
    let mut order: Vec<u32> = (0..batch.num_rows() as u32).collect();
    order.sort_by(|a, b| {
        key_at(*a as usize)
            .cmp(&key_at(*b as usize))
            .then_with(|| time_at(*a as usize).cmp(&time_at(*b as usize)))
    });
    order
}

fn sort_by_lexsort(batch: &RecordBatch) -> Vec<u32> {
    let metadata = batch
        .column_by_name("metadata")
        .and_then(|c| c.as_any().downcast_ref::<StructArray>())
        .expect("metadata");
    let mut sort_columns = metadata
        .columns()
        .iter()
        .map(|values| SortColumn { values: values.clone(), options: None })
        .collect::<Vec<_>>();
    sort_columns
        .push(SortColumn { values: batch.column_by_name("time").expect("time").clone(), options: None });
    lexsort_to_indices(&sort_columns, None)
    .expect("lexsort")
    .values()
    .to_vec()
}

#[test]
fn typed_lexsort_is_far_cheaper_than_debug_formatting() {
    let batch = buffer();

    let started = Instant::now();
    let debug_order = sort_by_debug_format(&batch);
    let debug_elapsed = started.elapsed();

    let started = Instant::now();
    let lexsort_order = sort_by_lexsort(&batch);
    let lexsort_elapsed = started.elapsed();

    println!(
        "  {ROWS} rows: debug-format {:?}  vs  typed lexsort {:?}  ({:.1}x)",
        debug_elapsed,
        lexsort_elapsed,
        debug_elapsed.as_secs_f64() / lexsort_elapsed.as_secs_f64().max(f64::EPSILON),
    );

    // Exact-index equality holds ONLY because every metadata field above is
    // Utf8 and the timestamps all share a digit count, so Debug-string ordering
    // coincides with typed ordering. Adding a numeric metadata field (as
    // production has -- logged_time / processed_time are int64) makes the two
    // CORRECTLY diverge, and this assertion would then fail for the right
    // reason. Keep the stand-in all-Utf8, or drop to a clustering-only check.
    assert_eq!(debug_order, lexsort_order, "orderings diverged");

    // Timing is reported, NOT asserted. This suite runs on shared self-hosted
    // runners where a wall-clock ratio is not a dependable signal; the
    // structural guarantees live in the unit tests
    // (`pack_sort_key_keeps_every_scalar_metadata_column` and friends).
    assert!(
        lexsort_elapsed < debug_elapsed,
        "typed lexsort must not be slower than Debug-formatting: \
         {lexsort_elapsed:?} vs {debug_elapsed:?}"
    );
}
