// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

impl SearchService {
    /// Post-process funnel command results into the view shape the frontend
    /// expects.
    ///
    /// The SQL layer emits per-stage rows with these columns (see
    /// `generate_funnel_sql`):
    ///
    /// - `funnel_level`, `step_name`, `count` — standard funnel output
    /// - `dropper_count`, `dropper_median_idle_s` — aggregated stats for
    ///   entities that reached this stage but not the next
    /// - `_droppers_<field>` — sampled arrays (up to 1000 values) of the
    ///   per-entity `argMax(field, timestamp)` values for droppers at this
    ///   stage
    ///
    /// Post-processing here converts the raw `_droppers_<field>` arrays into
    /// a compact `dropper_top_attrs` JSON array of
    /// `{ field, value, count, pct }` objects — top 5 values per field,
    /// sorted by count desc. The internal `_droppers_*` columns are then
    /// dropped from the output.
    pub(crate) fn build_funnel_view(
        &self,
        results: Vec<serde_json::Value>,
        // Reserved for future per-command customization (e.g. per-byfield
        // attribution). Keep the plumbing even though today we only use the
        // shared field list — mirrors tree_view / asset_view signatures.
        _info: &FunnelCommandInfo,
    ) -> Vec<serde_json::Value> {
        use crate::search::query_processing::FUNNEL_DROPPER_FIELDS;

        const TOP_K: usize = 5;

        results
            .into_iter()
            .map(|mut row| {
                let Some(obj) = row.as_object_mut() else {
                    return row;
                };

                let dropper_count = obj
                    .get("dropper_count")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0)
                    .max(0) as u64;

                let mut top_attrs: Vec<serde_json::Value> = Vec::new();

                for &field in FUNNEL_DROPPER_FIELDS {
                    let key = format!("_droppers_{}", field);
                    let Some(arr) = obj.remove(&key) else {
                        continue;
                    };
                    let Some(values) = arr.as_array() else {
                        continue;
                    };

                    // Tally non-empty values
                    let mut counts: std::collections::HashMap<String, u64> =
                        std::collections::HashMap::new();
                    for v in values {
                        let s = match v {
                            serde_json::Value::String(s) => s.clone(),
                            serde_json::Value::Null => continue,
                            other => other.to_string(),
                        };
                        if s.is_empty() || s == "\"\"" {
                            continue;
                        }
                        *counts.entry(s).or_insert(0) += 1;
                    }

                    if counts.is_empty() {
                        continue;
                    }

                    // Sort by count desc, take top K
                    let mut entries: Vec<(String, u64)> = counts.into_iter().collect();
                    entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
                    entries.truncate(TOP_K);

                    // Sample size is capped at 1000 rows server-side; if the
                    // actual dropper_count exceeds 1000, the percentages we
                    // report are fractions of the sample, which is the best
                    // we can do without a full scan. Use sample size as the
                    // denominator when dropper_count > sample size so the
                    // math stays truthful.
                    let sample_size: u64 = values.len() as u64;
                    let denom = if dropper_count > 0 && dropper_count <= sample_size {
                        dropper_count
                    } else {
                        sample_size.max(1)
                    };

                    for (value, count) in entries {
                        let pct = (count as f64 / denom as f64) * 100.0;
                        top_attrs.push(serde_json::json!({
                            "field": field,
                            "value": value,
                            "count": count,
                            "pct": (pct * 10.0).round() / 10.0,
                        }));
                    }
                }

                obj.insert(
                    "dropper_top_attrs".to_string(),
                    serde_json::Value::Array(top_attrs),
                );
                row
            })
            .collect()
    }
}
