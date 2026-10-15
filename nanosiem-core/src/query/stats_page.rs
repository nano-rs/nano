// SPDX-License-Identifier: AGPL-3.0-or-later
//! The deliberately narrow proof for paging a complete grouped result.
use super::{Command, Query};

pub const TOTAL_ALIAS: &str = "__nano_stats_total";
pub const ORDINAL_ALIAS: &str = "__nano_stats_ordinal";
pub const TOTAL_EXPRESSION: &str = "count() OVER () AS __nano_stats_total";

/// Only ordering and bounded prefixes may follow a raw-search stats stage.
/// Filters, joins, nested scans and additional aggregates retain full-set
/// execution. Slice callers must still fetch every partial group before their
/// global merge; an exact total alone does not prove complete delivery.
pub fn eligible(query: &Query) -> bool {
    match query {
        Query::Piped {
            source,
            command:
                Command::Stats {
                    aggregations,
                    group_by: Some(groups),
                },
        } => {
            matches!(source.as_ref(), Query::Search(_))
                && !groups.is_empty()
                && !groups
                    .iter()
                    .any(|g| g == TOTAL_ALIAS || g == ORDINAL_ALIAS)
                && !aggregations
                    .iter()
                    .any(|a| matches!(a.output_alias().as_str(), TOTAL_ALIAS | ORDINAL_ALIAS))
        }
        Query::Piped {
            source,
            command: Command::Sort { .. } | Command::Head { .. },
        } => eligible(source),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::parse_query;
    #[test]
    fn only_complete_group_pages_are_eligible() {
        for q in [
            "* | stats count by user",
            "* | stats count, max(timestamp) as last_seen by user | sort -count | head 5",
            "* | stats count by src_ip, process_name | head 100",
        ] {
            assert!(eligible(&parse_query(q).unwrap()), "{q}");
        }
        for q in [
            "* | stats count",
            "* | stats count by user | where count > 10",
            "* | stats count by user | eventstats sum(count) as total",
            "* | stats count by user | stats count",
            "* | eval x=1 | stats count by user",
            "* | stats count as __nano_stats_total by user",
        ] {
            assert!(!eligible(&parse_query(q).unwrap()), "{q}");
        }
    }
}
