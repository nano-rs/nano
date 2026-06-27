// SPDX-License-Identifier: AGPL-3.0-or-later

//! IOC lookup-source pre-resolution (NAN-1581 Phase 6).
//!
//! The `ioc in lookup("<table>")` surface form (see
//! [`crate::query::ast::IocLookup`]) sweeps the indicator values stored in an
//! internal lookup table through the existing observable matchset. Rather than
//! teach the SQL generator about lookup tables (which would couple it to the
//! PG/CH lookup storage backend), the service layer PRE-RESOLVES the lookup
//! source to concrete `IocMatch::values` BEFORE SQL generation — mirroring how
//! the retro engine pre-resolves `feed(...)` to indicator values. Once resolved,
//! the existing OCSF/UDM-aware matchset (`generate_ioc_match_filter`) handles
//! column resolution unchanged, so the term is automatically profile-aware.
//!
//! Applied in BOTH execution paths:
//! * standalone search (`core_search`) — before SQL generation;
//! * retro-hunt (`retro::build_retro_view`) — alongside the feed pull.

use std::collections::HashSet;

use crate::lookup::{LookupError, LookupService};
use crate::query::{IocLookup, Query, SearchExpr, Value};
use crate::search::SearchError;

/// Hard cap on the number of indicator values expanded from a single lookup
/// table. A lookup table can hold up to a million rows (`MAX_LOOKUP_TABLE_ROWS`);
/// sweeping all of them through the observable matchset would generate an
/// enormous OR-of-equalities predicate, so the resolver errors clearly past this
/// bound rather than emitting an unusable query.
pub(crate) const LOOKUP_IOC_MAX: usize = 50_000;

/// Resolve a single `IocLookup` source to a deduped list of indicator values.
///
/// * validates the table exists via `get_table` — an unknown table surfaces a
///   clear `SearchError` naming the available lookups (NAN-1389 style);
/// * reads the values of the requested `column` (or the table's registry
///   primary-key column, else its first column) via `read_all_rows`;
/// * dedups (case-insensitively-keyed, preserving first-seen original value) and
///   caps at [`LOOKUP_IOC_MAX`] — over the cap is a clear error.
///
/// An EMPTY lookup (0 rows) resolves to an empty list — the caller substitutes a
/// term that matches nothing (with a warning), it is NOT an error.
pub(crate) async fn resolve_ioc_lookup(
    lookup: &IocLookup,
    lookup_service: Option<&LookupService>,
) -> Result<Vec<String>, SearchError> {
    let Some(service) = lookup_service else {
        return Err(SearchError::SqlValidationError(
            "`ioc in lookup(...)` requires the lookup service, which is not \
             configured for this search."
                .to_string(),
        ));
    };

    // Validate existence + recover the column set / primary key.
    let table = match service.get_table(&lookup.table).await {
        Ok(t) => t,
        Err(LookupError::TableNotFound(_)) => {
            let available: Vec<String> = match service.list_tables().await {
                Ok(tables) => tables.into_iter().map(|t| t.name).collect(),
                Err(_) => Vec::new(),
            };
            return Err(SearchError::SqlValidationError(unknown_lookup_message(
                &lookup.table,
                &available,
            )));
        }
        Err(e) => {
            return Err(SearchError::SqlValidationError(format!(
                "Failed to read lookup table '{}': {}",
                lookup.table, e
            )));
        }
    };

    // Choose the indicator column: explicit arg → registry primary key → first
    // column. Validate an explicit column actually exists on the table.
    let column = match &lookup.column {
        Some(col) => {
            if !table.columns.iter().any(|c| &c.name == col) {
                let cols: Vec<String> = table.columns.iter().map(|c| c.name.clone()).collect();
                return Err(SearchError::SqlValidationError(format!(
                    "Column '{}' not found in lookup table '{}'. Available columns: {}",
                    col,
                    lookup.table,
                    cols.join(", ")
                )));
            }
            col.clone()
        }
        None => table
            .primary_key
            .clone()
            .or_else(|| table.columns.first().map(|c| c.name.clone()))
            .ok_or_else(|| {
                SearchError::SqlValidationError(format!(
                    "Lookup table '{}' has no columns to read indicators from.",
                    lookup.table
                ))
            })?,
    };

    let rows = service.read_all_rows(&lookup.table).await.map_err(|e| {
        SearchError::SqlValidationError(format!(
            "Failed to read rows from lookup table '{}': {}",
            lookup.table, e
        ))
    })?;

    let mut seen: HashSet<String> = HashSet::new();
    let mut out: Vec<String> = Vec::new();
    for row in &rows {
        let Some(raw) = row.get(&column) else {
            continue;
        };
        let value = json_value_to_indicator(raw);
        let Some(value) = value else { continue };
        if value.is_empty() {
            continue;
        }
        // Dedup case-insensitively (the matchset lowercases anyway).
        if seen.insert(value.to_lowercase()) {
            out.push(value);
            if out.len() > LOOKUP_IOC_MAX {
                return Err(SearchError::SqlValidationError(format!(
                    "Lookup table '{}' column '{}' has more than {} distinct indicator \
                     values — too many to sweep through `ioc in lookup(...)`. Narrow the \
                     table or pre-filter the indicator set.",
                    lookup.table, column, LOOKUP_IOC_MAX
                )));
            }
        }
    }

    Ok(out)
}

/// Convert a lookup-row JSON cell into an indicator string. Strings pass through
/// (trimmed); numbers/bools stringify; null / arrays / objects are skipped.
fn json_value_to_indicator(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => Some(s.trim().to_string()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Build the user-facing error message for an unknown lookup table referenced by
/// `ioc in lookup(...)` (NAN-1389 style).
fn unknown_lookup_message(table_name: &str, available: &[String]) -> String {
    const MAX_LISTED: usize = 10;
    if available.is_empty() {
        format!(
            "Lookup table '{}' (referenced by `ioc in lookup(\"{}\")`) does not exist and no \
             lookup tables are defined. Create the lookup table first.",
            table_name, table_name
        )
    } else {
        let mut listed = available
            .iter()
            .take(MAX_LISTED)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        if available.len() > MAX_LISTED {
            listed.push_str(", …");
        }
        format!(
            "Lookup table '{}' (referenced by `ioc in lookup(\"{}\")`) does not exist. \
             Available lookup tables: {}",
            table_name, table_name, listed
        )
    }
}

/// Whether a parsed query contains any `ioc in lookup(...)` term (cheap pre-check
/// so the standalone path only does the async resolution work when needed).
pub(crate) fn query_has_ioc_lookup(query: &Query) -> bool {
    fn walk(expr: &SearchExpr) -> bool {
        match expr {
            SearchExpr::IocMatch { lookup, .. } => lookup.is_some(),
            SearchExpr::And(l, r) | SearchExpr::Or(l, r) => walk(l) || walk(r),
            SearchExpr::Not(inner) | SearchExpr::Group(inner) => walk(inner),
            _ => false,
        }
    }
    match query {
        Query::Search(expr) => walk(expr),
        Query::Piped { source, .. } => query_has_ioc_lookup(source),
    }
}

/// Walk a parsed query and pre-resolve every `IocMatch` lookup source to concrete
/// `values`, substituting them in place. After this runs the SQL generator never
/// sees an unresolved lookup source.
///
/// An empty resolution (0-row table) leaves an `IocMatch` with empty `values` and
/// a cleared `lookup` — a term that matches nothing — and records a warning.
pub(crate) async fn resolve_ioc_lookup_sources(
    query: &mut Query,
    lookup_service: Option<&LookupService>,
    warnings: &mut Vec<String>,
) -> Result<(), SearchError> {
    // Collect mutable references to every IocMatch carrying a lookup. We resolve
    // sequentially (the count is tiny — usually one).
    let mut nodes: Vec<&mut SearchExpr> = Vec::new();
    collect_ioc_lookup_nodes(query, &mut nodes);

    for node in nodes {
        if let SearchExpr::IocMatch {
            values,
            feed,
            lookup,
        } = node
        {
            let Some(src) = lookup.take() else { continue };
            let resolved = resolve_ioc_lookup(&src, lookup_service).await?;
            if resolved.is_empty() {
                warnings.push(format!(
                    "Lookup table '{}' returned no indicator values — `ioc in lookup(\"{}\")` \
                     matches nothing.",
                    src.table, src.table
                ));
            }
            *values = resolved.into_iter().map(Value::String).collect();
            *feed = None;
        }
    }
    Ok(())
}

/// Depth-first collect mutable references to every `IocMatch` node that has a
/// lookup source.
fn collect_ioc_lookup_nodes<'a>(query: &'a mut Query, out: &mut Vec<&'a mut SearchExpr>) {
    match query {
        Query::Search(expr) => collect_in_expr(expr, out),
        Query::Piped { source, .. } => collect_ioc_lookup_nodes(source, out),
    }
}

fn collect_in_expr<'a>(expr: &'a mut SearchExpr, out: &mut Vec<&'a mut SearchExpr>) {
    // Determine whether THIS node is a lookup-bearing IocMatch without holding a
    // borrow across the recursive descent into children.
    let is_lookup_ioc = matches!(
        expr,
        SearchExpr::IocMatch {
            lookup: Some(_),
            ..
        }
    );
    if is_lookup_ioc {
        out.push(expr);
        return;
    }
    match expr {
        SearchExpr::And(l, r) | SearchExpr::Or(l, r) => {
            collect_in_expr(l, out);
            collect_in_expr(r, out);
        }
        SearchExpr::Not(inner) | SearchExpr::Group(inner) => collect_in_expr(inner, out),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lookup::{LookupColumn, LookupService, LookupStore, LookupTable};
    use async_trait::async_trait;
    use std::collections::HashMap;

    /// Minimal in-memory `LookupStore` for resolver unit tests. Only the methods
    /// the resolver touches (`get_table`, `list_tables`, `list_rows`) carry real
    /// behaviour; the rest are unimplemented (never called here).
    struct MockStore {
        tables: HashMap<String, LookupTable>,
        rows: HashMap<String, Vec<HashMap<String, serde_json::Value>>>,
    }

    fn make_table(name: &str, columns: Vec<LookupColumn>, pk: Option<&str>) -> LookupTable {
        LookupTable {
            id: uuid::Uuid::now_v7(),
            name: name.to_string(),
            description: None,
            table_name: format!("lookup_{name}"),
            columns,
            primary_key: pk.map(|s| s.to_string()),
            row_count: 0,
            size_bytes: 0,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            created_by: None,
        }
    }

    use crate::lookup::repository::{LookupRepositoryError, RuleReferenceRow};
    use crate::lookup::types::NewLookupTable;
    use uuid::Uuid;

    #[async_trait]
    impl LookupStore for MockStore {
        async fn list_tables(&self) -> Result<Vec<LookupTable>, LookupRepositoryError> {
            Ok(self.tables.values().cloned().collect())
        }

        async fn get_table(&self, name: &str) -> Result<LookupTable, LookupRepositoryError> {
            self.tables
                .get(name)
                .cloned()
                .ok_or_else(|| LookupRepositoryError::TableNotFound(name.to_string()))
        }

        async fn table_exists(&self, name: &str) -> Result<bool, LookupRepositoryError> {
            Ok(self.tables.contains_key(name))
        }

        async fn list_rows(
            &self,
            table_name: &str,
            limit: i64,
            offset: i64,
        ) -> Result<(Vec<HashMap<String, serde_json::Value>>, i64), LookupRepositoryError> {
            let rows = self.rows.get(table_name).cloned().unwrap_or_default();
            let total = rows.len() as i64;
            let sliced: Vec<_> = rows
                .into_iter()
                .skip(offset.max(0) as usize)
                .take(limit.max(0) as usize)
                .collect();
            Ok((sliced, total))
        }

        // --- methods the resolver never touches ---
        async fn register_table(
            &self,
            _: &NewLookupTable,
            _: &str,
            _: Option<Uuid>,
        ) -> Result<LookupTable, LookupRepositoryError> {
            unimplemented!()
        }
        async fn update_table_stats(
            &self,
            _: &str,
            _: i64,
            _: i64,
        ) -> Result<(), LookupRepositoryError> {
            unimplemented!()
        }
        async fn unregister_table(&self, _: &str) -> Result<LookupTable, LookupRepositoryError> {
            unimplemented!()
        }
        async fn update_table_columns(
            &self,
            _: &str,
            _: &[LookupColumn],
            _: Option<&str>,
        ) -> Result<(), LookupRepositoryError> {
            unimplemented!()
        }
        async fn find_rules_referencing(
            &self,
            _: &str,
        ) -> Result<Vec<RuleReferenceRow>, LookupRepositoryError> {
            unimplemented!()
        }
        async fn create_dynamic_table(
            &self,
            _: &str,
            _: &[LookupColumn],
            _: Option<&str>,
        ) -> Result<(), LookupRepositoryError> {
            unimplemented!()
        }
        async fn drop_dynamic_table(&self, _: &str) -> Result<(), LookupRepositoryError> {
            unimplemented!()
        }
        async fn truncate_dynamic_table(&self, _: &str) -> Result<(), LookupRepositoryError> {
            unimplemented!()
        }
        async fn swap_staged_table(
            &self,
            _: &str,
            _: &str,
            _: &str,
            _: &[LookupColumn],
            _: Option<&str>,
            _: i64,
        ) -> Result<(), LookupRepositoryError> {
            unimplemented!()
        }
        async fn insert_records(
            &self,
            _: &str,
            _: &[LookupColumn],
            _: &[HashMap<String, serde_json::Value>],
        ) -> Result<usize, LookupRepositoryError> {
            unimplemented!()
        }
        async fn get_table_row_count(&self, _: &str) -> Result<i64, LookupRepositoryError> {
            unimplemented!()
        }
        async fn get_table_size(&self, _: &str) -> Result<i64, LookupRepositoryError> {
            unimplemented!()
        }
        async fn lookup(
            &self,
            _: &str,
            _: &str,
            _: &serde_json::Value,
            _: Option<&[String]>,
            _: bool,
        ) -> Result<Option<HashMap<String, serde_json::Value>>, LookupRepositoryError> {
            unimplemented!()
        }
        async fn lookup_batch(
            &self,
            _: &str,
            _: &str,
            _: &[serde_json::Value],
            _: Option<&[String]>,
            _: bool,
        ) -> Result<HashMap<String, HashMap<String, serde_json::Value>>, LookupRepositoryError>
        {
            unimplemented!()
        }
        async fn sample_rows(
            &self,
            _: &str,
            _: i64,
        ) -> Result<Vec<HashMap<String, serde_json::Value>>, LookupRepositoryError> {
            unimplemented!()
        }
        async fn insert_row(
            &self,
            _: &str,
            _: &[LookupColumn],
            _: &HashMap<String, serde_json::Value>,
        ) -> Result<i64, LookupRepositoryError> {
            unimplemented!()
        }
        async fn update_row(
            &self,
            _: &str,
            _: i64,
            _: &[LookupColumn],
            _: &HashMap<String, serde_json::Value>,
        ) -> Result<(), LookupRepositoryError> {
            unimplemented!()
        }
        async fn delete_row(&self, _: &str, _: i64) -> Result<(), LookupRepositoryError> {
            unimplemented!()
        }
        async fn delete_rows(&self, _: &str, _: &[i64]) -> Result<u64, LookupRepositoryError> {
            unimplemented!()
        }
    }

    fn service_with(table: LookupTable, rows: Vec<HashMap<String, serde_json::Value>>) -> LookupService {
        let mut tables = HashMap::new();
        let physical = table.table_name.clone();
        let name = table.name.clone();
        tables.insert(name, table);
        let mut row_map = HashMap::new();
        row_map.insert(physical, rows);
        LookupService::new(MockStore {
            tables,
            rows: row_map,
        })
    }

    fn row(col: &str, val: &str) -> HashMap<String, serde_json::Value> {
        let mut m = HashMap::new();
        m.insert(col.to_string(), serde_json::Value::String(val.to_string()));
        m
    }

    #[tokio::test]
    async fn resolves_primary_key_column_by_default() {
        let table = make_table(
            "threat_iocs",
            vec![LookupColumn::text("indicator", false)],
            Some("indicator"),
        );
        let rows = vec![
            row("indicator", "1.2.3.4"),
            row("indicator", "evil.com"),
            row("indicator", "1.2.3.4"), // dup
        ];
        let svc = service_with(table, rows);
        let lookup = IocLookup {
            table: "threat_iocs".to_string(),
            column: None,
        };
        let vals = resolve_ioc_lookup(&lookup, Some(&svc)).await.unwrap();
        assert_eq!(vals, vec!["1.2.3.4".to_string(), "evil.com".to_string()]);
    }

    #[tokio::test]
    async fn resolves_explicit_column() {
        let table = make_table(
            "threat_iocs",
            vec![
                LookupColumn::text("id", false),
                LookupColumn::text("indicator", false),
            ],
            Some("id"),
        );
        let mut r1 = row("id", "1");
        r1.insert("indicator".into(), serde_json::Value::String("bad.test".into()));
        let svc = service_with(table, vec![r1]);
        let lookup = IocLookup {
            table: "threat_iocs".to_string(),
            column: Some("indicator".to_string()),
        };
        let vals = resolve_ioc_lookup(&lookup, Some(&svc)).await.unwrap();
        assert_eq!(vals, vec!["bad.test".to_string()]);
    }

    #[tokio::test]
    async fn unknown_table_errors_with_available() {
        let table = make_table("known", vec![LookupColumn::text("v", false)], Some("v"));
        let svc = service_with(table, vec![]);
        let lookup = IocLookup {
            table: "missing".to_string(),
            column: None,
        };
        let err = resolve_ioc_lookup(&lookup, Some(&svc)).await.unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("missing"), "msg: {msg}");
        assert!(msg.contains("known"), "msg: {msg}");
    }

    #[tokio::test]
    async fn unknown_column_errors() {
        let table = make_table(
            "t",
            vec![LookupColumn::text("indicator", false)],
            Some("indicator"),
        );
        let svc = service_with(table, vec![]);
        let lookup = IocLookup {
            table: "t".to_string(),
            column: Some("nope".to_string()),
        };
        let err = resolve_ioc_lookup(&lookup, Some(&svc)).await.unwrap_err();
        assert!(format!("{err}").contains("nope"));
    }

    #[tokio::test]
    async fn over_cap_errors() {
        let table = make_table(
            "big",
            vec![LookupColumn::text("indicator", false)],
            Some("indicator"),
        );
        let rows: Vec<_> = (0..(LOOKUP_IOC_MAX + 5))
            .map(|i| row("indicator", &format!("ind-{i}")))
            .collect();
        let svc = service_with(table, rows);
        let lookup = IocLookup {
            table: "big".to_string(),
            column: None,
        };
        let err = resolve_ioc_lookup(&lookup, Some(&svc)).await.unwrap_err();
        assert!(format!("{err}").contains("too many"));
    }

    #[tokio::test]
    async fn empty_table_resolves_to_empty() {
        let table = make_table(
            "empty",
            vec![LookupColumn::text("indicator", false)],
            Some("indicator"),
        );
        let svc = service_with(table, vec![]);
        let lookup = IocLookup {
            table: "empty".to_string(),
            column: None,
        };
        let vals = resolve_ioc_lookup(&lookup, Some(&svc)).await.unwrap();
        assert!(vals.is_empty());
    }

    #[tokio::test]
    async fn resolve_sources_substitutes_values_in_query() {
        let table = make_table(
            "threat_iocs",
            vec![LookupColumn::text("indicator", false)],
            Some("indicator"),
        );
        let svc = service_with(table, vec![row("indicator", "1.2.3.4")]);
        let mut query = crate::query::parse_query(r#"ioc in lookup("threat_iocs")"#).unwrap();
        let mut warnings = Vec::new();
        resolve_ioc_lookup_sources(&mut query, Some(&svc), &mut warnings)
            .await
            .unwrap();
        match query {
            Query::Search(SearchExpr::IocMatch { values, lookup, .. }) => {
                assert_eq!(values, vec![Value::String("1.2.3.4".to_string())]);
                assert!(lookup.is_none());
            }
            other => panic!("unexpected: {other:?}"),
        }
        assert!(warnings.is_empty());
    }

    #[tokio::test]
    async fn resolve_sources_empty_warns_and_clears() {
        let table = make_table(
            "empty",
            vec![LookupColumn::text("indicator", false)],
            Some("indicator"),
        );
        let svc = service_with(table, vec![]);
        let mut query = crate::query::parse_query(r#"ioc in lookup("empty")"#).unwrap();
        let mut warnings = Vec::new();
        resolve_ioc_lookup_sources(&mut query, Some(&svc), &mut warnings)
            .await
            .unwrap();
        match query {
            Query::Search(SearchExpr::IocMatch { values, lookup, .. }) => {
                assert!(values.is_empty());
                assert!(lookup.is_none());
            }
            other => panic!("unexpected: {other:?}"),
        }
        assert_eq!(warnings.len(), 1);
    }
}
