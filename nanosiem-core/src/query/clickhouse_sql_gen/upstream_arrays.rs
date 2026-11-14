//! NAN-5350: stage columns that hold a multi-valued (`Array(..)`) field under a
//! name the schema no longer resolves.
//!
//! `| table`, `| rename` and an explicit `table f AS g` project an array field
//! into a stage column. NAN-5306 made `table` keep every requested name, and
//! registered names like `module.file.signatures.state` (a JSON path across an
//! OCSF array, projected as `arrayMap(…) AS "…"`) and `category` (a UDM alias
//! of `http_request.url.categories`) as upstream-computed so later stages read
//! the projected column instead of re-resolving the dropped source. That also
//! hid their array type: a later `| where f="v"` compiled the scalar
//! `lower(toString(f)) = 'v'`, which compares `"['v']"` and silently returns
//! no rows. A renamed or copied array (`rename f as g`, `table f as g`,
//! `eval g = f`) had the same problem before NAN-5306.
//!
//! This scope records, per stage, which in-scope column names hold such an
//! array and the schema field they were read from (for element typing:
//! numeric, lowercased at ingest). `where`/`search` predicates, `IN` lists,
//! eval comparisons and `stats … by` read it so the projected column keeps the
//! membership semantics of the field it came from. Same scope rules as
//! `upstream_computed_fields`: typed against the scope before each command,
//! reset per generation, swapped per subsearch.
//!
//! `rename` and `eval` apply their mappings/assignments in order, as their SQL
//! does (`rename a AS b, b AS c`; `eval sig="x", copy=sig`). `join`/`append`
//! carry the arrays a subsearch ends with into the columns they take from it
//! (`generate_join_sql` / `generate_append_sql` decide which). In-place
//! scalar rewrites (`rex mode=sed`, `fillnull`, in-place `bin`, `spath
//! output=`) end a column's array typing.

use std::collections::{HashMap, HashSet};

use super::{command_keeps_base_columns, ClickHouseSqlGenerator};
use crate::query::ast::{Command, EvalExpression, RexMode};

/// A stage column that holds an array field (see the module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UpstreamArray {
    /// The schema field the column was read from. Predicates type the
    /// elements by it (numeric, lowercased at ingest).
    pub(crate) source: String,
    /// Whether `stats … by` splits the column per element, as it does for the
    /// source field read directly (a physical `Array(T)` column). A JSON array
    /// path groups by the whole value, as it does without the projection.
    pub(crate) split_by: bool,
}

pub(crate) type UpstreamArrays = HashMap<String, UpstreamArray>;

/// The names `cmd` rewrites IN PLACE with a scalar value. They are not in the
/// upstream-computed set (the name keeps resolving to the same column), so
/// they must be dropped from the array scope explicitly.
fn in_place_scalar_rewrites(cmd: &Command) -> Vec<String> {
    match cmd {
        // `replaceRegexpAll(f::String, …) AS f`.
        Command::Rex { field, mode: RexMode::Sed { .. }, .. } => {
            vec![field.clone().unwrap_or_else(|| "message".to_string())]
        }
        // `ifNull(toString(f), 'v') AS f`.
        Command::Fillnull { fields: Some(fields), .. } => fields.clone(),
        // `bin f span=…` floors `f` in place.
        Command::Bin { field: Some(field), alias: None, .. } => vec![field.clone()],
        // `JSONExtractString(…) AS output`.
        Command::Spath { output: Some(output), .. } => vec![output.clone()],
        _ => Vec::new(),
    }
}

impl ClickHouseSqlGenerator {
    /// The array a stage column `name` holds, when an upstream `table` or
    /// `rename` projected one under that name.
    pub(crate) fn upstream_array(&self, name: &str) -> Option<UpstreamArray> {
        self.upstream_arrays
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(name)
            .cloned()
    }

    /// The recorded array column a `| where` operand names: the name as
    /// written (the projected column), else its canonical form. Returns the
    /// in-scope column name with the array it holds.
    pub(super) fn upstream_array_operand<'a>(
        &self,
        raw: &'a str,
        canonical: &'a str,
    ) -> Option<(&'a str, UpstreamArray)> {
        self.upstream_array(raw)
            .map(|array| (raw, array))
            .or_else(|| self.upstream_array(canonical).map(|array| (canonical, array)))
    }

    fn current_upstream_arrays(&self) -> UpstreamArrays {
        self.upstream_arrays
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub(super) fn swap_upstream_arrays(&self, new: UpstreamArrays) -> UpstreamArrays {
        let mut guard = self
            .upstream_arrays
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        std::mem::replace(&mut *guard, new)
    }

    /// Record the arrays a just-generated subsearch ended with, for the
    /// `join`/`append` that embeds it.
    pub(super) fn set_subsearch_arrays(&self, arrays: UpstreamArrays) {
        *self
            .subsearch_arrays
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = arrays;
    }

    fn take_subsearch_arrays(&self) -> UpstreamArrays {
        std::mem::take(
            &mut *self
                .subsearch_arrays
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        )
    }

    fn set_pending_arrays(&self, arrays: Option<UpstreamArrays>) {
        *self
            .pending_subsearch_arrays
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = arrays;
    }

    fn take_pending_arrays(&self) -> Option<UpstreamArrays> {
        self.pending_subsearch_arrays
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
    }

    /// Reset the join/append hand-off slots (per generation).
    pub(super) fn reset_subsearch_array_slots(&self) {
        self.set_subsearch_arrays(UpstreamArrays::new());
        self.set_pending_arrays(None);
    }

    /// `join`: the columns it takes from the subsearch (`taken`; `None` when
    /// the subsearch output is not a modeled column list) carry the
    /// subsearch's array typing; every other column keeps the main side's.
    /// `sub_gen` is the generator that produced the subsearch (a clone for a
    /// cross-dataset join).
    pub(super) fn record_join_arrays(&self, sub_gen: &ClickHouseSqlGenerator, taken: Option<&[String]>) {
        let sub = sub_gen.take_subsearch_arrays();
        let mut next = self.current_upstream_arrays();
        for c in taken.unwrap_or_default() {
            match sub.get(c) {
                Some(array) => next.insert(c.clone(), array.clone()),
                None => next.remove(c),
            };
        }
        self.set_pending_arrays(Some(next));
    }

    /// `append` (UNION ALL): a column is an array when every arm that carries
    /// it holds an array; an arm that lacks it pads `NULL`. `columns` is the
    /// union column list with each arm's columns, or `None` for two wide arms
    /// (same columns positionally), where both arms must agree.
    pub(super) fn record_append_arrays(&self, columns: Option<(&[String], &[String], &[String])>) {
        let main = self.current_upstream_arrays();
        let sub = self.take_subsearch_arrays();
        let next = match columns {
            Some((union, main_cols, sub_cols)) => union
                .iter()
                .filter_map(|c| {
                    let m = main.get(c);
                    let s = sub.get(c);
                    let main_ok = m.is_some() || !main_cols.contains(c);
                    let sub_ok = s.is_some() || !sub_cols.contains(c);
                    (main_ok && sub_ok)
                        .then(|| m.or(s).cloned())
                        .flatten()
                        .map(|array| (c.clone(), array))
                })
                .collect(),
            None => main
                .into_iter()
                .filter(|(name, _)| sub.contains_key(name))
                .collect(),
        };
        self.set_pending_arrays(Some(next));
    }

    /// Whether `name` is an array field in a scope given by `arrays` (the
    /// recorded columns) and `shadowed` (names this command already rewrote
    /// with a non-array value): a recorded column, or a schema array field
    /// nothing upstream has recomputed.
    fn array_in(&self, arrays: &UpstreamArrays, shadowed: &HashSet<String>, name: &str) -> Option<UpstreamArray> {
        if let Some(found) = arrays.get(name) {
            return Some(found.clone());
        }
        if shadowed.contains(name)
            || name.contains('*')
            || name.contains('(')
            || self.is_upstream_computed_field(name)
        {
            return None;
        }
        let canonical = self.canonicalize_field(name);
        (self.profile.is_array_field(canonical) || super::is_array_column(canonical)).then(|| {
            UpstreamArray {
                source: canonical.to_string(),
                split_by: self.stats_by_field_is_array(name),
            }
        })
    }

    /// The array columns in scope after `cmd`, computed against the scope
    /// BEFORE it (`added` is what `cmd` recomputes). `table` rebuilds the set
    /// from its projection; `rename` and `eval` apply their mappings in order;
    /// `join`/`append` take what their generator recorded; row-passthrough
    /// stages keep every column they do not recompute or rewrite in place.
    /// Anything that replaces the row set (stats, timechart, top, …) clears
    /// it; its outputs are aggregates, not the projected arrays.
    pub(super) fn upstream_arrays_after(&self, cmd: &Command, added: &HashSet<String>) -> UpstreamArrays {
        let current = self.current_upstream_arrays();
        let no_shadow = HashSet::new();
        let mut next = match cmd {
            Command::Table { fields } => {
                // One SELECT list: every field reads the scope before `table`.
                // Wildcards expand to physical names; recorded columns they
                // match stay as they were.
                let mut next = if fields.iter().any(|f| f.name.contains('*')) {
                    current.clone()
                } else {
                    UpstreamArrays::new()
                };
                for f in fields.iter().filter(|f| !f.name.contains('*')) {
                    let out = f.alias.as_deref().unwrap_or(&f.name);
                    match self.array_in(&current, &no_shadow, &f.name) {
                        Some(array) => next.insert(out.to_string(), array),
                        None => next.remove(out),
                    };
                }
                next
            }
            // Sequential: a later mapping reads the column an earlier one wrote.
            Command::Rename { mappings } => {
                let mut next = current;
                let mut shadowed = HashSet::new();
                for m in mappings.iter().filter(|m| m.from != m.to) {
                    let array = self.array_in(&next, &shadowed, &m.from);
                    next.remove(&m.from);
                    shadowed.insert(m.from.clone());
                    match array {
                        Some(array) => {
                            shadowed.remove(&m.to);
                            next.insert(m.to.clone(), array);
                        }
                        None => {
                            next.remove(&m.to);
                            shadowed.insert(m.to.clone());
                        }
                    }
                }
                next
            }
            // Sequential: `eval g = f` copies the array column as `f` stands
            // after the assignments before it.
            Command::Eval { assignments } => {
                let mut next = current;
                let mut shadowed = HashSet::new();
                for a in assignments {
                    let array = match &a.expression {
                        EvalExpression::Field(source) => self.array_in(&next, &shadowed, source),
                        _ => None,
                    };
                    match array {
                        Some(array) => {
                            shadowed.remove(&a.field);
                            next.insert(a.field.clone(), array);
                        }
                        None => {
                            next.remove(&a.field);
                            shadowed.insert(a.field.clone());
                        }
                    }
                }
                next
            }
            Command::Join { .. } | Command::Append { .. } => self.take_pending_arrays().unwrap_or_else(|| {
                let mut next = current;
                next.retain(|name, _| !added.contains(name));
                next
            }),
            Command::Fields { fields, keep } => {
                let mut next = current;
                next.retain(|name, _| !added.contains(name));
                if !*keep {
                    for f in fields {
                        next.remove(f);
                    }
                }
                next
            }
            _ if command_keeps_base_columns(cmd) => {
                let mut next = current;
                next.retain(|name, _| !added.contains(name));
                next
            }
            _ => UpstreamArrays::new(),
        };
        for name in in_place_scalar_rewrites(cmd) {
            next.remove(&name);
        }
        next
    }
}
