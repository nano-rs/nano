// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5895: which stage columns hold an untyped JSON path's TEXT.
//!
//! An untyped JSON path of the event (an OCSF `unmapped.*` key, or any other
//! JSON attribute the schema gives no type) reads as its text in a pipeline
//! stage: `multiIf(isNotNull(unmapped."x"), toString(unmapped."x"), …)`, a
//! String. A numeric literal compared with that bare (`* | where unmapped.x >
//! 5`, `| eval eq = if(unmapped.x == 5, …)`) was a ClickHouse NO_COMMON_TYPE
//! error (String vs UInt8) that failed the whole search. The search term
//! (`unmapped.x>5`) compares the path's numeric value, and so must every stage.
//!
//! Two cases, both judged per STAGE (never from the whole-query
//! `computed_fields`, which also holds names a LATER stage creates):
//!
//! * [`reads_event_json_path`]: the stage still carries the event and nothing
//!   upstream recomputed the name, so the comparison is exactly the search
//!   term's predicate (`accurateCastOrNull(unmapped."x", 'Float64') > 5`).
//! * [`is_upstream_json_text`]: a stage column that passes the path's text
//!   through under its own or a new name: `table` (with or without `AS`,
//!   chained), `rename`, an `eval` copy (`eval y = unmapped.x`), and the
//!   by-fields of `stats` / `chart` / `timechart`. The comparison casts that
//!   column. A name a stage computed (`stats count as n`, `eval n = 10`) is
//!   never in the set and keeps the bare compare.
//!
//! The set follows the same scope rules as `upstream_arrays` (NAN-5350):
//! typed against the scope before each command, rebuilt by projections,
//! applied in order by `rename` / `eval`, kept by row-passthrough stages minus
//! what they recompute, reset per generation and swapped per subsearch. It is
//! separate from NAN-4276's `upstream_string_fields` on purpose: on OCSF every
//! bare name resolves to an `unmapped` path, so a String eval output (`eval s
//! = lower(status)`) must keep its text compare, not become numeric.
//!
//! [`reads_event_json_path`]: ClickHouseSqlGenerator::reads_event_json_path
//! [`is_upstream_json_text`]: ClickHouseSqlGenerator::is_upstream_json_text

use std::collections::HashSet;

use super::{helpers, ClickHouseSqlGenerator};
use crate::query::ast::*;
use crate::schema::FieldResolution;

impl ClickHouseSqlGenerator {
    /// Whether the schema reads `field` from an untyped JSON path of the
    /// event: a JSON path with no declared type, not numeric, not an array.
    fn is_untyped_json_path(&self, field: &str) -> bool {
        !field.contains('(')
            && !field.contains('*')
            && self.agg_reference_alias(field).is_none()
            && !self.profile.is_array_field(field)
            && self.profile.field_type(field).is_none()
            && !self.is_numeric_field(field)
            && matches!(self.profile.resolve(field), FieldResolution::JsonPath { .. })
    }

    /// Whether `field`, in the stage being generated, still reads the event's
    /// untyped JSON path: the stage carries the event (nothing projected it
    /// away) and no stage upstream recomputed the name.
    pub(crate) fn reads_event_json_path(&self, field: &str) -> bool {
        !self.is_upstream_projected()
            && !self.is_upstream_computed_field(field)
            && self.is_untyped_json_path(field)
    }

    /// Whether `field` is a stage column holding an untyped JSON path's text
    /// (projected, renamed, copied or grouped on; see the module docs).
    pub(crate) fn is_upstream_json_text(&self, field: &str) -> bool {
        match self.upstream_json_text.read() {
            Ok(guard) => guard.contains(field),
            Err(poisoned) => poisoned.get_ref().contains(field),
        }
    }

    pub(super) fn swap_upstream_json_text(&self, new: HashSet<String>) -> HashSet<String> {
        match self.upstream_json_text.write() {
            Ok(mut guard) => std::mem::replace(&mut *guard, new),
            Err(poisoned) => std::mem::replace(&mut *poisoned.into_inner(), new),
        }
    }

    fn current_upstream_json_text(&self) -> HashSet<String> {
        match self.upstream_json_text.read() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => (**poisoned.get_ref()).clone(),
        }
    }

    /// Whether `name` holds JSON text in a scope given by `set` (the recorded
    /// columns) and `shadowed` (names this command already rewrote): a
    /// recorded column, or the event's own untyped path.
    fn json_text_in(&self, set: &HashSet<String>, shadowed: &HashSet<String>, name: &str) -> bool {
        set.contains(name) || (!shadowed.contains(name) && self.reads_event_json_path(name))
    }

    /// The JSON-text columns in scope after `cmd`, computed against the scope
    /// BEFORE it (`added` is what `cmd` recomputes).
    ///
    /// TABLE-DRIVEN: [`json_text_rule`] gives every nPL command an explicit
    /// [`JsonTextRule`]. Its `match` has no wildcard arm, so a new `Command`
    /// variant does not compile until it says how it transforms the set.
    pub(super) fn upstream_json_text_after(&self, cmd: &Command, added: &HashSet<String>) -> HashSet<String> {
        let current = self.current_upstream_json_text();
        let no_shadow = HashSet::new();
        let passthrough = |keep_in_place: &[String]| {
            let mut next = current.clone();
            next.retain(|name| !added.contains(name) || keep_in_place.contains(name));
            next
        };
        let grouped = |fields: &mut dyn Iterator<Item = &String>| -> HashSet<String> {
            fields
                .filter(|f| self.json_text_in(&current, &no_shadow, f))
                .map(|f| helpers::by_field_output_name(f, self).to_string())
                .collect()
        };
        match json_text_rule(cmd) {
            JsonTextRule::Passthrough => passthrough(&[]),
            JsonTextRule::RewriteTextInPlace(fields) => match fields {
                Some(fields) => passthrough(&fields),
                // `fillnull` with no field list rewrites every column as text.
                None => current.clone(),
            },
            JsonTextRule::RewriteNonText(fields) => {
                let mut next = passthrough(&[]);
                for f in fields {
                    next.remove(&f);
                }
                next
            }
            JsonTextRule::Cleared => HashSet::new(),
            JsonTextRule::GroupBy(fields) => grouped(&mut fields.iter()),
            JsonTextRule::Subsearch => self.take_pending_json_text().unwrap_or_else(|| passthrough(&[])),
            JsonTextRule::Table(fields) => {
                // One SELECT list: every field reads the scope before `table`;
                // a wildcard keeps the recorded columns it matches.
                let mut next = HashSet::new();
                for f in fields {
                    if f.name.contains('*') {
                        next.extend(current.iter().filter(|c| glob_matches(&f.name, c)).cloned());
                        next.extend(
                            self.expand_wildcard(&f.name)
                                .into_iter()
                                .filter(|c| self.json_text_in(&current, &no_shadow, c)),
                        );
                        continue;
                    }
                    let out = f.alias.as_deref().unwrap_or(&f.name);
                    if self.json_text_in(&current, &no_shadow, &f.name) {
                        next.insert(out.to_string());
                    } else {
                        next.remove(out);
                    }
                }
                next
            }
            JsonTextRule::FieldsKeep(fields) => {
                // `fields a, b*` projects like `table` (no aliases).
                let mut next = HashSet::new();
                for f in fields {
                    if f.contains('*') {
                        next.extend(current.iter().filter(|c| glob_matches(f, c)).cloned());
                        next.extend(
                            self.expand_wildcard(f)
                                .into_iter()
                                .filter(|c| self.json_text_in(&current, &no_shadow, c)),
                        );
                    } else if self.json_text_in(&current, &no_shadow, f) {
                        next.insert(f.clone());
                    }
                }
                next
            }
            JsonTextRule::FieldsRemove(fields) => {
                let mut next = passthrough(&[]);
                next.retain(|c| !fields.iter().any(|f| glob_matches(f, c)));
                next
            }
            // Sequential: a later mapping reads the column an earlier one wrote.
            JsonTextRule::Rename(mappings) => {
                let mut next = current.clone();
                let mut shadowed = HashSet::new();
                for m in mappings.iter().filter(|m| m.from != m.to) {
                    let text = self.json_text_in(&next, &shadowed, &m.from);
                    next.remove(&m.from);
                    shadowed.insert(m.from.clone());
                    shadowed.insert(m.to.clone());
                    if text {
                        next.insert(m.to.clone());
                    } else {
                        next.remove(&m.to);
                    }
                }
                next
            }
            // Sequential: `eval y = f` copies `f` as it stands after the
            // assignments before it; any other expression is a new value.
            JsonTextRule::Eval(assignments) => {
                let mut next = current.clone();
                let mut shadowed = HashSet::new();
                for a in assignments {
                    let text = match &a.expression {
                        EvalExpression::Field(source) => self.json_text_in(&next, &shadowed, source),
                        _ => false,
                    };
                    shadowed.insert(a.field.clone());
                    if text {
                        next.insert(a.field.clone());
                    } else {
                        next.remove(&a.field);
                    }
                }
                next
            }
        }
    }

    pub(super) fn set_subsearch_json_text(&self, set: HashSet<String>) {
        *self.subsearch_json_text.write().unwrap_or_else(|p| p.into_inner()) = set;
    }

    fn take_subsearch_json_text(&self) -> HashSet<String> {
        std::mem::take(&mut *self.subsearch_json_text.write().unwrap_or_else(|p| p.into_inner()))
    }

    fn set_pending_json_text(&self, set: Option<HashSet<String>>) {
        *self.pending_subsearch_json_text.write().unwrap_or_else(|p| p.into_inner()) = set;
    }

    fn take_pending_json_text(&self) -> Option<HashSet<String>> {
        self.pending_subsearch_json_text.write().unwrap_or_else(|p| p.into_inner()).take()
    }

    /// Reset the join/append hand-off slots (per generation).
    pub(super) fn reset_subsearch_json_text_slots(&self) {
        self.set_subsearch_json_text(HashSet::new());
        self.set_pending_json_text(None);
    }

    /// `join`: the columns it takes from the subsearch (`taken`; `None` when
    /// the subsearch output is not a modeled column list) carry the
    /// subsearch's JSON-text typing; every other column keeps the main side's,
    /// whatever the subsearch did internally. `sub_gen` produced the subsearch.
    ///
    /// `main_columns`: the main side's columns when a projection fixed them
    /// (`table`, `fields`, `stats`, …), `Some(&[])` when the shape is not
    /// modeled (fail safe: a subsearch JSON-text column is taken as surfacing
    /// bare, so a numeric compare on it is cast rather than a NO_COMMON_TYPE
    /// error), `None` when main is still the wide event row (then its physical
    /// schema columns shadow same-named subsearch columns).
    pub(super) fn record_join_json_text(
        &self,
        sub_gen: &ClickHouseSqlGenerator,
        taken: Option<&[String]>,
        main_columns: Option<&[String]>,
    ) {
        let sub = sub_gen.take_subsearch_json_text();
        let mut next = self.current_upstream_json_text();
        match taken {
            Some(taken) => {
                for c in taken {
                    if sub.contains(c) {
                        next.insert(c.clone());
                    } else {
                        next.remove(c);
                    }
                }
            }
            // A wide subsearch (`SELECT * … JOIN (…) AS sub`): ClickHouse
            // surfaces a subsearch column bare unless the main side already
            // has one of that name (then it is `sub.<name>` and the main
            // column wins). So a subsearch JSON-text column the main side
            // does not have arrives as JSON text.
            None => {
                for c in sub {
                    let main_has = next.contains(&c)
                        || match main_columns {
                            Some(cols) => cols.iter().any(|m| m == &c),
                            None => {
                                self.is_upstream_computed_field(&c)
                                    || !matches!(self.profile.resolve(&c), FieldResolution::JsonPath { .. })
                            }
                        };
                    if !main_has {
                        next.insert(c);
                    }
                }
            }
        }
        self.set_pending_json_text(Some(next));
    }

    /// `append` (UNION ALL): a column is JSON text when every arm that carries
    /// it holds JSON text (an arm that lacks it pads `NULL`). `columns` is the
    /// union column list with each arm's columns, or `None` for two wide arms
    /// (same columns positionally), where both arms must agree.
    pub(super) fn record_append_json_text(&self, columns: Option<(&[String], &[String], &[String])>) {
        let main = self.current_upstream_json_text();
        let sub = self.take_subsearch_json_text();
        let next = match columns {
            Some((union, main_cols, sub_cols)) => union
                .iter()
                .filter(|c| {
                    let in_main = main.contains(*c);
                    let in_sub = sub.contains(*c);
                    (in_main || in_sub)
                        && (in_main || !main_cols.contains(c))
                        && (in_sub || !sub_cols.contains(c))
                })
                .cloned()
                .collect(),
            None => main.intersection(&sub).cloned().collect(),
        };
        self.set_pending_json_text(Some(next));
    }
}

/// `*` globs as `table` / `fields` read them (every other character literal).
fn glob_matches(pattern: &str, name: &str) -> bool {
    if !pattern.contains('*') {
        return pattern == name;
    }
    regex::Regex::new(&format!("^{}$", regex::escape(pattern).replace("\\*", ".*")))
        .map(|re| re.is_match(name))
        .unwrap_or(false)
}

/// How one command transforms the JSON-text set (see [`json_text_rule`]).
#[derive(Debug)]
pub(crate) enum JsonTextRule<'a> {
    /// Rows pass through with every column: keep the set minus the names the
    /// command recomputes.
    Passthrough,
    /// Rewrites these columns in place as TEXT (`fillnull`, `rex mode=sed`):
    /// they stay JSON text. `None` = every column.
    RewriteTextInPlace(Option<Vec<String>>),
    /// Rewrites these columns in place with a non-text value (`bin` floors,
    /// `spath output=` is a new extraction): they leave the set.
    RewriteNonText(Vec<String>),
    /// Replaces the row set with outputs that are none of the input columns.
    Cleared,
    /// Replaces the row set; these grouping columns pass a value through.
    GroupBy(Vec<String>),
    /// `join` / `append`: the subsearch hand-off decides.
    Subsearch,
    Table(&'a [TableField]),
    FieldsKeep(&'a [String]),
    FieldsRemove(&'a [String]),
    Rename(&'a [FieldRename]),
    Eval(&'a [EvalAssignment]),
}

/// The JSON-text rule of every nPL command. No wildcard arm on purpose: a new
/// `Command` variant must choose a rule here before the crate compiles.
pub(crate) fn json_text_rule(cmd: &Command) -> JsonTextRule<'_> {
    use JsonTextRule as R;
    let some = |v: &Option<Vec<String>>| v.clone().unwrap_or_default();
    match cmd {
        Command::Table { fields } => R::Table(fields),
        Command::Fields { fields, keep: true } => R::FieldsKeep(fields),
        Command::Fields { fields, keep: false } => R::FieldsRemove(fields),
        Command::Rename { mappings } => R::Rename(mappings),
        Command::Eval { assignments } => R::Eval(assignments),
        Command::Stats { group_by, .. } | Command::Chart { group_by, .. } => R::GroupBy(some(group_by)),
        Command::Timechart { split_by, .. } => R::GroupBy(split_by.clone()),
        // `top f by g` / `rare f by g` group on `f` and `g` (count/percent are new).
        Command::Top { field, by_fields, .. } | Command::Rare { field, by_fields, .. } => {
            R::GroupBy(std::iter::once(field.clone()).chain(by_fields.iter().cloned()).collect())
        }
        // `transaction f` groups on `f` (duration/eventcount are new).
        Command::Transaction { fields, .. } => R::GroupBy(fields.clone()),
        Command::Fillnull { fields, .. } => R::RewriteTextInPlace(fields.clone()),
        Command::Rex { field, mode: RexMode::Sed { .. }, .. } => {
            R::RewriteTextInPlace(Some(vec![field.clone().unwrap_or_else(|| "message".to_string())]))
        }
        // Named captures are new String columns (in `added`).
        Command::Rex { mode: RexMode::Extract, .. } => R::Passthrough,
        Command::Bin { field: Some(field), alias: None, .. } => R::RewriteNonText(vec![field.clone()]),
        Command::Bin { .. } => R::Passthrough,
        // Without `path=` spath is a no-op (`SELECT *`).
        Command::Spath { output: Some(output), path: Some(_), .. } => R::RewriteNonText(vec![output.clone()]),
        Command::Spath { .. } => R::Passthrough,
        Command::Join { .. } | Command::Append { .. } => R::Subsearch,
        // Row filters / reorders and stages that append columns to unchanged rows.
        Command::Where { .. }
        | Command::Sort { .. }
        | Command::Head { .. }
        | Command::Tail { .. }
        | Command::Sample { .. }
        | Command::Reverse
        | Command::Dedup { .. }
        | Command::Lookup { .. }
        | Command::Mvexpand { .. }
        | Command::EventStats { .. }
        | Command::StreamStats { .. }
        | Command::Risk { .. }
        | Command::Prevalence { .. }
        | Command::ResolveIdentity { .. }
        | Command::Anomaly { .. } => R::Passthrough,
        // Their own outputs replace the rows (or the stage is not a row stage).
        Command::Format { .. }
        | Command::Return { .. }
        | Command::Sequence { .. }
        | Command::Funnel { .. }
        | Command::InputLookup { .. }
        | Command::Tree { .. }
        | Command::Asset { .. }
        | Command::Cloud { .. }
        | Command::Lateral { .. }
        | Command::Ai { .. }
        | Command::Output { .. }
        | Command::Services
        | Command::Service { .. }
        | Command::Trace { .. }
        | Command::Metric { .. }
        | Command::Retro { .. }
        | Command::Baseline { .. } => R::Cleared,
    }
}
