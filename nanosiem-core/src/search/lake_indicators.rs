// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4664: the derived IOC indicator column of lean-lake data files.
//!
//! The lake worker's part writer appends one `List<Utf8>` column per
//! indicator kind to every data file it writes ([`Kind::column`]), holding
//! the row's ASCII-lowercased, deduplicated indicator values, with a Parquet
//! bloom per row group. The columns are derived and read-only: they are
//! recomputed from the stored row on every write (L0 flush, merge, erasure
//! rewrite), never replace a source field, and are not part of the tenant
//! read schema, so no query, field list, row or export ever shows them. A
//! file that carries them says so in its footer ([`FILE_MARKER_KEY`]); the
//! data files are signed, so the marker is trusted. A file without it (every
//! file written before this) answers nothing from them: its row groups are
//! kept, exactly as before.
//!
//! # Which kinds
//!
//! Only [`Kind::Domain`]. A column earns its bytes only when it prunes a
//! lookup no existing evidence answers. The review of NAN-4664 measured the
//! first cut (hashes, IPs, domains, users and hosts: +12.6 B/row, +15.6%)
//! on the bakeoff hour: only the domain hunts (H3, `domain=`) read fewer
//! rows (480k -> 216k, 10 -> 3 row groups). Hash leaves and bare hash / IPv4
//! terms are already pruned per row group by the token index (whole hash and
//! address tokens), the scalar IP / host / user leaves by their own blooms,
//! and the repeated `resources.*` leaves are hunted by no bakeoff query.
//!
//! # What the column holds
//!
//! Every string leaf whose dotted event path [`classify`] maps to the kind,
//! at any depth (list wrappers dropped), ASCII-lowercased. A compiled
//! equality on such a path is `lower(col) = 'v'` (ClickHouse `lower` folds
//! ASCII only), a raw `col = 'v'` on an ingest-lowercased leaf, or an `ioc=`
//! `IN` list; for an ASCII literal each holds only when the ASCII-lowercased
//! stored value equals the ASCII-lowercased literal, so an absent value is
//! proof that the row cannot match. A non-ASCII literal is lowered with
//! Unicode rules by the SQL generator (`'É'` becomes `'é'`, which matches a
//! stored `'é'`), so a reader never decides one from the column
//! ([`probe`]): it keeps the group.
//!
//! Bare search terms never route to the column: they compile to a match over
//! `message` / `raw_data`, which the column does not index.

use crate::query::{Comparator, Query, RhsSyntax, SearchExpr};

/// Footer key-value metadata key on a data file that carries the columns.
pub const FILE_MARKER_KEY: &str = "nano.ioc_indicators";
/// The derivation version the marker names. Readers trust only this value.
/// `2`: the domain-only derivation (`1` was the five-column review draft,
/// never rolled; a reader ignores it).
pub const VERSION: &str = "2";
/// Every indicator column name starts with this. The namespace is reserved:
/// ingest drops a top-level source field of this prefix.
pub const COLUMN_PREFIX: &str = "nano_ioc_";

/// One indicator column.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    Domain,
}

impl Kind {
    pub const ALL: [Kind; 1] = [Kind::Domain];

    /// The file column holding this kind.
    pub fn column(self) -> &'static str {
        match self {
            Kind::Domain => "nano_ioc_domains",
        }
    }

    pub fn of_column(column: &str) -> Option<Kind> {
        Kind::ALL.into_iter().find(|kind| kind.column() == column)
    }
}

/// True for a name the indicator derivation owns (source data never may).
pub fn is_indicator_column(name: &str) -> bool {
    name.starts_with(COLUMN_PREFIX)
}

/// The indicator kind of a dotted event path, or `None`.
///
/// The writer indexes every string leaf this maps, and a reader consults a
/// column only for a path this maps, so both sides agree by construction.
pub fn classify(path: &str) -> Option<Kind> {
    let mut segments = path.rsplit('.');
    let last = segments.next()?;
    let parent = segments.next().unwrap_or("");
    match (parent, last) {
        ("query" | "url", "hostname") => Some(Kind::Domain),
        (parent, "domain") if parent.ends_with("endpoint") => Some(Kind::Domain),
        _ => None,
    }
}

/// The stored spelling of a value: ASCII lowercase (ClickHouse `lower`).
pub fn normalize(value: &str) -> String {
    value.to_ascii_lowercase()
}

/// The column spelling a reader probes for an entity literal, or `None`
/// when the column cannot decide it (a non-ASCII literal, see the module
/// docs): the group is then kept.
pub fn probe(value: &str) -> Option<String> {
    value.is_ascii().then(|| normalize(value))
}

/// NAN-4664: the typed IOC fields. `hash=v`, `ip=v` and `domain=v` match
/// `v` in any of these canonical OCSF leaves (an OR of the field
/// equalities, so each leg is an indicator-covered entity hint).
pub const TYPED_FIELDS: &[(&str, &[&str])] = &[
    ("hash", &["file.hashes.value", "process.file.hashes.value", "actor.process.file.hashes.value"]),
    ("ip", &["src_endpoint.ip", "dst_endpoint.ip", "device.ip"]),
    (
        "domain",
        &["dst_endpoint.domain", "src_endpoint.domain", "query.hostname", "http_request.url.hostname", "url.hostname"],
    ),
];

/// Rewrite every `hash=` / `ip=` / `domain=` (and `!=`) filter of the
/// search and `where` stages into its field OR. `is_known` is the profile's
/// field check: a name the profile already resolves is never rewritten.
pub fn expand_typed_fields(query: &mut Query, is_known: &dyn Fn(&str) -> bool) {
    match query {
        Query::Search(expression) => expand_expression(expression, is_known),
        Query::Piped { source, command } => {
            expand_typed_fields(source, is_known);
            if let crate::query::Command::Where { condition } = command {
                expand_expression(condition, is_known);
            }
        }
    }
}

fn expand_expression(expression: &mut SearchExpr, is_known: &dyn Fn(&str) -> bool) {
    match expression {
        SearchExpr::And(left, right) | SearchExpr::Or(left, right) => {
            expand_expression(left, is_known);
            expand_expression(right, is_known);
        }
        SearchExpr::Not(inner) | SearchExpr::Group(inner) => expand_expression(inner, is_known),
        SearchExpr::FieldFilter { field, op: op @ (Comparator::Eq | Comparator::Ne), value, rhs } => {
            let Some((_, paths)) = TYPED_FIELDS.iter().find(|(name, _)| field.eq_ignore_ascii_case(name)) else { return };
            if is_known(field) {
                return;
            }
            let negated = *op == Comparator::Ne;
            // The value is always a literal here: no typed name is a column.
            let rhs = match rhs {
                RhsSyntax::Bareword => RhsSyntax::Literal,
                other => *other,
            };
            let legs = paths.iter().map(|path| SearchExpr::FieldFilter {
                field: (*path).to_string(),
                op: Comparator::Eq,
                value: value.clone(),
                rhs,
            });
            let union = legs.reduce(|left, right| SearchExpr::Or(Box::new(left), Box::new(right))).expect("typed field has paths");
            let union = SearchExpr::Group(Box::new(union));
            *expression = if negated { SearchExpr::Not(Box::new(union)) } else { union };
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_maps_only_the_ocsf_domain_leaves() {
        for (path, kind) in [
            ("dst_endpoint.domain", Some(Kind::Domain)),
            ("src_endpoint.domain", Some(Kind::Domain)),
            ("query.hostname", Some(Kind::Domain)),
            ("http_request.url.hostname", Some(Kind::Domain)),
            ("url.hostname", Some(Kind::Domain)),
            ("evidences.query.hostname", Some(Kind::Domain)),
            ("device.hostname", None),
            ("dst_endpoint.hostname", None),
            ("process.file.hashes.value", None),
            ("resources.ip", None),
            ("user.name", None),
            ("domain", None),
            ("metadata.uid", None),
        ] {
            assert_eq!(classify(path), kind, "{path}");
        }
    }

    /// A non-ASCII literal is lowered with Unicode rules by the SQL
    /// generator; the ASCII-folded column cannot decide it.
    #[test]
    fn probe_refuses_non_ascii_literals() {
        assert_eq!(probe("Update-CDN.Example").as_deref(), Some("update-cdn.example"));
        assert_eq!(probe("B\u{dc}CHER.de"), None);
        assert_eq!(probe("b\u{fc}cher.de"), None);
    }

    #[test]
    fn typed_fields_expand_to_field_unions() {
        let mut query = crate::query::parse_query("hash=ABC | where ip!=1.2.3.4").unwrap();
        expand_typed_fields(&mut query, &|_| false);
        let text = format!("{query:?}");
        for path in ["file.hashes.value", "process.file.hashes.value", "actor.process.file.hashes.value", "src_endpoint.ip", "device.ip"] {
            assert!(text.contains(&format!("\"{path}\"")), "{path}: {text}");
        }
        assert!(text.contains("Not("), "{text}");
        let mut known = crate::query::parse_query("domain=x.example").unwrap();
        let before = known.clone();
        expand_typed_fields(&mut known, &|_| true);
        assert_eq!(known, before);
    }
}
