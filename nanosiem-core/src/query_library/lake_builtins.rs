// SPDX-License-Identifier: AGPL-3.0-or-later

//! Lake variants of the legacy built-ins seeded by archive/039_query_library.sql.
//! Match the original text exactly: edited and tenant-authored queries are not
//! product templates and must retain their owner's semantics.

use std::sync::OnceLock;

#[derive(serde::Deserialize)]
struct Builtin {
    original: String,
    query: String,
}

fn builtins() -> &'static [Builtin] {
    static BUILTINS: OnceLock<Vec<Builtin>> = OnceLock::new();
    BUILTINS.get_or_init(|| {
        serde_json::from_str(include_str!("lake_builtins.json"))
            .expect("lake built-in query variants must be valid JSON")
    })
}

pub(super) fn rewrite(query: &str, is_builtin: bool) -> Option<&'static str> {
    is_builtin
        .then(|| builtins().iter().find(|entry| entry.original == query))
        .flatten()
        .map(|entry| entry.query.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        query::{parse_query, validate_query_fields_with_profile},
        schema::OcsfProfile,
    };

    #[test]
    fn lake_builtin_variants_validate_and_leave_user_content_alone() {
        let profile = OcsfProfile::lake_1_9();
        for entry in builtins() {
            let parsed =
                parse_query(&entry.query).unwrap_or_else(|e| panic!("{}: {e}", entry.query));
            let errors = validate_query_fields_with_profile(&parsed, Some(&profile));
            assert!(errors.is_empty(), "{}: {errors:?}", entry.query);
            assert_eq!(rewrite(&entry.original, true), Some(entry.query.as_str()));
            assert_eq!(rewrite(&entry.original, false), None);
            assert_eq!(rewrite(&format!("{} | head 7", entry.original), true), None);
        }
        assert_eq!(rewrite("user=* | stats count by user", true), None);
    }
}
