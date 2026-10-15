// SPDX-License-Identifier: AGPL-3.0-or-later

//! Dashboard panel `$variable` substitution (DSH18/DSH19).
//!
//! Shared by the dedicated `POST /api/dashboards/panel/query` handler and the
//! enterprise-shared tenant panel executor (NAN-2771) so both deployment
//! profiles resolve a panel's variables byte-identically.

use regex::Regex;
use std::collections::HashMap;
use std::sync::OnceLock;

/// Substitute `$name` variables in a query string.
///
/// DSH18: a single left-to-right regex pass (`$([A-Za-z_][A-Za-z0-9_]*)`) with
/// a map lookup — NOT the previous per-entry `str::replace` over
/// nondeterministic HashMap order, which (a) shadowed prefixed identifiers
/// (`$host` clobbering `$host_group`) and (b) re-scanned the accumulated
/// string, so a value that happened to contain `$othervar` was substituted
/// again. Only **defined** names are substituted; an unknown `$token` is left
/// intact (matching prior server behavior and avoiding silent corruption).
///
/// DSH19: values are escaped per target language.
/// - SQL arm: SQL-escape (`''` doubling + backslash) exactly as before; the SQL
///   author supplies the surrounding quotes (`col = '$var'`).
/// - Piped (nPL) arm: nPL has NO backslash escaping (NAN-1157) and no `''`
///   convention. A bare `field=$var` is wrapped in double quotes so multi-word
///   / special-char values stay a single term; a `$var` already sitting inside
///   a quoted literal (preceded by `"` or `'`) is inserted un-wrapped. In both
///   cases the active quote char is STRIPPED from the value (not backslashed),
///   since nPL can't represent an escaped quote.
pub fn substitute_panel_variables(
    query: &str,
    variables: &Option<HashMap<String, String>>,
    is_sql: bool,
) -> String {
    let vars = match variables {
        Some(v) => v,
        None => return query.to_string(),
    };

    static VAR_RE: OnceLock<Regex> = OnceLock::new();
    let re = VAR_RE.get_or_init(|| Regex::new(r"\$([A-Za-z_][A-Za-z0-9_]*)").unwrap());

    let mut out = String::with_capacity(query.len());
    let mut last = 0;
    for caps in re.captures_iter(query) {
        let whole = caps.get(0).unwrap();
        let name = &caps[1];
        let value = match vars.get(name) {
            Some(v) => v,
            // Leave undefined `$token` intact (do not advance `last`, so the
            // literal text is preserved by the next append / the tail append).
            None => continue,
        };

        out.push_str(&query[last..whole.start()]);
        if is_sql {
            out.push_str(&escape_sql_value(value));
        } else {
            out.push_str(&format_piped_value(value, query[..whole.start()].chars().next_back()));
        }
        last = whole.end();
    }
    out.push_str(&query[last..]);
    out
}

/// Format a substituted value for the piped (nPL) arm (DSH19). `preceding` is
/// the char immediately before the `$token`; when it's a quote the token is
/// inside a string literal, so the value is inserted without adding new quotes.
/// nPL has no backslash escaping, so the active quote char is stripped.
fn format_piped_value(value: &str, preceding: Option<char>) -> String {
    match preceding {
        Some(q @ ('"' | '\'')) => value.replace(q, ""),
        _ => format!("\"{}\"", value.replace('"', "")),
    }
}

/// Escape a value for safe SQL interpolation.
/// Escapes single quotes by doubling them, and escapes backslashes.
fn escape_sql_value(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\'', "''")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_substitute_variables_piped_quotes_and_isolates() {
        let query = "source_type = $source AND severity = $level";
        let mut vars = HashMap::new();
        vars.insert("source".to_string(), "apache".to_string());
        vars.insert("level".to_string(), "error".to_string());

        // Piped arm quote-wraps bare values so multi-word / special-char values
        // stay a single term (DSH4/DSH19).
        let result = substitute_panel_variables(query, &Some(vars), false);
        assert_eq!(result, "source_type = \"apache\" AND severity = \"error\"");
    }

    #[test]
    fn test_substitute_variables_sql_escapes_only() {
        let query = "source_type = '$source'";
        let mut vars = HashMap::new();
        vars.insert("source".to_string(), "O'Brien".to_string());

        // SQL arm doubles single quotes; the author supplies the quotes.
        let result = substitute_panel_variables(query, &Some(vars), true);
        assert_eq!(result, "source_type = 'O''Brien'");
    }

    #[test]
    fn test_substitute_variables_no_vars() {
        let query = "source_type = apache";
        let result = substitute_panel_variables(query, &None, false);
        assert_eq!(result, "source_type = apache");
    }

    #[test]
    fn test_substitute_variables_missing_var_left_intact() {
        let query = "source_type = $source AND severity = $level";
        let mut vars = HashMap::new();
        vars.insert("source".to_string(), "apache".to_string());
        // $level is not provided, should remain as-is.

        let result = substitute_panel_variables(query, &Some(vars), false);
        assert_eq!(result, "source_type = \"apache\" AND severity = $level");
    }

    #[test]
    fn test_substitute_variables_prefix_shadowing() {
        // DSH18: `$host` must not clobber `$host_group`, regardless of map order.
        let query = "src_host=$host AND group=$host_group";
        let mut vars = HashMap::new();
        vars.insert("host".to_string(), "web1".to_string());
        vars.insert("host_group".to_string(), "prod".to_string());

        let result = substitute_panel_variables(query, &Some(vars), false);
        assert_eq!(result, "src_host=\"web1\" AND group=\"prod\"");
    }

    #[test]
    fn test_substitute_variables_piped_no_backslash_escape() {
        // DSH19: nPL keeps backslashes literal; the value is quote-wrapped, and
        // embedded double quotes are stripped (not backslash-escaped).
        let query = "file_path=$path";
        let mut vars = HashMap::new();
        vars.insert("path".to_string(), r#"C:\Windows\a"b"#.to_string());

        let result = substitute_panel_variables(query, &Some(vars), false);
        assert_eq!(result, r#"file_path="C:\Windows\ab""#);
    }

    #[test]
    fn test_substitute_variables_piped_inside_quotes() {
        // A `$var` already inside a quoted literal is inserted un-wrapped, with
        // the active quote char stripped.
        let query = "user=\"$user\"";
        let mut vars = HashMap::new();
        vars.insert("user".to_string(), "John \"JD\" Smith".to_string());

        let result = substitute_panel_variables(query, &Some(vars), false);
        assert_eq!(result, "user=\"John JD Smith\"");
    }
}
