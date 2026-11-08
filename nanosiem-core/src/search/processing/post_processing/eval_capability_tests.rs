// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4902: the capability table is the single source of truth for which
//! functions a post-processing stage can run. Validation accepts exactly the
//! table; these tests prove every entry (and alias) is actually implemented by
//! `evaluate_function_call`, so the validator can never admit a function that
//! would then evaluate to null and silently filter.
use super::eval::{evaluate_eval_expression, lookup_function, FUNCTIONS};
use crate::query::{EvalExpression, Value};

fn s(v: &str) -> Value {
    Value::String(v.to_owned())
}
fn n(v: f64) -> Value {
    Value::Number(v)
}

/// A known-good argument list per canonical name.
fn sample_args(canonical: &str) -> Option<Vec<Value>> {
    let url = "https://www.example.com/p";
    Some(match canonical {
        "lower" | "upper" | "len" | "reverse" => vec![s("AbC")],
        "trim" | "ltrim" | "rtrim" => vec![s(" a ")],
        "substr" => vec![s("abcdef"), n(1.0), n(2.0)],
        "replace" => vec![s("aXa"), s("X"), s("b")],
        "concat" => vec![s("a"), s("b")],
        "split" => vec![s("a,b"), s(",")],
        "base64_encode" | "hex_encode" | "url_encode" | "md5" | "sha1" | "sha256" => vec![s("hi")],
        "base64_decode" => vec![s("aGk=")],
        "hex_decode" => vec![s("6869")],
        "url_decode" => vec![s("a%20b")],
        "is_private_ip" | "is_public_ip" | "is_loopback" => vec![s("10.0.0.1")],
        "cidr_match" => vec![s("10.0.0.1"), s("10.0.0.0/8")],
        "match" => vec![s("abc"), s("^a")],
        "like" => vec![s("abc"), s("a%")],
        "array_contains" => vec![s("abc"), s("b")],
        "extract_domain" | "extract_tld" | "extract_path" => vec![s(url)],
        "defang" => vec![s("1.2.3.4")],
        "refang" => vec![s("1[.]2[.]3[.]4")],
        "coalesce" | "isnull" | "isnotnull" => vec![s("a")],
        "if" => vec![Value::Bool(true), n(1.0), n(2.0)],
        "in" => vec![s("A"), s("b"), s("a")],
        "isnum" | "isint" | "isstr" | "isbool" => vec![s("5")],
        "searchmatch" => vec![s("x=1")],
        "not" => vec![Value::Bool(true)],
        "min" | "max" | "pow" => vec![n(2.0), n(3.0)],
        "abs" => vec![n(-1.0)],
        "ceil" | "floor" => vec![n(1.2)],
        "round" => vec![n(1.26), n(1.0)],
        "sqrt" | "log" | "log10" => vec![n(4.0)],
        "tonumber" | "toint" => vec![s("3")],
        "tostring" => vec![n(3.0)],
        "now" => vec![],
        "dayofweek" => vec![s("2026-11-02T00:00:00Z")],
        _ => return None,
    })
}

fn call(name: &str, args: &[Value]) -> Option<serde_json::Value> {
    let expr = EvalExpression::FunctionCall {
        name: name.to_owned(),
        args: args.iter().cloned().map(EvalExpression::Literal).collect(),
    };
    evaluate_eval_expression(&expr, &serde_json::Map::new())
}

#[test]
fn every_capability_and_alias_evaluates() {
    for spec in FUNCTIONS {
        let args = sample_args(spec.canonical)
            .unwrap_or_else(|| panic!("add a sample for new capability '{}'", spec.canonical));
        assert!(spec.accepts(args.len()), "{}: sample violates declared arity", spec.canonical);
        let expected = call(spec.canonical, &args);
        assert!(expected.is_some(), "'{}' is in the capability table but does not evaluate", spec.canonical);
        for alias in spec.aliases.iter().copied().chain([spec.canonical]) {
            for spelling in [alias.to_owned(), alias.to_ascii_uppercase()] {
                let got = call(&spelling, &args);
                assert!(got.is_some(), "alias '{spelling}' of '{}' does not evaluate", spec.canonical);
                if spec.canonical != "now" {
                    assert_eq!(got, expected, "alias '{spelling}' disagrees with '{}'", spec.canonical);
                }
            }
        }
    }
}

#[test]
fn names_and_aliases_are_unique_and_lowercase() {
    let mut seen = std::collections::HashSet::new();
    for spec in FUNCTIONS {
        for name in spec.aliases.iter().copied().chain([spec.canonical]) {
            assert_eq!(name, name.to_ascii_lowercase(), "{name}");
            assert!(seen.insert(name), "duplicate function name '{name}'");
        }
    }
}

#[test]
fn wrong_arity_never_evaluates() {
    for spec in FUNCTIONS {
        let too_few = spec.min_args.checked_sub(1).map(|count| vec![s("1"); count]);
        let too_many = spec.max_args.map(|max| vec![s("1"); max + 1]);
        for args in too_few.into_iter().chain(too_many) {
            assert!(!spec.accepts(args.len()));
            assert_eq!(call(spec.canonical, &args), None, "{}({} args)", spec.canonical, args.len());
        }
    }
}

#[test]
fn unknown_functions_are_not_capabilities() {
    for name in ["strlen", "relative_time"] {
        assert!(lookup_function(name).is_none(), "{name}");
        assert_eq!(call(name, &[s("x")]), None, "{name}");
    }
}
