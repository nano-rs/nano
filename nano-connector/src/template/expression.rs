//! Small, closed expression grammar. No evaluation of user code.
use super::{FORBIDDEN, NAMESPACES, Scope, TemplateError, lookup, value_to_string};
use serde_json::Value;
use base64::Engine as _;

enum Expr {
    Path(String),
    Literal(Value),
    Call(String, Vec<Expr>),
}

fn response_dependent(expr: &Expr) -> bool {
    match expr {
        Expr::Path(p) => p.starts_with("steps.") || p.starts_with("poll."),
        Expr::Literal(_) => false,
        Expr::Call(_, args) => args.iter().any(response_dependent),
    }
}
fn source(expr: &Expr) -> String {
    match expr {
        Expr::Path(p) => p.clone(),
        Expr::Literal(v) => v.to_string(),
        Expr::Call(name, args) => format!(
            "({name} {})",
            args.iter().map(source).collect::<Vec<_>>().join(" ")
        ),
    }
}

fn bad(message: &str) -> TemplateError {
    TemplateError::Expression(message.into())
}

fn parse(text: &str, depth: usize) -> Result<Expr, TemplateError> {
    if depth > 8 || text.len() > 8192 {
        return Err(bad("expression exceeds its size or nesting limit"));
    }
    let text = text.trim();
    if text.starts_with('(') && text.ends_with(')') {
        return parse(&text[1..text.len() - 1], depth + 1);
    }
    let mut tokens = Vec::new();
    let (mut start, mut nesting, mut quoted, mut escaped) = (0, 0usize, false, false);
    for (i, ch) in text.char_indices() {
        if quoted {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                quoted = false;
            }
        } else {
            match ch {
                '"' => quoted = true,
                '(' => nesting += 1,
                ')' => {
                    nesting = nesting
                        .checked_sub(1)
                        .ok_or_else(|| bad("unbalanced parentheses"))?
                }
                c if c.is_whitespace() && nesting == 0 => {
                    if start < i {
                        tokens.push(&text[start..i]);
                    }
                    start = i + ch.len_utf8();
                }
                _ => {}
            }
        }
    }
    if quoted || nesting != 0 {
        return Err(bad("unterminated literal or parentheses"));
    }
    if start < text.len() {
        tokens.push(&text[start..]);
    }
    let Some(head) = tokens.first().copied() else {
        return Err(bad("empty expression"));
    };
    if matches!(
        head,
        "coalesce" | "first" | "join" | "lower" | "json_quote" | "base64url" | "notification_body" | "with_field"
    ) {
        let n = tokens.len() - 1;
        let valid = match head {
            "coalesce" => (2..=16).contains(&n),
            "join" => n == 2,
            "notification_body" => n == 3,
            "with_field" => n == 3,
            _ => n == 1,
        };
        if !valid {
            return Err(bad("invalid helper argument count"));
        }
        return Ok(Expr::Call(
            head.into(),
            tokens[1..]
                .iter()
                .map(|t| parse(t, depth + 1))
                .collect::<Result<_, _>>()?,
        ));
    }
    if tokens.len() != 1 {
        return Err(bad("unknown helper"));
    }
    if head.starts_with('"')
        || matches!(head, "null" | "true" | "false" | "[]" | "{}")
        || head.parse::<i64>().is_ok()
    {
        return serde_json::from_str(head)
            .map(Expr::Literal)
            .map_err(|_| bad("invalid literal"));
    }
    let ns = head.split('.').next().unwrap_or_default();
    if FORBIDDEN.contains(&ns.to_ascii_lowercase().as_str()) {
        return Err(TemplateError::Forbidden(head.into()));
    }
    if !NAMESPACES.contains(&ns) {
        return Err(TemplateError::Unknown(ns.into()));
    }
    if head
        .split('.')
        .any(|s| s.is_empty() || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
    {
        return Err(bad("paths contain only identifiers and array indices"));
    }
    Ok(Expr::Path(head.into()))
}

pub fn expression_references(text: &str) -> Result<Vec<String>, TemplateError> {
    fn walk(expr: Expr, out: &mut Vec<String>) {
        match expr {
            Expr::Path(p) => out.push(p),
            Expr::Call(_, args) => args.into_iter().for_each(|e| walk(e, out)),
            Expr::Literal(_) => {}
        }
    }
    let mut out = Vec::new();
    walk(parse(text, 0)?, &mut out);
    Ok(out)
}

fn eval_inner(expr: Expr, scope: &Scope) -> Result<Value, TemplateError> {
    match expr {
        Expr::Path(p)
            if scope.defer_responses && (p.starts_with("steps.") || p.starts_with("poll.")) =>
        {
            Ok(Value::String(format!("{{{{{p}}}}}")))
        }
        Expr::Path(p) => Ok(lookup(&p, scope)),
        Expr::Literal(v) => Ok(v),
        Expr::Call(name, args) => {
            if name == "coalesce" {
                for arg in args {
                    let value = eval(arg, scope)?;
                    if !value.is_null() && value.as_str() != Some("") {
                        return Ok(value);
                    }
                }
                return Ok(Value::Null);
            }
            if scope.defer_responses && args.iter().any(response_dependent) {
                let expression = format!(
                    "{name} {}",
                    args.iter().map(source).collect::<Vec<_>>().join(" ")
                );
                return Ok(Value::String(format!("{{{{{expression}}}}}")));
            }
            let args = args
                .into_iter()
                .map(|a| eval(a, scope))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(match name.as_str() {
                "with_field" => {
                    let key = args[1]
                        .as_str()
                        .ok_or_else(|| bad("with_field key must be a string"))?;
                    if key.is_empty()
                        || key.len() > 64
                        || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                    {
                        return Err(bad("with_field key must be a bounded identifier"));
                    }
                    let mut object = args[0]
                        .as_object()
                        .ok_or_else(|| bad("with_field requires an object"))?
                        .clone();
                    object.insert(key.into(), args[2].clone());
                    Value::Object(object)
                }
                "first" => args[0]
                    .as_array()
                    .ok_or_else(|| bad("first requires an array"))?
                    .first()
                    .cloned()
                    .unwrap_or(Value::Null),
                "join" => {
                    let values = args[0]
                        .as_array()
                        .ok_or_else(|| bad("join requires an array"))?;
                    let delimiter = args[1]
                        .as_str()
                        .ok_or_else(|| bad("join delimiter must be a string"))?;
                    let separators = delimiter
                        .len()
                        .checked_mul(values.len().saturating_sub(1))
                        .filter(|n| *n <= super::MAX_RENDER_BYTES)
                        .ok_or_else(|| bad("join output exceeds 4 MiB"))?;
                    let mut rendered = Vec::new();
                    let mut size = separators;
                    for value in values {
                        let text = value_to_string(value);
                        size = size
                            .checked_add(text.len())
                            .filter(|n| *n <= super::MAX_RENDER_BYTES)
                            .ok_or_else(|| bad("join output exceeds 4 MiB"))?;
                        rendered.push(text);
                    }
                    Value::String(rendered.join(delimiter))
                }
                "lower" => Value::String(
                    args[0]
                        .as_str()
                        .ok_or_else(|| bad("lower requires a string"))?
                        .to_lowercase(),
                ),
                "base64url" => {
                    let text = args[0].as_str().ok_or_else(|| bad("base64url requires a string"))?;
                    let size = text.len().checked_mul(4).and_then(|n| n.checked_add(2)).map(|n| n / 3)
                        .filter(|n| *n <= super::MAX_RENDER_BYTES)
                        .ok_or_else(|| bad("base64url output exceeds 4 MiB"))?;
                    let mut encoded = String::with_capacity(size);
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode_string(text.as_bytes(), &mut encoded);
                    Value::String(encoded)
                }
                "json_quote" => Value::String(
                    serde_json::to_string(&args[0]).map_err(|_| bad("cannot quote value"))?,
                ),
                "notification_body" => {
                    use nanosiem_core::webhooks::{
                        channels::{
                            NotificationTransport, build_notification_body,
                            decode_notification_event,
                        },
                        models::WebhookPayload,
                    };
                    let vendor = args[0]
                        .as_str()
                        .ok_or_else(|| bad("notification vendor must be a string"))?;
                    // A canonical event is data, never a template or a secret namespace.
                    let payload: WebhookPayload = decode_notification_event(args[1].clone())
                        .map_err(|_| bad("invalid canonical notification event"))?;
                    let destination = args[2]
                        .as_str()
                        .ok_or_else(|| bad("notification destination must be a string"))?;
                    let transport = match vendor {
                        "generic" => NotificationTransport::Generic,
                        "slack" => NotificationTransport::SlackChat {
                            channel: destination,
                        },
                        "teams" => NotificationTransport::TeamsGraph,
                        "pagerduty" => NotificationTransport::PagerDuty,
                        _ => return Err(bad("unknown notification vendor")),
                    };
                    let bytes = build_notification_body(transport, &payload)
                        .map_err(|_| bad("cannot format notification event"))?;
                    Value::String(
                        String::from_utf8(bytes).map_err(|_| bad("invalid notification JSON"))?,
                    )
                }
                _ => return Err(bad("unknown helper")),
            })
        }
    }
}

fn checked(value: Value, scope: &Scope, guard_secret: bool) -> Result<Value, TemplateError> {
    let encoded = value.to_string();
    if encoded.len() > super::MAX_RENDER_BYTES {
        return Err(bad("expression output exceeds 4 MiB"));
    }
    if guard_secret && scope.secret_guard.as_ref().is_some_and(|guard| guard.contains(encoded.as_bytes())) {
        return Err(bad("expression would expose credential material"));
    }
    Ok(value)
}

fn eval(expr: Expr, scope: &Scope) -> Result<Value, TemplateError> {
    checked(eval_inner(expr, scope)?, scope, true)
}

pub fn evaluate(text: &str, scope: &Scope) -> Result<Value, TemplateError> {
    let parsed = parse(text, 0)?;
    // Previews retain their existing final-summary redaction for raw values.
    // Every helper operand still goes through eval(), before any transform,
    // so an encoding composition cannot conceal a credential from redaction.
    let guard_secret = !scope.secret_guard.as_ref().is_some_and(|g| g.allows_raw_preview());
    checked(eval_inner(parsed, scope)?, scope, guard_secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn response_helpers_cannot_amplify_into_unbounded_allocations() {
        let scope = Scope {
            steps: json!({"read":{"items":vec!["";1024],"delimiter":"x".repeat(8192)}}),
            ..Default::default()
        };
        assert!(evaluate("join steps.read.items steps.read.delimiter", &scope).is_err());
        let mut scope = scope;
        scope.defer_responses = true;
        assert_eq!(
            evaluate("first steps.read.items", &scope).unwrap(),
            json!("{{first steps.read.items}}")
        );
        let scope = Scope {
            input: json!({"value":"chosen"}),
            ..Default::default()
        };
        assert_eq!(
            evaluate("coalesce input.value (first steps.missing.items)", &scope).unwrap(),
            json!("chosen")
        );
    }

    #[test]
    fn url_identifiers_are_unpadded_bounded_and_keep_secret_namespaces_closed() {
        for (plain, encoded) in [("", ""), ("f", "Zg"), ("fo", "Zm8"), ("foo", "Zm9v"), ("✓", "4pyT"), ("\u{ffff}", "77-_")] {
            let scope=Scope{input:json!({"url":plain}),..Default::default()};
            assert_eq!(evaluate("base64url input.url",&scope).unwrap(),json!(encoded));
        }
        let scope=Scope{input:json!({"wrong":5,"large":"x".repeat(super::super::MAX_RENDER_BYTES * 3 / 4 + 1)}),..Default::default()};
        for expression in ["base64url input.wrong","base64url input.large","base64url secret.KEY","base64url credentials.KEY","base64url env.KEY","base64url", "base64url input.x input.y"] {
            assert!(evaluate(expression,&scope).is_err(),"{expression}");
        }
        assert_eq!(evaluate("coalesce input.missing []",&Scope::default()).unwrap(),json!([]));
        assert_eq!(evaluate("coalesce input.missing {}",&Scope::default()).unwrap(),json!({}));
    }

    #[test]
    fn helpers_keep_types_and_reject_code_or_hidden_secrets() {
        let scope = Scope {
            input: json!({"ids": ["A", "B"]}),
            ..Default::default()
        };
        assert_eq!(
            evaluate("coalesce input.missing (first input.ids)", &scope).unwrap(),
            json!("A")
        );
        assert_eq!(
            evaluate("join input.ids \",\"", &scope).unwrap(),
            json!("A,B")
        );
        assert_eq!(
            evaluate("lower (first input.ids)", &scope).unwrap(),
            json!("a")
        );
        assert_eq!(
            evaluate("json_quote input.ids", &scope).unwrap(),
            json!("[\"A\",\"B\"]")
        );
        for t in [
            "coalesce input.id secrets.TOKEN",
            "eval input.code",
            "first",
            "input.x[0]",
            "input..x",
        ] {
            assert!(evaluate(t, &scope).is_err(), "{t}");
        }
    }
}

#[cfg(test)]
mod notification_tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn notification_helper_is_closed_typed_and_does_not_reinterpret_event_text() {
        let scope = Scope {
            input: json!({"event":{"event_type":"case.created", "created_at":"2024-03-09T16:00:00Z", "rule_name":"{{credentials.KEY}}"}}),
            ..Default::default()
        };
        let body = evaluate(r#"notification_body "generic" input.event """#, &scope).unwrap();
        assert!(body.as_str().unwrap().contains("{{credentials.KEY}}"));
        for text in [
            r#"notification_body "unknown" input.event """#,
            r#"notification_body "slack" input.event """#,
            r#"notification_body "generic" input.missing """#,
            r#"notification_body "generic" credentials.KEY """#,
            r#"notification_body "generic" input.event"#,
        ] {
            assert!(evaluate(text, &scope).is_err(), "{text}");
        }
    }
}

#[cfg(test)]
mod with_field_tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn with_field_preserves_opaque_properties_and_types_without_mutating_scope() {
        let scope = Scope {
            steps: json!({"current":{"properties":{"title":"Example","severity":"High","status":"New","labels":[{"labelName":"keep"}],"owner":{"objectId":"abc"},"future":{"retain":true}}}}),
            input: json!({"status":"Active"}),
            ..Default::default()
        };
        let updated = evaluate(
            r#"with_field steps.current.properties "status" input.status"#,
            &scope,
        )
        .unwrap();
        assert_eq!(updated["status"], "Active");
        assert_eq!(scope.steps["current"]["properties"]["status"], "New");
        for name in ["title", "severity", "labels", "owner", "future"] {
            assert_eq!(updated[name], scope.steps["current"]["properties"][name]);
        }
        for text in [
            r#"with_field input.status "x" input.status"#,
            r#"with_field steps.current.properties "a.b" input.status"#,
            r#"with_field steps.current.properties "" input.status"#,
            r#"with_field steps.current.properties "status" secrets.X"#,
        ] {
            assert!(evaluate(text, &scope).is_err());
        }
    }
}

#[cfg(test)]
mod merge_guard_tests {
    use super::*;
    use crate::{secrets::SecretSet, template::SecretGuard};
    use serde_json::json;

    #[test]
    fn with_field_keeps_connection_and_caller_guards_in_live_and_preview() {
        let secret = "synthetic-binding-secret";
        for caller in [false, true] {
            for preview in [false, true] {
                let registered = SecretSet::new([secret]);
                let guard = if caller {
                    SecretGuard::new(SecretSet::default(), registered)
                } else {
                    SecretGuard::new(registered, SecretSet::default())
                };
                let mut scope = Scope {
                    input: json!({"object":{"public":true},"value":secret}),
                    secret_guard: Some(if preview { guard.for_preview() } else { guard }),
                    ..Default::default()
                };
                for expression in [
                    r#"with_field input.object "note" input.value"#,
                    r#"json_quote (with_field input.object "note" input.value)"#,
                ] {
                    let error = evaluate(expression, &scope).unwrap_err().to_string();
                    assert!(error.contains("credential material"), "{error}");
                    assert!(!error.contains(secret));
                }
                scope.input["value"] = json!("public note");
                assert_eq!(
                    evaluate(r#"with_field input.object "note" input.value"#, &scope).unwrap(),
                    json!({"public":true,"note":"public note"})
                );
                assert_eq!(scope.input["object"], json!({"public":true}));
            }
        }
    }
}
