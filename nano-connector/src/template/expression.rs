//! Small, closed expression grammar. No evaluation of user code.
use super::{FORBIDDEN, NAMESPACES, Scope, TemplateError, lookup, value_to_string};
use serde_json::Value;

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
    if matches!(head, "coalesce" | "first" | "join" | "lower" | "json_quote") {
        let n = tokens.len() - 1;
        let valid = match head {
            "coalesce" => (2..=16).contains(&n),
            "join" => n == 2,
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
        || matches!(head, "null" | "true" | "false")
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
                "json_quote" => Value::String(
                    serde_json::to_string(&args[0]).map_err(|_| bad("cannot quote value"))?,
                ),
                _ => return Err(bad("unknown helper")),
            })
        }
    }
}

fn eval(expr: Expr, scope: &Scope) -> Result<Value, TemplateError> {
    let value = eval_inner(expr, scope)?;
    if value.to_string().len() > super::MAX_RENDER_BYTES {
        return Err(bad("expression output exceeds 4 MiB"));
    }
    Ok(value)
}

pub fn evaluate(text: &str, scope: &Scope) -> Result<Value, TemplateError> {
    let parsed = parse(text, 0)?;
    eval(parsed, scope)
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
