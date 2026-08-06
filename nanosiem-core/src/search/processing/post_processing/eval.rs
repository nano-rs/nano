// SPDX-License-Identifier: AGPL-3.0-or-later

//! Expression evaluation for post-processing
//!
//! This module provides eval expression evaluation functions including:
//! - Binary operations (arithmetic, comparison, logical)
//! - Function calls (string, encoding, hashing, IP/network, domain/URL, security, conditional, math, type conversion)

use crate::query::{BinaryOperator, EvalExpression, Value};

/// Evaluate an eval expression on a row
///
/// # Arguments
/// * `expr` - The expression to evaluate
/// * `row` - The row data to evaluate against
///
/// # Returns
/// * `Some(serde_json::Value)` - The evaluated value
/// * `None` - If evaluation fails or produces null
pub fn evaluate_eval_expression(
    expr: &EvalExpression,
    row: &serde_json::Map<String, serde_json::Value>,
) -> Option<serde_json::Value> {
    match expr {
        EvalExpression::Field(name) => row.get(name).cloned(),
        EvalExpression::Literal(val) => Some(match val {
            Value::String(s) => serde_json::Value::String(s.clone()),
            Value::Number(n) => serde_json::json!(n),
            Value::Bool(b) => serde_json::Value::Bool(*b),
            Value::Regex(r) => serde_json::Value::String(r.clone()),
            Value::Ip(ip) => serde_json::Value::String(ip.to_string()),
            Value::Interval(duration, unit) => {
                // Convert interval to a string representation
                serde_json::Value::String(format!(
                    "INTERVAL {} {}",
                    duration.as_secs(),
                    unit.as_str().to_uppercase()
                ))
            }
        }),
        EvalExpression::BinaryOp { left, op, right } => {
            let left_val = evaluate_eval_expression(left, row)?;
            let right_val = evaluate_eval_expression(right, row)?;

            match op {
                BinaryOperator::Add => {
                    let l = left_val.as_f64()?;
                    let r = right_val.as_f64()?;
                    Some(serde_json::json!(l + r))
                }
                BinaryOperator::Sub => {
                    let l = left_val.as_f64()?;
                    let r = right_val.as_f64()?;
                    Some(serde_json::json!(l - r))
                }
                BinaryOperator::Mul => {
                    let l = left_val.as_f64()?;
                    let r = right_val.as_f64()?;
                    Some(serde_json::json!(l * r))
                }
                BinaryOperator::Div => {
                    let l = left_val.as_f64()?;
                    let r = right_val.as_f64()?;
                    if r != 0.0 {
                        Some(serde_json::json!(l / r))
                    } else {
                        None
                    }
                }
                BinaryOperator::Mod => {
                    let l = left_val.as_f64()?;
                    let r = right_val.as_f64()?;
                    if r != 0.0 {
                        Some(serde_json::json!(l % r))
                    } else {
                        None
                    }
                }
                BinaryOperator::Concat => {
                    // String concatenation
                    let l = left_val
                        .as_str()
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| left_val.to_string());
                    let r = right_val
                        .as_str()
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| right_val.to_string());
                    Some(serde_json::Value::String(format!("{}{}", l, r)))
                }
                BinaryOperator::Eq => Some(serde_json::json!(left_val == right_val)),
                BinaryOperator::Ne => Some(serde_json::json!(left_val != right_val)),
                BinaryOperator::Gt => {
                    let l = left_val.as_f64()?;
                    let r = right_val.as_f64()?;
                    Some(serde_json::json!(l > r))
                }
                BinaryOperator::Lt => {
                    let l = left_val.as_f64()?;
                    let r = right_val.as_f64()?;
                    Some(serde_json::json!(l < r))
                }
                BinaryOperator::Gte => {
                    let l = left_val.as_f64()?;
                    let r = right_val.as_f64()?;
                    Some(serde_json::json!(l >= r))
                }
                BinaryOperator::Lte => {
                    let l = left_val.as_f64()?;
                    let r = right_val.as_f64()?;
                    Some(serde_json::json!(l <= r))
                }
                BinaryOperator::And => {
                    let l = left_val.as_bool()?;
                    let r = right_val.as_bool()?;
                    Some(serde_json::json!(l && r))
                }
                BinaryOperator::Or => {
                    let l = left_val.as_bool()?;
                    let r = right_val.as_bool()?;
                    Some(serde_json::json!(l || r))
                }
                BinaryOperator::Contains => {
                    let l = left_val.as_str()?;
                    let r = right_val.as_str()?;
                    Some(serde_json::json!(l
                        .to_lowercase()
                        .contains(&r.to_lowercase())))
                }
                BinaryOperator::Like => {
                    // Simple LIKE evaluation: % = any, _ = single char
                    let l = left_val.as_str()?.to_lowercase();
                    let r = right_val.as_str()?.to_lowercase();
                    let pattern = format!("^{}$", r.replace('%', ".*").replace('_', "."));
                    regex::Regex::new(&pattern)
                        .ok()
                        .map(|re| serde_json::json!(re.is_match(&l)))
                }
            }
        }
        EvalExpression::FunctionCall { name, args } => evaluate_function_call(name, args, row),
    }
}

/// Evaluate a function call in an eval expression
///
/// # Arguments
/// * `name` - The function name
/// * `args` - The function arguments
/// * `row` - The row data to evaluate against
///
/// # Returns
/// * `Some(serde_json::Value)` - The function result
/// * `None` - If evaluation fails
fn evaluate_function_call(
    name: &str,
    args: &[EvalExpression],
    row: &serde_json::Map<String, serde_json::Value>,
) -> Option<serde_json::Value> {
    match name.to_lowercase().as_str() {
        // ============================================================
        // String Functions
        // ============================================================
        "lower" | "tolower" => {
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            Some(serde_json::Value::String(arg.as_str()?.to_lowercase()))
        }
        "upper" | "toupper" => {
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            Some(serde_json::Value::String(arg.as_str()?.to_uppercase()))
        }
        "len" | "length" => {
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            Some(serde_json::json!(arg.as_str()?.len()))
        }
        "trim" => {
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            Some(serde_json::Value::String(arg.as_str()?.trim().to_string()))
        }
        "ltrim" => {
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            Some(serde_json::Value::String(
                arg.as_str()?.trim_start().to_string(),
            ))
        }
        "rtrim" => {
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            Some(serde_json::Value::String(
                arg.as_str()?.trim_end().to_string(),
            ))
        }
        "reverse" => {
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            Some(serde_json::Value::String(
                arg.as_str()?.chars().rev().collect(),
            ))
        }
        "substr" | "substring" => {
            let s = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            let start = args.get(1).and_then(|a| evaluate_eval_expression(a, row))?;
            let s_str = s.as_str()?;
            let start_idx = start.as_i64()? as usize;
            if args.len() >= 3 {
                let len = args.get(2).and_then(|a| evaluate_eval_expression(a, row))?;
                let len_val = len.as_i64()? as usize;
                Some(serde_json::Value::String(
                    s_str.chars().skip(start_idx).take(len_val).collect(),
                ))
            } else {
                Some(serde_json::Value::String(
                    s_str.chars().skip(start_idx).collect(),
                ))
            }
        }
        "replace" => {
            let s = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            let from = args.get(1).and_then(|a| evaluate_eval_expression(a, row))?;
            let to = args.get(2).and_then(|a| evaluate_eval_expression(a, row))?;
            Some(serde_json::Value::String(
                s.as_str()?.replace(from.as_str()?, to.as_str()?),
            ))
        }
        "concat" => {
            let parts: Vec<String> = args
                .iter()
                .filter_map(|a| evaluate_eval_expression(a, row))
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
            Some(serde_json::Value::String(parts.join("")))
        }
        "split" => {
            let s = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            let delim = args.get(1).and_then(|a| evaluate_eval_expression(a, row))?;
            let parts: Vec<serde_json::Value> = s
                .as_str()?
                .split(delim.as_str()?)
                .map(|p| serde_json::Value::String(p.to_string()))
                .collect();
            Some(serde_json::Value::Array(parts))
        }

        // ============================================================
        // Encoding/Decoding Functions (Security Essential)
        // ============================================================
        "base64_encode" | "base64encode" => {
            use base64::Engine;
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            let encoded =
                base64::engine::general_purpose::STANDARD.encode(arg.as_str()?.as_bytes());
            Some(serde_json::Value::String(encoded))
        }
        "base64_decode" | "base64decode" => {
            use base64::Engine;
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(arg.as_str()?)
                .ok()?;
            let decoded_str = String::from_utf8(decoded).ok()?;
            Some(serde_json::Value::String(decoded_str))
        }
        "hex_encode" | "hexencode" | "tohex" => {
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            let encoded = hex::encode(arg.as_str()?.as_bytes());
            Some(serde_json::Value::String(encoded))
        }
        "hex_decode" | "hexdecode" | "fromhex" => {
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            let decoded = hex::decode(arg.as_str()?).ok()?;
            let decoded_str = String::from_utf8(decoded).ok()?;
            Some(serde_json::Value::String(decoded_str))
        }
        "url_encode" | "urlencode" => {
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            let encoded = urlencoding::encode(arg.as_str()?);
            Some(serde_json::Value::String(encoded.into_owned()))
        }
        "url_decode" | "urldecode" => {
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            let decoded = urlencoding::decode(arg.as_str()?).ok()?;
            Some(serde_json::Value::String(decoded.into_owned()))
        }

        // ============================================================
        // Hashing Functions (Security Essential)
        // ============================================================
        "md5" => {
            use md5::{Digest, Md5};
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            let mut hasher = Md5::new();
            hasher.update(arg.as_str()?.as_bytes());
            let result = hasher.finalize();
            Some(serde_json::Value::String(hex::encode(result)))
        }
        "sha1" => {
            use sha1::{Digest, Sha1};
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            let mut hasher = Sha1::new();
            hasher.update(arg.as_str()?.as_bytes());
            let result = hasher.finalize();
            Some(serde_json::Value::String(hex::encode(result)))
        }
        "sha256" => {
            use sha2::{Digest, Sha256};
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            let mut hasher = Sha256::new();
            hasher.update(arg.as_str()?.as_bytes());
            let result = hasher.finalize();
            Some(serde_json::Value::String(hex::encode(result)))
        }

        // ============================================================
        // IP/Network Functions (Security Essential)
        // ============================================================
        "is_private_ip" | "isprivateip" | "is_rfc1918" => {
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            let ip_str = arg.as_str()?;
            let is_private = ip_str.starts_with("10.")
                || ip_str.starts_with("192.168.")
                || (ip_str.starts_with("172.") && {
                    let parts: Vec<&str> = ip_str.split('.').collect();
                    parts
                        .get(1)
                        .and_then(|s| s.parse::<u8>().ok())
                        .map(|n| n >= 16 && n <= 31)
                        .unwrap_or(false)
                });
            Some(serde_json::Value::Bool(is_private))
        }
        "is_public_ip" | "ispublicip" => {
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            let ip_str = arg.as_str()?;
            let is_private = ip_str.starts_with("10.")
                || ip_str.starts_with("192.168.")
                || ip_str.starts_with("127.")
                || (ip_str.starts_with("172.") && {
                    let parts: Vec<&str> = ip_str.split('.').collect();
                    parts
                        .get(1)
                        .and_then(|s| s.parse::<u8>().ok())
                        .map(|n| n >= 16 && n <= 31)
                        .unwrap_or(false)
                });
            Some(serde_json::Value::Bool(!is_private))
        }
        "is_loopback" | "isloopback" => {
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            let ip_str = arg.as_str()?;
            Some(serde_json::Value::Bool(ip_str.starts_with("127.")))
        }

        // ============================================================
        // Domain/URL Extraction Functions (Security Essential)
        // ============================================================
        "extract_domain" | "extractdomain" => {
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            let url = arg.as_str()?;
            // Remove protocol
            let without_protocol = url
                .trim_start_matches("http://")
                .trim_start_matches("https://")
                .trim_start_matches("ftp://");
            // Get domain (before first /)
            let domain = without_protocol
                .split('/')
                .next()
                .unwrap_or(without_protocol);
            // Remove port if present
            let domain = domain.split(':').next().unwrap_or(domain);
            Some(serde_json::Value::String(domain.to_string()))
        }
        "extract_tld" | "extracttld" => {
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            let url = arg.as_str()?;
            let without_protocol = url
                .trim_start_matches("http://")
                .trim_start_matches("https://");
            let domain = without_protocol
                .split('/')
                .next()
                .unwrap_or(without_protocol);
            let domain = domain.split(':').next().unwrap_or(domain);
            let tld = domain.rsplit('.').next().unwrap_or("");
            Some(serde_json::Value::String(tld.to_string()))
        }
        "extract_path" | "extractpath" => {
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            let url = arg.as_str()?;
            let without_protocol = url
                .trim_start_matches("http://")
                .trim_start_matches("https://");
            let path = without_protocol
                .find('/')
                .map(|i| &without_protocol[i..])
                .unwrap_or("/");
            Some(serde_json::Value::String(path.to_string()))
        }

        // ============================================================
        // Security-Specific Functions
        // ============================================================
        "defang" => {
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            let defanged = arg
                .as_str()?
                .replace("http", "hxxp")
                .replace(".", "[.]")
                .replace("://", "[://]");
            Some(serde_json::Value::String(defanged))
        }
        "refang" => {
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            let refanged = arg
                .as_str()?
                .replace("hxxp", "http")
                .replace("[.]", ".")
                .replace("[://]", "://");
            Some(serde_json::Value::String(refanged))
        }

        // ============================================================
        // Conditional Functions
        // ============================================================
        "coalesce" => {
            for arg in args {
                if let Some(val) = evaluate_eval_expression(arg, row) {
                    if !val.is_null() {
                        return Some(val);
                    }
                }
            }
            None
        }
        "if" | "iif" => {
            if args.len() >= 3 {
                let cond = evaluate_eval_expression(&args[0], row)?;
                let is_true = match cond {
                    serde_json::Value::Bool(b) => b,
                    serde_json::Value::Number(n) => n.as_f64().map(|v| v != 0.0).unwrap_or(false),
                    serde_json::Value::String(s) => !s.is_empty(),
                    _ => false,
                };
                if is_true {
                    evaluate_eval_expression(&args[1], row)
                } else {
                    evaluate_eval_expression(&args[2], row)
                }
            } else {
                None
            }
        }
        "isnull" | "is_null" => {
            let arg = args.first().and_then(|a| evaluate_eval_expression(a, row));
            Some(serde_json::Value::Bool(
                arg.is_none() || arg.as_ref().map(|v| v.is_null()).unwrap_or(true),
            ))
        }
        "isnotnull" | "is_not_null" => {
            let arg = args.first().and_then(|a| evaluate_eval_expression(a, row));
            Some(serde_json::Value::Bool(
                arg.is_some() && !arg.as_ref().map(|v| v.is_null()).unwrap_or(true),
            ))
        }

        // ============================================================
        // Math Functions
        // ============================================================
        "min" | "max" => {
            let mut values = args.iter().map(|arg| evaluate_eval_expression(arg, row));
            let first = values.next()??;
            values.try_fold(first, |best, candidate| {
                let candidate = candidate?;
                let ordering = match (best.as_f64(), candidate.as_f64()) {
                    (Some(left), Some(right)) => left.partial_cmp(&right),
                    _ => match (best.as_str(), candidate.as_str()) {
                        (Some(left), Some(right)) => Some(left.cmp(right)),
                        _ => None,
                    },
                }?;
                let take_candidate = if name.eq_ignore_ascii_case("min") {
                    ordering.is_gt()
                } else {
                    ordering.is_lt()
                };
                Some(if take_candidate { candidate } else { best })
            })
        }
        "abs" => {
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            let n = arg.as_f64()?;
            Some(serde_json::json!(n.abs()))
        }
        "ceil" | "ceiling" => {
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            let n = arg.as_f64()?;
            Some(serde_json::json!(n.ceil()))
        }
        "floor" => {
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            let n = arg.as_f64()?;
            Some(serde_json::json!(n.floor()))
        }
        "round" => {
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            let n = arg.as_f64()?;
            if args.len() >= 2 {
                let decimals = args.get(1).and_then(|a| evaluate_eval_expression(a, row))?;
                let d = decimals.as_i64()? as i32;
                let factor = 10_f64.powi(d);
                Some(serde_json::json!((n * factor).round() / factor))
            } else {
                Some(serde_json::json!(n.round()))
            }
        }
        "sqrt" => {
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            let n = arg.as_f64()?;
            Some(serde_json::json!(n.sqrt()))
        }
        "pow" | "power" => {
            let base = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            let exp = args.get(1).and_then(|a| evaluate_eval_expression(a, row))?;
            Some(serde_json::json!(base.as_f64()?.powf(exp.as_f64()?)))
        }
        "log" | "ln" => {
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            let n = arg.as_f64()?;
            Some(serde_json::json!(n.ln()))
        }
        "log10" => {
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            let n = arg.as_f64()?;
            Some(serde_json::json!(n.log10()))
        }

        // ============================================================
        // Type Conversion Functions
        // ============================================================
        "tonumber" | "to_number" | "toint" | "to_int" => {
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            match arg {
                serde_json::Value::Number(n) => Some(serde_json::Value::Number(n)),
                serde_json::Value::String(s) => s.parse::<f64>().ok().map(|n| serde_json::json!(n)),
                _ => None,
            }
        }
        "tostring" | "to_string" => {
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            Some(serde_json::Value::String(match arg {
                serde_json::Value::String(s) => s,
                serde_json::Value::Number(n) => n.to_string(),
                serde_json::Value::Bool(b) => b.to_string(),
                _ => arg.to_string(),
            }))
        }

        _ => None,
    }
}

#[cfg(test)]
mod nan2331_scalar_min_max_tests {
    use super::*;

    #[test]
    fn evaluates_case_insensitive_scalar_min_max() {
        let row = serde_json::Map::new();
        let expression = EvalExpression::FunctionCall {
            name: "MAX".to_string(),
            args: vec![
                EvalExpression::Literal(Value::Number(1.0)),
                EvalExpression::Literal(Value::Number(3.0)),
                EvalExpression::Literal(Value::Number(2.0)),
            ],
        };

        assert_eq!(
            evaluate_eval_expression(&expression, &row),
            Some(serde_json::json!(3.0))
        );
    }
}
