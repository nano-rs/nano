// SPDX-License-Identifier: AGPL-3.0-or-later

/// Evaluation functions for converting eval expressions to PostgreSQL SQL
///
/// Supports 100+ functions for SIEM analysis including:
/// - String manipulation (lower, upper, substr, replace, split, etc.)
/// - Encoding/decoding (base64, hex, URL encoding)
/// - Hashing (MD5, SHA1, SHA256)
/// - IP/network operations (CIDR matching, private IP detection)
/// - Domain/URL extraction and analysis
/// - Security-specific functions (defang, refang, entropy)
/// - Date/time manipulation (PPL-compatible)
/// - Type conversions
/// - Conditional logic
/// - Math operations
/// - Regex operations
/// - String similarity (Levenshtein, n-gram distance)
/// - Array operations
use super::field_utils::field_to_sql_expr;
use super::SqlGenError;
use crate::query::ast::*;

/// Convert eval expression to SQL
pub(crate) fn eval_expression_to_sql(expr: &EvalExpression) -> Result<String, SqlGenError> {
    eval_expression_to_sql_inner(expr, false)
}

/// Convert eval expression to SQL, optionally casting for numeric context
fn eval_expression_to_sql_inner(
    expr: &EvalExpression,
    numeric_context: bool,
) -> Result<String, SqlGenError> {
    match expr {
        EvalExpression::Field(name) => {
            let (sql_expr, needs_cast) = field_to_sql_expr(name);
            // If we're in a numeric context and this is a JSONB field (needs_cast=true),
            // cast it to numeric for arithmetic operations
            // The sql_expr for JSONB is like: metadata->>'field_name'
            // We need to wrap it: (metadata->>'field_name')::numeric
            if numeric_context && needs_cast {
                Ok(format!("({})::numeric", sql_expr))
            } else {
                Ok(sql_expr)
            }
        }
        EvalExpression::Literal(value) => Ok(match value {
            Value::String(s) => format!("'{}'", s.replace('\'', "''")),
            Value::Number(n) => n.to_string(),
            Value::Bool(b) => b.to_string(),
            Value::Ip(ip) => format!("'{}'", ip),
            Value::Regex(pattern) => format!("'{}'", pattern.replace('\'', "''")),
            Value::Interval(duration, unit) => {
                let seconds = duration.as_secs();
                match unit {
                    IntervalUnit::Microsecond => {
                        format!("INTERVAL '{} microseconds'", seconds * 1_000_000)
                    }
                    IntervalUnit::Millisecond => {
                        format!("INTERVAL '{} milliseconds'", seconds * 1_000)
                    }
                    IntervalUnit::Second => format!("INTERVAL '{} seconds'", seconds),
                    IntervalUnit::Minute => format!("INTERVAL '{} minutes'", seconds / 60),
                    IntervalUnit::Hour => format!("INTERVAL '{} hours'", seconds / 3600),
                    IntervalUnit::Day => format!("INTERVAL '{} days'", seconds / 86400),
                    IntervalUnit::Week => format!("INTERVAL '{} weeks'", seconds / 604800),
                    IntervalUnit::Month => format!("INTERVAL '{} months'", seconds / 2592000),
                    IntervalUnit::Year => format!("INTERVAL '{} years'", seconds / 31536000),
                }
            }
        }),
        EvalExpression::BinaryOp { left, op, right } => {
            // Determine if this is a numeric operation
            let is_numeric_op = matches!(
                op,
                BinaryOperator::Add
                    | BinaryOperator::Sub
                    | BinaryOperator::Mul
                    | BinaryOperator::Div
                    | BinaryOperator::Mod
                    | BinaryOperator::Gt
                    | BinaryOperator::Lt
                    | BinaryOperator::Gte
                    | BinaryOperator::Lte
            );

            let left_sql = eval_expression_to_sql_inner(left, is_numeric_op)?;
            let right_sql = eval_expression_to_sql_inner(right, is_numeric_op)?;

            let op_sql = match op {
                BinaryOperator::Add => "+",
                BinaryOperator::Sub => "-",
                BinaryOperator::Mul => "*",
                BinaryOperator::Div => "/",
                BinaryOperator::Mod => "%",
                BinaryOperator::Concat => "||", // PostgreSQL string concatenation
                BinaryOperator::Eq => "=",
                BinaryOperator::Ne => "!=",
                BinaryOperator::Gt => ">",
                BinaryOperator::Lt => "<",
                BinaryOperator::Gte => ">=",
                BinaryOperator::Lte => "<=",
                BinaryOperator::And => "AND",
                BinaryOperator::Or => "OR",
                BinaryOperator::Contains | BinaryOperator::Like => "",
            };

            match op {
                BinaryOperator::Contains => {
                    Ok(format!("(position({} in {}) > 0)", right_sql, left_sql))
                }
                BinaryOperator::Like => Ok(format!("({} LIKE {})", left_sql, right_sql)),
                _ => Ok(format!("({} {} {})", left_sql, op_sql, right_sql)),
            }
        }
        EvalExpression::FunctionCall { name, args } => eval_function_to_sql(name, args),
    }
}

/// Convert eval function call to PostgreSQL SQL
/// Supports security-focused helper functions for SIEM analysts
fn eval_function_to_sql(name: &str, args: &[EvalExpression]) -> Result<String, SqlGenError> {
    let arg_sqls: Result<Vec<String>, SqlGenError> = args
        .iter()
        .map(|arg| eval_expression_to_sql_inner(arg, false))
        .collect();
    let arg_sqls = arg_sqls?;

    match name.to_lowercase().as_str() {
        // ============================================================
        // String Functions
        // ============================================================
        "lower" | "tolower" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("lower() requires 1 argument".into()))?;
            Ok(format!("LOWER({})", arg))
        }
        "upper" | "toupper" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("upper() requires 1 argument".into()))?;
            Ok(format!("UPPER({})", arg))
        }
        "len" | "length" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("len() requires 1 argument".into()))?;
            Ok(format!("LENGTH({})", arg))
        }
        "substr" | "substring" => {
            match arg_sqls.len() {
                2 => {
                    // PostgreSQL substring is 1-indexed, but we accept 0-indexed
                    // Convert: substr(str, 0) -> SUBSTRING(str FROM 1)
                    Ok(format!(
                        "SUBSTRING({} FROM {} + 1)",
                        arg_sqls[0], arg_sqls[1]
                    ))
                }
                3 => {
                    // Convert: substr(str, start, len) -> SUBSTRING(str FROM start+1 FOR len)
                    Ok(format!(
                        "SUBSTRING({} FROM {} + 1 FOR {})",
                        arg_sqls[0], arg_sqls[1], arg_sqls[2]
                    ))
                }
                _ => Err(SqlGenError::InvalidQuery(
                    "substr() requires 2 or 3 arguments".into(),
                )),
            }
        }
        "replace" => {
            if arg_sqls.len() != 3 {
                return Err(SqlGenError::InvalidQuery(
                    "replace() requires 3 arguments".into(),
                ));
            }
            Ok(format!(
                "REPLACE({}, {}, {})",
                arg_sqls[0], arg_sqls[1], arg_sqls[2]
            ))
        }
        "trim" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("trim() requires 1 argument".into()))?;
            Ok(format!("TRIM({})", arg))
        }
        "ltrim" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("ltrim() requires 1 argument".into()))?;
            Ok(format!("LTRIM({})", arg))
        }
        "rtrim" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("rtrim() requires 1 argument".into()))?;
            Ok(format!("RTRIM({})", arg))
        }
        "reverse" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("reverse() requires 1 argument".into()))?;
            Ok(format!("REVERSE({})", arg))
        }
        "split" => {
            // PostgreSQL: string_to_array(string, delimiter)
            if arg_sqls.len() != 2 {
                return Err(SqlGenError::InvalidQuery(
                    "split() requires 2 arguments".into(),
                ));
            }
            Ok(format!("string_to_array({}, {})", arg_sqls[0], arg_sqls[1]))
        }
        "concat" => Ok(format!("CONCAT({})", arg_sqls.join(", "))),

        // ============================================================
        // Encoding/Decoding Functions (Security Essential)
        // ============================================================
        "base64_encode" | "base64encode" => {
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("base64_encode() requires 1 argument".into())
            })?;
            Ok(format!("encode({}::bytea, 'base64')", arg))
        }
        "base64_decode" | "base64decode" => {
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("base64_decode() requires 1 argument".into())
            })?;
            Ok(format!("convert_from(decode({}, 'base64'), 'UTF8')", arg))
        }
        "hex_encode" | "hexencode" | "tohex" => {
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("hex_encode() requires 1 argument".into())
            })?;
            Ok(format!("encode({}::bytea, 'hex')", arg))
        }
        "hex_decode" | "hexdecode" | "fromhex" => {
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("hex_decode() requires 1 argument".into())
            })?;
            Ok(format!("convert_from(decode({}, 'hex'), 'UTF8')", arg))
        }
        "url_encode" | "urlencode" => {
            // PostgreSQL doesn't have native URL encoding, use a workaround
            // This is a simplified version - full URL encoding would need a custom function
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("url_encode() requires 1 argument".into())
            })?;
            Ok(format!(
                "REPLACE(REPLACE(REPLACE({}, ' ', '%20'), '&', '%26'), '=', '%3D')",
                arg
            ))
        }
        "url_decode" | "urldecode" => {
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("url_decode() requires 1 argument".into())
            })?;
            Ok(format!(
                "REPLACE(REPLACE(REPLACE({}, '%20', ' '), '%26', '&'), '%3D', '=')",
                arg
            ))
        }

        // ============================================================
        // Hashing Functions (Security Essential)
        // ============================================================
        "md5" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("md5() requires 1 argument".into()))?;
            Ok(format!("md5({})", arg))
        }
        "sha1" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("sha1() requires 1 argument".into()))?;
            Ok(format!("encode(sha1({}::bytea), 'hex')", arg))
        }
        "sha256" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("sha256() requires 1 argument".into()))?;
            Ok(format!("encode(sha256({}::bytea), 'hex')", arg))
        }

        // ============================================================
        // IP/Network Functions (Security Essential)
        // ============================================================
        "cidr_match" | "cidrmatch" => {
            // Check if IP is in CIDR range(s)
            // 2-arg form: cidrmatch(cidr, ip) or cidr_match(ip, cidr)
            // Multi-arg form: cidr_match(ip, cidr1, cidr2, ...)
            if arg_sqls.len() == 2 {
                Ok(format!("({}::inet <<= {}::inet)", arg_sqls[0], arg_sqls[1]))
            } else if arg_sqls.len() > 2 {
                let ip = &arg_sqls[0];
                let checks: Vec<String> = arg_sqls[1..]
                    .iter()
                    .map(|cidr| format!("({}::inet <<= {}::inet)", ip, cidr))
                    .collect();
                Ok(format!("({})", checks.join(" OR ")))
            } else {
                return Err(SqlGenError::InvalidQuery(
                    "cidr_match() requires at least 2 arguments".into(),
                ));
            }
        }
        "is_private_ip" | "isprivateip" | "is_rfc1918" => {
            // Check if IP is in private ranges (RFC1918)
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("is_private_ip() requires 1 argument".into())
            })?;
            Ok(format!(
                "({}::inet <<= '10.0.0.0/8'::inet OR {}::inet <<= '172.16.0.0/12'::inet OR {}::inet <<= '192.168.0.0/16'::inet)",
                arg, arg, arg
            ))
        }
        "is_public_ip" | "ispublicip" => {
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("is_public_ip() requires 1 argument".into())
            })?;
            Ok(format!(
                "NOT ({}::inet <<= '10.0.0.0/8'::inet OR {}::inet <<= '172.16.0.0/12'::inet OR {}::inet <<= '192.168.0.0/16'::inet OR {}::inet <<= '127.0.0.0/8'::inet)",
                arg, arg, arg, arg
            ))
        }
        "is_loopback" | "isloopback" => {
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("is_loopback() requires 1 argument".into())
            })?;
            Ok(format!("({}::inet <<= '127.0.0.0/8'::inet)", arg))
        }

        // ============================================================
        // Domain/URL Extraction Functions (Security Essential)
        // ============================================================
        "extract_domain" | "extractdomain" => {
            // Extract domain from URL or email
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("extract_domain() requires 1 argument".into())
            })?;
            // Remove protocol, path, and extract domain
            Ok(format!(
                "REGEXP_REPLACE(REGEXP_REPLACE({}, '^https?://', ''), '/.*$', '')",
                arg
            ))
        }
        "extract_tld" | "extracttld" => {
            // Extract top-level domain
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("extract_tld() requires 1 argument".into())
            })?;
            Ok(format!(
                "SUBSTRING(REGEXP_REPLACE(REGEXP_REPLACE({}, '^https?://', ''), '/.*$', '') FROM '\\.([^.]+)$')",
                arg
            ))
        }
        "extract_path" | "extractpath" => {
            // Extract path from URL
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("extract_path() requires 1 argument".into())
            })?;
            Ok(format!(
                "COALESCE(SUBSTRING({} FROM '^https?://[^/]+(/.*)$'), '/')",
                arg
            ))
        }

        // ============================================================
        // Security-Specific Functions
        // ============================================================
        "defang" => {
            // Defang URLs/IPs for safe sharing: http://evil.com -> hxxp://evil[.]com
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("defang() requires 1 argument".into()))?;
            Ok(format!(
                "REPLACE(REPLACE(REPLACE({}, 'http', 'hxxp'), '.', '[.]'), '://', '[://]')",
                arg
            ))
        }
        "refang" => {
            // Refang defanged URLs/IPs: hxxp://evil[.]com -> http://evil.com
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("refang() requires 1 argument".into()))?;
            Ok(format!(
                "REPLACE(REPLACE(REPLACE({}, 'hxxp', 'http'), '[.]', '.'), '[://]', '://')",
                arg
            ))
        }
        "entropy" => {
            // Shannon entropy calculation (useful for detecting encoded/encrypted data)
            // This is a simplified approximation using string length variance
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("entropy() requires 1 argument".into()))?;
            // PostgreSQL doesn't have native entropy, return length as proxy
            // Real entropy would need a custom function
            Ok(format!("LENGTH({})", arg))
        }

        // ============================================================
        // Time Functions
        // ============================================================
        "now" => Ok("NOW()".to_string()),
        "strftime" | "to_char" => {
            if arg_sqls.len() != 2 {
                return Err(SqlGenError::InvalidQuery(
                    "strftime() requires 2 arguments (timestamp, format)".into(),
                ));
            }
            Ok(format!("to_char({}, {})", arg_sqls[0], arg_sqls[1]))
        }
        "relative_time" | "relativetime" => {
            // relative_time(timestamp, "-1h") -> timestamp - interval '1 hour'
            if arg_sqls.len() != 2 {
                return Err(SqlGenError::InvalidQuery(
                    "relative_time() requires 2 arguments".into(),
                ));
            }
            // Parse the relative time string and convert to interval
            Ok(format!("{} + {}", arg_sqls[0], arg_sqls[1]))
        }
        "epoch" | "to_epoch" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("epoch() requires 1 argument".into()))?;
            Ok(format!("EXTRACT(EPOCH FROM {})", arg))
        }
        "from_epoch" | "fromepoch" => {
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("from_epoch() requires 1 argument".into())
            })?;
            Ok(format!("to_timestamp({})", arg))
        }

        // ============================================================
        // Enhanced Date/Time Functions (PPL-compatible)
        // ============================================================
        "date_add" | "dateadd" => {
            // date_add(date, interval) - add time interval to date
            if arg_sqls.len() != 2 {
                return Err(SqlGenError::InvalidQuery(
                    "date_add() requires 2 arguments (date, interval)".into(),
                ));
            }
            Ok(format!("{} + {}", arg_sqls[0], arg_sqls[1]))
        }
        "date_sub" | "datesub" => {
            // date_sub(date, interval) - subtract time interval from date
            if arg_sqls.len() != 2 {
                return Err(SqlGenError::InvalidQuery(
                    "date_sub() requires 2 arguments (date, interval)".into(),
                ));
            }
            Ok(format!("{} - {}", arg_sqls[0], arg_sqls[1]))
        }
        "date_diff" | "datediff" => {
            // date_diff supports two forms:
            // - date_diff(date1, date2) - difference in seconds
            // - dateDiff('unit', date1, date2) - difference in specified unit
            match arg_sqls.len() {
                2 => Ok(format!(
                    "EXTRACT(EPOCH FROM ({} - {}))",
                    arg_sqls[0], arg_sqls[1]
                )),
                3 => {
                    // For PostgreSQL, we extract epoch and convert based on unit
                    let unit = arg_sqls[0].trim_matches('\'').to_lowercase();
                    let diff = format!("EXTRACT(EPOCH FROM ({} - {}))", arg_sqls[2], arg_sqls[1]);
                    match unit.as_str() {
                        "second" => Ok(diff),
                        "minute" => Ok(format!("({}) / 60", diff)),
                        "hour" => Ok(format!("({}) / 3600", diff)),
                        "day" => Ok(format!("({}) / 86400", diff)),
                        _ => Ok(diff), // Default to seconds
                    }
                }
                _ => Err(SqlGenError::InvalidQuery(
                    "date_diff() requires 2 or 3 arguments".into(),
                )),
            }
        }
        "date_trunc" | "datetrunc" => {
            // date_trunc(unit, timestamp) - truncate timestamp to unit
            if arg_sqls.len() != 2 {
                return Err(SqlGenError::InvalidQuery(
                    "date_trunc() requires 2 arguments (unit, timestamp)".into(),
                ));
            }
            Ok(format!("date_trunc({}, {})", arg_sqls[0], arg_sqls[1]))
        }
        "date_part" | "datepart" | "extract" => {
            // date_part(part, timestamp) - extract part from timestamp
            if arg_sqls.len() != 2 {
                return Err(SqlGenError::InvalidQuery(
                    "date_part() requires 2 arguments (part, timestamp)".into(),
                ));
            }
            Ok(format!("EXTRACT({} FROM {})", arg_sqls[0], arg_sqls[1]))
        }
        "year" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("year() requires 1 argument".into()))?;
            Ok(format!("EXTRACT(YEAR FROM {})", arg))
        }
        "month" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("month() requires 1 argument".into()))?;
            Ok(format!("EXTRACT(MONTH FROM {})", arg))
        }
        "day" | "dayofmonth" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("day() requires 1 argument".into()))?;
            Ok(format!("EXTRACT(DAY FROM {})", arg))
        }
        "hour" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("hour() requires 1 argument".into()))?;
            Ok(format!("EXTRACT(HOUR FROM {})", arg))
        }
        "minute" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("minute() requires 1 argument".into()))?;
            Ok(format!("EXTRACT(MINUTE FROM {})", arg))
        }
        "second" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("second() requires 1 argument".into()))?;
            Ok(format!("EXTRACT(SECOND FROM {})", arg))
        }
        "dayofweek" | "dow" => {
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("dayofweek() requires 1 argument".into())
            })?;
            Ok(format!("EXTRACT(DOW FROM {})", arg))
        }
        "dayofyear" | "doy" => {
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("dayofyear() requires 1 argument".into())
            })?;
            Ok(format!("EXTRACT(DOY FROM {})", arg))
        }
        "week" | "weekofyear" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("week() requires 1 argument".into()))?;
            Ok(format!("EXTRACT(WEEK FROM {})", arg))
        }
        "quarter" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("quarter() requires 1 argument".into()))?;
            Ok(format!("EXTRACT(QUARTER FROM {})", arg))
        }
        "age" => {
            // age(timestamp1, timestamp2) - interval between timestamps
            match arg_sqls.len() {
                1 => Ok(format!("AGE({})", arg_sqls[0])),
                2 => Ok(format!("AGE({}, {})", arg_sqls[0], arg_sqls[1])),
                _ => Err(SqlGenError::InvalidQuery(
                    "age() requires 1 or 2 arguments".into(),
                )),
            }
        }
        "timezone" | "at_timezone" => {
            // timezone(zone, timestamp) - convert timestamp to timezone
            if arg_sqls.len() != 2 {
                return Err(SqlGenError::InvalidQuery(
                    "timezone() requires 2 arguments (zone, timestamp)".into(),
                ));
            }
            Ok(format!("timezone({}, {})", arg_sqls[0], arg_sqls[1]))
        }
        "to_timestamp" | "totimestamp" => match arg_sqls.len() {
            1 => Ok(format!("to_timestamp({})", arg_sqls[0])),
            2 => Ok(format!("to_timestamp({}, {})", arg_sqls[0], arg_sqls[1])),
            _ => Err(SqlGenError::InvalidQuery(
                "to_timestamp() requires 1 or 2 arguments".into(),
            )),
        },
        "to_date" | "todate" => match arg_sqls.len() {
            1 => Ok(format!("to_date({}, 'YYYY-MM-DD')", arg_sqls[0])),
            2 => Ok(format!("to_date({}, {})", arg_sqls[0], arg_sqls[1])),
            _ => Err(SqlGenError::InvalidQuery(
                "to_date() requires 1 or 2 arguments".into(),
            )),
        },
        "isocalendar" => {
            // isocalendar(timestamp) - returns ISO week date as array [year, week, day]
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("isocalendar() requires 1 argument".into())
            })?;
            Ok(format!(
                "ARRAY[EXTRACT(ISOYEAR FROM {}), EXTRACT(WEEK FROM {}), EXTRACT(ISODOW FROM {})]",
                arg, arg, arg
            ))
        }
        "earliest" => {
            // earliest(timestamp1, timestamp2, ...) - return earliest timestamp
            if arg_sqls.is_empty() {
                return Err(SqlGenError::InvalidQuery(
                    "earliest() requires at least 1 argument".into(),
                ));
            }
            Ok(format!("LEAST({})", arg_sqls.join(", ")))
        }
        "latest" => {
            // latest(timestamp1, timestamp2, ...) - return latest timestamp
            if arg_sqls.is_empty() {
                return Err(SqlGenError::InvalidQuery(
                    "latest() requires at least 1 argument".into(),
                ));
            }
            Ok(format!("GREATEST({})", arg_sqls.join(", ")))
        }
        "time_bucket" | "timebucket" => {
            // time_bucket(interval, timestamp) - bucket timestamp into intervals
            if arg_sqls.len() != 2 {
                return Err(SqlGenError::InvalidQuery(
                    "time_bucket() requires 2 arguments (interval, timestamp)".into(),
                ));
            }
            // Use date_trunc for PostgreSQL compatibility
            Ok(format!("date_trunc({}, {})", arg_sqls[0], arg_sqls[1]))
        }
        "make_timestamp" | "maketimestamp" => {
            // make_timestamp(year, month, day, hour, minute, second)
            if arg_sqls.len() != 6 {
                return Err(SqlGenError::InvalidQuery("make_timestamp() requires 6 arguments (year, month, day, hour, minute, second)".into()));
            }
            Ok(format!(
                "make_timestamp({}, {}, {}, {}, {}, {})",
                arg_sqls[0], arg_sqls[1], arg_sqls[2], arg_sqls[3], arg_sqls[4], arg_sqls[5]
            ))
        }
        "make_date" | "makedate" => {
            // make_date(year, month, day)
            if arg_sqls.len() != 3 {
                return Err(SqlGenError::InvalidQuery(
                    "make_date() requires 3 arguments (year, month, day)".into(),
                ));
            }
            Ok(format!(
                "make_date({}, {}, {})",
                arg_sqls[0], arg_sqls[1], arg_sqls[2]
            ))
        }
        "make_time" | "maketime" => {
            // make_time(hour, minute, second)
            if arg_sqls.len() != 3 {
                return Err(SqlGenError::InvalidQuery(
                    "make_time() requires 3 arguments (hour, minute, second)".into(),
                ));
            }
            Ok(format!(
                "make_time({}, {}, {})",
                arg_sqls[0], arg_sqls[1], arg_sqls[2]
            ))
        }

        // ============================================================
        // Type Conversion Functions
        // ============================================================
        "tonumber" | "to_number" => {
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("tonumber() requires 1 argument".into())
            })?;
            Ok(format!("({}::numeric)", arg))
        }
        "tostring" | "to_string" => {
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("tostring() requires 1 argument".into())
            })?;
            Ok(format!("({}::text)", arg))
        }
        "toint" | "to_int" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("toint() requires 1 argument".into()))?;
            Ok(format!("({}::integer)", arg))
        }

        // ============================================================
        // Conditional Functions
        // ============================================================
        "if" | "iif" => {
            // if(condition, true_value, false_value)
            if arg_sqls.len() != 3 {
                return Err(SqlGenError::InvalidQuery(
                    "if() requires 3 arguments".into(),
                ));
            }
            Ok(format!(
                "CASE WHEN {} THEN {} ELSE {} END",
                arg_sqls[0], arg_sqls[1], arg_sqls[2]
            ))
        }
        "coalesce" | "nvl" => {
            if arg_sqls.is_empty() {
                return Err(SqlGenError::InvalidQuery(
                    "coalesce() requires at least 1 argument".into(),
                ));
            }
            Ok(format!("COALESCE({})", arg_sqls.join(", ")))
        }
        "nullif" => {
            if arg_sqls.len() != 2 {
                return Err(SqlGenError::InvalidQuery(
                    "nullif() requires 2 arguments".into(),
                ));
            }
            Ok(format!("NULLIF({}, {})", arg_sqls[0], arg_sqls[1]))
        }
        "isnull" | "is_null" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("isnull() requires 1 argument".into()))?;
            Ok(format!("({} IS NULL)", arg))
        }
        "isnotnull" | "is_not_null" => {
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("isnotnull() requires 1 argument".into())
            })?;
            Ok(format!("({} IS NOT NULL)", arg))
        }

        // ============================================================
        // Literal/Boolean Functions
        // ============================================================
        "null" => Ok("NULL".to_string()),
        "true" => Ok("TRUE".to_string()),
        "false" => Ok("FALSE".to_string()),

        // ============================================================
        // Math Functions
        // ============================================================
        "abs" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("abs() requires 1 argument".into()))?;
            Ok(format!("ABS({})", arg))
        }
        "ceil" | "ceiling" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("ceil() requires 1 argument".into()))?;
            Ok(format!("CEIL({})", arg))
        }
        "floor" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("floor() requires 1 argument".into()))?;
            Ok(format!("FLOOR({})", arg))
        }
        "round" => match arg_sqls.len() {
            1 => Ok(format!("ROUND({})", arg_sqls[0])),
            2 => Ok(format!("ROUND({}, {})", arg_sqls[0], arg_sqls[1])),
            _ => Err(SqlGenError::InvalidQuery(
                "round() requires 1 or 2 arguments".into(),
            )),
        },
        "log" | "ln" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("log() requires 1 argument".into()))?;
            Ok(format!("LN({})", arg))
        }
        "log10" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("log10() requires 1 argument".into()))?;
            Ok(format!("LOG({})", arg))
        }
        "pow" | "power" => {
            if arg_sqls.len() != 2 {
                return Err(SqlGenError::InvalidQuery(
                    "pow() requires 2 arguments".into(),
                ));
            }
            Ok(format!("POWER({}, {})", arg_sqls[0], arg_sqls[1]))
        }
        "sqrt" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("sqrt() requires 1 argument".into()))?;
            Ok(format!("SQRT({})", arg))
        }

        // ============================================================
        // Regex Functions
        // ============================================================
        "match" | "regex_match" => {
            // Returns true if pattern matches
            if arg_sqls.len() != 2 {
                return Err(SqlGenError::InvalidQuery(
                    "match() requires 2 arguments (string, pattern)".into(),
                ));
            }
            Ok(format!("({} ~ {})", arg_sqls[0], arg_sqls[1]))
        }
        "regex_extract" | "extract_regex" => {
            // Extract first match of pattern
            if arg_sqls.len() != 2 {
                return Err(SqlGenError::InvalidQuery(
                    "regex_extract() requires 2 arguments".into(),
                ));
            }
            Ok(format!("SUBSTRING({} FROM {})", arg_sqls[0], arg_sqls[1]))
        }
        "regex_replace" => {
            // Replace pattern matches
            if arg_sqls.len() != 3 {
                return Err(SqlGenError::InvalidQuery(
                    "regex_replace() requires 3 arguments".into(),
                ));
            }
            Ok(format!(
                "REGEXP_REPLACE({}, {}, {})",
                arg_sqls[0], arg_sqls[1], arg_sqls[2]
            ))
        }

        // ============================================================
        // String Similarity Functions (Phishing/Typosquatting Detection)
        // ============================================================
        "levenshtein" | "levenshtein_distance" | "edit_distance" => {
            // Edit distance between two strings - requires fuzzystrmatch extension
            if arg_sqls.len() != 2 {
                return Err(SqlGenError::InvalidQuery(
                    "levenshtein() requires 2 arguments".into(),
                ));
            }
            Ok(format!("levenshtein({}, {})", arg_sqls[0], arg_sqls[1]))
        }
        "levenshtein_normalized" | "edit_distance_normalized" => {
            // Normalized edit distance (0-1 range)
            if arg_sqls.len() != 2 {
                return Err(SqlGenError::InvalidQuery(
                    "levenshtein_normalized() requires 2 arguments".into(),
                ));
            }
            Ok(format!(
                "(levenshtein({}, {})::float / GREATEST(LENGTH({}), LENGTH({}), 1))",
                arg_sqls[0], arg_sqls[1], arg_sqls[0], arg_sqls[1]
            ))
        }
        "ngram_distance" | "ngramdistance" | "trigram_distance" | "trigramdistance" => {
            // Trigram distance (requires pg_trgm extension)
            if arg_sqls.len() != 2 {
                return Err(SqlGenError::InvalidQuery(
                    "ngram_distance() requires 2 arguments".into(),
                ));
            }
            // pg_trgm provides similarity (0-1, higher = more similar)
            // Convert to distance (0-1, lower = more similar) for consistency
            Ok(format!(
                "(1 - similarity({}, {}))",
                arg_sqls[0], arg_sqls[1]
            ))
        }
        "ngram_search" | "ngramsearch" => {
            // Trigram similarity search
            if arg_sqls.len() != 2 {
                return Err(SqlGenError::InvalidQuery(
                    "ngram_search() requires 2 arguments".into(),
                ));
            }
            Ok(format!("similarity({}, {})", arg_sqls[0], arg_sqls[1]))
        }

        // ============================================================
        // Domain Analysis Functions (Threat Hunting)
        // ============================================================
        "extract_root_domain" | "extractrootdomain" | "registered_domain" => {
            // Extract registered domain - PostgreSQL regex approximation
            // Note: This is a simplified version, doesn't handle all eTLDs
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("extract_root_domain() requires 1 argument".into())
            })?;
            Ok(format!(
                "SUBSTRING(REGEXP_REPLACE(REGEXP_REPLACE({}, '^https?://', ''), '/.*$', '') FROM '([^.]+\\.[^.]+)$')",
                arg
            ))
        }
        "extract_subdomain" | "extractsubdomain" | "first_subdomain" => {
            // Extract first subdomain
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("extract_subdomain() requires 1 argument".into())
            })?;
            Ok(format!(
                "SPLIT_PART(REGEXP_REPLACE(REGEXP_REPLACE({}, '^https?://', ''), '/.*$', ''), '.', 1)",
                arg
            ))
        }
        "domain_depth" | "subdomain_count" => {
            // Count domain levels
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("domain_depth() requires 1 argument".into())
            })?;
            Ok(format!(
                "ARRAY_LENGTH(STRING_TO_ARRAY(REGEXP_REPLACE(REGEXP_REPLACE({}, '^https?://', ''), '/.*$', ''), '.'), 1)",
                arg
            ))
        }

        // ============================================================
        // Array Functions
        // ============================================================
        "array_length" | "arraylength" => {
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("array_length() requires 1 argument".into())
            })?;
            Ok(format!("ARRAY_LENGTH({}, 1)", arg))
        }
        "array_join" | "arrayjoin" => {
            if arg_sqls.is_empty() {
                return Err(SqlGenError::InvalidQuery(
                    "array_join() requires at least 1 argument".into(),
                ));
            }
            if arg_sqls.len() == 1 {
                Ok(format!("ARRAY_TO_STRING({}, ',')", arg_sqls[0]))
            } else {
                Ok(format!("ARRAY_TO_STRING({}, {})", arg_sqls[0], arg_sqls[1]))
            }
        }
        "array_contains" | "arraycontains" | "has" => {
            if arg_sqls.len() != 2 {
                return Err(SqlGenError::InvalidQuery(
                    "array_contains() requires 2 arguments".into(),
                ));
            }
            Ok(format!("({} = ANY({}))", arg_sqls[1], arg_sqls[0]))
        }

        // ============================================================
        // Multivalue Functions
        // ============================================================
        "mvjoin" => {
            if arg_sqls.len() != 2 {
                return Err(SqlGenError::InvalidQuery(
                    "mvjoin() requires 2 arguments (field, separator)".into(),
                ));
            }
            Ok(format!("ARRAY_TO_STRING({}, {})", arg_sqls[0], arg_sqls[1]))
        }
        "mvfind" => {
            if arg_sqls.len() != 2 {
                return Err(SqlGenError::InvalidQuery(
                    "mvfind() requires 2 arguments (field, pattern)".into(),
                ));
            }
            // PostgreSQL: find first matching index
            Ok(format!(
                "(SELECT i FROM generate_subscripts({0}, 1) i WHERE ({0})[i] ~ {1} LIMIT 1)",
                arg_sqls[0], arg_sqls[1]
            ))
        }
        "mvcount" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("mvcount() requires 1 argument".into()))?;
            Ok(format!("ARRAY_LENGTH({}, 1)", arg))
        }
        "mvindex" => {
            if arg_sqls.len() != 2 {
                return Err(SqlGenError::InvalidQuery(
                    "mvindex() requires 2 arguments (field, index)".into(),
                ));
            }
            Ok(format!("({})[{} + 1]", arg_sqls[0], arg_sqls[1]))
        }
        "mvfilter" => {
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("mvfilter() requires 1 argument".into())
            })?;
            Ok(arg.clone())
        }
        "mvdedup" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("mvdedup() requires 1 argument".into()))?;
            Ok(format!(
                "(SELECT ARRAY_AGG(DISTINCT x) FROM UNNEST({}) x)",
                arg
            ))
        }
        "mvsort" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("mvsort() requires 1 argument".into()))?;
            Ok(format!(
                "(SELECT ARRAY_AGG(x ORDER BY x) FROM UNNEST({}) x)",
                arg
            ))
        }
        "mvappend" => {
            if arg_sqls.is_empty() {
                return Err(SqlGenError::InvalidQuery(
                    "mvappend() requires at least 1 argument".into(),
                ));
            }
            Ok(format!("ARRAY[{}]", arg_sqls.join(", ")))
        }
        "mvzip" => {
            if arg_sqls.len() < 2 {
                return Err(SqlGenError::InvalidQuery(
                    "mvzip() requires at least 2 arguments".into(),
                ));
            }
            let delim = if arg_sqls.len() > 2 {
                &arg_sqls[2]
            } else {
                &"','".to_string()
            };
            Ok(format!(
                "(SELECT ARRAY_AGG(a || {} || b) FROM UNNEST({}, {}) AS t(a, b))",
                delim, arg_sqls[0], arg_sqls[1]
            ))
        }
        "mvrange" => {
            if arg_sqls.len() < 2 {
                return Err(SqlGenError::InvalidQuery(
                    "mvrange() requires at least 2 arguments (start, end)".into(),
                ));
            }
            if arg_sqls.len() == 2 {
                Ok(format!(
                    "(SELECT ARRAY_AGG(i) FROM generate_series({}, {} - 1) i)",
                    arg_sqls[0], arg_sqls[1]
                ))
            } else {
                Ok(format!(
                    "(SELECT ARRAY_AGG(i) FROM generate_series({}, {} - 1, {}) i)",
                    arg_sqls[0], arg_sqls[1], arg_sqls[2]
                ))
            }
        }
        "exact" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("exact() requires 1 argument".into()))?;
            Ok(arg.clone())
        }
        "ip_version" => {
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("ip_version() requires 1 argument".into())
            })?;
            Ok(format!("CASE WHEN {}::text ~ '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$' THEN 4 WHEN {}::text ~ ':' THEN 6 ELSE 0 END", arg, arg))
        }
        "tolong" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("tolong() requires 1 argument".into()))?;
            Ok(format!("({}::text)::bigint", arg))
        }
        "typeof" | "type" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("typeof() requires 1 argument".into()))?;
            Ok(format!("pg_typeof({})", arg))
        }

        // Reject unknown functions — never pass through to the database
        _ => {
            return Err(SqlGenError::InvalidQuery(format!(
                "Unknown eval function '{}'. Use a supported function.",
                name
            )))
        }
    }
}
