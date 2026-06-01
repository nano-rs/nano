// SPDX-License-Identifier: AGPL-3.0-or-later

/// Evaluation functions for converting eval expressions to ClickHouse SQL
///
/// Supports 100+ functions for SIEM analysis including:
/// - String manipulation
/// - Encoding/decoding (base64, hex, URL)
/// - Hashing (MD5, SHA1, SHA256)
/// - IP/network operations
/// - Domain/URL extraction
/// - Security functions (defang, refang, entropy)
/// - Date/time manipulation (ClickHouse-specific)
/// - Type conversions
/// - Conditional logic
/// - Math operations
/// - Regex operations
/// - String similarity (Levenshtein, n-gram)
/// - Array operations
use super::{escape_regex_pattern, ClickHouseSqlGenerator};
use crate::query::ast::*;
use crate::query::sql_gen::SqlGenError;

/// Convert strftime format codes to ClickHouse formatDateTime codes
/// https://clickhouse.com/docs/en/sql-reference/functions/date-time-functions#formatdatetime
fn convert_strftime_to_clickhouse(format: &str) -> String {
    let mut result = String::new();
    let mut chars = format.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '%' {
            if let Some(&next) = chars.peek() {
                chars.next(); // consume the format character
                match next {
                    // Day
                    'a' => result.push_str("%a"), // Abbreviated weekday name (Mon)
                    'A' => result.push_str("%W"), // Full weekday name (Monday) - ClickHouse uses %W
                    'd' => result.push_str("%d"), // Day of month (01-31)
                    'e' => result.push_str("%e"), // Day of month (1-31)
                    'j' => result.push_str("%j"), // Day of year (001-366)
                    'w' => result.push_str("%w"), // Weekday as number (0-6, Sunday=0)

                    // Month
                    'b' | 'h' => result.push_str("%b"), // Abbreviated month name (Jan)
                    'B' => result.push_str("%M"), // Full month name (January) - ClickHouse uses %M
                    'm' => result.push_str("%m"), // Month (01-12)

                    // Year
                    'y' => result.push_str("%y"), // Year without century (00-99)
                    'Y' => result.push_str("%Y"), // Year with century (2024)
                    'C' => result.push_str("%C"), // Century

                    // Time
                    'H' => result.push_str("%H"), // Hour 24-hour (00-23)
                    'I' => result.push_str("%I"), // Hour 12-hour (01-12)
                    'M' => result.push_str("%M"), // Minute (00-59)
                    'S' => result.push_str("%S"), // Second (00-59)
                    'p' => result.push_str("%p"), // AM/PM

                    // Combined
                    'c' => result.push_str("%c"), // Date and time
                    'x' => result.push_str("%F"), // Date (YYYY-MM-DD)
                    'X' => result.push_str("%T"), // Time (HH:MM:SS)
                    'F' => result.push_str("%F"), // ISO date (YYYY-MM-DD)
                    'T' => result.push_str("%T"), // ISO time (HH:MM:SS)
                    'R' => result.push_str("%R"), // Time HH:MM

                    // Timezone
                    'z' => result.push_str("%z"), // Timezone offset
                    'Z' => result.push_str("%Z"), // Timezone name

                    // Literal %
                    '%' => result.push('%'),

                    // Unsupported - pass through as-is
                    _ => {
                        result.push('%');
                        result.push(next);
                    }
                }
            } else {
                result.push('%');
            }
        } else {
            result.push(ch);
        }
    }

    result
}

// Helper function to get field SQL expression
fn field_to_sql_expr(field: &str, gen: &ClickHouseSqlGenerator) -> (String, bool) {
    super::field_to_sql_expr(field, gen)
}

/// Convert eval expression to SQL
pub(crate) fn eval_expression_to_sql(
    gen: &ClickHouseSqlGenerator,
    expr: &EvalExpression,
) -> Result<String, SqlGenError> {
    eval_expression_to_sql_inner(gen, expr, false)
}
/// Convert eval expression to SQL, optionally casting for numeric context
fn eval_expression_to_sql_inner(
    gen: &ClickHouseSqlGenerator,
    expr: &EvalExpression,
    numeric_context: bool,
) -> Result<String, SqlGenError> {
    match expr {
        EvalExpression::Field(name) => {
            let (sql_expr, _needs_alias) = field_to_sql_expr(name, gen);
            if numeric_context {
                // In numeric context (comparisons, arithmetic), cast field to Float64
                // This handles fields extracted from JSON as strings
                // toFloat64OrNull returns NULL for non-numeric strings (safer than OrZero)
                // We use assumeNotNull to handle the NULL case, defaulting to 0
                Ok(format!("toFloat64OrNull(toString({}))", sql_expr))
            } else {
                Ok(sql_expr)
            }
        }
        EvalExpression::Literal(value) => Ok(match value {
            Value::String(s) => format!("'{}'", s.replace('\\', "\\\\").replace('\'', "''")),
            Value::Number(n) => n.to_string(),
            Value::Bool(b) => if *b { "1" } else { "0" }.to_string(),
            Value::Ip(ip) => format!("'{}'", ip),
            Value::Regex(pattern) => format!("'{}'", escape_regex_pattern(pattern)),
            Value::Interval(duration, unit) => {
                let seconds = duration.as_secs();
                match unit {
                    IntervalUnit::Microsecond => {
                        format!("INTERVAL {} MICROSECOND", seconds * 1_000_000)
                    }
                    IntervalUnit::Millisecond => {
                        format!("INTERVAL {} MILLISECOND", seconds * 1_000)
                    }
                    IntervalUnit::Second => format!("INTERVAL {} SECOND", seconds),
                    IntervalUnit::Minute => format!("INTERVAL {} MINUTE", seconds / 60),
                    IntervalUnit::Hour => format!("INTERVAL {} HOUR", seconds / 3600),
                    IntervalUnit::Day => format!("INTERVAL {} DAY", seconds / 86400),
                    IntervalUnit::Week => format!("INTERVAL {} WEEK", seconds / 604800),
                    IntervalUnit::Month => format!("INTERVAL {} MONTH", seconds / 2592000),
                    IntervalUnit::Year => format!("INTERVAL {} YEAR", seconds / 31536000),
                }
            }
        }),
        EvalExpression::BinaryOp { left, op, right } => {
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

            let left_sql = eval_expression_to_sql_inner(gen, left, is_numeric_op)?;
            let right_sql = eval_expression_to_sql_inner(gen, right, is_numeric_op)?;

            let op_sql = match op {
                BinaryOperator::Add => "+",
                BinaryOperator::Sub => "-",
                BinaryOperator::Mul => "*",
                BinaryOperator::Div => "/",
                BinaryOperator::Mod => "%",
                BinaryOperator::Concat => "||", // ClickHouse also supports ||
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
                    // CONTAINS maps to: position(haystack, needle) > 0
                    Ok(format!("(position({}, {}) > 0)", left_sql, right_sql))
                }
                BinaryOperator::Like => Ok(format!("({} LIKE {})", left_sql, right_sql)),
                _ => Ok(format!("({} {} {})", left_sql, op_sql, right_sql)),
            }
        }
        EvalExpression::FunctionCall { name, args } => eval_function_to_sql(gen, name, args),
    }
}

/// Convert eval function call to ClickHouse SQL
/// Supports security-focused helper functions for SIEM analysts
fn eval_function_to_sql(
    gen: &ClickHouseSqlGenerator,
    name: &str,
    args: &[EvalExpression],
) -> Result<String, SqlGenError> {
    let arg_sqls: Result<Vec<String>, SqlGenError> = args
        .iter()
        .map(|arg| eval_expression_to_sql_inner(gen, arg, false))
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
            Ok(format!("lower({})", arg))
        }
        "upper" | "toupper" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("upper() requires 1 argument".into()))?;
            Ok(format!("upper({})", arg))
        }
        "len" | "length" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("len() requires 1 argument".into()))?;
            Ok(format!("length({})", arg))
        }
        "substr" | "substring" => {
            match arg_sqls.len() {
                2 => {
                    // ClickHouse substring is 1-indexed, but we accept 0-indexed
                    // Convert: substr(str, 0, len) -> substring(str, 1, len)
                    Ok(format!("substring({}, {} + 1)", arg_sqls[0], arg_sqls[1]))
                }
                3 => {
                    // Convert: substr(str, start, len) -> substring(str, start+1, len)
                    Ok(format!(
                        "substring({}, {} + 1, {})",
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
                "replaceAll({}, {}, {})",
                arg_sqls[0], arg_sqls[1], arg_sqls[2]
            ))
        }
        "trim" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("trim() requires 1 argument".into()))?;
            Ok(format!("trimBoth({})", arg))
        }
        "ltrim" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("ltrim() requires 1 argument".into()))?;
            Ok(format!("trimLeft({})", arg))
        }
        "rtrim" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("rtrim() requires 1 argument".into()))?;
            Ok(format!("trimRight({})", arg))
        }
        "reverse" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("reverse() requires 1 argument".into()))?;
            Ok(format!("reverse({})", arg))
        }
        "split" => {
            // ClickHouse: splitByString(separator, string)
            if arg_sqls.len() != 2 {
                return Err(SqlGenError::InvalidQuery(
                    "split() requires 2 arguments".into(),
                ));
            }
            Ok(format!("splitByString({}, {})", arg_sqls[1], arg_sqls[0]))
        }
        "concat" => Ok(format!("concat({})", arg_sqls.join(", "))),

        // ============================================================
        // Encoding/Decoding Functions (Security Essential)
        // ============================================================
        "base64_encode" | "base64encode" => {
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("base64_encode() requires 1 argument".into())
            })?;
            Ok(format!("base64Encode({})", arg))
        }
        "base64_decode" | "base64decode" => {
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("base64_decode() requires 1 argument".into())
            })?;
            Ok(format!("base64Decode({})", arg))
        }
        "hex_encode" | "hexencode" | "tohex" => {
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("hex_encode() requires 1 argument".into())
            })?;
            Ok(format!("hex({})", arg))
        }
        "hex_decode" | "hexdecode" | "fromhex" => {
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("hex_decode() requires 1 argument".into())
            })?;
            Ok(format!("unhex({})", arg))
        }
        "url_encode" | "urlencode" => {
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("url_encode() requires 1 argument".into())
            })?;
            Ok(format!("encodeURLComponent({})", arg))
        }
        "url_decode" | "urldecode" => {
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("url_decode() requires 1 argument".into())
            })?;
            Ok(format!("decodeURLComponent({})", arg))
        }

        // ============================================================
        // Hashing Functions (Security Essential)
        // ============================================================
        "md5" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("md5() requires 1 argument".into()))?;
            Ok(format!("lower(hex(MD5({})))", arg))
        }
        "sha1" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("sha1() requires 1 argument".into()))?;
            Ok(format!("lower(hex(SHA1({})))", arg))
        }
        "sha256" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("sha256() requires 1 argument".into()))?;
            Ok(format!("lower(hex(SHA256({})))", arg))
        }

        // ============================================================
        // IP/Network Functions (Security Essential)
        // ============================================================
        "cidr_match" | "cidrmatch" => {
            // Check if IP is in CIDR range(s)
            // 2-arg form: cidrmatch(cidr, ip) — legacy nPL convention
            // Multi-arg form: cidr_match(ip, cidr1, cidr2, ...) — alternate convention
            if arg_sqls.len() == 2 {
                // Legacy: cidrmatch(cidr, ip) → isIPAddressInRange(ip, cidr)
                // Guard against empty strings which crash isIPAddressInRange
                Ok(format!(
                    "(length({}) > 0 AND isIPAddressInRange({}, {}))",
                    arg_sqls[1], arg_sqls[1], arg_sqls[0]
                ))
            } else if arg_sqls.len() > 2 {
                // Multi-CIDR: cidr_match(ip, cidr1, cidr2, ...) → OR chain
                let ip = &arg_sqls[0];
                let checks: Vec<String> = arg_sqls[1..]
                    .iter()
                    .map(|cidr| format!("isIPAddressInRange({}, {})", ip, cidr))
                    .collect();
                // Guard against empty strings which crash isIPAddressInRange
                Ok(format!("(length({}) > 0 AND ({}))", ip, checks.join(" OR ")))
            } else {
                return Err(SqlGenError::InvalidQuery(
                    "cidr_match() requires at least 2 arguments".into(),
                ));
            }
        }
        "is_private_ip" | "isprivateip" | "is_rfc1918" => {
            // Check if IP is in private ranges (RFC1918)
            // Guard against empty strings which crash isIPAddressInRange
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("is_private_ip() requires 1 argument".into())
            })?;
            Ok(format!(
                    "(length({}) > 0 AND (isIPAddressInRange({}, '10.0.0.0/8') OR isIPAddressInRange({}, '172.16.0.0/12') OR isIPAddressInRange({}, '192.168.0.0/16')))",
                    arg, arg, arg, arg
                ))
        }
        "is_public_ip" | "ispublicip" => {
            // Guard against empty strings which crash isIPAddressInRange
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("is_public_ip() requires 1 argument".into())
            })?;
            Ok(format!(
                    "(length({}) > 0 AND NOT (isIPAddressInRange({}, '10.0.0.0/8') OR isIPAddressInRange({}, '172.16.0.0/12') OR isIPAddressInRange({}, '192.168.0.0/16') OR isIPAddressInRange({}, '127.0.0.0/8')))",
                    arg, arg, arg, arg, arg
                ))
        }
        "is_loopback" | "isloopback" => {
            // Guard against empty strings which crash isIPAddressInRange
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("is_loopback() requires 1 argument".into())
            })?;
            Ok(format!("(length({}) > 0 AND isIPAddressInRange({}, '127.0.0.0/8'))", arg, arg))
        }
        "ipv4_to_int" | "ip_to_int" => {
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("ipv4_to_int() requires 1 argument".into())
            })?;
            Ok(format!("IPv4StringToNum({})", arg))
        }
        "int_to_ipv4" | "int_to_ip" => {
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("int_to_ipv4() requires 1 argument".into())
            })?;
            Ok(format!("IPv4NumToString({})", arg))
        }

        // ============================================================
        // Domain/URL Extraction Functions (Security Essential)
        // ============================================================
        "extract_domain" | "extractdomain" => {
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("extract_domain() requires 1 argument".into())
            })?;
            Ok(format!("domain({})", arg))
        }
        "extract_tld" | "extracttld" => {
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("extract_tld() requires 1 argument".into())
            })?;
            Ok(format!("topLevelDomain({})", arg))
        }
        "extract_path" | "extractpath" => {
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("extract_path() requires 1 argument".into())
            })?;
            Ok(format!("path({})", arg))
        }
        "extract_protocol" | "extractprotocol" => {
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("extract_protocol() requires 1 argument".into())
            })?;
            Ok(format!("protocol({})", arg))
        }
        "extract_query_string" | "extractquerystring" => {
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("extract_query_string() requires 1 argument".into())
            })?;
            Ok(format!("queryString({})", arg))
        }

        // ============================================================
        // Security-Specific Functions
        // ============================================================
        "defang" => {
            // Defang URLs/IPs for safe sharing
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("defang() requires 1 argument".into()))?;
            Ok(format!(
                    "replaceAll(replaceAll(replaceAll({}, 'http', 'hxxp'), '.', '[.]'), '://', '[://]')",
                    arg
                ))
        }
        "refang" => {
            // Refang defanged URLs/IPs
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("refang() requires 1 argument".into()))?;
            Ok(format!(
                    "replaceAll(replaceAll(replaceAll({}, 'hxxp', 'http'), '[.]', '.'), '[://]', '://')",
                    arg
                ))
        }
        "entropy" => {
            // Shannon entropy over the character array of the argument:
            //   H = -Σ p(c) * log2(p(c)) for each distinct character c.
            // extractAll(str, '.') splits into individual characters (regex . = any char).
            // The previous form wrapped this in a scalar subquery
            //   (SELECT ... FROM (SELECT extractAll(arg,'.') AS chars))
            // which failed with Code 48 (NOT_IMPLEMENTED) on a real column — the column
            // could not be correlated into the derived table (NAN-1144). This inline form
            // binds the char array exactly once by mapping a single-element array
            // [extractAll(arg,'.')] through a lambda and taking element [1], so there is no
            // subquery and extractAll is evaluated only once. Empty/single-char strings yield 0
            // (the countEqual=0 guard avoids log2(0)/NaN).
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("entropy() requires 1 argument".into()))?;
            Ok(format!(
                "arrayMap(arr -> arrayReduce('sum', arrayMap(c -> \
                 if(countEqual(arr, c) = 0, 0, \
                 -(countEqual(arr, c) / length(arr)) * log2(countEqual(arr, c) / length(arr))), \
                 arrayDistinct(arr))), [extractAll({}, '.')])[1]",
                arg
            ))
        }

        // ============================================================
        // Time Functions
        // ============================================================
        "now" => Ok("now()".to_string()),
        "strftime" | "to_char" => {
            if arg_sqls.len() != 2 {
                return Err(SqlGenError::InvalidQuery(
                    "strftime() requires 2 arguments (timestamp, format)".into(),
                ));
            }
            // Convert strftime format codes to ClickHouse formatDateTime codes
            // arg_sqls[1] is the format string (with quotes)
            let format_str = arg_sqls[1].trim_matches('\'');
            let ch_format = convert_strftime_to_clickhouse(format_str);
            Ok(format!("formatDateTime({}, '{}')", arg_sqls[0], ch_format))
        }
        "relative_time" | "relativetime" => {
            if arg_sqls.len() != 2 {
                return Err(SqlGenError::InvalidQuery(
                    "relative_time() requires 2 arguments".into(),
                ));
            }
            Ok(format!("{} + {}", arg_sqls[0], arg_sqls[1]))
        }
        "epoch" | "to_epoch" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("epoch() requires 1 argument".into()))?;
            Ok(format!("toUnixTimestamp({})", arg))
        }
        "from_epoch" | "fromepoch" => {
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("from_epoch() requires 1 argument".into())
            })?;
            Ok(format!("fromUnixTimestamp({})", arg))
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
                    "dateDiff('second', {}, {})",
                    arg_sqls[1], arg_sqls[0]
                )),
                3 => Ok(format!(
                    "dateDiff({}, {}, {})",
                    arg_sqls[0], arg_sqls[1], arg_sqls[2]
                )),
                _ => Err(SqlGenError::InvalidQuery(
                    "date_diff() requires 2 or 3 arguments".into(),
                )),
            }
        }
        "date_trunc" | "datetrunc" => {
            // date_trunc(unit, timestamp) - truncate timestamp to unit
            // Map to ClickHouse toStartOf* functions based on unit
            if arg_sqls.len() != 2 {
                return Err(SqlGenError::InvalidQuery(
                    "date_trunc() requires 2 arguments (unit, timestamp)".into(),
                ));
            }
            // The unit is the first arg, clean it up (remove quotes if present)
            let unit = arg_sqls[0].trim_matches('\'').to_lowercase();
            let ts = &arg_sqls[1];
            match unit.as_str() {
                "second" => Ok(format!("toStartOfSecond({})", ts)),
                "minute" => Ok(format!("toStartOfMinute({})", ts)),
                "hour" => Ok(format!("toStartOfHour({})", ts)),
                "day" => Ok(format!("toStartOfDay({})", ts)),
                "week" => Ok(format!("toStartOfWeek({})", ts)),
                "month" => Ok(format!("toStartOfMonth({})", ts)),
                "quarter" => Ok(format!("toStartOfQuarter({})", ts)),
                "year" => Ok(format!("toStartOfYear({})", ts)),
                _ => Ok(format!(
                    "toStartOfInterval({}, INTERVAL 1 {})",
                    ts,
                    unit.to_uppercase()
                )),
            }
        }
        "date_part" | "datepart" => {
            // date_part(part, timestamp) - extract a calendar/clock component from a timestamp.
            // args[0] MUST be a string literal naming the part; dispatch it to the matching
            // ClickHouse to* function applied to the lowered timestamp expression (arg_sqls[1]).
            // ClickHouse `extract` is a REGEX function (see the "extract" arm below), so date_part
            // must NOT lower to extract(...) — doing so returned Code 43 on every part (NAN-1144).
            if args.len() != 2 {
                return Err(SqlGenError::InvalidQuery(
                    "date_part() requires 2 arguments (part, timestamp)".into(),
                ));
            }
            let part = match &args[0] {
                EvalExpression::Literal(Value::String(s)) => s.to_lowercase(),
                _ => {
                    return Err(SqlGenError::InvalidQuery(
                        "date_part() requires a string literal part name as the first argument \
                         (e.g. \"hour\", \"day\", \"month\")"
                            .into(),
                    ));
                }
            };
            let ts = &arg_sqls[1];
            match part.as_str() {
                "hour" => Ok(format!("toHour({})", ts)),
                "minute" => Ok(format!("toMinute({})", ts)),
                "second" => Ok(format!("toSecond({})", ts)),
                "day" => Ok(format!("toDayOfMonth({})", ts)),
                "month" => Ok(format!("toMonth({})", ts)),
                "year" => Ok(format!("toYear({})", ts)),
                "week" => Ok(format!("toISOWeek({})", ts)),
                "dayofweek" => Ok(format!("toDayOfWeek({})", ts)),
                "dayofyear" => Ok(format!("toDayOfYear({})", ts)),
                other => Err(SqlGenError::InvalidQuery(format!(
                    "date_part() unsupported part '{}' (supported: hour, minute, second, \
                     day, month, year, week, dayofweek, dayofyear)",
                    other
                ))),
            }
        }
        "extract" => {
            // ClickHouse-native regex extract: extract(haystack, pattern) returns the first
            // capture group. This is distinct from date_part (above) — the two were previously
            // aliased together, which broke date_part. Keep the regex form intact (NAN-1144).
            if arg_sqls.len() != 2 {
                return Err(SqlGenError::InvalidQuery(
                    "extract() requires 2 arguments (string, pattern)".into(),
                ));
            }
            Ok(format!("extract({}, {})", arg_sqls[0], arg_sqls[1]))
        }
        "year" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("year() requires 1 argument".into()))?;
            Ok(format!("toYear({})", arg))
        }
        "month" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("month() requires 1 argument".into()))?;
            Ok(format!("toMonth({})", arg))
        }
        "day" | "dayofmonth" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("day() requires 1 argument".into()))?;
            Ok(format!("toDayOfMonth({})", arg))
        }
        "hour" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("hour() requires 1 argument".into()))?;
            Ok(format!("toHour({})", arg))
        }
        "minute" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("minute() requires 1 argument".into()))?;
            Ok(format!("toMinute({})", arg))
        }
        "second" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("second() requires 1 argument".into()))?;
            Ok(format!("toSecond({})", arg))
        }
        "dayofweek" | "dow" => {
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("dayofweek() requires 1 argument".into())
            })?;
            Ok(format!("toDayOfWeek({})", arg))
        }
        "dayofyear" | "doy" => {
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("dayofyear() requires 1 argument".into())
            })?;
            Ok(format!("toDayOfYear({})", arg))
        }
        "week" | "weekofyear" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("week() requires 1 argument".into()))?;
            Ok(format!("toWeek({})", arg))
        }
        "quarter" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("quarter() requires 1 argument".into()))?;
            Ok(format!("toQuarter({})", arg))
        }
        "age" => {
            // age(timestamp1, timestamp2) - interval between timestamps
            match arg_sqls.len() {
                1 => Ok(format!("dateDiff('second', {}, now())", arg_sqls[0])),
                2 => Ok(format!(
                    "dateDiff('second', {}, {})",
                    arg_sqls[1], arg_sqls[0]
                )),
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
            Ok(format!("toTimeZone({}, {})", arg_sqls[1], arg_sqls[0]))
        }
        "to_timestamp" | "totimestamp" => match arg_sqls.len() {
            1 => Ok(format!("toDateTime({})", arg_sqls[0])),
            2 => Ok(format!("parseDateTime({}, {})", arg_sqls[0], arg_sqls[1])),
            _ => Err(SqlGenError::InvalidQuery(
                "to_timestamp() requires 1 or 2 arguments".into(),
            )),
        },
        "to_date" | "todate" => match arg_sqls.len() {
            1 => Ok(format!("toDate({})", arg_sqls[0])),
            2 => {
                // Honor the explicit format instead of dropping it (the old
                // parseDateTimeBestEffort ignored arg 1, silently misparsing ambiguous
                // dates — NAN-1144). args[1] must be a string literal so we can statically
                // translate strftime codes to ClickHouse codes via the shared helper.
                // Read the RAW literal from `args` (arg_sqls[1] is the already-quoted SQL form).
                let format_str = match &args[1] {
                    EvalExpression::Literal(Value::String(s)) => s,
                    _ => {
                        return Err(SqlGenError::InvalidQuery(
                            "to_date() format (2nd argument) must be a string literal".into(),
                        ))
                    }
                };
                let ch_format = convert_strftime_to_clickhouse(format_str);
                // Escape exactly as a SQL string literal (mirrors Literal(Value::String) lowering).
                let escaped_format = ch_format.replace('\\', "\\\\").replace('\'', "''");
                // parseDateTimeOrNull honors the explicit format and returns NULL on rows that
                // don't match (no whole-query failure); wrap in toDate so the 2-arg form returns
                // a Date like the 1-arg form. Result type is Nullable(Date).
                Ok(format!(
                    "toDate(parseDateTimeOrNull({}, '{}'))",
                    arg_sqls[0], escaped_format
                ))
            }
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
                "[toISOYear({}), toISOWeek({}), toDayOfWeek({})]",
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
            Ok(format!("least({})", arg_sqls.join(", ")))
        }
        "latest" => {
            // latest(timestamp1, timestamp2, ...) - return latest timestamp
            if arg_sqls.is_empty() {
                return Err(SqlGenError::InvalidQuery(
                    "latest() requires at least 1 argument".into(),
                ));
            }
            Ok(format!("greatest({})", arg_sqls.join(", ")))
        }
        "time_bucket" | "timebucket" => {
            // time_bucket(interval, timestamp) - bucket timestamp into intervals
            if arg_sqls.len() != 2 {
                return Err(SqlGenError::InvalidQuery(
                    "time_bucket() requires 2 arguments (interval, timestamp)".into(),
                ));
            }
            // Use toStartOfInterval for ClickHouse
            Ok(format!(
                "toStartOfInterval({}, {})",
                arg_sqls[1], arg_sqls[0]
            ))
        }
        "make_timestamp" | "maketimestamp" => {
            // make_timestamp(year, month, day, hour, minute, second)
            // Build via makeDateTime (numeric constructor) rather than
            // toDateTime(concat(...)): the concat form emits an unpadded string like
            // '2024-1-1 12:30:0' that toDateTime cannot parse (Code 6 CANNOT_PARSE_TEXT),
            // so every make_timestamp call errored. Mirrors make_time's coercion so both
            // numeric literals and string-typed field refs work; year needs a wider cast
            // (toUInt8OrNull caps at 255 and would null out 2024).
            if arg_sqls.len() != 6 {
                return Err(SqlGenError::InvalidQuery("make_timestamp() requires 6 arguments (year, month, day, hour, minute, second)".into()));
            }
            Ok(format!(
                "makeDateTime(toUInt16OrNull(toString({})), toUInt8OrNull(toString({})), \
                 toUInt8OrNull(toString({})), toUInt8OrNull(toString({})), \
                 toUInt8OrNull(toString({})), toUInt8OrNull(toString({})))",
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
                "toDate(concat({}, '-', {}, '-', {}))",
                arg_sqls[0], arg_sqls[1], arg_sqls[2]
            ))
        }
        "make_time" | "maketime" => {
            // make_time(hour, minute, second) -> a usable time-of-day value.
            // ClickHouse has no standalone time type and toTime(String) fails (Code 43 on
            // CH 26.4: toTimeWithFixedDate only accepts Date/DateTime — NAN-1144). Build a
            // DateTime on the epoch date carrying the requested HH:MM:SS via makeDateTime,
            // which is downstream-usable with toHour/toMinute/toSecond/formatDateTime.
            // Components are coerced with toUInt8OrNull(toString(...)) so both numeric literals
            // and string-typed field refs work (makeDateTime rejects String args), degrading
            // invalid input to NULL (Nullable(DateTime)) rather than erroring the whole query.
            if arg_sqls.len() != 3 {
                return Err(SqlGenError::InvalidQuery(
                    "make_time() requires 3 arguments (hour, minute, second)".into(),
                ));
            }
            Ok(format!(
                "makeDateTime(1970, 1, 1, toUInt8OrNull(toString({})), \
                 toUInt8OrNull(toString({})), toUInt8OrNull(toString({})))",
                arg_sqls[0], arg_sqls[1], arg_sqls[2]
            ))
        }
        "today" => Ok("today()".to_string()),
        "yesterday" => Ok("yesterday()".to_string()),
        "start_of_hour" | "startofhour" => {
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("start_of_hour() requires 1 argument".into())
            })?;
            Ok(format!("toStartOfHour({})", arg))
        }
        "start_of_day" | "startofday" => {
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("start_of_day() requires 1 argument".into())
            })?;
            Ok(format!("toStartOfDay({})", arg))
        }
        "start_of_week" | "startofweek" => {
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("start_of_week() requires 1 argument".into())
            })?;
            Ok(format!("toStartOfWeek({})", arg))
        }
        "start_of_month" | "startofmonth" => {
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("start_of_month() requires 1 argument".into())
            })?;
            Ok(format!("toStartOfMonth({})", arg))
        }
        "start_of_quarter" | "startofquarter" => {
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("start_of_quarter() requires 1 argument".into())
            })?;
            Ok(format!("toStartOfQuarter({})", arg))
        }
        "start_of_year" | "startofyear" => {
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("start_of_year() requires 1 argument".into())
            })?;
            Ok(format!("toStartOfYear({})", arg))
        }

        // ============================================================
        // Type Conversion Functions
        // ============================================================
        "tonumber" | "to_number" => {
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("tonumber() requires 1 argument".into())
            })?;
            // Convert to string first to handle all types (including UInt16, etc.)
            Ok(format!("toFloat64OrZero(toString({}))", arg))
        }
        "tostring" | "to_string" => {
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("tostring() requires 1 argument".into())
            })?;
            Ok(format!("toString({})", arg))
        }
        "toint" | "to_int" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("toint() requires 1 argument".into()))?;
            Ok(format!("toInt64OrZero({})", arg))
        }

        // ============================================================
        // Conditional Functions
        // ============================================================
        "if" | "iif" => {
            if arg_sqls.len() != 3 {
                return Err(SqlGenError::InvalidQuery(
                    "if() requires 3 arguments".into(),
                ));
            }
            Ok(format!(
                "if({}, {}, {})",
                arg_sqls[0], arg_sqls[1], arg_sqls[2]
            ))
        }
        "coalesce" | "nvl" => {
            if arg_sqls.is_empty() {
                return Err(SqlGenError::InvalidQuery(
                    "coalesce() requires at least 1 argument".into(),
                ));
            }
            Ok(format!("coalesce({})", arg_sqls.join(", ")))
        }
        "nullif" => {
            if arg_sqls.len() != 2 {
                return Err(SqlGenError::InvalidQuery(
                    "nullif() requires 2 arguments".into(),
                ));
            }
            Ok(format!("nullIf({}, {})", arg_sqls[0], arg_sqls[1]))
        }
        "isnull" | "is_null" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("isnull() requires 1 argument".into()))?;
            Ok(format!("isNull({})", arg))
        }
        "isnotnull" | "is_not_null" => {
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("isnotnull() requires 1 argument".into())
            })?;
            Ok(format!("isNotNull({})", arg))
        }
        "case" => {
            // case(condition1, value1, condition2, value2, ..., [default]) →
            // ClickHouse multiIf(cond1, val1, cond2, val2, ..., default)
            // multiIf requires odd number of args (pairs + default)
            if arg_sqls.is_empty() {
                return Err(SqlGenError::InvalidQuery(
                    "case() requires at least one argument".into(),
                ));
            }

            if arg_sqls.len() % 2 == 0 {
                // Even number: pairs without explicit default
                // Add NULL as default for ClickHouse multiIf
                let mut args = arg_sqls.clone();
                args.push("NULL".to_string());
                Ok(format!("multiIf({})", args.join(", ")))
            } else {
                // Odd number: pairs + explicit default
                Ok(format!("multiIf({})", arg_sqls.join(", ")))
            }
        }
        "null" => {
            // nPL null() -> ClickHouse NULL keyword
            Ok("NULL".to_string())
        }
        "true" => {
            // PPL true() -> ClickHouse 1 (or true)
            Ok("1".to_string())
        }
        "false" => {
            // PPL false() -> ClickHouse 0 (or false)
            Ok("0".to_string())
        }

        // ============================================================
        // Math Functions
        // ============================================================
        "abs" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("abs() requires 1 argument".into()))?;
            Ok(format!("abs({})", arg))
        }
        "ceil" | "ceiling" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("ceil() requires 1 argument".into()))?;
            Ok(format!("ceil({})", arg))
        }
        "floor" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("floor() requires 1 argument".into()))?;
            Ok(format!("floor({})", arg))
        }
        "round" => match arg_sqls.len() {
            1 => Ok(format!("round({})", arg_sqls[0])),
            2 => Ok(format!("round({}, {})", arg_sqls[0], arg_sqls[1])),
            _ => Err(SqlGenError::InvalidQuery(
                "round() requires 1 or 2 arguments".into(),
            )),
        },
        "log" | "ln" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("log() requires 1 argument".into()))?;
            Ok(format!("log({})", arg))
        }
        "log10" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("log10() requires 1 argument".into()))?;
            Ok(format!("log10({})", arg))
        }
        "pow" | "power" => {
            if arg_sqls.len() != 2 {
                return Err(SqlGenError::InvalidQuery(
                    "pow() requires 2 arguments".into(),
                ));
            }
            Ok(format!("pow({}, {})", arg_sqls[0], arg_sqls[1]))
        }
        "sqrt" => {
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("sqrt() requires 1 argument".into()))?;
            Ok(format!("sqrt({})", arg))
        }

        // ============================================================
        // Regex Functions
        // ============================================================
        "like" => {
            // like(field, pattern) → field LIKE pattern
            if arg_sqls.len() != 2 {
                return Err(SqlGenError::InvalidQuery(
                    "like() requires 2 arguments (string, pattern)".into(),
                ));
            }
            Ok(format!("({} LIKE {})", arg_sqls[0], arg_sqls[1]))
        }
        "match" | "regex_match" => {
            if arg_sqls.len() != 2 {
                return Err(SqlGenError::InvalidQuery(
                    "match() requires 2 arguments (string, pattern)".into(),
                ));
            }
            Ok(format!("match({}, {})", arg_sqls[0], arg_sqls[1]))
        }
        "regex_extract" | "extract_regex" => {
            // regex_extract(string, pattern) - returns first capture group
            // regex_extract(string, pattern, group_num) - returns specific capture group
            match arg_sqls.len() {
                    2 => Ok(format!("extract({}, {})", arg_sqls[0], arg_sqls[1])),
                    3 => {
                        // Use extractGroups to get all groups, then index into the array
                        // ClickHouse arrays are 1-indexed, and extractGroups returns [group1, group2, ...]
                        // So user's group 1 = array[1], group 2 = array[2], etc.
                        Ok(format!("extractGroups({}, {})[{}]", arg_sqls[0], arg_sqls[1], arg_sqls[2]))
                    }
                    _ => Err(SqlGenError::InvalidQuery("regex_extract() requires 2 or 3 arguments: regex_extract(string, pattern[, group_num])".into())),
                }
        }
        "regex_replace" => {
            if arg_sqls.len() != 3 {
                return Err(SqlGenError::InvalidQuery(
                    "regex_replace() requires 3 arguments".into(),
                ));
            }
            Ok(format!(
                "replaceRegexpOne({}, {}, {})",
                arg_sqls[0], arg_sqls[1], arg_sqls[2]
            ))
        }
        "regex_replace_all" => {
            if arg_sqls.len() != 3 {
                return Err(SqlGenError::InvalidQuery(
                    "regex_replace_all() requires 3 arguments".into(),
                ));
            }
            Ok(format!(
                "replaceRegexpAll({}, {}, {})",
                arg_sqls[0], arg_sqls[1], arg_sqls[2]
            ))
        }

        // ============================================================
        // String Similarity Functions (Phishing/Typosquatting Detection)
        // ============================================================
        "levenshtein" | "levenshtein_distance" | "edit_distance" => {
            // Edit distance between two strings - great for typosquatting detection
            if arg_sqls.len() != 2 {
                return Err(SqlGenError::InvalidQuery(
                    "levenshtein() requires 2 arguments".into(),
                ));
            }
            Ok(format!("editDistance({}, {})", arg_sqls[0], arg_sqls[1]))
        }
        "levenshtein_normalized" | "edit_distance_normalized" => {
            // Normalized edit distance (0-1 range) - easier to set thresholds
            if arg_sqls.len() != 2 {
                return Err(SqlGenError::InvalidQuery(
                    "levenshtein_normalized() requires 2 arguments".into(),
                ));
            }
            // Normalize by max length of the two strings
            Ok(format!(
                "(editDistance({}, {}) / greatest(length({}), length({}), 1))",
                arg_sqls[0], arg_sqls[1], arg_sqls[0], arg_sqls[1]
            ))
        }
        "ngram_distance" | "ngramdistance" => {
            // N-gram based distance (0-1, lower = more similar)
            if arg_sqls.len() != 2 {
                return Err(SqlGenError::InvalidQuery(
                    "ngram_distance() requires 2 arguments".into(),
                ));
            }
            Ok(format!("ngramDistance({}, {})", arg_sqls[0], arg_sqls[1]))
        }
        "ngram_search" | "ngramsearch" => {
            // N-gram search score (0-1, higher = needle found in haystack)
            if arg_sqls.len() != 2 {
                return Err(SqlGenError::InvalidQuery(
                    "ngram_search() requires 2 arguments (haystack, needle)".into(),
                ));
            }
            Ok(format!("ngramSearch({}, {})", arg_sqls[0], arg_sqls[1]))
        }
        "trigram_distance" | "trigramdistance" => {
            // Trigram (3-gram) distance - common for fuzzy matching
            if arg_sqls.len() != 2 {
                return Err(SqlGenError::InvalidQuery(
                    "trigram_distance() requires 2 arguments".into(),
                ));
            }
            Ok(format!("ngramDistance({}, {})", arg_sqls[0], arg_sqls[1]))
        }

        // ============================================================
        // Domain Analysis Functions (Threat Hunting)
        // ============================================================
        "extract_root_domain" | "extractrootdomain" | "registered_domain" => {
            // Extract registered domain (eTLD+1): www.mail.google.com -> google.com
            // Handles complex TLDs like .co.uk, .com.au properly
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("extract_root_domain() requires 1 argument".into())
            })?;
            Ok(format!("cutToFirstSignificantSubdomain({})", arg))
        }
        "extract_subdomain" | "extractsubdomain" | "first_subdomain" => {
            // Extract the first significant subdomain: www.mail.google.com -> mail
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("extract_subdomain() requires 1 argument".into())
            })?;
            Ok(format!("firstSignificantSubdomain({})", arg))
        }
        "domain_depth" | "subdomain_count" => {
            // Count subdomain levels: www.mail.google.com -> 4
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("domain_depth() requires 1 argument".into())
            })?;
            Ok(format!(
                "length(splitByChar('.', domainWithoutWWW({})))",
                arg
            ))
        }

        // ============================================================
        // Array/Aggregation Functions (for eval context)
        // ============================================================
        "array_length" | "arraylength" => {
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("array_length() requires 1 argument".into())
            })?;
            Ok(format!("length({})", arg))
        }
        "array_join" | "arrayjoin" => {
            // Join array elements into string
            if arg_sqls.len() < 1 {
                return Err(SqlGenError::InvalidQuery(
                    "array_join() requires at least 1 argument".into(),
                ));
            }
            if arg_sqls.len() == 1 {
                Ok(format!("arrayStringConcat({}, ',')", arg_sqls[0]))
            } else {
                Ok(format!(
                    "arrayStringConcat({}, {})",
                    arg_sqls[0], arg_sqls[1]
                ))
            }
        }
        "array_contains" | "arraycontains" | "has" => {
            // Check if array/string contains element
            // ClickHouse `has()` only works on Array types, but many fields (e.g. ioc_tags)
            // are stored as comma-separated strings in ext JSON. Use positionCaseInsensitive()
            // which works on any string type and returns non-zero (truthy) if found.
            if arg_sqls.len() != 2 {
                return Err(SqlGenError::InvalidQuery(
                    "array_contains() requires 2 arguments (array, element)".into(),
                ));
            }
            Ok(format!("positionCaseInsensitive(toString({}), {})", arg_sqls[0], arg_sqls[1]))
        }

        // ============================================================
        // Multivalue Functions
        // ============================================================
        "mvjoin" => {
            // Join multivalue field with separator: mvjoin(field, sep) → arrayStringConcat(field, sep)
            if arg_sqls.len() != 2 {
                return Err(SqlGenError::InvalidQuery(
                    "mvjoin() requires 2 arguments (field, separator)".into(),
                ));
            }
            Ok(format!(
                "arrayStringConcat({}, {})",
                arg_sqls[0], arg_sqls[1]
            ))
        }
        "mvfind" => {
            // Find index of first match in multivalue: mvfind(field, pattern) →
            // indexOf(arrayMap(x -> match(x, pattern), field), 1) — 1-based position of
            // the first matching element, 0 if none.
            // Must be arrayMap, not arrayFilter: arrayFilter returns the matching String
            // elements, so indexOf(<String array>, 1) compares String vs the integer 1 →
            // Code 386 NO_COMMON_TYPE and the whole query errored. arrayMap yields a 0/1
            // UInt8 array whose first `1` is exactly the first-match position.
            if arg_sqls.len() != 2 {
                return Err(SqlGenError::InvalidQuery(
                    "mvfind() requires 2 arguments (field, pattern)".into(),
                ));
            }
            Ok(format!(
                "indexOf(arrayMap(x -> match(x, {}), {}), 1)",
                arg_sqls[1], arg_sqls[0]
            ))
        }
        "mvcount" => {
            // Count elements in multivalue field: mvcount(field) → length(field)
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("mvcount() requires 1 argument".into()))?;
            Ok(format!("length({})", arg))
        }
        "mvindex" => {
            // Get element at index from multivalue field: mvindex(field, idx) → field[idx+1] (ClickHouse is 1-based)
            if arg_sqls.len() != 2 {
                return Err(SqlGenError::InvalidQuery(
                    "mvindex() requires 2 arguments (field, index)".into(),
                ));
            }
            Ok(format!("{}[{} + 1]", arg_sqls[0], arg_sqls[1]))
        }
        "mvfilter" => {
            // mvfilter(predicate) cannot be correctly lowered at this layer. Splunk evaluates
            // `predicate` per-element of the multivalue field referenced inside it; that is an
            // arrayFilter lambda whose variable is bound INSIDE the predicate
            // (e.g. arrayFilter(x -> match(x, '^-'), parts)). But by the time we reach this arm
            // the predicate has been lowered to scalar SQL with the source field baked in as a
            // bare column, so we can recover neither the source array nor the per-element binding.
            // The old emission `arrayFilter(x -> <pred>, x)` left the source array `x` unbound and
            // crashed at runtime with Code 47 (UNKNOWN_IDENTIFIER) — i.e. it generated Ok but the
            // query always failed in ClickHouse (NAN-1144). Reject up front with an actionable
            // message instead of emitting broken SQL. (Arity is validated first to preserve the
            // historical single-argument contract.)
            let _pred = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("mvfilter() requires 1 argument".into())
            })?;
            Err(SqlGenError::InvalidQuery(
                "mvfilter() is not supported: a multivalue predicate cannot be translated to \
                 ClickHouse at this layer because the source array and the per-element binding \
                 cannot be recovered from the lowered predicate. Rewrite it as an explicit array \
                 filter (e.g. arrayFilter/arrayExists over a split() field) or filter with \
                 `where match(field, \"...\")` instead."
                    .into(),
            ))
        }
        "mvdedup" => {
            // Deduplicate multivalue field: mvdedup(field) → arrayDistinct(field)
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("mvdedup() requires 1 argument".into()))?;
            Ok(format!("arrayDistinct({})", arg))
        }
        "mvsort" => {
            // Sort multivalue field: mvsort(field) → arraySort(field)
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("mvsort() requires 1 argument".into()))?;
            Ok(format!("arraySort({})", arg))
        }
        "mvappend" => {
            // Append values to multivalue: mvappend(val1, val2, ...) → array(val1, val2, ...)
            if arg_sqls.is_empty() {
                return Err(SqlGenError::InvalidQuery(
                    "mvappend() requires at least 1 argument".into(),
                ));
            }
            Ok(format!("array({})", arg_sqls.join(", ")))
        }
        "mvzip" => {
            // Zip two multivalue fields: mvzip(mv1, mv2, delim) → arrayMap((x,y) -> concat(x,delim,y), mv1, mv2)
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
                "arrayMap((x, y) -> concat(toString(x), {}, toString(y)), {}, {})",
                delim, arg_sqls[0], arg_sqls[1]
            ))
        }
        "mvrange" => {
            // Generate numeric range: mvrange(start, end, step) → range(start, end, step)
            if arg_sqls.len() < 2 {
                return Err(SqlGenError::InvalidQuery(
                    "mvrange() requires at least 2 arguments (start, end)".into(),
                ));
            }
            if arg_sqls.len() == 2 {
                Ok(format!("range({}, {})", arg_sqls[0], arg_sqls[1]))
            } else {
                Ok(format!(
                    "range({}, {}, {})",
                    arg_sqls[0], arg_sqls[1], arg_sqls[2]
                ))
            }
        }
        "exact" => {
            // Pass through — exact() is a hint for case-sensitive comparison;
            // ClickHouse already does that for `=`, so the function is a no-op.
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("exact() requires 1 argument".into()))?;
            Ok(arg.clone())
        }
        "ip_version" => {
            // Detect IP version: ip_version(ip) → if(isIPv4String(ip), 4, if(isIPv6String(ip), 6, 0))
            let arg = arg_sqls.first().ok_or_else(|| {
                SqlGenError::InvalidQuery("ip_version() requires 1 argument".into())
            })?;
            Ok(format!(
                "if(isIPv4String(toString({})), 4, if(isIPv6String(toString({})), 6, 0))",
                arg, arg
            ))
        }
        "tolong" => {
            // Convert to integer: tolong(x) → toInt64OrNull(x)
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("tolong() requires 1 argument".into()))?;
            Ok(format!("toInt64OrNull(toString({}))", arg))
        }
        "typeof" | "type" => {
            // Get type name: typeof(x) → toTypeName(x)
            let arg = arg_sqls
                .first()
                .ok_or_else(|| SqlGenError::InvalidQuery("typeof() requires 1 argument".into()))?;
            Ok(format!("toTypeName({})", arg))
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
