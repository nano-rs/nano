// SPDX-License-Identifier: AGPL-3.0-or-later

//! Parse error types and utilities

/// Parse error with rich context and suggestions
#[derive(Debug, Clone)]
pub struct ParseError {
    /// The error message
    pub message: String,
    /// Position in the query string
    pub position: usize,
    /// Line number (1-indexed)
    pub line: usize,
    /// Column number (1-indexed)  
    pub column: usize,
    /// The problematic token text
    pub token: Option<String>,
    /// What came before (for context)
    pub context_before: Option<String>,
    /// What was expected
    pub expected: Vec<String>,
    /// Suggested fixes
    pub suggestions: Vec<ErrorSuggestion>,
    /// The full query for display
    pub full_query: Option<String>,
}

/// A suggested fix for a parse error
#[derive(Debug, Clone)]
pub struct ErrorSuggestion {
    /// Description of the fix
    pub description: String,
    /// The corrected query snippet
    pub replacement: String,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Main error line
        writeln!(f, "Syntax error: {}", self.message)?;
        writeln!(f)?;

        // Show the query with pointer
        if let Some(ref query) = self.full_query {
            writeln!(f, "  {}", query)?;
            let pointer_pos = self.column.saturating_sub(1);
            let pointer_len = self.token.as_ref().map(|t| t.len()).unwrap_or(1);
            writeln!(
                f,
                "  {}{}",
                " ".repeat(pointer_pos),
                "^".repeat(pointer_len)
            )?;
        }

        // Expected tokens
        if !self.expected.is_empty() {
            writeln!(f)?;
            writeln!(f, "Expected: {}", self.expected.join(", "))?;
        }

        // Suggestions
        if !self.suggestions.is_empty() {
            writeln!(f)?;
            writeln!(f, "Did you mean:")?;
            for suggestion in &self.suggestions {
                writeln!(
                    f,
                    "  • {}  ({})",
                    suggestion.replacement, suggestion.description
                )?;
            }
        }

        Ok(())
    }
}

impl std::error::Error for ParseError {}

/// Convert nom error to our ParseError with position info and enhanced context
pub(crate) fn convert_error(input: &str, error: nom::error::Error<&str>) -> ParseError {
    // C3: Check for max nesting depth exceeded
    if error.code == nom::error::ErrorKind::TooLarge {
        return ParseError {
            message: "Expression nesting depth exceeded (maximum 50 levels). Simplify your query."
                .to_string(),
            position: 0,
            line: 1,
            column: 1,
            token: None,
            context_before: None,
            expected: vec![],
            suggestions: vec![],
            full_query: Some(input.to_string()),
        };
    }

    let position = input.len() - error.input.len();
    let (line, column) = calculate_position(input, position);

    // Extract the problematic token
    let token = extract_token_at_position(input, position);

    // Get context before the error
    let context_before = extract_context_before(input, position);

    // Generate enhanced error message and suggestions
    let (message, expected, suggestions) =
        analyze_error_context(input, position, &token, &context_before);

    ParseError {
        message,
        position,
        line,
        column,
        token,
        context_before,
        expected,
        suggestions,
        full_query: Some(input.to_string()),
    }
}

/// Extract the token at the error position
fn extract_token_at_position(input: &str, position: usize) -> Option<String> {
    if position >= input.len() {
        return None;
    }

    let remaining = &input[position..];
    let mut chars = remaining.chars();

    // Skip whitespace
    let mut start_offset = 0;
    while let Some(c) = chars.next() {
        if !c.is_whitespace() {
            break;
        }
        start_offset += c.len_utf8();
    }

    if start_offset >= remaining.len() {
        return None;
    }

    let token_start = &remaining[start_offset..];

    // Extract token (alphanumeric, underscore, or special chars)
    let token_end = token_start
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '-' || *c == '.' || *c == '/')
        .map(|c| c.len_utf8())
        .sum::<usize>();

    if token_end > 0 {
        Some(token_start[..token_end].to_string())
    } else {
        // Single character token
        token_start.chars().next().map(|c| c.to_string())
    }
}

/// Extract context before the error position
fn extract_context_before(input: &str, position: usize) -> Option<String> {
    if position == 0 {
        return None;
    }

    let before = &input[..position];

    // Find the last command or significant token
    let words: Vec<&str> = before.split_whitespace().collect();
    if words.len() >= 2 {
        Some(format!(
            "{} {}",
            words[words.len() - 2],
            words[words.len() - 1]
        ))
    } else if words.len() == 1 {
        Some(words[0].to_string())
    } else {
        None
    }
}

/// NAN-2241: detect the `\"`-inside-a-double-quoted-string trap and explain it.
///
/// `values::double_quoted_string` is `take_while(|c| c != '"')` — the FIRST `"`
/// always terminates and a preceding backslash is an ordinary character. That
/// is deliberate (NAN-1157) so Windows paths like `"C:\Windows\System32\"`
/// parse. The cost is that a regex author reaching for the familiar
/// `"\"name\":\"app_name\""` gets a literal that ends after the backslash, with
/// the rest of the pattern re-tokenized as query syntax — and, before this,
/// an error message that named a symptom miles from the cause.
///
/// Returns `Some((message, suggestions))` only when the parse died IMMEDIATELY
/// after a `\"`-terminated literal AND more `"` remain further along. Both
/// conditions are needed: a query that merely CONTAINS `\"` may be a perfectly
/// valid trailing-backslash path (`file_path="C:\Windows\"`) that failed later
/// for an unrelated reason, and must not be mislabelled.
fn escaped_double_quote_diagnostic(
    input: &str,
    position: usize,
) -> Option<(String, Vec<ErrorSuggestion>)> {
    let consumed = input.get(..position)?;
    if !consumed.trim_end().ends_with("\\\"") || !input.get(position..)?.contains('"') {
        return None;
    }

    let message = "`\\\"` is not an escape sequence in nPL: a double-quoted string ends at the \
                   FIRST `\"`, so everything after it is read as query syntax (NAN-1157 — this \
                   is what lets Windows paths like \"C:\\Windows\\System32\\\" parse). Use a \
                   SINGLE-quoted string for a pattern containing double quotes; `\"` is an \
                   ordinary character inside `'…'`."
        .to_string();

    let mut suggestions = Vec::new();

    // Reconstruct what the author meant: the span from the `"` that opened the
    // literal to the last `"` in the query, with `\"` unescaped and the whole
    // thing re-quoted with `'`.
    let escape_at = consumed.rfind("\\\"");
    if let (Some(escape_at), Some(close)) = (escape_at, input.rfind('"')) {
        if let Some(open) = consumed.get(..escape_at).and_then(|s| s.rfind('"')) {
            if close > open + 1 {
                let inner = input[open + 1..close].replace("\\\"", "\"");
                if !inner.contains('\'') {
                    suggestions.push(ErrorSuggestion {
                        description: "single-quote the pattern so its double quotes stay literal"
                            .to_string(),
                        replacement: format!("'{}'", inner),
                    });
                }
            }
        }
    }

    if suggestions.is_empty() {
        suggestions.push(ErrorSuggestion {
            description: "single-quote patterns that contain double quotes".to_string(),
            replacement: r#"rex field=message '"key":"(?<value>[^"]+)"'"#.to_string(),
        });
    }

    Some((message, suggestions))
}

/// Analyze error context and generate helpful messages and suggestions
fn analyze_error_context(
    input: &str,
    position: usize,
    token: &Option<String>,
    context_before: &Option<String>,
) -> (String, Vec<String>, Vec<ErrorSuggestion>) {
    let mut expected = Vec::new();
    let mut suggestions = Vec::new();

    // NAN-2241: name the `\"` trap before any generic guess. It reads like an
    // escape but isn't one, so the generic analyzers below produce actively
    // misleading advice (the canonical `rex field=message "\"name\":\"app\""`
    // came back as "Unknown command 'name'. Did you mean 'rename'?").
    if let Some((message, escape_suggestions)) = escaped_double_quote_diagnostic(input, position) {
        return (
            message,
            vec!["a single-quoted string: '…'".to_string()],
            escape_suggestions,
        );
    }

    // Default message
    let mut message = if position >= input.len() {
        "Unexpected end of query".to_string()
    } else {
        format!(
            "Unexpected token{}",
            token
                .as_ref()
                .map(|t| format!(" '{}'", t))
                .unwrap_or_default()
        )
    };

    // Analyze based on context
    if let Some(ref context) = context_before {
        if let Some(ref tok) = token {
            // Check for common patterns
            if context.ends_with("head") || context.ends_with("tail") {
                if !tok.chars().all(|c| c.is_ascii_digit()) {
                    message = format!(
                        "Expected number after '{}', got '{}'",
                        context.split_whitespace().last().unwrap_or("command"),
                        tok
                    );
                    expected.push("number".to_string());

                    // Suggest if it looks like a search term
                    if looks_like_search_term(tok) {
                        suggestions.push(ErrorSuggestion {
                            description: format!("filter for events containing '{}'", tok),
                            replacement: format!("| search {}", tok),
                        });
                    }
                }
            } else if context.contains("head") && context.contains("10") {
                // Pattern: "head 10 foobar" - trailing token after complete command
                message = format!("Unexpected '{}' after '{}'", tok, context);
                expected.push("end of query".to_string());
                expected.push("pipe (|) followed by a command".to_string());

                suggestions.extend(generate_trailing_token_suggestions(tok));
            } else if looks_like_typo_command(tok) {
                if let Some(similar) = find_similar_command(tok) {
                    message = format!("Unknown command '{}'. Did you mean '{}'?", tok, similar);
                    suggestions.push(ErrorSuggestion {
                        description: format!("use the '{}' command", similar),
                        replacement: format!("| {}", similar),
                    });
                }
            }
        }
    }

    // Check for colon in keyword position — common mistake
    if let Some(ref tok) = token {
        let colon_at_position = position < input.len() && input.as_bytes()[position] == b':';
        if tok == ":" || colon_at_position {
            // Reconstruct what the user likely typed: word before colon + colon + word after
            let before = &input[..position];
            let word_before = before.split_whitespace().last().unwrap_or("");
            let after = if position < input.len() {
                &input[position..]
            } else {
                ":"
            };
            // Grab ":" plus the next token
            let colon_and_rest: String = after
                .chars()
                .take_while(|c| !c.is_whitespace() && *c != '|' && *c != ')' && *c != '(')
                .collect();
            let full_token = format!("{}{}", word_before, colon_and_rest);

            message = format!(
                "Colons are not allowed in keyword searches (found '{}')",
                full_token
            );
            expected.clear();
            suggestions.clear();
            suggestions.push(ErrorSuggestion {
                description: "wrap in quotes to search for the literal value".to_string(),
                replacement: format!("\"{}\"", full_token),
            });
            if !word_before.is_empty() && colon_and_rest.len() > 1 {
                let value_after = &colon_and_rest[1..]; // skip the ':'
                suggestions.push(ErrorSuggestion {
                    description: format!("use = for field comparison"),
                    replacement: format!("{}=\"{}\"", word_before, value_after),
                });
            }
            return (message, expected, suggestions);
        }
    }

    // Check for specific error patterns
    if let Some(ref tok) = token {
        // Check for missing quotes around strings with spaces
        if tok.contains(' ') && !input[..position].ends_with('"') {
            suggestions.push(ErrorSuggestion {
                description: "wrap in quotes for literal match".to_string(),
                replacement: format!("\"{}\"", tok),
            });
        }

        // Check for common typos
        if let Some(similar) = find_similar_command(tok) {
            suggestions.push(ErrorSuggestion {
                description: format!("did you mean the '{}' command?", similar),
                replacement: format!("| {}", similar),
            });
        }
    }

    (message, expected, suggestions)
}

/// Generate suggestions for trailing tokens after complete commands
fn generate_trailing_token_suggestions(token: &str) -> Vec<ErrorSuggestion> {
    let mut suggestions = Vec::new();

    if looks_like_search_term(token) {
        suggestions.push(ErrorSuggestion {
            description: format!("filter for events containing '{}'", token),
            replacement: format!("| search {}", token),
        });

        suggestions.push(ErrorSuggestion {
            description: "filter by specific field".to_string(),
            replacement: format!("| where field = \"{}\"", token),
        });
    }

    suggestions
}

/// Check if a token looks like a search term
fn looks_like_search_term(token: &str) -> bool {
    // Simple heuristic: alphanumeric with possible underscores/dashes
    token
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.')
        && token.len() > 1
        && !token.chars().all(|c| c.is_ascii_digit())
}

/// Check if a token looks like a typo of a command
fn looks_like_typo_command(token: &str) -> bool {
    find_similar_command(token).is_some()
}

/// Find similar command using Levenshtein distance
pub fn find_similar_command(input: &str) -> Option<&'static str> {
    const COMMANDS: &[&str] = &[
        "stats",
        "table",
        "head",
        "tail",
        "sort",
        "dedup",
        "where",
        "eval",
        "search",
        "rex",
        "rename",
        "fields",
        "top",
        "rare",
        "timechart",
        "transaction",
        "lookup",
        "join",
        "append",
        "bin",
        "fillnull",
        "mvexpand",
        "spath",
        "format",
        "return",
        "risk",
        "prevalence",
        "output",
    ];

    let input_lower = input.to_lowercase();
    let mut best_match = None;
    let mut best_distance = usize::MAX;

    for cmd in COMMANDS {
        let distance = levenshtein(&input_lower, cmd);
        // Only suggest if distance is small and reasonable compared to word length
        if distance <= 2 && distance < cmd.len() / 2 && distance < best_distance {
            best_match = Some(*cmd);
            best_distance = distance;
        }
    }

    best_match
}

/// Calculate Levenshtein distance between two strings
fn levenshtein(a: &str, b: &str) -> usize {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    let a_len = a_chars.len();
    let b_len = b_chars.len();

    if a_len == 0 {
        return b_len;
    }
    if b_len == 0 {
        return a_len;
    }

    let mut matrix = vec![vec![0; b_len + 1]; a_len + 1];

    // Initialize first row and column
    for i in 0..=a_len {
        matrix[i][0] = i;
    }
    for j in 0..=b_len {
        matrix[0][j] = j;
    }

    // Fill the matrix
    for i in 1..=a_len {
        for j in 1..=b_len {
            let cost = if a_chars[i - 1] == b_chars[j - 1] {
                0
            } else {
                1
            };
            matrix[i][j] = std::cmp::min(
                std::cmp::min(
                    matrix[i - 1][j] + 1, // deletion
                    matrix[i][j - 1] + 1, // insertion
                ),
                matrix[i - 1][j - 1] + cost, // substitution
            );
        }
    }

    matrix[a_len][b_len]
}

/// Calculate line and column from byte position
pub(crate) fn calculate_position(input: &str, position: usize) -> (usize, usize) {
    let prefix = &input[..position.min(input.len())];
    let line = prefix.matches('\n').count() + 1;
    let column = prefix
        .rfind('\n')
        .map(|i| position - i)
        .unwrap_or(position + 1);
    (line, column)
}
