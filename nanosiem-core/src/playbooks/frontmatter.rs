// SPDX-License-Identifier: AGPL-3.0-or-later

//! YAML frontmatter splitter + parser for playbook markdown.
//!
//! Playbook files may optionally lead with a `---`-delimited YAML frontmatter
//! block. Example:
//!
//! ```text
//! ---
//! title: Credential reuse
//! category: identity
//! match_signals:
//!   - offboarded
//!   - iam.credential_reuse
//! ---
//! # Credential reuse
//! ...
//! ```
//!
//! `split_frontmatter` returns the parsed frontmatter (if any) and the remainder
//! of the doc (the body the parser works on).

use super::error::PlaybookError;
use super::models::PlaybookFrontmatter;

/// Split `---\n...\n---\n` YAML frontmatter from the body. Returns
/// `(Some(parsed), body)` on success, or `(None, original)` if there's no
/// frontmatter fence at the start of the file.
///
/// If a frontmatter fence is present but YAML parsing fails, returns a
/// `PlaybookError::Frontmatter`.
pub fn split_frontmatter(src: &str) -> Result<(Option<PlaybookFrontmatter>, &str), PlaybookError> {
    // Strip optional BOM / leading whitespace lines then check for opening fence.
    let trimmed = src.trim_start_matches('\u{feff}');
    let rest = trimmed;

    // Must start with exactly `---` on its own line.
    if !rest.starts_with("---") {
        return Ok((None, src));
    }

    // Find the next `---` line after the first one.
    let after_first = &rest[3..];
    // Require newline after the opening fence.
    let body_start = match after_first.find('\n') {
        Some(idx) => idx + 1,
        None => return Ok((None, src)),
    };
    let yaml_and_rest = &after_first[body_start..];

    // Find the closing `---` line (must be at start of line).
    let closing_idx = find_closing_fence(yaml_and_rest);
    let Some((close_start, close_end)) = closing_idx else {
        return Ok((None, src));
    };

    let yaml_text = &yaml_and_rest[..close_start];
    let body = &yaml_and_rest[close_end..];

    // Parse YAML
    let fm: PlaybookFrontmatter = serde_yaml::from_str(yaml_text)
        .map_err(|e| PlaybookError::Frontmatter(e.to_string()))?;

    Ok((Some(fm), body))
}

/// Find the closing `---\n` fence in the remaining text. Returns `(start, end)`
/// byte offsets, where `start` is the offset of the `-` in `---`, and `end` is
/// the offset just past the newline after the closing fence.
fn find_closing_fence(text: &str) -> Option<(usize, usize)> {
    let mut offset = 0usize;
    for line in text.split_inclusive('\n') {
        let line_no_newline = line.trim_end_matches('\n').trim_end_matches('\r');
        if line_no_newline == "---" || line_no_newline == "..." {
            return Some((offset, offset + line.len()));
        }
        offset += line.len();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_simple_frontmatter() {
        let src = r#"---
title: Credential reuse
category: identity
match_signals:
  - offboarded
  - iam.credential_reuse
---
# Credential reuse

body goes here
"#;
        let (fm, body) = split_frontmatter(src).unwrap();
        let fm = fm.expect("frontmatter parsed");
        assert_eq!(fm.title.as_deref(), Some("Credential reuse"));
        assert_eq!(fm.category.as_deref(), Some("identity"));
        assert_eq!(fm.match_signals.len(), 2);
        assert!(body.starts_with("# Credential reuse"));
    }

    #[test]
    fn returns_none_when_no_frontmatter() {
        let src = "# no frontmatter here\n\nbody\n";
        let (fm, body) = split_frontmatter(src).unwrap();
        assert!(fm.is_none());
        assert_eq!(body, src);
    }

    #[test]
    fn rejects_malformed_yaml() {
        let src = "---\nthis is not: yaml: valid\n---\nbody\n";
        let err = split_frontmatter(src).err().expect("should error");
        assert!(matches!(err, PlaybookError::Frontmatter(_)));
    }

    #[test]
    fn parses_danger_policy_map() {
        let src = r#"---
title: Example
danger_policy:
  "action:high": approval
  "action:medium": auto
---
body
"#;
        let (fm, _) = split_frontmatter(src).unwrap();
        let fm = fm.unwrap();
        assert_eq!(
            fm.danger_policy.get("action:high").map(String::as_str),
            Some("approval")
        );
        assert_eq!(
            fm.danger_policy.get("action:medium").map(String::as_str),
            Some("auto")
        );
    }

    #[test]
    fn parses_authored_date() {
        let src = r#"---
title: Example
authored: 2025-11-14
---
body
"#;
        let (fm, _) = split_frontmatter(src).unwrap();
        let fm = fm.unwrap();
        let d = fm.authored.expect("date parsed");
        assert_eq!(d.to_string(), "2025-11-14");
    }
}
