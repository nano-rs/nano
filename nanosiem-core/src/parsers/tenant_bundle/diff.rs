// SPDX-License-Identifier: AGPL-3.0-or-later

//! A small, dependency-free unified diff between two bundle trees.
//!
//! Bundle files are a few hundred lines each, so a plain LCS table is fine;
//! files over [`MAX_LINES`] (or non-UTF-8) are reported by digest only.

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

use super::archive::BundleTree;

const MAX_LINES: usize = 4000;
const CONTEXT: usize = 3;

/// Paths whose bytes differ between `a` and `b` (added, removed or changed).
pub fn changed_paths(a: &BundleTree, b: &BundleTree) -> Vec<String> {
    let paths: BTreeSet<&String> = a.files.keys().chain(b.files.keys()).collect();
    paths
        .into_iter()
        .filter(|path| a.files.get(*path) != b.files.get(*path))
        .cloned()
        .collect()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Op {
    Keep,
    Del,
    Add,
}

fn edit_script(a: &[&str], b: &[&str]) -> Vec<(Op, usize, usize)> {
    let (n, m) = (a.len(), b.len());
    let mut lcs = vec![vec![0u32; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[i][j] = if a[i] == b[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }
    let (mut i, mut j) = (0, 0);
    let mut ops = Vec::new();
    while i < n || j < m {
        if i < n && j < m && a[i] == b[j] {
            ops.push((Op::Keep, i, j));
            i += 1;
            j += 1;
        } else if i < n && (j == m || lcs[i + 1][j] >= lcs[i][j + 1]) {
            // Deletions before insertions, as `diff -u` prints them.
            ops.push((Op::Del, i, j));
            i += 1;
        } else {
            ops.push((Op::Add, i, j));
            j += 1;
        }
    }
    ops
}

fn file_diff(path: &str, a: Option<&[u8]>, b: Option<&[u8]>) -> String {
    let (old, new) = (
        a.map(|_| format!("a/{path}"))
            .unwrap_or_else(|| "/dev/null".into()),
        b.map(|_| format!("b/{path}"))
            .unwrap_or_else(|| "/dev/null".into()),
    );
    let mut out = format!("--- {old}\n+++ {new}\n");
    let (Ok(a_text), Ok(b_text)) = (
        a.map(std::str::from_utf8).transpose(),
        b.map(std::str::from_utf8).transpose(),
    ) else {
        out.push_str("binary files differ\n");
        return out;
    };
    let a_lines: Vec<&str> = a_text.map(|t| t.lines().collect()).unwrap_or_default();
    let b_lines: Vec<&str> = b_text.map(|t| t.lines().collect()).unwrap_or_default();
    if a_lines.len() > MAX_LINES || b_lines.len() > MAX_LINES {
        let digest = |d: Option<&[u8]>| {
            d.map(|d| hex::encode(Sha256::digest(d)))
                .unwrap_or_default()
        };
        out.push_str(&format!(
            "file too large to diff: sha256 {} -> {}\n",
            digest(a),
            digest(b)
        ));
        return out;
    }
    let ops = edit_script(&a_lines, &b_lines);
    let changed: Vec<usize> = ops
        .iter()
        .enumerate()
        .filter(|(_, (op, _, _))| *op != Op::Keep)
        .map(|(index, _)| index)
        .collect();
    let mut index = 0;
    while index < changed.len() {
        let start = changed[index].saturating_sub(CONTEXT);
        let mut end = changed[index];
        while index < changed.len() && changed[index] <= end + 2 * CONTEXT {
            end = changed[index];
            index += 1;
        }
        let end = (end + CONTEXT).min(ops.len() - 1);
        let hunk = &ops[start..=end];
        let a_start = hunk[0].1;
        let b_start = hunk[0].2;
        let a_count = hunk.iter().filter(|(op, _, _)| *op != Op::Add).count();
        let b_count = hunk.iter().filter(|(op, _, _)| *op != Op::Del).count();
        out.push_str(&format!(
            "@@ -{},{} +{},{} @@\n",
            if a_count == 0 { a_start } else { a_start + 1 },
            a_count,
            if b_count == 0 { b_start } else { b_start + 1 },
            b_count
        ));
        for (op, i, j) in hunk {
            match op {
                Op::Keep => out.push_str(&format!(" {}\n", a_lines[*i])),
                Op::Del => out.push_str(&format!("-{}\n", a_lines[*i])),
                Op::Add => out.push_str(&format!("+{}\n", b_lines[*j])),
            }
        }
    }
    out
}

/// Unified diff `a → b` over every changed path, truncated to `limit` bytes.
/// Returns the text and whether it was truncated.
pub fn unified(a: &BundleTree, b: &BundleTree, limit: usize) -> (String, bool) {
    let mut out = String::new();
    for path in changed_paths(a, b) {
        let chunk = file_diff(&path, a.file(&path), b.file(&path));
        if out.len() + chunk.len() > limit {
            out.push_str("… diff truncated; compare the bundles by digest\n");
            return (out, true);
        }
        out.push_str(&chunk);
    }
    (out, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(files: &[(&str, &str)]) -> BundleTree {
        let mut t = BundleTree::default();
        for (p, d) in files {
            t.put(p, d.as_bytes().to_vec());
        }
        t
    }

    #[test]
    fn unified_diff_shows_changed_lines_with_context() {
        let a = tree(&[("x.toml", "a\nb\nc\nd\n"), ("same", "1\n")]);
        let b = tree(&[("x.toml", "a\nB\nc\nd\n"), ("same", "1\n"), ("new", "n\n")]);
        let (diff, truncated) = unified(&a, &b, 1 << 20);
        assert!(!truncated);
        assert!(
            diff.contains("--- a/x.toml\n+++ b/x.toml\n@@ -1,4 +1,4 @@\n a\n-b\n+B\n c\n d\n"),
            "{diff}"
        );
        assert!(
            diff.contains("--- /dev/null\n+++ b/new\n@@ -0,0 +1,1 @@\n+n\n"),
            "{diff}"
        );
        assert!(!diff.contains("same"));
    }
}
