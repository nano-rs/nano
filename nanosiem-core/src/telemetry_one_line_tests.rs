// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5432: plaintext logs keep one event per line.

use std::io::Write;

use super::{escape_log_line, OneLineWriter};

#[test]
fn clean_line_is_borrowed_unchanged() {
    let line = b"2026-11-14T00:00:00Z  INFO nanosiem: ok\tdone \x1b[2mcolored\x1b[0m\n";
    let out = escape_log_line(line);
    assert!(matches!(out, std::borrow::Cow::Borrowed(_)));
    assert_eq!(&*out, &line[..]);
}

#[test]
fn embedded_breaks_and_controls_are_escaped_final_newline_kept() {
    let line = b"ERROR search: Cannot parse date here: zz\x00\nFAKE LOG LINE\r\x01x\x7f\n";
    let out = escape_log_line(line);
    assert_eq!(
        std::str::from_utf8(&out).unwrap(),
        "ERROR search: Cannot parse date here: zz\\0\\nFAKE LOG LINE\\r\\x01x\\x7f\n"
    );
    assert_eq!(out.iter().filter(|b| **b == b'\n').count(), 1);
}

#[test]
fn line_without_trailing_newline_is_fully_escaped() {
    assert_eq!(&*escape_log_line(b"a\nb"), b"a\\nb");
    assert_eq!(&*escape_log_line(b""), b"");
    assert_eq!(&*escape_log_line(b"\n"), b"\n");
}

#[test]
fn utf8_passes_through() {
    let line = "naïve ✓ \u{FFFD}\n".as_bytes();
    assert_eq!(&*escape_log_line(line), line);
}

#[test]
fn writer_reports_the_whole_input_written() {
    let mut writer = OneLineWriter(Vec::new());
    let input = b"x\ny\n";
    writer.write_all(input).unwrap();
    assert_eq!(writer.0, b"x\\ny\n");
}
