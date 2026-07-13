// SPDX-License-Identifier: AGPL-3.0-or-later

//! Report artifact rendering (NAN-1793).
//!
//! Produces self-contained, offline-safe artifacts — CSV plus rendered HTML —
//! with NO external assets (no CDN, no remote fonts/images): every byte is
//! inline so the HTML renders in an air-gapped browser. No headless browser or
//! external renderer is used; HTML/CSV/SVG are hand-built strings.
//!
//! Everything is bounded: the caller passes a hard byte cap; row emission stops
//! before the cap is exceeded and the artifact is flagged truncated (never
//! silently cut). A separate display cap keeps the HTML table small regardless.

use chrono::{DateTime, Utc};
use serde_json::Value;

/// Max rows rendered into an HTML table (cosmetic — CSV carries the full,
/// byte-capped set). Keeps the HTML artifact small and the browser responsive.
pub const HTML_DISPLAY_ROW_CAP: usize = 500;

/// Max data points charted in an inline SVG. Beyond this we fall back to a table
/// (a dense SVG with thousands of points is unreadable and large).
const SVG_MAX_POINTS: usize = 200;

/// A single panel's executed result, handed to the dashboard renderer.
#[derive(Debug, Clone)]
pub struct PanelOutput {
    pub title: String,
    /// Frontend `visualizationType` (e.g. "line", "bar", "table", "single_value").
    pub viz_type: String,
    /// Column order (from the search response) when known.
    pub columns: Vec<String>,
    pub rows: Vec<Value>,
    /// Per-panel execution error (rendered inline instead of the data).
    pub error: Option<String>,
    /// Panel was skipped as unsupported in v1 (e.g. obs_metric widgets).
    pub unsupported: Option<String>,
}

/// HTML-escape text for safe embedding in element content / attributes.
pub fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Render a JSON cell value as a flat display string (objects/arrays compacted).
pub fn cell_to_string(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        other => other.to_string(),
    }
}

/// Best-effort numeric parse of a JSON cell (Number, or a numeric String).
fn cell_to_f64(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse::<f64>().ok(),
        _ => None,
    }
}

/// Determine column order: prefer the provided order, else the union of keys in
/// first-seen order across the (bounded sample of) rows.
pub fn resolve_columns(columns: &[String], rows: &[Value]) -> Vec<String> {
    if !columns.is_empty() {
        return columns.to_vec();
    }
    let mut seen: Vec<String> = Vec::new();
    for row in rows.iter().take(HTML_DISPLAY_ROW_CAP.max(1000)) {
        if let Some(obj) = row.as_object() {
            for k in obj.keys() {
                if !seen.iter().any(|c| c == k) {
                    seen.push(k.clone());
                }
            }
        }
    }
    seen
}

/// Neutralize a CSV field that a spreadsheet would evaluate as a FORMULA.
///
/// This is a SIEM: cell content is attacker-controlled log data. Excel / Sheets /
/// LibreOffice execute any cell starting with `=`, `+`, `-`, `@` (or a leading
/// tab/CR before one of those), so a crafted `user` or `command_line` value like
/// `=cmd|'/c calc'!A0` becomes code execution on the analyst's workstation when
/// they open the exported CSV (CSV injection / DDE).
///
/// Genuine negative numbers (`-5`, `-1.25`) must survive as numbers, so a
/// leading-`-` field is only neutralized when it does NOT parse as a number —
/// `-5` stays numeric, `-5+3` (a formula) does not. Neutralization prefixes a
/// single quote, the conventional "treat as text" marker.
fn csv_neutralize_formula(field: &str) -> std::borrow::Cow<'_, str> {
    let trimmed = field.trim_start_matches(['\t', '\r', ' ']);
    let first = match trimmed.chars().next() {
        Some(c) => c,
        None => return std::borrow::Cow::Borrowed(field),
    };
    if !matches!(first, '=' | '+' | '-' | '@') {
        return std::borrow::Cow::Borrowed(field);
    }
    // A well-formed number is data, not a formula — keep it intact.
    if field.trim().parse::<f64>().is_ok() {
        return std::borrow::Cow::Borrowed(field);
    }
    std::borrow::Cow::Owned(format!("'{field}"))
}

/// Escape a CSV field per RFC 4180 (quote when it contains `,`, `"`, CR, or LF;
/// double embedded quotes), after neutralizing spreadsheet formulas.
fn csv_escape(field: &str) -> String {
    let field = csv_neutralize_formula(field);
    if field.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.into_owned()
    }
}

/// Render rows to CSV, bounded by `byte_cap`. Returns the bytes and whether the
/// output was truncated (cap reached before all rows were written).
pub fn render_csv(rows: &[Value], columns: &[String], byte_cap: usize) -> (Vec<u8>, bool) {
    let cols = resolve_columns(columns, rows);
    let mut out = String::new();

    // Header.
    let header = cols
        .iter()
        .map(|c| csv_escape(c))
        .collect::<Vec<_>>()
        .join(",");
    out.push_str(&header);
    out.push_str("\r\n");

    let mut truncated = false;
    for row in rows {
        let obj = row.as_object();
        let line = cols
            .iter()
            .map(|c| {
                let cell = obj.and_then(|o| o.get(c)).map(cell_to_string).unwrap_or_default();
                csv_escape(&cell)
            })
            .collect::<Vec<_>>()
            .join(",");
        // +2 for CRLF. Stop before exceeding the cap so the file stays valid.
        if out.len() + line.len() + 2 > byte_cap {
            truncated = true;
            break;
        }
        out.push_str(&line);
        out.push_str("\r\n");
    }

    (out.into_bytes(), truncated)
}

/// Shared inline stylesheet — dense, mono for IDs/counts/timestamps, 1px borders,
/// no shadows (matches the app's UI conventions). Theme-aware light/dark.
fn base_style() -> &'static str {
    r#"<style>
:root{color-scheme:light dark;--bg:#ffffff;--fg:#1a1a1a;--muted:#6b7280;--border:#e4e4e7;--head:#f4f4f5;--accent:#2563eb;--warn-bg:#fef3c7;--warn-fg:#92400e;--warn-border:#fcd34d;}
@media (prefers-color-scheme:dark){:root{--bg:#0b0b0d;--fg:#e5e5e7;--muted:#9ca3af;--border:#27272a;--head:#18181b;--accent:#60a5fa;--warn-bg:#3f2d0a;--warn-fg:#fcd34d;--warn-border:#78560f;}}
*{box-sizing:border-box;}
body{margin:0;padding:24px;background:var(--bg);color:var(--fg);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:13px;line-height:1.45;}
.mono{font-family:ui-monospace,SFMono-Regular,'SF Mono',Menlo,Consolas,monospace;}
h1{font-size:18px;margin:0 0 4px;}
h2{font-size:14px;margin:28px 0 8px;border-bottom:1px solid var(--border);padding-bottom:4px;}
.meta{color:var(--muted);font-size:11px;margin:2px 0;}
.meta .mono{font-size:10.5px;}
.qbox{background:var(--head);border:1px solid var(--border);border-radius:4px;padding:8px 10px;margin:10px 0;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;white-space:pre-wrap;word-break:break-word;}
table{border-collapse:collapse;width:100%;margin:6px 0 4px;font-size:12px;}
th,td{border:1px solid var(--border);padding:4px 8px;text-align:left;vertical-align:top;}
th{background:var(--head);font-weight:600;font-size:10.5px;text-transform:uppercase;letter-spacing:0.04em;color:var(--muted);}
td{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:11px;}
.tablewrap{overflow-x:auto;}
.warn{background:var(--warn-bg);color:var(--warn-fg);border:1px solid var(--warn-border);border-radius:4px;padding:8px 10px;margin:10px 0;font-size:12px;}
.err{color:#b91c1c;font-size:12px;margin:6px 0;}
.empty{color:var(--muted);font-size:12px;margin:6px 0;}
.count{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;}
.footer{color:var(--muted);font-size:10.5px;margin-top:32px;border-top:1px solid var(--border);padding-top:8px;}
svg{max-width:100%;height:auto;border:1px solid var(--border);border-radius:4px;background:var(--bg);}
.single{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:28px;font-weight:600;margin:6px 0;}
</style>"#
}

/// Append an HTML `<table>` for `rows`, bounded by `byte_cap` (stops adding rows
/// before the cap). Returns whether it truncated. Adds a "showing N of M" note
/// when rows exceed the display cap.
fn push_html_table(
    out: &mut String,
    rows: &[Value],
    columns: &[String],
    byte_cap: usize,
) -> bool {
    let cols = resolve_columns(columns, rows);
    if cols.is_empty() {
        out.push_str("<p class=\"empty\">No columns.</p>");
        return false;
    }

    out.push_str("<div class=\"tablewrap\"><table><thead><tr>");
    for c in &cols {
        out.push_str("<th>");
        out.push_str(&html_escape(c));
        out.push_str("</th>");
    }
    out.push_str("</tr></thead><tbody>");

    let display_total = rows.len();
    let mut rendered = 0usize;
    let mut truncated = false;
    for row in rows.iter().take(HTML_DISPLAY_ROW_CAP) {
        let obj = row.as_object();
        let mut line = String::from("<tr>");
        for c in &cols {
            let cell = obj.and_then(|o| o.get(c)).map(cell_to_string).unwrap_or_default();
            line.push_str("<td>");
            line.push_str(&html_escape(&cell));
            line.push_str("</td>");
        }
        line.push_str("</tr>");
        if out.len() + line.len() + 64 > byte_cap {
            truncated = true;
            break;
        }
        out.push_str(&line);
        rendered += 1;
    }
    out.push_str("</tbody></table></div>");

    if display_total > rendered {
        out.push_str(&format!(
            "<p class=\"meta\">Showing first <span class=\"mono\">{}</span> of <span class=\"mono\">{}</span> rows.</p>",
            rendered, display_total
        ));
    }
    truncated
}

/// Build an inline SVG line/bar chart when `rows` has a simple (label, single
/// numeric) shape — the common `timechart count` / `stats count by x` output.
/// Returns `None` when the shape isn't chartable (caller falls back to a table).
fn try_svg_chart(rows: &[Value], columns: &[String], viz_type: &str) -> Option<String> {
    if rows.is_empty() {
        return None;
    }
    let cols = resolve_columns(columns, rows);
    if cols.len() < 2 {
        return None;
    }

    // Pick the FIRST purely-numeric column as the value column and the first
    // column as the label. A shape with no consistent numeric column isn't
    // chartable here.
    let sample = rows.first().and_then(|r| r.as_object())?;
    let label_col = cols[0].clone();
    let value_col = cols.iter().skip(1).find(|c| {
        rows.iter()
            .filter_map(|r| r.as_object())
            .filter_map(|o| o.get(*c))
            .all(|v| cell_to_f64(v).is_some())
            && sample.contains_key(*c)
    })?;

    let mut labels: Vec<String> = Vec::new();
    let mut values: Vec<f64> = Vec::new();
    for row in rows.iter().take(SVG_MAX_POINTS) {
        let obj = row.as_object()?;
        let label = obj.get(&label_col).map(cell_to_string).unwrap_or_default();
        let value = obj.get(value_col).and_then(cell_to_f64)?;
        labels.push(label);
        values.push(value);
    }
    if values.len() < 2 {
        return None;
    }

    let as_bar = matches!(viz_type, "bar" | "ranked_bar");
    Some(render_svg(&labels, &values, &label_col, value_col, as_bar))
}

/// Render a compact single-series SVG chart (line by default, bars when
/// `as_bar`). Axis-free but with min/max labels and a baseline — enough to read
/// the trend offline. All coordinates are computed here; nothing external.
fn render_svg(
    labels: &[String],
    values: &[f64],
    label_col: &str,
    value_col: &str,
    as_bar: bool,
) -> String {
    let width = 720.0f64;
    let height = 220.0f64;
    let pad_l = 8.0;
    let pad_r = 8.0;
    let pad_t = 24.0;
    let pad_b = 28.0;
    let plot_w = width - pad_l - pad_r;
    let plot_h = height - pad_t - pad_b;

    let max_v = values.iter().cloned().fold(f64::MIN, f64::max);
    let min_v = values.iter().cloned().fold(f64::MAX, f64::min).min(0.0);
    let span = (max_v - min_v).abs().max(f64::EPSILON);
    let n = values.len();

    let x_at = |i: usize| -> f64 {
        if n <= 1 {
            pad_l + plot_w / 2.0
        } else {
            pad_l + (i as f64 / (n as f64 - 1.0)) * plot_w
        }
    };
    let y_at = |v: f64| -> f64 { pad_t + plot_h - ((v - min_v) / span) * plot_h };

    // No `xmlns` attribute: this SVG is INLINE in an HTML document, where the
    // HTML5 parser assigns the SVG namespace automatically. Omitting it keeps the
    // artifact free of ANY absolute URL (even a non-fetched namespace URI), so the
    // "zero external references" air-gap guarantee is trivially verifiable.
    let mut svg = format!(
        "<svg viewBox=\"0 0 {w:.0} {h:.0}\" width=\"{w:.0}\" height=\"{h:.0}\" role=\"img\" aria-label=\"{alt}\">",
        w = width,
        h = height,
        alt = html_escape(&format!("{} by {}", value_col, label_col))
    );

    // Baseline.
    let base_y = y_at(min_v);
    svg.push_str(&format!(
        "<line x1=\"{x1:.1}\" y1=\"{y:.1}\" x2=\"{x2:.1}\" y2=\"{y:.1}\" stroke=\"currentColor\" stroke-opacity=\"0.2\" stroke-width=\"1\"/>",
        x1 = pad_l, x2 = pad_l + plot_w, y = base_y
    ));

    if as_bar {
        let bar_w = (plot_w / n as f64) * 0.7;
        for (i, v) in values.iter().enumerate() {
            let cx = x_at(i);
            let top = y_at(*v);
            let bh = (base_y - top).max(0.0);
            svg.push_str(&format!(
                "<rect x=\"{x:.1}\" y=\"{y:.1}\" width=\"{bw:.1}\" height=\"{bh:.1}\" fill=\"#2563eb\" fill-opacity=\"0.75\"/>",
                x = cx - bar_w / 2.0, y = top, bw = bar_w, bh = bh
            ));
        }
    } else {
        // Area fill + line.
        let mut path = String::new();
        for (i, v) in values.iter().enumerate() {
            path.push_str(if i == 0 { "M" } else { "L" });
            path.push_str(&format!("{:.1} {:.1} ", x_at(i), y_at(*v)));
        }
        let mut area = path.clone();
        area.push_str(&format!(
            "L{:.1} {:.1} L{:.1} {:.1} Z",
            x_at(n - 1),
            base_y,
            x_at(0),
            base_y
        ));
        svg.push_str(&format!(
            "<path d=\"{}\" fill=\"#2563eb\" fill-opacity=\"0.12\" stroke=\"none\"/>",
            area
        ));
        svg.push_str(&format!(
            "<path d=\"{}\" fill=\"none\" stroke=\"#2563eb\" stroke-width=\"1.5\"/>",
            path.trim()
        ));
    }

    // Min/max value labels (top-left) and first/last x labels.
    svg.push_str(&format!(
        "<text x=\"{x:.1}\" y=\"14\" font-size=\"10\" font-family=\"ui-monospace,monospace\" fill=\"currentColor\" fill-opacity=\"0.7\">{vc}: max {mx}</text>",
        x = pad_l, vc = html_escape(value_col), mx = fmt_num(max_v)
    ));
    if let (Some(first), Some(last)) = (labels.first(), labels.last()) {
        svg.push_str(&format!(
            "<text x=\"{x:.1}\" y=\"{y:.1}\" font-size=\"9\" font-family=\"ui-monospace,monospace\" fill=\"currentColor\" fill-opacity=\"0.6\">{f}</text>",
            x = pad_l, y = height - 8.0, f = html_escape(&truncate_label(first))
        ));
        svg.push_str(&format!(
            "<text x=\"{x:.1}\" y=\"{y:.1}\" font-size=\"9\" text-anchor=\"end\" font-family=\"ui-monospace,monospace\" fill=\"currentColor\" fill-opacity=\"0.6\">{l}</text>",
            x = pad_l + plot_w, y = height - 8.0, l = html_escape(&truncate_label(last))
        ));
    }

    svg.push_str("</svg>");
    svg
}

fn truncate_label(s: &str) -> String {
    if s.chars().count() > 22 {
        let t: String = s.chars().take(21).collect();
        format!("{t}…")
    } else {
        s.to_string()
    }
}

fn fmt_num(v: f64) -> String {
    if v.fract() == 0.0 && v.abs() < 1e15 {
        format!("{}", v as i64)
    } else {
        format!("{v:.2}")
    }
}

/// Render the self-contained HTML summary for a SEARCH report.
#[allow(clippy::too_many_arguments)]
pub fn render_search_html(
    report_name: &str,
    query: &str,
    range_start: DateTime<Utc>,
    range_end: DateTime<Utc>,
    generated_at: DateTime<Utc>,
    rows: &[Value],
    columns: &[String],
    total_count: u64,
    result_truncated: bool,
    byte_cap: usize,
) -> (Vec<u8>, bool) {
    let mut out = String::new();
    out.push_str(&base_style());
    out.push_str(&format!("<h1>{}</h1>", html_escape(report_name)));
    out.push_str(&format!(
        "<p class=\"meta\">Search report · generated <span class=\"mono\">{}</span></p>",
        generated_at.format("%Y-%m-%d %H:%M:%S UTC")
    ));
    out.push_str(&format!(
        "<p class=\"meta\">Window <span class=\"mono\">{}</span> → <span class=\"mono\">{}</span></p>",
        range_start.format("%Y-%m-%d %H:%M:%S UTC"),
        range_end.format("%Y-%m-%d %H:%M:%S UTC")
    ));
    out.push_str(&format!(
        "<p class=\"meta\">Matches <span class=\"count\">{}</span> · rows in report <span class=\"count\">{}</span></p>",
        total_count,
        rows.len()
    ));
    out.push_str("<div class=\"qbox\">");
    out.push_str(&html_escape(query));
    out.push_str("</div>");

    if result_truncated {
        out.push_str(&format!(
            "<div class=\"warn\">Results were truncated to the row cap — more than <span class=\"mono\">{}</span> rows matched. The CSV and this table show a bounded subset.</div>",
            rows.len()
        ));
    }

    let mut artifact_truncated = false;
    if rows.is_empty() {
        out.push_str("<p class=\"empty\">No matching events in the window.</p>");
    } else {
        out.push_str("<h2>Results</h2>");
        artifact_truncated = push_html_table(&mut out, rows, columns, byte_cap);
        if artifact_truncated {
            out.push_str("<div class=\"warn\">This HTML artifact hit its size cap and was truncated. Download the CSV for the full (row-capped) result set.</div>");
        }
    }

    out.push_str(&format!(
        "<p class=\"footer\">Generated by nano · scheduled report · {}</p>",
        generated_at.format("%Y-%m-%dT%H:%M:%SZ")
    ));
    (out.into_bytes(), artifact_truncated)
}

/// Render the self-contained HTML report for a DASHBOARD (one section per panel).
pub fn render_dashboard_html(
    report_name: &str,
    dashboard_name: &str,
    range_start: DateTime<Utc>,
    range_end: DateTime<Utc>,
    generated_at: DateTime<Utc>,
    panels: &[PanelOutput],
    byte_cap: usize,
) -> (Vec<u8>, bool) {
    let mut out = String::new();
    out.push_str(&base_style());
    out.push_str(&format!("<h1>{}</h1>", html_escape(report_name)));
    out.push_str(&format!(
        "<p class=\"meta\">Dashboard report · <span class=\"mono\">{}</span> · generated <span class=\"mono\">{}</span></p>",
        html_escape(dashboard_name),
        generated_at.format("%Y-%m-%d %H:%M:%S UTC")
    ));
    out.push_str(&format!(
        "<p class=\"meta\">Window <span class=\"mono\">{}</span> → <span class=\"mono\">{}</span> · <span class=\"count\">{}</span> panels</p>",
        range_start.format("%Y-%m-%d %H:%M:%S UTC"),
        range_end.format("%Y-%m-%d %H:%M:%S UTC"),
        panels.len()
    ));

    let mut artifact_truncated = false;
    for panel in panels {
        // Stop adding panels once the cap is hit; flag truncation.
        if out.len() + 512 > byte_cap {
            artifact_truncated = true;
            break;
        }
        out.push_str(&format!("<h2>{}</h2>", html_escape(&panel.title)));

        if let Some(reason) = &panel.unsupported {
            out.push_str(&format!(
                "<p class=\"empty\">{}</p>",
                html_escape(reason)
            ));
            continue;
        }
        if let Some(err) = &panel.error {
            out.push_str(&format!("<p class=\"err\">Panel failed: {}</p>", html_escape(err)));
            continue;
        }
        if panel.rows.is_empty() {
            out.push_str("<p class=\"empty\">No data in the window.</p>");
            continue;
        }

        // single_value: show the first numeric cell prominently.
        if panel.viz_type == "single_value" {
            let value = panel
                .rows
                .first()
                .and_then(|r| r.as_object())
                .and_then(|o| o.values().next())
                .map(cell_to_string)
                .unwrap_or_default();
            out.push_str(&format!("<div class=\"single\">{}</div>", html_escape(&value)));
            continue;
        }

        // Chartable line/area/bar shapes → inline SVG; else a table.
        let charted = if matches!(panel.viz_type.as_str(), "line" | "area" | "bar" | "ranked_bar") {
            try_svg_chart(&panel.rows, &panel.columns, &panel.viz_type)
        } else {
            None
        };
        match charted {
            Some(svg) => out.push_str(&svg),
            None => {
                if push_html_table(&mut out, &panel.rows, &panel.columns, byte_cap) {
                    artifact_truncated = true;
                    out.push_str("<div class=\"warn\">Truncated to the artifact size cap.</div>");
                    break;
                }
            }
        }
    }

    out.push_str(&format!(
        "<p class=\"footer\">Generated by nano · scheduled report · {}</p>",
        generated_at.format("%Y-%m-%dT%H:%M:%SZ")
    ));
    (out.into_bytes(), artifact_truncated)
}
