// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3652: user-visible text never names a third-party SIEM vendor.
//!
//! The HTTP Event Collector protocol is "HEC" in every label, description,
//! template title and API description. Its wire literals stay as they are,
//! because senders and Vector depend on them: the `Authorization: Splunk
//! <token>` header scheme, `X-Splunk-Request-Channel`, the `splunk_hec`
//! source/sink/exporter types (and identifiers built on them), Fluent Bit's
//! `splunk` output plugin and the OpenTelemetry `com.splunk.*` attributes.
//!
//! [`vendor_name_mentions`] is the guard the label, template and OpenAPI tests
//! run over user-visible text: it removes the allow-listed wire literals and
//! reports whatever vendor naming is left.

use std::sync::LazyLock;

use regex::Regex;

/// Wire literals that may carry the vendor name. Everything else is branding.
static WIRE_LITERALS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?x)
          Authorization:\ Splunk\b            # HEC auth header scheme
        | (?i:x-splunk-request-channel)       # HEC ack channel header
        | \bsplunk_hec\w*                     # Vector / OTel type names and ids
        | \bSplunk_Token\b                    # Fluent Bit splunk output key
        | \bName\ +splunk\b                   # Fluent Bit output plugin name
        | `Name\ splunk`
        | \bcom\.splunk\.\w+                  # OpenTelemetry HEC attributes
        | \bSplunkHec\w*                      # Rust/TS enum and type identifiers
        ",
    )
    .expect("wire literal regex")
});

static VENDOR: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)splunk").expect("vendor regex"));

/// The vendor mentions left in `text` once the allow-listed wire literals are
/// removed, each with a little surrounding context. Empty means clean.
pub fn vendor_name_mentions(text: &str) -> Vec<String> {
    let stripped = WIRE_LITERALS.replace_all(text, "");
    VENDOR
        .find_iter(&stripped)
        .map(|m| {
            let start = stripped[..m.start()].char_indices().rev().nth(30).map_or(0, |(i, _)| i);
            let end = stripped[m.end()..].char_indices().nth(30).map_or(stripped.len(), |(i, _)| m.end() + i);
            stripped[start..end].to_string()
        })
        .collect()
}

/// NAN-4282: the customer-facing product name (lowercase "nano"). Customers never
/// see the internal code name "lean"; identifiers (`lean_*`, `/api/lean/...`,
/// `nano-lean`, `lean-landing-admin`, lake_profile `lean`) are unchanged.
pub const PRODUCT_DISPLAY_NAME: &str = "nano Security Lake";

static CODE_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b([Ll])ean(-lake|-cell)?\b( ?)").expect("code name regex"));

/// Characters that make an adjacent "lean" part of an identifier, a path, code
/// or a quoted echo of the caller's own input (`unknown field 'lean'`).
fn identifier_neighbor(c: Option<char>) -> bool {
    matches!(c, Some('_' | '/' | '`' | '.' | '-' | ':' | '=' | '\'' | '"'))
}

/// Each prose "lean" in `text` with its range (the code name, plus a "-lake" /
/// "-cell" suffix and one trailing space), skipping identifier forms.
fn code_name_matches(text: &str) -> Vec<regex::Captures<'_>> {
    CODE_NAME
        .captures_iter(text)
        .filter(|caps| {
            let whole = caps.get(0).expect("match");
            let core_end = whole.end() - caps.get(3).map_or(0, |m| m.len());
            !identifier_neighbor(text[..whole.start()].chars().next_back())
                && !identifier_neighbor(text[core_end..].chars().next())
        })
        .collect()
}

/// Operator-written text on its way to a customer (an error message, a step
/// message) with the internal code name removed: "lean-lake cell" reads "lake
/// cell", "the lean cell" reads "the cell", "(lean) tenant" reads "(nano
/// Security Lake) tenant". Identifiers are left alone. The source strings, and
/// any code that matches on them, are unchanged: this runs at the boundary.
pub fn without_internal_code_name(text: &str) -> std::borrow::Cow<'_, str> {
    let matches = code_name_matches(text);
    if matches.is_empty() {
        return std::borrow::Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len() + 16);
    let mut last = 0;
    let mut capitalize_next = false;
    for caps in matches {
        let whole = caps.get(0).expect("match");
        out.push_str(&text[last..whole.start()]);
        let upper = &caps[1] == "L";
        let space = caps.get(3).map_or("", |m| m.as_str());
        match caps.get(2).map(|m| m.as_str()) {
            Some("-lake") => { out.push_str(if upper { "Lake" } else { "lake" }); out.push_str(space); }
            Some(_) => { out.push_str(if upper { "Lake cell" } else { "lake cell" }); out.push_str(space); }
            None if !space.is_empty() && text[whole.end()..].starts_with(|c: char| c.is_alphanumeric()) => {
                capitalize_next = upper;
            }
            None => { out.push_str(PRODUCT_DISPLAY_NAME); out.push_str(space); }
        }
        last = whole.end();
        if capitalize_next {
            capitalize_next = false;
            let mut rest = text[last..].chars();
            if let Some(first) = rest.next() {
                out.extend(first.to_uppercase());
                last += first.len_utf8();
            }
        }
    }
    out.push_str(&text[last..]);
    std::borrow::Cow::Owned(out)
}

/// The prose "lean" mentions left in `text` (identifiers excluded), each with a
/// little surrounding context. Empty means clean.
pub fn code_name_mentions(text: &str) -> Vec<String> {
    code_name_matches(text)
        .into_iter()
        .map(|caps| {
            let m = caps.get(0).expect("match");
            let start = text[..m.start()].char_indices().rev().nth(30).map_or(0, |(i, _)| i);
            let end = text[m.end()..].char_indices().nth(30).map_or(text.len(), |(i, _)| m.end() + i);
            text[start..end].to_string()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{code_name_mentions, vendor_name_mentions, without_internal_code_name};

    #[test]
    fn wire_literals_pass_and_branding_fails() {
        for clean in [
            "HEC event endpoint",
            "-H \"Authorization: Splunk {{token}}\"",
            "X-Splunk-Request-Channel: abc",
            "type = \"splunk_hec_logs\"",
            "exporters: [splunk_hec/nano]",
            "    Name         splunk\n    Splunk_Token {{token}}",
            "each record's `com.splunk.sourcetype` attribute",
            "Self::SplunkHec",
        ] {
            assert!(vendor_name_mentions(clean).is_empty(), "{clean}");
        }
        for branded in ["Splunk HEC", "Send a test event (Splunk HEC)", "nPL is Splunk-like", "splunk output", "SPLUNK"] {
            assert!(!vendor_name_mentions(branded).is_empty(), "{branded}");
        }
    }

    #[test]
    fn log_source_and_source_config_labels_say_hec() {
        use crate::log_sources::SourceType;
        use crate::source_configs::types::SourceConfigType;
        let mut texts: Vec<String> = Vec::new();
        for t in SourceType::all_types() {
            texts.extend([t.label().to_string(), t.description().to_string()]);
        }
        for t in SourceConfigType::all_types() {
            texts.extend([t.label().to_string(), t.description().to_string()]);
            for preset in t.match_field_presets() {
                texts.extend([preset.label, preset.description]);
            }
        }
        for text in &texts {
            assert!(vendor_name_mentions(text).is_empty(), "user-visible label names a vendor: {text:?}");
        }
        assert_eq!(SourceType::SplunkHec.label(), "HEC");
        assert_eq!(SourceConfigType::SplunkHec.label(), "HEC");
    }

    /// Titles, descriptions, placeholder help and bodies of every sender
    /// template (the SIEM "Add data" flow and the docs render all of them).
    #[test]
    fn sender_templates_say_hec() {
        let catalog = serde_json::to_string_pretty(&crate::ingest_sender_templates::sender_template_catalog())
            .expect("catalog json");
        let mentions = vendor_name_mentions(&catalog);
        assert!(mentions.is_empty(), "sender templates name a vendor: {mentions:#?}");
    }

    #[test]
    fn code_name_leaves_customer_text_and_identifiers_stay() {
        for (internal, customer) in [
            ("lean-lake cell is not ready for durable work", "lake cell is not ready for durable work"),
            ("tenant is no longer placed on a lean-lake cell", "tenant is no longer placed on a lake cell"),
            ("Lean-lake query service returned HTTP 503", "Lake query service returned HTTP 503"),
            ("The tenant's lean-cell job lane is unavailable", "The tenant's lake cell job lane is unavailable"),
            ("lean Prevalence exports run on the tenant's lean-lake cell", "Prevalence exports run on the tenant's lake cell"),
            ("durable baselines run on a lean cell job runner", "durable baselines run on a cell job runner"),
            ("Lean tenant: served by GET /x", "Tenant: served by GET /x"),
            ("enterprise-shared (lean) tenant", "enterprise-shared (nano Security Lake) tenant"),
            ("ok", "ok"),
        ] {
            assert_eq!(without_internal_code_name(internal), customer, "{internal}");
            assert!(code_name_mentions(customer).is_empty(), "{customer}");
        }
        for identifier in [
            "docker compose run --rm lean-landing-admin add",
            "GET /api/lean/ingest-health",
            "code `lean_prevalence_export`",
            "http://nano-lean-otel-a.nano-lean.svc:3014/",
            "lake_profile=lean",
            "clean boolean leaning",
            "unknown field 'lean' in the query",
            "search \"lean\" matched 0 events",
        ] {
            assert_eq!(without_internal_code_name(identifier), identifier, "{identifier}");
            assert!(code_name_mentions(identifier).is_empty(), "{identifier}");
        }
        assert!(!code_name_mentions("served for lean-lake tenants").is_empty());
    }
}
