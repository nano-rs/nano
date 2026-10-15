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

#[cfg(test)]
mod tests {
    use super::vendor_name_mentions;

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
}
