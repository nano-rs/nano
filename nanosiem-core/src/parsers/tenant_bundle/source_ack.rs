// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4846: reader-first upgrade for bounded, duplicate-safe direct ingestion.
//! Edits only platform HTTP/HEC authentication and the existing UID writer.

use super::{archive::BundleTree, bronze_row_contract::BRONZE_SINK_FILES, TenantBundleError};

pub const KEY_VRL: &str = include_str!("source_ack_key.vrl");
pub const LOSS_PROBE_CONFIG: &str = include_str!("source_ack_loss_probe.toml");
pub const HTTP_MARKER: &str = "# NAN-4846: signed HTTP transport envelope v1";
const LEGACY_UID: &str =
    "if (to_string(metadata.uid) ?? \"\") == \"\" { metadata.uid = uuid_v4() }";
pub const UID_VRL: &str = r#"# NAN-4846: request-hour identities survive parser time changes and restart.
event_key = to_string(%nano_event_key) ?? ""
request_hour = to_int(%nano_request_hour) ?? -1
if event_key != "" && request_hour >= 0 {
    old_uid = to_string(metadata.uid) ?? ""
    uid_digest = sha2("nano-uid-v1:key:" + tenant_id + ":" + event_key, variant: "SHA-256")
    metadata.uid = "nano-request-v1:" + to_string(request_hour) + ":" + uid_digest
    if old_uid != "" && !starts_with(old_uid, "nano-request-v1:") { metadata.original_event_uid = old_uid }
} else if (to_string(metadata.uid) ?? "") == "" {
    metadata.uid = uuid_v4()
}"#;

pub fn http_vrl() -> String {
    format!(
        r#"{HTTP_MARKER}
nano_wire = to_string(."X-Nano-Event-Wire") ?? to_string(."x-nano-event-wire") ?? ""
del(."X-Nano-Event-Wire")
del(."x-nano-event-wire")
if nano_wire != "" {{
    if nano_wire != "v1" {{ abort }}
    nano_packet = parse_json!(string!(.message))
    nano_event_key = string!(nano_packet._nano_ingest_v1.key)
{KEY_VRL}
    if !nano_key_verified {{ abort }}
    .message = string!(nano_packet._nano_ingest_v1.payload)
}}
"#
    )
}

pub fn hec_vrl() -> String {
    format!("# NAN-4846: signed HEC event key v1\nnano_event_key = to_string(.nano_event_key) ?? \"\"\ndel(.nano_event_key)\n{KEY_VRL}")
}

fn error(message: &str) -> TenantBundleError {
    TenantBundleError::Base(format!("source acknowledgement upgrade: {message}"))
}

fn append_transform(text: &str, name: &str, addition: &str) -> Result<String, TenantBundleError> {
    let header = format!("[transforms.{name}]\n");
    if text.matches(&header).count() != 1 {
        return Err(error("authentication transform is absent or ambiguous"));
    }
    let start = text.find(&header).unwrap();
    let source = text[start..]
        .find("source = '''\n")
        .ok_or_else(|| error("authentication source is absent"))?
        + start
        + "source = '''\n".len();
    let end = text[source..]
        .find("'''")
        .ok_or_else(|| error("authentication source is unterminated"))?
        + source;
    if text[source..end].contains(HTTP_MARKER) {
        return Err(error("base is already upgraded"));
    }
    Ok(format!("{}\n{}{}", &text[..end], addition, &text[end..]))
}

/// Derive a platform base, then use the ordinary signed tenant-bundle build.
/// Existing unwrapped requests remain accepted, permitting reader-first rollout.
pub fn upgrade_source_ack(base: &BundleTree) -> Result<BundleTree, TenantBundleError> {
    let mut tree = base.clone();
    tree.put("93-loss-probe.toml", LOSS_PROBE_CONFIG.as_bytes().to_vec());
    let direct = base.text("06-cloudflare-direct-ingest.toml")?;
    let headers = direct
        .lines()
        .find(|line| line.starts_with("headers = ["))
        .ok_or_else(|| error("HTTP header allowlist is absent"))?;
    if headers.contains("X-Nano-Event-Wire") {
        return Err(error("base is already upgraded"));
    }
    let expanded = headers.replacen('[', "[\"X-Nano-Event-Wire\", ", 1);
    let direct = direct.replacen(headers, &expanded, 1);
    tree.put(
        "06-cloudflare-direct-ingest.toml",
        append_transform(&direct, "cloudflare_direct_auth", &http_vrl())?.into_bytes(),
    );
    let hec = base.text("02-hec-source.toml")?;
    // Before any legacy object lift, so payload fields cannot replace the key.
    let anchor = "if !is_null(removed_hec_token) { abort }\n";
    if hec.matches(anchor).count() != 1 {
        return Err(error("private HEC authentication edge differs"));
    }
    tree.put(
        "02-hec-source.toml",
        hec.replacen(anchor, &format!("{anchor}\n{}", hec_vrl()), 1)
            .into_bytes(),
    );
    for path in BRONZE_SINK_FILES {
        let text = base.text(path)?;
        let upgraded = if text.contains("nano-uid-v1:key:")
            && text.contains("%nano_event_key")
            && text.matches(".metadata = metadata\n").count() == 1
        {
            text.replacen(
                ".metadata = metadata\n",
                &format!("{UID_VRL}\n.metadata = metadata\n"),
                1,
            )
        } else if text.matches(LEGACY_UID).count() == 1 {
            text.replacen(LEGACY_UID, UID_VRL, 1)
        } else {
            return Err(error("lake UID writer differs"));
        };
        tree.put(path, upgraded.into_bytes());
    }
    Ok(tree)
}

/// Exact source fragments, checked against the bytes under the signed bundle
/// hash. A marker alone cannot authorize a Worker to race direct and replay.
pub fn supports_fast_source_ack(base: &BundleTree) -> bool {
    base.text("93-loss-probe.toml")
        .is_ok_and(|s| s == LOSS_PROBE_CONFIG)
        && base
            .text("06-cloudflare-direct-ingest.toml")
            .is_ok_and(|s| {
                s.contains(&http_vrl())
                    && toml::from_str::<toml::Value>(s).is_ok_and(|config| {
                        let Some(source) = config
                            .get("sources")
                            .and_then(|v| v.get("cloudflare_direct_ingest"))
                        else {
                            return false;
                        };
                        source.get("type").and_then(toml::Value::as_str) == Some("http_server")
                            && source
                                .get("framing")
                                .and_then(|v| v.get("method"))
                                .and_then(toml::Value::as_str)
                                == Some("newline_delimited")
                            && source
                                .get("decoding")
                                .and_then(|v| v.get("codec"))
                                .and_then(toml::Value::as_str)
                                == Some("bytes")
                            && source
                                .get("acknowledgements")
                                .and_then(|v| v.get("enabled"))
                                .and_then(toml::Value::as_bool)
                                == Some(true)
                            && source
                                .get("headers")
                                .and_then(toml::Value::as_array)
                                .is_some_and(|headers| {
                                    headers
                                        .iter()
                                        .any(|v| v.as_str() == Some("X-Nano-Event-Wire"))
                                })
                    })
            })
        && base
            .text("02-hec-source.toml")
            .is_ok_and(|s| s.contains(&hec_vrl()))
        && BRONZE_SINK_FILES
            .iter()
            .all(|p| base.text(p).is_ok_and(|s| s.contains(UID_VRL)))
}
