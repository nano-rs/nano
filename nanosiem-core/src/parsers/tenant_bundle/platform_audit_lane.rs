// SPDX-License-Identifier: AGPL-3.0-or-later

//! The platform `audit` plumbing lane of the tenant parser base (NAN-2999).
//!
//! A lean tenant's platform audit (the OCSF API Activity mirrors of
//! `platform_audit_events`) reaches its search data through its own ingest
//! path: the platform sends the control plane's `audit-events:delivery` batch to
//! the tenant Worker with the tenant's platform-only `audit` source
//! credential, one OCSF document per line, as `text/plain` so `parse_content`
//! keeps each line whole in `.message`. This lane turns such a line back into
//! the OCSF row, exactly as the gen1 event publisher stores it; the canonical
//! lake sink then stamps `metadata.log_source = audit` (from the routing key)
//! and `metadata.tenant_uid`, and the row travels the normal edge log →
//! `ingest[T]` → signed part path.
//!
//! The lane is plumbing, like `otlp_log` / `unknown`: no source parser, no
//! tenant parser may route `audit` (it is a platform slug that is not in
//! [`super::overlay::PLUMBING_SOURCE_SLUGS`]), and the control DB refuses any
//! `audit` credential but the delivery job's (9008700). It refuses (drops)
//! any line that is not a nano API Activity event of THIS cell's tenant, so a
//! delivery can never put another tenant's row, or a non-audit row, under
//! `log_source = audit`.
//!
//! [`add_platform_audit_lane`] derives a base carrying the lane from any
//! platform base (v1, collector-v2, zero), editing exactly the four wiring
//! points a platform source uses and adding one platform file.

use super::archive::BundleTree;
use super::overlay::{HEC_FILE, LAKE_SINK_FILE, ROUTER_FILE};
use super::TenantBundleError;

/// The platform source slug (the lake sink stamps `metadata.log_source` from it).
pub const AUDIT_SLUG: &str = "audit";
/// The lane's platform file (underscore: platform plumbing, never a parser).
pub const AUDIT_LANE_FILE: &str = "sources/parsers/_platform_audit.toml";
/// Router output and transform names.
pub const AUDIT_ROUTE: &str = "nano_platform_audit";
pub const AUDIT_PREPARE: &str = "nano_platform_audit_prepare";

const HEC_TOKEN: &str = "${VECTOR_AUTH_TOKEN}:nano-source-v1:audit";

/// The lane's VRL: one delivered line → the `{event, timestamp, source_type}`
/// row every OCSF lane hands the lake sink (`OCSF_PREPARE_VRL`'s shape).
/// Refuses anything that is not a nano platform audit event (API Activity
/// 6003, Authentication 3002 or Account Change 3001 — NAN-3460) of this
/// cell's tenant carrying a UUID `metadata.uid` and an epoch-ms `time`.
pub const AUDIT_LANE_VRL: &str = r#"# NAN-2999: platform audit (OCSF API Activity 6003, Authentication 3002,
# Account Change 3001 — NAN-3460) delivered by nano-main.
raw = to_string(.message) ?? ""
parsed, parse_err = parse_json(raw)
if parse_err != null || !is_object(parsed) {
    log("platform audit line is not a JSON object; refused", level: "warn", rate_limit_secs: 60)
    abort
}
event = object!(parsed)
tenant_id = downcase(to_string(%tenant_id) ?? "")
event_tenant = downcase(to_string(event.metadata.tenant_uid) ?? "")
event_uid = downcase(to_string(event.metadata.uid) ?? "")
time_ms = to_int(event.time) ?? 0
admitted = tenant_id != "" && event_tenant == tenant_id
class_uid = to_int(event.class_uid) ?? 0
admitted = admitted && (class_uid == 6003 || class_uid == 3002 || class_uid == 3001)
admitted = admitted && (to_string(event.metadata.log_name) ?? "") == "audit"
admitted = admitted && (to_string(event.metadata.product.name) ?? "") == "nano"
admitted = admitted && match(event_uid, r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
admitted = admitted && time_ms > 0
if !admitted {
    log("platform audit line is not this tenant's platform audit event; refused", level: "warn", rate_limit_secs: 60)
    abort
}
# NAN-3304: ingest[T] admits a bronze row with its null members dropped (the
# Parquet form carries no nulls), then validates OCSF 1.9. The mirror says
# "unknown" with nulls (`src_endpoint: {"ip": null}`, `actor.user: {"name":
# null, "uid": null}`): a null-valued key passes the at-least-one constraint
# on gen1, but the lake saw `{}` and refused the row. Anchor each such object
# as gen1's publisher does for an audit without a client (the emitting
# service, marked in `unmapped`), and drop an `actor.user` or `resources[]`
# entry that names no one (`unmapped` keeps the nano-native values).
service = to_string(event.api.service.name) ?? ""
if service == "" || strlen(service) > 256 || match(service, r'[[:cntrl:]]') { service = "nano" }
markable = is_object(event.unmapped) || event.unmapped == null
src_anchored = false
for_each(["ip", "uid", "name", "hostname", "svc_name", "instance_uid", "interface_uid", "interface_name", "domain"]) -> |_index, key| {
    if (get(event.src_endpoint, [key]) ?? null) != null { src_anchored = true }
}
# API Activity requires a source endpoint; Authentication / Account Change
# (NAN-3460) do not, and an unknown client there is simply absent.
if !src_anchored && class_uid != 6003 {
    event = remove!(event, ["src_endpoint"])
} else if !src_anchored && markable {
    event.unmapped.nano_src_endpoint = "synthesized:emitting_service"
    event.src_endpoint = { "name": service, "svc_name": service, "type": "Other", "type_id": 99 }
}
user_anchored = false
for_each(["account", "name", "uid"]) -> |_index, key| {
    if (get(event.actor.user, [key]) ?? null) != null { user_anchored = true }
}
if !user_anchored && is_object(event.actor) {
    event.actor = remove!(object!(event.actor), ["user"])
}
actor_anchored = false
for_each(["process", "user", "iam_role", "invoked_by", "session", "application", "app_name", "app_uid"]) -> |_index, key| {
    if (get(event.actor, [key]) ?? null) != null { actor_anchored = true }
}
if !actor_anchored && markable {
    event.unmapped.nano_actor = "synthesized:emitting_service"
    event.actor = merge(object(event.actor) ?? {}, { "app_name": service })
}
if is_array(event.resources) {
    named = filter(array!(event.resources)) -> |_index, resource| {
        (get(resource, ["uid"]) ?? null) != null || (get(resource, ["name"]) ?? null) != null
    }
    if length(named) == 0 { event = remove!(event, ["resources"]) } else { event.resources = named }
}
# NAN-3304: bronze carries `unmapped` as ONE JSON string, like every other lake
# lane (NAN-3079): the sink infers one Parquet schema per batch, and an object
# here (its `details` free-form) failed it and dropped the whole batch.
# ingest[T] decodes it back before admission.
if is_object(event.unmapped) { event.unmapped = encode_json(event.unmapped) }
ts = from_unix_timestamp!(time_ms, unit: "milliseconds")
. = { "event": event, "timestamp": format_timestamp!(ts, "%Y-%m-%d %H:%M:%S%.3f"), "source_type": "audit" }
"#;

/// The second NAN-3304 lane (#5695: null-only `src_endpoint` / `actor.user`
/// anchored), admitting API Activity 6003 only. Frozen: the release bases
/// built with it (`selected-parser-zero-nan3304-v2.js`,
/// `selected-parser-zero-nan3339-v2.js`) stay verifiable as builder output;
/// never derive a new base from it. It REFUSES the NAN-3460 Authentication /
/// Account Change rows — the reason a tenant's base must carry the current
/// lane before its control plane writes them.
pub const AUDIT_LANE_VRL_NAN3304_V2: &str = r#"# NAN-2999: platform audit (OCSF API Activity 6003) delivered by nano-main.
raw = to_string(.message) ?? ""
parsed, parse_err = parse_json(raw)
if parse_err != null || !is_object(parsed) {
    log("platform audit line is not a JSON object; refused", level: "warn", rate_limit_secs: 60)
    abort
}
event = object!(parsed)
tenant_id = downcase(to_string(%tenant_id) ?? "")
event_tenant = downcase(to_string(event.metadata.tenant_uid) ?? "")
event_uid = downcase(to_string(event.metadata.uid) ?? "")
time_ms = to_int(event.time) ?? 0
admitted = tenant_id != "" && event_tenant == tenant_id
admitted = admitted && (to_int(event.class_uid) ?? 0) == 6003
admitted = admitted && (to_string(event.metadata.log_name) ?? "") == "audit"
admitted = admitted && (to_string(event.metadata.product.name) ?? "") == "nano"
admitted = admitted && match(event_uid, r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
admitted = admitted && time_ms > 0
if !admitted {
    log("platform audit line is not this tenant's API Activity event; refused", level: "warn", rate_limit_secs: 60)
    abort
}
# NAN-3304: ingest[T] admits a bronze row with its null members dropped (the
# Parquet form carries no nulls), then validates OCSF 1.9. The mirror says
# "unknown" with nulls (`src_endpoint: {"ip": null}`, `actor.user: {"name":
# null, "uid": null}`): a null-valued key passes the at-least-one constraint
# on gen1, but the lake saw `{}` and refused the row. Anchor each such object
# as gen1's publisher does for an audit without a client (the emitting
# service, marked in `unmapped`), and drop an `actor.user` or `resources[]`
# entry that names no one (`unmapped` keeps the nano-native values).
service = to_string(event.api.service.name) ?? ""
if service == "" || strlen(service) > 256 || match(service, r'[[:cntrl:]]') { service = "nano" }
markable = is_object(event.unmapped) || event.unmapped == null
src_anchored = false
for_each(["ip", "uid", "name", "hostname", "svc_name", "instance_uid", "interface_uid", "interface_name", "domain"]) -> |_index, key| {
    if (get(event.src_endpoint, [key]) ?? null) != null { src_anchored = true }
}
if !src_anchored && markable {
    event.unmapped.nano_src_endpoint = "synthesized:emitting_service"
    event.src_endpoint = { "name": service, "svc_name": service, "type": "Other", "type_id": 99 }
}
user_anchored = false
for_each(["account", "name", "uid"]) -> |_index, key| {
    if (get(event.actor.user, [key]) ?? null) != null { user_anchored = true }
}
if !user_anchored && is_object(event.actor) {
    event.actor = remove!(object!(event.actor), ["user"])
}
actor_anchored = false
for_each(["process", "user", "iam_role", "invoked_by", "session", "application", "app_name", "app_uid"]) -> |_index, key| {
    if (get(event.actor, [key]) ?? null) != null { actor_anchored = true }
}
if !actor_anchored && markable {
    event.unmapped.nano_actor = "synthesized:emitting_service"
    event.actor = merge(object(event.actor) ?? {}, { "app_name": service })
}
if is_array(event.resources) {
    named = filter(array!(event.resources)) -> |_index, resource| {
        (get(resource, ["uid"]) ?? null) != null || (get(resource, ["name"]) ?? null) != null
    }
    if length(named) == 0 { event = remove!(event, ["resources"]) } else { event.resources = named }
}
# NAN-3304: bronze carries `unmapped` as ONE JSON string, like every other lake
# lane (NAN-3079): the sink infers one Parquet schema per batch, and an object
# here (its `details` free-form) failed it and dropped the whole batch.
# ingest[T] decodes it back before admission.
if is_object(event.unmapped) { event.unmapped = encode_json(event.unmapped) }
ts = from_unix_timestamp!(time_ms, unit: "milliseconds")
. = { "event": event, "timestamp": format_timestamp!(ts, "%Y-%m-%d %H:%M:%S%.3f"), "source_type": "audit" }
"#;

/// The first NAN-3304 lane VRL (`unmapped` as one JSON string; null-only
/// `src_endpoint` / `actor.user` left as they came, which the lake refuses).
/// Frozen: the release base built with it (`selected-parser-zero-nan3304.js`,
/// and `selected-parser-zero-nan3339.js` derived from it) stays verifiable as
/// builder output; never derive a new base from it.
#[cfg(test)]
pub(crate) const AUDIT_LANE_VRL_NAN3304: &str = r#"# NAN-2999: platform audit (OCSF API Activity 6003) delivered by nano-main.
raw = to_string(.message) ?? ""
parsed, parse_err = parse_json(raw)
if parse_err != null || !is_object(parsed) {
    log("platform audit line is not a JSON object; refused", level: "warn", rate_limit_secs: 60)
    abort
}
event = object!(parsed)
tenant_id = downcase(to_string(%tenant_id) ?? "")
event_tenant = downcase(to_string(event.metadata.tenant_uid) ?? "")
event_uid = downcase(to_string(event.metadata.uid) ?? "")
time_ms = to_int(event.time) ?? 0
admitted = tenant_id != "" && event_tenant == tenant_id
admitted = admitted && (to_int(event.class_uid) ?? 0) == 6003
admitted = admitted && (to_string(event.metadata.log_name) ?? "") == "audit"
admitted = admitted && (to_string(event.metadata.product.name) ?? "") == "nano"
admitted = admitted && match(event_uid, r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
admitted = admitted && time_ms > 0
if !admitted {
    log("platform audit line is not this tenant's API Activity event; refused", level: "warn", rate_limit_secs: 60)
    abort
}
# NAN-3304: bronze carries `unmapped` as ONE JSON string, like every other lake
# lane (NAN-3079): the sink infers one Parquet schema per batch, and an object
# here (its `details` free-form) failed it and dropped the whole batch.
# ingest[T] decodes it back before admission.
if is_object(event.unmapped) { event.unmapped = encode_json(event.unmapped) }
ts = from_unix_timestamp!(time_ms, unit: "milliseconds")
. = { "event": event, "timestamp": format_timestamp!(ts, "%Y-%m-%d %H:%M:%S%.3f"), "source_type": "audit" }
"#;

/// The NAN-2999 lane VRL, before NAN-3304 (`unmapped` left an object). Frozen:
/// the release bases built with it (`selected-parser-zero-audit.js`,
/// `selected-parser-zero-nan3176-audit.js`, `selected-parser-zero-nan3242.js`)
/// stay verifiable as builder output; never derive a new base from it.
#[cfg(test)]
pub(crate) const AUDIT_LANE_VRL_NAN2999: &str = r#"# NAN-2999: platform audit (OCSF API Activity 6003) delivered by nano-main.
raw = to_string(.message) ?? ""
parsed, parse_err = parse_json(raw)
if parse_err != null || !is_object(parsed) {
    log("platform audit line is not a JSON object; refused", level: "warn", rate_limit_secs: 60)
    abort
}
event = object!(parsed)
tenant_id = downcase(to_string(%tenant_id) ?? "")
event_tenant = downcase(to_string(event.metadata.tenant_uid) ?? "")
event_uid = downcase(to_string(event.metadata.uid) ?? "")
time_ms = to_int(event.time) ?? 0
admitted = tenant_id != "" && event_tenant == tenant_id
admitted = admitted && (to_int(event.class_uid) ?? 0) == 6003
admitted = admitted && (to_string(event.metadata.log_name) ?? "") == "audit"
admitted = admitted && (to_string(event.metadata.product.name) ?? "") == "nano"
admitted = admitted && match(event_uid, r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
admitted = admitted && time_ms > 0
if !admitted {
    log("platform audit line is not this tenant's API Activity event; refused", level: "warn", rate_limit_secs: 60)
    abort
}
ts = from_unix_timestamp!(time_ms, unit: "milliseconds")
. = { "event": event, "timestamp": format_timestamp!(ts, "%Y-%m-%d %H:%M:%S%.3f"), "source_type": "audit" }
"#;

fn lane_file(vrl: &str) -> String {
    format!(
        "# NAN-2999: platform audit lane (plumbing; no source parser). Lean tenants'\n\
         # platform audit, delivered by nano-main as the `audit` source, becomes\n\
         # searchable as metadata.log_source = audit. Platform-owned: DO NOT EDIT.\n\
         [transforms.{AUDIT_PREPARE}]\n\
         type = \"remap\"\n\
         inputs = [\"source_router.{AUDIT_ROUTE}\"]\n\
         drop_on_abort = true\n\
         drop_on_error = true\n\
         source = '''\n{vrl}'''\n"
    )
}

fn base_error(what: &str) -> TenantBundleError {
    TenantBundleError::Base(format!("platform audit lane: {what}"))
}

/// Insert `item` into the `[...]` list on `line` (sorted when `sorted`,
/// else appended). Refuses a line without exactly one list or that already
/// carries the item.
fn add_list_item(line: &str, item: &str, sorted: bool, what: &str) -> Result<String, TenantBundleError> {
    let (open, close) = (line.find('['), line.rfind(']'));
    let (Some(open), Some(close)) = (open, close) else { return Err(base_error(&format!("{what} list is absent"))) };
    if line[open + 1..].contains('[') || close < open {
        return Err(base_error(&format!("{what} list is not a flat list")));
    }
    let quoted = serde_json::to_string(item).expect("string");
    let mut items: Vec<String> = line[open + 1..close]
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    if items.contains(&quoted) {
        return Err(base_error(&format!("{what} already carries {item}")));
    }
    items.push(quoted);
    if sorted {
        items.sort_by_key(|value| serde_json::from_str::<String>(value).unwrap_or_default());
    }
    Ok(format!("{}{}{}", &line[..=open], items.join(", "), &line[close..]))
}

fn edit_unique_line(
    text: &str,
    matches: impl Fn(&str) -> bool,
    edit: impl Fn(&str) -> Result<String, TenantBundleError>,
    what: &str,
) -> Result<String, TenantBundleError> {
    let lines: Vec<&str> = text.split('\n').collect();
    let hits: Vec<usize> = lines.iter().enumerate().filter(|(_, l)| matches(l)).map(|(i, _)| i).collect();
    if hits.len() != 1 {
        return Err(base_error(&format!("expected one {what} line, found {}", hits.len())));
    }
    let mut out: Vec<String> = lines.iter().map(|l| l.to_string()).collect();
    out[hits[0]] = edit(lines[hits[0]])?;
    Ok(out.join("\n"))
}

/// Whether `base` already carries the audit lane.
pub fn has_platform_audit_lane(base: &BundleTree) -> bool {
    base.files.contains_key(AUDIT_LANE_FILE)
}

/// Derive the base with the platform audit lane: the HEC delivery token and
/// normalizer allowlist (`hec_sources` gains `audit`, so the Worker's pins
/// and the control DB's enrollment carry it), the router output plus the
/// `generic` exclusion, the lake sink input, and the lane file. Refuses a
/// base whose wiring points differ from the known shape, or one that already
/// carries the lane.
pub fn add_platform_audit_lane(base: &BundleTree) -> Result<BundleTree, TenantBundleError> {
    add_platform_audit_lane_with(base, AUDIT_LANE_VRL)
}

/// [`add_platform_audit_lane`] with an explicit lane VRL (tests re-derive the
/// historical release bases with [`AUDIT_LANE_VRL_NAN2999`]).
pub(crate) fn add_platform_audit_lane_with(base: &BundleTree, vrl: &str) -> Result<BundleTree, TenantBundleError> {
    if has_platform_audit_lane(base) {
        return Err(base_error("the base already carries the lane"));
    }
    let mut tree = base.clone();

    let hec = tree.text(HEC_FILE)?.to_string();
    let hec = edit_unique_line(&hec, |l| l.starts_with("valid_tokens = ["),
        |l| add_list_item(l, HEC_TOKEN, true, "HEC token"), "HEC valid_tokens")?;
    let hec = edit_unique_line(&hec,
        |l| l.starts_with("if !includes([") && l.ends_with("], authorized_source) { abort }"),
        |l| add_list_item(l, AUDIT_SLUG, true, "HEC allowlist"), "HEC allowlist")?;
    tree.put(HEC_FILE, hec.into_bytes());

    let router = tree.text(ROUTER_FILE)?.to_string();
    let route_line = format!("{AUDIT_ROUTE} = '.source_type == \"{AUDIT_SLUG}\"'");
    if router.contains(&format!("'.source_type == \"{AUDIT_SLUG}\"'")) {
        return Err(base_error("the router already routes audit"));
    }
    let router = edit_unique_line(&router, |l| l.starts_with("generic = '!includes(["), |l| {
        // The exclusion list is the router's `[...]` before `, .source_type)`.
        let (head, tail) = l.split_once("], .source_type)").ok_or_else(|| base_error("generic lane shape"))?;
        let edited = add_list_item(&format!("{head}]"), AUDIT_SLUG, false, "generic exclusion")?;
        Ok(format!("{route_line}\n{edited}, .source_type){tail}"))
    }, "generic lane")?;
    tree.put(ROUTER_FILE, router.into_bytes());

    let sink = tree.text(LAKE_SINK_FILE)?.to_string();
    let lines: Vec<&str> = sink.split('\n').collect();
    let section = lines.iter().position(|l| *l == "[transforms.ocsf_lake_storage_prepare]")
        .ok_or_else(|| base_error("lake sink storage-prepare section is absent"))?;
    let inputs = (section + 1..lines.len()).take_while(|i| !lines[*i].starts_with('['))
        .find(|i| lines[*i].starts_with("inputs = ["))
        .ok_or_else(|| base_error("lake sink storage-prepare inputs are absent"))?;
    let mut out: Vec<String> = lines.iter().map(|l| l.to_string()).collect();
    out[inputs] = add_list_item(lines[inputs], AUDIT_PREPARE, false, "lake sink inputs")?;
    tree.put(LAKE_SINK_FILE, out.join("\n").into_bytes());

    tree.put(AUDIT_LANE_FILE, lane_file(vrl).into_bytes());
    Ok(tree)
}

/// NAN-3304: bring a base that already carries the platform audit lane up to
/// the current lane, replacing ONLY the lane file (its four wiring points are
/// unchanged by every lane revision). Refuses a base without the lane, or one
/// whose lane is already current, so a release base is never rebuilt
/// byte-identical under a new name.
pub fn upgrade_platform_audit_lane(base: &BundleTree) -> Result<BundleTree, TenantBundleError> {
    upgrade_platform_audit_lane_with(base, AUDIT_LANE_VRL)
}

/// [`upgrade_platform_audit_lane`] to an explicit lane VRL (tests re-derive
/// the historical release bases with the frozen lane revisions).
pub fn upgrade_platform_audit_lane_with(base: &BundleTree, vrl: &str) -> Result<BundleTree, TenantBundleError> {
    if !has_platform_audit_lane(base) {
        return Err(base_error("the base does not carry the lane; add it instead"));
    }
    let current = lane_file(vrl);
    if base.files.get(AUDIT_LANE_FILE).map(Vec::as_slice) == Some(current.as_bytes()) {
        return Err(base_error("the base already carries the current lane"));
    }
    let mut tree = base.clone();
    tree.put(AUDIT_LANE_FILE, current.into_bytes());
    Ok(tree)
}

/// Run one VRL program over a Vector event carrying `%tenant_id` and
/// `%source_type = audit` metadata (the embedded VRL runtime).
fn run_vrl(source: &str, value: serde_json::Value, tenant: &str) -> Result<serde_json::Value, String> {
    use vrl::compiler::runtime::Runtime;
    use vrl::compiler::state::RuntimeState;
    use vrl::compiler::{TargetValue, TimeZone};
    use vrl::value::{Secrets, Value};
    let program = crate::parsers::vrl_guard::compile(source, &vrl::stdlib::all())
        .map_err(|e| e.render(source))?
        .program;
    let mut metadata = vrl::value::ObjectMap::new();
    metadata.insert("tenant_id".into(), Value::from(tenant));
    metadata.insert("source_type".into(), Value::from(AUDIT_SLUG));
    let mut target = TargetValue { value: Value::from(value), metadata: Value::Object(metadata), secrets: Secrets::new() };
    Runtime::new(RuntimeState::default())
        .resolve(&mut target, &program, &TimeZone::Local)
        .map_err(|e| e.to_string())?;
    target.value.try_into().map_err(|_| "VRL output is not JSON".to_string())
}

/// The base's own `ocsf_lake_storage_prepare` VRL (the bronze sink's input),
/// with the renderer's shard interpolation resolved to one shard.
pub(crate) fn storage_prepare_vrl(tree: &BundleTree) -> Result<String, String> {
    let text = tree.text(LAKE_SINK_FILE).map_err(|e| e.to_string())?;
    // Resolve every `${VAR:-default}` interpolation to its default, as Vector
    // would with the variable unset (one bronze shard, default knobs).
    let defaults = regex::Regex::new(r"\$\{[A-Z0-9_]+:-([^}]*)\}").expect("static regex");
    let resolved = defaults.replace_all(text, "$1");
    let doc: toml::Table = resolved.parse().map_err(|e| format!("{e}"))?;
    doc.get("transforms").and_then(|t| t.get("ocsf_lake_storage_prepare")).and_then(|t| t.get("source"))
        .and_then(|s| s.as_str()).map(str::to_string)
        .ok_or_else(|| "lake sink storage-prepare source is absent".to_string())
}

/// The exact lake row a cell's Vector writes to bronze for one delivered
/// `audit` line (the lane's VRL, then the base's lake-sink prepare), run with
/// the embedded VRL runtime. For contract tests of the delivery path (the
/// row `ingest[T]` then admits into signed parts); `Err` when the lane or the
/// sink refuses the line.
pub fn lake_row(base_with_lane: &BundleTree, line: &str, tenant_id: &str) -> Result<serde_json::Value, String> {
    let lane: toml::Table = base_with_lane.text(AUDIT_LANE_FILE).map_err(|e| e.to_string())?
        .parse().map_err(|e| format!("{e}"))?;
    let source = lane.get("transforms").and_then(|t| t.get(AUDIT_PREPARE)).and_then(|t| t.get("source"))
        .and_then(|s| s.as_str()).ok_or_else(|| "lane source is absent".to_string())?;
    let laned = run_vrl(source, serde_json::json!({"message": line, "source_type": AUDIT_SLUG}), tenant_id)?;
    run_vrl(&storage_prepare_vrl(base_with_lane)?, laned, tenant_id)
}

#[cfg(test)]
mod tests {
    use super::super::{archive, overlay};
    use super::*;
    use vrl::compiler::compile;

    const BASES: [(&str, &[u8]); 4] = [
        ("v1", include_bytes!("testdata/platform-base.tar.gz")),
        ("collector-v2", include_bytes!("testdata/platform-base-collector-v2.tar.gz")),
        ("zero", include_bytes!("testdata/platform-base-zero.tar.gz")),
        ("zero-collector-v2", include_bytes!("testdata/platform-base-zero-collector-v2.tar.gz")),
    ];
    const TENANT: &str = "11111111-1111-4111-8111-111111111111";
    const OTHER: &str = "22222222-2222-4222-8222-222222222222";
    const EVENT_ID: &str = "018f6a1e-0d2b-7c3a-9e4f-5a6b7c8d9e0f";

    /// The line the control plane delivers: `AuditEvent::to_ocsf_event_for_lake`.
    fn line(tenant: &str) -> String {
        let event = crate::audit::AuditEvent::builder(crate::audit::AuditSource::Detection, "rule_created")
            .actor(Some(uuid::Uuid::nil()), Some("dan@nano.rs".to_string()))
            .resource("detection_rule", Some(uuid::Uuid::nil()), Some("Suspicious Login".to_string()))
            .success(true)
            .build();
        let at = chrono::DateTime::parse_from_rfc3339("2026-09-28T12:00:00.123Z").unwrap().with_timezone(&chrono::Utc);
        serde_json::to_string(&event.to_ocsf_event_for_lake(at, uuid::Uuid::parse_str(EVENT_ID).unwrap(), tenant)).unwrap()
    }

    #[test]
    fn the_lane_vrl_compiles() {
        compile(AUDIT_LANE_VRL, &vrl::stdlib::all()).unwrap();
    }

    #[test]
    fn every_base_gains_exactly_the_four_wiring_edits_and_the_lane_file() {
        for (name, packed) in BASES {
            let base = archive::unpack(packed).unwrap();
            let with = add_platform_audit_lane(&base).unwrap_or_else(|e| panic!("{name}: {e}"));
            // hec_sources gains `audit` (so the Worker pins and enrollment carry it).
            let mut expected = overlay::platform_slugs(&base).unwrap();
            expected.push(AUDIT_SLUG.into());
            expected.sort();
            assert_eq!(overlay::platform_slugs(&with).unwrap(), expected, "{name}");
            let hec = with.text(HEC_FILE).unwrap();
            assert!(hec.lines().any(|l| l.starts_with("if !includes([") && l.contains("\"audit\"")), "{name}: allowlist");
            let router = with.text(ROUTER_FILE).unwrap();
            assert!(router.contains("nano_platform_audit = '.source_type == \"audit\"'"), "{name}");
            let generic = router.lines().find(|l| l.starts_with("generic = ")).unwrap();
            assert!(generic.contains("\"audit\"], .source_type)"), "{name}: generic lane excludes audit: {generic}");
            assert!(with.text(LAKE_SINK_FILE).unwrap().contains("\"nano_platform_audit_prepare\"]"), "{name}");
            // Everything else is byte-identical; only the lane file is new.
            let changed: std::collections::BTreeSet<&str> = with.files.keys()
                .filter(|p| base.files.get(*p) != with.files.get(*p)).map(String::as_str).collect();
            assert_eq!(changed, std::collections::BTreeSet::from([HEC_FILE, AUDIT_LANE_FILE, LAKE_SINK_FILE, ROUTER_FILE]), "{name}");
            // The lane file is valid TOML wiring the router output to the sink.
            let lane: toml::Table = with.text(AUDIT_LANE_FILE).unwrap().parse().unwrap();
            assert_eq!(lane["transforms"][AUDIT_PREPARE]["inputs"][0].as_str(), Some("source_router.nano_platform_audit"));
            assert_eq!(lane["transforms"][AUDIT_PREPARE]["source"].as_str(), Some(AUDIT_LANE_VRL));
            // Idempotency is refused, not silently doubled.
            assert!(add_platform_audit_lane(&with).is_err(), "{name}");
            // The tenant overlay still builds on it and strips back to it, and
            // no tenant parser may route `audit`.
            let (candidate, _) = overlay::apply_overlay(&with, &[]).unwrap();
            assert_eq!(archive::pack(&candidate).unwrap(), archive::pack(&with).unwrap(), "{name}");
            let platform: std::collections::BTreeSet<String> = overlay::platform_slugs(&with).unwrap().into_iter().collect();
            assert!(overlay::tenant_slug_allowed(&with, &platform, AUDIT_SLUG).is_err(), "{name}: audit is platform-only");
        }
    }

    /// Delivered line → lane → the base's own lake-sink prepare: the lake row
    /// is the tenant's API Activity event under `log_source = audit`, the
    /// audit event id stays its `metadata.uid` (deterministic replays), and
    /// the gen1 fields analysts pivot on are intact.
    #[test]
    fn a_delivered_line_becomes_the_tenants_audit_row() {
        for (name, packed) in BASES {
            let with = add_platform_audit_lane(&archive::unpack(packed).unwrap()).unwrap();
            let delivered = line(TENANT);
            let laned = run_vrl(AUDIT_LANE_VRL, serde_json::json!({"message": delivered, "source_type": "audit"}), TENANT).unwrap();
            assert_eq!(laned["source_type"], "audit");
            assert!(laned["timestamp"].as_str().unwrap().starts_with("2026-09-28"), "{laned}");
            let row = run_vrl(&storage_prepare_vrl(&with).unwrap(), laned, TENANT).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(row["metadata"]["log_source"], "audit", "{name}");
            assert_eq!(row["metadata"]["tenant_uid"], TENANT, "{name}");
            assert_eq!(row["metadata"]["uid"], EVENT_ID, "{name}: the audit id is the event uid");
            assert_eq!(row["class_uid"], 6003, "{name}");
            assert_eq!(row["api"]["operation"], "rule_created", "{name}");
            assert_eq!(row["actor"]["user"]["name"], "dan@nano.rs", "{name}");
            assert_eq!(row["metadata"]["product"]["name"], "nano", "{name}");
        }
    }

    /// NAN-3304: the bronze sink encodes each Vector batch as ONE Parquet file
    /// whose schema Arrow infers from that batch. Every other lake lane carries
    /// `unmapped` as a JSON string (NAN-3079); an audit row carrying it as an
    /// object (with `details` a free-form value) failed the inference, and
    /// Vector dropped the whole batch: live, 2000 delivered + acked audit rows
    /// never became searchable (`parquet_schema_generation_failed`, "Events
    /// dropped"), taking co-batched rows of other sources with them.
    #[test]
    fn audit_rows_share_one_bronze_parquet_schema_with_every_other_lane() {
        let with_details = |details: serde_json::Value| {
            let mut v: serde_json::Value = serde_json::from_str(&line(TENANT)).unwrap();
            v["unmapped"]["details"] = details;
            serde_json::to_string(&v).unwrap()
        };
        // A generic-lane row as `OCSF_PREPARE_VRL` + NAN-3079 hands it to the sink.
        let generic = serde_json::json!({"class_uid": 4001, "time": 1_790_000_000_000_i64,
            "metadata": {"log_source": "conduit_proxy", "uid": "g1"}, "unmapped": "{\"raw_event\":\"{}\"}"});
        for (name, packed) in BASES {
            let with = add_platform_audit_lane(&archive::unpack(packed).unwrap()).unwrap();
            let audit = |message: String| lake_row(&with, &message, TENANT).unwrap_or_else(|e| panic!("{name}: {e}"));
            let rows = [
                audit(with_details(serde_json::json!({"templates_suspended": 2, "reason": "x"}))),
                audit(with_details(serde_json::json!("free text"))),
                audit(line(TENANT)),
                generic.clone(),
            ];
            for row in &rows {
                assert!(row["unmapped"].is_string(), "{name}: bronze unmapped is one JSON string: {}", row["unmapped"]);
            }
            for batch in [&rows[..], &rows[..2], &rows[2..]] {
                arrow_json::reader::infer_json_schema_from_iterator(batch.iter().cloned().map(Ok))
                    .unwrap_or_else(|e| panic!("{name}: one batch, one Parquet schema: {e}"));
            }
            // ingest[T] decodes it back: parts and search see the gen1 object.
            let mut decoded = rows[0].clone();
            nanosiem_lake_worker::bronze::decode_bronze_unmapped(&mut decoded);
            assert_eq!(decoded["unmapped"]["details"]["templates_suspended"], 2, "{name}");
            assert!(decoded["unmapped"].get("action").is_none(), "{name}: NAN-3460 no mapped field in unmapped");
        }
    }

    /// NAN-3304: a base carrying the NAN-2999 lane is upgraded by swapping
    /// ONLY the lane file; a lane-less or already-current base is refused.
    #[test]
    fn a_nan2999_lane_base_upgrades_by_its_lane_file_alone() {
        for (name, packed) in BASES {
            let base = archive::unpack(packed).unwrap();
            assert!(upgrade_platform_audit_lane(&base).is_err(), "{name}: no lane to upgrade");
            let old = add_platform_audit_lane_with(&base, AUDIT_LANE_VRL_NAN2999).unwrap();
            let upgraded = upgrade_platform_audit_lane(&old).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(archive::pack(&upgraded).unwrap(), archive::pack(&add_platform_audit_lane(&base).unwrap()).unwrap(),
                "{name}: upgrading equals deriving fresh");
            let changed: Vec<&String> = upgraded.files.keys().filter(|p| old.files.get(*p) != upgraded.files.get(*p)).collect();
            assert_eq!(changed, [&AUDIT_LANE_FILE.to_string()], "{name}");
            assert!(upgrade_platform_audit_lane(&upgraded).is_err(), "{name}: already current");
        }
    }

    /// The row as `ingest[T]` validates it: bronze (Parquet) drops every null
    /// member, `unmapped` is decoded back, `time` is epoch ms (bronze.rs +
    /// iceberg.rs `normalize_event`). The lake-worker test
    /// `nan3304_audit_null_anchor_admission` runs the real admission.
    fn as_the_lake_admits(row: &serde_json::Value) -> serde_json::Value {
        fn strip(value: &mut serde_json::Value) {
            match value {
                serde_json::Value::Object(map) => {
                    map.retain(|_, member| !member.is_null());
                    map.values_mut().for_each(strip);
                }
                serde_json::Value::Array(items) => items.iter_mut().for_each(strip),
                _ => {}
            }
        }
        let mut event = row.clone();
        // The sink's `encoding.except_fields`.
        event.as_object_mut().unwrap().remove("_nano_bronze_partition");
        // The platform `metadata.nano_*` stamps are set aside while OCSF
        // validation runs (iceberg.rs `take_platform_metadata_stamps`).
        if let Some(metadata) = event["metadata"].as_object_mut() {
            metadata.retain(|key, _| !key.starts_with("nano_"));
        }
        strip(&mut event);
        if let Some(text) = event["unmapped"].as_str() {
            event["unmapped"] = serde_json::from_str(text).unwrap();
        }
        let time = chrono::DateTime::parse_from_rfc3339(event["time"].as_str().unwrap()).unwrap();
        event["time"] = serde_json::json!(time.timestamp_millis());
        event
    }

    /// NAN-3304 (live 2026-10-08 18:20Z / 18:30Z, after the first lane fix):
    /// the control plane's mirror says "unknown" with nulls,
    /// `src_endpoint: {"ip": null}` and `actor.user: {"name": null, "uid":
    /// null}` (54% of the load-test tenant's audit rows). Bronze drops the nulls, the lake
    /// validated `{}` and refused the row: "src_endpoint: at least one of [ip,
    /// uid, name, …] is required; actor.user: at least one of [account, name,
    /// uid] is required". The lane anchors those objects the way gen1's
    /// publisher does for an audit without a client, so every such row is a
    /// valid OCSF 1.9 API Activity once the lake sees it.
    #[test]
    fn null_only_endpoint_and_actor_rows_survive_the_lakes_ocsf_validation() {
        let base = |line: &dyn Fn(&mut serde_json::Value)| {
            let event = crate::audit::AuditEvent::builder(crate::audit::AuditSource::Identity, "identity_sync_completed")
                .success(true)
                .build();
            let at = chrono::DateTime::parse_from_rfc3339("2026-10-08T18:19:53.538Z").unwrap().with_timezone(&chrono::Utc);
            let mut v = event.to_ocsf_event_for_lake(at, uuid::Uuid::parse_str(EVENT_ID).unwrap(), TENANT);
            line(&mut v);
            serde_json::to_string(&v).unwrap()
        };
        let session = |v: &mut serde_json::Value| v["actor"]["session"] = serde_json::json!({"uid": EVENT_ID});
        let cases: [(&str, String); 6] = [
            ("system actor, no client", base(&|_| {})),
            ("session refresh (no user, no client)", base(&session)),
            ("no src_endpoint at all", base(&|v| { v.as_object_mut().unwrap().remove("src_endpoint"); })),
            ("named user from a known client", base(&|v| {
                v["actor"]["user"] = serde_json::json!({"uid": EVENT_ID, "name": "Dan", "email_addr": "dan@nano.rs"});
                v["src_endpoint"]["ip"] = serde_json::json!("10.1.2.3");
            })),
            ("user with only a credential", base(&|v| v["actor"]["user"]["credential_uid"] = serde_json::json!(EVENT_ID))),
            ("type-only resource", base(&|v| v["resources"] = serde_json::json!([{"uid": null, "name": null, "type": "case_settings"}]))),
        ];
        for (name, packed) in BASES {
            let with = add_platform_audit_lane(&archive::unpack(packed).unwrap()).unwrap();
            for (case, line) in &cases {
                let row = lake_row(&with, line, TENANT).unwrap_or_else(|e| panic!("{name} {case}: {e}"));
                let lake = as_the_lake_admits(&row);
                let verdict = crate::parsers::validate_ocsf_event(&lake);
                assert!(verdict.valid, "{name} {case}: {:?}\n{lake:#}", verdict.errors);
                assert_eq!(lake["metadata"]["uid"], EVENT_ID, "{name} {case}");
                let marked_endpoint = lake["unmapped"].get("nano_src_endpoint").is_some();
                if *case == "named user from a known client" {
                    assert_eq!(lake["src_endpoint"], serde_json::json!({"ip": "10.1.2.3"}), "{name}: a real client is untouched");
                    assert_eq!(lake["actor"]["user"]["name"], "Dan", "{name}");
                    assert!(!marked_endpoint && lake["unmapped"].get("nano_actor").is_none(), "{name}: nothing synthesized");
                } else {
                    assert_eq!(lake["src_endpoint"], serde_json::json!(
                        {"name": "identity", "svc_name": "identity", "type": "Other", "type_id": 99}), "{name} {case}");
                    assert_eq!(lake["unmapped"]["nano_src_endpoint"], "synthesized:emitting_service", "{name} {case}");
                    assert!(lake["actor"].get("user").is_none(), "{name} {case}: an actor.user naming no one is dropped");
                }
                // Only the markers: mapped fields are not repeated (NAN-3460).
                assert!(lake["unmapped"].get("action").is_none(), "{name} {case}");
            }
            // Session refresh keeps its real anchor; only a nameless system
            // actor is attributed to the emitting service.
            let lake = |i: usize| as_the_lake_admits(&lake_row(&with, &cases[i].1, TENANT).unwrap());
            assert_eq!(lake(1)["actor"], serde_json::json!({"session": {"uid": EVENT_ID}}), "{name}");
            assert!(lake(1)["unmapped"].get("nano_actor").is_none(), "{name}");
            assert!(lake(5).get("resources").is_none(), "{name}: a resource naming nothing is dropped");
            for i in [0, 2, 4, 5] {
                assert_eq!(lake(i)["actor"], serde_json::json!({"app_name": "identity"}), "{name} {}", cases[i].0);
                assert_eq!(lake(i)["unmapped"]["nano_actor"], "synthesized:emitting_service", "{name}");
            }
        }
        // The release base the tenant runs (first NAN-3304 lane) refuses them:
        // this is the live failure.
        let frozen = run_vrl(AUDIT_LANE_VRL_NAN3304, serde_json::json!({"message": cases[1].1}), TENANT).unwrap();
        let mut event = frozen["event"].clone();
        event["time"] = serde_json::json!(chrono::DateTime::from_timestamp_millis(event["time"].as_i64().unwrap()).unwrap().to_rfc3339());
        let lake = as_the_lake_admits(&event);
        let errors: Vec<String> = crate::parsers::validate_ocsf_event(&lake).errors.into_iter().map(|e| e.attribute_path).collect();
        assert_eq!(errors, ["actor.user", "src_endpoint"], "the first NAN-3304 lane hands the lake `{{}}`");
    }

    #[test]
    fn foreign_or_non_audit_lines_never_land_as_audit() {
        let ok = |message: String| run_vrl(AUDIT_LANE_VRL, serde_json::json!({"message": message}), TENANT);
        ok(line(TENANT)).unwrap();
        // Another tenant's audit row, delivered into this tenant's cell.
        assert!(ok(line(OTHER)).is_err(), "another tenant's row is refused");
        let mutate = |f: &dyn Fn(&mut serde_json::Value)| {
            let mut v: serde_json::Value = serde_json::from_str(&line(TENANT)).unwrap();
            f(&mut v);
            serde_json::to_string(&v).unwrap()
        };
        for (what, message) in [
            ("not JSON", "rule_created by dan".to_string()),
            ("not an object", "[1,2]".to_string()),
            ("another class", mutate(&|v| v["class_uid"] = serde_json::json!(2004))),
            ("not an audit log", mutate(&|v| v["metadata"]["log_name"] = serde_json::json!("security"))),
            ("not nano", mutate(&|v| v["metadata"]["product"]["name"] = serde_json::json!("acme"))),
            ("no uuid uid", mutate(&|v| v["metadata"]["uid"] = serde_json::json!("x"))),
            ("no time", mutate(&|v| v["time"] = serde_json::json!(0))),
            ("no tenant", mutate(&|v| { v["metadata"].as_object_mut().unwrap().remove("tenant_uid"); })),
        ] {
            assert!(ok(message).is_err(), "{what}");
        }
        // A cell without a tenant identity refuses everything.
        assert!(run_vrl(AUDIT_LANE_VRL, serde_json::json!({"message": line(TENANT)}), "").is_err());
    }

    /// NAN-3460: a login (Authentication 3002) and an account change (Account
    /// Change 3001) cross the lane into a valid OCSF 1.9 lake row of their
    /// class, with or without a known client — and the lane a tenant runs
    /// today (zero-nan3304-v2 / zero-nan3339-v2) refuses them, which is why
    /// the base must roll before the control plane writes them.
    #[test]
    fn authentication_and_account_change_rows_cross_the_lane() {
        let at = chrono::DateTime::parse_from_rfc3339("2026-10-09T12:00:00.000Z").unwrap().with_timezone(&chrono::Utc);
        let user = uuid::Uuid::parse_str(EVENT_ID).unwrap();
        let ocsf = |event: crate::audit::AuditEvent| {
            serde_json::to_string(&event.to_ocsf_event_for_lake_with(at, uuid::Uuid::now_v7(), TENANT, true)).unwrap()
        };
        use crate::audit::{AuditEvent, AuditSource};
        let cases = [
            ("logon from a client", 3002, 1, ocsf(AuditEvent::builder(AuditSource::Auth, "login_success")
                .actor(Some(user), Some("admin@nano.rs".into()))
                .resource("user", Some(user), Some("admin@nano.rs".into()))
                .client(Some("198.51.100.23".into()), Some("Mozilla/5.0".into()))
                .build())),
            ("logoff, no client, id only", 3002, 2, ocsf(AuditEvent::builder(AuditSource::Auth, "logout")
                .actor(Some(user), None)
                .resource("session", None, None)
                .build())),
            ("failed logon", 3002, 1, ocsf(AuditEvent::builder(AuditSource::Auth, "login_failed")
                .actor(None, Some("ghost@example.com".into()))
                .client(Some("192.0.2.9".into()), None)
                .success(false)
                .details(serde_json::json!({"error": "invalid credentials"}))
                .build())),
            ("password change", 3001, 3, ocsf(AuditEvent::builder(AuditSource::Auth, "password_changed")
                .actor(Some(user), None)
                .resource("user", Some(user), None)
                .build())),
        ];
        for (name, packed) in BASES {
            let with = add_platform_audit_lane(&archive::unpack(packed).unwrap()).unwrap();
            for (case, class, activity, line) in &cases {
                let row = lake_row(&with, line, TENANT).unwrap_or_else(|e| panic!("{name} {case}: {e}"));
                let lake = as_the_lake_admits(&row);
                let verdict = crate::parsers::validate_ocsf_event(&lake);
                assert!(verdict.valid, "{name} {case}: {:?}\n{lake:#}", verdict.errors);
                assert_eq!((lake["class_uid"].as_i64(), lake["activity_id"].as_i64()), (Some(*class), Some(*activity)), "{name} {case}");
                assert_eq!(lake["metadata"]["log_source"], "audit", "{name} {case}");
                assert!(lake["user"].is_object(), "{name} {case}");
                assert!(lake["unmapped"].get("nano_src_endpoint").is_none(), "{name} {case}: no synthesized endpoint");
            }
            let logon = as_the_lake_admits(&lake_row(&with, &cases[0].3, TENANT).unwrap());
            assert_eq!(logon["src_endpoint"], serde_json::json!({"ip": "198.51.100.23"}), "{name}");
            assert_eq!(logon["user"]["name"], "admin@nano.rs", "{name}");
            let logoff = as_the_lake_admits(&lake_row(&with, &cases[1].3, TENANT).unwrap());
            assert!(logoff.get("src_endpoint").is_none(), "{name}: an unknown client is absent");
        }
        for (case, _, _, line) in &cases {
            assert!(run_vrl(AUDIT_LANE_VRL_NAN3304_V2, serde_json::json!({"message": line}), TENANT).is_err(),
                "{case}: the frozen lane refuses IAM classes");
        }
    }

    /// NAN-3460 rollout gate: with `NANO_AUDIT_OCSF_IAM_CLASSES` off (the
    /// default), every audit action in every writer shape is API Activity
    /// 6003 and crosses the lane the live lean bases carry
    /// (`AUDIT_LANE_VRL_NAN3304_V2`, zero-nan3304-v2 / zero-nan3339-v2) and the
    /// lake's OCSF 1.9 validation — the de-duplicated `unmapped` and the
    /// metadata search keys included — so the API can ship before the
    /// zero-nan3460 base rolls.
    #[test]
    fn flag_off_rows_cross_the_live_lane_for_every_action() {
        use crate::audit::ocsf_mapping::tests::EVERY_AUDIT_ACTION;
        use crate::audit::{AuditEvent, AuditSource};
        let at = chrono::DateTime::parse_from_rfc3339("2026-10-09T12:00:00.000Z").unwrap().with_timezone(&chrono::Utc);
        let live = upgrade_platform_audit_lane_with(&add_platform_audit_lane(&archive::unpack(BASES[0].1).unwrap()).unwrap(),
            AUDIT_LANE_VRL_NAN3304_V2).unwrap();
        let shapes: [(&str, fn(&str) -> AuditEvent); 4] = [
            ("named actor, user resource, client", |action| {
                let user = uuid::Uuid::now_v7();
                AuditEvent::builder(AuditSource::Auth, action)
                    .actor(Some(user), Some("dan@nano.rs".into()))
                    .resource("user", Some(user), Some("dan@nano.rs".into()))
                    .client(Some("198.51.100.23".into()), Some("Mozilla/5.0".into()))
                    .details(serde_json::json!({"mfa_verified": true}))
                    .build()
            }),
            ("actor id only, no client", |action| {
                AuditEvent::builder(AuditSource::Auth, action).actor(Some(uuid::Uuid::now_v7()), None).build()
            }),
            ("failed by name, api key, type-only resource", |action| {
                AuditEvent::builder(AuditSource::Settings, action)
                    .actor(None, Some("probe@example.com".into()))
                    .api_key(Some(uuid::Uuid::now_v7()), Some("ci-bot".into()))
                    .resource("session", None, None)
                    .client(Some("2001:db8::7".into()), None)
                    .success(false)
                    .build()
            }),
            ("system", |action| AuditEvent::builder(AuditSource::Storage, action).build()),
        ];
        for (action, _, _) in EVERY_AUDIT_ACTION {
            for (shape, build) in &shapes {
                let event = build(action);
                let ocsf = event.to_ocsf_event_for_lake_with(at, uuid::Uuid::now_v7(), TENANT, false);
                assert_eq!(ocsf["class_uid"], 6003, "{action} / {shape}");
                assert_eq!(ocsf["activity_id"], event.ocsf_activity().0, "{action} / {shape}");
                assert_eq!(ocsf["api"]["operation"], *action, "{action} / {shape}");
                assert!(ocsf.get("user").is_none() && ocsf.get("is_mfa").is_none(), "{action} / {shape}: IAM fields while off");
                let row = lake_row(&live, &ocsf.to_string(), TENANT)
                    .unwrap_or_else(|e| panic!("{action} / {shape}: the live lane refused a flag-off row: {e}"));
                let lake = as_the_lake_admits(&row);
                let verdict = crate::parsers::validate_ocsf_event(&lake);
                assert!(verdict.valid, "{action} / {shape}: {:?}\n{lake:#}", verdict.errors);
                assert_eq!(lake["metadata"]["event_code"], *action, "{action} / {shape}");
            }
        }
    }
}
