//! Class-aware entity resolution for OCSF rows, with a UDM fallback (NAN-5271 C).
//!
//! OCSF puts the same concept in different columns depending on the event
//! class: an endpoint event (Sysmon process/file/module/registry) carries the
//! host in `device.hostname` and the user in `actor.user.name`, while an
//! authentication or network event carries them in `src_endpoint.hostname` and
//! `user.name`. Code that read a single fixed key per concept (UDM `src_host`, or
//! one OCSF column) came back empty for whole classes: SOAR alert entities were
//! null, real-time findings were attributed to `unknown`, and grouped dedup
//! collapsed every signal into one bucket.
//!
//! This module is the one place that knows which columns hold each entity for
//! each class. It has two forms that agree with each other:
//!
//! - **Row form**: [`resolve`], [`resolve_all`], [`resolve_field`],
//!   [`primary_entity`]. Each takes a result row (a JSON object). OCSF rows from
//!   ClickHouse `JSONEachRow` have flat dotted keys (`"device.hostname"`); nested
//!   objects are also walked. Each resolver tries the class-correct OCSF columns
//!   for the row's `class_uid`, then falls back to the UDM keys (`src_host`,
//!   `user`, …), so legacy UDM rows and UDM-keyed payloads (for example the
//!   real-time matched-log JSON) keep resolving.
//! - **SQL form**: [`ocsf_sql_expr`] and [`ocsf_primary_entity_sql`]. Each
//!   returns a ClickHouse expression over **physical** `ocsf_logs` columns
//!   only (no `*_unified` ALIAS columns), so it is valid inside a materialized
//!   view body or under an inner `SELECT *`. When a WHERE or GROUP BY needs
//!   skip-index pruning, use the indexed unified column from
//!   [`ocsf_indexed_column`] instead. It holds the same value for every class
//!   in the shipped data.
//!
//! # API for other consumers (for example the prevalence MVs)
//!
//! ```ignore
//! use nanosiem_core::schema::entities::{self, EntityKind};
//! // The host key for a prevalence MV:
//! let host = entities::ocsf_sql_expr(EntityKind::SrcHost);
//! // => multiIf(<endpoint classes>, if(notEmpty(`device.hostname`), ...), ...)
//! // Reading a row back:
//! let host = entities::resolve(&row, EntityKind::SrcHost);
//! ```
//!
//! Do not add per-surface key lists. Extend the tables in this module instead.

use serde_json::{Map, Value};

use crate::sql_hygiene::quote_identifier as escape_identifier;

/// One entity concept. The names follow the SOAR `alert.entities` and UDM vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntityKind {
    /// The host the activity came from or happened on.
    SrcHost,
    /// The remote or target host.
    DestHost,
    /// The acting or primary user.
    User,
    /// The target user (UDM only; OCSF has no reliable column for it).
    DestUser,
    SrcIp,
    DestIp,
    /// The process the event is about: the launched process on Process Activity
    /// (1007), the acting process on every other class.
    Process,
    CommandLine,
    FileHash,
    ProcessHash,
    Domain,
}

impl EntityKind {
    pub const ALL: [EntityKind; 11] = [
        EntityKind::SrcHost,
        EntityKind::DestHost,
        EntityKind::User,
        EntityKind::DestUser,
        EntityKind::SrcIp,
        EntityKind::DestIp,
        EntityKind::Process,
        EntityKind::CommandLine,
        EntityKind::FileHash,
        EntityKind::ProcessHash,
        EntityKind::Domain,
    ];

    /// Map a field name (UDM or OCSF) to the concept it names, so a rule whose
    /// `risk_entity_field` is `src_ip` still resolves on an OCSF row and one
    /// whose field is `src_endpoint.ip` still resolves on a UDM-keyed payload.
    pub fn from_field_name(name: &str) -> Option<EntityKind> {
        let name = name.trim();
        for kind in Self::ALL {
            if udm_keys(kind).contains(&name) {
                return Some(kind);
            }
        }
        for kind in Self::ALL {
            for family in ClassFamily::ALL {
                if ocsf_columns(kind, family).contains(&name) {
                    return Some(kind);
                }
            }
        }
        // Unified materialized columns resolve to their concept too.
        for kind in Self::ALL {
            if ocsf_indexed_column(kind) == Some(name) {
                return Some(kind);
            }
        }
        None
    }
}

/// True when `name` is a UDM entity key or a `*_unified` ALIAS column: an entity
/// name that is never a physical `ocsf_logs` column. The OCSF real-time MV maps
/// such a name to [`ocsf_sql_expr`] instead of interpolating it.
pub fn is_non_physical_entity_name(name: &str) -> bool {
    let name = name.trim();
    EntityKind::ALL
        .iter()
        .any(|&k| udm_keys(k).contains(&name) || ocsf_indexed_column(k) == Some(name))
}

/// Priority order for picking ONE entity per finding (risk attribution, grouped
/// dedup, webhook "who/what"). It mirrors the role order of
/// `SchemaProfile::entity_extraction_order()`: IPs, then users, then hosts, then
/// hashes, then domain.
pub const PRIMARY_ORDER: [EntityKind; 8] = [
    EntityKind::SrcIp,
    EntityKind::DestIp,
    EntityKind::User,
    EntityKind::SrcHost,
    EntityKind::DestHost,
    EntityKind::FileHash,
    EntityKind::ProcessHash,
    EntityKind::Domain,
];

/// OCSF class families whose entity columns differ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassFamily {
    /// System Activity (1xxx) and Windows registry (2010xx). These have no
    /// src/dst sides. The host is `device.hostname` and the user is `actor.user`.
    Endpoint,
    /// Process Activity (1007). Like [`ClassFamily::Endpoint`], but the
    /// top-level `process` is the launched process, and that is the subject.
    ProcessActivity,
    /// Identity & Access Management (3xxx). `user` is the subject, and
    /// `src_endpoint` is the source workstation.
    Iam,
    /// Network Activity (4xxx), including HTTP (4002) and DNS (4003).
    Network,
    /// Application Activity (6xxx), for example CloudTrail API (6003). The
    /// identity is `actor.user`.
    Application,
    /// Unknown or absent `class_uid`: the class-spanning order, which matches
    /// the `*_unified` ALIAS columns.
    Generic,
}

impl ClassFamily {
    pub const ALL: [ClassFamily; 6] = [
        ClassFamily::Endpoint,
        ClassFamily::ProcessActivity,
        ClassFamily::Iam,
        ClassFamily::Network,
        ClassFamily::Application,
        ClassFamily::Generic,
    ];

    pub fn of(class_uid: Option<u64>) -> ClassFamily {
        match class_uid {
            Some(1007) => ClassFamily::ProcessActivity,
            Some(1000..=1999) | Some(201_000..=201_999) => ClassFamily::Endpoint,
            Some(3000..=3999) => ClassFamily::Iam,
            Some(4000..=4999) => ClassFamily::Network,
            Some(6000..=6999) => ClassFamily::Application,
            _ => ClassFamily::Generic,
        }
    }

    /// The SQL predicate selecting this family's rows, or `None` for
    /// [`ClassFamily::Generic`].
    fn sql_predicate(self) -> Option<&'static str> {
        match self {
            ClassFamily::ProcessActivity => Some("class_uid = 1007"),
            ClassFamily::Endpoint => Some(
                "(class_uid BETWEEN 1000 AND 1999 OR class_uid BETWEEN 201000 AND 201999)",
            ),
            ClassFamily::Iam => Some("class_uid BETWEEN 3000 AND 3999"),
            ClassFamily::Network => Some("class_uid BETWEEN 4000 AND 4999"),
            ClassFamily::Application => Some("class_uid BETWEEN 6000 AND 6999"),
            ClassFamily::Generic => None,
        }
    }
}

/// The OCSF columns holding `kind` for a class family, in priority order (first
/// non-empty wins). Every column named here is a plain physical column of
/// `ocsf_logs`.
pub fn ocsf_columns(kind: EntityKind, family: ClassFamily) -> &'static [&'static str] {
    use ClassFamily as F;
    use EntityKind as E;
    match (kind, family) {
        // Endpoint classes have no src/dst sides. The host they ran on is the device.
        (E::SrcHost, F::Endpoint | F::ProcessActivity) => {
            &["device.hostname", "src_endpoint.hostname"]
        }
        // Matches `src_host_unified`.
        (E::SrcHost, _) => &["src_endpoint.hostname", "device.hostname"],
        // Identity & Access: a Windows logon is logged on the TARGET machine, so
        // `device.hostname` is the destination host. Some auth classes carry it
        // only there (Authorize Session 3003 / 4672 has no `dst_endpoint`).
        (E::DestHost, F::Iam) => &["dst_endpoint.hostname", "device.hostname"],
        // Every other class: `device.hostname` is the local endpoint (the
        // source side), never the peer.
        (E::DestHost, _) => &["dst_endpoint.hostname"],

        (E::User, F::Endpoint | F::ProcessActivity | F::Application) => {
            &["actor.user.name", "user.name"]
        }
        // Matches `user_unified`.
        (E::User, _) => &["user.name", "actor.user.name"],
        (E::DestUser, _) => &[],

        (E::SrcIp, _) => &["src_endpoint.ip"],
        (E::DestIp, _) => &["dst_endpoint.ip"],

        // On 1007 the top-level process is the launched child (the subject), and
        // `actor.process` is its parent. Every other class carries only the
        // acting process. Both orders agree with `process_name_unified` on real
        // data, because the top-level process is empty outside 1007.
        (E::Process, F::ProcessActivity | F::Generic) => &["process.name", "actor.process.name"],
        (E::Process, _) => &["actor.process.name", "process.name"],
        (E::CommandLine, F::ProcessActivity | F::Generic) => {
            &["process.cmd_line", "actor.process.cmd_line"]
        }
        (E::CommandLine, _) => &["actor.process.cmd_line", "process.cmd_line"],

        (E::FileHash, _) => &["file.hashes.sha256"],
        (E::ProcessHash, F::ProcessActivity | F::Generic) => {
            &["process.file.hashes.sha256", "actor.process.file.hashes.sha256"]
        }
        (E::ProcessHash, _) => &["actor.process.file.hashes.sha256", "process.file.hashes.sha256"],

        // HTTP URL host, then DNS question, then generic URL host.
        (E::Domain, _) => &["http_request.url.hostname", "query.hostname", "url.hostname"],
    }
}

/// UDM keys (legacy `logs` rows and UDM-keyed payloads) holding `kind`, in
/// priority order.
pub fn udm_keys(kind: EntityKind) -> &'static [&'static str] {
    match kind {
        EntityKind::SrcHost => &["src_host", "host", "hostname"],
        EntityKind::DestHost => &["dest_host"],
        EntityKind::User => &["user", "src_user"],
        EntityKind::DestUser => &["dest_user"],
        EntityKind::SrcIp => &["src_ip"],
        EntityKind::DestIp => &["dest_ip"],
        EntityKind::Process => &["process_name"],
        EntityKind::CommandLine => &["command_line"],
        EntityKind::FileHash => &["file_hash"],
        EntityKind::ProcessHash => &["process_hash"],
        EntityKind::Domain => &["domain", "url_domain", "dns_query"],
    }
}

/// The indexed `*_unified` column for `kind`, when one exists. Use it for
/// WHERE and GROUP BY on interactive reads, where the words index prunes. Do
/// not use it in MV bodies or under `SELECT *`: it is an ALIAS column.
pub fn ocsf_indexed_column(kind: EntityKind) -> Option<&'static str> {
    match kind {
        EntityKind::SrcHost => Some("src_host_unified"),
        EntityKind::User => Some("user_unified"),
        EntityKind::Process => Some("process_name_unified"),
        EntityKind::CommandLine => Some("command_line_unified"),
        EntityKind::ProcessHash => Some("process_hash_unified"),
        _ => None,
    }
}

/// The `class_uid` of a row, accepting a number or a numeric string.
pub fn row_class_uid(row: &Map<String, Value>) -> Option<u64> {
    match row.get("class_uid")? {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

/// Look up `key` as a flat key first (ClickHouse JSONEachRow dotted columns),
/// then as a nested path. Returns a usable entity string: a JSON string that
/// is non-empty, not `-` and not `null`.
fn lookup(row: &Map<String, Value>, key: &str) -> Option<String> {
    let v = match row.get(key) {
        Some(v) => Some(v),
        None if key.contains('.') => {
            let mut parts = key.split('.');
            let mut cur = row.get(parts.next()?)?;
            for p in parts {
                cur = cur.get(p)?;
            }
            Some(cur)
        }
        None => None,
    }?;
    // Entity values are strings; a number or bool under an entity key is not an
    // identifier (SOAR refuses non-scalar-string entities).
    let s = match v {
        Value::String(s) => s.trim().to_string(),
        _ => return None,
    };
    if s.is_empty() || s == "-" || s.eq_ignore_ascii_case("null") {
        None
    } else {
        Some(s)
    }
}

/// The candidate keys tried for `kind` on a row of `class_uid`: the class-correct
/// OCSF columns first, then the UDM keys.
pub fn candidate_keys(kind: EntityKind, class_uid: Option<u64>) -> Vec<&'static str> {
    let mut keys: Vec<&'static str> = ocsf_columns(kind, ClassFamily::of(class_uid)).to_vec();
    keys.extend_from_slice(udm_keys(kind));
    keys
}

/// Resolve `kind` on a row. Returns `(key it came from, value)`.
pub fn resolve_with_key(row: &Map<String, Value>, kind: EntityKind) -> Option<(&'static str, String)> {
    let class_uid = row_class_uid(row);
    candidate_keys(kind, class_uid)
        .into_iter()
        .find_map(|k| lookup(row, k).map(|v| (k, v)))
}

/// Resolve `kind` on a row. This is the first non-empty class-correct value,
/// with the UDM keys as the fallback.
pub fn resolve(row: &Map<String, Value>, kind: EntityKind) -> Option<String> {
    resolve_with_key(row, kind).map(|(_, v)| v)
}

/// Every distinct non-empty value of `kind` on a row, in priority order. For
/// surfaces that list entities, such as investigation seeds and baselines.
pub fn resolve_all(row: &Map<String, Value>, kind: EntityKind) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for k in candidate_keys(kind, row_class_uid(row)) {
        if let Some(v) = lookup(row, k) {
            if !out.contains(&v) {
                out.push(v);
            }
        }
    }
    out
}

/// Resolve a named field: the literal key first, then (when `field` names a
/// known entity concept) the class-correct resolution of that concept. Returns
/// `(value, key)`.
pub fn resolve_field(row: &Map<String, Value>, field: &str) -> Option<(String, String)> {
    if let Some(v) = lookup(row, field) {
        return Some((v, field.to_string()));
    }
    let kind = EntityKind::from_field_name(field)?;
    resolve_with_key(row, kind).map(|(k, v)| (v, k.to_string()))
}

/// The single entity a finding is attributed to, in [`PRIMARY_ORDER`].
/// Returns `(kind, key, value)`.
pub fn primary_entity(row: &Map<String, Value>) -> Option<(EntityKind, &'static str, String)> {
    PRIMARY_ORDER
        .iter()
        .find_map(|&kind| resolve_with_key(row, kind).map(|(k, v)| (kind, k, v)))
}

/// [`resolve_field`] / [`primary_entity`] over a `serde_json::Value`, for
/// callers holding an event rather than a map. With `field = None`, the primary
/// entity is used.
pub fn event_entity(event: &Value, field: Option<&str>) -> Option<(String, String)> {
    let row = event.as_object()?;
    match field.map(str::trim).filter(|f| !f.is_empty()) {
        Some(f) => resolve_field(row, f),
        None => primary_entity(row).map(|(_, k, v)| (v, k.to_string())),
    }
}

/// The webhook or notification "who/what" for an alert: the rule's entity field
/// (or the primary entity when none is set), resolved class-aware on the first
/// matched event that has one.
pub fn alert_primary_entity(risk_entity_field: Option<&str>, matched_events: &Value) -> Option<String> {
    let events = matched_events.as_array()?;
    // Payload compatibility: the webhook `entity` used to be the first event's
    // literal value for the rule's field, numbers and bools stringified (for
    // example `dest_port` -> "443"). Keep that value when present, so an existing
    // consumer never sees a filled field turn null.
    if let Some(field) = risk_entity_field.map(str::trim).filter(|f| !f.is_empty()) {
        match events.first().and_then(|ev| ev.get(field)) {
            Some(Value::Number(n)) => return Some(n.to_string()),
            Some(Value::Bool(b)) => return Some(b.to_string()),
            _ => {}
        }
    }
    events
        .iter()
        .find_map(|ev| event_entity(ev, risk_entity_field))
        .map(|(v, _)| v)
}

/// First-non-empty chain over physical columns: `if(notEmpty(a), a, if(…, b, c))`.
fn chain_sql(cols: &[&str]) -> String {
    match cols {
        [] => "''".to_string(),
        [only] => escape_identifier(only),
        [first, rest @ ..] => {
            let c = escape_identifier(first);
            format!("if(notEmpty({c}), {c}, {})", chain_sql(rest))
        }
    }
}

/// The class-aware ClickHouse expression for `kind` over physical `ocsf_logs`
/// columns. It returns the same value as [`resolve`] would for that row, and
/// `''` when nothing is set. It is safe in MV bodies and under an inner
/// `SELECT *`. When the chain is the same for every class family, there is no
/// `class_uid` branch.
pub fn ocsf_sql_expr(kind: EntityKind) -> String {
    let generic = ocsf_columns(kind, ClassFamily::Generic);
    let mut arms: Vec<String> = Vec::new();
    for family in ClassFamily::ALL {
        let Some(pred) = family.sql_predicate() else { continue };
        let cols = ocsf_columns(kind, family);
        if cols != generic {
            arms.push(format!("{pred}, {}", chain_sql(cols)));
        }
    }
    if arms.is_empty() {
        chain_sql(generic)
    } else {
        format!("multiIf({}, {})", arms.join(", "), chain_sql(generic))
    }
}

/// The class-aware SQL for the primary entity ([`PRIMARY_ORDER`]): the first
/// non-empty concept. The real-time detection MV uses it as `risk_entity` when
/// the rule names no entity field, so a Sysmon finding is attributed to its user
/// or host rather than to an empty `src_endpoint.ip`.
pub fn ocsf_primary_entity_sql() -> String {
    // `arrayFirst` evaluates each concept once and returns '' when none is set.
    let exprs: Vec<String> = PRIMARY_ORDER.iter().map(|&k| ocsf_sql_expr(k)).collect();
    format!("arrayFirst(x -> notEmpty(x), [{}])", exprs.join(", "))
}

#[cfg(test)]
#[path = "entities_tests.rs"]
mod tests;
