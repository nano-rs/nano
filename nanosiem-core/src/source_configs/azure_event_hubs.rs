// SPDX-License-Identifier: AGPL-3.0-or-later

//! Azure Event Hubs source configs (NAN-3764, ported to the ClickHouse
//! product in NAN-4914 phase 1) on the nano Vector fork's native
//! `azure_event_hubs` source.
//!
//! Point-forward only: `start_position = "latest"`, which with a checkpoint
//! store writes each partition's current end as its first checkpoint at
//! connect. A checkpoint store (Azure Blob Storage) is mandatory: without one
//! every restart would start at the newest events and drop whatever arrived
//! while Vector was down. End-to-end acknowledgements, so a position is
//! checkpointed only once its events are delivered.
//!
//! Secrets (SAS / storage connection strings, the Entra client secret) never
//! live in `connection_config`: they come from a sealed `azure_event_hubs`
//! credential. With no credential bound the source authenticates with the
//! deployment's managed identity.

use super::service::SourceConfigServiceError;

/// The consumer group an Event Hubs source reads with when none is given.
pub(crate) const AZURE_DEFAULT_CONSUMER_GROUP: &str = "$Default";

/// Where a partition with no checkpoint starts. There is deliberately no
/// backfill option: `earliest` would ingest the hub's whole retention (up to
/// 7 days, 90 on premium) on the first start.
pub(crate) const AZURE_START_POSITION: &str = "latest";

/// How often acknowledged positions are written to the checkpoint container.
pub(crate) const AZURE_CHECKPOINT_INTERVAL_SECS: u32 = 5;

/// DNS suffix of a public-cloud Event Hubs namespace.
const AZURE_EVENT_HUBS_SUFFIX: &str = "servicebus.windows.net";

/// The literal behind [`AZURE_RECORDS_CAP`], so the `concat!` VRL and the
/// Rust constant cannot drift apart.
macro_rules! azure_records_cap {
    () => {
        10000
    };
}

/// The most records one Event Hubs message explodes into. A batch over the
/// cap keeps its first `AZURE_RECORDS_CAP` records and adds ONE truncation
/// event (`nano_pull_error = "azure_records_truncated"`, the original count,
/// the cap), so one message fans out to at most cap + 1 events.
#[allow(dead_code)] // documented bound; the VRL uses the macro literal
pub(crate) const AZURE_RECORDS_CAP: usize = azure_records_cap!();

/// Event Hubs message -> one event per record. An Azure Monitor export is a
/// `{"records": [...]}` batch (or a bare array); each record becomes one event
/// with the record in `.message`. Other top-level keys next to `records` and
/// the batch's application `properties` are dropped (only the records are
/// events). An empty batch emits nothing. A single object, an object without
/// a `records` array, or a non-JSON body passes through as ONE event: never
/// dropped, the lane decides. Infallible and abort-free, so it can never drop
/// an event (a drop would count as delivered and advance the checkpoint).
///
/// Same VRL as main's hosted pull stamp (`PullEnvelope::AzureRecords`), so a
/// parser shared between editions sees the same event shape.
pub(crate) const AZURE_RECORDS_SPLIT_VRL: &str = concat!(
    "# NAN-3604: Event Hubs message -> one event per record ({\"records\": [...]} or a bare array).\n",
    "nano_pull_parsed, nano_pull_error = parse_json(string(.message) ?? \"\")\n",
    "nano_pull_is_batch = false\n",
    "nano_pull_records = []\n",
    "if nano_pull_error == null {\n",
    "  if is_array(nano_pull_parsed) {\n",
    "    nano_pull_is_batch = true\n",
    "    nano_pull_records = array(nano_pull_parsed) ?? []\n",
    "  } else if is_object(nano_pull_parsed) {\n",
    "    nano_pull_envelope = object(nano_pull_parsed) ?? {}\n",
    "    if is_array(nano_pull_envelope.records) {\n",
    "      nano_pull_is_batch = true\n",
    "      nano_pull_records = array(nano_pull_envelope.records) ?? []\n",
    "    }\n",
    "  }\n",
    "}\n",
    "if nano_pull_is_batch {\n",
    "  del(.message)\n",
    "  del(.properties)\n",
    "  nano_pull_total = length(nano_pull_records)\n",
    "  nano_pull_truncated = nano_pull_total > ", azure_records_cap!(), "\n",
    "  if nano_pull_truncated {\n",
    "    nano_pull_records = slice(nano_pull_records, 0, ", azure_records_cap!(), ") ?? []\n",
    "  }\n",
    "  nano_pull_event = .\n",
    "  nano_pull_out = map_values(nano_pull_records) -> |nano_pull_record| {\n",
    "    nano_pull_one = nano_pull_event\n",
    "    nano_pull_one.message = string(nano_pull_record) ?? encode_json(nano_pull_record)\n",
    "    nano_pull_one\n",
    "  }\n",
    "  if nano_pull_truncated {\n",
    "    nano_pull_marker = nano_pull_event\n",
    "    nano_pull_marker.nano_pull_error = \"azure_records_truncated\"\n",
    "    nano_pull_marker.nano_pull_records_total = nano_pull_total\n",
    "    nano_pull_marker.nano_pull_records_cap = ", azure_records_cap!(), "\n",
    "    nano_pull_marker.message = encode_json({\"nano_pull_error\": \"azure_records_truncated\", \"records_total\": nano_pull_total, \"records_kept\": ", azure_records_cap!(), "})\n",
    "    nano_pull_out = push(nano_pull_out, nano_pull_marker)\n",
    "  }\n",
    "  . = nano_pull_out\n",
    "}\n",
);

/// Event Hub / consumer-group name grammar: letters, digits, `.`, `_`, `-`;
/// alphanumeric first and last; at most `max` bytes.
fn azure_entity_name(value: &str, max: usize) -> bool {
    let b = value.as_bytes();
    !b.is_empty()
        && b.len() <= max
        && b[0].is_ascii_alphanumeric()
        && b[b.len() - 1].is_ascii_alphanumeric()
        && b.iter()
            .all(|&c| c.is_ascii_alphanumeric() || c == b'.' || c == b'_' || c == b'-')
}

/// Blob container name: 3-63 lowercase letters, digits or single hyphens,
/// letter/digit first and last.
fn azure_blob_container_name(container: &str) -> bool {
    let b = container.as_bytes();
    let alnum = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    (3..=63).contains(&b.len())
        && alnum(b[0])
        && alnum(b[b.len() - 1])
        && b.iter().all(|&c| alnum(c) || c == b'-')
        && !container.contains("--")
}

/// The namespace host Vector connects to. A bare namespace name (`acme-logs`)
/// becomes `acme-logs.servicebus.windows.net`; a full host (sovereign clouds,
/// private DNS) is kept. `sb://` and a trailing `/` are tolerated because the
/// Azure portal shows them. `None` for anything that is not a DNS name.
pub(crate) fn azure_namespace_host(raw: &str) -> Option<String> {
    let host = raw
        .trim()
        .trim_start_matches("sb://")
        .trim_end_matches('/')
        .to_ascii_lowercase();
    let label_ok = |l: &str| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
    };
    if host.is_empty() || host.len() > 253 || !host.split('.').all(label_ok) {
        return None;
    }
    if host.contains('.') {
        Some(host)
    } else {
        Some(format!("{host}.{AZURE_EVENT_HUBS_SUFFIX}"))
    }
}

/// Event Hubs namespace DNS suffixes of the Azure clouds (public, China,
/// US Government, legacy Germany).
pub(crate) const EVENT_HUBS_SUFFIXES: &[&str] = &[
    "servicebus.windows.net",
    "servicebus.chinacloudapi.cn",
    "servicebus.usgovcloudapi.net",
    "servicebus.cloudapi.de",
];

/// Blob Storage endpoint DNS suffixes of the same clouds.
pub(crate) const BLOB_SUFFIXES: &[&str] = &[
    "blob.core.windows.net",
    "blob.core.chinacloudapi.cn",
    "blob.core.usgovcloudapi.net",
    "blob.core.cloudapi.de",
];

/// Admin allowlist for Azure endpoints outside the public cloud suffixes
/// (Azure Stack Hub, a custom private DNS zone, the local Event Hubs
/// emulator): comma-separated exact hosts or `.suffix` entries. Read from the
/// deployment environment only, never from a request.
pub(crate) const AZURE_ENDPOINT_ALLOWLIST_ENV: &str = "NANO_AZURE_ENDPOINT_ALLOWLIST";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AzureService {
    EventHubs,
    Blob,
}

/// Whether Vector may be pointed at `host` for `service`.
///
/// The host must sit under a recognized Azure cloud suffix for the service,
/// or match the admin allowlist. That is the whole SSRF boundary here:
/// Vector, not nano, resolves and dials these hosts, so nano cannot pin the
/// resolution; it can only refuse every name it does not trust. Names under
/// Azure's own zones cannot be pointed at an attacker or an internal service
/// by a tenant (Azure owns the DNS; a Private Link name resolving to a
/// private address is the customer's legitimate private endpoint), and IP
/// literals, single-label and other names are refused unless an
/// administrator allowlisted them.
pub(crate) fn azure_host_allowed(host: &str, service: AzureService, allowlist: Option<&str>) -> bool {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return false;
    }
    let allowlisted = allowlist.unwrap_or_default().split(',').map(|e| e.trim().to_ascii_lowercase()).filter(|e| !e.is_empty()).any(|entry| {
        match entry.strip_prefix('.') {
            Some(sfx) => host.ends_with(&format!(".{sfx}")),
            None => host == entry,
        }
    });
    if allowlisted {
        return true;
    }
    // An IP literal (v4, or v6 in brackets) never matches a cloud suffix.
    if host.parse::<std::net::IpAddr>().is_ok() || host.starts_with('[') {
        return false;
    }
    let suffixes = match service {
        AzureService::EventHubs => EVENT_HUBS_SUFFIXES,
        AzureService::Blob => BLOB_SUFFIXES,
    };
    let label_ok = |l: &str| {
        !l.is_empty() && l.len() <= 63 && l.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
    };
    suffixes.iter().any(|sfx| {
        host.strip_suffix(sfx)
            .and_then(|rest| rest.strip_suffix('.'))
            .is_some_and(|account| account.split('.').all(label_ok))
    })
}

fn allowlist_env() -> Option<String> {
    std::env::var(AZURE_ENDPOINT_ALLOWLIST_ENV).ok()
}

/// Host of a connection-string endpoint value (`sb://host/`,
/// `https://host;`, a bare host).
fn endpoint_host(value: &str) -> Option<String> {
    let v = value.trim();
    let parsed = if v.contains("://") { url::Url::parse(v).ok()? } else { url::Url::parse(&format!("https://{v}")).ok()? };
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return None;
    }
    parsed.host_str().map(|h| h.to_ascii_lowercase())
}

/// Check every endpoint a connection string would make Vector dial.
/// Event Hubs: `Endpoint` (required). Storage: `BlobEndpoint`, or the host
/// derived from `AccountName` + `EndpointSuffix` (default public cloud);
/// queue/table/file endpoints are refused (the checkpoint store uses Blob
/// only). `UseDevelopmentEmulator` (and Azurite's `UseDevelopmentStorage`)
/// needs its endpoint host on the admin allowlist like any other name.
pub(crate) fn check_connection_string(
    conn_str: &str,
    service: AzureService,
    allowlist: Option<&str>,
) -> Result<(), String> {
    let mut fields: Vec<(String, String)> = Vec::new();
    for part in conn_str.split(';').map(str::trim).filter(|p| !p.is_empty()) {
        let (k, v) = part.split_once('=').ok_or_else(|| "connection string has a malformed part".to_string())?;
        fields.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
    }
    let get = |k: &str| fields.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
    let refuse = |what: &str, host: &str| {
        Err(format!(
            "{what} host `{host}` is not an Azure endpoint (allowed: *.{}); an administrator can allow other hosts with {AZURE_ENDPOINT_ALLOWLIST_ENV}",
            match service {
                AzureService::EventHubs => EVENT_HUBS_SUFFIXES.join(", *."),
                AzureService::Blob => BLOB_SUFFIXES.join(", *."),
            }
        ))
    };
    if get("usedevelopmentstorage").is_some_and(|v| v.eq_ignore_ascii_case("true")) {
        return Err("UseDevelopmentStorage connection strings are refused; give the BlobEndpoint explicitly".into());
    }
    match service {
        AzureService::EventHubs => {
            let endpoint = get("endpoint").ok_or_else(|| "Event Hubs connection string has no Endpoint".to_string())?;
            let host = endpoint_host(endpoint).ok_or_else(|| "Event Hubs connection string Endpoint is not a host".to_string())?;
            if !azure_host_allowed(&host, service, allowlist) {
                return refuse("Event Hubs Endpoint", &host);
            }
        }
        AzureService::Blob => {
            for other in ["queueendpoint", "tableendpoint", "fileendpoint"] {
                if get(other).is_some() {
                    return Err(format!("storage connection string must not carry {other}; the checkpoint store uses Blob only"));
                }
            }
            let host = match get("blobendpoint") {
                Some(endpoint) => endpoint_host(endpoint).ok_or_else(|| "BlobEndpoint is not a host".to_string())?,
                None => {
                    let account = get("accountname").ok_or_else(|| "storage connection string needs AccountName or BlobEndpoint".to_string())?;
                    let suffix = get("endpointsuffix").unwrap_or("core.windows.net");
                    format!("{}.blob.{}", account.to_ascii_lowercase(), suffix.to_ascii_lowercase())
                }
            };
            if !azure_host_allowed(&host, service, allowlist) {
                return refuse("Blob checkpoint store", &host);
            }
        }
    }
    Ok(())
}

/// Credential-time check of an `azure_event_hubs` payload's connection
/// strings (used by the credentials API at create and rotate).
pub(crate) fn check_credential_endpoints(credentials: &serde_json::Value) -> Result<(), String> {
    let allow = allowlist_env();
    if let Some(cs) = str_field(Some(credentials), "connection_string") {
        check_connection_string(cs, AzureService::EventHubs, allow.as_deref())?;
    }
    if let Some(cs) = str_field(Some(credentials), "checkpoint_connection_string") {
        check_connection_string(cs, AzureService::Blob, allow.as_deref())?;
    }
    Ok(())
}

fn str_field<'a>(value: Option<&'a serde_json::Value>, key: &str) -> Option<&'a str> {
    value
        .and_then(|v| v.get(key))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|v| !v.is_empty())
}

/// Write-time validation of an Event Hubs `connection_config`. Point-forward
/// only, so a `start_position` other than `latest` is refused rather than
/// ignored.
pub(crate) fn validate_conn(conn: &serde_json::Value) -> Result<(), SourceConfigServiceError> {
    let invalid = |msg: String| SourceConfigServiceError::InvalidConfig(msg);
    for key in [
        "namespace",
        "event_hub_name",
        "consumer_group",
        "checkpoint_account",
        "checkpoint_container",
        "start_position",
    ] {
        if conn.get(key).is_some_and(|v| !v.is_null() && !v.is_string()) {
            return Err(invalid(format!(
                "azure_event_hubs connection_config.{key} must be a string"
            )));
        }
    }
    let field = |key: &str| str_field(Some(conn), key);

    let hub = field("event_hub_name").ok_or_else(|| {
        invalid("azure_event_hubs connection_config.event_hub_name is required".into())
    })?;
    if !azure_entity_name(hub, 256) {
        return Err(invalid(
            "azure_event_hubs connection_config.event_hub_name must be 1-256 letters, digits, \
             '.', '_' or '-', starting and ending with a letter or digit"
                .into(),
        ));
    }
    if let Some(group) = field("consumer_group") {
        if group != AZURE_DEFAULT_CONSUMER_GROUP && !azure_entity_name(group, 50) {
            return Err(invalid(
                "azure_event_hubs connection_config.consumer_group must be $Default or 1-50 \
                 letters, digits, '.', '_' or '-'"
                    .into(),
            ));
        }
    }
    if let Some(namespace) = field("namespace") {
        match azure_namespace_host(namespace) {
            None => {
                return Err(invalid(
                    "azure_event_hubs connection_config.namespace must be a namespace name \
                     (e.g. acme-logs) or its host (acme-logs.servicebus.windows.net)"
                        .into(),
                ))
            }
            Some(host) if !azure_host_allowed(&host, AzureService::EventHubs, allowlist_env().as_deref()) => {
                return Err(invalid(format!(
                    "azure_event_hubs connection_config.namespace `{host}` is not under an Azure Event Hubs \
                     domain ({}); an administrator can allow other hosts with {AZURE_ENDPOINT_ALLOWLIST_ENV}",
                    EVENT_HUBS_SUFFIXES.join(", ")
                )))
            }
            Some(_) => {}
        }
    }
    if let Some(account) = field("checkpoint_account") {
        let ok = (3..=24).contains(&account.len())
            && account
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
        if !ok {
            return Err(invalid(
                "azure_event_hubs connection_config.checkpoint_account must be 3-24 \
                 lowercase letters or digits"
                    .into(),
            ));
        }
    }
    let container = field("checkpoint_container").ok_or_else(|| {
        invalid(
            "azure_event_hubs connection_config.checkpoint_container is required: \
             checkpoints are what let a restart resume without loss or duplicates"
                .into(),
        )
    })?;
    if !azure_blob_container_name(container) {
        return Err(invalid(
            "azure_event_hubs connection_config.checkpoint_container must be 3-63 lowercase \
             letters, digits or single hyphens, starting and ending with a letter or digit"
                .into(),
        ));
    }
    if let Some(start) = field("start_position") {
        if start != AZURE_START_POSITION {
            return Err(invalid(format!(
                "azure_event_hubs connection_config.start_position must be \
                 \"{AZURE_START_POSITION}\": pull sources start at the newest events and \
                 have no backfill option"
            )));
        }
    }
    Ok(())
}

/// The `[sources.<name>]` table of an Event Hubs source.
///
/// Event Hub authentication, from the sealed credential:
///
/// | credential                         | result                                     |
/// |------------------------------------|--------------------------------------------|
/// | `connection_string`                | SAS connection string (`namespace` unused) |
/// | tenant + client id + client secret | Entra service principal on `namespace`     |
/// | none                               | managed identity on `namespace`            |
///
/// The checkpoint store uses the credential's `checkpoint_connection_string`
/// when set, else `checkpoint_account` with the same Entra service principal
/// or managed identity.
pub(crate) fn source_table(
    conn: &serde_json::Value,
    creds: Option<&serde_json::Value>,
) -> Result<toml::Table, SourceConfigServiceError> {
    let invalid =
        |msg: &str| SourceConfigServiceError::InvalidConfig(format!("azure_event_hubs: {msg}"));
    let conn_field = |key: &str| str_field(Some(conn), key);
    let cred_field = |key: &str| str_field(creds, key);

    let event_hub = conn_field("event_hub_name")
        .ok_or_else(|| invalid("connection_config.event_hub_name is required"))?;
    // Re-checked at every render (not only at write time): a credential or a
    // row written before this check, or the allowlist shrinking, must never
    // send Vector (and the secret it carries) to a non-Azure host.
    let allow = allowlist_env();
    check_credential_endpoints(creds.unwrap_or(&serde_json::Value::Null))
        .map_err(|e| invalid(&e))?;
    let container = conn_field("checkpoint_container")
        .ok_or_else(|| invalid("connection_config.checkpoint_container is required"))?;
    let consumer_group = conn_field("consumer_group").unwrap_or(AZURE_DEFAULT_CONSUMER_GROUP);

    // Entra service principal when all three parts are present; a partial one
    // is a misconfiguration, not a credential (same rule as AWS keys).
    let entra = match (
        cred_field("azure_tenant_id"),
        cred_field("azure_client_id"),
        cred_field("azure_client_secret"),
    ) {
        (Some(tenant), Some(client), Some(secret)) => {
            let mut auth = toml::Table::new();
            auth.insert(
                "azure_credential_kind".into(),
                "client_secret_credential".into(),
            );
            auth.insert("azure_tenant_id".into(), tenant.into());
            auth.insert("azure_client_id".into(), client.into());
            auth.insert("azure_client_secret".into(), secret.into());
            auth
        }
        _ => {
            let mut auth = toml::Table::new();
            auth.insert("azure_credential_kind".into(), "managed_identity".into());
            auth
        }
    };

    let mut source = toml::Table::new();
    source.insert("type".into(), "azure_event_hubs".into());
    if let Some(connection_string) = cred_field("connection_string") {
        source.insert("connection_string".into(), connection_string.into());
    } else {
        let namespace = conn_field("namespace")
            .and_then(azure_namespace_host)
            .ok_or_else(|| {
                invalid(
                    "connection_config.namespace is required unless the credential \
                     carries an Event Hubs connection string",
                )
            })?;
        if !azure_host_allowed(&namespace, AzureService::EventHubs, allow.as_deref()) {
            return Err(invalid(&format!("namespace `{namespace}` is not an Azure Event Hubs host")));
        }
        source.insert("namespace".into(), namespace.into());
        source.insert("auth".into(), toml::Value::Table(entra.clone()));
    }
    source.insert("event_hub_name".into(), event_hub.into());
    source.insert("consumer_group".into(), consumer_group.into());
    // Only for a partition with no checkpoint yet: point-forward.
    source.insert("start_position".into(), AZURE_START_POSITION.into());
    source.insert(
        "checkpoint_interval_secs".into(),
        toml::Value::Integer(i64::from(AZURE_CHECKPOINT_INTERVAL_SECS)),
    );

    let store = match cred_field("checkpoint_connection_string") {
        Some(connection_string) => checkpoint_store(container, connection_string, None),
        None => {
            let account = conn_field("checkpoint_account").ok_or_else(|| {
                invalid(
                    "connection_config.checkpoint_account is required unless the credential \
                     carries a storage connection string",
                )
            })?;
            let host = format!("{account}.blob.core.windows.net");
            if !azure_host_allowed(&host, AzureService::Blob, allow.as_deref()) {
                return Err(invalid(&format!("checkpoint account host `{host}` is not allowed")));
            }
            checkpoint_store(container, account, Some(entra))
        }
    };
    source.insert("checkpoint_store".into(), toml::Value::Table(store));

    let mut acknowledgements = toml::Table::new();
    acknowledgements.insert("enabled".into(), true.into());
    source.insert(
        "acknowledgements".into(),
        toml::Value::Table(acknowledgements),
    );
    let mut decoding = toml::Table::new();
    decoding.insert("codec".into(), "bytes".into());
    source.insert("decoding".into(), toml::Value::Table(decoding));
    let mut framing = toml::Table::new();
    framing.insert("method".into(), "bytes".into());
    source.insert("framing".into(), toml::Value::Table(framing));

    Ok(source)
}

/// The `checkpoint_store` table: Azure Blob Storage, addressed by a storage
/// connection string (`auth` `None`; the fork refuses a credential-bearing
/// connection string next to `auth`) or by an account name with Entra `auth`.
fn checkpoint_store(
    container: &str,
    connection_string_or_account: &str,
    auth: Option<toml::Table>,
) -> toml::Table {
    let mut store = toml::Table::new();
    store.insert("type".into(), "azure_blob".into());
    match auth {
        None => {
            store.insert(
                "connection_string".into(),
                connection_string_or_account.into(),
            );
        }
        Some(auth) => {
            store.insert("account_name".into(), connection_string_or_account.into());
            store.insert("auth".into(), toml::Value::Table(auth));
        }
    }
    store.insert("container_name".into(), container.into());
    store
}
