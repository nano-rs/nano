// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared UDM event classification — single source of truth used by both the
//! asset search paths and the dossier endpoint.
//!
//! Two consumers today:
//! - [`EVENT_TYPE_SQL`] — returns a string label (`'AUTH_SUCCESS'`, `'NETWORK'`, …)
//!   consumed by the per-event facet aggregation in `service/asset.rs` and by
//!   the paginated asset-events endpoint (via `detect_event_type` in Rust).
//! - [`LANE_SQL`] — returns an integer lane index (0-4) consumed by the 5-lane
//!   heatmap timeline in `service/asset_dossier.rs`.
//!
//! Both expressions must agree on what "kind of event this is" — if you change
//! one, change the other to match. The mapping is:
//!
//! | Lane idx | String types            |
//! |---------:|-------------------------|
//! |        0 | AUTH_SUCCESS, AUTH_FAILURE |
//! |        1 | PROCESS, IMAGE_LOAD     |
//! |        2 | NETWORK, DNS, DHCP      |
//! |        3 | FILE, REGISTRY, PIPE    |
//! |        4 | ALERT                   |
//! |       -1 | EVENT (uncategorized)   |
//!
//! Predicate fragments are declared as macros so each predicate is a literal
//! `&'static str` at compile time (required by `concat!`). Edit a predicate in
//! exactly one place and both classifiers pick up the change.

/// Predicate: alert / signal / finding event.
macro_rules! p_alert {
    () => {
        "(lower(source_type) = 'signal' OR position(lower(source_type), 'alert') > 0)"
    };
}

/// Predicate: DHCP / network-info event. Must come before DNS in a CASE WHEN
/// chain so the DNS port-53 predicate doesn't swallow DHCP rows.
macro_rules! p_dhcp {
    () => {
        "(lower(source_type) LIKE '%dhcp%' OR position(lower(action), 'dhcp') > 0 OR lower(action) = 'network_info' OR lower(action) = 'networkinfo' OR position(lower(action), 'network_adapter') > 0)"
    };
}

/// Predicate: DNS event (excluding DHCP).
macro_rules! p_dns {
    () => {
        "((lower(source_type) LIKE '%dns%' OR query != '' OR src_port = 53 OR dest_port = 53) AND lower(source_type) NOT LIKE '%dhcp%')"
    };
}

/// Predicate: authentication / identity event. Includes the `category` axis so
/// Windows-event rows (4624/4625 fall through `auth_result`; 4634/4647/4648/4672
/// and the 472x account-management family arrive only with `.udm.category` set
/// by the parser) get bucketed instead of falling through to `EVENT`.
macro_rules! p_auth {
    () => {
        "(auth_result != '' OR lower(source_type) LIKE '%auth%' OR position(lower(action), 'login') > 0 OR position(lower(action), 'logon') > 0 OR lower(category) IN ('authentication','authorization','account_management','credential_access'))"
    };
}

/// Predicate: auth-failure sub-condition. Only meaningful when [`p_auth!`] is
/// also true.
macro_rules! p_auth_fail {
    () => {
        "(position(lower(auth_result), 'fail') > 0 OR position(lower(action), 'fail') > 0)"
    };
}

/// Predicate: image-load event.
macro_rules! p_image_load {
    () => {
        "(lower(action) = 'image_load' OR lower(action) = 'imageload')"
    };
}

/// Predicate: registry event.
macro_rules! p_registry {
    () => {
        "(position(lower(action), 'registry') > 0 OR lower(category) = 'registry')"
    };
}

/// Predicate: named-pipe event.
macro_rules! p_pipe {
    () => {
        "(position(lower(action), 'pipe') > 0 OR lower(category) = 'pipe')"
    };
}

/// Predicate: network event by action / source_type (proxy / firewall / connection).
macro_rules! p_network {
    () => {
        "(position(lower(action), 'connection') > 0 OR lower(source_type) LIKE '%proxy%' OR lower(source_type) LIKE '%firewall%' OR lower(category) IN ('network','firewall'))"
    };
}

/// Predicate: process-execution event.
macro_rules! p_process {
    () => {
        "(process_name != '' OR position(lower(action), 'process') > 0 OR position(lower(action), 'exec') > 0)"
    };
}

/// Predicate: file-system event.
macro_rules! p_file {
    () => {
        "(file_action != '' OR position(lower(action), 'file') > 0 OR position(lower(action), 'write') > 0 OR lower(category) IN ('file_access','object_access'))"
    };
}

/// Predicate: fallback network match on `dest_ip` when no other predicate fits.
macro_rules! p_network_fallback {
    () => {
        "(dest_ip != '')"
    };
}

// ---------------------------------------------------------------------------
// Predicate exports
//
// The macros above produce literal `&'static str` so `concat!` can splice them
// into `EVENT_TYPE_SQL` / `LANE_SQL`. They're also useful to non-classifier
// callers that need to filter on "is this an auth event?" — the dossier
// service in particular (NAN-1049) used to embed its own near-copies of these
// predicates and drifted when NAN-1047 added the `category` axis here.
//
// Expose each predicate as a `pub const` so any module can splice it into a
// SQL query. Edit the macro in one place; both the classifier and the dossier
// service inherit the change. Do NOT re-export the macro itself — the
// `pub const` form is enough and keeps the API smaller.
// ---------------------------------------------------------------------------

pub const ALERT_PREDICATE: &str = p_alert!();
pub const DHCP_PREDICATE: &str = p_dhcp!();
pub const DNS_PREDICATE: &str = p_dns!();
pub const AUTH_PREDICATE: &str = p_auth!();
pub const AUTH_FAIL_PREDICATE: &str = p_auth_fail!();
pub const IMAGE_LOAD_PREDICATE: &str = p_image_load!();
pub const REGISTRY_PREDICATE: &str = p_registry!();
pub const PIPE_PREDICATE: &str = p_pipe!();
pub const NETWORK_PREDICATE: &str = p_network!();
pub const PROCESS_PREDICATE: &str = p_process!();
pub const FILE_PREDICATE: &str = p_file!();

/// Classify a log event into a UDM event-type string label.
///
/// Returns one of: `ALERT`, `DHCP`, `DNS`, `AUTH_SUCCESS`, `AUTH_FAILURE`,
/// `IMAGE_LOAD`, `REGISTRY`, `PIPE`, `NETWORK`, `PROCESS`, `FILE`, `EVENT`.
/// Used by the facet aggregation and filter-condition queries in the asset
/// service.
pub const EVENT_TYPE_SQL: &str = concat!(
    "CASE",
    " WHEN ", p_alert!(), " THEN 'ALERT'",
    " WHEN ", p_dhcp!(), " THEN 'DHCP'",
    " WHEN ", p_dns!(), " THEN 'DNS'",
    " WHEN ", p_auth!(),
        " THEN CASE WHEN ", p_auth_fail!(), " THEN 'AUTH_FAILURE' ELSE 'AUTH_SUCCESS' END",
    " WHEN ", p_image_load!(), " THEN 'IMAGE_LOAD'",
    " WHEN ", p_registry!(), " THEN 'REGISTRY'",
    " WHEN ", p_pipe!(), " THEN 'PIPE'",
    " WHEN ", p_network!(), " THEN 'NETWORK'",
    " WHEN ", p_process!(), " THEN 'PROCESS'",
    " WHEN ", p_file!(), " THEN 'FILE'",
    " WHEN ", p_network_fallback!(), " THEN 'NETWORK'",
    " ELSE 'EVENT'",
    " END",
);

/// Classify a log event into a 5-lane heatmap index for the asset timeline.
///
/// Returns 0–4 for one of {auth, proc, net, file, alert}, or `-1` for
/// uncategorized events (caller should filter those out). Collapses related
/// event types into a single lane per the doc-comment mapping at the top of
/// this module.
pub const LANE_SQL: &str = concat!(
    "CASE",
    " WHEN ", p_alert!(), " THEN 4",
    " WHEN ", p_auth!(), " THEN 0",
    " WHEN (", p_process!(), " OR ", p_image_load!(), ") THEN 1",
    " WHEN (", p_dns!(), " OR ", p_dhcp!(), " OR ", p_network!(), " OR ", p_network_fallback!(), ") THEN 2",
    " WHEN (", p_file!(), " OR ", p_registry!(), " OR ", p_pipe!(), ") THEN 3",
    " ELSE -1",
    " END",
);

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity check: both classifiers should compile to valid-looking SQL
    /// (balanced `CASE`/`END`, non-empty, starts with the keyword).
    #[test]
    fn event_type_sql_is_well_formed() {
        assert!(EVENT_TYPE_SQL.starts_with("CASE"));
        assert!(EVENT_TYPE_SQL.ends_with("END"));
        let cases = EVENT_TYPE_SQL.matches("CASE").count();
        let ends = EVENT_TYPE_SQL.matches("END").count();
        assert_eq!(cases, ends, "CASE / END count mismatch: {EVENT_TYPE_SQL}");
    }

    /// The `pub const` predicate exports must stay in sync with the underlying
    /// macros so that downstream callers (e.g. `service::asset_dossier`) and the
    /// classifier never operate on differently-shaped SQL fragments. If someone
    /// edits the const directly instead of the macro, this test catches it.
    /// (NAN-1049 — the whole point of exposing the consts was to remove a copy.)
    #[test]
    fn pub_const_predicates_match_macros() {
        assert_eq!(ALERT_PREDICATE, p_alert!(), "ALERT_PREDICATE drift");
        assert_eq!(DHCP_PREDICATE, p_dhcp!(), "DHCP_PREDICATE drift");
        assert_eq!(DNS_PREDICATE, p_dns!(), "DNS_PREDICATE drift");
        assert_eq!(AUTH_PREDICATE, p_auth!(), "AUTH_PREDICATE drift");
        assert_eq!(AUTH_FAIL_PREDICATE, p_auth_fail!(), "AUTH_FAIL_PREDICATE drift");
        assert_eq!(IMAGE_LOAD_PREDICATE, p_image_load!(), "IMAGE_LOAD_PREDICATE drift");
        assert_eq!(REGISTRY_PREDICATE, p_registry!(), "REGISTRY_PREDICATE drift");
        assert_eq!(PIPE_PREDICATE, p_pipe!(), "PIPE_PREDICATE drift");
        assert_eq!(NETWORK_PREDICATE, p_network!(), "NETWORK_PREDICATE drift");
        assert_eq!(PROCESS_PREDICATE, p_process!(), "PROCESS_PREDICATE drift");
        assert_eq!(FILE_PREDICATE, p_file!(), "FILE_PREDICATE drift");
    }

    /// Windows-event parser sets `.udm.category` to one of `authentication`,
    /// `authorization`, `account_management`, `credential_access` for the
    /// 4624/4625/4634/4647/4648/4672/472x family. The classifier must key off
    /// `category` so those rows don't fall through to the `EVENT` bucket
    /// (NAN-1047).
    #[test]
    fn auth_predicate_keys_off_category() {
        for cat in [
            "authentication",
            "authorization",
            "account_management",
            "credential_access",
        ] {
            let token = format!("'{cat}'");
            assert!(
                EVENT_TYPE_SQL.contains(&token),
                "EVENT_TYPE_SQL missing category '{cat}': {EVENT_TYPE_SQL}"
            );
            assert!(
                LANE_SQL.contains(&token),
                "LANE_SQL missing category '{cat}': {LANE_SQL}"
            );
        }
    }

    #[test]
    fn lane_sql_is_well_formed() {
        assert!(LANE_SQL.starts_with("CASE"));
        assert!(LANE_SQL.ends_with("END"));
        assert_eq!(LANE_SQL.matches("CASE").count(), LANE_SQL.matches("END").count());
        // Sanity: the 5 lane indices must all appear
        for idx in 0..5 {
            assert!(LANE_SQL.contains(&format!(" THEN {idx} ")) || LANE_SQL.contains(&format!(" THEN {idx}\n")),
                "lane {idx} missing from LANE_SQL: {LANE_SQL}");
        }
    }
}
