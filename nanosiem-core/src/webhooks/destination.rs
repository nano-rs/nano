// SPDX-License-Identifier: AGPL-3.0-or-later

//! Destination rules for a webhook update (NAN-5224).
//!
//! A channel's stored headers and secret were entered for one destination.
//! An update may not carry them to a different one:
//!
//! * a PagerDuty channel always delivers to [`PAGERDUTY_EVENTS_URL`], keyed on
//!   the STORED channel type, so a request cannot re-point the routing key by
//!   omitting `channel_type`;
//! * when the URL origin (scheme, host, port) changes on a row with stored
//!   headers or a secret, the request must re-supply each stored value (a new
//!   value, or an empty map / empty string to clear it).
//!
//! For Slack/Teams the URL is itself the credential, so supplying a new URL
//! already replaces it; the rule above still covers any header/secret stored
//! alongside it.

use super::channels::PAGERDUTY_EVENTS_URL;
use super::models::{UpdateWebhookRequest, Webhook};
use crate::scheduler::same_url_origin;

/// Outcome of a permitted update, for the audit record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WebhookDestinationChange {
    /// The request moves the channel to a different URL origin.
    pub origin_changed: bool,
}

/// The stored channel type, with the legacy empty value read as `generic`.
fn stored_channel_type(existing: &Webhook) -> &str {
    match existing.channel_type.trim() {
        "" => "generic",
        t => t,
    }
}

/// Apply the destination rules to an update of `existing`, pinning the
/// PagerDuty URL into `request`. Returns a 400-style message on rejection.
pub fn resolve_update_destination(
    existing: &Webhook,
    request: &mut UpdateWebhookRequest,
) -> Result<WebhookDestinationChange, String> {
    if stored_channel_type(existing) == "pagerduty" {
        if let Some(url) = request.url.as_deref() {
            if url.trim() != PAGERDUTY_EVENTS_URL {
                return Err(format!(
                    "a PagerDuty channel always delivers to {PAGERDUTY_EVENTS_URL}; omit url"
                ));
            }
        }
        // Re-pin on every update so a row can never drift off the vendor URL.
        request.url = Some(PAGERDUTY_EVENTS_URL.to_string());
        return Ok(WebhookDestinationChange {
            origin_changed: !same_url_origin(&existing.url, PAGERDUTY_EVENTS_URL),
        });
    }

    let Some(new_url) = request.url.as_deref() else {
        return Ok(WebhookDestinationChange::default());
    };
    // An unparseable or undecryptable stored URL never matches (fail closed).
    if same_url_origin(&existing.url, new_url) {
        return Ok(WebhookDestinationChange::default());
    }

    let has_headers = existing.headers_encrypted.as_ref().is_some_and(|h| !h.is_empty());
    let has_secret = existing.secret_encrypted.as_ref().is_some_and(|s| !s.is_empty());
    let mut missing = Vec::new();
    if has_headers && request.headers.is_none() {
        missing.push("headers");
    }
    if has_secret && request.secret.is_none() {
        missing.push("secret");
    }
    if !missing.is_empty() {
        return Err(format!(
            "The URL origin (scheme, host or port) changed, so the stored {} {} not carried over. \
             Re-enter {} for the new URL, or send an empty value to clear {}.",
            missing.join(" and "),
            if missing.len() == 1 { "is" } else { "are" },
            if missing.len() == 1 { "it" } else { "them" },
            if missing.len() == 1 { "it" } else { "them" },
        ));
    }
    Ok(WebhookDestinationChange { origin_changed: true })
}

#[cfg(test)]
#[path = "destination_tests.rs"]
mod destination_tests;
