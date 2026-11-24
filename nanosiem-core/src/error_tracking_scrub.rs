// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5798: secret scrubbing for Sentry payloads.
//!
//! Sentry runs only in nano-operated environments (local, e2e, a few small
//! nano-run tenants), never on customer installs, so payloads keep what makes
//! them useful for debugging: full messages and log text, breadcrumbs, URLs
//! and routes, span and transaction names, tags, contexts, stacks and
//! fingerprints. On top of the SDK defaults (`send_default_pii = false`: no
//! request bodies, cookies or user IPs), only SECRETS are removed, from every
//! string and every field:
//!
//! - `Authorization`, `Cookie`, `Set-Cookie` (and `X-Api-Key`) headers, and
//!   their values wherever they appear in text;
//! - API keys and tokens: `nit_` ingest tokens, JWTs, bearer / basic
//!   credentials, PEM blocks, and the values of `*_token`, `*_secret`,
//!   `password`, `api_key`-style keys (in `key=value` text and as field
//!   names);
//! - query-string values for sensitive keys (token, key, secret, password,
//!   code, sig, ...);
//! - DSNs and connection strings: the userinfo of any `scheme://user[:pass]@`.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;
use sentry::protocol::{Breadcrumb, Context, Event, Log, Request, Transaction, Value};
use sha2::{Digest, Sha256};

pub const FILTERED: &str = "[Filtered]";

fn re(pattern: &str) -> Regex {
    Regex::new(pattern).expect("scrub regex")
}

/// Field / header / tag names whose value is a secret.
static SENSITIVE_KEY_RE: LazyLock<Regex> = LazyLock::new(|| {
    re(r"(?i)^(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|dsn|jwt|bearer|.*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|credential|session[_-]?id|licen[cs]e[_-]?key).*)$")
});

pub fn is_sensitive_key(key: &str) -> bool {
    SENSITIVE_KEY_RE.is_match(key)
}

struct Rule {
    re: Regex,
    rep: &'static str,
}

/// Secret masks, applied in order to every string.
static RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    [
        // PEM blocks (to the END line, or the end of the text).
        (r"-----BEGIN [A-Z0-9 ]+-----[\s\S]*?(?:-----END [A-Z0-9 ]+-----|$)", "[Filtered]"),
        // Header-shaped secrets: the whole value, every cookie included.
        // Plain (`Cookie: a=1; b=2`), quoted (`Cookie="..."`) and JSON /
        // Debug-map (`{"Cookie": "..."}`) forms.
        (
            r#"(?i)\b((?:proxy-)?authorization|(?:set-)?cookie|x-api-key)(["']?\s*[:=]\s*)(?:"[^"]*"?|'[^']*'?|[^\r\n"']*)"#,
            "${1}${2}[Filtered]",
        ),
        // DSNs and connection strings: any URL userinfo.
        // Greedy to the last `@` before the path, so a password containing
        // `@` is masked whole.
        (r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s]*@", "${1}[Filtered]@"),
        // Query-string values of sensitive keys.
        (
            r#"(?i)([?&;][A-Za-z0-9_.-]*(?:token|key|secret|password|passwd|pwd|code|sig|signature|auth|session|credential)[A-Za-z0-9_.-]*=)[^&#\s"']*"#,
            "${1}[Filtered]",
        ),
        // Authorization schemes in free text.
        (r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}", "${1} [Filtered]"),
        // key=value / key: value whose key names a secret (access_token,
        // client_secret, api_key, password, ...).
        (
            r#"(?i)\b([A-Za-z0-9_.-]*(?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|credential|session[_-]?id|jwt|dsn|licen[cs]e[_-]?key))(["']?\s*[=:]\s*)(?:"[^"]*"?|'[^']*'?|[^\s"'&,;}]+)"#,
            "${1}${2}[Filtered]",
        ),
        // nano ingest tokens.
        (r"\bnit_[A-Za-z0-9_-]{8,}", "[Filtered]"),
        // JWTs.
        (r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*", "[Filtered]"),
    ]
    .into_iter()
    .map(|(pattern, rep)| Rule { re: re(pattern), rep })
    .collect()
});

/// `text` with secrets masked; everything else unchanged.
pub fn scrub_text(text: &str) -> String {
    let mut out = Cow::Borrowed(text);
    for r in RULES.iter() {
        if r.re.is_match(&out) {
            out = Cow::Owned(r.re.replace_all(&out, r.rep).into_owned());
        }
    }
    out.into_owned()
}

/// Kept for callers of the earlier API; same as [`scrub_text`].
pub fn template_message(text: &str) -> String {
    scrub_text(text)
}

/// Kept for callers of the earlier API; same as [`scrub_text`].
pub fn safe_message(text: &str) -> String {
    scrub_text(text)
}

pub fn scrub_value(value: &mut Value) {
    match value {
        Value::String(s) => *s = scrub_text(s),
        Value::Array(items) => items.iter_mut().for_each(scrub_value),
        Value::Object(map) => scrub_map(map.iter_mut()),
        _ => {}
    }
}

fn scrub_map<'a>(map: impl IntoIterator<Item = (&'a String, &'a mut Value)>) {
    for (key, value) in map {
        if is_sensitive_key(key) {
            *value = Value::String(FILTERED.into());
        } else {
            scrub_value(value);
        }
    }
}

pub fn scrub_fields(map: &mut BTreeMap<String, Value>) {
    scrub_map(map.iter_mut());
}

fn scrub_tags(tags: &mut BTreeMap<String, String>) {
    for (key, value) in tags.iter_mut() {
        *value = if is_sensitive_key(key) { FILTERED.into() } else { scrub_text(value) };
    }
}

fn scrub_string_map(map: &mut BTreeMap<String, String>) {
    scrub_tags(map);
}

/// Hash a user identifier so issues can still count distinct users.
pub fn hashed_user_id(raw: &str) -> String {
    let digest = Sha256::digest(format!("nano-sentry-user:{raw}").as_bytes());
    hex::encode(&digest[..8])
}

static QUERY_KEY_RE: LazyLock<Regex> = LazyLock::new(|| {
    re(r"(?i)token|key|secret|password|passwd|pwd|code|sig|signature|auth|session|credential")
});

/// A URL scrubbed structurally (never re-parsed from text, so it cannot fail
/// open): no userinfo, sensitive query values filtered, other query values,
/// path and fragment through [`scrub_text`].
fn scrub_url(url: &mut sentry::protocol::Url) {
    let _ = url.set_username("");
    let _ = url.set_password(None);
    if url.query().is_some() {
        let pairs: Vec<(String, String)> = url
            .query_pairs()
            .map(|(k, v)| {
                let v = if QUERY_KEY_RE.is_match(&k) || is_sensitive_key(&k) { FILTERED.to_string() } else { scrub_text(&v) };
                (k.into_owned(), v)
            })
            .collect();
        url.query_pairs_mut().clear().extend_pairs(pairs);
    }
    let path = scrub_text(url.path());
    url.set_path(&path);
    if let Some(fragment) = url.fragment().map(scrub_text) {
        url.set_fragment(Some(&fragment));
    }
}

fn scrub_request(request: &mut Request) {
    if let Some(url) = request.url.as_mut() {
        scrub_url(url);
    }
    request.cookies = None;
    request.query_string = request.query_string.as_deref().map(|q| scrub_text(&format!("?{q}"))[1..].to_string());
    request.data = request.data.as_deref().map(scrub_text);
    scrub_string_map(&mut request.headers);
    scrub_string_map(&mut request.env);
}

fn scrub_contexts(contexts: &mut BTreeMap<String, Context>) {
    for context in contexts.values_mut() {
        match context {
            Context::Other(map) => scrub_fields(map),
            Context::Trace(trace) => {
                trace.description = trace.description.as_deref().map(scrub_text);
                scrub_fields(&mut trace.data);
            }
            Context::Response(resp) => {
                resp.cookies = None;
                scrub_string_map(&mut resp.headers);
                if let Some(data) = resp.data.as_mut() {
                    scrub_value(data);
                }
            }
            _ => {}
        }
    }
}

pub fn scrub_breadcrumb(crumb: &mut Breadcrumb) {
    crumb.message = crumb.message.as_deref().map(scrub_text);
    scrub_fields(&mut crumb.data);
}

/// Secrets removed from every string and secret-named field of `event`.
pub fn scrub_event(event: &mut Event<'static>) {
    if let Some(request) = event.request.as_mut() {
        scrub_request(request);
    }
    if let Some(user) = event.user.as_mut() {
        user.ip_address = None;
        scrub_fields(&mut user.other);
    }
    event.message = event.message.as_deref().map(scrub_text);
    if let Some(entry) = event.logentry.as_mut() {
        entry.message = scrub_text(&entry.message);
        entry.params.iter_mut().for_each(scrub_value);
    }
    for exc in event.exception.values.iter_mut() {
        exc.value = exc.value.as_deref().map(scrub_text);
        if let Some(m) = exc.mechanism.as_mut() {
            m.description = m.description.as_deref().map(scrub_text);
            scrub_fields(&mut m.data);
        }
        for frames in [exc.stacktrace.as_mut(), exc.raw_stacktrace.as_mut()].into_iter().flatten() {
            for frame in frames.frames.iter_mut() {
                scrub_fields(&mut frame.vars);
            }
        }
    }
    event.transaction = event.transaction.as_deref().map(scrub_text);
    event.culprit = event.culprit.as_deref().map(scrub_text);
    let fp: Vec<Cow<'static, str>> = event.fingerprint.iter().map(|p| Cow::Owned(scrub_text(p))).collect();
    event.fingerprint = Cow::Owned(fp);
    scrub_fields(&mut event.extra);
    scrub_tags(&mut event.tags);
    scrub_contexts(&mut event.contexts);
    for crumb in event.breadcrumbs.values.iter_mut() {
        scrub_breadcrumb(crumb);
    }
}

/// The transaction counterpart of [`scrub_event`].
pub fn scrub_transaction(tx: &mut Transaction<'static>) {
    if let Some(request) = tx.request.as_mut() {
        scrub_request(request);
    }
    if let Some(user) = tx.user.as_mut() {
        user.ip_address = None;
        scrub_fields(&mut user.other);
    }
    tx.name = tx.name.as_deref().map(scrub_text);
    scrub_fields(&mut tx.extra);
    scrub_tags(&mut tx.tags);
    scrub_contexts(&mut tx.contexts);
    for span in tx.spans.iter_mut() {
        span.description = span.description.as_deref().map(scrub_text);
        scrub_fields(&mut span.data);
        scrub_tags(&mut span.tags);
    }
}

/// Secrets removed from a log's body and attributes (the message template
/// and its parameters included).
pub fn scrub_log(log: &mut Log) {
    log.body = scrub_text(&log.body);
    for (key, attr) in log.attributes.iter_mut() {
        if is_sensitive_key(key) {
            attr.0 = Value::String(FILTERED.into());
        } else {
            scrub_value(&mut attr.0);
        }
    }
}

#[cfg(test)]
#[path = "error_tracking_scrub_tests.rs"]
mod tests;
