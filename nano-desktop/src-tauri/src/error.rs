use serde::Serialize;

/// Errors surfaced to the UI. `kind` lets the frontend branch (e.g. show the
/// TLS-trust affordance only for `tls`) without string-matching messages.
#[derive(Debug, thiserror::Error, Serialize)]
#[serde(tag = "kind", content = "message", rename_all = "snake_case")]
pub enum Error {
    #[error("{0}")]
    InvalidUrl(String),

    #[error("{0}")]
    Unreachable(String),

    /// The host answered but the certificate could not be verified. The UI
    /// offers to retry with verification disabled (self-signed on-prem).
    #[error("{0}")]
    Tls(String),

    /// Something is listening, but it does not look like a nano instance.
    #[error("{0}")]
    NotNano(String),

    #[error("{0}")]
    Unauthorized(String),

    /// The stored refresh token is gone or rejected — re-login required.
    #[error("session expired")]
    SessionExpired,

    /// The search service is shedding load (HTTP 429). Its own variant, because
    /// it is the one error worth RETRYING: a dashboard opens N panels at once and
    /// the admission controller sheds the burst. Matching this on a substring of
    /// the message did not work — the body says TOO_MANY_REQUESTS, never "429".
    #[error("{0}")]
    RateLimited(String),

    #[error("not connected to a server")]
    NotConnected,

    #[error("{0}")]
    Server(String),

    #[error("{0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        // reqwest folds TLS failures into the generic connect error, so the
        // source chain is the only way to tell "wrong cert" from "host is down"
        // — and that distinction decides which affordance the UI shows.
        let mut source: Option<&dyn std::error::Error> = Some(&e);
        while let Some(err) = source {
            let text = err.to_string().to_lowercase();
            if text.contains("certificate")
                || text.contains("self-signed")
                || text.contains("self signed")
                || text.contains("tls")
                || text.contains("ssl")
            {
                return Error::Tls(format!(
                    "The server's TLS certificate could not be verified: {err}"
                ));
            }
            source = err.source();
        }

        if e.is_timeout() {
            Error::Unreachable("The server did not respond in time.".into())
        } else if e.is_connect() {
            Error::Unreachable(format!("Could not reach the server: {e}"))
        } else {
            Error::Internal(e.to_string())
        }
    }
}

impl From<keyring::Error> for Error {
    fn from(e: keyring::Error) -> Self {
        Error::Internal(format!("keychain: {e}"))
    }
}
