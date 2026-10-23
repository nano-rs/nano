// SPDX-License-Identifier: AGPL-3.0-or-later

//! Sanitized reqwest attempt spans; no replay, logging or transport changes.
use reqwest::{RequestBuilder, Response};
use tracing::Instrument;

/// Reqwest middleware for both ordinary and fresh-connection attempts. The
/// span ends at response headers; body decoding belongs to the caller's span.
pub(crate) async fn send_observed(builder: RequestBuilder) -> Result<Response, reqwest::Error> {
    let (client, request) = builder.build_split();
    execute_observed(&client, request?).await
}

pub(crate) async fn execute_observed(
    client: &reqwest::Client,
    request: reqwest::Request,
) -> Result<Response, reqwest::Error> {
    let host = request.url().host_str().unwrap_or("");
    let span = tracing::info_span!(
        "http.client.request",
        server.address = host,
        http.response.status_code = tracing::field::Empty
    );
    async {
        let response = client.execute(request).await?;
        tracing::Span::current().record(
            "http.response.status_code",
            u64::from(response.status().as_u16()),
        );
        Ok(response)
    }
    .instrument(span)
    .await
}

/// Middleware for plain outbound requests, preserving the caller's retry policy.
pub trait ObservedRequestBuilderExt {
    fn send_observed(
        self,
    ) -> impl std::future::Future<Output = Result<Response, reqwest::Error>> + Send;
}
impl ObservedRequestBuilderExt for RequestBuilder {
    fn send_observed(
        self,
    ) -> impl std::future::Future<Output = Result<Response, reqwest::Error>> + Send {
        send_observed(self)
    }
}
