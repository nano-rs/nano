// SPDX-License-Identifier: AGPL-3.0-or-later

//! Request logging middleware

use axum::http::Response;
use tower_http::classify::{
    ClassifiedResponse, ClassifyResponse, NeverClassifyEos, ServerErrorsAsFailures,
    ServerErrorsFailureClass, SharedClassifier,
};
use tower_http::trace::{DefaultMakeSpan, DefaultOnRequest, DefaultOnResponse, TraceLayer};
use tracing::Level;

/// Server errors are failures (logged at ERROR as "response failed"), except
/// a response marked [`nanosiem_api_lib::ExpectedServerError`] (NAN-5877: a
/// feature that is not set up, such as AI): that is an expected state, and
/// [`nanosiem_api_lib::ApiError`] already logged it at INFO.
#[derive(Debug, Clone, Copy, Default)]
pub struct ExpectedAwareServerErrors;

impl ClassifyResponse for ExpectedAwareServerErrors {
    type FailureClass = ServerErrorsFailureClass;
    type ClassifyEos = NeverClassifyEos<ServerErrorsFailureClass>;

    fn classify_response<B>(
        self,
        res: &Response<B>,
    ) -> ClassifiedResponse<Self::FailureClass, Self::ClassifyEos> {
        if res
            .extensions()
            .get::<nanosiem_api_lib::ExpectedServerError>()
            .is_some()
        {
            return ClassifiedResponse::Ready(Ok(()));
        }
        ServerErrorsAsFailures::new().classify_response(res)
    }

    fn classify_error<E>(self, error: &E) -> Self::FailureClass
    where
        E: std::fmt::Display + 'static,
    {
        ServerErrorsAsFailures::new().classify_error(error)
    }
}

/// Create a request logging layer
pub fn request_logging_layer() -> TraceLayer<
    SharedClassifier<ExpectedAwareServerErrors>,
    DefaultMakeSpan,
    DefaultOnRequest,
    DefaultOnResponse,
> {
    TraceLayer::new(SharedClassifier::new(ExpectedAwareServerErrors))
        .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
        .on_request(DefaultOnRequest::new().level(Level::INFO))
        .on_response(DefaultOnResponse::new().level(Level::INFO))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    fn classify(response: Response<axum::body::Body>) -> bool {
        matches!(
            ExpectedAwareServerErrors.classify_response(&response),
            ClassifiedResponse::Ready(Err(_))
        )
    }

    #[test]
    fn ai_not_configured_is_not_a_request_failure() {
        let response = nanosiem_api_lib::ApiError::ai_not_configured().into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(!classify(response));
    }

    #[test]
    fn other_server_errors_still_fail() {
        let internal = nanosiem_api_lib::ApiError::InternalError("boom".into()).into_response();
        assert!(classify(internal));
        let unavailable =
            nanosiem_api_lib::ApiError::ServiceUnavailable("down".into()).into_response();
        assert!(classify(unavailable));
        let ok = StatusCode::OK.into_response();
        assert!(!classify(ok));
    }
}
