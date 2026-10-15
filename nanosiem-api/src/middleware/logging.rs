// SPDX-License-Identifier: AGPL-3.0-or-later

//! Request logging middleware

use axum::http::Response;
use nanosiem_api_lib::ExpectedUnavailable;
use tower_http::classify::{
    ClassifiedResponse, ClassifyResponse, NeverClassifyEos, ServerErrorsAsFailures,
    ServerErrorsFailureClass, SharedClassifier,
};
use tower_http::trace::{DefaultMakeSpan, DefaultOnRequest, DefaultOnResponse, TraceLayer};
use tracing::Level;

/// `ServerErrorsAsFailures`, except a 5xx the handler marked as an expected
/// answer ([`ExpectedUnavailable`], e.g. a feature disabled on this
/// deployment) is a success. Without this, every such request logs
/// `tower_http::trace::on_failure` "response failed" at ERROR (NAN-3442).
#[derive(Debug, Clone, Copy, Default)]
pub struct ApiFailureClassifier;

impl ClassifyResponse for ApiFailureClassifier {
    type FailureClass = ServerErrorsFailureClass;
    type ClassifyEos = NeverClassifyEos<ServerErrorsFailureClass>;

    fn classify_response<B>(
        self,
        res: &Response<B>,
    ) -> ClassifiedResponse<Self::FailureClass, Self::ClassifyEos> {
        if res.extensions().get::<ExpectedUnavailable>().is_some() {
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
    SharedClassifier<ApiFailureClassifier>,
    DefaultMakeSpan,
    DefaultOnRequest,
    DefaultOnResponse,
> {
    TraceLayer::new(SharedClassifier::new(ApiFailureClassifier))
        .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
        .on_request(DefaultOnRequest::new().level(Level::INFO))
        .on_response(DefaultOnResponse::new().level(Level::INFO))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use nanosiem_api_lib::ApiError;

    fn is_failure(response: &Response<axum::body::Body>) -> bool {
        match ApiFailureClassifier.classify_response(response) {
            ClassifiedResponse::Ready(result) => result.is_err(),
            ClassifiedResponse::RequiresEos(_) => unreachable!("never classifies on EOS"),
        }
    }

    #[test]
    fn feature_disabled_503_is_not_a_trace_failure() {
        let response = ApiError::FeatureDisabled(
            "Pipeline preview is not enabled on this deployment".to_string(),
        )
        .into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(!is_failure(&response));
    }

    #[test]
    fn genuine_server_errors_stay_trace_failures() {
        for error in [
            ApiError::ServiceUnavailable("worker crashed".to_string()),
            ApiError::InternalError("boom".to_string()),
        ] {
            assert!(is_failure(&error.into_response()));
        }
        assert!(!is_failure(
            &ApiError::NotFound("x".to_string()).into_response()
        ));
    }
}
