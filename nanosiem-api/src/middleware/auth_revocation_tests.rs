// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5214: an unreadable JWT revocation denylist fails closed with 503.

use super::revocation_unavailable_response;
use axum::http::{header::RETRY_AFTER, StatusCode};

#[test]
fn revocation_store_outage_is_503_with_retry_after_not_401() {
    let response = revocation_unavailable_response();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers().get(RETRY_AFTER).unwrap(), "2");
}
